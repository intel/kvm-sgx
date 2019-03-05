// SPDX-License-Identifier: GPL-2.0

#include <linux/anon_inodes.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/page_types.h>
#include <asm/sgx.h>
#include <uapi/asm/sgx.h>
#include "sgx.h"

struct sgx_virt_page {
	struct sgx_epc_page *epc_page;
};

struct sgx_virt_epc {
	u64 size;
	struct rw_semaphore lock;
	struct radix_tree_root page_tree;
	struct kref refcount;
};

static inline unsigned long sgx_virt_epc_page_index(struct vm_area_struct *vma,
						    unsigned long addr)
{
	return vma->vm_pgoff + PFN_DOWN(addr - vma->vm_start);
}

static void sgx_virt_epc_destroy(struct kref *ref)
{
	struct radix_tree_iter iter;
	struct sgx_virt_page *page;
	struct sgx_virt_epc *epc;
	void **slot;

	LIST_HEAD(secs_pages);

	epc = container_of(ref, struct sgx_virt_epc, refcount);

	radix_tree_for_each_slot(slot, &epc->page_tree, &iter, 0) {
		page = *slot;
		if (page->epc_page) {
			if (__sgx_free_page(page->epc_page))
				continue;
		}
		kfree(page);
		radix_tree_delete(&epc->page_tree, iter.index);
	}

	/*
	 * Because we don't track which pages are SECS pages, it's possible
	 * for EREMOVE to fail, e.g. a SECS page can have children if a VM
	 * shutdown unexpectedly.  Retry all failed pages after iterating
	 * through the entire tree, at which point all children should be
	 * removed and the SECS pages can be nuked as well.
	 */
	radix_tree_for_each_slot(slot, &epc->page_tree, &iter, 0) {
		page = *slot;
		if (!(WARN_ON(!page->epc_page)))
			sgx_free_page(page->epc_page);
		radix_tree_delete(&epc->page_tree, iter.index);
	}

	kfree(epc);

	return;
}


static void sgx_virt_epc_open(struct vm_area_struct *vma)
{
	struct sgx_virt_epc *epc = vma->vm_private_data;

	if (!epc)
		return;

	if (!kref_get_unless_zero(&epc->refcount))
		vma->vm_private_data = NULL;
}

static void sgx_virt_epc_close(struct vm_area_struct *vma)
{
	struct sgx_virt_epc *epc = vma->vm_private_data;

	if (epc)
		kref_put(&epc->refcount, sgx_virt_epc_destroy);
}

static struct sgx_virt_page *__sgx_virt_epc_fault(struct sgx_virt_epc *epc,
						  struct vm_area_struct *vma,
						  unsigned long addr)
{
	struct sgx_epc_page *epc_page;
	struct sgx_virt_page *page;
	unsigned long index;
	int ret;

	index = sgx_virt_epc_page_index(vma, addr);

	page = radix_tree_lookup(&epc->page_tree, index);
	if (page) {
		if (page->epc_page)
			return page;
	} else {
		page = kzalloc(sizeof(*page), GFP_KERNEL);
		if (!page)
			return ERR_PTR(-ENOMEM);

		ret = radix_tree_insert(&epc->page_tree, index, page);
		if (unlikely(ret)) {
			kfree(page);
			return ERR_PTR(ret);
		}
	}

	epc_page = sgx_alloc_page(&epc, false);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	ret = vmf_insert_pfn(vma, addr, PFN_DOWN(epc_page->desc));
	if (unlikely(ret != VM_FAULT_NOPAGE)) {
		sgx_free_page(epc_page);
		return ERR_PTR(-EFAULT);
	}

	page->epc_page = epc_page;

	return page;
}

static int sgx_virt_epc_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_virt_epc *epc = (struct sgx_virt_epc *)vma->vm_private_data;
	struct sgx_virt_page *page;

	if (!epc || WARN_ON((vmf->address - vma->vm_start) > epc->size))
		return VM_FAULT_SIGBUS;

	down_write(&epc->lock);
	page = __sgx_virt_epc_fault(epc, vma, vmf->address);
	up_write(&epc->lock);

	if (!IS_ERR(page) || signal_pending(current))
		return VM_FAULT_NOPAGE;

	if (PTR_ERR(page) == -EBUSY && (vmf->flags & FAULT_FLAG_ALLOW_RETRY)) {
		up_read(&vma->vm_mm->mmap_sem);
		return VM_FAULT_RETRY;
	}

	return VM_FAULT_SIGBUS;
}

static struct sgx_virt_page *__sgx_virt_get_page(struct sgx_virt_epc *epc,
						 unsigned long index)
{
	struct sgx_virt_page *page;

	if (index > PFN_DOWN(epc->size))
		return ERR_PTR(-EINVAL);

	down_read(&epc->lock);
	page = radix_tree_lookup(&epc->page_tree, index);
	if (!page || !page->epc_page)
		page = ERR_PTR(-EFAULT);
	up_read(&epc->lock);

	return page;
}

static int sgx_virt_epc_access(struct vm_area_struct *vma, unsigned long start,
			       void *buf, int len, int write)
{
	/* EDBG{RD,WR} are naturally sized, i.e. always 8-byte on 64-bit. */
	unsigned char data[sizeof(unsigned long)];
	struct sgx_virt_page *page;
	struct sgx_virt_epc *epc;
	unsigned long addr, index;
	int offset, cnt, i;
	int ret = 0;
	void * p;

	epc = vma->vm_private_data;
	if (!epc)
		return -EINVAL;

	for (i = 0; i < len && !ret; i += cnt) {
		addr = start + i;
		if (i == 0 || PFN_DOWN(addr) != PFN_DOWN(addr - cnt))
			index = sgx_virt_epc_page_index(vma, addr);

		page = __sgx_virt_get_page(epc, index);

		/*
		 * EDBG{RD,WR} require an active enclave, and given that VMM
		 * EPC oversubscription isn't supported, a not-present EPC page
		 * means the guest hasn't accessed the page and therefore can't
		 * have associated the page with an enclave.
		 */
		if (IS_ERR(page))
			return PTR_ERR(page);

		offset = addr & (sizeof(unsigned long) - 1);
		addr = ALIGN_DOWN(addr, sizeof(unsigned long));
		cnt = min((int)sizeof(unsigned long) - offset, len - i);

		p = sgx_epc_addr(page->epc_page) + (addr & ~PAGE_MASK);

		/* EDBGRD for read, or to do RMW for a partial write. */
		if (!write || cnt != sizeof(unsigned long))
			ret = __edbgrd(p, (void *)data);

		if (!ret) {
			if (write) {
				memcpy(data + offset, buf + i, cnt);
				ret = __edbgwr(p, (void *)data);
			} else {
				memcpy(buf + i, data + offset, cnt);
			}
		}
	}

	return ret ? encls_to_err(ret) : i;
}

static int sgx_virt_epc_mremap(struct vm_area_struct *vma)
{
	struct sgx_virt_epc *epc = vma->vm_private_data;
	unsigned long size;

	if (!epc)
		return -EINVAL;

	size = (vma->vm_pgoff << PAGE_SHIFT) + (vma->vm_end - vma->vm_start);
	if (size > epc->size)
		return -EINVAL;

	return 0;
}

const struct vm_operations_struct sgx_virt_epc_vm_ops = {
	.open = sgx_virt_epc_open,
	.close = sgx_virt_epc_close,
	.fault = sgx_virt_epc_fault,
	.access = sgx_virt_epc_access,
	.mremap = sgx_virt_epc_mremap,
};

static int sgx_virt_epc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sgx_virt_epc *epc = file->private_data;

	if (WARN_ON(!kref_get_unless_zero(&epc->refcount)))
		return -ENOENT;

	vma->vm_ops = &sgx_virt_epc_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_IO | VM_DONTDUMP;
	vma->vm_private_data = epc;

	return 0;
}

static unsigned long sgx_virt_epc_get_unmapped_area(struct file *file,
						    unsigned long addr,
						    unsigned long len,
						    unsigned long pgoff,
						    unsigned long flags)
{
	if (flags & MAP_PRIVATE)
		return -EINVAL;

	if ((flags & MAP_FIXED) && !PAGE_ALIGNED(addr))
		return -EINVAL;

	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

static int sgx_virt_epc_release(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *epc = file->private_data;

	kref_put(&epc->refcount, sgx_virt_epc_destroy);
	return 0;
}

static struct file_operations sgx_virt_epc_fops = {
	.mmap			= sgx_virt_epc_mmap,
	.get_unmapped_area	= sgx_virt_epc_get_unmapped_area,
	.release        	= sgx_virt_epc_release,
	.llseek			= noop_llseek,
};

struct sgx_epc_page *sgx_virt_get_epc_page(unsigned long addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct sgx_virt_page *page;
	struct sgx_virt_epc *epc;
	unsigned long index;

retry:
	down_read(&mm->mmap_sem);

	vma = find_vma_intersection(mm, addr, addr + 1);
	if (!vma || vma->vm_ops != &sgx_virt_epc_vm_ops ||
	    !vma->vm_private_data) {
		page = ERR_PTR(-EFAULT);
		goto out;
	}

	epc = vma->vm_private_data;
	index = sgx_virt_epc_page_index(vma, addr);
	page = __sgx_virt_get_page(epc, index);

	if (IS_ERR(page)) {
		down_write(&epc->lock);
		page = __sgx_virt_epc_fault(epc, vma, addr);
		up_write(&epc->lock);
	}
out:
	up_read(&mm->mmap_sem);

	if (PTR_ERR(page) == -EBUSY && !signal_pending(current))
		goto retry;
	if (IS_ERR(page))
		return ERR_CAST(page);
	return page->epc_page;
}
EXPORT_SYMBOL_GPL(sgx_virt_get_epc_page);

int sgx_virt_ecreate(struct sgx_pageinfo *pginfo, struct sgx_epc_page *secs,
                     int *trapnr)
{
	int ret = __ecreate(pginfo, sgx_epc_addr(secs));

	if (IS_ENCLS_FAULT(ret)) {
		*trapnr = ENCLS_TRAPNR(ret);
		return -EFAULT;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sgx_virt_ecreate);

static int sgx_virt_epc_create(unsigned long arg)
{
	struct sgx_virt_epc_create params;
	struct sgx_virt_epc *epc;

	if (copy_from_user(&params, (void __user *)arg, sizeof(params)))
		return -EFAULT;

	if (!PAGE_ALIGNED(params.size))
		return -EINVAL;

	epc = kzalloc(sizeof(struct sgx_virt_epc), GFP_KERNEL);
	if (!epc)
		return -ENOMEM;

	epc->size = params.size;
	init_rwsem(&epc->lock);
	kref_init(&epc->refcount);
	INIT_RADIX_TREE(&epc->page_tree, GFP_KERNEL);

	return anon_inode_getfd("sgx-virt-epc", &sgx_virt_epc_fops, epc,
				O_RDWR | O_CLOEXEC);
}

long sgx_virt_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	if (cmd != SGX_VIRT_EPC_CREATE)
		return -ENOIOCTLCMD;

	return sgx_virt_epc_create(arg);
}

static const struct file_operations sgx_virt_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= sgx_virt_ioctl,
};

int sgx_virt_driver_probe(void)
{
	return sgx_device_alloc("sgx_virt", &sgx_virt_fops);
}
