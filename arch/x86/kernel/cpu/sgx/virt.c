// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <asm/sgx.h>
#include <uapi/asm/sgx.h>

#include "encls.h"
#include "sgx.h"
#include "virt.h"

struct sgx_virt_epc {
	struct xarray page_array;
	struct mutex lock;
	struct mm_struct *mm;
};

static struct mutex virt_epc_lock;
static struct list_head virt_epc_zombie_pages;

static int __sgx_virt_epc_fault(struct sgx_virt_epc *epc,
				struct vm_area_struct *vma, unsigned long addr)
{
	struct sgx_epc_page *epc_page;
	unsigned long index, pfn;
	int ret;

	/* epc->lock must already have been hold */

	/* Calculate index of EPC page in virtual EPC's page_array */
	index = vma->vm_pgoff + PFN_DOWN(addr - vma->vm_start);

	epc_page = xa_load(&epc->page_array, index);
	if (epc_page)
		return 0;

	epc_page = sgx_alloc_epc_page(epc, false);
	if (IS_ERR(epc_page))
		return PTR_ERR(epc_page);

	ret = xa_err(xa_store(&epc->page_array, index, epc_page, GFP_KERNEL));
	if (ret)
		goto err_free;

	pfn = PFN_DOWN(sgx_get_epc_phys_addr(epc_page));

	ret = vmf_insert_pfn(vma, addr, pfn);
	if (ret != VM_FAULT_NOPAGE) {
		ret = -EFAULT;
		goto err_delete;
	}

	return 0;

err_delete:
	xa_erase(&epc->page_array, index);
err_free:
	sgx_free_epc_page(epc_page);
	return ret;
}

static vm_fault_t sgx_virt_epc_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_virt_epc *epc = vma->vm_private_data;
	int ret;

	mutex_lock(&epc->lock);
	ret = __sgx_virt_epc_fault(epc, vma, vmf->address);
	mutex_unlock(&epc->lock);

	if (!ret)
		return VM_FAULT_NOPAGE;

	if (ret == -EBUSY && (vmf->flags & FAULT_FLAG_ALLOW_RETRY)) {
		mmap_read_unlock(vma->vm_mm);
		return VM_FAULT_RETRY;
	}

	return VM_FAULT_SIGBUS;
}

const struct vm_operations_struct sgx_virt_epc_vm_ops = {
	.fault = sgx_virt_epc_fault,
};

static int sgx_virt_epc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sgx_virt_epc *epc = file->private_data;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	/*
	 * Don't allow mmap() from child after fork(), since child and parent
	 * cannot map to the same EPC.
	 */
	if (vma->vm_mm != epc->mm)
		return -EINVAL;

	vma->vm_ops = &sgx_virt_epc_vm_ops;
	/* Don't copy VMA in fork() */
	vma->vm_flags |= VM_PFNMAP | VM_IO | VM_DONTDUMP | VM_DONTCOPY;
	vma->vm_private_data = file->private_data;

	return 0;
}

static int sgx_virt_epc_free_page(struct sgx_epc_page *epc_page)
{
	int ret;

	if (!epc_page)
		return 0;

	/*
	 * Explicitly EREMOVE virtual EPC page. Virtual EPC is only used by
	 * guest, and in normal condition guest should have done EREMOVE for
	 * all EPC pages before they are freed here. But it's possible guest
	 * is killed or crashed unnormally in which case EREMOVE has not been
	 * done. Do EREMOVE unconditionally here to cover both cases, because
	 * it's not possible to tell whether guest has done EREMOVE, since
	 * virtual EPC page status is not tracked. And it is fine to EREMOVE
	 * EPC page multiple times.
	 */
	ret = __eremove(sgx_get_epc_virt_addr(epc_page));
	if (ret) {
		/*
		 * Only SGX_CHILD_PRESENT is expected, which is because of
		 * EREMOVE-ing an SECS still with child, in which case it can
		 * be handled by EREMOVE-ing the SECS again after all pages in
		 * virtual EPC have been EREMOVE-ed. See comments in below in
		 * sgx_virt_epc_release().
		 */
		WARN_ON_ONCE(ret != SGX_CHILD_PRESENT);
		return ret;
	}

	__sgx_free_epc_page(epc_page);
	return 0;
}

static int sgx_virt_epc_release(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *epc = file->private_data;
	struct sgx_epc_page *epc_page, *tmp, *entry;
	unsigned long index;

	LIST_HEAD(secs_pages);

	mmdrop(epc->mm);

	xa_for_each(&epc->page_array, index, entry) {
		/*
		 * Virtual EPC pages are not tracked, so it's possible for
		 * EREMOVE to fail due to, e.g. a SECS page still has children
		 * if guest was shutdown unexpectedly. If it is the case, leave
		 * it in the xarray and retry EREMOVE below later.
		 */
		if (sgx_virt_epc_free_page(entry))
			continue;

		xa_erase(&epc->page_array, index);
	}

	/*
	 * Retry all failed pages after iterating through the entire tree, at
	 * which point all children should be removed and the SECS pages can be
	 * nuked as well...unless userspace has exposed multiple instance of
	 * virtual EPC to a single VM.
	 */
	xa_for_each(&epc->page_array, index, entry) {
		epc_page = entry;
		/*
		 * Error here means that EREMOVE failed due to a SECS page
		 * still has child on *another* EPC instance.  Put it to a
		 * temporary SECS list which will be spliced to 'zombie page
		 * list' and will be EREMOVE-ed again when freeing another
		 * virtual EPC instance.
		 */
		if (sgx_virt_epc_free_page(epc_page))
			list_add_tail(&epc_page->list, &secs_pages);

		xa_erase(&epc->page_array, index);
	}

	/*
	 * Third time's a charm.  Try to EREMOVE zombie SECS pages from virtual
	 * EPC instances that were previously released, i.e. free SECS pages
	 * that were in limbo due to having children in *this* EPC instance.
	 */
	mutex_lock(&virt_epc_lock);
	list_for_each_entry_safe(epc_page, tmp, &virt_epc_zombie_pages, list) {
		/*
		 * Speculatively remove the page from the list of zombies, if
		 * the page is successfully EREMOVE it will be added to the
		 * list of free pages.  If EREMOVE fails, throw the page on the
		 * local list, which will be spliced on at the end.
		 */
		list_del(&epc_page->list);

		if (sgx_virt_epc_free_page(epc_page))
			list_add_tail(&epc_page->list, &secs_pages);
	}

	if (!list_empty(&secs_pages))
		list_splice_tail(&secs_pages, &virt_epc_zombie_pages);
	mutex_unlock(&virt_epc_lock);

	kfree(epc);

	return 0;
}

static int sgx_virt_epc_open(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *epc;

	epc = kzalloc(sizeof(struct sgx_virt_epc), GFP_KERNEL);
	if (!epc)
		return -ENOMEM;
	/*
	 * Keep the current->mm to virtual EPC. It will be checked in
	 * sgx_virt_epc_mmap() to prevent, in case of fork, child being
	 * able to mmap() to the same virtual EPC pages.
	 */
	mmgrab(current->mm);
	epc->mm = current->mm;
	mutex_init(&epc->lock);
	xa_init(&epc->page_array);

	file->private_data = epc;

	return 0;
}

static const struct file_operations sgx_virt_epc_fops = {
	.owner			= THIS_MODULE,
	.open			= sgx_virt_epc_open,
	.release		= sgx_virt_epc_release,
	.mmap			= sgx_virt_epc_mmap,
};

static struct miscdevice sgx_virt_epc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sgx_virt_epc",
	.nodename = "sgx_virt_epc",
	.fops = &sgx_virt_epc_fops,
};

int __init sgx_virt_epc_init(void)
{
	INIT_LIST_HEAD(&virt_epc_zombie_pages);
	mutex_init(&virt_epc_lock);

	return misc_register(&sgx_virt_epc_dev);
}

int sgx_virt_ecreate(struct sgx_pageinfo *pageinfo, void __user *secs,
		     int *trapnr)
{
	int ret;

	__uaccess_begin();
	ret = __ecreate(pageinfo, (void *)secs);
	__uaccess_end();

	if (encls_faulted(ret)) {
		*trapnr = ENCLS_TRAPNR(ret);
		return -EFAULT;
	}

	/* ECREATE doesn't return an error code, it faults or succeeds. */
	WARN_ON_ONCE(ret);
	return 0;
}
EXPORT_SYMBOL_GPL(sgx_virt_ecreate);

static int __sgx_virt_einit(void __user *sigstruct, void __user *token,
			    void __user *secs)
{
	int ret;

	__uaccess_begin();
	ret =  __einit((void *)sigstruct, (void *)token, (void *)secs);
	__uaccess_end();
	return ret;
}

int sgx_virt_einit(void __user *sigstruct, void __user *token,
		   void __user *secs, u64 *lepubkeyhash, int *trapnr)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		ret = __sgx_virt_einit(sigstruct, token, secs);
	} else {
		preempt_disable();

		sgx_update_lepubkeyhash(lepubkeyhash);

		ret = __sgx_virt_einit(sigstruct, token, secs);
		preempt_enable();
	}

	if (encls_faulted(ret)) {
		*trapnr = ENCLS_TRAPNR(ret);
		return -EFAULT;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sgx_virt_einit);
