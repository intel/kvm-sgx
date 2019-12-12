// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#define pr_fmt(fmt)	"SGX virtual EPC: " fmt

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
};

static struct mutex zombie_secs_pages_lock;
static struct list_head zombie_secs_pages;

static int __sgx_virt_epc_fault(struct sgx_virt_epc *vepc,
				struct vm_area_struct *vma, unsigned long addr)
{
	struct sgx_epc_page *epc_page;
	unsigned long index, pfn;
	int ret;

	WARN_ON(!mutex_is_locked(&vepc->lock));

	/* Calculate index of EPC page in virtual EPC's page_array */
	index = vma->vm_pgoff + PFN_DOWN(addr - vma->vm_start);

	epc_page = xa_load(&vepc->page_array, index);
	if (epc_page)
		return 0;

	epc_page = sgx_alloc_epc_page(vepc, false);
	if (IS_ERR(epc_page))
		return PTR_ERR(epc_page);

	ret = xa_err(xa_store(&vepc->page_array, index, epc_page, GFP_KERNEL));
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
	xa_erase(&vepc->page_array, index);
err_free:
	sgx_free_epc_page(epc_page);
	return ret;
}

static vm_fault_t sgx_virt_epc_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_virt_epc *vepc = vma->vm_private_data;
	int ret;

	mutex_lock(&vepc->lock);
	ret = __sgx_virt_epc_fault(vepc, vma, vmf->address);
	mutex_unlock(&vepc->lock);

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
	struct sgx_virt_epc *vepc = file->private_data;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	vma->vm_ops = &sgx_virt_epc_vm_ops;
	/* Don't copy VMA in fork() */
	vma->vm_flags |= VM_PFNMAP | VM_IO | VM_DONTDUMP | VM_DONTCOPY;
	vma->vm_private_data = vepc;

	return 0;
}

static int sgx_virt_epc_free_page(struct sgx_epc_page *epc_page)
{
	int ret;

	/*
	 * Take a previously guest-owned EPC page and return it to the
	 * general EPC page pool.
	 *
	 * Guests can not be trusted to have left this page in a good
	 * state, so run EREMOVE on the page unconditionally.  In the
	 * case that a guest properly EREMOVE'd this page, a superfluous
	 * EREMOVE is harmless.
	 */
	ret = __eremove(sgx_get_epc_virt_addr(epc_page));
	if (ret) {
		/*
		 * Only SGX_CHILD_PRESENT is expected, which is because of
		 * EREMOVE'ing an SECS still with child, in which case it can
		 * be handled by EREMOVE'ing the SECS again after all pages in
		 * virtual EPC have been EREMOVE'd. See comments in below in
		 * sgx_virt_epc_release().
		 *
		 * The user of virtual EPC (KVM) needs to guarantee there's no
		 * logical processor is still running in the enclave in guest,
		 * otherwise EREMOVE will get SGX_ENCLAVE_ACT which cannot be
		 * handled here.
		 */
		WARN_ONCE(ret != SGX_CHILD_PRESENT,
			  "EREMOVE (EPC page 0x%lx): unexpected error: %d\n",
			  sgx_get_epc_phys_addr(epc_page), ret);
		return ret;
	}

	sgx_free_epc_page(epc_page);
	return 0;
}

static int sgx_virt_epc_release(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *vepc = file->private_data;
	struct sgx_epc_page *epc_page, *tmp, *entry;
	unsigned long index;

	LIST_HEAD(secs_pages);

	xa_for_each(&vepc->page_array, index, entry) {
		/*
		 * Remove all normal, child pages.  sgx_virt_epc_free_page()
		 * will fail if EREMOVE fails, but this is OK and expected on
		 * SECS pages.  Those can only be EREMOVE'd *after* all their
		 * child pages. Retries below will clean them up.
		 */
		if (sgx_virt_epc_free_page(entry))
			continue;

		xa_erase(&vepc->page_array, index);
	}

	/*
	 * Retry EREMOVE'ing pages.  This will clean up any SECS pages that
	 * only had children in this 'epc' area.
	 */
	xa_for_each(&vepc->page_array, index, entry) {
		epc_page = entry;
		/*
		 * An EREMOVE failure here means that the SECS page
		 * still has children.  But, since all children in this
		 * 'sgx_virt_epc' have been removed, the SECS page must
		 * have a child on another instance.
		 */
		if (sgx_virt_epc_free_page(epc_page))
			list_add_tail(&epc_page->list, &secs_pages);

		xa_erase(&vepc->page_array, index);
	}

	/*
	 * SECS pages are "pinned" by child pages, an unpinned once all
	 * children have been EREMOVE'd.  A child page in this instance
	 * may have pinned an SECS page encountered in an earlier
	 * release(), creating a zombie.  Since some children were
	 * EREMOVE'd above, try to EREMOVE all zombies in the hopes that
	 * one was unpinned.
	 */
	mutex_lock(&zombie_secs_pages_lock);
	list_for_each_entry_safe(epc_page, tmp, &zombie_secs_pages, list) {
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
		list_splice_tail(&secs_pages, &zombie_secs_pages);
	mutex_unlock(&zombie_secs_pages_lock);

	kfree(vepc);

	return 0;
}

static int sgx_virt_epc_open(struct inode *inode, struct file *file)
{
	struct sgx_virt_epc *vepc;

	vepc = kzalloc(sizeof(struct sgx_virt_epc), GFP_KERNEL);
	if (!vepc)
		return -ENOMEM;
	mutex_init(&vepc->lock);
	xa_init(&vepc->page_array);

	file->private_data = vepc;

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
	/* SGX virtualization requires KVM to work */
	if (!boot_cpu_has(X86_FEATURE_VMX) || !IS_ENABLED(CONFIG_KVM_INTEL))
		return -ENODEV;

	INIT_LIST_HEAD(&zombie_secs_pages);
	mutex_init(&zombie_secs_pages_lock);

	return misc_register(&sgx_virt_epc_dev);
}

int sgx_virt_ecreate(struct sgx_pageinfo *pageinfo, void __user *secs,
		     int *trapnr)
{
	int ret;

	/*
	 * @secs is userspace address, and it's not guaranteed @secs points at
	 * an actual EPC page. It's also possible to generate a kernel mapping
	 * to physical EPC page by resolving PFN but using __uaccess_xx() is
	 * simpler.
	 */
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
