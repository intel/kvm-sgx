// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include <linux/suspend.h>
#include <linux/sched/mm.h>
#include "arch.h"
#include "encl.h"
#include "encls.h"
#include "sgx.h"

static struct sgx_encl_page *sgx_encl_load_page(struct sgx_encl *encl,
						unsigned long addr)
{
	struct sgx_encl_page *entry;
	unsigned int flags;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return ERR_PTR(-EFAULT);

	flags = atomic_read(&encl->flags);

	if ((flags & SGX_ENCL_DEAD) || !(flags & SGX_ENCL_INITIALIZED))
		return ERR_PTR(-EFAULT);

	entry = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!entry)
		return ERR_PTR(-EFAULT);

	/* Page is already resident in the EPC. */
	if (entry->epc_page)
		return entry;

	return ERR_PTR(-EFAULT);
}

static void sgx_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm =
		container_of(mn, struct sgx_encl_mm, mmu_notifier);
	struct sgx_encl_mm *tmp = NULL;

	/*
	 * The enclave itself can remove encl_mm.  Note, objects can't be moved
	 * off an RCU protected list, but deletion is ok.
	 */
	spin_lock(&encl_mm->encl->mm_lock);
	list_for_each_entry(tmp, &encl_mm->encl->mm_list, list) {
		if (tmp == encl_mm) {
			list_del_rcu(&encl_mm->list);
			break;
		}
	}
	spin_unlock(&encl_mm->encl->mm_lock);

	if (tmp == encl_mm) {
		synchronize_srcu(&encl_mm->encl->srcu);
		mmu_notifier_put(mn);
	}
}

static void sgx_mmu_notifier_free(struct mmu_notifier *mn)
{
	struct sgx_encl_mm *encl_mm =
		container_of(mn, struct sgx_encl_mm, mmu_notifier);

	kfree(encl_mm);
}

static const struct mmu_notifier_ops sgx_mmu_notifier_ops = {
	.release		= sgx_mmu_notifier_release,
	.free_notifier		= sgx_mmu_notifier_free,
};

static struct sgx_encl_mm *sgx_encl_find_mm(struct sgx_encl *encl,
					    struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm = NULL;
	struct sgx_encl_mm *tmp;
	int idx;

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(tmp, &encl->mm_list, list) {
		if (tmp->mm == mm) {
			encl_mm = tmp;
			break;
		}
	}

	srcu_read_unlock(&encl->srcu, idx);

	return encl_mm;
}

int sgx_encl_mm_add(struct sgx_encl *encl, struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm;
	int ret;

	/* mm_list can be accessed only by a single thread at a time. */
	mmap_assert_write_locked(mm);

	if (atomic_read(&encl->flags) & SGX_ENCL_DEAD)
		return -EINVAL;

	/*
	 * mm_structs are kept on mm_list until the mm or the enclave dies,
	 * i.e. once an mm is off the list, it's gone for good, therefore it's
	 * impossible to get a false positive on @mm due to a stale mm_list.
	 */
	if (sgx_encl_find_mm(encl, mm))
		return 0;

	encl_mm = kzalloc(sizeof(*encl_mm), GFP_KERNEL);
	if (!encl_mm)
		return -ENOMEM;

	encl_mm->encl = encl;
	encl_mm->mm = mm;
	encl_mm->mmu_notifier.ops = &sgx_mmu_notifier_ops;

	ret = __mmu_notifier_register(&encl_mm->mmu_notifier, mm);
	if (ret) {
		kfree(encl_mm);
		return ret;
	}

	spin_lock(&encl->mm_lock);
	list_add_rcu(&encl_mm->list, &encl->mm_list);
	spin_unlock(&encl->mm_lock);

	return 0;
}

static void sgx_vma_open(struct vm_area_struct *vma)
{
	struct sgx_encl *encl = vma->vm_private_data;

	if (!encl)
		return;

	if (sgx_encl_mm_add(encl, vma->vm_mm))
		vma->vm_private_data = NULL;
}

static unsigned int sgx_vma_fault(struct vm_fault *vmf)
{
	unsigned long addr = (unsigned long)vmf->address;
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry;
	int ret = VM_FAULT_NOPAGE;
	unsigned long pfn;

	if (!encl)
		return VM_FAULT_SIGBUS;

	mutex_lock(&encl->lock);

	entry = sgx_encl_load_page(encl, addr);
	if (IS_ERR(entry)) {
		if (unlikely(PTR_ERR(entry) != -EBUSY))
			ret = VM_FAULT_SIGBUS;

		goto out;
	}

	if (!follow_pfn(vma, addr, &pfn))
		goto out;

	ret = vmf_insert_pfn(vma, addr, PFN_DOWN(entry->epc_page->desc));
	if (ret != VM_FAULT_NOPAGE) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

out:
	mutex_unlock(&encl->lock);
	return ret;
}

/**
 * sgx_encl_may_map() - Check if a requested VMA mapping is allowed
 * @encl:		an enclave
 * @start:		lower bound of the address range, inclusive
 * @end:		upper bound of the address range, exclusive
 * @vm_prot_bits:	requested protections of the address range
 *
 * Iterate through the enclave pages contained within [@start, @end) to verify
 * the permissions requested by @vm_prot_bits do not exceed that of any enclave
 * page to be mapped.
 *
 * Return:
 *   0 on success,
 *   -EACCES if VMA permissions exceed enclave page permissions
 */
int sgx_encl_may_map(struct sgx_encl *encl, unsigned long start,
		     unsigned long end, unsigned long vm_prot_bits)
{
	unsigned long idx, idx_start, idx_end;
	struct sgx_encl_page *page;

	/*
	 * Disallow RIE tasks as their VMA permissions might conflict with the
	 * enclave page permissions.
	 */
	if (!!(current->personality & READ_IMPLIES_EXEC))
		return -EACCES;

	idx_start = PFN_DOWN(start);
	idx_end = PFN_DOWN(end - 1);

	for (idx = idx_start; idx <= idx_end; ++idx) {
		mutex_lock(&encl->lock);
		page = radix_tree_lookup(&encl->page_tree, idx);
		mutex_unlock(&encl->lock);

		if (!page || (~page->vm_max_prot_bits & vm_prot_bits))
			return -EACCES;
	}

	return 0;
}

static int sgx_vma_mprotect(struct vm_area_struct *vma, unsigned long start,
			    unsigned long end, unsigned long prot)
{
	return sgx_encl_may_map(vma->vm_private_data, start, end,
				calc_vm_prot_bits(prot, 0));
}

const struct vm_operations_struct sgx_vm_ops = {
	.open = sgx_vma_open,
	.fault = sgx_vma_fault,
	.mprotect = sgx_vma_mprotect,
};

/**
 * sgx_encl_find - find an enclave
 * @mm:		mm struct of the current process
 * @addr:	address in the ELRANGE
 * @vma:	the resulting VMA
 *
 * Find an enclave identified by the given address. Give back a VMA that is
 * part of the enclave and located in that address. The VMA is given back if it
 * is a proper enclave VMA even if an &sgx_encl instance does not exist yet
 * (enclave creation has not been performed).
 *
 * Return:
 *   0 on success,
 *   -EINVAL if an enclave was not found,
 *   -ENOENT if the enclave has not been created yet
 */
int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma)
{
	struct vm_area_struct *result;
	struct sgx_encl *encl;

	result = find_vma(mm, addr);
	if (!result || result->vm_ops != &sgx_vm_ops || addr < result->vm_start)
		return -EINVAL;

	encl = result->vm_private_data;
	*vma = result;

	return encl ? 0 : -ENOENT;
}

/**
 * sgx_encl_destroy() - destroy enclave resources
 * @encl:	an &sgx_encl instance
 */
void sgx_encl_destroy(struct sgx_encl *encl)
{
	struct sgx_encl_page *entry;
	struct radix_tree_iter iter;
	void **slot;

	atomic_or(SGX_ENCL_DEAD, &encl->flags);

	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;

		if (entry->epc_page) {
			sgx_free_epc_page(entry->epc_page);
			encl->secs_child_cnt--;
			entry->epc_page = NULL;
		}

		radix_tree_delete(&entry->encl->page_tree,
				  PFN_DOWN(entry->desc));
		kfree(entry);
	}

	if (!encl->secs_child_cnt && encl->secs.epc_page) {
		sgx_free_epc_page(encl->secs.epc_page);
		encl->secs.epc_page = NULL;
	}
}

/**
 * sgx_encl_release - Destroy an enclave instance
 * @kref:	address of a kref inside &sgx_encl
 *
 * Used together with kref_put(). Frees all the resources associated with the
 * enclave and the instance itself.
 */
void sgx_encl_release(struct kref *ref)
{
	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);

	sgx_encl_destroy(encl);

	if (encl->backing)
		fput(encl->backing);

	cleanup_srcu_struct(&encl->srcu);

	WARN_ON_ONCE(!list_empty(&encl->mm_list));

	/* Detect EPC page leak's. */
	WARN_ON_ONCE(encl->secs_child_cnt);
	WARN_ON_ONCE(encl->secs.epc_page);

	kfree(encl);
}
