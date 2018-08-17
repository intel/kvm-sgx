// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <asm/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include "sgx.h"

struct sgx_add_page_req {
	struct sgx_encl *encl;
	struct sgx_encl_page *encl_page;
	struct sgx_secinfo secinfo;
	u16 mrmask;
	struct list_head list;
};

/**
 * sgx_encl_find - find an enclave
 * @mm:		mm struct of the current process
 * @addr:	address in the ELRANGE
 * @vma:	the resulting VMA
 *
 * Finds an enclave identified by the given address. Gives back the VMA, that
 * is part of the enclave, located in that address. The VMA is given back if it
 * is a proper enclave VMA even if an &sgx_encl instance does not exist
 * yet (enclave creation has not been performed).
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
 * sgx_invalidate - kill an enclave
 * @encl:	an &sgx_encl instance
 * @flush_cpus	Set if there can be active threads inside the enclave.
 *
 * Mark the enclave as dead and immediately free its EPC pages (but not
 * its resources).  For active enclaves, the entry points to the enclave
 * are destroyed first and hardware threads are kicked out so that the
 * EPC pages can be safely manipulated.
 */
void sgx_invalidate(struct sgx_encl *encl, bool flush_cpus)
{
	struct sgx_encl_page *entry;
	struct radix_tree_iter iter;
	struct vm_area_struct *vma;
	unsigned long addr;
	void **slot;

	if (encl->flags & SGX_ENCL_DEAD)
		return;

	encl->flags |= SGX_ENCL_DEAD;
	if (flush_cpus) {
		radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
			entry = *slot;
			addr = SGX_ENCL_PAGE_ADDR(entry);
			if ((entry->desc & SGX_ENCL_PAGE_LOADED) &&
			    (entry->desc & SGX_ENCL_PAGE_TCS) &&
			    !sgx_encl_find(encl->mm, addr, &vma))
				zap_vma_ptes(vma, addr, PAGE_SIZE);
		}
		sgx_flush_cpus(encl);
	}
	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;
		/* If the page has RECLAIMED set, it is being reclaimed so we
		 * need to check that and let the swapper thread to free the
		 * page if this is the case.
		 */
		if ((entry->desc & SGX_ENCL_PAGE_LOADED) &&
		    !(entry->desc & SGX_ENCL_PAGE_RECLAIMED)) {
			if (!__sgx_free_page(entry->epc_page))
				entry->desc &= ~SGX_ENCL_PAGE_LOADED;
		}
	}
}

static int sgx_measure(struct sgx_epc_page *secs_page,
		       struct sgx_epc_page *epc_page,
		       u16 mrmask)
{
	int ret = 0;
	void *secs;
	void *epc;
	int i;
	int j;

	if (!mrmask)
		return ret;

	secs = sgx_epc_addr(secs_page);
	epc = sgx_epc_addr(epc_page);

	for (i = 0, j = 1; i < 0x1000 && !ret; i += 0x100, j <<= 1) {
		if (!(j & mrmask))
			continue;

		ret = __eextend(secs, (void *)((unsigned long)epc + i));
	}

	return ret;
}

static int sgx_eadd(struct sgx_epc_page *secs_page,
		    struct sgx_epc_page *epc_page,
		    unsigned long linaddr,
		    struct sgx_secinfo *secinfo,
		    struct page *backing)
{
	struct sgx_pageinfo pginfo;
	int ret;

	pginfo.secs = (unsigned long)sgx_epc_addr(secs_page);
	pginfo.addr = linaddr;
	pginfo.metadata = (unsigned long)secinfo;

	pginfo.contents = (unsigned long)kmap_atomic(backing);
	ret = __eadd(&pginfo, sgx_epc_addr(epc_page));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	return ret;
}

static bool sgx_process_add_page_req(struct sgx_add_page_req *req,
				     struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = req->encl_page;
	struct sgx_encl *encl = req->encl;
	struct sgx_secinfo secinfo;
	struct vm_area_struct *vma;
	pgoff_t backing_index;
	struct page *backing;
	unsigned long addr;
	int ret;

	if (encl->flags & (SGX_ENCL_SUSPEND | SGX_ENCL_DEAD))
		return false;

	addr = SGX_ENCL_PAGE_ADDR(encl_page);
	ret = sgx_encl_find(encl->mm, addr, &vma);
	if (ret)
		return false;

	backing_index = SGX_ENCL_PAGE_BACKING_INDEX(encl_page, encl);
	backing = sgx_get_backing(encl->backing, backing_index);
	if (IS_ERR(backing))
		return false;

	ret = vm_insert_pfn(vma, addr, PFN_DOWN(epc_page->desc));
	if (ret) {
		sgx_err(encl, "%s: vm_insert_pfn() returned %d\n", __func__,
			ret);
		sgx_put_backing(backing, false);
		return false;
	}

	/*
	 * The SECINFO field must be 64-byte aligned, copy it to a local
	 * variable that is guaranteed to be aligned as req->secinfo may
	 * or may not be 64-byte aligned, e.g. req may have been allocated
	 * via kzalloc which is not aware of __aligned attributes.
	 */
	memcpy(&secinfo, &req->secinfo, sizeof(secinfo));

	ret = sgx_eadd(encl->secs.epc_page, epc_page, addr, &secinfo, backing);

	sgx_put_backing(backing, false);
	if (ret) {
		sgx_err(encl, "EADD returned %d\n", ret);
		zap_vma_ptes(vma, addr, PAGE_SIZE);
		return false;
	}

	ret = sgx_measure(encl->secs.epc_page, epc_page, req->mrmask);
	if (ret) {
		sgx_err(encl, "EEXTEND returned %d\n", ret);
		zap_vma_ptes(vma, addr, PAGE_SIZE);
		return false;
	}

	encl_page->encl = encl;
	encl->secs_child_cnt++;
	sgx_set_epc_page(encl_page, epc_page);
	sgx_set_page_reclaimable(encl_page);
	return true;
}

static void sgx_add_page_worker(struct work_struct *work)
{
	struct sgx_add_page_req *req;
	bool skip_rest = false;
	bool is_empty = false;
	struct sgx_encl *encl;
	struct sgx_epc_page *epc_page;

	encl = container_of(work, struct sgx_encl, add_page_work);

	do {
		schedule();

		mutex_lock(&encl->lock);
		if (encl->flags & SGX_ENCL_DEAD)
			skip_rest = true;

		req = list_first_entry(&encl->add_page_reqs,
				       struct sgx_add_page_req, list);
		list_del(&req->list);
		is_empty = list_empty(&encl->add_page_reqs);
		mutex_unlock(&encl->lock);

		if (skip_rest)
			goto next;

		epc_page = sgx_alloc_page(&req->encl_page->impl, 0);
		down_read(&encl->mm->mmap_sem);
		mutex_lock(&encl->lock);

		if (IS_ERR(epc_page)) {
			sgx_invalidate(encl, false);
			skip_rest = true;
		} else	if (!sgx_process_add_page_req(req, epc_page)) {
			sgx_free_page(epc_page);
			sgx_invalidate(encl, false);
			skip_rest = true;
		}

		mutex_unlock(&encl->lock);
		up_read(&encl->mm->mmap_sem);

next:
		kfree(req);
	} while (!kref_put(&encl->refcount, sgx_encl_release) && !is_empty);
}

static u32 sgx_calc_ssaframesize(u32 miscselect, u64 xfrm)
{
	u32 size_max = PAGE_SIZE;
	u32 size;
	int i;

	for (i = 2; i < 64; i++) {
		if (!((1 << i) & xfrm))
			continue;

		size = SGX_SSA_GPRS_SIZE + sgx_xsave_size_tbl[i];
		if (miscselect & SGX_MISC_EXINFO)
			size += SGX_SSA_MISC_EXINFO_SIZE;

		if (size > size_max)
			size_max = size;
	}

	return (size_max + PAGE_SIZE - 1) >> PAGE_SHIFT;
}

static int sgx_validate_secs(const struct sgx_secs *secs,
			     unsigned long ssaframesize)
{
	int i;

	if (secs->size < (2 * PAGE_SIZE) ||
	    (secs->size & (secs->size - 1)) != 0)
		return -EINVAL;

	if (secs->base & (secs->size - 1))
		return -EINVAL;

	if (secs->attributes & SGX_ATTR_RESERVED_MASK ||
	    secs->miscselect & sgx_misc_reserved)
		return -EINVAL;

	if (secs->attributes & SGX_ATTR_MODE64BIT) {
		if (secs->size > sgx_encl_size_max_64)
			return -EINVAL;
	} else {
		/* On 64-bit architecture allow 32-bit encls only in
		 * the compatibility mode.
		 */
		if (!test_thread_flag(TIF_ADDR32))
			return -EINVAL;
		if (secs->size > sgx_encl_size_max_32)
			return -EINVAL;
	}

	if ((secs->xfrm & 0x3) != 0x3 || (secs->xfrm & ~sgx_xfrm_mask))
		return -EINVAL;

	/* Check that BNDREGS and BNDCSR are equal. */
	if (((secs->xfrm >> 3) & 1) != ((secs->xfrm >> 4) & 1))
		return -EINVAL;

	if (!secs->ssa_frame_size || ssaframesize > secs->ssa_frame_size)
		return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED1_SIZE; i++)
		if (secs->reserved1[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED2_SIZE; i++)
		if (secs->reserved2[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED3_SIZE; i++)
		if (secs->reserved3[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED4_SIZE; i++)
		if (secs->reserved4[i])
			return -EINVAL;

	return 0;
}

static void sgx_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct sgx_encl *encl =
		container_of(mn, struct sgx_encl, mmu_notifier);

	mutex_lock(&encl->lock);
	encl->flags |= SGX_ENCL_DEAD;
	mutex_unlock(&encl->lock);
}

static const struct mmu_notifier_ops sgx_mmu_notifier_ops = {
	.release	= sgx_mmu_notifier_release,
};

static int sgx_encl_grow(struct sgx_encl *encl)
{
	struct sgx_va_page *va_page;
	int ret;

	BUILD_BUG_ON(SGX_VA_SLOT_COUNT !=
		(SGX_ENCL_PAGE_VA_OFFSET_MASK >> 3) + 1);

	mutex_lock(&encl->lock);
	if (!(encl->page_cnt % SGX_VA_SLOT_COUNT)) {
		mutex_unlock(&encl->lock);

		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return -ENOMEM;
		va_page->epc_page = sgx_alloc_va_page(0);
		if (IS_ERR(va_page->epc_page)) {
			ret = PTR_ERR(va_page->epc_page);
			kfree(va_page);
			return ret;
		}

		mutex_lock(&encl->lock);
		if (encl->page_cnt % SGX_VA_SLOT_COUNT) {
			sgx_free_page(va_page->epc_page);
			kfree(va_page);
		} else {
			list_add(&va_page->list, &encl->va_pages);
		}
	}
	encl->page_cnt++;
	mutex_unlock(&encl->lock);
	return 0;
}

/**
 * sgx_encl_alloc - allocate memory for an enclave and set attributes
 *
 * @secs:	SECS data (must be page aligned)
 *
 * Allocates a new &sgx_encl instance. Validates SECS attributes, creates
 * backing storage for the enclave and sets enclave attributes to sane initial
 * values.
 *
 * Return:
 *   an &sgx_encl instance,
 *   -errno otherwise
 */
struct sgx_encl *sgx_encl_alloc(struct sgx_secs *secs)
{
	unsigned long ssaframesize;
	struct sgx_encl *encl;
	struct file *backing;
	struct file *pcmd;

	ssaframesize = sgx_calc_ssaframesize(secs->miscselect, secs->xfrm);
	if (sgx_validate_secs(secs, ssaframesize))
		return ERR_PTR(-EINVAL);

	backing = shmem_file_setup("[dev/sgx]", secs->size + PAGE_SIZE,
				   VM_NORESERVE);
	if (IS_ERR(backing))
		return (void *)backing;

	pcmd = shmem_file_setup("[dev/sgx]", (secs->size + PAGE_SIZE) >> 5,
				VM_NORESERVE);
	if (IS_ERR(pcmd)) {
		fput(backing);
		return (void *)pcmd;
	}

	encl = kzalloc(sizeof(*encl), GFP_KERNEL);
	if (!encl) {
		fput(backing);
		fput(pcmd);
		return ERR_PTR(-ENOMEM);
	}

	encl->attributes = secs->attributes;
	encl->xfrm = secs->xfrm;

	kref_init(&encl->refcount);
	INIT_LIST_HEAD(&encl->add_page_reqs);
	INIT_LIST_HEAD(&encl->va_pages);
	INIT_RADIX_TREE(&encl->page_tree, GFP_KERNEL);
	mutex_init(&encl->lock);
	INIT_WORK(&encl->add_page_work, sgx_add_page_worker);

	encl->mm = current->mm;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->ssaframesize = secs->ssa_frame_size;
	encl->backing = backing;
	encl->pcmd = pcmd;

	return encl;
}

static int sgx_encl_pm_notifier(struct notifier_block *nb,
				unsigned long action, void *data)
{
	struct sgx_encl *encl = container_of(nb, struct sgx_encl, pm_notifier);

	if (action != PM_SUSPEND_PREPARE && action != PM_HIBERNATION_PREPARE)
		return NOTIFY_DONE;

	mutex_lock(&encl->lock);
	sgx_invalidate(encl, false);
	encl->flags |= SGX_ENCL_SUSPEND;
	mutex_unlock(&encl->lock);
	flush_work(&encl->add_page_work);
	return NOTIFY_DONE;
}

/**
 * sgx_encl_create - create an enclave
 *
 * @encl:	an enclave
 * @secs:	page aligned SECS data
 *
 * Validates SECS attributes, allocates an EPC page for the SECS and creates
 * the enclave by performing ECREATE.
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs)
{
	struct vm_area_struct *vma;
	struct sgx_pageinfo pginfo;
	struct sgx_secinfo secinfo;
	struct sgx_epc_page *secs_epc;
	long ret;

	secs_epc = sgx_alloc_page(&encl->secs.impl, 0);
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		return ret;
	}

	sgx_set_epc_page(&encl->secs, secs_epc);
	encl->secs.encl = encl;
	encl->secs.impl.ops = &sgx_encl_page_ops;
	encl->tgid = get_pid(task_tgid(current));

	ret = sgx_encl_grow(encl);
	if (ret)
		return ret;

	pginfo.addr = 0;
	pginfo.contents = (unsigned long)secs;
	pginfo.metadata = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));
	ret = __ecreate((void *)&pginfo, sgx_epc_addr(secs_epc));

	if (ret) {
		sgx_dbg(encl, "ECREATE returned %ld\n", ret);
		return ret;
	}

	if (secs->attributes & SGX_ATTR_DEBUG)
		encl->flags |= SGX_ENCL_DEBUG;

	encl->mmu_notifier.ops = &sgx_mmu_notifier_ops;
	ret = mmu_notifier_register(&encl->mmu_notifier, encl->mm);
	if (ret) {
		if (ret == -EINTR)
			ret = -ERESTARTSYS;
		encl->mmu_notifier.ops = NULL;
		return ret;
	}

	encl->pm_notifier.notifier_call = &sgx_encl_pm_notifier;
	ret = register_pm_notifier(&encl->pm_notifier);
	if (ret) {
		encl->pm_notifier.notifier_call = NULL;
		return ret;
	}

	down_read(&current->mm->mmap_sem);
	ret = sgx_encl_find(current->mm, secs->base, &vma);
	if (ret != -ENOENT) {
		if (!ret)
			ret = -EINVAL;
		up_read(&current->mm->mmap_sem);
		return ret;
	}

	if (vma->vm_start != secs->base ||
	    vma->vm_end != (secs->base + secs->size) ||
	    vma->vm_pgoff != 0) {
		ret = -EINVAL;
		up_read(&current->mm->mmap_sem);
		return ret;
	}

	vma->vm_private_data = encl;
	up_read(&current->mm->mmap_sem);
	return 0;
}

static int sgx_validate_secinfo(struct sgx_secinfo *secinfo)
{
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	u64 perm = secinfo->flags & SGX_SECINFO_PERMISSION_MASK;
	int i;

	if ((secinfo->flags & SGX_SECINFO_RESERVED_MASK) ||
	    ((perm & SGX_SECINFO_W) && !(perm & SGX_SECINFO_R)) ||
	    (page_type != SGX_SECINFO_TCS &&
	     page_type != SGX_SECINFO_REG))
		return -EINVAL;

	for (i = 0; i < SGX_SECINFO_RESERVED_SIZE; i++)
		if (secinfo->reserved[i])
			return -EINVAL;

	return 0;
}

static bool sgx_validate_offset(struct sgx_encl *encl, unsigned long offset)
{
	if (offset & (PAGE_SIZE - 1))
		return false;

	if (offset >= encl->size)
		return false;

	return true;
}

static int sgx_validate_tcs(struct sgx_encl *encl, struct sgx_tcs *tcs)
{
	int i;

	if (tcs->flags & SGX_TCS_RESERVED_MASK)
		return -EINVAL;

	if (tcs->flags & SGX_TCS_DBGOPTIN)
		return -EINVAL;

	if (!sgx_validate_offset(encl, tcs->ssa_offset))
		return -EINVAL;

	if (!sgx_validate_offset(encl, tcs->fs_offset))
		return -EINVAL;

	if (!sgx_validate_offset(encl, tcs->gs_offset))
		return -EINVAL;

	if ((tcs->fs_limit & 0xFFF) != 0xFFF)
		return -EINVAL;

	if ((tcs->gs_limit & 0xFFF) != 0xFFF)
		return -EINVAL;

	for (i = 0; i < SGX_TCS_RESERVED_SIZE; i++)
		if (tcs->reserved[i])
			return -EINVAL;

	return 0;
}

static int __sgx_encl_add_page(struct sgx_encl *encl,
			       struct sgx_encl_page *encl_page,
			       void *data,
			       struct sgx_secinfo *secinfo,
			       unsigned int mrmask)
{
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	struct sgx_add_page_req *req = NULL;
	pgoff_t backing_index;
	struct page *backing;
	void *backing_ptr;
	int empty;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	backing_index = SGX_ENCL_PAGE_BACKING_INDEX(encl_page, encl);
	backing = sgx_get_backing(encl->backing, backing_index);
	if (IS_ERR(backing)) {
		kfree(req);
		return PTR_ERR(backing);
	}
	backing_ptr = kmap(backing);
	memcpy(backing_ptr, data, PAGE_SIZE);
	kunmap(backing);
	if (page_type == SGX_SECINFO_TCS)
		encl_page->desc |= SGX_ENCL_PAGE_TCS;
	memcpy(&req->secinfo, secinfo, sizeof(*secinfo));
	req->encl = encl;
	req->encl_page = encl_page;
	req->mrmask = mrmask;
	empty = list_empty(&encl->add_page_reqs);
	kref_get(&encl->refcount);
	list_add_tail(&req->list, &encl->add_page_reqs);
	if (empty)
		queue_work(sgx_add_page_wq, &encl->add_page_work);
	sgx_put_backing(backing, true /* write */);
	return 0;
}

/**
 * sgx_encl_alloc_page - allocate a new enclave page
 * @encl:	an enclave
 * @addr:	page address in the ELRANGE
 *
 * Return:
 *   an &sgx_encl_page instance on success,
 *   -errno otherwise
 */
struct sgx_encl_page *sgx_encl_alloc_page(struct sgx_encl *encl,
					  unsigned long addr)
{
	struct sgx_encl_page *encl_page;
	int ret;

	if (radix_tree_lookup(&encl->page_tree, PFN_DOWN(addr)))
		return ERR_PTR(-EEXIST);
	encl_page = kzalloc(sizeof(*encl_page), GFP_KERNEL);
	if (!encl_page)
		return ERR_PTR(-ENOMEM);
	encl_page->desc = addr;
	encl_page->impl.ops = &sgx_encl_page_ops;
	encl_page->encl = encl;
	ret = radix_tree_insert(&encl->page_tree, PFN_DOWN(encl_page->desc),
				encl_page);
	if (ret) {
		kfree(encl_page);
		return ERR_PTR(ret);
	}
	return encl_page;
}

/**
 * sgx_encl_free_page - free an enclave page
 * @encl_page:	an enclave page
 */
void sgx_encl_free_page(struct sgx_encl_page *encl_page)
{
	radix_tree_delete(&encl_page->encl->page_tree,
			  PFN_DOWN(encl_page->desc));
	if (encl_page->desc & SGX_ENCL_PAGE_LOADED) {
		WARN_ON(encl_page->desc & SGX_ENCL_PAGE_RECLAIMED);
		sgx_free_page(encl_page->epc_page);
	}
	kfree(encl_page);
}

/**
 * sgx_encl_add_page - add a page to the enclave
 *
 * @encl:	an enclave
 * @addr:	page address in the ELRANGE
 * @data:	page data
 * @secinfo:	page permissions
 * @mrmask:	bitmask to select the 256 byte chunks to be measured
 *
 * Creates a new enclave page and enqueues an EADD operation that will be
 * processed by a worker thread later on.
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
int sgx_encl_add_page(struct sgx_encl *encl, unsigned long addr, void *data,
		      struct sgx_secinfo *secinfo, unsigned int mrmask)
{
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	struct sgx_encl_page *encl_page;
	int ret;

	if (sgx_validate_secinfo(secinfo))
		return -EINVAL;
	if (page_type == SGX_SECINFO_TCS) {
		ret = sgx_validate_tcs(encl, data);
		if (ret)
			return ret;
	}
	ret = sgx_encl_grow(encl);
	if (ret)
		return ret;
	mutex_lock(&encl->lock);
	if (encl->flags & (SGX_ENCL_INITIALIZED | SGX_ENCL_DEAD)) {
		mutex_unlock(&encl->lock);
		return -EINVAL;
	}
	encl_page = sgx_encl_alloc_page(encl, addr);
	if (IS_ERR(encl_page)) {
		mutex_unlock(&encl->lock);
		return PTR_ERR(encl_page);
	}
	ret = __sgx_encl_add_page(encl, encl_page, data, secinfo, mrmask);
	if (ret)
		sgx_encl_free_page(encl_page);
	mutex_unlock(&encl->lock);
	return ret;
}

static int __sgx_get_key_hash(struct crypto_shash *tfm, const void *modulus,
			      void *hash)
{
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;
	shash->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	return crypto_shash_digest(shash, modulus, SGX_MODULUS_SIZE, hash);
}

static int sgx_get_key_hash(const void *modulus, void *hash)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = __sgx_get_key_hash(tfm, modulus, hash);

	crypto_free_shash(tfm);
	return ret;
}

/**
 * sgx_encl_init - perform EINIT for the given enclave
 *
 * @encl:	an enclave
 * @sigstruct:	SIGSTRUCT for the enclave
 * @token:	EINITTOKEN for the enclave
 *
 * Retries a few times in order to perform EINIT operation on an enclave
 * because there could be potentially an interrupt storm.
 *
 * Return:
 *   0 on success,
 *   SGX error code on EINIT failure,
 *   -errno otherwise
 */
int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
		  struct sgx_einittoken *token)
{
	u64 mrsigner[4];
	int ret;
	int i;
	int j;

	ret = sgx_get_key_hash(sigstruct->modulus, mrsigner);
	if (ret)
		return ret;

	flush_work(&encl->add_page_work);

	mutex_lock(&encl->lock);

	if (encl->flags & SGX_ENCL_INITIALIZED) {
		mutex_unlock(&encl->lock);
		return 0;
	}
	if (encl->flags & SGX_ENCL_DEAD) {
		mutex_unlock(&encl->lock);
		return -EFAULT;
	}

	for (i = 0; i < SGX_EINIT_SLEEP_COUNT; i++) {
		for (j = 0; j < SGX_EINIT_SPIN_COUNT; j++) {
			ret = sgx_einit(sigstruct, token, encl->secs.epc_page,
					mrsigner);
			if (ret == SGX_UNMASKED_EVENT)
				continue;
			else
				break;
		}

		if (ret != SGX_UNMASKED_EVENT)
			break;

		msleep_interruptible(SGX_EINIT_SLEEP_TIME);
		if (signal_pending(current)) {
			mutex_unlock(&encl->lock);
			return -ERESTARTSYS;
		}
	}

	if (ret > 0)
		sgx_dbg(encl, "EINIT returned %d\n", ret);
	else if (!ret)
		encl->flags |= SGX_ENCL_INITIALIZED;
	mutex_unlock(&encl->lock);

	return ret;
}

static int sgx_encl_mod(struct sgx_encl_page *encl_page,
			struct sgx_secinfo *secinfo, unsigned int op)
{
	struct sgx_encl *encl = encl_page->encl;
	bool perm = (op == SGX_ENCLAVE_MODIFY_PERMISSIONS);
	int ret;

	if ((encl->flags & SGX_ENCL_DEAD) ||
	    !(encl->flags & SGX_ENCL_INITIALIZED))
		return -EINVAL;

	sgx_encl_block(encl_page);

	if (perm)
		ret = __emodpr(secinfo, sgx_epc_addr(encl_page->epc_page));
	else
		ret = __emodt(secinfo, sgx_epc_addr(encl_page->epc_page));
	SGX_INVD(ret, encl, "EMOD%s returned %d (0x%x)",
		 perm ? "PR" : "T", ret, ret);
	return ret;
}

/**
 * sgx_enclave_modify_pages - modify a range of pages
 * @encl:	an enclave
 * @addr:	address in the ELRANGE
 * @length:	length of the address range (must be multiple of the page size)
 * @secinfo:	a modified SECINFO for the page
 * @op:		a value of &sgx_enclave_modify_ops
 *
 * Modifies permissions or type for a range of pages. The enclave must
 * acknowledge the modifications with EACCEPT. Initializes a new shootdown
 * sequence after applying EMODPR/T operations.
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
int sgx_encl_modify_pages(struct sgx_encl *encl, unsigned long addr,
			  unsigned long length, struct sgx_secinfo *secinfo,
			  unsigned int op)
{
	struct sgx_encl_page *page;
	struct vm_area_struct *vma;
	int ret;

	if (op != SGX_ENCLAVE_MODIFY_PERMISSIONS ||
	    op != SGX_ENCLAVE_MODIFY_TYPES)
		return -EINVAL;

	if ((addr & (PAGE_SIZE - 1)) || (length & (PAGE_SIZE - 1)) ||
	    addr < encl->base || length > encl->size)
		return -EINVAL;

	ret = sgx_validate_secinfo(secinfo);
	if (ret)
		return ret;

	for ( ; addr < (addr + length); addr += PAGE_SIZE) {
		ret = sgx_encl_find(encl->mm, addr, &vma);
		if (!vma) {
			ret = -EFAULT;
			break;
		}

		page = sgx_fault_page(vma, addr, true);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			break;
		}

		down_read(&encl->mm->mmap_sem);
		mutex_lock(&encl->lock);
		ret = sgx_encl_mod(page, secinfo, op);
		mutex_unlock(&encl->lock);
		up_read(&encl->mm->mmap_sem);
		if (ret)
			break;
	}

	down_read(&encl->mm->mmap_sem);
	mutex_lock(&encl->lock);
	if (!(encl->flags & SGX_ENCL_DEAD) &&
	    (encl->flags & SGX_ENCL_INITIALIZED)) {
		sgx_flush_cpus(encl);
		sgx_encl_track(encl);
	}
	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);
	return ret;
}


/**
 * sgx_encl_block - block an enclave page
 * @encl_page:	an enclave page
 *
 * Changes the state of the associated EPC page to blocked.
 */
void sgx_encl_block(struct sgx_encl_page *encl_page)
{
	unsigned long addr = SGX_ENCL_PAGE_ADDR(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	struct vm_area_struct *vma;
	int ret;

	if (encl->flags & SGX_ENCL_DEAD)
		return;

	ret = sgx_encl_find(encl->mm, addr, &vma);
	if (ret || encl != vma->vm_private_data)
		return;

	zap_vma_ptes(vma, addr, PAGE_SIZE);
	ret = __eblock(sgx_epc_addr(encl_page->epc_page));
	SGX_INVD(ret, encl, "EBLOCK returned %d (0x%x)", ret, ret);
}

/**
 * sgx_encl_track - start tracking pages in the blocked state
 * @encl:	an enclave
 *
 * Start blocking accesses for pages in the blocked state for threads that enter
 * inside the enclave by executing the ETRACK leaf instruction. This starts a
 * shootdown sequence for threads that entered before ETRACK.
 *
 * The caller must take care (with an IPI when necessary) to make sure that the
 * previous shootdown sequence was completed before calling this function.  If
 * this is not the case, the callee prints a critical error to the klog and
 * kills the enclave.
 */
void sgx_encl_track(struct sgx_encl *encl)
{
	int ret = __etrack(sgx_epc_addr(encl->secs.epc_page));

	SGX_INVD(ret, encl, "ETRACK returned %d (0x%x)", ret, ret);
}

/**
 * sgx_encl_load_page - load an enclave page
 * @encl_page:	a &sgx_encl_page
 * @epc_page:	a &sgx_epc_page
 *
 * Loads an enclave page from the regular memory to the EPC. The pages, which
 * are not children of a SECS (eg SECS itself and VA pages) should set their
 * address to zero.
 */
int sgx_encl_load_page(struct sgx_encl_page *encl_page,
		       struct sgx_epc_page *epc_page)
{
	unsigned long addr = SGX_ENCL_PAGE_ADDR(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_pageinfo pginfo;
	unsigned long pcmd_offset;
	unsigned long va_offset;
	pgoff_t backing_index;
	struct page *backing;
	struct page *pcmd;
	void *va_ptr;
	int ret;

	backing_index = SGX_ENCL_PAGE_BACKING_INDEX(encl_page, encl);
	pcmd_offset = SGX_ENCL_PAGE_PCMD_OFFSET(encl_page, encl);
	va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);

	backing = sgx_get_backing(encl->backing, backing_index);
	if (IS_ERR(backing))
		return PTR_ERR(backing);

	pcmd = sgx_get_backing(encl->pcmd, backing_index >> 5);
	if (IS_ERR(pcmd)) {
		sgx_put_backing(backing, false);
		return PTR_ERR(pcmd);
	}


	va_ptr = sgx_epc_addr(encl_page->va_page->epc_page) + va_offset;

	pginfo.addr = addr;
	pginfo.contents = (unsigned long)kmap_atomic(backing);
	pginfo.metadata = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.secs = addr ? (unsigned long)sgx_epc_addr(encl->secs.epc_page) :
		      0;

	ret = __eldu(&pginfo, sgx_epc_addr(epc_page), va_ptr);
	if (ret) {
		sgx_err(encl, "ELDU returned %d\n", ret);
		ret = encls_to_err(ret);
	}

	kunmap_atomic((void *)(unsigned long)(pginfo.metadata - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	sgx_put_backing(pcmd, false);
	sgx_put_backing(backing, false);
	return ret;
}

/**
 * sgx_encl_release - destroy an enclave instance
 *
 * @kref:	address of a kref inside &sgx_encl
 *
 * Used together with kref_put(). Frees all the resources associated with the
 * enclave and the instance itself.
 */
void sgx_encl_release(struct kref *ref)
{
	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);
	struct sgx_encl_page *entry;
	struct radix_tree_iter iter;
	struct sgx_va_page *va_page;
	void **slot;

	if (encl->mmu_notifier.ops) {
		mmu_notifier_unregister_no_release(&encl->mmu_notifier,
						   encl->mm);
		encl->mmu_notifier.ops = NULL;
	}

	if (encl->pm_notifier.notifier_call) {
		unregister_pm_notifier(&encl->pm_notifier);
		encl->pm_notifier.notifier_call = NULL;
	}

	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;
		sgx_encl_free_page(entry);
	}

	if (encl->tgid) {
		put_pid(encl->tgid);
		encl->tgid = NULL;
	}

	while (!list_empty(&encl->va_pages)) {
		va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
					   list);
		list_del(&va_page->list);
		sgx_free_page(va_page->epc_page);
		kfree(va_page);
	}

	if (encl->secs.desc & SGX_ENCL_PAGE_LOADED)
		sgx_free_page(encl->secs.epc_page);

	if (encl->backing) {
		fput(encl->backing);
		encl->backing = NULL;
	}

	if (encl->pcmd) {
		fput(encl->pcmd);
		encl->pcmd = NULL;
	}

	kfree(encl);
}
