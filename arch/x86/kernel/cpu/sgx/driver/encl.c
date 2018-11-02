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
#include "driver.h"

struct sgx_add_page_req {
	struct sgx_encl *encl;
	struct sgx_encl_page *encl_page;
	struct sgx_secinfo secinfo;
	unsigned long mrmask;
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

static void sgx_free_va_pages(struct sgx_encl *encl)
{
	struct sgx_va_page *va_page;

	while (!list_empty(&encl->va_pages)) {
		va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
					   list);
		list_del(&va_page->list);
		sgx_free_page(va_page->epc_page);
		kfree(va_page);
	}
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

	encl->flags |= SGX_ENCL_DEAD;

	if (flush_cpus && (encl->flags & SGX_ENCL_INITIALIZED)) {
		radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
			entry = *slot;
			addr = SGX_ENCL_PAGE_ADDR(entry);
			if (entry->epc_page &&
			    (entry->desc & SGX_ENCL_PAGE_TCS) &&
			    !sgx_encl_find(encl->mm, addr, &vma))
				zap_vma_ptes(vma, addr, PAGE_SIZE);
		}
		sgx_flush_cpus(encl);
	}

	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;
		/*
		 * If the page has RECLAIMED set, the reclaimer effectively
		 * owns the page, i.e. we need to let the reclaimer free it.
		 */
		if (entry->epc_page &&
		    !(entry->desc & SGX_ENCL_PAGE_RECLAIMED)) {
			if (!__sgx_free_page(entry->epc_page)) {
				encl->secs_child_cnt--;
				entry->epc_page = NULL;
			}
		}
	}

	if (!encl->secs_child_cnt && encl->secs.epc_page) {
		sgx_free_page(encl->secs.epc_page);
		encl->secs.epc_page = NULL;
	}
	sgx_free_va_pages(encl);
}

static bool sgx_process_add_page_req(struct sgx_add_page_req *req,
				     struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = req->encl_page;
	struct sgx_encl *encl = req->encl;
	unsigned long page_index = sgx_encl_get_index(encl, encl_page);
	unsigned long backing_addr = encl->backing + page_index * PAGE_SIZE;
	struct sgx_secinfo secinfo;
	struct sgx_pageinfo pginfo;
	struct vm_area_struct *vma;
	struct page *backing;
	unsigned long addr;
	int ret;
	int i;

	if (encl->flags & (SGX_ENCL_SUSPEND | SGX_ENCL_DEAD))
		return false;

	addr = SGX_ENCL_PAGE_ADDR(encl_page);
	ret = sgx_encl_find(encl->mm, addr, &vma);
	if (ret)
		return false;

	ret = get_user_pages_remote(NULL, encl->mm, backing_addr, 1, 0,
				    &backing, NULL, NULL);
	if (ret < 0)
		return false;

	/*
	 * The SECINFO field must be 64-byte aligned, copy it to a local
	 * variable that is guaranteed to be aligned as req->secinfo may
	 * or may not be 64-byte aligned, e.g. req may have been allocated
	 * via kzalloc which is not aware of __aligned attributes.
	 */
	memcpy(&secinfo, &req->secinfo, sizeof(secinfo));

	pginfo.secs = (unsigned long)sgx_epc_addr(encl->secs.epc_page);
	pginfo.addr = addr;
	pginfo.metadata = (unsigned long)&secinfo;
	pginfo.contents = (unsigned long)kmap_atomic(backing);
	ret = __eadd(&pginfo, sgx_epc_addr(epc_page));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	put_page(backing);
	if (ret) {
		SGX_INVD(ret, encl, "EADD returned %d (0x%x)", ret, ret);
		return false;
	}

	for_each_set_bit(i, &req->mrmask, 16) {
		ret = __eextend(sgx_epc_addr(encl->secs.epc_page),
				sgx_epc_addr(epc_page) + (i * 0x100));
		if (ret) {
			SGX_INVD(ret, encl, "EEXTEND returned %d (0x%x)", ret,
				 ret);
			return false;
		}
	}

	encl_page->encl = encl;
	encl_page->epc_page = epc_page;
	encl->secs_child_cnt++;
	sgx_test_and_clear_young(encl_page);
	sgx_page_reclaimable(encl_page->epc_page);

	return true;
}

static void sgx_add_page_worker(struct work_struct *work)
{
	struct sgx_add_page_req *req;
	bool skip_rest = false;
	bool is_empty = false;
	struct sgx_encl *encl;
	struct sgx_epc_page *epc_page;

	encl = container_of(work, struct sgx_encl, work);

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

		epc_page = sgx_alloc_page(req->encl_page, true);
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

	return PFN_UP(size_max);
}

static int sgx_validate_secs(const struct sgx_secs *secs,
			     unsigned long ssaframesize)
{
	if (secs->size < (2 * PAGE_SIZE) || !is_power_of_2(secs->size))
		return -EINVAL;

	if (secs->base & (secs->size - 1))
		return -EINVAL;

	if (secs->miscselect & sgx_misc_reserved_mask ||
	    secs->attributes & sgx_attributes_reserved_mask ||
	    secs->xfrm & sgx_xfrm_reserved_mask)
		return -EINVAL;

	if (secs->attributes & SGX_ATTR_MODE64BIT) {
		if (secs->size > sgx_encl_size_max_64)
			return -EINVAL;
	} else if (secs->size > sgx_encl_size_max_32)
		return -EINVAL;

	if (!(secs->xfrm & XFEATURE_MASK_FP) ||
	    !(secs->xfrm & XFEATURE_MASK_SSE) ||
	    (((secs->xfrm >> XFEATURE_BNDREGS) & 1) !=
	     ((secs->xfrm >> XFEATURE_BNDCSR) & 1)))
		return -EINVAL;

	if (!secs->ssa_frame_size || ssaframesize > secs->ssa_frame_size)
		return -EINVAL;

	if (memchr_inv(secs->reserved1, 0, SGX_SECS_RESERVED1_SIZE) ||
	    memchr_inv(secs->reserved2, 0, SGX_SECS_RESERVED2_SIZE) ||
	    memchr_inv(secs->reserved3, 0, SGX_SECS_RESERVED3_SIZE) ||
	    memchr_inv(secs->reserved4, 0, SGX_SECS_RESERVED4_SIZE))
		return -EINVAL;

	return 0;
}

static void sgx_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct sgx_encl *encl =
		container_of(mn, struct sgx_encl, mmu_notifier);

	mutex_lock(&encl->lock);
	encl->flags |= SGX_ENCL_DEAD | SGX_ENCL_MM_RELEASED;
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
	if (encl->flags & SGX_ENCL_DEAD) {
		mutex_unlock(&encl->lock);
		return -EFAULT;
	}

	if (!(encl->page_cnt % SGX_VA_SLOT_COUNT)) {
		mutex_unlock(&encl->lock);

		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return -ENOMEM;
		va_page->epc_page = sgx_alloc_va_page();
		if (IS_ERR(va_page->epc_page)) {
			ret = PTR_ERR(va_page->epc_page);
			kfree(va_page);
			return ret;
		}

		mutex_lock(&encl->lock);
		if (encl->flags & SGX_ENCL_DEAD) {
			sgx_free_page(va_page->epc_page);
			kfree(va_page);
			mutex_unlock(&encl->lock);
			return -EFAULT;
		} else if (encl->page_cnt % SGX_VA_SLOT_COUNT) {
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
	unsigned long backing_size = secs->size + PAGE_SIZE;
	unsigned long ssaframesize;
	struct sgx_encl *encl;
	unsigned long backing;
	int ret;

	ssaframesize = sgx_calc_ssaframesize(secs->miscselect, secs->xfrm);
	if (sgx_validate_secs(secs, ssaframesize))
		return ERR_PTR(-EINVAL);

	backing = vm_mmap(NULL, 0, backing_size + (backing_size >> 5),
			  PROT_READ | PROT_WRITE, MAP_PRIVATE, 0);
	if (IS_ERR((void *)backing)) {
		ret = PTR_ERR((void *)backing);
		goto err_backing;
	}

	encl = kzalloc(sizeof(*encl), GFP_KERNEL);
	if (!encl) {
		ret = -ENOMEM;
		goto err_alloc;
	}

	encl->secs_attributes = secs->attributes;
	encl->allowed_attributes = SGX_ATTR_ALLOWED_MASK;
	kref_init(&encl->refcount);
	INIT_LIST_HEAD(&encl->add_page_reqs);
	INIT_LIST_HEAD(&encl->va_pages);
	INIT_RADIX_TREE(&encl->page_tree, GFP_KERNEL);
	mutex_init(&encl->lock);
	INIT_WORK(&encl->work, sgx_add_page_worker);
	encl->mm = current->mm;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->ssaframesize = secs->ssa_frame_size;
	encl->backing = backing;

	return encl;

err_alloc:
	vm_munmap((unsigned long)backing, backing_size + (backing_size >> 5));

err_backing:
	return ERR_PTR(ret);
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
	flush_work(&encl->work);
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

	secs_epc = sgx_alloc_page(&encl->secs, true);
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		return ret;
	}

	encl->secs.encl = encl;
	encl->secs.epc_page = secs_epc;
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
	unsigned long page_index = sgx_encl_get_index(encl, encl_page);
	unsigned long backing_addr = encl->backing + page_index * PAGE_SIZE;
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	struct sgx_add_page_req *req = NULL;
	struct page *backing;
	void *backing_ptr;
	int empty;
	int ret;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	ret = get_user_pages(backing_addr, 1, FOLL_WRITE, &backing, NULL);
	if (ret < 0) {
		kfree(req);
		return ret;
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
		queue_work(sgx_encl_wq, &encl->work);
	set_page_dirty(backing);
	put_page(backing);
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

	down_read(&current->mm->mmap_sem);
	mutex_lock(&encl->lock);

	if (encl->flags & (SGX_ENCL_INITIALIZED | SGX_ENCL_DEAD)) {
		ret = -EINVAL;
		goto out;
	}

	encl_page = sgx_encl_alloc_page(encl, addr);
	if (IS_ERR(encl_page)) {
		ret = PTR_ERR(encl_page);
		goto out;
	}

	ret = __sgx_encl_add_page(encl, encl_page, data, secinfo, mrmask);
	if (ret) {
		radix_tree_delete(&encl_page->encl->page_tree,
				  PFN_DOWN(encl_page->desc));
		kfree(encl_page);
	}

out:
	mutex_unlock(&encl->lock);
	up_read(&current->mm->mmap_sem);
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

	/* Check that the required attributes have been authorized. */
	if (encl->secs_attributes & ~encl->allowed_attributes)
		return -EINVAL;

	ret = sgx_get_key_hash(sigstruct->modulus, mrsigner);
	if (ret)
		return ret;

	flush_work(&encl->work);

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

	if (unlikely(IS_ENCLS_FAULT(ret)))
		SGX_INVD(ret, encl, "EINIT returned %d (%x)", ret, ret);
	else if (ret > 0)
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

	sgx_encl_eblock(encl_page);

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

		down_read(&encl->mm->mmap_sem);

		page = sgx_reserve_page(vma, addr);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			up_read(&encl->mm->mmap_sem);
			break;
		}

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
		sgx_encl_etrack(encl);
	}
	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);
	return ret;
}

static void sgx_encl_release_worker(struct work_struct *work)
{
	struct sgx_encl *encl = container_of(work, struct sgx_encl, work);
	unsigned long backing_size = encl->size + PAGE_SIZE;

	if (!(encl->flags & SGX_ENCL_MM_RELEASED)) {
		down_write(&encl->mm->mmap_sem);
		do_munmap(encl->mm, (unsigned long)encl->backing, backing_size +
			  (backing_size >> 5), NULL);
		up_write(&encl->mm->mmap_sem);
	}

	if (encl->mmu_notifier.ops)
		mmu_notifier_unregister(&encl->mmu_notifier, encl->mm);

	if (encl->tgid)
		put_pid(encl->tgid);

	kfree(encl);
}

/**
 * sgx_encl_release - destroy an enclave instance
 * @kref:	address of a kref inside &sgx_encl
 *
 * Used together with kref_put(). Frees all the resources associated with the
 * enclave and the instance itself. Done as a deferred call so that we can
 * freely use mmap_sem.
 */
void sgx_encl_release(struct kref *ref)
{
	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);

	if (encl->pm_notifier.notifier_call)
		unregister_pm_notifier(&encl->pm_notifier);

	sgx_invalidate(encl, false);

	INIT_WORK(&encl->work, sgx_encl_release_worker);
	queue_work(sgx_encl_wq, &encl->work);
}

/**
 * sgx_encl_get_index() - convert page descriptor to a page index
 * @encl:	an enclave
 * @page:	an enclave page
 *
 * Given an enclave page descriptor, convert it to a page index used to access
 * backing storage. The backing page for SECS is located after the enclave
 * pages.
 */
pgoff_t sgx_encl_get_index(struct sgx_encl *encl, struct sgx_encl_page *page)
{
	if (!PFN_DOWN(page->desc))
		return PFN_DOWN(encl->size);

	return PFN_DOWN(page->desc - encl->base);
}
