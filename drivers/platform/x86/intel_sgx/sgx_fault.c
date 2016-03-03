// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include "sgx.h"

static int sgx_test_and_clear_young_cb(pte_t *ptep, pgtable_t token,
				       unsigned long addr, void *data)
{
	pte_t pte;
	int ret;

	ret = pte_young(*ptep);
	if (ret) {
		pte = pte_mkold(*ptep);
		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
	}

	return ret;
}

/**
 * sgx_test_and_clear_young() - Test and reset the accessed bit
 * @page:	enclave page to be tested for recent access
 *
 * Checks the Access (A) bit from the PTE corresponding to the
 * enclave page and clears it.  Returns 1 if the page has been
 * recently accessed and 0 if not.
 */
int sgx_test_and_clear_young(struct sgx_encl_page *page)
{
	unsigned long addr = SGX_ENCL_PAGE_ADDR(page);
	struct sgx_encl *encl = page->encl;
	struct vm_area_struct *vma;
	int ret;

	ret = sgx_encl_find(encl->mm, addr, &vma);
	if (ret)
		return 0;

	if (encl != vma->vm_private_data)
		return 0;

	return apply_to_page_range(vma->vm_mm, addr, PAGE_SIZE,
				   sgx_test_and_clear_young_cb, vma->vm_mm);
}

static void sgx_ipi_cb(void *info)
{
}

void sgx_flush_cpus(struct sgx_encl *encl)
{
	on_each_cpu_mask(mm_cpumask(encl->mm), sgx_ipi_cb, NULL, 1);
}

static struct sgx_epc_page *__sgx_load_faulted_page(
	struct sgx_encl_page *encl_page)
{
	unsigned long va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_page(&encl_page->impl, SGX_ALLOC_ATOMIC);
	if (IS_ERR(epc_page))
		return epc_page;
	ret = sgx_encl_load_page(encl_page, epc_page);
	if (ret) {
		sgx_free_page(epc_page);
		return ERR_PTR(ret);
	}
	sgx_free_va_slot(encl_page->va_page, va_offset);
	list_move(&encl_page->va_page->list, &encl->va_pages);
	encl_page->desc &= ~SGX_ENCL_PAGE_VA_OFFSET_MASK;
	sgx_set_epc_page(encl_page, epc_page);
	return epc_page;
}

static struct sgx_encl_page *__sgx_fault_page(struct vm_area_struct *vma,
					      unsigned long addr,
					      bool do_reserve)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_epc_page *epc_page;
	struct sgx_encl_page *entry;
	int rc = 0;

	if ((encl->flags & SGX_ENCL_DEAD) ||
	    !(encl->flags & SGX_ENCL_INITIALIZED))
		return ERR_PTR(-EFAULT);

	entry = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!entry)
		return ERR_PTR(-EFAULT);

	/* Page is already resident in the EPC. */
	if (entry->desc & SGX_ENCL_PAGE_LOADED) {
		if (entry->desc & SGX_ENCL_PAGE_RESERVED) {
			sgx_dbg(encl, "EPC page 0x%p is already reserved\n",
				(void *)SGX_ENCL_PAGE_ADDR(entry));
			return ERR_PTR(-EBUSY);
		}
		if (entry->desc & SGX_ENCL_PAGE_RECLAIMED) {
			sgx_dbg(encl, "EPC page 0x%p is being reclaimed\n",
				(void *)SGX_ENCL_PAGE_ADDR(entry));
			return ERR_PTR(-EBUSY);
		}
		if (do_reserve)
			entry->desc |= SGX_ENCL_PAGE_RESERVED;
		return entry;
	}

	if (!(encl->secs.desc & SGX_ENCL_PAGE_LOADED)) {
		epc_page = __sgx_load_faulted_page(&encl->secs);
		if (IS_ERR(epc_page))
			return (void *)epc_page;
	}
	epc_page = __sgx_load_faulted_page(entry);
	if (IS_ERR(epc_page))
		return (void *)epc_page;

	encl->secs_child_cnt++;
	sgx_set_page_reclaimable(entry);
	if (do_reserve)
		entry->desc |= SGX_ENCL_PAGE_RESERVED;

	rc = vm_insert_pfn(vma, addr, PFN_DOWN(entry->epc_page->desc));
	SGX_INVD(rc, encl, "%s: vm_insert_pfn() returned %d\n", __func__, rc);
	if (rc)
		return ERR_PTR(rc);

	return entry;
}

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr, bool do_reserve)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return ERR_PTR(-EFAULT);
	do {
		mutex_lock(&encl->lock);
		entry = __sgx_fault_page(vma, addr, do_reserve);
		mutex_unlock(&encl->lock);
		if (!do_reserve)
			break;
	} while (PTR_ERR(entry) == -EBUSY);

	return entry;
}
