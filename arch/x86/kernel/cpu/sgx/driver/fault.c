// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include "driver.h"

static struct sgx_encl_page *sgx_try_fault_page(struct vm_area_struct *vma,
						unsigned long addr)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_epc_page *epc_page;
	struct sgx_encl_page *entry;
	unsigned long pfn;
	int rc = 0;

	if ((encl->flags & SGX_ENCL_DEAD) ||
	    !(encl->flags & SGX_ENCL_INITIALIZED))
		return ERR_PTR(-EFAULT);

	entry = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!entry)
		return ERR_PTR(-EFAULT);

	/* Page is already resident in the EPC. */
	if (entry->epc_page) {
		if (entry->desc & SGX_ENCL_PAGE_RECLAIMED) {
			sgx_dbg(encl, "EPC page 0x%p is being reclaimed\n",
				(void *)SGX_ENCL_PAGE_ADDR(entry));
			return ERR_PTR(-EBUSY);
		}

		if (follow_pfn(vma, addr, &pfn))
			goto out_pfn;
		else
			return entry;
	}

	if (!(encl->secs.epc_page)) {
		epc_page = sgx_encl_eldu(&encl->secs);
		if (IS_ERR(epc_page))
			return ERR_CAST(epc_page);
	}

	epc_page = entry->epc_page ? entry->epc_page : sgx_encl_eldu(entry);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	encl->secs_child_cnt++;
	sgx_test_and_clear_young(entry);
	sgx_page_reclaimable(entry->epc_page);

out_pfn:
	rc = vmf_insert_pfn(vma, addr, PFN_DOWN(entry->epc_page->desc));
	if (rc != VM_FAULT_NOPAGE) {
		sgx_invalidate(encl, true);
		return ERR_PTR(-EFAULT);
	}

	return entry;
}

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return ERR_PTR(-EFAULT);

	mutex_lock(&encl->lock);
	entry = sgx_try_fault_page(vma, addr);
	mutex_unlock(&encl->lock);

	return entry;
}
