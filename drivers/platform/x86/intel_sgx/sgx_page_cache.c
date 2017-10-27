/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 * Sean Christopherson <sean.j.christopherson@intel.com>
 */

#include "sgx.h"
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

LIST_HEAD(sgx_encl_list);
DEFINE_MUTEX(sgx_encl_mutex);

#define ENCL_PAGE(entry) ((struct sgx_encl_page *)((entry)->owner))

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
 * @page:	enclave EPC page to be tested for recent access
 *
 * Checks the Access (A) bit from the PTE corresponding to the
 * enclave page and clears it.  Returns 1 if the page has been
 * recently accessed and 0 if not.
 */
static int sgx_test_and_clear_young(struct sgx_epc_page *epc_page)
{
	struct vm_area_struct *vma;
	int ret;
	struct sgx_encl_page *page = ENCL_PAGE(epc_page);
	if (WARN_ON(!page || !page->encl))
		return 0;

	ret = sgx_encl_find(page->encl->mm, page->addr, &vma);
	if (ret)
		return 0;

	if (page->encl != vma->vm_private_data)
		return 0;

	return apply_to_page_range(vma->vm_mm, page->addr, PAGE_SIZE,
				   sgx_test_and_clear_young_cb, vma->vm_mm);
}

void sgx_activate_page(struct sgx_epc_page *epc_page,
		       struct sgx_encl *encl,
		       struct sgx_encl_page *encl_page)
{
	encl_page->encl = encl;
	encl_page->epc_page = epc_page;

	sgx_test_and_clear_young(epc_page);

	sgx_page_reclaimable(epc_page);
}

static int __sgx_ewb(struct sgx_encl *encl,
		     struct sgx_encl_page *encl_page)
{
	struct sgx_pageinfo pginfo;
	struct page *backing;
	struct page *pcmd;
	unsigned long pcmd_offset;
	void *epc;
	void *va;
	int ret;

	pcmd_offset = ((encl_page->addr >> PAGE_SHIFT) & 31) * 128;

	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		sgx_warn(encl, "pinning the backing page for EWB failed with %d\n",
			 ret);
		return ret;
	}

	pcmd = sgx_get_backing(encl, encl_page, true);
	if (IS_ERR(pcmd)) {
		ret = PTR_ERR(pcmd);
		sgx_warn(encl, "pinning the pcmd page for EWB failed with %d\n",
			 ret);
		goto out;
	}

	epc = sgx_get_page(encl_page->epc_page);
	va = sgx_get_page(encl_page->va_page->epc_page);

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	pginfo.pcmd = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.linaddr = 0;
	pginfo.secs = 0;
	ret = __ewb(&pginfo, epc,
		    (void *)((unsigned long)va + encl_page->va_offset));
	kunmap_atomic((void *)(unsigned long)(pginfo.pcmd - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);

	sgx_put_page(va);
	sgx_put_page(epc);
	sgx_put_backing(pcmd, true);

out:
	sgx_put_backing(backing, true);
	return ret;
}

static bool sgx_ewb(struct sgx_encl *encl,
		    struct sgx_encl_page *entry)
{
	int ret = __sgx_ewb(encl, entry);

	if (ret == SGX_NOT_TRACKED) {
		/* slow path, IPI needed */
		sgx_flush_cpus(encl);
		ret = __sgx_ewb(encl, entry);
	}

	if (ret) {
		/* make enclave inaccessible */
		sgx_invalidate(encl, true);
		if (ret > 0)
			sgx_err(encl, "EWB returned %d, enclave killed\n", ret);
		return false;
	}

	return true;
}

static void sgx_evict_page(struct sgx_encl_page *entry,
			   struct sgx_encl *encl)
{
	sgx_ewb(encl, entry);
	sgx_free_page(entry->epc_page);
	entry->epc_page = NULL;
	entry->flags &= ~SGX_ENCL_PAGE_RESERVED;
}

static void sgx_write_pages(struct sgx_encl *encl, struct list_head *src)
{
	struct sgx_epc_page *entry, *tmp;
	struct vm_area_struct *vma;
	int ret;

	if (list_empty(src))
		return;

	/* EBLOCK */
	list_for_each_entry_safe(entry, tmp, src, list) {
		ret = sgx_encl_find(encl->mm, ENCL_PAGE(entry)->addr, &vma);
		if (!ret && encl == vma->vm_private_data)
			zap_vma_ptes(vma, ENCL_PAGE(entry)->addr, PAGE_SIZE);

		sgx_eblock(encl, entry);
	}

	/* ETRACK */
	sgx_etrack(encl);

	/* EWB */
	while (!list_empty(src)) {
		entry = list_first_entry(src, struct sgx_epc_page, list);
		list_del_init(&entry->list);
		sgx_evict_page(ENCL_PAGE(entry), encl);
		encl->secs_child_cnt--;
	}

	if (!encl->secs_child_cnt && (encl->flags & SGX_ENCL_INITIALIZED)) {
		sgx_evict_page(&encl->secs, encl);
		encl->flags |= SGX_ENCL_SECS_EVICTED;
	}
}

static inline void sgx_age_pages(struct list_head *swap,
				 struct list_head *skip)
{
	struct sgx_epc_page *entry, *tmp;

	if (list_empty(swap))
		return;

	list_for_each_entry_safe(entry, tmp, swap, list) {
		if (sgx_test_and_clear_young(entry))
			list_move_tail(&entry->list, skip);
	}
}

static inline void sgx_reserve_pages(struct list_head *swap,
				     struct list_head *skip)
{
	struct sgx_epc_page *entry, *tmp;

	if (list_empty(swap))
		return;

	list_for_each_entry_safe(entry, tmp, swap, list) {
		if (ENCL_PAGE(entry)->flags & SGX_ENCL_PAGE_RESERVED)
			list_move_tail(&entry->list, skip);
		else
			ENCL_PAGE(entry)->flags |= SGX_ENCL_PAGE_RESERVED;
	}
}

static inline void sgx_del_if_dead(struct sgx_encl *encl,
				   struct list_head *swap,
				   struct list_head *skip)
{
	if (encl->flags & SGX_ENCL_DEAD) {
		list_del_init(swap);
		list_del_init(skip);
	}
}

static int sgx_encl_get_ref(struct sgx_epc_page *epc_page)
{
	struct sgx_encl *encl = ENCL_PAGE(epc_page)->encl;
	if (WARN_ON(!encl))
		return 0;

	if (encl->flags & SGX_ENCL_DEAD)
		return 0;

	return kref_get_unless_zero(&encl->refcount);
}

static void sgx_encl_swap_pages(struct sgx_epc_page *entry,
                                struct list_head *iso)
{
	struct sgx_epc_page *tmp;
	struct sgx_encl *encl;
	struct sgx_encl_page *page = ENCL_PAGE(entry);
	struct sgx_epc_operations *ops = entry->ops;

	LIST_HEAD(swap);
	LIST_HEAD(skip);

	encl = page->encl;
	kref_get(&encl->refcount);

	list_for_each_entry_safe(entry, tmp, iso, list) {
		if (entry->ops != ops)
			continue;

		page = ENCL_PAGE(entry);
		if (!page || page->encl != encl)
			continue;

		kref_put(&encl->refcount, sgx_encl_release);
		list_move_tail(&entry->list, &swap);
	}

	down_read(&encl->mm->mmap_sem);

	sgx_del_if_dead(encl, &swap, &skip);
	sgx_age_pages(&swap, &skip);

	if (!list_empty(&swap)) {
		mutex_lock(&encl->lock);

		sgx_del_if_dead(encl, &swap, &skip);
		sgx_reserve_pages(&swap, &skip);
		sgx_write_pages(encl, &swap);

		mutex_unlock(&encl->lock);
	}

	up_read(&encl->mm->mmap_sem);

	sgx_reclaimable_putback(&skip);

	kref_put(&encl->refcount, sgx_encl_release);
}

struct sgx_epc_operations encl_page_ops = {
        .get_ref = sgx_encl_get_ref,
        .swap_pages = sgx_encl_swap_pages,
};

struct sgx_epc_page *sgx_encl_alloc_page(unsigned int flags,
					 struct sgx_encl_page *owner)
{
	return sgx_alloc_page(flags, owner, &encl_page_ops);
}

/**
 * sgx_drv_free_page - free an EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.
 * If EREMOVE fails, the error is printed out loud as a critical error.
 * It is an indicator of a driver bug if that would happen.
 *
 * @entry:	any EPC page
 * @encl:	enclave that owns the given EPC page
 */
void sgx_drv_free_page(struct sgx_epc_page *entry, struct sgx_encl *encl)
{
	void *epc;
	int ret;

	sgx_page_defunct(entry);

	epc = sgx_get_page(entry);
	ret = __eremove(epc);
	sgx_put_page(epc);

	if (ret)
		sgx_crit(encl, "EREMOVE returned %d\n", ret);

	sgx_free_page(entry);
}
