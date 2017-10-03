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

#define SGX_NR_LOW_EPC_PAGES_DEFAULT 32
#define SGX_NR_SWAP_CLUSTER_MAX	16

static LIST_HEAD(sgx_free_list);
static DEFINE_SPINLOCK(sgx_free_list_lock);
static LIST_HEAD(sgx_global_lru);
static DEFINE_SPINLOCK(sgx_global_lru_lock);

LIST_HEAD(sgx_encl_list);
DEFINE_MUTEX(sgx_encl_mutex);
static unsigned int sgx_nr_total_epc_pages;
static unsigned int sgx_nr_free_pages;
static unsigned int sgx_nr_low_pages = SGX_NR_LOW_EPC_PAGES_DEFAULT;
static unsigned int sgx_nr_high_pages;
static struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

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
static int sgx_test_and_clear_young(struct sgx_encl_page *page)
{
	struct vm_area_struct *vma;
	int ret;

	ret = sgx_encl_find(page->encl->mm, page->addr, &vma);
	if (ret)
		return 0;

	if (page->encl != vma->vm_private_data)
		return 0;

	return apply_to_page_range(vma->vm_mm, page->addr, PAGE_SIZE,
				   sgx_test_and_clear_young_cb, vma->vm_mm);
}

static void sgx_page_reclaimable(struct sgx_epc_page *epc_page)
{
	spin_lock(&sgx_global_lru_lock);
	list_add_tail(&epc_page->list, &sgx_global_lru);
	spin_unlock(&sgx_global_lru_lock);
}

static void sgx_page_defunct(struct sgx_epc_page *epc_page)
{
	if (!list_empty(&epc_page->list)) {
		spin_lock(&sgx_global_lru_lock);
		if (!list_empty(&epc_page->list))
			list_del_init(&epc_page->list);
		spin_unlock(&sgx_global_lru_lock);
	}
}

void sgx_activate_page(struct sgx_epc_page *epc_page,
		       struct sgx_encl *encl,
		       struct sgx_encl_page *encl_page)
{
	epc_page->owner = encl_page;

	encl_page->encl = encl;
	encl_page->epc_page = epc_page;

	sgx_test_and_clear_young(encl_page);

	sgx_page_reclaimable(epc_page);
}

static void sgx_isolate_pages(struct list_head *dst,
			      unsigned long nr_to_scan)
{
	unsigned long i;
	struct sgx_epc_page *entry;

	spin_lock(&sgx_global_lru_lock);

	for (i = 0; i < nr_to_scan; i++) {
		if (list_empty(&sgx_global_lru))
			break;

		entry = list_first_entry(&sgx_global_lru,
					 struct sgx_epc_page,
					 list);

		if ((ENCL_PAGE(entry)->encl->flags & SGX_ENCL_DEAD) ||
		    !kref_get_unless_zero(&ENCL_PAGE(entry)->encl->refcount))
			list_del_init(&entry->list);
		else
			list_move_tail(&entry->list, dst);
	}

	spin_unlock(&sgx_global_lru_lock);
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
	sgx_free_page(entry->epc_page, encl);
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
		if (sgx_test_and_clear_young(ENCL_PAGE(entry)))
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

static void sgx_swap_pages(unsigned long nr_to_scan)
{
	struct sgx_epc_page *entry, *tmp;
	struct sgx_encl *encl;

	LIST_HEAD(iso);
	LIST_HEAD(swap);
	LIST_HEAD(skip);

	sgx_isolate_pages(&iso, nr_to_scan);

	while (!list_empty(&iso)) {
		entry = list_first_entry(&iso, struct sgx_epc_page, list);
		encl = ENCL_PAGE(entry)->encl;
		kref_get(&encl->refcount);

		list_for_each_entry_safe(entry, tmp, &iso, list) {
			if (ENCL_PAGE(entry)->encl != encl)
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

		if (!list_empty(&skip)) {
			spin_lock(&sgx_global_lru_lock);
			list_splice_tail_init(&skip, &sgx_global_lru);
			spin_unlock(&sgx_global_lru_lock);
		}

		kref_put(&encl->refcount, sgx_encl_release);
	}
}

static int ksgxswapd(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxswapd_waitq,
				     kthread_should_stop() ||
				     sgx_nr_free_pages < sgx_nr_high_pages);

		if (sgx_nr_free_pages < sgx_nr_high_pages)
			sgx_swap_pages(SGX_NR_SWAP_CLUSTER_MAX);
	}

	pr_info("%s: done\n", __func__);
	return 0;
}

int sgx_add_epc_bank(resource_size_t start, unsigned long size, int bank)
{
	unsigned long i;
	struct sgx_epc_page *new_epc_page, *entry;
	struct list_head *parser, *temp;

	for (i = 0; i < size; i += PAGE_SIZE) {
		new_epc_page = kzalloc(sizeof(*new_epc_page), GFP_KERNEL);
		if (!new_epc_page)
			goto err_freelist;
		new_epc_page->pa = (start + i) | bank;

		spin_lock(&sgx_free_list_lock);
		list_add_tail(&new_epc_page->list, &sgx_free_list);
		sgx_nr_total_epc_pages++;
		sgx_nr_free_pages++;
		spin_unlock(&sgx_free_list_lock);
	}

	return 0;
err_freelist:
	list_for_each_safe(parser, temp, &sgx_free_list) {
		spin_lock(&sgx_free_list_lock);
		entry = list_entry(parser, struct sgx_epc_page, list);
		list_del(&entry->list);
		spin_unlock(&sgx_free_list_lock);
		kfree(entry);
	}
	return -ENOMEM;
}

int sgx_page_cache_init(void)
{
	struct task_struct *tmp;

	sgx_nr_high_pages = 2 * sgx_nr_low_pages;

	tmp = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (!IS_ERR(tmp))
		ksgxswapd_tsk = tmp;
	return PTR_ERR_OR_ZERO(tmp);
}

void sgx_page_cache_teardown(void)
{
	struct sgx_epc_page *entry;
	struct list_head *parser, *temp;

	if (ksgxswapd_tsk) {
		kthread_stop(ksgxswapd_tsk);
		ksgxswapd_tsk = NULL;
	}

	spin_lock(&sgx_free_list_lock);
	list_for_each_safe(parser, temp, &sgx_free_list) {
		entry = list_entry(parser, struct sgx_epc_page, list);
		list_del(&entry->list);
		kfree(entry);
	}
	spin_unlock(&sgx_free_list_lock);
}

static struct sgx_epc_page *sgx_alloc_page_fast(void)
{
	struct sgx_epc_page *entry = NULL;

	spin_lock(&sgx_free_list_lock);

	if (!list_empty(&sgx_free_list)) {
		entry = list_first_entry(&sgx_free_list, struct sgx_epc_page,
					 list);
		list_del_init(&entry->list);
		sgx_nr_free_pages--;
	}

	spin_unlock(&sgx_free_list_lock);

	return entry;
}

/**
 * sgx_alloc_page - allocate an EPC page
 * @flags:	allocation flags
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. If called with SGX_ALLOC_ATOMIC,
 * the function will return immediately if the list is empty. Otherwise, it
 * will swap pages up until there is a free page available. Before returning
 * the low watermark is checked and ksgxswapd is waken up if we are below it.
 *
 * Return: an EPC page or a system error code
 */
struct sgx_epc_page *sgx_alloc_page(unsigned int flags)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_alloc_page_fast();
		if (entry)
			break;

		if (list_empty(&sgx_global_lru)) {
			entry = ERR_PTR(-ENOMEM);
			break;
		}

		if (flags & SGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_swap_pages(SGX_NR_SWAP_CLUSTER_MAX);
		schedule();
	}

	if (sgx_nr_free_pages < sgx_nr_low_pages)
		wake_up(&ksgxswapd_waitq);

	return entry;
}

/**
 * sgx_free_page - free an EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.
 * If EREMOVE fails, the error is printed out loud as a critical error.
 * It is an indicator of a driver bug if that would happen.
 *
 * @entry:	any EPC page
 * @encl:	enclave that owns the given EPC page
 */
void sgx_free_page(struct sgx_epc_page *entry, struct sgx_encl *encl)
{
	void *epc;
	int ret;

	sgx_page_defunct(entry);

	epc = sgx_get_page(entry);
	ret = __eremove(epc);
	sgx_put_page(epc);

	if (ret)
		sgx_crit(encl, "EREMOVE returned %d\n", ret);

	entry->owner = NULL;

	spin_lock(&sgx_free_list_lock);
	list_add(&entry->list, &sgx_free_list);
	sgx_nr_free_pages++;
	spin_unlock(&sgx_free_list_lock);
}

void *sgx_get_page(struct sgx_epc_page *entry)
{
#ifdef CONFIG_X86_32
	return kmap_atomic_pfn(PFN_DOWN(entry->pa));
#else
	int i = ((entry->pa) & ~PAGE_MASK);

	return (void *)(sgx_epc_banks[i].va +
		((entry->pa & PAGE_MASK) - sgx_epc_banks[i].pa));
#endif
}

void sgx_put_page(void *epc_page_vaddr)
{
#ifdef CONFIG_X86_32
	kunmap_atomic(epc_page_vaddr);
#else
#endif
}
