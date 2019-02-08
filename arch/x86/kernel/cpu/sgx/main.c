// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "sgx.h"

/**
 * enum sgx_swap_constants - the constants used by the swapping code
 * %SGX_NR_TO_SCAN:	the number of pages to scan in a single round
 * %SGX_NR_LOW_PAGES:	the low watermark for ksgxswapd when it starts to swap
 *			pages.
 * %SGX_NR_HIGH_PAGES:	the high watermark for ksgxswapd what it stops swapping
 *			pages.
 */
enum sgx_swap_constants {
	SGX_NR_TO_SCAN		= 16,
	SGX_NR_LOW_PAGES	= 32,
	SGX_NR_HIGH_PAGES	= 64,
};

struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];

static int sgx_nr_epc_sections;
static LIST_HEAD(sgx_active_page_list);
static DEFINE_SPINLOCK(sgx_active_page_list_lock);
static struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

/* A per-cpu cache for the last known values of IA32_SGXLEPUBKEYHASHx MSRs. */
static DEFINE_PER_CPU(u64 [4], sgx_lepubkeyhash_cache);

static void sgx_section_put_page(struct sgx_epc_section *section,
				 struct sgx_epc_page *page)
{
	list_add_tail(&page->list, &section->page_list);
	section->free_cnt++;
}

static struct sgx_epc_page *sgx_section_get_page(
	struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	if (!section->free_cnt)
		return NULL;

	page = list_first_entry(&section->page_list,
				struct sgx_epc_page, list);
	list_del_init(&page->list);
	section->free_cnt--;
	return page;
}

/**
 * sgx_reclaim_pages - reclaim EPC pages from the consumers
 *
 * Takes a fixed chunk of pages from the global list of consumed EPC pages and
 * tries to swap them. Only the pages that are either being freed by the
 * consumer or actively used are skipped.
 */
static void sgx_reclaim_pages(void)
{
	struct sgx_epc_page *chunk[SGX_NR_TO_SCAN + 1];
	struct sgx_epc_page *epc_page;
	struct sgx_epc_section *section;
	int i, j;

	spin_lock(&sgx_active_page_list_lock);
	for (i = 0, j = 0; i < SGX_NR_TO_SCAN; i++) {
		if (list_empty(&sgx_active_page_list))
			break;

		epc_page = list_first_entry(&sgx_active_page_list,
					    struct sgx_epc_page, list);
		list_del_init(&epc_page->list);

		if (sgx_encl_page_get(epc_page))
			chunk[j++] = epc_page;
		else
			/* The owner is freeing the page. No need to add the
			 * page back to the list of reclaimable pages.
			 */
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
	}
	spin_unlock(&sgx_active_page_list_lock);

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (sgx_encl_page_reclaim(epc_page))
			continue;

		sgx_encl_page_put(epc_page);

		spin_lock(&sgx_active_page_list_lock);
		list_add_tail(&epc_page->list, &sgx_active_page_list);
		spin_unlock(&sgx_active_page_list_lock);

		chunk[i] = NULL;
	}

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page)
			sgx_encl_page_block(epc_page);
	}

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page) {
			sgx_encl_page_write(epc_page);
			sgx_encl_page_put(epc_page);
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;

			section = sgx_epc_section(epc_page);
			spin_lock(&section->lock);
			sgx_section_put_page(section, epc_page);
			spin_unlock(&section->lock);
		}
	}
}

static unsigned long sgx_calc_free_cnt(void)
{
	struct sgx_epc_section *section;
	unsigned long free_cnt = 0;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++) {
		section = &sgx_epc_sections[i];
		free_cnt += section->free_cnt;
	}

	return free_cnt;
}

static inline bool sgx_should_reclaim(void)
{
	return sgx_calc_free_cnt() < SGX_NR_HIGH_PAGES &&
	       !list_empty(&sgx_active_page_list);
}

static int ksgxswapd(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxswapd_waitq, kthread_should_stop() ||
						      sgx_should_reclaim());

		if (sgx_should_reclaim())
			sgx_reclaim_pages();

		cond_resched();
	}

	return 0;
}

static struct sgx_epc_page *sgx_try_alloc_page(void *owner)
{
	struct sgx_epc_section *section;
	struct sgx_epc_page *page;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++) {
		section = &sgx_epc_sections[i];
		spin_lock(&section->lock);
		page = sgx_section_get_page(section);
		spin_unlock(&section->lock);

		if (page) {
			page->owner = owner;
			return page;
		}
	}

	return NULL;
}

/**
 * sgx_alloc_page - Allocate an EPC page
 * @owner:	the owner of the EPC page
 * @reclaim:	reclaim pages if necessary
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. The @reclaim parameter hints
 * the EPC memory manager to swap pages when required.
 *
 * Return:
 *   a pointer to a &struct sgx_epc_page instance,
 *   -errno on error
 */
struct sgx_epc_page *sgx_alloc_page(void *owner, bool reclaim)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_try_alloc_page(owner);
		if (entry)
			break;

		if (list_empty(&sgx_active_page_list))
			return ERR_PTR(-ENOMEM);

		if (!reclaim) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_reclaim_pages();
		schedule();
	}

	if (sgx_calc_free_cnt() < SGX_NR_LOW_PAGES)
		wake_up(&ksgxswapd_waitq);

	return entry;
}

/**
 * __sgx_free_page - Free an EPC page
 * @page:	pointer a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.  If the
 * page is reclaimable, delete it from the active page list.
 *
 * Return:
 *   0 on success
 *   -EBUSY if the page cannot be removed from the active list
 *   SGX error code if EREMOVE fails
 */
int __sgx_free_page(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_epc_section(page);
	int ret;

	/*
	 * Remove the page from the active list if necessary.  If the page
	 * is actively being reclaimed, i.e. RECLAIMABLE is set but the
	 * page isn't on the active list, return -EBUSY as we can't free
	 * the page at this time since it is "owned" by the reclaimer.
	 */
	spin_lock(&sgx_active_page_list_lock);
	if (page->desc & SGX_EPC_PAGE_RECLAIMABLE) {
		if (list_empty(&page->list)) {
			spin_unlock(&sgx_active_page_list_lock);
			return -EBUSY;
		}
		list_del(&page->list);
		page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
	}
	spin_unlock(&sgx_active_page_list_lock);

	ret = __eremove(sgx_epc_addr(page));
	if (ret)
		return ret;

	spin_lock(&section->lock);
	sgx_section_put_page(section, page);
	spin_unlock(&section->lock);

	return 0;
}

/**
 * sgx_free_page - Free an EPC page and WARN on failure
 * @page:	pointer to a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.  If the
 * page is reclaimable, delete it from the active page list.  WARN on any
 * failure.  For use when the call site cannot (or chooses not to) handle
 * failure, i.e. the page is leaked on failure.
 */
void sgx_free_page(struct sgx_epc_page *page)
{
	int ret;

	ret = __sgx_free_page(page);
	WARN(ret < 0, "sgx: cannot free page, reclaim in-progress");
	WARN(ret > 0, "sgx: EREMOVE returned %d (0x%x)", ret, ret);
}

static void sgx_update_lepubkeyhash_msrs(u64 *lepubkeyhash, bool enforce)
{
	u64 __percpu *cache;
	int i;

	cache = per_cpu(sgx_lepubkeyhash_cache, smp_processor_id());
	for (i = 0; i < 4; i++) {
		if (enforce || (lepubkeyhash[i] != cache[i])) {
			wrmsrl(MSR_IA32_SGXLEPUBKEYHASH0 + i, lepubkeyhash[i]);
			cache[i] = lepubkeyhash[i];
		}
	}
}

/**
 * sgx_einit - initialize an enclave
 * @sigstruct:		a pointer a SIGSTRUCT
 * @token:		a pointer an EINITTOKEN (optional)
 * @secs:		a pointer a SECS
 * @lepubkeyhash:	the desired value for IA32_SGXLEPUBKEYHASHx MSRs
 *
 * Execute ENCLS[EINIT], writing the IA32_SGXLEPUBKEYHASHx MSRs according
 * to @lepubkeyhash (if possible and necessary).
 *
 * Return:
 *   0 on success,
 *   -errno or SGX error on failure
 */
int sgx_einit(struct sgx_sigstruct *sigstruct, struct sgx_einittoken *token,
	      struct sgx_epc_page *secs, u64 *lepubkeyhash)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX_LC))
		return __einit(sigstruct, token, sgx_epc_addr(secs));

	preempt_disable();
	sgx_update_lepubkeyhash_msrs(lepubkeyhash, false);
	ret = __einit(sigstruct, token, sgx_epc_addr(secs));
	if (ret == SGX_INVALID_EINITTOKEN) {
		sgx_update_lepubkeyhash_msrs(lepubkeyhash, true);
		ret = __einit(sigstruct, token, sgx_epc_addr(secs));
	}
	preempt_enable();
	return ret;
}

/**
 * sgx_page_reclaimable - mark a page as reclaimable
 *
 * @page:	EPC page
 *
 * Mark a page as reclaimable and add it to the active page list.  Pages
 * are automatically removed from the active list when freed.
 */
void sgx_page_reclaimable(struct sgx_epc_page *page)
{
	spin_lock(&sgx_active_page_list_lock);
	page->desc |= SGX_EPC_PAGE_RECLAIMABLE;
	list_add_tail(&page->list, &sgx_active_page_list);
	spin_unlock(&sgx_active_page_list_lock);
}

static __init void sgx_free_epc_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	while (!list_empty(&section->page_list)) {
		page = list_first_entry(&section->page_list,
					struct sgx_epc_page, list);
		list_del(&page->list);
		kfree(page);
	}
	memunmap(section->va);
}

static __init int sgx_init_epc_section(u64 addr, u64 size, unsigned long index,
				       struct sgx_epc_section *section)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct sgx_epc_page *page;
	unsigned long i;

	section->va = memremap(addr, size, MEMREMAP_WB);
	if (!section->va)
		return -ENOMEM;

	section->pa = addr;
	section->free_cnt = 0;
	spin_lock_init(&section->lock);
	INIT_LIST_HEAD(&section->page_list);

	for (i = 0; i < nr_pages; i++) {
		page = kzalloc(sizeof(*page), GFP_KERNEL);
		if (!page)
			goto out;
		page->desc = (addr + (i << PAGE_SHIFT)) | index;
		sgx_section_put_page(section, page);
	}

	return 0;
out:
	sgx_free_epc_section(section);
	return -ENOMEM;
}

static __init void sgx_page_cache_teardown(void)
{
	int i;

	if (ksgxswapd_tsk) {
		kthread_stop(ksgxswapd_tsk);
		ksgxswapd_tsk = NULL;
	}

	for (i = 0; i < sgx_nr_epc_sections; i++)
		sgx_free_epc_section(&sgx_epc_sections[i]);

	sgx_nr_epc_sections = 0;
}

/**
 * A section metric is concatenated in a way that @low bits 12-31 define the
 * bits 12-31 of the metric and @high bits 0-19 define the bits 32-51 of the
 * metric.
 */
static inline u64 sgx_calc_section_metric(u64 low, u64 high)
{
	return (low & GENMASK_ULL(31, 12)) +
	       ((high & GENMASK_ULL(19, 0)) << 32);
}

static __init int sgx_page_cache_init(void)
{
	u32 eax, ebx, ecx, edx, type;
	u64 pa, size;
	int ret;
	int i;

	BUILD_BUG_ON(SGX_MAX_EPC_SECTIONS > (SGX_EPC_SECTION_MASK + 1));

	for (i = 0; i < (SGX_MAX_EPC_SECTIONS + 1); i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_FIRST_VARIABLE_SUB_LEAF,
			    &eax, &ebx, &ecx, &edx);

		type = eax & SGX_CPUID_SUB_LEAF_TYPE_MASK;
		if (type == SGX_CPUID_SUB_LEAF_INVALID)
			break;
		if (type != SGX_CPUID_SUB_LEAF_EPC_SECTION) {
			pr_err_once("sgx: Unknown sub-leaf type: %u\n", type);
			return -ENODEV;
		}
		if (i == SGX_MAX_EPC_SECTIONS) {
			pr_warn("sgx: More than "
				__stringify(SGX_MAX_EPC_SECTIONS)
				" EPC sections\n");
			break;
		}

		pa = sgx_calc_section_metric(eax, ebx);
		size = sgx_calc_section_metric(ecx, edx);
		pr_info("sgx: EPC section 0x%llx-0x%llx\n", pa, pa + size - 1);

		ret = sgx_init_epc_section(pa, size, i, &sgx_epc_sections[i]);
		if (ret) {
			sgx_page_cache_teardown();
			return ret;
		}

		sgx_nr_epc_sections++;
	}

	if (!sgx_nr_epc_sections) {
		pr_err("sgx: There are zero EPC sections.\n");
		return -ENODEV;
	}

	return 0;
}

static __init int sgx_init(void)
{
	struct task_struct *tsk;
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX))
		return false;

	ret = sgx_page_cache_init();
	if (ret)
		return ret;

	tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (IS_ERR(tsk)) {
		sgx_page_cache_teardown();
		return PTR_ERR(tsk);
	}
	ksgxswapd_tsk = tsk;

	return 0;
}

arch_initcall(sgx_init);
