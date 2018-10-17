// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <asm/sgx.h>
#include <asm/sgx_pr.h>

#include "intel_sgx.h"

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

bool sgx_enabled __ro_after_init;
EXPORT_SYMBOL_GPL(sgx_enabled);
bool sgx_lc_enabled __ro_after_init;
EXPORT_SYMBOL_GPL(sgx_lc_enabled);
struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];
EXPORT_SYMBOL_GPL(sgx_epc_banks);

static struct sgx_epc_lru sgx_global_lru;

static int sgx_nr_epc_banks;
static struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

/*
 * A cache for last known values of IA32_SGXLEPUBKEYHASHx MSRs. Cache entries
 * are initialized when they are first used by sgx_einit().
 */
static DEFINE_PER_CPU(u64 [4], sgx_le_pubkey_hash_cache);

static inline struct sgx_epc_lru *sgx_lru(struct sgx_epc_page *epc_page)
{
	return &sgx_global_lru;
}

/**
 * sgx_isolate_pages - isolate pages from an LRU for reclaim
 * @lru		LRU from which to reclaim
 * @nr_pages	Number of pages to scan for reclaim
 * @dst		Destination list to hold the isolated pages
 */
void sgx_isolate_pages(struct sgx_epc_lru *lru, int *nr_pages,
		       struct list_head *dst)
{
	struct sgx_epc_page *epc_page;

	spin_lock(&lru->lock);
	for (; *nr_pages > 0; --(*nr_pages)) {
		if (list_empty(&lru->reclaimable))
			break;

		epc_page = list_first_entry(&lru->reclaimable,
					    struct sgx_epc_page, list);

		if (epc_page->impl->ops->get(epc_page)) {
			epc_page->desc |= SGX_EPC_PAGE_RECLAIM_IN_PROGRESS;
			list_move_tail(&epc_page->list, dst);
		} else {
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
			list_del_init(&epc_page->list);
		}
	}
	spin_unlock(&lru->lock);
}

/**
 * sgx_reclaim_pages - reclaim EPC pages from the consumers
 *
 * @rc		Reclaim control, e.g. number of pages to scan
 *
 * Return: Number of EPC pages reclaimed.
 *
 * Scan @rc->nr_pages from the global list of reclaimable EPC pages and attempt
 * to them.  Pages that are being freed by the consumer (get() fails) or are
 * actively being used (reclaim() fails) are skipped.  Note that @rc->nr_pages
 * is modified, i.e. multiple calls to sgx_reclaim_pages() with the same struct
 * need to reset rc->nr_pages prior to every call.
 */
int sgx_reclaim_pages(struct sgx_epc_reclaim_control *rc)
{
	struct sgx_epc_page *epc_page, *tmp;
	struct sgx_epc_bank *bank;
	struct sgx_epc_lru *lru;
	int nr_reclaimed = 0;
	LIST_HEAD(iso);

	sgx_isolate_pages(&sgx_global_lru, &rc->nr_pages, &iso);

	if (list_empty(&iso))
		goto out;

	list_for_each_entry_safe(epc_page, tmp, &iso, list) {
		if (epc_page->impl->ops->reclaim(epc_page, false))
			continue;

		epc_page->impl->ops->put(epc_page);

		lru = sgx_lru(epc_page);
		spin_lock(&lru->lock);
		epc_page->desc &= ~SGX_EPC_PAGE_RECLAIM_IN_PROGRESS;
		list_move_tail(&epc_page->list, &lru->reclaimable);
		spin_unlock(&lru->lock);
	}

	if (list_empty(&iso))
		goto out;

	list_for_each_entry(epc_page, &iso, list)
		epc_page->impl->ops->block(epc_page);

	list_for_each_entry_safe(epc_page, tmp, &iso, list) {
		epc_page->impl->ops->write(epc_page);
		epc_page->impl->ops->put(epc_page);

		/*
		 * Put the page back on the free list only after we
		 * have put() our reference to the owner of the EPC
		 * page, otherwise the page could be re-allocated and
		 * we'd call put() on the wrong impl.
		 */
		epc_page->desc &= ~(SGX_EPC_PAGE_RECLAIMABLE |
				    SGX_EPC_PAGE_RECLAIM_IN_PROGRESS);

		list_del_init(&epc_page->list);

		bank = sgx_epc_bank(epc_page);
		spin_lock(&bank->lock);
		bank->pages[bank->free_cnt++] = epc_page;
		spin_unlock(&bank->lock);

		nr_reclaimed++;
	}

out:
	cond_resched();

	return nr_reclaimed;
}

static inline void sgx_global_reclaim_pages(void)
{
	struct sgx_epc_reclaim_control rc;

	sgx_epc_reclaim_control_init(&rc, SGX_NR_TO_SCAN);
	sgx_reclaim_pages(&rc);
}

static inline struct sgx_epc_page *sgx_get_oom_victim(struct sgx_epc_lru *lru)
{
	struct sgx_epc_page *epc_page, *tmp;

	if (list_empty(&lru->unreclaimable))
		return NULL;

	list_for_each_entry_safe(epc_page, tmp, &lru->unreclaimable, list) {
		list_del_init(&epc_page->list);

		if (epc_page->impl->ops->get(epc_page))
			return epc_page;
	}
	return NULL;
}

/**
 * sgx_oom - invoke EPC out-of-memory handling on target LRU
 * @lru		LRU that is OOM
 *
 * Return: %true if a victim was found and signaled
 */
bool sgx_oom(struct sgx_epc_lru *lru)
{
	struct sgx_epc_page *victim;

retry:
	spin_lock(&lru->lock);
	victim = sgx_get_oom_victim(lru);
	spin_unlock(&lru->lock);

	if (!victim)
		return false;
	if (!victim->impl->ops->oom(victim))
		goto retry;
	return true;
}

static unsigned long sgx_calc_free_cnt(void)
{
	struct sgx_epc_bank *bank;
	unsigned long free_cnt = 0;
	int i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		bank = &sgx_epc_banks[i];
		free_cnt += bank->free_cnt;
	}

	return free_cnt;
}

static inline bool sgx_can_reclaim(void)
{
	return !list_empty(&sgx_global_lru.reclaimable);
}

static bool sgx_should_reclaim(void)
{
	return sgx_calc_free_cnt() < SGX_NR_HIGH_PAGES && sgx_can_reclaim();
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
			sgx_global_reclaim_pages();
	}

	return 0;
}

static struct sgx_epc_page *sgx_try_alloc_page(struct sgx_epc_page_impl *impl)
{
	struct sgx_epc_bank *bank;
	struct sgx_epc_page *page;
	int i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		bank = &sgx_epc_banks[i];
		spin_lock(&bank->lock);
		if (bank->free_cnt) {
			page = bank->pages[bank->free_cnt - 1];
			bank->free_cnt--;
		}
		spin_unlock(&bank->lock);

		if (page) {
			page->impl = impl;
			return page;
		}
	}

	return NULL;
}

/**
 * sgx_alloc_page - Allocate an EPC page
 * @flags:	allocation flags
 * @impl:	implementation for the EPC page
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. If called with SGX_ALLOC_ATOMIC,
 * the function will return immediately if the list is empty. Otherwise, it
 * will swap pages up until there is a free page available. Upon returning the
 * low watermark is checked and ksgxswapd is waken up if we are below it.
 *
 * Return:
 *   a pointer to a &struct sgx_epc_page instace,
 *   -ENOMEM if all pages are unreclaimable,
 *   -EBUSY when called with SGX_ALLOC_ATOMIC and out of free pages
 */
struct sgx_epc_page *sgx_alloc_page(struct sgx_epc_page_impl *impl,
				    unsigned int flags)
{
	struct sgx_epc_page *entry;
	struct sgx_epc_lru *lru;

	if (WARN_ON_ONCE(!impl || !impl->ops || !impl->ops->oom))
		return ERR_PTR(-EFAULT);

	for ( ; ; ) {
		entry = sgx_try_alloc_page(impl);
		if (entry)
			break;

		if (!sgx_can_reclaim())
			return ERR_PTR(-ENOMEM);

		if (flags & SGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_global_reclaim_pages();
	}

	if (sgx_calc_free_cnt() < SGX_NR_LOW_PAGES)
		wake_up(&ksgxswapd_waitq);

	if (!IS_ERR(entry)) {
		lru = sgx_lru(entry);
		spin_lock(&lru->lock);
		list_add_tail(&entry->list, &lru->unreclaimable);
		spin_unlock(&lru->lock);
	}

	return entry;
}
EXPORT_SYMBOL_GPL(sgx_alloc_page);

/**
 * __sgx_free_page - Free an EPC page
 * @page:	pointer a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.
 * If the page is reclaimable, deletes it from the active page list.
 *
 * Return:
 *   0 on success
 *   -EBUSY if the page cannot be removed from the active list
 *   SGX error code if EREMOVE fails
 */
int __sgx_free_page(struct sgx_epc_page *page)
{
	struct sgx_epc_bank *bank = sgx_epc_bank(page);
	struct sgx_epc_lru *lru = sgx_lru(page);
	int ret;

	/*
	 * The page may have already been remove from the LRUs, in which
	 * case we can skip taking the LRU lock.  That is, unless the page
	 * is actively being reclaimed, i.e. RECLAIM{ABLE,_IN_PROGRESS} are
	 * both set, in which case return -EBUSY as we can't free the page
	 * at this time since it's "owned" by the reclaimer.
	 */
	if (!list_empty(&page->list) || page->desc & SGX_EPC_PAGE_RECLAIMABLE) {
		spin_lock(&lru->lock);
		if (page->desc & SGX_EPC_PAGE_RECLAIMABLE) {
			if (page->desc & SGX_EPC_PAGE_RECLAIM_IN_PROGRESS) {
				spin_unlock(&lru->lock);
				return -EBUSY;
			}
			page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
		}
		if (!list_empty(&page->list))
			list_del_init(&page->list);
		spin_unlock(&lru->lock);
	}

	ret = __eremove(sgx_epc_addr(page));
	if (ret)
		return ret;

	spin_lock(&bank->lock);
	bank->pages[bank->free_cnt++] = page;
	spin_unlock(&bank->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(__sgx_free_page);

/**
 * sgx_free_page - Free an EPC page and WARN on failure
 * @page:	pointer to a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.
 * If the page is reclaimable, deletes it from the active page list.
 * WARN on any failure.  For use when the call site cannot (or chooses
 * not to) handle failure, i.e. the page is leaked on failure.
 */
void sgx_free_page(struct sgx_epc_page *page)
{
	int ret;

	ret = __sgx_free_page(page);
	WARN(ret < 0, "sgx: cannot free page, reclaim in-progress");
	WARN(ret > 0, "sgx: EREMOVE returned %d (0x%x)", ret, ret);
}
EXPORT_SYMBOL_GPL(sgx_free_page);


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
	struct sgx_epc_lru *lru = sgx_lru(page);

	spin_lock(&lru->lock);
	page->desc |= SGX_EPC_PAGE_RECLAIMABLE;
	list_move_tail(&page->list, &lru->reclaimable);
	spin_unlock(&lru->lock);
}
EXPORT_SYMBOL_GPL(sgx_page_reclaimable);

struct page *sgx_get_backing(struct file *file, pgoff_t index)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfpmask = mapping_gfp_mask(mapping);

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}
EXPORT_SYMBOL_GPL(sgx_get_backing);

void sgx_put_backing(struct page *backing_page, bool write)
{
	if (write)
		set_page_dirty(backing_page);

	put_page(backing_page);
}
EXPORT_SYMBOL_GPL(sgx_put_backing);

/**
 * sgx_einit - EINIT an enclave with the appropriate LE pubkey hash
 * @sigstruct:		a pointer to the enclave's sigstruct
 * @token:		a pointer to the enclave's EINIT token
 * @secs_page:		a pointer to the enclave's SECS EPC page
 * @le_pubkey_hash:	the desired LE pubkey hash for EINIT
 */
int sgx_einit(struct sgx_sigstruct *sigstruct, struct sgx_einittoken *token,
	      struct sgx_epc_page *secs_page, u64 le_pubkey_hash[4])
{
	u64 __percpu *cache;
	int i, ret;

	if (!sgx_lc_enabled)
		return __einit(sigstruct, token, sgx_epc_addr(secs_page));

	cache = per_cpu(sgx_le_pubkey_hash_cache, smp_processor_id());

	preempt_disable();
	for (i = 0; i < 4; i++) {
		if (le_pubkey_hash[i] == cache[i])
			continue;

		wrmsrl(MSR_IA32_SGXLEPUBKEYHASH0 + i, le_pubkey_hash[i]);
		cache[i] = le_pubkey_hash[i];
	}
	ret = __einit(sigstruct, token, sgx_epc_addr(secs_page));
	preempt_enable();
	return ret;
}
EXPORT_SYMBOL(sgx_einit);

static __init int sgx_init_epc_bank(u64 addr, u64 size, unsigned long index,
				    struct sgx_epc_bank *bank)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct sgx_epc_page *pages_data;
	unsigned long i;
	void *va;

	va = ioremap_cache(addr, size);
	if (!va)
		return -ENOMEM;

	pages_data = kcalloc(nr_pages, sizeof(struct sgx_epc_page), GFP_KERNEL);
	if (!pages_data)
		goto out_iomap;

	bank->pages = kcalloc(nr_pages, sizeof(struct sgx_epc_page *),
			      GFP_KERNEL);
	if (!bank->pages)
		goto out_pdata;

	for (i = 0; i < nr_pages; i++) {
		bank->pages[i] = &pages_data[i];
		bank->pages[i]->desc = (addr + (i << PAGE_SHIFT)) | index;
	}

	bank->pa = addr;
	bank->size = size;
	bank->va = va;
	bank->free_cnt = nr_pages;
	bank->pages_data = pages_data;
	spin_lock_init(&bank->lock);
	return 0;
out_pdata:
	kfree(pages_data);
out_iomap:
	iounmap(va);
	return -ENOMEM;
}

static __init void sgx_page_cache_teardown(void)
{
	struct sgx_epc_bank *bank;
	int i;

	if (ksgxswapd_tsk) {
		kthread_stop(ksgxswapd_tsk);
		ksgxswapd_tsk = NULL;
	}

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		bank = &sgx_epc_banks[i];
		iounmap((void *)bank->va);
		kfree(bank->pages);
		kfree(bank->pages_data);
	}
}

static inline u64 sgx_combine_bank_regs(u64 low, u64 high)
{
	return (low & 0xFFFFF000) + ((high & 0xFFFFF) << 32);
}

static __init int sgx_page_cache_init(void)
{
	u32 eax, ebx, ecx, edx;
	u64 pa, size;
	int ret;
	int i;

	BUILD_BUG_ON(SGX_MAX_EPC_BANKS > (SGX_EPC_BANK_MASK + 1));

	for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
		cpuid_count(SGX_CPUID, 2 + i, &eax, &ebx, &ecx, &edx);
		if (!(eax & 0xF))
			break;

		pa = sgx_combine_bank_regs(eax, ebx);
		size = sgx_combine_bank_regs(ecx, edx);
		pr_info("EPC bank 0x%llx-0x%llx\n", pa, pa + size - 1);

		ret = sgx_init_epc_bank(pa, size, i, &sgx_epc_banks[i]);
		if (ret) {
			sgx_page_cache_teardown();
			return ret;
		}

		sgx_nr_epc_banks++;
	}

	if (!sgx_nr_epc_banks) {
		pr_err("There are zero EPC banks.\n");
		return -ENODEV;
	}

	return 0;
}

static __init int sgx_init(void)
{
	struct task_struct *tsk;
	unsigned long fc;
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX))
		return false;

	if (!boot_cpu_has(X86_FEATURE_SGX1))
		return false;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, fc);
	if (!(fc & FEATURE_CONTROL_LOCKED)) {
		pr_info("IA32_FEATURE_CONTROL MSR is not locked\n");
		return false;
	}

	if (!(fc & FEATURE_CONTROL_SGX_ENABLE)) {
		pr_info("disabled by the firmware\n");
		return false;
	}

	if (!(fc & FEATURE_CONTROL_SGX_LE_WR))
		pr_info("IA32_SGXLEPUBKEYHASHn MSRs are not writable\n");

	ret = sgx_page_cache_init();
	if (ret)
		return ret;

	tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (IS_ERR(tsk)) {
		sgx_page_cache_teardown();
		return PTR_ERR(tsk);
	}
	ksgxswapd_tsk = tsk;

	sgx_lru_init(&sgx_global_lru);

	sgx_enabled = true;
	sgx_lc_enabled = !!(fc & FEATURE_CONTROL_SGX_LE_WR);
	return 0;
}

arch_initcall(sgx_init);
