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

static LIST_HEAD(sgx_active_page_list);
static DEFINE_SPINLOCK(sgx_active_page_list_lock);

static int sgx_nr_epc_banks;
static struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

/*
 * A cache for last known values of IA32_SGXLEPUBKEYHASHx MSRs. Cache entries
 * are initialized when they are first used by sgx_einit().
 */
static DEFINE_PER_CPU(u64 [4], sgx_le_pubkey_hash_cache);

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
	struct sgx_epc_bank *bank;
	int i, j;

	spin_lock(&sgx_active_page_list_lock);
	for (i = 0, j = 0; i < SGX_NR_TO_SCAN; i++) {
		if (list_empty(&sgx_active_page_list))
			break;

		epc_page = list_first_entry(&sgx_active_page_list,
					    struct sgx_epc_page, list);
		list_del_init(&epc_page->list);

		if (epc_page->impl->ops->get(epc_page))
			chunk[j++] = epc_page;
		else
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
	}
	spin_unlock(&sgx_active_page_list_lock);

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page->impl->ops->reclaim(epc_page))
			continue;

		spin_lock(&sgx_active_page_list_lock);
		list_add_tail(&epc_page->list, &sgx_active_page_list);
		spin_unlock(&sgx_active_page_list_lock);

		epc_page->impl->ops->put(epc_page);
		chunk[i] = NULL;
	}

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page)
			epc_page->impl->ops->block(epc_page);
	}

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page) {
			epc_page->impl->ops->write(epc_page);
			epc_page->impl->ops->put(epc_page);

			/*
			 * Put the page back on the free list only after we
			 * have put() our reference to the owner of the EPC
			 * page, otherwise the page could be re-allocated and
			 * we'd call put() on the wrong impl.
			 */
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;

			bank = sgx_epc_bank(epc_page);
			spin_lock(&bank->lock);
			bank->pages[bank->free_cnt++] = epc_page;
			spin_unlock(&bank->lock);
		}
	}
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

static int ksgxswapd(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxswapd_waitq, kthread_should_stop() ||
				     sgx_calc_free_cnt() < SGX_NR_HIGH_PAGES);

		if (sgx_calc_free_cnt() < SGX_NR_HIGH_PAGES)
			sgx_reclaim_pages();
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

	for ( ; ; ) {
		entry = sgx_try_alloc_page(impl);
		if (entry)
			break;

		if (list_empty(&sgx_active_page_list))
			return ERR_PTR(-ENOMEM);

		if (flags & SGX_ALLOC_ATOMIC) {
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
	int ret;

	/*
	 * Remove the page from the active list if necessary.  If the page
	 * is actively being reclaimed, i.e. RECLAIMABLE is set but the
	 * page isn't on the active list, return -EBUSY as we can't free
	 * the page at this time since it is "owned" by the reclaimer.
	 */
	if (page->desc & SGX_EPC_PAGE_RECLAIMABLE) {
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
	WARN(ret < 0, "cannot free page, reclaim in-progress");
	WARN(ret > 0, "EREMOVE returned %d\n", ret);
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
	spin_lock(&sgx_active_page_list_lock);
	page->desc |= SGX_EPC_PAGE_RECLAIMABLE;
	list_add_tail(&page->list, &sgx_active_page_list);
	spin_unlock(&sgx_active_page_list_lock);
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

	sgx_enabled = true;
	sgx_lc_enabled = !!(fc & FEATURE_CONTROL_SGX_LE_WR);
	return 0;
}

arch_initcall(sgx_init);
