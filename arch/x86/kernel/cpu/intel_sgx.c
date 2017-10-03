/*
* This file is provided under a dual BSD/GPLv2 license.  When using or
* redistributing this file, you may do so under either license.
*
* GPL LICENSE SUMMARY
*
* Copyright(c) 2016 Intel Corporation.
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
* Copyright(c) 2016 Intel Corporation.
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

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

#include <asm/sgx.h>

bool sgx_enabled __ro_after_init = false;
EXPORT_SYMBOL(sgx_enabled);

#define SGX_NR_EPC_PAGES_TO_SCAN 16
#define SGX_NR_LOW_EPC_PAGES_DEFAULT 32

static unsigned int sgx_nr_total_epc_pages __ro_after_init;
static unsigned int sgx_nr_free_pages;
static unsigned int sgx_nr_low_pages = SGX_NR_LOW_EPC_PAGES_DEFAULT;
static unsigned int sgx_nr_high_pages = SGX_NR_LOW_EPC_PAGES_DEFAULT * 2;
static struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

static LIST_HEAD(sgx_free_list);
static DEFINE_SPINLOCK(sgx_free_list_lock);
static LIST_HEAD(sgx_global_lru);
static DEFINE_SPINLOCK(sgx_global_lru_lock);

struct sgx_epc_bank {
	unsigned long pa;
#ifdef CONFIG_X86_64
	unsigned long va;
#endif
	unsigned long size;
};
#define SGX_MAX_EPC_BANKS 8
static struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS] __ro_after_init;
static int sgx_nr_epc_banks __ro_after_init;

void sgx_page_reclaimable(struct sgx_epc_page *epc_page)
{
	if (WARN_ON(!epc_page->ops->get_ref || !epc_page->ops->swap_pages))
		return;

	spin_lock(&sgx_global_lru_lock);
	list_add_tail(&epc_page->list, &sgx_global_lru);
	spin_unlock(&sgx_global_lru_lock);
}
EXPORT_SYMBOL(sgx_page_reclaimable);

void sgx_reclaimable_putback(struct list_head *src)
{
	if (list_empty(src))
		return;

	spin_lock(&sgx_global_lru_lock);
	list_splice_tail_init(src, &sgx_global_lru);
	spin_unlock(&sgx_global_lru_lock);
}
EXPORT_SYMBOL(sgx_reclaimable_putback);

void sgx_page_defunct(struct sgx_epc_page *epc_page)
{
	if (!list_empty(&epc_page->list)) {
		spin_lock(&sgx_global_lru_lock);
		if (!list_empty(&epc_page->list))
			list_del_init(&epc_page->list);
		spin_unlock(&sgx_global_lru_lock);
	}
}
EXPORT_SYMBOL(sgx_page_defunct);

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

		if (!entry->ops->get_ref(entry))
			list_del_init(&entry->list);
		else
			list_move_tail(&entry->list, dst);
	}

	spin_unlock(&sgx_global_lru_lock);
}

static void sgx_swap_pages(unsigned long nr_to_scan)
{
	struct sgx_epc_page *entry;

	LIST_HEAD(iso);

	sgx_isolate_pages(&iso, nr_to_scan);

	while (!list_empty(&iso)) {
		entry = list_first_entry(&iso, struct sgx_epc_page, list);
		entry->ops->swap_pages(entry, &iso);
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
			sgx_swap_pages(SGX_NR_EPC_PAGES_TO_SCAN);
	}

	pr_info("%s: done\n", __func__);
	return 0;
}


static struct sgx_epc_page *sgx_alloc_page_fast(void *owner,
						struct sgx_epc_operations *ops)
{
	struct sgx_epc_page *entry = NULL;

	if (WARN_ON(!owner || !ops))
		return entry;

	spin_lock(&sgx_free_list_lock);

	if (!list_empty(&sgx_free_list)) {
		entry = list_first_entry(&sgx_free_list, struct sgx_epc_page,
					 list);
		list_del_init(&entry->list);
		sgx_nr_free_pages--;
		entry->owner = owner;
		entry->ops = ops;
	}

	spin_unlock(&sgx_free_list_lock);

	return entry;
}

/**
 * sgx_alloc_page - allocate an EPC page
 * @flags:	allocation flags
 * @owner:	the object that will own the EPC page
 * @ops:	callback operations required for allocating an EPC page
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. If called with SGX_ALLOC_ATOMIC,
 * the function will return immediately if the list is empty. Otherwise, it
 * will swap pages up until there is a free page available. Before returning
 * the low watermark is checked and ksgxswapd is waken up if we are below it.
 *
 * Return: an EPC page or a system error code
 */
struct sgx_epc_page *sgx_alloc_page(unsigned int flags, void *owner,
				    struct sgx_epc_operations *ops)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_alloc_page_fast(owner, ops);
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

		sgx_swap_pages(SGX_NR_EPC_PAGES_TO_SCAN);
		schedule();
	}

	if (sgx_nr_free_pages < sgx_nr_low_pages)
		wake_up(&ksgxswapd_waitq);

	return entry;
}
EXPORT_SYMBOL(sgx_alloc_page);

int sgx_batch_alloc_pages(int nr_pages, struct list_head *dst,
			  void *owner, struct sgx_epc_operations *ops)
{
	int i = 0;
	struct sgx_epc_page *entry, *tmp;

	spin_lock(&sgx_free_list_lock);
	if (nr_pages > sgx_nr_free_pages)
		goto out;

	sgx_nr_free_pages -= nr_pages;

	for (i = 0; i < nr_pages && !list_empty(&sgx_free_list); i++) {
		entry = list_first_entry(&sgx_free_list, struct sgx_epc_page,
					 list);
		list_move_tail(&entry->list, dst);
	}
	if (WARN_ON_ONCE(i < nr_pages)) {
		list_for_each_entry_safe(entry, tmp, dst, list)
			list_move_tail(&entry->list, &sgx_free_list);
		sgx_nr_free_pages += nr_pages;
	}
out:
	spin_unlock(&sgx_free_list_lock);
	return (i < nr_pages) ? -ENOMEM : 0;
}
EXPORT_SYMBOL(sgx_batch_alloc_pages);

void sgx_free_page(struct sgx_epc_page *entry)
{
	if (WARN_ON(!list_empty(&entry->list)))
		sgx_page_defunct(entry);

	entry->ops = NULL;
	entry->owner = NULL;

	spin_lock(&sgx_free_list_lock);
	list_add(&entry->list, &sgx_free_list);
	sgx_nr_free_pages++;
	spin_unlock(&sgx_free_list_lock);
}
EXPORT_SYMBOL(sgx_free_page);

void *__sgx_get_page(resource_size_t pa)
{
#ifdef CONFIG_X86_32
	return kmap_atomic_pfn(PFN_DOWN(pa));
#else
	int i = (pa & ~PAGE_MASK);
	return (void *)(sgx_epc_banks[i].va +
		((pa & PAGE_MASK) - sgx_epc_banks[i].pa));
#endif
}
EXPORT_SYMBOL(__sgx_get_page);

void sgx_put_page(void *epc_page_vaddr)
{
#ifdef CONFIG_X86_32
	kunmap_atomic(epc_page_vaddr);
#else
#endif
}
EXPORT_SYMBOL(sgx_put_page);

static __init int sgx_check_support(void) {
	unsigned int eax, ebx, ecx, edx;
	unsigned long fc;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return -ENODEV;

	if (!boot_cpu_has(X86_FEATURE_SGX)) {
		pr_err("intel_sgx: the CPU is missing SGX\n");
		return -ENODEV;
	}

	rdmsrl(MSR_IA32_FEATURE_CONTROL, fc);
	if (!(fc & FEATURE_CONTROL_LOCKED)) {
		pr_err("intel_sgx: the feature control MSR is not locked\n");
		return -ENODEV;
	}

	if (!(fc & FEATURE_CONTROL_SGX_ENABLE)) {
		pr_err("intel_sgx: SGX is not enabled\n");
		return -ENODEV;
	}

	cpuid(0, &eax, &ebx, &ecx, &edx);
	if (eax < SGX_CPUID) {
		pr_err("intel_sgx: CPUID is missing the SGX leaf\n");
		return -ENODEV;
	}

	cpuid_count(SGX_CPUID, SGX_CPUID_CAPABILITIES, &eax, &ebx, &ecx, &edx);
	if (!(eax & 1)) {
		pr_err("intel_sgx: CPU does not support the SGX1 instructions\n");
		return -ENODEV;
	}
	return 0;
}

static __init void sgx_teardown_epc(void)
{
#ifdef CONFIG_X86_64
	int i;
#endif
	struct sgx_epc_page *entry, *tmp;

	spin_lock(&sgx_free_list_lock);
	list_for_each_entry_safe(entry, tmp, &sgx_free_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	spin_unlock(&sgx_free_list_lock);

#ifdef CONFIG_X86_64
	for (i = 0; i < sgx_nr_epc_banks; i++)
		iounmap((void *)sgx_epc_banks[i].va);
#endif
}

static __init int sgx_add_epc_bank(resource_size_t start, unsigned long size, int bank)
{
	unsigned long i;
	struct sgx_epc_page *new_epc_page, *entry;
	unsigned int nr_pages = 0;
	LIST_HEAD(epc_pages);

	for (i = 0; i < size; i += PAGE_SIZE) {
		new_epc_page = kzalloc(sizeof(*new_epc_page), GFP_KERNEL);
		if (!new_epc_page)
			goto err_freelist;
		new_epc_page->pa = (start + i) | bank;

		list_add_tail(&new_epc_page->list, &epc_pages);
		nr_pages++;
	}

	spin_lock(&sgx_free_list_lock);
	list_splice_tail(&epc_pages, &sgx_free_list);
	sgx_nr_total_epc_pages += nr_pages;
	sgx_nr_free_pages += nr_pages;
	spin_unlock(&sgx_free_list_lock);
	return 0;
err_freelist:
	list_for_each_entry(entry, &epc_pages, list)
		kfree(entry);
	return -ENOMEM;
}

static __init int sgx_init_epc(void)
{
	int i, ret;
	unsigned int eax, ebx, ecx, edx;
	unsigned long pa, size;

	ret = -ENODEV;

	for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
		cpuid_count(SGX_CPUID, i + 2, &eax, &ebx, &ecx, &edx);
		if (!(eax & 0xf))
			break;

		pa = ((u64)(ebx & 0xfffff) << 32) + (u64)(eax & 0xfffff000);
		size = ((u64)(edx & 0xfffff) << 32) + (u64)(ecx & 0xfffff000);

		pr_info("intel_sgx: EPC bank 0x%lx-0x%lx\n", pa, pa + size);

		sgx_epc_banks[i].pa = pa;
		sgx_epc_banks[i].size = size;
	}

	sgx_nr_epc_banks = i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
#ifdef CONFIG_X86_64
		sgx_epc_banks[i].va = (unsigned long)
			ioremap_cache(sgx_epc_banks[i].pa,
				sgx_epc_banks[i].size);
		if (!sgx_epc_banks[i].va) {
			pr_warn("intel_sgx: ioremap_cache of EPC failed\n");
			ret = -ENOMEM;
			break;
		}
#endif
		ret = sgx_add_epc_bank(sgx_epc_banks[i].pa,
				       sgx_epc_banks[i].size, i);
		if (ret) {
			pr_warn("intel_sgx: sgx_add_epc_bank failed\n");
#ifdef CONFIG_X86_64
			iounmap((void *)sgx_epc_banks[i].va);
#endif
			break;
		}
	}

	sgx_nr_epc_banks = i;

	if (sgx_nr_epc_banks)
		ret = 0;
	return ret;
}

static int sgx_init_swapd(void)
{
       struct task_struct *tmp = kthread_run(ksgxswapd, NULL, "ksgxswapd");
       if (!IS_ERR(tmp))
               ksgxswapd_tsk = tmp;
       return PTR_ERR_OR_ZERO(tmp);
}

static __init int sgx_init(void)
{
	int ret;

	ret = sgx_check_support();
	if (ret)
		return ret;

	ret = sgx_init_epc();
	if (ret)
		return ret;

	ret = sgx_init_swapd();
	if (ret) {
		sgx_teardown_epc();
		return ret;
	}

	sgx_enabled = true;

	return 0;
}
arch_initcall(sgx_init);
