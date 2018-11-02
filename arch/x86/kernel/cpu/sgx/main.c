// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "encls.h"

struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];
int sgx_nr_epc_sections;

static struct sgx_epc_page *__sgx_try_alloc_page(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	if (list_empty(&section->page_list))
		return NULL;

	page = list_first_entry(&section->page_list, struct sgx_epc_page, list);
	list_del_init(&page->list);
	return page;
}

/**
 * sgx_try_alloc_page() - Allocate an EPC page
 *
 * Try to grab a page from the free EPC page list.
 *
 * Return:
 *   a pointer to a &struct sgx_epc_page instance,
 *   -errno on error
 */
struct sgx_epc_page *sgx_try_alloc_page(void)
{
	struct sgx_epc_section *section;
	struct sgx_epc_page *page;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++) {
		section = &sgx_epc_sections[i];
		spin_lock(&section->lock);
		page = __sgx_try_alloc_page(section);
		spin_unlock(&section->lock);

		if (page)
			return page;
	}

	return ERR_PTR(-ENOMEM);
}

/**
 * sgx_free_page() - Free an EPC page
 * @page:	pointer a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.
 */
void sgx_free_page(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_epc_section(page);
	int ret;

	ret = __eremove(sgx_epc_addr(page));
	if (WARN_ONCE(ret, "EREMOVE returned %d (0x%x)", ret, ret))
		return;

	spin_lock(&section->lock);
	list_add_tail(&page->list, &section->page_list);
	spin_unlock(&section->lock);
}

static void __init sgx_free_epc_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	while (!list_empty(&section->page_list)) {
		page = list_first_entry(&section->page_list,
					struct sgx_epc_page, list);
		list_del(&page->list);
		kfree(page);
	}

	while (!list_empty(&section->unsanitized_page_list)) {
		page = list_first_entry(&section->unsanitized_page_list,
					struct sgx_epc_page, list);
		list_del(&page->list);
		kfree(page);
	}

	memunmap(section->va);
}

static bool __init sgx_alloc_epc_section(u64 addr, u64 size,
					 unsigned long index,
					 struct sgx_epc_section *section)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct sgx_epc_page *page;
	unsigned long i;

	section->va = memremap(addr, size, MEMREMAP_WB);
	if (!section->va)
		return false;

	section->pa = addr;
	spin_lock_init(&section->lock);
	INIT_LIST_HEAD(&section->page_list);
	INIT_LIST_HEAD(&section->unsanitized_page_list);

	for (i = 0; i < nr_pages; i++) {
		page = kzalloc(sizeof(*page), GFP_KERNEL);
		if (!page)
			goto err_out;

		page->desc = (addr + (i << PAGE_SHIFT)) | index;
		list_add_tail(&page->list, &section->unsanitized_page_list);
	}

	return true;

err_out:
	sgx_free_epc_section(section);
	return false;
}

static void __init sgx_page_cache_teardown(void)
{
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++)
		sgx_free_epc_section(&sgx_epc_sections[i]);
}

/**
 * A section metric is concatenated in a way that @low bits 12-31 define the
 * bits 12-31 of the metric and @high bits 0-19 define the bits 32-51 of the
 * metric.
 */
static inline u64 __init sgx_calc_section_metric(u64 low, u64 high)
{
	return (low & GENMASK_ULL(31, 12)) +
	       ((high & GENMASK_ULL(19, 0)) << 32);
}

static bool __init sgx_page_cache_init(void)
{
	u32 eax, ebx, ecx, edx, type;
	u64 pa, size;
	int i;

	for (i = 0; i <= ARRAY_SIZE(sgx_epc_sections); i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_FIRST_VARIABLE_SUB_LEAF,
			    &eax, &ebx, &ecx, &edx);

		type = eax & SGX_CPUID_SUB_LEAF_TYPE_MASK;
		if (type == SGX_CPUID_SUB_LEAF_INVALID)
			break;

		if (type != SGX_CPUID_SUB_LEAF_EPC_SECTION) {
			pr_err_once("Unknown EPC section type: %u\n", type);
			break;
		}

		if (i == ARRAY_SIZE(sgx_epc_sections)) {
			pr_warn("No free slot for an EPC section\n");
			break;
		}

		pa = sgx_calc_section_metric(eax, ebx);
		size = sgx_calc_section_metric(ecx, edx);

		pr_info("EPC section 0x%llx-0x%llx\n", pa, pa + size - 1);

		if (!sgx_alloc_epc_section(pa, size, i, &sgx_epc_sections[i])) {
			pr_err("No free memory for an EPC section\n");
			break;
		}

		sgx_nr_epc_sections++;
	}

	if (!sgx_nr_epc_sections) {
		pr_err("There are zero EPC sections.\n");
		return false;
	}

	return true;
}

static void __init sgx_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_SGX))
		return;

	if (!sgx_page_cache_init())
		return;

	if (!sgx_page_reclaimer_init())
		goto err_page_cache;

	return;

err_page_cache:
	sgx_page_cache_teardown();
}

arch_initcall(sgx_init);
