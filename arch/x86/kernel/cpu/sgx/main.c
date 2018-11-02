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

struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];
EXPORT_SYMBOL_GPL(sgx_epc_sections);

static int sgx_nr_epc_sections;

static void sgx_section_put_page(struct sgx_epc_section *section,
				 struct sgx_epc_page *page)
{
	list_add_tail(&page->list, &section->page_list);
	section->free_cnt++;
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

	for (i = 0; i < sgx_nr_epc_sections; i++)
		sgx_free_epc_section(&sgx_epc_sections[i]);
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
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX))
		return false;

	ret = sgx_page_cache_init();
	if (ret)
		return ret;

	return 0;
}

arch_initcall(sgx_init);
