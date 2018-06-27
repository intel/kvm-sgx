// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <asm/sgx.h>
#include <asm/sgx_pr.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>

bool sgx_enabled __ro_after_init;
EXPORT_SYMBOL(sgx_enabled);
bool sgx_lc_enabled __ro_after_init;
EXPORT_SYMBOL(sgx_lc_enabled);

static atomic_t sgx_nr_free_pages = ATOMIC_INIT(0);
static struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];
static int sgx_nr_epc_banks;

/**
 * sgx_get_page - pin an EPC page
 * @page:	an EPC page
 *
 * Return: a pointer to the pinned EPC page
 */
void *sgx_get_page(struct sgx_epc_page *page)
{
	struct sgx_epc_bank *bank = SGX_EPC_BANK(page);

	if (IS_ENABLED(CONFIG_X86_64))
		return (void *)(bank->va + SGX_EPC_ADDR(page) - bank->pa);

	return kmap_atomic_pfn(SGX_EPC_PFN(page));
}
EXPORT_SYMBOL(sgx_get_page);

/**
 * sgx_put_page - unpin an EPC page
 * @ptr:	a pointer to the pinned EPC page
 */
void sgx_put_page(void *ptr)
{
	if (IS_ENABLED(CONFIG_X86_64))
		return;

	kunmap_atomic(ptr);
}
EXPORT_SYMBOL(sgx_put_page);

static __init int sgx_init_epc_bank(unsigned long addr, unsigned long size,
				    unsigned long index,
				    struct sgx_epc_bank *bank)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long i;
	void *va;

	if (IS_ENABLED(CONFIG_X86_64)) {
		va = ioremap_cache(addr, size);
		if (!va)
			return -ENOMEM;
	}

	bank->pages_data = kzalloc(nr_pages * sizeof(struct sgx_epc_page),
				   GFP_KERNEL);
	if (!bank->pages_data) {
		if (IS_ENABLED(CONFIG_X86_64))
			iounmap(va);

		return -ENOMEM;
	}

	bank->pages = kzalloc(nr_pages * sizeof(struct sgx_epc_page *),
			      GFP_KERNEL);
	if (!bank->pages) {
		if (IS_ENABLED(CONFIG_X86_64))
			iounmap(va);
		kfree(bank->pages_data);
		bank->pages_data = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < nr_pages; i++) {
		bank->pages[i] = &bank->pages_data[i];
		bank->pages[i]->desc = (addr + (i << PAGE_SHIFT)) | index;
	}

	bank->pa = addr;
	bank->size = size;
	if (IS_ENABLED(CONFIG_X86_64))
		bank->va = (unsigned long)va;

	atomic_set(&bank->free_cnt, nr_pages);
	init_rwsem(&bank->lock);
	atomic_add(nr_pages, &sgx_nr_free_pages);
	return 0;
}

static __init void sgx_page_cache_teardown(void)
{
	struct sgx_epc_bank *bank;
	int i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		bank = &sgx_epc_banks[i];

		if (IS_ENABLED(CONFIG_X86_64))
			iounmap((void *)bank->va);

		kfree(bank->pages);
		kfree(bank->pages_data);
	}
}

static __init int sgx_page_cache_init(void)
{
	unsigned long size;
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned long pa;
	int i;
	int ret;

	for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_EPC_BANKS, &eax, &ebx,
			    &ecx, &edx);
		if (!(eax & 0xf))
			break;

		pa = ((u64)(ebx & 0xfffff) << 32) + (u64)(eax & 0xfffff000);
		size = ((u64)(edx & 0xfffff) << 32) + (u64)(ecx & 0xfffff000);

		pr_info("EPC bank 0x%lx-0x%lx\n", pa, pa + size);

		ret = sgx_init_epc_bank(pa, size, i, &sgx_epc_banks[i]);
		if (ret) {
			sgx_page_cache_teardown();
			return ret;
		}

		sgx_nr_epc_banks++;
	}

	return 0;
}

static __init bool sgx_is_enabled(bool *lc_enabled)
{
	unsigned long fc;

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

	if (!(fc & FEATURE_CONTROL_SGX_LE_WR)) {
		pr_info("IA32_SGXLEPUBKEYHASHn MSRs are not writable\n");
		return false;
	}

	*lc_enabled = !!(fc & FEATURE_CONTROL_SGX_LE_WR);
	return true;
}

static __init int sgx_init(void)
{
	int ret;

	if (!sgx_is_enabled(&sgx_lc_enabled))
		return 0;

	ret = sgx_page_cache_init();
	if (ret)
		return ret;

	sgx_enabled = true;
	return 0;
}

arch_initcall(sgx_init);
