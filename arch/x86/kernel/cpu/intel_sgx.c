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

bool sgx_enabled __ro_after_init;
EXPORT_SYMBOL_GPL(sgx_enabled);
bool sgx_lc_enabled __ro_after_init;
EXPORT_SYMBOL_GPL(sgx_lc_enabled);
struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];
EXPORT_SYMBOL_GPL(sgx_epc_banks);

static int sgx_nr_epc_banks;

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

	sgx_enabled = true;
	sgx_lc_enabled = !!(fc & FEATURE_CONTROL_SGX_LE_WR);
	return 0;
}

arch_initcall(sgx_init);
