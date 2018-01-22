// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <asm/sgx.h>
#include <asm/sgx_pr.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

bool sgx_enabled __ro_after_init;
EXPORT_SYMBOL_GPL(sgx_enabled);
bool sgx_lc_enabled __ro_after_init;
EXPORT_SYMBOL_GPL(sgx_lc_enabled);

static __init int sgx_init(void)
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

	if (!(fc & FEATURE_CONTROL_SGX_LE_WR))
		pr_info("IA32_SGXLEPUBKEYHASHn MSRs are not writable\n");

	sgx_enabled = true;
	sgx_lc_enabled = !!(fc & FEATURE_CONTROL_SGX_LE_WR);
	return 0;
}

arch_initcall(sgx_init);
