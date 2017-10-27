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

static __init int sgx_init(void)
{
	int ret;

	ret = sgx_check_support();
	if (ret)
		return ret;

	sgx_enabled = true;

	return 0;
}
arch_initcall(sgx_init);
