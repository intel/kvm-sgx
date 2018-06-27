// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <asm/sgx_arch.h>
#include <asm/asm.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/rwsem.h>
#include <linux/types.h>

#define SGX_MAX_EPC_BANKS 8

#define SGX_EPC_BANK(epc_page) \
	(&sgx_epc_banks[(unsigned long)(epc_page->desc) & ~PAGE_MASK])
#define SGX_EPC_PFN(epc_page) PFN_DOWN((unsigned long)(epc_page->desc))
#define SGX_EPC_ADDR(epc_page) ((unsigned long)(epc_page->desc) & PAGE_MASK)

struct sgx_epc_page {
	unsigned long desc;
	struct list_head list;
};

struct sgx_epc_bank {
	unsigned long pa;
	unsigned long va;
	unsigned long size;
	struct sgx_epc_page *pages_data;
	struct sgx_epc_page **pages;
	atomic_t free_cnt;
	struct rw_semaphore lock;
};

extern bool sgx_enabled;
extern bool sgx_lc_enabled;

void *sgx_get_page(struct sgx_epc_page *ptr);
void sgx_put_page(void *epc_page_ptr);

#endif /* _ASM_X86_SGX_H */
