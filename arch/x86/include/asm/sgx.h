// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <asm/sgx_arch.h>
#include <asm/asm.h>

#define SGX_MAX_EPC_BANKS 8

struct sgx_epc_page {
	unsigned long desc;
	struct list_head list;
};

struct sgx_epc_bank {
	unsigned long pa;
	void *va;
	unsigned long size;
	struct sgx_epc_page *pages_data;
	struct sgx_epc_page **pages;
	unsigned long free_cnt;
	spinlock_t lock;
};

extern bool sgx_enabled;
extern bool sgx_lc_enabled;
extern struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];

/*
 * enum sgx_epc_page_desc - defines bits and masks for an EPC page's desc
 * @SGX_EPC_BANK_MASK:	      SGX allows a system to multiple EPC banks (at
 *			      different physical locations).  The index of a
 *			      page's bank in its desc so that we can do a quick
 *			      lookup of its virtual address (EPC is mapped via
 *			      ioremap_cache() because it's non-standard memory).
 *			      Current and near-future hardware defines at most
 *			      eight banks, hence three bits to hold the bank.
 *			      sgx_page_cache_init() asserts that the max bank
 *			      index doesn't exceed SGX_EPC_BANK_MASK.
 * @SGX_EPC_PAGE_RECLAIMABLE: When set, indicates a page is reclaimable.  Used
 *			      when freeing a page to know that we also need to
 *			      remove the page from the active page list.
 *
 * Defines the layout of the desc field in the &struct sgx_epc_page, which
 * contains EPC bank number, physical address of the page and the page status
 * flag.
 */
enum sgx_epc_page_desc {
	SGX_EPC_BANK_MASK			= GENMASK_ULL(3, 0),
	SGX_EPC_PAGE_RECLAIMABLE		= BIT(4),
	/* bits 12-63 are reserved for the physical page address of the page */
};

static inline struct sgx_epc_bank *sgx_epc_bank(struct sgx_epc_page *page)
{
	return &sgx_epc_banks[page->desc & SGX_EPC_BANK_MASK];
}

static inline void *sgx_epc_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_bank *bank = sgx_epc_bank(page);

	return (void *)(bank->va + (page->desc & PAGE_MASK) - bank->pa);
}

#endif /* _ASM_X86_SGX_H */
