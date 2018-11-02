/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
#ifndef _X86_SGX_H
#define _X86_SGX_H

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <asm/asm.h>
#include "arch.h"

#undef pr_fmt
#define pr_fmt(fmt) "sgx: " fmt

struct sgx_epc_page {
	unsigned long desc;
	struct list_head list;
};

/**
 * struct sgx_epc_section
 *
 * The firmware can define multiple chunks of EPC to the different areas of the
 * physical memory e.g. for memory areas of the each node. This structure is
 * used to store EPC pages for one EPC section and virtual memory area where
 * the pages have been mapped.
 */
struct sgx_epc_section {
	unsigned long pa;
	void *va;
	struct list_head page_list;
	struct list_head unsanitized_page_list;
	spinlock_t lock;
};

/**
 * enum sgx_epc_page_desc - bits and masks for an EPC page's descriptor
 * %SGX_EPC_SECTION_MASK:	SGX allows to have multiple EPC sections in the
 *				physical memory. The existing and near-future
 *				hardware defines at most eight sections, hence
 *				three bits to hold a section.
 */
enum sgx_epc_page_desc {
	SGX_EPC_SECTION_MASK			= GENMASK_ULL(3, 0),
	/* bits 12-63 are reserved for the physical page address of the page */
};

#define SGX_MAX_EPC_SECTIONS (SGX_EPC_SECTION_MASK + 1)

extern struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];

static inline struct sgx_epc_section *sgx_epc_section(struct sgx_epc_page *page)
{
	return &sgx_epc_sections[page->desc & SGX_EPC_SECTION_MASK];
}

static inline void *sgx_epc_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_epc_section(page);

	return section->va + (page->desc & PAGE_MASK) - section->pa;
}

extern int sgx_nr_epc_sections;
extern struct task_struct *ksgxswapd_tsk;

bool __init sgx_page_reclaimer_init(void);

struct sgx_epc_page *sgx_try_alloc_page(void);
void sgx_free_page(struct sgx_epc_page *page);

#endif /* _X86_SGX_H */
