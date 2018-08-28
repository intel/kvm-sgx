/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2018 Intel Corporation. */

#ifndef _ASM_X86_INTEL_SGX_H
#define _ASM_X86_INTEL_SGX_H

struct sgx_epc_lru {
	spinlock_t lock;
	struct list_head reclaimable;
};

static inline void sgx_lru_init(struct sgx_epc_lru *lru)
{
	spin_lock_init(&lru->lock);
	INIT_LIST_HEAD(&lru->reclaimable);
}

void sgx_reclaim_pages(void);

#endif /* _ASM_X86_INTEL_SGX_H */
