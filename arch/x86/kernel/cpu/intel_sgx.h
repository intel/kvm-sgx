/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2018 Intel Corporation. */

#ifndef _ASM_X86_INTEL_SGX_H
#define _ASM_X86_INTEL_SGX_H

struct sgx_epc_lru {
	spinlock_t lock;
	struct list_head reclaimable;
	struct list_head unreclaimable;
};

static inline void sgx_lru_init(struct sgx_epc_lru *lru)
{
	spin_lock_init(&lru->lock);
	INIT_LIST_HEAD(&lru->reclaimable);
	INIT_LIST_HEAD(&lru->unreclaimable);
}

struct sgx_epc_reclaim_control {
	int nr_pages;
};

static inline
void sgx_epc_reclaim_control_init(struct sgx_epc_reclaim_control *rc,
				  int nr_pages)
{
	rc->nr_pages = nr_pages;
}

int sgx_reclaim_pages(struct sgx_epc_reclaim_control *rc);

#endif /* _ASM_X86_INTEL_SGX_H */
