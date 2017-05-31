/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2018 Intel Corporation. */

#ifndef _ASM_X86_INTEL_SGX_H
#define _ASM_X86_INTEL_SGX_H

struct sgx_epc_cgroup;

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
	int nr_fails;
	bool ignore_age;
	struct sgx_epc_cgroup *epc_cg;
};

static inline
void sgx_epc_reclaim_control_init(struct sgx_epc_reclaim_control *rc,
				  struct sgx_epc_cgroup *epc_cg, int nr_pages)
{
	rc->nr_pages = nr_pages;
	rc->nr_fails = 0;
	rc->ignore_age = false;
	rc->epc_cg = epc_cg;
}

int sgx_reclaim_pages(struct sgx_epc_reclaim_control *rc);
void sgx_isolate_pages(struct sgx_epc_lru *lru, int *nr_pages,
		       struct list_head *dst);
bool sgx_oom(struct sgx_epc_lru *lru);

#endif /* _ASM_X86_INTEL_SGX_H */
