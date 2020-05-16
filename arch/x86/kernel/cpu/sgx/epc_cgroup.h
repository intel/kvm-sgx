/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2017-18 Intel Corporation. */
#ifndef _INTEL_SGX_EPC_CGROUP_H_
#define _INTEL_SGX_EPC_CGROUP_H_

#include <asm/sgx.h>
#include <linux/cgroup.h>
#include <linux/list.h>
#include <linux/page_counter.h>
#include <linux/workqueue.h>

#include "sgx.h"

#ifndef CONFIG_CGROUP_SGX_EPC
struct sgx_epc_cgroup;
#else
enum sgx_epc_cgroup_counter {
	SGX_EPC_CGROUP_PAGES,
	SGX_EPC_CGROUP_RECLAIMED,
	SGX_EPC_CGROUP_RECLAMATIONS,
	SGX_EPC_CGROUP_LOW,
	SGX_EPC_CGROUP_HIGH,
	SGX_EPC_CGROUP_MAX,
	SGX_EPC_CGROUP_NR_COUNTERS,
};

struct sgx_epc_cgroup {
	struct cgroup_subsys_state	css;

	struct page_counter	pc;
	unsigned long		high;

	struct sgx_epc_lru	lru;
	struct sgx_epc_cgroup	*reclaim_iter;
	struct work_struct	reclaim_work;
	unsigned int		epoch;

	atomic_long_t           cnt[SGX_EPC_CGROUP_NR_COUNTERS];

	struct cgroup_file      events_file;
};

struct sgx_epc_cgroup *sgx_epc_cgroup_try_charge(struct mm_struct *mm,
						 bool reclaim);
void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg, bool reclaimed);
bool sgx_epc_cgroup_lru_empty(struct sgx_epc_cgroup *root);
void sgx_epc_cgroup_isolate_pages(struct sgx_epc_cgroup *root,
				  int *nr_to_scan, struct list_head *dst);
#endif

#endif /* _INTEL_SGX_EPC_CGROUP_H_ */
