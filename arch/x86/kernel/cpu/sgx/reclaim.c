// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-19 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include "encls.h"

struct task_struct *ksgxswapd_tsk;

static void sgx_sanitize_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;
	LIST_HEAD(secs_list);
	int ret;

	while (!list_empty(&section->unsanitized_page_list)) {
		if (kthread_should_stop())
			return;

		spin_lock(&section->lock);

		page = list_first_entry(&section->unsanitized_page_list,
					struct sgx_epc_page, list);

		ret = __eremove(sgx_epc_addr(page));
		if (!ret)
			list_move(&page->list, &section->page_list);
		else
			list_move_tail(&page->list, &secs_list);

		spin_unlock(&section->lock);

		cond_resched();
	}
}

static int ksgxswapd(void *p)
{
	int i;

	set_freezable();

	/*
	 * Reset all pages to uninitialized state. Pages could be in initialized
	 * on kmemexec.
	 */
	for (i = 0; i < sgx_nr_epc_sections; i++)
		sgx_sanitize_section(&sgx_epc_sections[i]);

	/*
	 * 2nd round for the SECS pages as they cannot be removed when they
	 * still hold child pages.
	 */
	for (i = 0; i < sgx_nr_epc_sections; i++) {
		sgx_sanitize_section(&sgx_epc_sections[i]);

		/* Should never happen. */
		if (!list_empty(&sgx_epc_sections[i].unsanitized_page_list))
			WARN(1, "EPC section %d has unsanitized pages.\n", i);
	}

	return 0;
}

bool __init sgx_page_reclaimer_init(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (IS_ERR(tsk))
		return false;

	ksgxswapd_tsk = tsk;

	return true;
}
