// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/device.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "driver.h"

bool sgx_encl_page_get(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = to_encl_page(epc_page);
	struct sgx_encl *encl = encl_page->encl;

	return kref_get_unless_zero(&encl->refcount) != 0;
}

void sgx_encl_page_put(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = to_encl_page(epc_page);
	struct sgx_encl *encl = encl_page->encl;

	kref_put(&encl->refcount, sgx_encl_release);
}

bool sgx_encl_page_reclaim(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = to_encl_page(epc_page);
	struct sgx_encl *encl = encl_page->encl;
	bool ret;

	down_read(&encl->mm->mmap_sem);
	mutex_lock(&encl->lock);

	if (encl->flags & SGX_ENCL_DEAD)
		ret = true;
	else
		ret = !sgx_test_and_clear_young(encl_page);

	if (ret)
		encl_page->desc |= SGX_ENCL_PAGE_RECLAIMED;

	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);

	return ret;
}

void sgx_encl_page_block(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = to_encl_page(epc_page);
	struct sgx_encl *encl = encl_page->encl;

	down_read(&encl->mm->mmap_sem);
	mutex_lock(&encl->lock);
	sgx_encl_eblock(encl_page);
	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);
}

void sgx_encl_page_write(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *encl_page = to_encl_page(epc_page);
	struct sgx_encl *encl = encl_page->encl;

	down_read(&encl->mm->mmap_sem);
	mutex_lock(&encl->lock);

	sgx_encl_ewb(epc_page, false);
	encl->secs_child_cnt--;
	if (!encl->secs_child_cnt &&
	    (encl->flags & (SGX_ENCL_DEAD | SGX_ENCL_INITIALIZED)))
		sgx_encl_ewb(encl->secs.epc_page, true);

	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);
}
