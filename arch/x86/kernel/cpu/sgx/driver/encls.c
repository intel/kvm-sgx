// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-19 Intel Corporation.

#include <linux/device.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "driver.h"

/**
 * sgx_encl_eblock - block an enclave page
 * @encl_page:	an enclave page
 *
 * Changes the state of the associated EPC page to blocked.
 */
void sgx_encl_eblock(struct sgx_encl_page *encl_page)
{
	unsigned long addr = SGX_ENCL_PAGE_ADDR(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	struct vm_area_struct *vma;
	int ret;

	if (encl->flags & SGX_ENCL_DEAD)
		return;

	ret = sgx_encl_find(encl->mm, addr, &vma);
	if (!ret && encl == vma->vm_private_data)
		zap_vma_ptes(vma, addr, PAGE_SIZE);

	ret = __eblock(sgx_epc_addr(encl_page->epc_page));
	SGX_INVD(ret, encl, "EBLOCK returned %d (0x%x)", ret, ret);
}

/**
 * sgx_encl_etrack - start tracking pages in the blocked state
 * @encl:	an enclave
 *
 * Start blocking accesses for pages in the blocked state for threads that enter
 * inside the enclave by executing the ETRACK leaf instruction. This starts a
 * shootdown sequence for threads that entered before ETRACK.
 *
 * The caller must take care (with an IPI when necessary) to make sure that the
 * previous shootdown sequence was completed before calling this function.  If
 * this is not the case, the callee prints a critical error to the klog and
 * kills the enclave.
 */
void sgx_encl_etrack(struct sgx_encl *encl)
{
	int ret = __etrack(sgx_epc_addr(encl->secs.epc_page));

	SGX_INVD(ret, encl, "ETRACK returned %d (0x%x)", ret, ret);
}

static int __sgx_encl_ewb(struct sgx_encl *encl, struct sgx_epc_page *epc_page,
			  struct sgx_va_page *va_page, unsigned int va_offset)
{
	struct sgx_encl_page *encl_page = to_encl_page(epc_page);
	pgoff_t page_index = sgx_encl_get_index(encl, encl_page);
	unsigned long pcmd_offset =
		(page_index & (PAGE_SIZE / sizeof(struct sgx_pcmd) - 1)) *
		sizeof(struct sgx_pcmd);
	unsigned long page_addr = encl->backing + page_index * PAGE_SIZE;
	unsigned long pcmd_addr = encl->backing + encl->size + PAGE_SIZE +
				  ((page_index * PAGE_SIZE) >> 5);
	struct sgx_pageinfo pginfo;
	struct page *backing;
	struct page *pcmd;
	int ret;

	ret = get_user_pages_remote(NULL, encl->mm, page_addr, 1, FOLL_WRITE,
				    &backing, NULL, NULL);
	if (ret < 0)
		goto err_backing;

	ret = get_user_pages_remote(NULL, encl->mm, pcmd_addr, 1, FOLL_WRITE,
				    &pcmd, NULL, NULL);
	if (ret < 0)
		goto err_pcmd;

	pginfo.addr = 0;
	pginfo.contents = (unsigned long)kmap_atomic(backing);
	pginfo.metadata = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.secs = 0;
	ret = __ewb(&pginfo, sgx_epc_addr(epc_page),
		    sgx_epc_addr(va_page->epc_page) + va_offset);
	kunmap_atomic((void *)(unsigned long)(pginfo.metadata - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	set_page_dirty(pcmd);
	put_page(pcmd);
	set_page_dirty(backing);

err_pcmd:
	put_page(backing);

err_backing:
	return ret;
}

/**
 * sgx_encl_ewb - write a page to the backing storage
 *
 * Writes an EPC page to the the enclave backing storage. Flushes the CPUs and
 * retries if there are hardware threads that can potentially have TLB entries
 * to the page (indicated by SGX_NOT_TRACKED). Clears the reserved flag after
 * the page has been swapped.
 *
 * @epc_page:	an EPC page
 */
void sgx_encl_ewb(struct sgx_epc_page *epc_page, bool do_free)
{
	struct sgx_encl_page *encl_page = to_encl_page(epc_page);
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_va_page *va_page;
	unsigned int va_offset;
	int ret;

	encl_page->desc &= ~SGX_ENCL_PAGE_RECLAIMED;

	if (!(encl->flags & SGX_ENCL_DEAD)) {
		va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
					   list);
		va_offset = sgx_alloc_va_slot(va_page);
		if (sgx_va_page_full(va_page))
			list_move_tail(&va_page->list, &encl->va_pages);

		ret = __sgx_encl_ewb(encl, epc_page, va_page, va_offset);
		if (ret == SGX_NOT_TRACKED) {
			sgx_encl_etrack(encl);
			ret = __sgx_encl_ewb(encl, epc_page, va_page,
					     va_offset);
			if (ret == SGX_NOT_TRACKED) {
				/* slow path, IPI needed */
				sgx_flush_cpus(encl);
				ret = __sgx_encl_ewb(encl, epc_page, va_page,
						     va_offset);
			}
		}

		/* Invalidate silently as the backing VMA has been kicked out.
		 */
		if (ret < 0)
			sgx_invalidate(encl, true);
		else
			SGX_INVD(ret, encl, "EWB returned %d (0x%x)",
				 ret, ret);

		encl_page->desc |= va_offset;
		encl_page->va_page = va_page;
	} else if (!do_free) {
		ret = __eremove(sgx_epc_addr(epc_page));
		WARN(ret, "EREMOVE returned %d\n", ret);
	}

	if (do_free)
		sgx_free_page(epc_page);

	encl_page->epc_page = NULL;
}

static int __sgx_encl_eldu(struct sgx_encl_page *encl_page,
			   struct sgx_epc_page *epc_page)
{
	unsigned long addr = SGX_ENCL_PAGE_ADDR(encl_page);
	unsigned long va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	pgoff_t page_index = sgx_encl_get_index(encl, encl_page);
	unsigned long pcmd_offset =
		(page_index & (PAGE_SIZE / sizeof(struct sgx_pcmd) - 1)) *
		sizeof(struct sgx_pcmd);
	unsigned long page_addr = encl->backing + page_index * PAGE_SIZE;
	unsigned long pcmd_addr = encl->backing + encl->size + PAGE_SIZE +
				  ((page_index * PAGE_SIZE) >> 5);
	struct sgx_pageinfo pginfo;
	struct page *backing;
	struct page *pcmd;
	int ret;

	ret = get_user_pages_remote(NULL, encl->mm, page_addr, 1, 0, &backing,
				    NULL, NULL);
	if (ret < 0)
		goto err_backing;

	ret = get_user_pages_remote(NULL, encl->mm, pcmd_addr, 1, 0, &pcmd,
				    NULL, NULL);
	if (ret < 0)
		goto err_pcmd;

	pginfo.addr = addr;
	pginfo.contents = (unsigned long)kmap_atomic(backing);
	pginfo.metadata = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.secs = addr ? (unsigned long)sgx_epc_addr(encl->secs.epc_page) :
		      0;

	ret = __eldu(&pginfo, sgx_epc_addr(epc_page),
		     sgx_epc_addr(encl_page->va_page->epc_page) + va_offset);
	if (ret) {
		SGX_INVD(ret, encl, "ELDU returned %d (0x%x)", ret, ret);
		ret = encls_to_err(ret);
	}

	kunmap_atomic((void *)(unsigned long)(pginfo.metadata - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	put_page(pcmd);

err_pcmd:
	put_page(backing);

err_backing:
	/* Invalidate silently as the backing VMA has been kicked out. */
	if (ret < 0)
		sgx_invalidate(encl, true);

	return ret;
}

/**
 * sgx_encl_ewb - read a page from the backing storage
 *
 * Read an EPC page from the the enclave backing storage.
 *
 * @epc_page:	an EPC page
 */
struct sgx_epc_page *sgx_encl_eldu(struct sgx_encl_page *encl_page)
{
	unsigned long va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_page(encl_page, false);
	if (IS_ERR(epc_page))
		return epc_page;

	ret = __sgx_encl_eldu(encl_page, epc_page);
	if (ret) {
		sgx_free_page(epc_page);
		return ERR_PTR(ret);
	}

	sgx_free_va_slot(encl_page->va_page, va_offset);
	list_move(&encl_page->va_page->list, &encl->va_pages);
	encl_page->desc &= ~SGX_ENCL_PAGE_VA_OFFSET_MASK;
	encl_page->epc_page = epc_page;

	return epc_page;
}
