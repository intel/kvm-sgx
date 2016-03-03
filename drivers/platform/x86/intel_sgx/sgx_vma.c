// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <asm/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include "sgx.h"

static void sgx_vma_open(struct vm_area_struct *vma)
{
	struct sgx_encl *encl = vma->vm_private_data;

	if (!encl)
		return;

	/* kref cannot underflow because ECREATE ioctl checks that there is only
	 * one single VMA for the enclave before proceeding.
	 */
	kref_get(&encl->refcount);
}

static void sgx_vma_close(struct vm_area_struct *vma)
{
	struct sgx_encl *encl = vma->vm_private_data;

	if (!encl)
		return;

	mutex_lock(&encl->lock);
	sgx_invalidate(encl, true);
	mutex_unlock(&encl->lock);
	kref_put(&encl->refcount, sgx_encl_release);
}

static int sgx_vma_fault(struct vm_fault *vmf)
{
	unsigned long addr = (unsigned long)vmf->address;
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_encl_page *entry;

	entry = sgx_fault_page(vma, addr, 0);

	if (!IS_ERR(entry) || PTR_ERR(entry) == -EBUSY)
		return VM_FAULT_NOPAGE;
	else
		return VM_FAULT_SIGBUS;
}

static int sgx_edbgrd(struct sgx_encl *encl, struct sgx_encl_page *page,
		      unsigned long addr, void *data)
{
	unsigned long offset;
	int ret;

	offset = addr & ~PAGE_MASK;

	if ((page->desc & SGX_ENCL_PAGE_TCS) &&
	    offset > offsetof(struct sgx_tcs, gs_limit))
		return -ECANCELED;

	ret = __edbgrd(sgx_epc_addr(page->epc_page) + offset, data);
	if (ret) {
		sgx_dbg(encl, "EDBGRD returned %d\n", ret);
		return ENCLS_TO_ERR(ret);
	}

	return 0;
}

static int sgx_edbgwr(struct sgx_encl *encl, struct sgx_encl_page *page,
		      unsigned long addr, void *data)
{
	unsigned long offset;
	int ret;

	offset = addr & ~PAGE_MASK;

	/* Writing anything else than flags will cause #GP */
	if ((page->desc & SGX_ENCL_PAGE_TCS) &&
	    offset != offsetof(struct sgx_tcs, flags))
		return -ECANCELED;

	ret = __edbgwr(sgx_epc_addr(page->epc_page) + offset, data);
	if (ret) {
		sgx_dbg(encl, "EDBGWR returned %d\n", ret);
		return ENCLS_TO_ERR(ret);
	}

	return 0;
}

static int sgx_vma_access(struct vm_area_struct *vma, unsigned long addr,
			  void *buf, int len, int write)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry = NULL;
	unsigned long align;
	char data[sizeof(unsigned long)];
	int offset;
	int cnt;
	int ret = 0;
	int i;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return -EFAULT;

	if (!(encl->flags & SGX_ENCL_DEBUG) ||
	    !(encl->flags & SGX_ENCL_INITIALIZED) ||
	    (encl->flags & SGX_ENCL_DEAD))
		return -EFAULT;

	for (i = 0; i < len; i += cnt) {
		if (!entry || !((addr + i) & (PAGE_SIZE - 1))) {
			if (entry)
				entry->desc &= ~SGX_ENCL_PAGE_RESERVED;

			entry = sgx_fault_page(vma, (addr + i) & PAGE_MASK,
					       true);
			if (IS_ERR(entry)) {
				ret = PTR_ERR(entry);
				entry = NULL;
				break;
			}
		}

		/* Locking is not needed because only immutable fields of the
		 * page are accessed and page itself is reserved so that it
		 * cannot be swapped out in the middle.
		 */

		align = ALIGN_DOWN(addr + i, sizeof(unsigned long));
		offset = (addr + i) & (sizeof(unsigned long) - 1);
		cnt = sizeof(unsigned long) - offset;
		cnt = min(cnt, len - i);

		ret = sgx_edbgrd(encl, entry, align, data);
		if (ret)
			break;
		if (write) {
			memcpy(data + offset, buf + i, cnt);
			ret = sgx_edbgwr(encl, entry, align, data);
			if (ret)
				break;
		} else
			memcpy(buf + i, data + offset, cnt);
	}

	if (entry)
		entry->desc &= ~SGX_ENCL_PAGE_RESERVED;

	return (ret < 0 && ret != -ECANCELED) ? ret : i;
}

const struct vm_operations_struct sgx_vm_ops = {
	.close = sgx_vma_close,
	.open = sgx_vma_open,
	.fault = sgx_vma_fault,
	.access = sgx_vma_access,
};
