// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-19 Intel Corporation.

#include <asm/mman.h>
#include <linux/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include "driver.h"
#include "encl.h"
#include "encls.h"

static u32 sgx_calc_ssa_frame_size(u32 miscselect, u64 xfrm)
{
	u32 size_max = PAGE_SIZE;
	u32 size;
	int i;

	for (i = 2; i < 64; i++) {
		if (!((1 << i) & xfrm))
			continue;

		size = SGX_SSA_GPRS_SIZE + sgx_xsave_size_tbl[i];

		if (miscselect & SGX_MISC_EXINFO)
			size += SGX_SSA_MISC_EXINFO_SIZE;

		if (size > size_max)
			size_max = size;
	}

	return PFN_UP(size_max);
}

static int sgx_validate_secs(const struct sgx_secs *secs)
{
	u64 max_size = (secs->attributes & SGX_ATTR_MODE64BIT) ?
		       sgx_encl_size_max_64 : sgx_encl_size_max_32;

	if (secs->size < (2 * PAGE_SIZE) || !is_power_of_2(secs->size))
		return -EINVAL;

	if (secs->base & (secs->size - 1))
		return -EINVAL;

	if (secs->miscselect & sgx_misc_reserved_mask ||
	    secs->attributes & sgx_attributes_reserved_mask ||
	    secs->xfrm & sgx_xfrm_reserved_mask)
		return -EINVAL;

	if (secs->size >= max_size)
		return -EINVAL;

	if (!(secs->xfrm & XFEATURE_MASK_FP) ||
	    !(secs->xfrm & XFEATURE_MASK_SSE) ||
	    (((secs->xfrm >> XFEATURE_BNDREGS) & 1) !=
	     ((secs->xfrm >> XFEATURE_BNDCSR) & 1)))
		return -EINVAL;

	if (!secs->ssa_frame_size)
		return -EINVAL;

	if (sgx_calc_ssa_frame_size(secs->miscselect, secs->xfrm) >
	    secs->ssa_frame_size)
		return -EINVAL;

	if (memchr_inv(secs->reserved1, 0, sizeof(secs->reserved1)) ||
	    memchr_inv(secs->reserved2, 0, sizeof(secs->reserved2)) ||
	    memchr_inv(secs->reserved3, 0, sizeof(secs->reserved3)) ||
	    memchr_inv(secs->reserved4, 0, sizeof(secs->reserved4)))
		return -EINVAL;

	return 0;
}

static int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs)
{
	unsigned long encl_size = secs->size + PAGE_SIZE;
	struct sgx_epc_page *secs_epc;
	struct sgx_pageinfo pginfo;
	struct sgx_secinfo secinfo;
	struct file *backing;
	long ret;

	if (sgx_validate_secs(secs)) {
		pr_debug("invalid SECS\n");
		return -EINVAL;
	}

	backing = shmem_file_setup("SGX backing", encl_size + (encl_size >> 5),
				   VM_NORESERVE);
	if (IS_ERR(backing))
		return PTR_ERR(backing);

	encl->backing = backing;

	secs_epc = __sgx_alloc_epc_page();
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		goto err_out_backing;
	}

	encl->secs.epc_page = secs_epc;

	pginfo.addr = 0;
	pginfo.contents = (unsigned long)secs;
	pginfo.metadata = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));

	ret = __ecreate((void *)&pginfo, sgx_get_epc_addr(secs_epc));
	if (ret) {
		pr_debug("ECREATE returned %ld\n", ret);
		goto err_out;
	}

	if (secs->attributes & SGX_ATTR_DEBUG)
		atomic_or(SGX_ENCL_DEBUG, &encl->flags);

	encl->secs.encl = encl;
	encl->secs_attributes = secs->attributes;
	encl->allowed_attributes |= SGX_ATTR_ALLOWED_MASK;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->ssaframesize = secs->ssa_frame_size;

	/*
	 * Set SGX_ENCL_CREATED only after the enclave is fully prepped.  This
	 * allows setting and checking enclave creation without having to take
	 * encl->lock.
	 */
	atomic_or(SGX_ENCL_CREATED, &encl->flags);

	return 0;

err_out:
	sgx_free_epc_page(encl->secs.epc_page);
	encl->secs.epc_page = NULL;

err_out_backing:
	fput(encl->backing);
	encl->backing = NULL;

	return ret;
}

/**
 * sgx_ioc_enclave_create - handler for %SGX_IOC_ENCLAVE_CREATE
 * @filep:	open file to /dev/sgx
 * @arg:	userspace pointer to a struct sgx_enclave_create instance
 *
 * Allocate kernel data structures for a new enclave and execute ECREATE after
 * verifying the correctness of the provided SECS.
 *
 * Note, enforcement of restricted and disallowed attributes is deferred until
 * sgx_ioc_enclave_init(), only the architectural correctness of the SECS is
 * checked by sgx_ioc_enclave_create().
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_create(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_create ecreate;
	struct page *secs_page;
	struct sgx_secs *secs;
	int ret;

	if (atomic_read(&encl->flags) & SGX_ENCL_CREATED)
		return -EINVAL;

	if (copy_from_user(&ecreate, arg, sizeof(ecreate)))
		return -EFAULT;

	secs_page = alloc_page(GFP_KERNEL);
	if (!secs_page)
		return -ENOMEM;

	secs = kmap(secs_page);
	if (copy_from_user(secs, (void __user *)ecreate.src, sizeof(*secs))) {
		ret = -EFAULT;
		goto out;
	}

	ret = sgx_encl_create(encl, secs);

out:
	kunmap(secs_page);
	__free_page(secs_page);
	return ret;
}

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct sgx_encl *encl = filep->private_data;
	int ret, encl_flags;

	encl_flags = atomic_fetch_or(SGX_ENCL_IOCTL, &encl->flags);
	if (encl_flags & SGX_ENCL_IOCTL)
		return -EBUSY;

	if (encl_flags & SGX_ENCL_DEAD) {
		ret = -EFAULT;
		goto out;
	}

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		ret = sgx_ioc_enclave_create(encl, (void __user *)arg);
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

out:
	atomic_andnot(SGX_ENCL_IOCTL, &encl->flags);
	return ret;
}
