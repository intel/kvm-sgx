// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <asm/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "sgx.h"

static int sgx_encl_get(unsigned long addr, struct sgx_encl **encl)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int ret;

	if (addr & (PAGE_SIZE - 1))
		return -EINVAL;

	down_read(&mm->mmap_sem);

	ret = sgx_encl_find(mm, addr, &vma);
	if (!ret) {
		*encl = vma->vm_private_data;

		if ((*encl)->flags & SGX_ENCL_SUSPEND)
			ret = SGX_POWER_LOST_ENCLAVE;
		else
			kref_get(&(*encl)->refcount);
	}

	up_read(&mm->mmap_sem);
	return ret;
}

/**
 * sgx_ioc_enclave_create - handler for %SGX_IOC_ENCLAVE_CREATE
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to an &sgx_enclave_create instance
 *
 * Validates SECS attributes, allocates an EPC page for the SECS and performs
 * ECREATE.
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_create(struct file *filep, unsigned int cmd,
				   unsigned long arg)
{
	struct sgx_enclave_create *createp = (struct sgx_enclave_create *)arg;
	struct page *secs_page;
	struct sgx_secs *secs;
	struct sgx_encl *encl;
	int ret;

	secs_page = alloc_page(GFP_HIGHUSER);
	if (!secs_page)
		return -ENOMEM;

	secs = kmap(secs_page);
	ret = copy_from_user(secs, (void __user *)createp->src, sizeof(*secs));
	if (ret)
		goto out;

	encl = sgx_encl_alloc(secs);
	if (IS_ERR(encl)) {
		ret = PTR_ERR(encl);
		goto out;
	}

	ret = sgx_encl_create(encl, secs);
	if (ret)
		kref_put(&encl->refcount, sgx_encl_release);

out:
	kunmap(secs_page);
	__free_page(secs_page);
	return ret;
}

/**
 * sgx_ioc_enclave_add_page - handler for %SGX_IOC_ENCLAVE_ADD_PAGE
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to an &sgx_enclave_add_page instance
 *
 * Creates a new enclave page and enqueues an EADD operation that will be
 * processed by a worker thread later on.
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_add_page(struct file *filep, unsigned int cmd,
				     unsigned long arg)
{
	struct sgx_enclave_add_page *addp = (void *)arg;
	struct sgx_secinfo secinfo;
	struct sgx_encl *encl;
	struct page *data_page;
	void *data;
	int ret;

	ret = sgx_encl_get(addp->addr, &encl);
	if (ret)
		return ret;

	if (copy_from_user(&secinfo, (void __user *)addp->secinfo,
			   sizeof(secinfo))) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -EFAULT;
	}

	data_page = alloc_page(GFP_HIGHUSER);
	if (!data_page) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -ENOMEM;
	}

	data = kmap(data_page);

	ret = copy_from_user((void *)data, (void __user *)addp->src, PAGE_SIZE);
	if (ret)
		goto out;

	ret = sgx_encl_add_page(encl, addp->addr, data, &secinfo, addp->mrmask);
	if (ret)
		goto out;

out:
	kref_put(&encl->refcount, sgx_encl_release);
	kunmap(data_page);
	__free_page(data_page);
	return ret;
}

/**
 * sgx_ioc_enclave_init - handler for %SGX_IOC_ENCLAVE_INIT
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to an &sgx_enclave_init instance
 *
 * Flushes the remaining enqueued EADD operations and performs EINIT. Does not
 * allow the EINITTOKENKEY attribute for an enclave.
 *
 * Return:
 *   0 on success,
 *   SGX error code on EINIT failure,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_init(struct file *filep, unsigned int cmd,
				 unsigned long arg)
{
	struct sgx_enclave_init *initp = (struct sgx_enclave_init *)arg;
	struct sgx_sigstruct *sigstruct;
	struct sgx_einittoken *einittoken;
	struct sgx_encl *encl;
	struct page *initp_page;
	int ret;

	initp_page = alloc_page(GFP_HIGHUSER);
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page);
	einittoken = (struct sgx_einittoken *)
		((unsigned long)sigstruct + PAGE_SIZE / 2);
	memset(einittoken, 0, sizeof(*einittoken));

	ret = copy_from_user(sigstruct, (void __user *)initp->sigstruct,
			     sizeof(*sigstruct));
	if (ret)
		goto out;
	if (sigstruct->attributes & SGX_ATTR_EINITTOKENKEY) {
		ret = EINVAL;
		goto out;
	}

	ret = sgx_encl_get(initp->addr, &encl);
	if (ret)
		goto out;

	ret = sgx_encl_init(encl, sigstruct, einittoken);

	kref_put(&encl->refcount, sgx_encl_release);

out:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}

/**
 * sgx_ioc_enclave_remove_pages - handler for %SGX_IOC_ENCLAVE_REMOVE_PAGES
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_remove_pages
 *
 * Remove pages from an address range.
 *
 * Return:
 *   0 on success,
 *   SGX error code on EREMOVE failure,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_remove_pages(struct file *filep, unsigned int cmd,
					 unsigned long arg)
{
	struct sgx_enclave_remove_pages *params = (void *)arg;
	unsigned long length = params->length;
	unsigned long addr = params->addr;
	struct sgx_encl_page *page;
	struct vm_area_struct *vma;
	struct sgx_encl *encl;
	int ret;

	ret = sgx_encl_get(params->addr, &encl);
	if (ret)
		return ret;

	/* Address and length must align to page boundaries. */
	if ((addr & (PAGE_SIZE - 1)) || (length & (PAGE_SIZE - 1)) ||
	    addr < encl->base || length > encl->size) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -EINVAL;
	}

	down_read(&encl->mm->mmap_sem);
	mutex_lock(&encl->lock);

	for ( ; addr < (addr + length); addr += PAGE_SIZE) {
		ret = sgx_encl_find(encl->mm, addr, &vma);
		if (!vma) {
			ret = -EFAULT;
			break;
		}

		page = sgx_fault_page(vma, addr, true);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			break;
		}

		zap_vma_ptes(vma, addr, PAGE_SIZE);
		ret = __sgx_free_page(page->epc_page);
		if (ret) {
			page->desc &= ~SGX_ENCL_PAGE_RESERVED;
			break;
		}
		encl->secs_child_cnt--;
		radix_tree_delete(&encl->page_tree, PFN_DOWN(addr));
		kfree(page);
	}

	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);
	kref_put(&encl->refcount, sgx_encl_release);
	return ret;
}

typedef long (*sgx_ioc_t)(struct file *filep, unsigned int cmd,
			  unsigned long arg);

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	char data[256];
	sgx_ioc_t handler = NULL;
	long ret;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		handler = sgx_ioc_enclave_create;
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		handler = sgx_ioc_enclave_add_page;
		break;
	case SGX_IOC_ENCLAVE_INIT:
		handler = sgx_ioc_enclave_init;
		break;
	case SGX_IOC_ENCLAVE_REMOVE_PAGES:
		handler = sgx_ioc_enclave_remove_pages;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	if (copy_from_user(data, (void __user *)arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = handler(filep, cmd, (unsigned long)((void *)data));
	if (!ret && (cmd & IOC_OUT)) {
		if (copy_to_user((void __user *)arg, data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}
	if (IS_ENCLS_FAULT(ret))
		return -EFAULT;
	return ret;
}
