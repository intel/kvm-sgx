/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 * Sean Christopherson <sean.j.christopherson@intel.com>
 */

#include "sgx.h"
#include <linux/acpi.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/hashtable.h>
#include <linux/kthread.h>
#include <linux/platform_device.h>
#include <linux/cdev.h>

#define DRV_DESCRIPTION "Intel SGX Driver"
#define DRV_VERSION "0.10"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>");
MODULE_VERSION(DRV_VERSION);

/*
 * Global data.
 */

struct workqueue_struct *sgx_add_page_wq;
#define SGX_MAX_EPC_BANKS 8
struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];
int sgx_nr_epc_banks;
u64 sgx_encl_size_max_32;
u64 sgx_encl_size_max_64;
u64 sgx_xfrm_mask = 0x3;
u32 sgx_misc_reserved;
u32 sgx_xsave_size_tbl[64];

#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	return sgx_ioctl(filep, cmd, arg);
}
#endif

static int sgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &sgx_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO |
			 VM_DONTCOPY;

	return 0;
}

static unsigned long sgx_get_unmapped_area(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if (len < 2 * PAGE_SIZE || (len & (len - 1)))
		return -EINVAL;

	/* On 64-bit architecture, allow mmap() to exceed 32-bit encl
	 * limit only if the task is not running in 32-bit compatibility
	 * mode.
	 */
	if (len > sgx_encl_size_max_32)
#ifdef CONFIG_X86_64
		if (test_thread_flag(TIF_ADDR32))
			return -EINVAL;
#else
		return -EINVAL;
#endif

#ifdef CONFIG_X86_64
	if (len > sgx_encl_size_max_64)
		return -EINVAL;
#endif

	addr = current->mm->get_unmapped_area(file, addr, 2 * len, pgoff,
					      flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	addr = (addr + (len - 1)) & ~(len - 1);

	return addr;
}

static const struct file_operations sgx_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= sgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sgx_compat_ioctl,
#endif
	.mmap			= sgx_mmap,
	.get_unmapped_area	= sgx_get_unmapped_area,
};

static int sgx_pm_suspend(struct device *dev)
{
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &ctx->encl_list, encl_list) {
			sgx_invalidate(encl, false);
			encl->flags |= SGX_ENCL_SUSPEND;
			flush_work(&encl->add_page_work);
		}
	}

	return 0;
}

static SIMPLE_DEV_PM_OPS(sgx_drv_pm, sgx_pm_suspend, NULL);

static struct bus_type sgx_bus_type = {
	.name	= "sgx",
};

struct sgx_context {
	struct device dev;
	struct cdev cdev;
};

static dev_t sgx_devt;

static void sgx_dev_release(struct device *dev)
{
	struct sgx_context *ctx = container_of(dev, struct sgx_context, dev);

	kfree(ctx);
}

static struct sgx_context *sgx_ctx_alloc(struct device *parent)
{
	struct sgx_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	device_initialize(&ctx->dev);

	ctx->dev.bus = &sgx_bus_type;
	ctx->dev.parent = parent;
	ctx->dev.devt = MKDEV(MAJOR(sgx_devt), 0);
	ctx->dev.release = sgx_dev_release;

	dev_set_name(&ctx->dev, "sgx");

	cdev_init(&ctx->cdev, &sgx_fops);
	ctx->cdev.owner = THIS_MODULE;

	dev_set_drvdata(parent, ctx);

	return ctx;
}

static struct sgx_context *sgxm_ctx_alloc(struct device *parent)
{
	struct sgx_context *ctx;
	int rc;

	ctx = sgx_ctx_alloc(parent);
	if (IS_ERR(ctx))
		return ctx;

	rc = devm_add_action_or_reset(parent, (void (*)(void *))put_device,
				      &ctx->dev);
	if (rc) {
		kfree(ctx);
		return ERR_PTR(rc);
	}

	return ctx;
}

static int sgx_dev_init(struct device *parent)
{
	struct sgx_context *sgx_dev;
	unsigned int eax, ebx, ecx, edx;
	unsigned long pa;
	unsigned long size;
	int ret;
	int i;

	pr_info("intel_sgx: " DRV_DESCRIPTION " v" DRV_VERSION "\n");

	sgx_dev = sgxm_ctx_alloc(parent);

	cpuid_count(SGX_CPUID, SGX_CPUID_CAPABILITIES, &eax, &ebx, &ecx, &edx);
	/* Only allow misc bits supported by the driver. */
	sgx_misc_reserved = ~ebx | SGX_MISC_RESERVED_MASK;
#ifdef CONFIG_X86_64
	sgx_encl_size_max_64 = 1ULL << ((edx >> 8) & 0xFF);
#endif
	sgx_encl_size_max_32 = 1ULL << (edx & 0xFF);

	if (boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		cpuid_count(SGX_CPUID, SGX_CPUID_ATTRIBUTES, &eax, &ebx, &ecx,
			    &edx);
		sgx_xfrm_mask = (((u64)edx) << 32) + (u64)ecx;

		for (i = 2; i < 64; i++) {
			cpuid_count(0x0D, i, &eax, &ebx, &ecx, &edx);
			if ((1 << i) & sgx_xfrm_mask)
				sgx_xsave_size_tbl[i] = eax + ebx;
		}
	}

	for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_EPC_BANKS, &eax, &ebx,
			    &ecx, &edx);
		if (!(eax & 0xf))
			break;

		pa = ((u64)(ebx & 0xfffff) << 32) + (u64)(eax & 0xfffff000);
		size = ((u64)(edx & 0xfffff) << 32) + (u64)(ecx & 0xfffff000);

		dev_info(parent, "EPC bank 0x%lx-0x%lx\n", pa, pa + size);

		sgx_epc_banks[i].pa = pa;
		sgx_epc_banks[i].size = size;
	}

	sgx_nr_epc_banks = i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
#ifdef CONFIG_X86_64
		sgx_epc_banks[i].va = (unsigned long)
			ioremap_cache(sgx_epc_banks[i].pa,
				      sgx_epc_banks[i].size);
		if (!sgx_epc_banks[i].va) {
			sgx_nr_epc_banks = i;
			ret = -ENOMEM;
			goto out_iounmap;
		}
#endif
		ret = sgx_add_epc_bank(sgx_epc_banks[i].pa,
				       sgx_epc_banks[i].size, i);
		if (ret) {
			sgx_nr_epc_banks = i + 1;
			goto out_iounmap;
		}
	}

	ret = sgx_page_cache_init();
	if (ret)
		goto out_iounmap;

	sgx_add_page_wq = alloc_workqueue("intel_sgx-add-page-wq",
					  WQ_UNBOUND | WQ_FREEZABLE, 1);
	if (!sgx_add_page_wq) {
		pr_err("intel_sgx: alloc_workqueue() failed\n");
		ret = -ENOMEM;
		goto out_iounmap;
	}

	ret = cdev_device_add(&sgx_dev->cdev, &sgx_dev->dev);
	if (ret)
		goto out_workqueue;

	return 0;
out_workqueue:
	destroy_workqueue(sgx_add_page_wq);
out_iounmap:
#ifdef CONFIG_X86_64
	for (i = 0; i < sgx_nr_epc_banks; i++)
		iounmap((void *)sgx_epc_banks[i].va);
#endif
	return ret;
}

static int sgx_drv_probe(struct platform_device *pdev)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned long fc;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return -ENODEV;

	if (!boot_cpu_has(X86_FEATURE_SGX)) {
		pr_err("intel_sgx: the CPU is missing SGX\n");
		return -ENODEV;
	}

	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		pr_err("intel_sgx: the CPU is missing launch control\n");
		return -ENODEV;
	}

	rdmsrl(MSR_IA32_FEATURE_CONTROL, fc);

	if (!(fc & FEATURE_CONTROL_LOCKED)) {
		pr_err("intel_sgx: the feature control MSR is not locked\n");
		return -ENODEV;
	}

	if (!(fc & FEATURE_CONTROL_SGX_ENABLE)) {
		pr_err("intel_sgx: SGX is not enabled\n");
		return -ENODEV;
	}

	cpuid(0, &eax, &ebx, &ecx, &edx);
	if (eax < SGX_CPUID) {
		pr_err("intel_sgx: CPUID is missing the SGX leaf\n");
		return -ENODEV;
	}

	cpuid_count(SGX_CPUID, SGX_CPUID_CAPABILITIES, &eax, &ebx, &ecx, &edx);
	if (!(eax & 1)) {
		pr_err("intel_sgx: CPU does not support the SGX1 instructions\n");
		return -ENODEV;
	}

	return sgx_dev_init(&pdev->dev);
}

static int sgx_drv_remove(struct platform_device *pdev)
{
	struct device *parent = &pdev->dev;
	struct sgx_context *ctx = dev_get_drvdata(parent);
	int i;

	cdev_device_del(&ctx->cdev, &ctx->dev);

	destroy_workqueue(sgx_add_page_wq);
#ifdef CONFIG_X86_64
	for (i = 0; i < sgx_nr_epc_banks; i++)
		iounmap((void *)sgx_epc_banks[i].va);
#endif
	sgx_page_cache_teardown();

	return 0;
}

#ifdef CONFIG_ACPI
static struct acpi_device_id sgx_device_ids[] = {
	{"INT0E0C", 0},
	{"", 0},
};
MODULE_DEVICE_TABLE(acpi, sgx_device_ids);
#endif

static struct platform_driver sgx_drv = {
	.probe = sgx_drv_probe,
	.remove = sgx_drv_remove,
	.driver = {
		.name			= "intel_sgx",
		.pm			= &sgx_drv_pm,
		.acpi_match_table	= ACPI_PTR(sgx_device_ids),
	},
};

static int __init sgx_drv_subsys_init(void)
{
	int ret;

	ret = bus_register(&sgx_bus_type);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&sgx_devt, 0, 1, "sgx");
	if (ret < 0) {
		bus_unregister(&sgx_bus_type);
		return ret;
	}

	return 0;
}

static void sgx_drv_subsys_exit(void)
{
	bus_unregister(&sgx_bus_type);
	unregister_chrdev_region(sgx_devt, 1);
}

static int __init sgx_drv_init(void)
{
	int ret;

	ret = sgx_drv_subsys_init();

	ret = platform_driver_register(&sgx_drv);
	if (ret)
		sgx_drv_subsys_exit();

	return ret;
}
module_init(sgx_drv_init);

static void __exit sgx_drv_exit(void)
{
	platform_driver_unregister(&sgx_drv);
	sgx_drv_subsys_exit();
}
module_exit(sgx_drv_exit);

MODULE_LICENSE("Dual BSD/GPL");
