// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/acpi.h>
#include <linux/cdev.h>
#include <linux/mman.h>
#include <linux/platform_device.h>
#include <linux/suspend.h>
#include <asm/traps.h>
#include "driver.h"

MODULE_DESCRIPTION("Intel SGX Enclave Driver");
MODULE_AUTHOR("Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>");
MODULE_LICENSE("Dual BSD/GPL");

struct workqueue_struct *sgx_encl_wq;
u64 sgx_encl_size_max_32;
u64 sgx_encl_size_max_64;
u32 sgx_misc_reserved_mask;
u64 sgx_attributes_reserved_mask;
u64 sgx_xfrm_reserved_mask = ~0x3;
u32 sgx_xsave_size_tbl[64];
int sgx_epcm_trapnr;

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
	if (len < 2 * PAGE_SIZE || len & (len - 1) || flags & MAP_PRIVATE)
		return -EINVAL;

	addr = current->mm->get_unmapped_area(file, addr, 2 * len, pgoff,
					      flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	addr = (addr + (len - 1)) & ~(len - 1);

	return addr;
}

static const struct file_operations sgx_ctrl_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= sgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sgx_compat_ioctl,
#endif
	.mmap			= sgx_mmap,
	.get_unmapped_area	= sgx_get_unmapped_area,
};

struct sgx_dev_ctx {
	struct device ctrl_dev;
	struct cdev ctrl_cdev;
};

static void sgx_dev_release(struct device *dev)
{
	struct sgx_dev_ctx *ctx = container_of(dev, struct sgx_dev_ctx,
					       ctrl_dev);

	kfree(ctx);
}

static int sgx_dev_ctx_alloc(const char *name,
			     const struct file_operations *fops)
{
	struct sgx_dev_ctx *ctx;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	device_initialize(&ctx->ctrl_dev);

	ctx->ctrl_dev.bus = &sgx_bus_type;
	ctx->ctrl_dev.devt = MKDEV(MAJOR(sgx_devt), 0);
	ctx->ctrl_dev.release = sgx_dev_release;

	ret = dev_set_name(&ctx->ctrl_dev, name);
	if (ret)
		goto out_error;

	cdev_init(&ctx->ctrl_cdev, fops);
	ctx->ctrl_cdev.owner = fops->owner;

	ret = cdev_device_add(&ctx->ctrl_cdev, &ctx->ctrl_dev);
	if (ret)
		goto out_error;

	return 0;

out_error:
	put_device(&ctx->ctrl_dev);
	return ret;
}

static int sgx_drv_init(void)
{
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	u64 attr_mask;
	u64 xfrm_mask;
	int ret;
	int i;

	cpuid_count(SGX_CPUID, 0, &eax, &ebx, &ecx, &edx);
	sgx_misc_reserved_mask = ~ebx | SGX_MISC_RESERVED_MASK;
	sgx_encl_size_max_64 = 1ULL << ((edx >> 8) & 0xFF);
	sgx_encl_size_max_32 = 1ULL << (edx & 0xFF);

	cpuid_count(SGX_CPUID, 1, &eax, &ebx, &ecx, &edx);

	attr_mask = (((u64)ebx) << 32) + (u64)eax;
	sgx_attributes_reserved_mask = ~attr_mask | SGX_ATTR_RESERVED_MASK;

	if (boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		xfrm_mask = (((u64)edx) << 32) + (u64)ecx;

		for (i = 2; i < 64; i++) {
			cpuid_count(0x0D, i, &eax, &ebx, &ecx, &edx);
			if ((1 << i) & xfrm_mask)
				sgx_xsave_size_tbl[i] = eax + ebx;
		}

		sgx_xfrm_reserved_mask = ~xfrm_mask;
	}

	sgx_epcm_trapnr = boot_cpu_has(X86_FEATURE_SGX2) ? X86_TRAP_PF :
							   X86_TRAP_GP;

	sgx_encl_wq = alloc_workqueue("sgx-encl-wq",
				      WQ_UNBOUND | WQ_FREEZABLE, 1);
	if (!sgx_encl_wq)
		return -ENOMEM;

	ret = sgx_dev_ctx_alloc("sgx", &sgx_ctrl_fops);
	if (ret)
		goto err_ctx_alloc;

	return 0;

err_ctx_alloc:
	destroy_workqueue(sgx_encl_wq);
	return ret;
}

int sgx_encl_drv_probe(void)
{
	if (!boot_cpu_has(X86_FEATURE_SGX))
		return -ENODEV;

	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		pr_warn("sgx: IA32_SGXLEPUBKEYHASHx MSRs are not writable\n");
		return -ENODEV;
	}

	return sgx_drv_init();
}
