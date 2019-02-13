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

static struct bus_type sgx_bus_type = {
	.name	= "sgx",
};

struct sgx_dev_ctx {
	struct device ctrl_dev;
	struct cdev ctrl_cdev;
};

static dev_t sgx_devt;

static void sgx_dev_release(struct device *dev)
{
	struct sgx_dev_ctx *ctx = container_of(dev, struct sgx_dev_ctx,
					       ctrl_dev);

	kfree(ctx);
}

static struct sgx_dev_ctx *sgx_dev_ctx_alloc(struct device *parent)
{
	struct sgx_dev_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	device_initialize(&ctx->ctrl_dev);

	ctx->ctrl_dev.bus = &sgx_bus_type;
	ctx->ctrl_dev.parent = parent;
	ctx->ctrl_dev.devt = MKDEV(MAJOR(sgx_devt), 0);
	ctx->ctrl_dev.release = sgx_dev_release;

	dev_set_name(&ctx->ctrl_dev, "sgx");

	cdev_init(&ctx->ctrl_cdev, &sgx_ctrl_fops);
	ctx->ctrl_cdev.owner = THIS_MODULE;

	dev_set_drvdata(parent, ctx);

	return ctx;
}

static struct sgx_dev_ctx *sgxm_dev_ctx_alloc(struct device *parent)
{
	struct sgx_dev_ctx *ctx;
	int rc;

	ctx = sgx_dev_ctx_alloc(parent);
	if (IS_ERR(ctx))
		return ctx;

	rc = devm_add_action_or_reset(parent, (void (*)(void *))put_device,
				      &ctx->ctrl_dev);
	if (rc)
		return ERR_PTR(rc);

	return ctx;
}

static int sgx_drv_init(struct device *parent)
{
	struct sgx_dev_ctx *sgx_dev;
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

	sgx_dev = sgxm_dev_ctx_alloc(parent);
	if (IS_ERR(sgx_dev)) {
		ret = PTR_ERR(sgx_dev);
		goto err_ctx_alloc;
	}

	ret = sgx_fs_init(&sgx_dev->ctrl_dev);
	if (ret)
		goto err_ctx_alloc;

	ret = cdev_device_add(&sgx_dev->ctrl_cdev, &sgx_dev->ctrl_dev);
	if (ret)
		goto err_device_add;

	return 0;

err_device_add:
	sgx_fs_remove();

err_ctx_alloc:
	destroy_workqueue(sgx_encl_wq);
	return ret;
}

static int sgx_drv_probe(struct platform_device *pdev)
{
	if (!boot_cpu_has(X86_FEATURE_SGX))
		return -ENODEV;

	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		pr_warn("sgx: IA32_SGXLEPUBKEYHASHx MSRs are not writable\n");
		return -ENODEV;
	}

	return sgx_drv_init(&pdev->dev);
}

static int sgx_drv_remove(struct platform_device *pdev)
{
	struct sgx_dev_ctx *ctx = dev_get_drvdata(&pdev->dev);

	sgx_fs_remove();
	cdev_device_del(&ctx->ctrl_cdev, &ctx->ctrl_dev);
	destroy_workqueue(sgx_encl_wq);

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
		.name			= "sgx",
		.acpi_match_table	= ACPI_PTR(sgx_device_ids),
	},
};

static int __init sgx_drv_subsys_init(void)
{
	int ret;

	ret = bus_register(&sgx_bus_type);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&sgx_devt, 0, SGX_DRV_NR_DEVICES, "sgx");
	if (ret < 0) {
		bus_unregister(&sgx_bus_type);
		return ret;
	}

	return 0;
}

static void sgx_drv_subsys_exit(void)
{
	bus_unregister(&sgx_bus_type);
	unregister_chrdev_region(sgx_devt, SGX_DRV_NR_DEVICES);
}

static int __init sgx_init(void)
{
	int ret;

	ret = sgx_drv_subsys_init();
	if (ret)
		return ret;

	ret = platform_driver_register(&sgx_drv);
	if (ret)
		sgx_drv_subsys_exit();

	return ret;
}
module_init(sgx_init);

static void __exit sgx_exit(void)
{
	platform_driver_unregister(&sgx_drv);
	sgx_drv_subsys_exit();
}
module_exit(sgx_exit);
