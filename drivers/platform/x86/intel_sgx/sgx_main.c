// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/acpi.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/suspend.h>
#include <asm/traps.h>
#include "sgx.h"

MODULE_DESCRIPTION("Intel SGX Driver");
MODULE_AUTHOR("Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>");
MODULE_LICENSE("Dual BSD/GPL");

struct workqueue_struct *sgx_add_page_wq;
u64 sgx_encl_size_max_32;
u64 sgx_encl_size_max_64;
u64 sgx_xfrm_mask = 0x3;
u32 sgx_misc_reserved;
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
	if (len < 2 * PAGE_SIZE || (len & (len - 1)))
		return -EINVAL;

	if (len > sgx_encl_size_max_64)
		return -EINVAL;

	if (len > sgx_encl_size_max_32 && test_thread_flag(TIF_ADDR32))
		return -EINVAL;

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
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	int ret;
	int i;

	sgx_dev = sgxm_ctx_alloc(parent);

	cpuid_count(SGX_CPUID, 0, &eax, &ebx, &ecx, &edx);
	/* Only allow misc bits supported by the driver. */
	sgx_misc_reserved = ~ebx | SGX_MISC_RESERVED_MASK;
	sgx_encl_size_max_64 = 1ULL << ((edx >> 8) & 0xFF);
	sgx_encl_size_max_32 = 1ULL << (edx & 0xFF);

	if (boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		cpuid_count(SGX_CPUID, 1, &eax, &ebx, &ecx, &edx);
		sgx_xfrm_mask = (((u64)edx) << 32) + (u64)ecx;

		for (i = 2; i < 64; i++) {
			cpuid_count(0x0D, i, &eax, &ebx, &ecx, &edx);
			if ((1 << i) & sgx_xfrm_mask)
				sgx_xsave_size_tbl[i] = eax + ebx;
		}
	}

	sgx_epcm_trapnr = boot_cpu_has(X86_FEATURE_SGX2) ?
				(X86_TRAP_PF | X86_PF_SGX) : X86_TRAP_GP;

	sgx_add_page_wq = alloc_workqueue("intel_sgx-add-page-wq",
					  WQ_UNBOUND | WQ_FREEZABLE, 1);
	if (!sgx_add_page_wq)
		return -ENOMEM;

	ret = cdev_device_add(&sgx_dev->cdev, &sgx_dev->dev);
	if (ret)
		goto out_workqueue;

	return 0;
out_workqueue:
	destroy_workqueue(sgx_add_page_wq);
	return ret;
}

static int sgx_drv_probe(struct platform_device *pdev)
{
	if (!sgx_enabled || !sgx_lc_enabled)
		return -ENODEV;

	return sgx_dev_init(&pdev->dev);
}

static int sgx_drv_remove(struct platform_device *pdev)
{
	struct sgx_context *ctx = dev_get_drvdata(&pdev->dev);

	cdev_device_del(&ctx->cdev, &ctx->dev);
	destroy_workqueue(sgx_add_page_wq);

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
	if (ret)
		return ret;

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
