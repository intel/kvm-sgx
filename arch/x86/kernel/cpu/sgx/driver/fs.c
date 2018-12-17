// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/acpi.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/security.h>
#include <linux/suspend.h>
#include <asm/traps.h>
#include "driver.h"

const struct file_operations sgx_fs_provision_fops;

static struct dentry *sgx_fs;
static struct dentry *sgx_fs_provision;

int sgx_fs_init(struct device *dev)
{
	int ret;

	sgx_fs = securityfs_create_dir(dev_name(dev), NULL);
	if (IS_ERR(sgx_fs)) {
		ret = PTR_ERR(sgx_fs);
		goto err_sgx_fs;
	}

	sgx_fs_provision = securityfs_create_file("provision", 0600, sgx_fs,
						  NULL, &sgx_fs_provision_fops);
	if (IS_ERR(sgx_fs)) {
		ret = PTR_ERR(sgx_fs_provision);
		goto err_sgx_fs_provision;
	}

	return 0;

err_sgx_fs_provision:
	securityfs_remove(sgx_fs);
	sgx_fs_provision = NULL;

err_sgx_fs:
	sgx_fs = NULL;
	return ret;
}

void sgx_fs_remove(void)
{
	securityfs_remove(sgx_fs_provision);
	securityfs_remove(sgx_fs);
}
