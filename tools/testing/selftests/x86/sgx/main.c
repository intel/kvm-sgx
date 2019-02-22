// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <asm/sgx_arch.h>
#include "encl_piggy.h"
#include "defines.h"
#include "../../../../../arch/x86/include/uapi/asm/sgx.h"

static const uint64_t MAGIC = 0x1122334455667788ULL;

static bool encl_create(int dev_fd, unsigned long bin_size,
			struct sgx_secs *secs)
{
	struct sgx_enclave_create ioc;
	void *base;
	int rc;

	memset(secs, 0, sizeof(*secs));
	secs->ssa_frame_size = 1;
	secs->attributes = SGX_ATTR_MODE64BIT;
	secs->xfrm = 3;

	for (secs->size = 4096; secs->size < bin_size; )
		secs->size <<= 1;

	base = mmap(NULL, secs->size, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_SHARED, dev_fd, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	secs->base = (uint64_t)base;

	ioc.src = (unsigned long)secs;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_CREATE, &ioc);
	if (rc) {
		fprintf(stderr, "ECREATE failed rc=%d.\n", rc);
		munmap(base, secs->size);
		return false;
	}

	return true;
}

static bool encl_add_page(int dev_fd, unsigned long addr, void *data,
			  uint64_t flags)
{
	struct sgx_enclave_add_page ioc;
	struct sgx_secinfo secinfo;
	int rc;

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = flags;

	ioc.secinfo = (unsigned long)&secinfo;
	ioc.mrmask = 0xFFFF;
	ioc.addr = addr;
	ioc.src = (uint64_t)data;

	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_ADD_PAGE, &ioc);
	if (rc) {
		fprintf(stderr, "EADD failed rc=%d.\n", rc);
		return false;
	}

	return true;
}

static bool encl_load(struct sgx_secs *secs, unsigned long bin_size)
{
	struct sgx_enclave_init ioc;
	uint64_t offset;
	uint64_t flags;
	int dev_fd;
	int rc;

	dev_fd = open("/dev/sgx", O_RDWR);
	if (dev_fd < 0) {
		fprintf(stderr, "Unable to open /dev/sgx\n");
		return false;
	}

	if (!encl_create(dev_fd, bin_size, secs))
		goto out_dev_fd;

	for (offset = 0; offset < bin_size; offset += 0x1000) {
		if (!offset)
			flags = SGX_SECINFO_TCS;
		else
			flags = SGX_SECINFO_REG | SGX_SECINFO_R |
				SGX_SECINFO_W | SGX_SECINFO_X;

		if (!encl_add_page(dev_fd, secs->base + offset,
				   encl_bin + offset, flags))
			goto out_map;
	}

	ioc.addr = secs->base;
	ioc.sigstruct = (uint64_t)&encl_ss;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_INIT, &ioc);
	if (rc) {
		printf("EINIT failed rc=%d\n", rc);
		goto out_map;
	}

	close(dev_fd);
	return true;
out_map:
	munmap((void *)secs->base, secs->size);
out_dev_fd:
	close(dev_fd);
	return false;
}

void sgx_call(void *rdi, void *rsi, void *entry);

int main(int argc, char **argv)
{
	unsigned long bin_size = encl_bin_end - encl_bin;
	unsigned long ss_size = encl_ss_end - encl_ss;
	struct sgx_secs secs;
	uint64_t result = 0;

	printf("Binary size %lu (0x%lx), SIGSTRUCT size %lu\n", bin_size,
	       bin_size, ss_size);
	if (ss_size != sizeof(struct sgx_sigstruct)) {
		fprintf(stderr, "The size of SIGSTRUCT should be %lu\n",
			sizeof(struct sgx_sigstruct));
		exit(1);
	}

	printf("Loading the enclave.\n");
	if (!encl_load(&secs, bin_size))
		exit(1);

	printf("Input: 0x%lx\n", MAGIC);
	sgx_call((void *)&MAGIC, &result, (void *)secs.base);
	if (result != MAGIC) {
		fprintf(stderr, "0x%lx != 0x%lx\n", result, MAGIC);
		exit(1);
	}

	printf("Output: 0x%lx\n", result);
	exit(0);
}
