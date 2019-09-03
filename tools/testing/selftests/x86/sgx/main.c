// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <elf.h>
#include <errno.h>
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
#include <sys/time.h>
#include <sys/types.h>
#include "defines.h"
#include "sgx_call.h"

#define PAGE_SIZE  4096

static const uint64_t MAGIC = 0x1122334455667788ULL;

static bool encl_create(int dev_fd, unsigned long bin_size,
			struct sgx_secs *secs)
{
	struct sgx_enclave_create ioc;
	void *area;
	int rc;

	memset(secs, 0, sizeof(*secs));
	secs->ssa_frame_size = 1;
	secs->attributes = SGX_ATTR_MODE64BIT;
	secs->xfrm = 3;

	for (secs->size = 4096; secs->size < bin_size; )
		secs->size <<= 1;

	area = mmap(NULL, secs->size * 2, PROT_NONE, MAP_SHARED, dev_fd, 0);
	if (area == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	secs->base = ((uint64_t)area + secs->size - 1) & ~(secs->size - 1);

	munmap(area, secs->base - (uint64_t)area);
	munmap((void *)(secs->base + secs->size),
	       (uint64_t)area + secs->size - secs->base);

	ioc.src = (unsigned long)secs;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_CREATE, &ioc);
	if (rc) {
		fprintf(stderr, "ECREATE failed rc=%d, err=%d.\n", rc, errno);
		munmap((void *)secs->base, secs->size);
		return false;
	}

	return true;
}

static bool encl_add_pages(int dev_fd, unsigned long offset, void *data,
			   unsigned long length, uint64_t flags)
{
	struct sgx_enclave_add_pages ioc;
	struct sgx_secinfo secinfo;
	int rc;

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = flags;

	ioc.src = (uint64_t)data;
	ioc.offset = offset;
	ioc.length = length;
	ioc.secinfo = (unsigned long)&secinfo;
	ioc.flags = SGX_PAGE_MEASURE;

	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_ADD_PAGES, &ioc);
	if (rc) {
		fprintf(stderr, "EADD failed rc=%d.\n", rc);
		return false;
	}

	if (ioc.count != ioc.length) {
		fprintf(stderr, "Partially processed, update the test.\n");
		return false;
	}

	return true;
}

#define SGX_REG_PAGE_FLAGS \
	(SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X)

static bool encl_build(struct sgx_secs *secs, void *bin,
		       unsigned long bin_size, struct sgx_sigstruct *sigstruct)
{
	struct sgx_enclave_init ioc;
	void *addr;
	int dev_fd;
	int rc;

	dev_fd = open("/dev/sgx/enclave", O_RDWR);
	if (dev_fd < 0) {
		fprintf(stderr, "Unable to open /dev/sgx\n");
		return false;
	}

	if (!encl_create(dev_fd, bin_size, secs))
		goto out_dev_fd;

	if (!encl_add_pages(dev_fd, 0, bin, PAGE_SIZE, SGX_SECINFO_TCS))
		goto out_dev_fd;

	if (!encl_add_pages(dev_fd, PAGE_SIZE, bin + PAGE_SIZE,
			    bin_size - PAGE_SIZE, SGX_REG_PAGE_FLAGS))
		goto out_dev_fd;

	ioc.sigstruct = (uint64_t)sigstruct;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_INIT, &ioc);
	if (rc) {
		printf("EINIT failed rc=%d\n", rc);
		goto out_map;
	}

	addr = mmap((void *)secs->base, PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_FIXED, dev_fd, 0);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "mmap() failed on TCS, errno=%d.\n", errno);
		return false;
	}

	addr = mmap((void *)(secs->base + PAGE_SIZE), bin_size - PAGE_SIZE,
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_SHARED | MAP_FIXED, dev_fd, 0);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "mmap() failed, errno=%d.\n", errno);
		return false;
	}

	close(dev_fd);
	return true;
out_map:
	munmap((void *)secs->base, secs->size);
out_dev_fd:
	close(dev_fd);
	return false;
}

bool get_file_size(const char *path, off_t *bin_size)
{
	struct stat sb;
	int ret;

	ret = stat(path, &sb);
	if (ret) {
		perror("stat");
		return false;
	}

	if (!sb.st_size || sb.st_size & 0xfff) {
		fprintf(stderr, "Invalid blob size %lu\n", sb.st_size);
		return false;
	}

	*bin_size = sb.st_size;
	return true;
}

bool encl_data_map(const char *path, void **bin, off_t *bin_size)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)  {
		fprintf(stderr, "open() %s failed, errno=%d.\n", path, errno);
		return false;
	}

	if (!get_file_size(path, bin_size))
		goto err_out;

	*bin = mmap(NULL, *bin_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*bin == MAP_FAILED) {
		fprintf(stderr, "mmap() %s failed, errno=%d.\n", path, errno);
		goto err_out;
	}

	close(fd);
	return true;

err_out:
	close(fd);
	return false;
}

bool load_sigstruct(const char *path, void *sigstruct)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)  {
		fprintf(stderr, "open() %s failed, errno=%d.\n", path, errno);
		return false;
	}

	if (read(fd, sigstruct, sizeof(struct sgx_sigstruct)) !=
	    sizeof(struct sgx_sigstruct)) {
		fprintf(stderr, "read() %s failed, errno=%d.\n", path, errno);
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

int main(int argc, char *argv[], char *envp[])
{
	struct sgx_sigstruct sigstruct;
	struct sgx_secs secs;
	uint64_t result = 0;
	off_t bin_size;
	void *bin;

	if (!encl_data_map("encl.bin", &bin, &bin_size))
		exit(1);

	if (!load_sigstruct("encl.ss", &sigstruct))
		exit(1);

	if (!encl_build(&secs, bin, bin_size, &sigstruct))
		exit(1);

	printf("Input: 0x%lx\n", MAGIC);

	sgx_call_eenter((void *)&MAGIC, &result, (void *)secs.base);
	if (result != MAGIC) {
		fprintf(stderr, "0x%lx != 0x%lx\n", result, MAGIC);
		exit(1);
	}

	printf("Output: 0x%lx\n", result);

	exit(0);
}
