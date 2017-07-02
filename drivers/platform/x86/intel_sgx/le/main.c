/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016, 2017 Intel Corporation.
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
 * Copyright(c) 2016, 2017 Intel Corporation.
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
 */

#include <linux/types.h>
#include <asm/sgx_arch.h>
#include <sgx_encl.h>
#include <uapi/asm/sgx.h>

#define SGX_LE_PROXY_FD 3
#define SGX_LE_DEV_FD 4

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

extern unsigned char sgx_aex[];
extern unsigned char sgx_le_blob[];
extern unsigned char sgx_le_blob_end[];
extern unsigned char sgx_le_ss[];

static void *start_launch_enclave(void)
{
	struct sgx_enclave_create create_ioc;
	struct sgx_enclave_add_page add_ioc;
	struct sgx_enclave_init init_ioc;
	struct sgx_secs secs;
	struct sgx_secinfo secinfo;
	unsigned long blob_base;
	unsigned long blob_size;
	unsigned long offset;
	int rc;

	sgx_memset(&secs, 0, sizeof(secs));
	sgx_memset(&secinfo, 0, sizeof(secinfo));

	secs.ssaframesize = 1;
	secs.attributes = SGX_ATTR_MODE64BIT | SGX_ATTR_EINITTOKENKEY;
	secs.xfrm = 3;

	blob_base = (unsigned long)&sgx_le_blob;
	blob_size = (unsigned long)&sgx_le_blob_end - blob_base;

	for (secs.size = 4096; secs.size < blob_size; secs.size <<= 1);

	secs.base = (unsigned long)sgx_sys_mmap(SGX_LE_DEV_FD, secs.size);
	if (secs.base == (unsigned long)MAP_FAILED)
		goto out;

	create_ioc.src = (unsigned long)&secs;
	rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_CREATE, &create_ioc);
	if (rc)
		goto out;

	add_ioc.secinfo = (unsigned long)&secinfo;
	add_ioc.mrmask = 0xFFFF;

	for (offset = 0; offset < blob_size; offset += 0x1000) {
		if (!offset)
			secinfo.flags = SGX_SECINFO_TCS;
		else
			secinfo.flags = SGX_SECINFO_REG | SGX_SECINFO_R |
					SGX_SECINFO_W | SGX_SECINFO_X;

		add_ioc.addr = secs.base + offset;
		add_ioc.src = blob_base + offset;

		rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_ADD_PAGE,
				   &add_ioc);
		if (rc)
			goto out;
	}

	init_ioc.addr = secs.base;
	init_ioc.sigstruct = (uint64_t)&sgx_le_ss;
	init_ioc.flags = SGX_ENCLAVE_INIT_ARCH;
	rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_INIT, &init_ioc);
	if (rc)
		goto out;

	return (void *)secs.base;
out:
	return NULL;
}

static int read_input(void *data, unsigned int len)
{
	uint8_t *ptr = (uint8_t *)data;
	long i;
	long ret;

	for (i = 0; i < len; ) {
		ret = sgx_sys_read(&ptr[i], len - i);
		if (ret < 0)
			return ret;

		i += ret;
	}

	return 0;
}

static int write_token(const struct sgx_einittoken *token)
{
	const uint8_t *ptr = (const uint8_t *)token;
	long i;
	long ret;

	for (i = 0; i < sizeof(*token); ) {
		ret = sgx_sys_write(&ptr[i], sizeof(*token) - i);
		if (ret < 0)
			return ret;

		i += ret;
	}

	return 0;
}

void _start(void)
{
	struct sgx_einittoken token;
	struct sgx_le_request req;
	uint8_t mrenclave[32];
	uint8_t mrsigner[32];
	uint64_t attributes;
	uint64_t xfrm;
	void *entry;

	sgx_sys_close(SGX_LE_PROXY_FD);
	entry = start_launch_enclave();
	sgx_sys_close(SGX_LE_DEV_FD);
	if (!entry)
		sgx_sys_exit(1);

	for ( ; ; ) {
		if (read_input(mrenclave, sizeof(mrenclave)))
			sgx_sys_exit(1);

		if (read_input(mrsigner, sizeof(mrsigner)))
			sgx_sys_exit(1);

		if (read_input(&attributes, sizeof(uint64_t)))
			sgx_sys_exit(1);

		if (read_input(&xfrm, sizeof(uint64_t)))
			sgx_sys_exit(1);

		req.mrenclave = mrenclave;
		req.mrsigner = mrsigner;
		req.attributes = attributes;
		req.xfrm = xfrm;

		sgx_memset(&token, 0, sizeof(token));
		req.einittoken = &token;
		sgx_le_request_token(&req, entry);

		if (write_token(&token))
			sgx_sys_exit(1);
	}

	__builtin_unreachable();
}
