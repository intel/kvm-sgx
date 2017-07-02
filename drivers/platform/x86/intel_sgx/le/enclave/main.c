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

#include <tinycrypt/cmac_mode.h>
#include <stdbool.h>
#include <linux/types.h>
#include <asm/sgx_arch.h>
#include <uapi/asm/sgx.h>
#include <sgx_encl.h>

static bool get_rand_uint32(uint32_t *value)
{
	int i;

	for (i = 0; i < 10; i++) {
		if (__builtin_ia32_rdrand32_step((unsigned int *)value))
			return true;
	}

	return false;
}

static bool read_rand(uint8_t *data, unsigned long size)
{
	uint32_t value;
	uint8_t* bytes = (uint8_t *)&value;
	unsigned long i;

	for (i = 0; i < size; i++) {
		if (!(i & 3)) {
			if (!get_rand_uint32(&value))
				return false;
		}

		data[i] = bytes[i & 3];
	}

	return true;
}

static bool sign_einittoken(struct sgx_einittoken *einittoken)
{
	struct sgx_keyrequest keyrequest __attribute__((aligned (512)));
	uint8_t launch_key[16] __attribute__((aligned (16)));
	struct tc_cmac_struct cmac_state;
	struct tc_aes_key_sched_struct cmac_sched;

	/* a random unique key id */
	if (!read_rand(einittoken->keyid, sizeof(einittoken->keyid)))
		return false;

	sgx_memset(&keyrequest, 0, sizeof(keyrequest));
	keyrequest.keyname = 0; /* LICENSE_KEY */
	sgx_memcpy(&keyrequest.keyid, &einittoken->keyid,
		   sizeof(keyrequest.keyid));
	sgx_memcpy(&keyrequest.cpusvn, &(einittoken->cpusvnle),
		   sizeof(keyrequest.cpusvn));
	sgx_memcpy(&keyrequest.isvsvn, &(einittoken->isvsvnle),
		   sizeof(keyrequest.isvsvn));

	keyrequest.attributemask = ~SGX_ATTR_MODE64BIT;
	keyrequest.xfrmmask = 0;
	keyrequest.miscmask = 0xFFFFFFFF;

	einittoken->maskedmiscselectle &= keyrequest.miscmask;
	einittoken->maskedattributesle &= keyrequest.attributemask;
	einittoken->maskedxfrmle &= keyrequest.xfrmmask;

	if (sgx_egetkey(&keyrequest, launch_key))
		return false;

	tc_cmac_setup(&cmac_state, launch_key, &cmac_sched);
	tc_cmac_init(&cmac_state);
	tc_cmac_update(&cmac_state, (const uint8_t *)&einittoken->payload,
		       sizeof(einittoken->payload));
	tc_cmac_final(einittoken->mac, &cmac_state);

	sgx_memset(launch_key, 0, sizeof(launch_key));

	return true;
}

static bool create_einittoken(uint8_t *mrenclave,
			      uint8_t *mrsigner,
			      uint64_t attributes,
			      uint64_t xfrm,
			      struct sgx_einittoken *einittoken)
{

	struct sgx_targetinfo tginfo __attribute__((aligned (512)));
	struct sgx_report report __attribute__((aligned (512)));
	uint8_t reportdata[64] __attribute__((aligned (128)));

	if (attributes & 8 /* RESERVED */)
		return false;

	sgx_memset(&tginfo, 0, sizeof(tginfo));
	sgx_memset(reportdata, 0, sizeof(reportdata));
	sgx_memset(&report, 0, sizeof(report));

	if (sgx_ereport(&tginfo, reportdata, &report))
		return false;

	sgx_memset(einittoken, 0, sizeof(*einittoken));

	einittoken->payload.valid = 1;

	sgx_memcpy(einittoken->payload.mrenclave, mrenclave, 32);
	sgx_memcpy(einittoken->payload.mrsigner, mrsigner, 32);
	einittoken->payload.attributes = attributes;
	einittoken->payload.xfrm = xfrm;

	sgx_memcpy(&einittoken->cpusvnle, &report.cpusvn,
		   sizeof(report.cpusvn));
	einittoken->isvsvnle = report.isvsvn;
	einittoken->isvprodidle = report.isvprodid;

	einittoken->maskedattributesle = report.attributes;
	einittoken->maskedxfrmle = report.xfrm;
	einittoken->maskedmiscselectle = report.miscselect;

	if (!sign_einittoken(einittoken))
		return false;

	return true;
}

void encl_body(void *req_ptr)
{
	struct sgx_le_request *req = (struct sgx_le_request *)req_ptr;
	struct sgx_einittoken token;
	uint8_t mrenclave[32];
	uint8_t mrsigner[32];
	uint64_t attributes;
	uint64_t xfrm;

	if (!req || !req->mrenclave || !req->mrsigner || !req->einittoken)
		return;

	sgx_memcpy(mrenclave, req->mrenclave, sizeof(mrenclave));
	sgx_memcpy(mrsigner, req->mrsigner, sizeof(mrsigner));
	sgx_memcpy(&attributes, &req->attributes, sizeof(uint64_t));
	sgx_memcpy(&xfrm, &req->xfrm, sizeof(uint64_t));
	sgx_memset(&token, 0, sizeof(token));

	if (!create_einittoken(mrenclave, mrsigner, attributes, xfrm, &token))
		return;

	sgx_memcpy(req->einittoken, &token, sizeof(token));
}
