/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017 Intel Corporation.
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
 * Copyright(c) 2017 Intel Corporation.
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

#define _GNU_SOURCE
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <asm/sgx_arch.h>
#include <openssl/err.h>
#include <openssl/pem.h>

static const char *sign_key_pass;

static bool check_crypto_errors(void)
{
	int err;
	bool had_errors = false;
	const char *filename;
	int line;
	char str[256];

	for ( ; ; ) {
		if (ERR_peek_error() == 0)
			break;

		had_errors = true;
		err = ERR_get_error_line(&filename, &line);
		ERR_error_string_n(err, str, sizeof(str));
		fprintf(stderr, "crypto: %s: %s:%d\n", str, filename, line);
	}

	return had_errors;
}

static void exit_usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s/sign-le <key> <enclave> <sigstruct>\n", program);
	exit(1);
}

static int pem_passwd_cb(char *buf, int size, int rwflag, void *u)
{
	if (!sign_key_pass)
		return -1;

	strncpy(buf, sign_key_pass, size);
	/* no retry */
	sign_key_pass = NULL;

	return strlen(buf) >= size ? size - 1 : strlen(buf);
}

static RSA *load_sign_key(const char *path)
{
	FILE *f;
	RSA *key;

	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "Unable to open %s\n", path);
		return NULL;
	}
	key = RSA_new();
	if (!PEM_read_RSAPrivateKey(f, &key, pem_passwd_cb, NULL))
		return NULL;
	fclose(f);

	if (BN_num_bytes(key->n) != SGX_MODULUS_SIZE) {
		fprintf(stderr, "Invalid key size %d\n", BN_num_bytes(key->n));
		RSA_free(key);
		return NULL;
	}

	return key;
}

static void reverse_bytes(void *data, int length)
{
	int i = 0;
	int j = length - 1;
	uint8_t temp;
	uint8_t *ptr = data;

	while (i < j) {
		temp = ptr[i];
		ptr[i] = ptr[j];
		ptr[j] = temp;
		i++;
		j--;
	}
}

enum mrtags {
	MRECREATE = 0x0045544145524345,
	MREADD = 0x0000000044444145,
	MREEXTEND = 0x00444E4554584545,
};

static bool mrenclave_update(EVP_MD_CTX *ctx, const void *data)
{
	if (!EVP_DigestUpdate(ctx, data, 64)) {
		fprintf(stderr, "digest update failed\n");
		return false;
	}

	return true;
}

static bool mrenclave_commit(EVP_MD_CTX *ctx, uint8_t *mrenclave)
{
	unsigned int size;

	if (!EVP_DigestFinal_ex(ctx, (unsigned char *)mrenclave, &size)) {
		fprintf(stderr, "digest commit failed\n");
		return false;
	}

	if (size != 32) {
		fprintf(stderr, "invalid digest size = %u\n", size);
		return false;
	}

	return true;
}

struct mrecreate {
	uint64_t tag;
	uint32_t ssaframesize;
	uint64_t size;
	uint8_t reserved[44];
} __attribute__((__packed__));


static bool mrenclave_ecreate(EVP_MD_CTX *ctx, uint64_t blob_size)
{
	struct mrecreate mrecreate;
	uint64_t encl_size;

	for (encl_size = 0x1000; encl_size < blob_size; encl_size <<= 1);

	memset(&mrecreate, 0, sizeof(mrecreate));
	mrecreate.tag = MRECREATE;
	mrecreate.ssaframesize = 1;
	mrecreate.size = encl_size;

	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		return false;

	return mrenclave_update(ctx, &mrecreate);
}

struct mreadd {
	uint64_t tag;
	uint64_t offset;
	uint64_t flags; /* SECINFO flags */
	uint8_t reserved[40];
} __attribute__((__packed__));

static bool mrenclave_eadd(EVP_MD_CTX *ctx, uint64_t offset, uint64_t flags)
{
	struct mreadd mreadd;

	memset(&mreadd, 0, sizeof(mreadd));
	mreadd.tag = MREADD;
	mreadd.offset = offset;
	mreadd.flags = flags;

	return mrenclave_update(ctx, &mreadd);
}

struct mreextend {
	uint64_t tag;
	uint64_t offset;
	uint8_t reserved[48];
} __attribute__((__packed__));

static bool mrenclave_eextend(EVP_MD_CTX *ctx, uint64_t offset, uint8_t *data)
{
	struct mreextend mreextend;
	int i;

	for (i = 0; i < 0x1000; i += 0x100) {
		memset(&mreextend, 0, sizeof(mreextend));
		mreextend.tag = MREEXTEND;
		mreextend.offset = offset + i;

		if (!mrenclave_update(ctx, &mreextend))
			return false;

		if (!mrenclave_update(ctx, &data[i + 0x00]))
			return false;

		if (!mrenclave_update(ctx, &data[i + 0x40]))
			return false;

		if (!mrenclave_update(ctx, &data[i + 0x80]))
			return false;

		if (!mrenclave_update(ctx, &data[i + 0xC0]))
			return false;
	}

	return true;
}

/**
 * measure_encl - measure enclave
 * @path: path to the enclave
 * @mrenclave: measurement
 *
 * Calculates MRENCLAVE. Assumes that the very first page is a TCS page and
 * following pages are regular pages. Does not measure the contents of the
 * enclave as the signing tool is used at the moment only for the launch
 * enclave, which is pass-through (everything gets a token).
 */
static bool measure_encl(const char *path, uint8_t *mrenclave)
{
	FILE *file;
	struct stat sb;
	EVP_MD_CTX *ctx;
	uint64_t flags;
	uint64_t offset;
	uint8_t data[0x1000];
	int rc;

	ctx = EVP_MD_CTX_create();
	if (!ctx)
		return false;

	file = fopen(path, "rb");
	if (!file) {
		perror("fopen");
		EVP_MD_CTX_destroy(ctx);
		return false;
	}

	rc = stat(path, &sb);
	if (rc) {
		perror("stat");
		goto out;
	}

	if (!sb.st_size || sb.st_size & 0xfff) {
		fprintf(stderr, "Invalid blob size %lu\n", sb.st_size);
		goto out;
	}

	if (!mrenclave_ecreate(ctx, sb.st_size))
		goto out;

	for (offset = 0; offset < sb.st_size; offset += 0x1000) {
		if (!offset)
			flags = SGX_SECINFO_TCS;
		else
			flags = SGX_SECINFO_REG | SGX_SECINFO_R |
				SGX_SECINFO_W | SGX_SECINFO_X;

		if (!mrenclave_eadd(ctx, offset, flags))
			goto out;

		rc = fread(data, 1, 0x1000, file);
		if (!rc)
			break;
		if (rc < 0x1000)
			goto out;

		if (!mrenclave_eextend(ctx, offset, data))
			goto out;
	}

	if (!mrenclave_commit(ctx, mrenclave))
		goto out;

	fclose(file);
	EVP_MD_CTX_destroy(ctx);
	return true;
out:
	fclose(file);
	EVP_MD_CTX_destroy(ctx);
	return false;
}

/**
 * sign_encl - sign enclave
 * @sigstruct: pointer to SIGSTRUCT
 * @key: 3072-bit RSA key
 * @signature: byte array for the signature
 *
 * Calculates EMSA-PKCSv1.5 signature for the given SIGSTRUCT. The result is
 * stored in big-endian format so that it can be further passed to OpenSSL
 * libcrypto functions.
 */
static bool sign_encl(const struct sgx_sigstruct *sigstruct, RSA *key,
		      uint8_t *signature)
{
	struct sgx_sigstruct_payload payload;
	unsigned int siglen;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	bool ret;

	memcpy(&payload.header, &sigstruct->header, sizeof(sigstruct->header));
	memcpy(&payload.body, &sigstruct->body, sizeof(sigstruct->body));

	SHA256((unsigned char *)&payload, sizeof(payload), digest);

	ret = RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature,
		       &siglen, key);

	return ret;
}

struct q1q2_ctx {
	BN_CTX *bn_ctx;
	BIGNUM *m;
	BIGNUM *s;
	BIGNUM *q1;
	BIGNUM *qr;
	BIGNUM *q2;
};

static void free_q1q2_ctx(struct q1q2_ctx *ctx)
{
	BN_CTX_free(ctx->bn_ctx);
	BN_free(ctx->m);
	BN_free(ctx->s);
	BN_free(ctx->q1);
	BN_free(ctx->qr);
	BN_free(ctx->q2);
}

static bool alloc_q1q2_ctx(const uint8_t *s, const uint8_t *m,
			   struct q1q2_ctx *ctx)
{
	ctx->bn_ctx = BN_CTX_new();
	ctx->s = BN_bin2bn(s, SGX_MODULUS_SIZE, NULL);
	ctx->m = BN_bin2bn(m, SGX_MODULUS_SIZE, NULL);
	ctx->q1 = BN_new();
	ctx->qr = BN_new();
	ctx->q2 = BN_new();

	if (!ctx->bn_ctx || !ctx->s || !ctx->m || !ctx->q1 || !ctx->qr ||
	    !ctx->q2) {
		free_q1q2_ctx(ctx);
		return false;
	}

	return true;
}

static bool calc_q1q2(const uint8_t *s, const uint8_t *m, uint8_t *q1,
		      uint8_t *q2)
{
	struct q1q2_ctx ctx;

	if (!alloc_q1q2_ctx(s, m, &ctx)) {
		fprintf(stderr, "Not enough memory for Q1Q2 calculation\n");
		return false;
	}

	if (!BN_mul(ctx.q1, ctx.s, ctx.s, ctx.bn_ctx))
		goto out;

	if (!BN_div(ctx.q1, ctx.qr, ctx.q1, ctx.m, ctx.bn_ctx))
		goto out;

	if (BN_num_bytes(ctx.q1) > SGX_MODULUS_SIZE) {
		fprintf(stderr, "Too large Q1 %d bytes\n",
			BN_num_bytes(ctx.q1));
		goto out;
	}

	if (!BN_mul(ctx.q2, ctx.s, ctx.qr, ctx.bn_ctx))
		goto out;

	if (!BN_div(ctx.q2, NULL, ctx.q2, ctx.m, ctx.bn_ctx))
		goto out;

	if (BN_num_bytes(ctx.q2) > SGX_MODULUS_SIZE) {
		fprintf(stderr, "Too large Q2 %d bytes\n",
			BN_num_bytes(ctx.q2));
		goto out;
	}

	BN_bn2bin(ctx.q1, q1);
	BN_bn2bin(ctx.q2, q2);

	free_q1q2_ctx(&ctx);
	return true;
out:
	free_q1q2_ctx(&ctx);
	return false;
}

static bool save_sigstruct(const struct sgx_sigstruct *sigstruct,
			   const char *path)
{
	FILE *f = fopen(path, "wb");

	if (!f) {
		fprintf(stderr, "Unable to open %s\n", path);
		return false;
	}

	fwrite(sigstruct, sizeof(*sigstruct), 1, f);
	fclose(f);
	return true;
}

int main(int argc, char **argv)
{
	uint64_t header1[2] = {0x000000E100000006, 0x0000000000010000};
	uint64_t header2[2] = {0x0000006000000101, 0x0000000100000060};
	struct sgx_sigstruct ss;
	const char *program;
	int opt;
	RSA *sign_key;

	memset(&ss, 0, sizeof(ss));
	ss.header.header1[0] = header1[0];
	ss.header.header1[1] = header1[1];
	ss.header.header2[0] = header2[0];
	ss.header.header2[1] = header2[1];
	ss.exponent = 3;
	ss.body.attributes = SGX_ATTR_MODE64BIT | SGX_ATTR_EINITTOKENKEY;
	ss.body.xfrm = 3,

	sign_key_pass = getenv("KBUILD_SGX_SIGN_PIN");
	program = argv[0];

	do {
		opt = getopt(argc, argv, "");
		switch (opt) {
		case -1:
			break;
		default:
			exit_usage(program);
		}
	} while (opt != -1);

	argc -= optind;
	argv += optind;

	if (argc < 3)
		exit_usage(program);

	/* sanity check only */
	if (check_crypto_errors())
		exit(1);

	sign_key = load_sign_key(argv[0]);
	if (!sign_key)
		goto out;

	BN_bn2bin(sign_key->n, ss.modulus);

	if (!measure_encl(argv[1], ss.body.mrenclave))
		goto out;

	if (!sign_encl(&ss, sign_key, ss.signature))
		goto out;

	if (!calc_q1q2(ss.signature, ss.modulus, ss.q1, ss.q2))
		goto out;

	/* convert to little endian */
	reverse_bytes(ss.signature, SGX_MODULUS_SIZE);
	reverse_bytes(ss.modulus, SGX_MODULUS_SIZE);
	reverse_bytes(ss.q1, SGX_MODULUS_SIZE);
	reverse_bytes(ss.q2, SGX_MODULUS_SIZE);

	if (!save_sigstruct(&ss, argv[2]))
		goto out;
	exit(0);
out:
	check_crypto_errors();
	exit(1);
}
