/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2016-19 Intel Corporation.
 */

#ifndef SGX_CALL_H
#define SGX_CALL_H

void sgx_call_eenter(void *rdi, void *rsi, void *entry);

int sgx_call_vdso(void *rdi, void *rsi, long rdx, void *rcx, void *r8, void *r9,
		  void *tcs, struct sgx_enclave_exception *ei, void *cb);

#endif /* SGX_CALL_H */
