/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
* Copyright(c) 2016-18 Intel Corporation.
*/
.macro ENCLU
.byte 0x0f, 0x01, 0xd7
.endm

	.text

	.global sgx_call
sgx_call:
	push	%rbx
	mov	$0x02, %rax
	mov	%rdx, %rbx
	lea	sgx_async_exit(%rip), %rcx
sgx_async_exit:
	ENCLU
	pop	%rbx
	ret
