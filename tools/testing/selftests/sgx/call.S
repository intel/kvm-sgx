/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
* Copyright(c) 2016-18 Intel Corporation.
*/

	.text

	.macro ENCLU
	.byte 0x0f, 0x01, 0xd7
	.endm

	.text

	.global sgx_call_vdso
sgx_call_vdso:
	.cfi_startproc
	push	%r15
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%r15, 0
	push	%r14
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%r14, 0
	push	%r13
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%r13, 0
	push	%r12
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%r12, 0
	push	%rbx
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%rbx, 0
	push	$0
	.cfi_adjust_cfa_offset	8
	push	0x48(%rsp)
	.cfi_adjust_cfa_offset	8
	push	0x48(%rsp)
	.cfi_adjust_cfa_offset	8
	push	0x48(%rsp)
	.cfi_adjust_cfa_offset	8
	call	*eenter(%rip)
	add	$0x20, %rsp
	.cfi_adjust_cfa_offset	-0x20
	pop	%rbx
	.cfi_adjust_cfa_offset	-8
	pop	%r12
	.cfi_adjust_cfa_offset	-8
	pop	%r13
	.cfi_adjust_cfa_offset	-8
	pop	%r14
	.cfi_adjust_cfa_offset	-8
	pop	%r15
	.cfi_adjust_cfa_offset	-8
	ret
	.cfi_endproc
