/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/errno.h>
#include <asm/enclu.h>

#include "extable.h"

#define EX_LEAF		0*8
#define EX_TRAPNR	0*8+4
#define EX_ERROR_CODE	0*8+6
#define EX_ADDRESS	1*8

.code64
.section .text, "ax"

SYM_FUNC_START(__vdso_sgx_enter_enclave)
	/* Prolog */
	.cfi_startproc
	push	%rbp
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%rbp, 0
	mov	%rsp, %rbp
	.cfi_def_cfa_register	%rbp
	push	%rbx
	.cfi_rel_offset		%rbx, -8

	mov	%ecx, %eax
.Lenter_enclave:
	/* EENTER <= leaf <= ERESUME */
	cmp	$EENTER, %eax
	jb	.Linvalid_leaf
	cmp	$ERESUME, %eax
	ja	.Linvalid_leaf

	/* Load TCS and AEP */
	mov	0x10(%rbp), %rbx
	lea	.Lasync_exit_pointer(%rip), %rcx

	/* Single ENCLU serving as both EENTER and AEP (ERESUME) */
.Lasync_exit_pointer:
.Lenclu_eenter_eresume:
	enclu

	/* EEXIT jumps here unless the enclave is doing something fancy. */
	xor	%eax, %eax

	/* Invoke userspace's exit handler if one was provided. */
.Lhandle_exit:
	cmp	$0, 0x20(%rbp)
	jne	.Linvoke_userspace_handler

.Lout:
	pop	%rbx
	leave
	.cfi_def_cfa		%rsp, 8
	ret

	/* The out-of-line code runs with the pre-leave stack frame. */
	.cfi_def_cfa		%rbp, 16

.Linvalid_leaf:
	mov	$(-EINVAL), %eax
	jmp	.Lout

.Lhandle_exception:
	mov	0x18(%rbp), %rcx
	test    %rcx, %rcx
	je	.Lskip_exception_info

	/* Fill optional exception info. */
	mov	%eax, EX_LEAF(%rcx)
	mov	%di,  EX_TRAPNR(%rcx)
	mov	%si,  EX_ERROR_CODE(%rcx)
	mov	%rdx, EX_ADDRESS(%rcx)
.Lskip_exception_info:
	mov	$(-EFAULT), %eax
	jmp	.Lhandle_exit

.Linvoke_userspace_handler:
	/* Pass the untrusted RSP (at exit) to the callback via %rcx. */
	mov	%rsp, %rcx

	/* Save the untrusted RSP offset in %rbx (non-volatile register). */
	mov	%rsp, %rbx
	and	$0xf, %rbx

	/*
	 * Align stack per x86_64 ABI. Note, %rsp needs to be 16-byte aligned
	 * _after_ pushing the parameters on the stack, hence the bonus push.
	 */
	and	$-0x10, %rsp
	push	%rax

	/* Push @e, the "return" value and @tcs as params to the callback. */
	push	0x18(%rbp)
	push	%rax
	push	0x10(%rbp)

	/* Clear RFLAGS.DF per x86_64 ABI */
	cld

	/* Load the callback pointer to %rax and invoke it via retpoline. */
	mov	0x20(%rbp), %rax
	call	.Lretpoline

	/* Undo the post-exit %rsp adjustment. */
	lea	0x20(%rsp, %rbx), %rsp

	/*
	 * If the return from callback is zero or negative, return immediately,
	 * else re-execute ENCLU with the postive return value interpreted as
	 * the requested ENCLU leaf.
	 */
	cmp	$0, %eax
	jle	.Lout
	jmp	.Lenter_enclave

.Lretpoline:
	call	2f
1:	pause
	lfence
	jmp	1b
2:	mov	%rax, (%rsp)
	ret
	.cfi_endproc

_ASM_VDSO_EXTABLE_HANDLE(.Lenclu_eenter_eresume, .Lhandle_exception)

SYM_FUNC_END(__vdso_sgx_enter_enclave)
