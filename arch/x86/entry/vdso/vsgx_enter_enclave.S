/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/errno.h>

#include "extable.h"

#define EX_LEAF		0*8
#define EX_TRAPNR	0*8+4
#define EX_ERROR_CODE	0*8+6
#define EX_ADDRESS	1*8

.code64
.section .text, "ax"

/**
 * __vdso_sgx_enter_enclave() - Enter an SGX enclave
 * @leaf:	ENCLU leaf, must be EENTER or ERESUME
 * @tcs:	TCS, must be non-NULL
 * @e:		Optional struct sgx_enclave_exception instance
 * @handler:	Optional enclave exit handler
 *
 * **Important!**  __vdso_sgx_enter_enclave() is **NOT** compliant with the
 * x86-64 ABI, i.e. cannot be called from standard C code.
 *
 * Input ABI:
 *  @leaf	%eax
 *  @tcs	8(%rsp)
 *  @e 		0x10(%rsp)
 *  @handler	0x18(%rsp)
 *
 * Output ABI:
 *  @ret	%eax
 *
 * All general purpose registers except RAX, RBX and RCX are passed as-is to
 * the enclave. RAX, RBX and RCX are consumed by EENTER and ERESUME and are
 * loaded with @leaf, asynchronous exit pointer, and @tcs respectively.
 *
 * RBP and the stack are used to anchor __vdso_sgx_enter_enclave() to the
 * pre-enclave state, e.g. to retrieve @e and @handler after an enclave exit.
 * All other registers are available for use by the enclave and its runtime,
 * e.g. an enclave can push additional data onto the stack (and modify RSP) to
 * pass information to the optional exit handler (see below).
 *
 * Most exceptions reported on ENCLU, including those that occur within the
 * enclave, are fixed up and reported synchronously instead of being delivered
 * via a standard signal. Debug Exceptions (#DB) and Breakpoints (#BP) are
 * never fixed up and are always delivered via standard signals. On synchrously
 * reported exceptions, -EFAULT is returned and details about the exception are
 * recorded in @e, the optional sgx_enclave_exception struct.

 * If an exit handler is provided, the handler will be invoked on synchronous
 * exits from the enclave and for all synchronously reported exceptions. In
 * latter case, @e is filled prior to invoking the handler.
 *
 * The exit handler's return value is interpreted as follows:
 *  >0:		continue, restart __vdso_sgx_enter_enclave() with @ret as @leaf
 *   0:		success, return @ret to the caller
 *  <0:		error, return @ret to the caller
 *
 * The userspace exit handler is responsible for unwinding the stack, e.g. to
 * pop @e, u_rsp and @tcs, prior to returning to __vdso_sgx_enter_enclave().
 * The exit handler may also transfer control, e.g. via longjmp() or a C++
 * exception, without returning to __vdso_sgx_enter_enclave().
 *
 * Return:
 *  0 on success,
 *  -EINVAL if ENCLU leaf is not allowed,
 *  -EFAULT if an exception occurs on ENCLU or within the enclave
 *  -errno for all other negative values returned by the userspace exit handler
 */
#ifdef SGX_KERNEL_DOC
/* C-style function prototype to coerce kernel-doc into parsing the comment. */
int __vdso_sgx_enter_enclave(int leaf, void *tcs,
			     struct sgx_enclave_exception *e,
			     sgx_enclave_exit_handler_t handler);
#endif
SYM_FUNC_START(__vdso_sgx_enter_enclave)
	/* Prolog */
	.cfi_startproc
	push	%rbp
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%rbp, 0
	mov	%rsp, %rbp
	.cfi_def_cfa_register	%rbp

.Lenter_enclave:
	/* EENTER <= leaf <= ERESUME */
	cmp	$0x2, %eax
	jb	.Linvalid_leaf
	cmp	$0x3, %eax
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

	/* Save the untrusted RSP in %rbx (non-volatile register). */
	mov	%rsp, %rbx

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

	/* Restore %rsp to its post-exit value. */
	mov	%rbx, %rsp

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
