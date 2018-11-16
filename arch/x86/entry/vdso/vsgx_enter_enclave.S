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
 *
 * %eax:        ENCLU leaf, must be EENTER or ERESUME
 * %rbx:        TCS, must be non-NULL
 * %rcx:        Optional pointer to 'struct sgx_enclave_exception'
 *
 * Return:
 *  0 on a clean entry/exit to/from the enclave
 *  -EINVAL if ENCLU leaf is not allowed or if TCS is NULL
 *  -EFAULT if ENCLU or the enclave faults
 *
 * Note that __vdso_sgx_enter_enclave() is not compliant with the x86-64 ABI.
 * All registers except RSP must be treated as volatile from the caller's
 * perspective, including but not limited to GPRs, EFLAGS.DF, MXCSR, FCW, etc...
 * Conversely, the enclave being run must preserve the untrusted RSP and stack.
 *
 * __vdso_sgx_enter_enclave(u32 leaf, void *tcs,
 *			    struct sgx_enclave_exception *exception_info)
 * {
 *	if (leaf != SGX_EENTER && leaf != SGX_ERESUME)
 *		return -EINVAL;
 *
 *	if (!tcs)
 *		return -EINVAL;
 *
 *	try {
 *		ENCLU[leaf];
 *	} catch (exception) {
 *		if (e)
 *	 		*e = exception;
 *		return -EFAULT;
 *	}
 *
 *	return 0;
 * }
 */
ENTRY(__vdso_sgx_enter_enclave)
	/* EENTER <= leaf <= ERESUME */
	cmp	$0x2, %eax
	jb	bad_input

	cmp	$0x3, %eax
	ja	bad_input

	/* TCS must be non-NULL */
	test	%rbx, %rbx
	je	bad_input

	/* Save @exception_info */
	push	%rcx

	/* Load AEP for ENCLU */
	lea	1f(%rip),  %rcx
1:	enclu

	add	$0x8, %rsp
	xor	%eax, %eax
	ret

bad_input:
	mov     $(-EINVAL), %rax
	ret

.pushsection .fixup, "ax"
	/* Re-load @exception_info and fill it (if it's non-NULL) */
2:	pop	%rcx
	test    %rcx, %rcx
	je      3f

	mov	%eax, EX_LEAF(%rcx)
	mov	%di,  EX_TRAPNR(%rcx)
	mov	%si,  EX_ERROR_CODE(%rcx)
	mov	%rdx, EX_ADDRESS(%rcx)
3:	mov	$(-EFAULT), %rax
	ret
.popsection

_ASM_VDSO_EXTABLE_HANDLE(1b, 2b)

ENDPROC(__vdso_sgx_enter_enclave)
