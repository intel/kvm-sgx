/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/* Copyright(c) 2016-18 Intel Corporation. */

#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <asm/sgx_arch.h>
#include <asm/asm.h>

#define SGX_MAX_EPC_BANKS 8

struct sgx_epc_page;

/**
 * struct sgx_epc_page_ops - operations to reclaim an EPC page
 * @get:	Pin the page. Returns false when the consumer is freeing the
 *		page itself.
 * @put:	Unpin the page.
 * @reclaim:	Try to reclaim the page. Returns false when the consumer is
 *		actively using needs the page.
 * @block:	Perform EBLOCK on the page.
 * @write:	Perform ETRACK (when required) and EWB on the page.
 *
 * These operations must be implemented by the EPC consumer to assist to reclaim
 * EPC pages.
 */
struct sgx_epc_page_ops {
	bool (*get)(struct sgx_epc_page *epc_page);
	void (*put)(struct sgx_epc_page *epc_page);
	bool (*reclaim)(struct sgx_epc_page *epc_page);
	void (*block)(struct sgx_epc_page *epc_page);
	void (*write)(struct sgx_epc_page *epc_page);
};

struct sgx_epc_page_impl {
	const struct sgx_epc_page_ops *ops;
};

struct sgx_epc_page {
	unsigned long desc;
	struct sgx_epc_page_impl *impl;
	struct list_head list;
};

struct sgx_epc_bank {
	unsigned long pa;
	void *va;
	unsigned long size;
	struct sgx_epc_page *pages_data;
	struct sgx_epc_page **pages;
	unsigned long free_cnt;
	spinlock_t lock;
};

extern bool sgx_enabled;
extern bool sgx_lc_enabled;
extern struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];

enum sgx_alloc_flags {
	SGX_ALLOC_ATOMIC	= BIT(0),
};

/*
 * enum sgx_epc_page_desc - defines bits and masks for an EPC page's desc
 * @SGX_EPC_BANK_MASK:	      SGX allows a system to multiple EPC banks (at
 *			      different physical locations).  The index of a
 *			      page's bank in its desc so that we can do a quick
 *			      lookup of its virtual address (EPC is mapped via
 *			      ioremap_cache() because it's non-standard memory).
 *			      Current and near-future hardware defines at most
 *			      eight banks, hence three bits to hold the bank.
 *			      sgx_page_cache_init() asserts that the max bank
 *			      index doesn't exceed SGX_EPC_BANK_MASK.
 * @SGX_EPC_PAGE_RECLAIMABLE: When set, indicates a page is reclaimable.  Used
 *			      when freeing a page to know that we also need to
 *			      remove the page from the active page list.
 *
 * Defines the layout of the desc field in the &struct sgx_epc_page, which
 * contains EPC bank number, physical address of the page and the page status
 * flag.
 */
enum sgx_epc_page_desc {
	SGX_EPC_BANK_MASK			= GENMASK_ULL(3, 0),
	SGX_EPC_PAGE_RECLAIMABLE		= BIT(4),
	/* bits 12-63 are reserved for the physical page address of the page */
};

static inline struct sgx_epc_bank *sgx_epc_bank(struct sgx_epc_page *page)
{
	return &sgx_epc_banks[page->desc & SGX_EPC_BANK_MASK];
}

static inline void *sgx_epc_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_bank *bank = sgx_epc_bank(page);

	return (void *)(bank->va + (page->desc & PAGE_MASK) - bank->pa);
}

struct sgx_epc_page *sgx_alloc_page(struct sgx_epc_page_impl *impl,
				    unsigned int flags);
int __sgx_free_page(struct sgx_epc_page *page);
void sgx_free_page(struct sgx_epc_page *page);
void sgx_page_reclaimable(struct sgx_epc_page *page);
struct page *sgx_get_backing(struct file *file, pgoff_t index);
void sgx_put_backing(struct page *backing_page, bool write);
int sgx_einit(struct sgx_sigstruct *sigstruct, struct sgx_einittoken *token,
	      struct sgx_epc_page *secs_page, u64 le_pubkey_hash[4]);

/**
 * ENCLS_FAULT_FLAG - flag signifying an ENCLS return code is a trapnr
 *
 * ENCLS has its own (positive value) error codes and also generates
 * ENCLS specific #GP and #PF faults.  And the ENCLS values get munged
 * with system error codes as everything percolates back up the stack.
 * Unfortunately (for us), we need to precisely identify each unique
 * error code, e.g. the action taken if EWB fails varies based on the
 * type of fault and on the exact SGX error code, i.e. we can't simply
 * convert all faults to -EFAULT.
 *
 * To make all three error types coexist, we set bit 30 to identify an
 * ENCLS fault.  Bit 31 (technically bits N:31) is used to differentiate
 * between positive (faults and SGX error codes) and negative (system
 * error codes) values.
 */
#define ENCLS_FAULT_FLAG 0x40000000UL
#define ENCLS_FAULT_FLAG_ASM "$0x40000000"

/**
 * IS_ENCLS_FAULT - check if a return code indicates an ENCLS fault
 *
 * Check for a fault by looking for a postive value with the fault
 * flag set.  The postive value check is needed to filter out system
 * error codes since negative values will have all higher order bits
 * set, including ENCLS_FAULT_FLAG.
 */
#define IS_ENCLS_FAULT(r) ((int)(r) > 0 && ((r) & ENCLS_FAULT_FLAG))

/**
 * ENCLS_TRAPNR - retrieve the trapnr exactly as passed via _ASM_EXTABLE_FAULT
 *
 * Retrieve the encoded trapnr from the specified return code, keeping
 * any error code bits that were included in trapnr when it was supplied
 * to the _ASM_EXTABLE_FAULT handler, e.g. X86_PF_SGX is propagated from
 * the error code to trapnr.
 */
#define ENCLS_TRAPNR(r) ((r) & ~ENCLS_FAULT_FLAG)

/**
 * ENCLS_FAULT_VECTOR - retrieve the fault vector from a return code
 *
 * Retrieve the encoded fault vector, e.g. #GP or #PF, from the specified
 * return code, dropping any potential error code bits in trapnr, e.g.
 * X86_PF_SGX.
 */
#define ENCLS_FAULT_VECTOR(r) (ENCLS_TRAPNR(r) & 0x1f)

/**
 * encls_to_err - translate an ENCLS fault or SGX code into a system error code
 * @ret:	positive value return code
 *
 * Returns:
 *	-EFAULT for faults
 *	-EINTR for unmasked events
 *	-EINVAL for SGX_INVALID_* error codes
 *	-EBUSY for non-fatal resource contention errors
 *	-EIO for all other errors
 *
 * Translate a postive return code, e.g. from ENCLS, into a system error
 * code.  Primarily used by functions that cannot return a non-negative
 * error code, e.g. kernel callbacks.
 */
static inline int encls_to_err(int ret)
{
	if (IS_ENCLS_FAULT(ret))
		return -EFAULT;

	switch (ret) {
	case SGX_UNMASKED_EVENT:
		return -EINTR;
	case SGX_INVALID_SIG_STRUCT:
	case SGX_INVALID_ATTRIBUTE:
	case SGX_INVALID_MEASUREMENT:
	case SGX_INVALID_EINITTOKEN:
	case SGX_INVALID_CPUSVN:
	case SGX_INVALID_ISVSVN:
	case SGX_INVALID_KEYNAME:
		return -EINVAL;
	case SGX_ENCLAVE_ACT:
	case SGX_CHILD_PRESENT:
	case SGX_ENTRYEPOCH_LOCKED:
	case SGX_PREV_TRK_INCMPL:
	case SGX_PAGE_NOT_MODIFIABLE:
	case SGX_PAGE_NOT_DEBUGGABLE:
		return -EBUSY;
	default:
		return -EIO;
	};
}

/**
 * __encls_ret_N - encode an ENCLS leaf that returns an error code in EAX
 * @rax:	leaf number
 * @inputs:	asm inputs for the leaf
 *
 * Returns:
 *	0 on success
 *	SGX error code on failure
 *	trapnr with ENCLS_FAULT_FLAG set on fault
 *
 * Emit assembly for an ENCLS leaf that returns an error code, e.g. EREMOVE.
 * And because SGX isn't complex enough as it is, leafs that return an error
 * code also modify flags.
 */
#define __encls_ret_N(rax, inputs...)			\
	({						\
	int ret;					\
	asm volatile(					\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"		\
	"2:\n"						\
	".section .fixup,\"ax\"\n"			\
	"3: orl "ENCLS_FAULT_FLAG_ASM",%%eax\n"		\
	"   jmp 2b\n"					\
	".previous\n"					\
	_ASM_EXTABLE_FAULT(1b, 3b)			\
	: "=a"(ret)					\
	: "a"(rax), inputs				\
	: "memory", "cc");				\
	ret;						\
	})

#define __encls_ret_1(rax, rcx)				\
	({						\
	__encls_ret_N(rax, "c"(rcx));			\
	})

#define __encls_ret_2(rax, rbx, rcx)			\
	({						\
	__encls_ret_N(rax, "b"(rbx), "c"(rcx));		\
	})

#define __encls_ret_3(rax, rbx, rcx, rdx)			\
	({							\
	__encls_ret_N(rax, "b"(rbx), "c"(rcx), "d"(rdx));	\
	})

/**
 * __encls_N - encode an ENCLS leaf that doesn't return an error code
 * @rax:	leaf number
 * @rbx_out:	optional output variable
 * @inputs:	asm inputs for the leaf
 *
 * Returns:
 *	0 on success
 *	trapnr with ENCLS_FAULT_FLAG set on fault
 *
 * Emit assembly for an ENCLS leaf that does not return an error code,
 * e.g. ECREATE.  Leaves without error codes either succeed or fault.
 * @rbx_out is an optional parameter for use by EDGBRD, which returns
 * the the requested value in RBX.
 */
#define __encls_N(rax, rbx_out, inputs...)		\
	({						\
	int ret;					\
	asm volatile(					\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"		\
	"   xor %%eax,%%eax;\n"				\
	"2:\n"						\
	".section .fixup,\"ax\"\n"			\
	"3: orl "ENCLS_FAULT_FLAG_ASM",%%eax\n"		\
	"   jmp 2b\n"					\
	".previous\n"					\
	_ASM_EXTABLE_FAULT(1b, 3b)			\
	: "=a"(ret), "=b"(rbx_out)			\
	: "a"(rax), inputs				\
	: "memory");					\
	ret;						\
	})

#define __encls_2(rax, rbx, rcx)				\
	({							\
	unsigned long ign_rbx_out;				\
	__encls_N(rax, ign_rbx_out, "b"(rbx), "c"(rcx));	\
	})

#define __encls_1_1(rax, data, rcx)			\
	({						\
	unsigned long rbx_out;				\
	int ret = __encls_N(rax, rbx_out, "c"(rcx));	\
	if (!ret)					\
		data = rbx_out;				\
	ret;						\
	})

static inline int __ecreate(struct sgx_pageinfo *pginfo, void *secs)
{
	return __encls_2(ECREATE, pginfo, secs);
}

static inline int __eextend(void *secs, void *epc)
{
	return __encls_2(EEXTEND, secs, epc);
}

static inline int __eadd(struct sgx_pageinfo *pginfo, void *epc)
{
	return __encls_2(EADD, pginfo, epc);
}

static inline int __einit(void *sigstruct, struct sgx_einittoken *einittoken,
			  void *secs)
{
	return __encls_ret_3(EINIT, sigstruct, secs, einittoken);
}

static inline int __eremove(void *epc)
{
	return __encls_ret_1(EREMOVE, epc);
}

static inline int __edbgwr(void *addr, unsigned long *data)
{
	return __encls_2(EDGBWR, *data, addr);
}

static inline int __edbgrd(void *addr, unsigned long *data)
{
	return __encls_1_1(EDGBRD, *data, addr);
}

static inline int __etrack(void *epc)
{
	return __encls_ret_1(ETRACK, epc);
}

static inline int __eldu(struct sgx_pageinfo *pginfo, void *epc, void *va)
{
	return __encls_ret_3(ELDU, pginfo, epc, va);
}

static inline int __eblock(void *epc)
{
	return __encls_ret_1(EBLOCK, epc);
}

static inline int __epa(void *epc)
{
	unsigned long rbx = SGX_PAGE_TYPE_VA;

	return __encls_2(EPA, rbx, epc);
}

static inline int __ewb(struct sgx_pageinfo *pginfo, void *epc, void *va)
{
	return __encls_ret_3(EWB, pginfo, epc, va);
}

static inline int __eaug(struct sgx_pageinfo *pginfo, void *epc)
{
	return __encls_2(EAUG, pginfo, epc);
}

static inline int __emodpr(struct sgx_secinfo *secinfo, void *epc)
{
	return __encls_ret_2(EMODPR, secinfo, epc);
}

static inline int __emodt(struct sgx_secinfo *secinfo, void *epc)
{
	return __encls_ret_2(EMODT, secinfo, epc);
}

#endif /* _ASM_X86_SGX_H */
