// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

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

/*
 * ENCLS has its own (positive value) error codes and also generates
 * ENCLS specific #GP and #PF faults.  On a fault, __encls{,_ret}_N
 * shift the vector into bits 31:16 so that the caller can identify
 * the fault vector (as opposed to the a generic -EFAULT) without
 * causing collisions between faults and SGX error codes.
 */
#define IS_ENCLS_FAULT(r) ((r) & 0xffff0000)
#define ENCLS_FAULT_VECTOR(r) ((r) >> 16)

/*
 * Translate an ENCLS fault or SGX error code into a kernel error code.
 * Primarily used by functions that cannot return a non-negative error
 * code, e.g. kernel callbacks.
 */
#define ENCLS_TO_ERR(r) (IS_ENCLS_FAULT(r) ? -EFAULT :		\
			(r) == SGX_UNMASKED_EVENT ? -EINTR :	\
			(r) == SGX_MAC_COMPARE_FAIL ? -EIO :	\
			(r) == SGX_ENTRYEPOCH_LOCKED ? -EBUSY : -EPERM)

/*
 * __encls_ret_N encodes ENCLS leafs that return an error code in EAX,
 * e.g. EREMOVE.  And because SGX isn't complex enough as it is, leafs
 * that return an error code also modify flags.
 *
 * @ret - 0 on success, SGX error code on failure, fault vector shifted
 *        into bits 31:16 on a fault (to avoid collisions with the SGX
 *        error codes).
 */
#define __encls_ret_N(rax, inputs...)			\
	({						\
	int ret;					\
	asm volatile(					\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"		\
	"2:\n"						\
	".section .fixup,\"ax\"\n"			\
	"3: shll $16,%%eax\n"				\
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

/*
 * __encls_N encodes ENCLS leafs that do not return an error code in EAX,
 * e.g. ECREATE.  Leaves without error codes either succeed or fault.
 * rbx_out is an optional parameter for use by EDGBRD, which returns the
 * the requested value in RBX.
 *
 * @ret - 0 on success, fault vector shifted into bits 31:16 on a fault
 *        (to be compatible with __encls_ret_N).
 */
#define __encls_N(rax, rbx_out, inputs...)		\
	({						\
	int ret;					\
	asm volatile(					\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"		\
	"   xor %%eax,%%eax;\n"				\
	"2:\n"						\
	".section .fixup,\"ax\"\n"			\
	"3: shll $16,%%eax\n"				\
	"   jmp 2b\n"					\
	".previous\n"					\
	_ASM_EXTABLE_FAULT(1b, 3b)				\
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
