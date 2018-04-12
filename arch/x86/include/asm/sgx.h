// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

#include <asm/sgx_arch.h>
#include <asm/asm.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/rwsem.h>
#include <linux/types.h>

#define IS_ENCLS_FAULT(r) ((r) & 0xffff0000)
#define ENCLS_FAULT_VECTOR(r) ((r) >> 16)

#define ENCLS_TO_ERR(r) (IS_ENCLS_FAULT(r) ? -EFAULT :		\
			(r) == SGX_UNMASKED_EVENT ? -EINTR :	\
			(r) == SGX_MAC_COMPARE_FAIL ? -EIO :	\
			(r) == SGX_ENTRYEPOCH_LOCKED ? -EBUSY : -EPERM)

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
	: "memory");					\
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

static inline int __edbgwr(unsigned long addr, unsigned long *data)
{
	return __encls_2(EDGBWR, *data, addr);
}

static inline int __edbgrd(unsigned long addr, unsigned long *data)
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

#define SGX_MAX_EPC_BANKS 8

#define SGX_EPC_BANK(epc_page) \
	(&sgx_epc_banks[(unsigned long)(epc_page->desc) & ~PAGE_MASK])
#define SGX_EPC_PFN(epc_page) PFN_DOWN((unsigned long)(epc_page->desc))
#define SGX_EPC_ADDR(epc_page) ((unsigned long)(epc_page->desc) & PAGE_MASK)

struct sgx_epc_page;

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
	unsigned long va;
	unsigned long size;
	struct sgx_epc_page *pages_data;
	struct sgx_epc_page **pages;
	atomic_t free_cnt;
	struct rw_semaphore lock;
};

extern bool sgx_enabled;
extern bool sgx_lc_enabled;
extern struct list_head sgx_active_page_list;
extern struct spinlock sgx_active_page_list_lock;

enum sgx_alloc_flags {
	SGX_ALLOC_ATOMIC	= BIT(0),
};

struct sgx_epc_page *sgx_alloc_page(struct sgx_epc_page_impl *impl,
				    unsigned int flags);
int sgx_free_page(struct sgx_epc_page *page);
void *sgx_get_page(struct sgx_epc_page *ptr);
void sgx_put_page(void *epc_page_ptr);
struct page *sgx_get_backing(struct file *file, pgoff_t index);
void sgx_put_backing(struct page *backing_page, bool write);

#define SGX_FN(name, params...)		\
{					\
	void *epc;			\
	int ret;			\
	epc = sgx_get_page(epc_page);	\
	ret = __##name(params);		\
	sgx_put_page(epc);		\
	return ret;			\
}

#define BUILD_SGX_FN(fn, name)				\
static inline int fn(struct sgx_epc_page *epc_page)	\
	SGX_FN(name, epc)
BUILD_SGX_FN(sgx_eremove, eremove)
BUILD_SGX_FN(sgx_eblock, eblock)
BUILD_SGX_FN(sgx_etrack, etrack)
BUILD_SGX_FN(sgx_epa, epa)

static inline int sgx_emodpr(struct sgx_secinfo *secinfo,
			     struct sgx_epc_page *epc_page)
	SGX_FN(emodpr, secinfo, epc)
static inline int sgx_emodt(struct sgx_secinfo *secinfo,
			    struct sgx_epc_page *epc_page)
	SGX_FN(emodt, secinfo, epc)

#endif /* _ASM_X86_SGX_H */
