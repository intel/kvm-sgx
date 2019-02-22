/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
#ifndef _X86_SGX_H
#define _X86_SGX_H

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <asm/asm.h>
#include <asm/sgx_arch.h>
#include <uapi/asm/sgx_errno.h>

extern const struct file_operations sgx_fs_provision_fops;

struct sgx_epc_page {
	unsigned long desc;
	void *owner;
	struct list_head list;
};

/**
 * struct sgx_epc_section
 *
 * The firmware can define multiple chunks of EPC to the different areas of the
 * physical memory e.g. for memory areas of the each node. This structure is
 * used to store EPC pages for one EPC section and virtual memory area where
 * the pages have been mapped.
 */
struct sgx_epc_section {
	unsigned long pa;
	void *va;
	struct list_head page_list;
	unsigned long free_cnt;
	spinlock_t lock;
};

#define SGX_MAX_EPC_SECTIONS	8

extern struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];

/**
 * enum sgx_epc_page_desc - bits and masks for an EPC page's descriptor
 * %SGX_EPC_SECTION_MASK:	SGX allows to have multiple EPC sections in the
 *				physical memory. The existing and near-future
 *				hardware defines at most eight sections, hence
 *				three bits to hold a section.
 * %SGX_EPC_PAGE_RECLAIMABLE:	The page has been been marked as reclaimable.
 *				Pages need to be colored this way because a page
 *				can be out of the active page list in the
 *				process of being swapped out.
 */
enum sgx_epc_page_desc {
	SGX_EPC_SECTION_MASK			= GENMASK_ULL(3, 0),
	SGX_EPC_PAGE_RECLAIMABLE		= BIT(4),
	/* bits 12-63 are reserved for the physical page address of the page */
};

static inline struct sgx_epc_section *sgx_epc_section(struct sgx_epc_page *page)
{
	return &sgx_epc_sections[page->desc & SGX_EPC_SECTION_MASK];
}

static inline void *sgx_epc_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_epc_section(page);

	return section->va + (page->desc & PAGE_MASK) - section->pa;
}

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
#define ENCLS_FAULT_FLAG 0x40000000

/**
 * Check for a fault by looking for a postive value with the fault
 * flag set.  The postive value check is needed to filter out system
 * error codes since negative values will have all higher order bits
 * set, including ENCLS_FAULT_FLAG.
 */
#define IS_ENCLS_FAULT(r) ((int)(r) > 0 && ((r) & ENCLS_FAULT_FLAG))

/**
 * Retrieve the encoded trapnr from the specified return code.
 */
#define ENCLS_TRAPNR(r) ((r) & ~ENCLS_FAULT_FLAG)

/**
 * encls_to_err - translate an ENCLS fault or SGX code into a system error code
 * @ret:	positive value return code
 *
 * Translate a postive return code, e.g. from ENCLS, into a system error
 * code.  Primarily used by functions that cannot return a non-negative
 * error code, e.g. kernel callbacks.
 *
 * Return:
 *	0 on success,
 *	-errno on failure
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
 * Emit assembly for an ENCLS leaf that returns an error code, e.g. EREMOVE.
 * And because SGX isn't complex enough as it is, leafs that return an error
 * code also modify flags.
 *
 * Return:
 *	0 on success,
 *	SGX error code on failure
 */
#define __encls_ret_N(rax, inputs...)				\
	({							\
	int ret;						\
	asm volatile(						\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"			\
	"2:\n"							\
	".section .fixup,\"ax\"\n"				\
	"3: orl $"__stringify(ENCLS_FAULT_FLAG)",%%eax\n"	\
	"   jmp 2b\n"						\
	".previous\n"						\
	_ASM_EXTABLE_FAULT(1b, 3b)				\
	: "=a"(ret)						\
	: "a"(rax), inputs					\
	: "memory", "cc");					\
	ret;							\
	})

#define __encls_ret_1(rax, rcx)		\
	({				\
	__encls_ret_N(rax, "c"(rcx));	\
	})

#define __encls_ret_2(rax, rbx, rcx)		\
	({					\
	__encls_ret_N(rax, "b"(rbx), "c"(rcx));	\
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
 * Emit assembly for an ENCLS leaf that does not return an error code,
 * e.g. ECREATE.  Leaves without error codes either succeed or fault.
 * @rbx_out is an optional parameter for use by EDGBRD, which returns
 * the the requested value in RBX.
 *
 * Return:
 *   0 on success,
 *   trapnr with ENCLS_FAULT_FLAG set on fault
 */
#define __encls_N(rax, rbx_out, inputs...)			\
	({							\
	int ret;						\
	asm volatile(						\
	"1: .byte 0x0f, 0x01, 0xcf;\n\t"			\
	"   xor %%eax,%%eax;\n"					\
	"2:\n"							\
	".section .fixup,\"ax\"\n"				\
	"3: orl $"__stringify(ENCLS_FAULT_FLAG)",%%eax\n"	\
	"   jmp 2b\n"						\
	".previous\n"						\
	_ASM_EXTABLE_FAULT(1b, 3b)				\
	: "=a"(ret), "=b"(rbx_out)				\
	: "a"(rax), inputs					\
	: "memory");						\
	ret;							\
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
	return __encls_2(SGX_ECREATE, pginfo, secs);
}

static inline int __eextend(void *secs, void *addr)
{
	return __encls_2(SGX_EEXTEND, secs, addr);
}

static inline int __eadd(struct sgx_pageinfo *pginfo, void *addr)
{
	return __encls_2(SGX_EADD, pginfo, addr);
}

static inline int __einit(void *sigstruct, struct sgx_einittoken *einittoken,
			  void *secs)
{
	return __encls_ret_3(SGX_EINIT, sigstruct, secs, einittoken);
}

static inline int __eremove(void *addr)
{
	return __encls_ret_1(SGX_EREMOVE, addr);
}

static inline int __edbgwr(void *addr, unsigned long *data)
{
	return __encls_2(SGX_EDGBWR, *data, addr);
}

static inline int __edbgrd(void *addr, unsigned long *data)
{
	return __encls_1_1(SGX_EDGBRD, *data, addr);
}

static inline int __etrack(void *addr)
{
	return __encls_ret_1(SGX_ETRACK, addr);
}

static inline int __eldu(struct sgx_pageinfo *pginfo, void *addr,
			 void *va)
{
	return __encls_ret_3(SGX_ELDU, pginfo, addr, va);
}

static inline int __eblock(void *addr)
{
	return __encls_ret_1(SGX_EBLOCK, addr);
}

static inline int __epa(void *addr)
{
	unsigned long rbx = SGX_PAGE_TYPE_VA;

	return __encls_2(SGX_EPA, rbx, addr);
}

static inline int __ewb(struct sgx_pageinfo *pginfo, void *addr,
			void *va)
{
	return __encls_ret_3(SGX_EWB, pginfo, addr, va);
}

static inline int __eaug(struct sgx_pageinfo *pginfo, void *addr)
{
	return __encls_2(SGX_EAUG, pginfo, addr);
}

static inline int __emodpr(struct sgx_secinfo *secinfo, void *addr)
{
	return __encls_ret_2(SGX_EMODPR, secinfo, addr);
}

static inline int __emodt(struct sgx_secinfo *secinfo, void *addr)
{
	return __encls_ret_2(SGX_EMODT, secinfo, addr);
}

int sgx_fs_init(const char *name);
void sgx_fs_remove(void);

int sgx_encl_drv_probe(void);
int sgx_virt_driver_probe(void);
int sgx_device_alloc(const char *name, const struct file_operations *fops);

struct sgx_epc_page *sgx_alloc_page(void *owner, bool reclaim);
int __sgx_free_page(struct sgx_epc_page *page);
void sgx_free_page(struct sgx_epc_page *page);
int sgx_einit(struct sgx_sigstruct *sigstruct, struct sgx_einittoken *token,
	      struct sgx_epc_page *secs, u64 *lepubkeyhash);
void sgx_page_reclaimable(struct sgx_epc_page *page);

bool sgx_encl_page_get(struct sgx_epc_page *epc_page);
void sgx_encl_page_put(struct sgx_epc_page *epc_page);
bool sgx_encl_page_reclaim(struct sgx_epc_page *epc_page);
void sgx_encl_page_block(struct sgx_epc_page *epc_page);
void sgx_encl_page_write(struct sgx_epc_page *epc_page);

#endif /* _X86_SGX_H */
