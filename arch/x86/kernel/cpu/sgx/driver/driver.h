/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
 * Copyright(c) 2016-18 Intel Corporation.
 */
#ifndef __ARCH_INTEL_SGX_H__
#define __ARCH_INTEL_SGX_H__

#include <crypto/hash.h>
#include <linux/kref.h>
#include <linux/mmu_notifier.h>
#include <linux/mmu_notifier.h>
#include <linux/radix-tree.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <uapi/asm/sgx.h>
#include "../sgx.h"

#define sgx_pr(level, encl, fmt, ...)				\
	pr_ ## level("sgx: [%d:0x%p] " fmt, pid_nr((encl)->tgid),	\
		     (void *)(encl)->base, ##__VA_ARGS__)
#define sgx_dbg(encl, fmt, ...) \
	sgx_pr(debug, encl, fmt, ##__VA_ARGS__)
#define sgx_info(encl, fmt, ...) \
	sgx_pr(info, encl, fmt, ##__VA_ARGS__)
#define sgx_warn(encl, fmt, ...) \
	sgx_pr(warn, encl, fmt, ##__VA_ARGS__)
#define sgx_err(encl, fmt, ...) \
	sgx_pr(err, encl, fmt, ##__VA_ARGS__)
#define sgx_crit(encl, fmt, ...) \
	sgx_pr(crit, encl, fmt, ##__VA_ARGS__)

#define SGX_EINIT_SPIN_COUNT	20
#define SGX_EINIT_SLEEP_COUNT	50
#define SGX_EINIT_SLEEP_TIME	20
#define SGX_VA_SLOT_COUNT	512

#define SGX_VA_SLOT_COUNT 512

struct sgx_va_page {
	struct sgx_epc_page *epc_page;
	DECLARE_BITMAP(slots, SGX_VA_SLOT_COUNT);
	struct list_head list;
};

/**
 * enum sgx_encl_page_desc - defines bits for an enclave page's descriptor
 * %SGX_ENCL_PAGE_TCS:			The page is a TCS page.
 * %SGX_ENCL_PAGE_RECLAIMED:		The page is in the process of being
 *					reclaimed.
 * %SGX_ENCL_PAGE_VA_OFFSET_MASK:	Holds the offset in the Version Array
 *					(VA) page for a swapped page.
 * %SGX_ENCL_PAGE_ADDR_MASK:		Holds the virtual address of the page.
 *
 * The page address for SECS is zero and is used by the subsystem to recognize
 * the SECS page.
 */
enum sgx_encl_page_desc {
	SGX_ENCL_PAGE_TCS		= BIT(0),
	/* Bits 11:3 are available when the page is not swapped. */
	SGX_ENCL_PAGE_RECLAIMED		= BIT(3),
	SGX_ENCL_PAGE_VA_OFFSET_MASK	= GENMASK_ULL(11, 3),
	SGX_ENCL_PAGE_ADDR_MASK		= PAGE_MASK,
};

#define SGX_ENCL_PAGE_ADDR(encl_page) \
	((encl_page)->desc & SGX_ENCL_PAGE_ADDR_MASK)
#define SGX_ENCL_PAGE_VA_OFFSET(encl_page) \
	((encl_page)->desc & SGX_ENCL_PAGE_VA_OFFSET_MASK)

struct sgx_encl_page {
	unsigned long desc;
	struct sgx_epc_page *epc_page;
	struct sgx_va_page *va_page;
	struct sgx_encl *encl;
};

enum sgx_encl_flags {
	SGX_ENCL_INITIALIZED	= BIT(0),
	SGX_ENCL_DEBUG		= BIT(1),
	SGX_ENCL_SUSPEND	= BIT(2),
	SGX_ENCL_DEAD		= BIT(3),
	SGX_ENCL_MM_RELEASED	= BIT(4),
};

struct sgx_encl {
	unsigned int flags;
	u64 secs_attributes;
	u64 allowed_attributes;
	unsigned int page_cnt;
	unsigned int secs_child_cnt;
	struct mutex lock;
	struct mm_struct *mm;
	unsigned long backing;
	struct kref refcount;
	unsigned long base;
	unsigned long size;
	unsigned long ssaframesize;
	struct list_head va_pages;
	struct radix_tree_root page_tree;
	struct list_head add_page_reqs;
	struct work_struct work;
	struct sgx_encl_page secs;
	struct pid *tgid;
	struct mmu_notifier mmu_notifier;
	struct notifier_block pm_notifier;
};

extern struct workqueue_struct *sgx_encl_wq;
extern u64 sgx_encl_size_max_32;
extern u64 sgx_encl_size_max_64;
extern u32 sgx_misc_reserved_mask;
extern u64 sgx_attributes_reserved_mask;
extern u64 sgx_xfrm_reserved_mask;
extern u32 sgx_xsave_size_tbl[64];
extern int sgx_epcm_trapnr;

extern const struct vm_operations_struct sgx_vm_ops;

/* ENCLS wrappers. */

static inline struct sgx_encl_page *to_encl_page(struct sgx_epc_page *epc_page)
{
	return (struct sgx_encl_page *)epc_page->owner;
}

void sgx_encl_eblock(struct sgx_encl_page *encl_page);
void sgx_encl_etrack(struct sgx_encl *encl);
void sgx_encl_ewb(struct sgx_epc_page *epc_page, bool do_free);
struct sgx_epc_page *sgx_encl_eldu(struct sgx_encl_page *encl_page);

int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma);
void sgx_invalidate(struct sgx_encl *encl, bool flush_cpus);

/**
 * SGX_INVD - invalidate an enclave on failure, i.e. if ret != 0
 * @ret:	a return code to check
 * @encl:	pointer to an enclave
 * @fmt:	message for WARN if failure is detected
 * @...:	optional arguments used by @fmt
 *
 * SGX_INVD is used in flows where an error, i.e. @ret is non-zero, is
 * indicative of a driver bug.  Invalidate @encl if @ret indicates an
 * error and WARN on error unless the error was due to a fault signaled
 * by the EPCM.
 *
 * Faults from the EPCM occur in normal kernel operation, e.g. due to
 * misonfigured mprotect() from userspace or because the EPCM invalidated
 * all EPC pages.  The EPCM invalidates the EPC on transitions to S3 or
 * lower sleep states, and VMMs emulate loss of EPC when migrating VMs.
 *
 * Defined as a macro instead of a function so that WARN can provide a
 * more precise trace.
 */
#define SGX_INVD(ret, encl, fmt, ...)					  \
do {									  \
	if (unlikely(ret)) {						  \
		int trapnr = IS_ENCLS_FAULT(ret) ? ENCLS_TRAPNR(ret) : 0; \
		WARN(trapnr != sgx_epcm_trapnr, fmt, ##__VA_ARGS__);	  \
		sgx_invalidate(encl, true);				  \
	}								  \
} while (0)

struct sgx_encl *sgx_encl_alloc(struct sgx_secs *secs);
int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs);
struct sgx_encl_page *sgx_encl_alloc_page(struct sgx_encl *encl,
					  unsigned long addr);
void sgx_encl_free_page(struct sgx_encl_page *encl_page);
int sgx_encl_add_page(struct sgx_encl *encl, unsigned long addr, void *data,
		      struct sgx_secinfo *secinfo, unsigned int mrmask);
int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
		  struct sgx_einittoken *einittoken);
int sgx_encl_modify_pages(struct sgx_encl *encl, unsigned long addr,
			  unsigned long length, struct sgx_secinfo *secinfo,
			  unsigned int op);
void sgx_encl_release(struct kref *ref);
pgoff_t sgx_encl_get_index(struct sgx_encl *encl, struct sgx_encl_page *page);

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#endif

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr);
struct sgx_encl_page *sgx_reserve_page(struct vm_area_struct *vma,
				       unsigned long addr);

int sgx_test_and_clear_young(struct sgx_encl_page *page);
void sgx_flush_cpus(struct sgx_encl *encl);
struct sgx_epc_page *sgx_alloc_va_page(void);
unsigned int sgx_alloc_va_slot(struct sgx_va_page *va_page);
void sgx_free_va_slot(struct sgx_va_page *va_page, unsigned int offset);
bool sgx_va_page_full(struct sgx_va_page *va_page);

#endif /* __ARCH_X86_INTEL_SGX_H__ */
