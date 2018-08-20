/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/* Copyright(c) 2016-18 Intel Corporation. */

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
#include <asm/sgx.h>
#include <asm/sgx_pr.h>
#include <uapi/asm/sgx.h>

#define sgx_pr_ratelimited(level, encl, fmt, ...)			\
	pr_ ## level ## _ratelimited("[%d:0x%p] " fmt,			\
				     pid_nr((encl)->tgid),		\
				     (void *)(encl)->base, ##__VA_ARGS__)
#define sgx_dbg(encl, fmt, ...) \
	sgx_pr_ratelimited(debug, encl, fmt, ##__VA_ARGS__)
#define sgx_info(encl, fmt, ...) \
	sgx_pr_ratelimited(info, encl, fmt, ##__VA_ARGS__)
#define sgx_warn(encl, fmt, ...) \
	sgx_pr_ratelimited(warn, encl, fmt, ##__VA_ARGS__)
#define sgx_err(encl, fmt, ...) \
	sgx_pr_ratelimited(err, encl, fmt, ##__VA_ARGS__)
#define sgx_crit(encl, fmt, ...) \
	sgx_pr_ratelimited(crit, encl, fmt, ##__VA_ARGS__)

#define SGX_EINIT_SPIN_COUNT	20
#define SGX_EINIT_SLEEP_COUNT	50
#define SGX_EINIT_SLEEP_TIME	20

#define SGX_VA_SLOT_COUNT 512

struct sgx_va_page {
	struct sgx_epc_page *epc_page;
	DECLARE_BITMAP(slots, SGX_VA_SLOT_COUNT);
	struct list_head list;
};

/**
 * enum sgx_encl_page_desc - defines bits and masks for an enclave page's desc
 *
 * @SGX_ENCL_PAGE_TCS:
 * @SGX_ENCL_PAGE_LOADED:
 * @SGX_ENCL_PAGE_RESERVED:  Set when we need to temporarily prevent reclaim,
 *			     e.g. the page is being directly accessed for debug
 *			     purposes.
 * @SGX_ENCL_PAGE_RECLAIMED: Set when a LOADED page is in the process of being
 *			     reclaimed by the EPC manager.  Once RECLAIMED is
 *			     set we no longer "own" the EPC page; we're still
 *			     involved in evicting the page, but we cannot free
 *			     the EPC page or rely on its contents in any way.
 *
 * @SGX_ENCL_PAGE_VA_OFFSET_MASK: Holds the offset into the VA page that was
 *				  used to evict the page.
 * @SGX_ENCL_PAGE_ADDR_MASK:	  Holds the userspace virtual address of the
 *				  page.  Primarily used to manipulate PTEs and
 *				  retrieve an enclave from a given page.
 *
 * enum sgx_encl_page_desc defines the layout of struct sgx_encl_page's @desc.
 * The metadata for an enclave page is compressed into a single variable to
 * reduce memory consumption as the size of enclaves are effectively unbounded,
 * e.g. a userspace process can create a 512gb enclave regardless of the actual
 * amount of EPC in the system.
 *
 * WARNING: Bits 11:3 are effectively a union, similar to how a union is used
 * to store either a pointer to an EPC page or VA page depending on whether or
 * not a struct sgx_encl_page is resident in the EPC.  When the page is evicted
 * from the EPC, bits 11:3 are used to hold the VA offset.  Flags that may be
 * set/cleared at any time must not reside in bits 11:3.
 */
enum sgx_encl_page_desc {
	SGX_ENCL_PAGE_TCS		= BIT(0),
	SGX_ENCL_PAGE_LOADED		= BIT(1),
	/* Bit 2 is free, may be used at any time */

	SGX_ENCL_PAGE_RESERVED		= BIT(3),
	SGX_ENCL_PAGE_RECLAIMED		= BIT(4),
	/* Bits 11:5 are free, may only be used when page is resident in EPC */

	SGX_ENCL_PAGE_VA_OFFSET_MASK	= GENMASK_ULL(11, 3),

	SGX_ENCL_PAGE_ADDR_MASK		= PAGE_MASK,
};

#define SGX_ENCL_PAGE_ADDR(encl_page) \
	((encl_page)->desc & SGX_ENCL_PAGE_ADDR_MASK)
#define SGX_ENCL_PAGE_VA_OFFSET(encl_page) \
	((encl_page)->desc & SGX_ENCL_PAGE_VA_OFFSET_MASK)
#define SGX_ENCL_PAGE_BACKING_INDEX(encl_page, encl)		\
({								\
	pgoff_t index;						\
	if (!PFN_DOWN(encl_page->desc))				\
		index = PFN_DOWN(encl->size);			\
	else							\
		index = PFN_DOWN(encl_page->desc - encl->base);	\
	index;							\
})
#define SGX_ENCL_PAGE_PCMD_OFFSET(encl_page, encl)		\
({								\
	unsigned long ret;					\
	ret = SGX_ENCL_PAGE_BACKING_INDEX(encl_page, encl);	\
	((ret & 31) * 128);					\
})

struct sgx_encl_page {
	unsigned long desc;
	union {
		struct sgx_epc_page *epc_page;
		struct sgx_va_page *va_page;
	};
	struct sgx_encl *encl;
	struct sgx_epc_page_impl impl;
};

enum sgx_encl_flags {
	SGX_ENCL_INITIALIZED	= BIT(0),
	SGX_ENCL_DEBUG		= BIT(1),
	SGX_ENCL_SUSPEND	= BIT(2),
	SGX_ENCL_DEAD		= BIT(3),
};

struct sgx_encl {
	unsigned int flags;
	uint64_t attributes;
	uint64_t xfrm;
	unsigned int page_cnt;
	unsigned int secs_child_cnt;
	struct mutex lock;
	struct mm_struct *mm;
	struct file *backing;
	struct file *pcmd;
	struct kref refcount;
	unsigned long base;
	unsigned long size;
	unsigned long ssaframesize;
	struct list_head va_pages;
	struct radix_tree_root page_tree;
	struct list_head add_page_reqs;
	struct work_struct add_page_work;
	struct sgx_encl_page secs;
	struct pid *tgid;
	struct mmu_notifier mmu_notifier;
	struct notifier_block pm_notifier;
};

extern struct workqueue_struct *sgx_add_page_wq;
extern u64 sgx_encl_size_max_32;
extern u64 sgx_encl_size_max_64;
extern u64 sgx_xfrm_mask;
extern u32 sgx_misc_reserved;
extern u32 sgx_xsave_size_tbl[64];

extern const struct vm_operations_struct sgx_vm_ops;

int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma);
void sgx_invalidate(struct sgx_encl *encl, bool flush_cpus);
#define SGX_INVD(ret, encl, fmt, ...)		\
do {						\
	if (WARN(ret, fmt, ##__VA_ARGS__))	\
		sgx_invalidate(encl, true);	\
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
void sgx_encl_block(struct sgx_encl_page *encl_page);
void sgx_encl_track(struct sgx_encl *encl);
int sgx_encl_load_page(struct sgx_encl_page *encl_page,
		       struct sgx_epc_page *epc_page);
void sgx_encl_release(struct kref *ref);

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#endif

/* Utility functions */
int sgx_test_and_clear_young(struct sgx_encl_page *page);
void sgx_flush_cpus(struct sgx_encl *encl);

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr,
				     bool do_reserve);

extern const struct sgx_epc_page_ops sgx_encl_page_ops;

void sgx_set_epc_page(struct sgx_encl_page *encl_page,
		      struct sgx_epc_page *epc_page);
void sgx_set_page_reclaimable(struct sgx_encl_page *encl_page);
struct sgx_epc_page *sgx_alloc_va_page(unsigned int flags);
unsigned int sgx_alloc_va_slot(struct sgx_va_page *va_page);
void sgx_free_va_slot(struct sgx_va_page *va_page, unsigned int offset);
bool sgx_va_page_full(struct sgx_va_page *va_page);

#endif /* __ARCH_X86_INTEL_SGX_H__ */
