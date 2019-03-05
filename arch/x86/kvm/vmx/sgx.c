// SPDX-License-Identifier: GPL-2.0

#include <linux/highmem.h>

#include <asm/page_types.h>
#include <asm/sgx.h>
#include <asm/sgx_arch.h>

#include "cpuid.h"
#include "kvm_cache_regs.h"
#include "vmx.h"
#include "x86.h"

struct encls_mem_op {
	const enum kvm_reg reg;
	gva_t gva;
	gpa_t gpa;
	unsigned long size;
	unsigned long align;
	void *p;
	bool write;
};

/*
 * ENCLS's memory operands use a fixed segment (DS) and a fixed
 * address size based on the mode.  Related prefixes are ignored.
 */
static bool get_encls_mem_op(struct kvm_vcpu *vcpu, struct encls_mem_op *op)
{
	struct kvm_segment s;
	bool fault;

	vmx_get_segment(vcpu, &s, VCPU_SREG_DS);

	op->gva = s.base + kvm_register_read(vcpu, op->reg);

	if (!IS_ALIGNED(op->gva, op->align)) {
		fault = true;
	} else if (is_long_mode(vcpu)) {
		fault = is_noncanonical_address(op->gva, vcpu);
	} else {
		op->gva &= 0xffffffff;
		fault = (s.unusable) ||
			(s.type != 2 && s.type != 3) ||
			(op->gva > s.limit) ||
			((s.base != 0 || s.limit != 0xffffffff) &&
			((op->gva + op->size) > (s.limit + 1)));
	}
	if (fault)
		kvm_inject_gp(vcpu, 0);
	return fault;
}

static bool get_encls_mem_value(struct kvm_vcpu *vcpu,
				const struct encls_mem_op *op)
{
	struct x86_exception ex;

	if (kvm_read_guest_virt(vcpu, op->gva, op->p, op->size, &ex)) {
		kvm_propagate_page_fault(vcpu, &ex);
		return true;
	}
	return false;
}

static bool get_encls_epc_gpa(struct kvm_vcpu *vcpu, struct encls_mem_op *op)
{
	struct x86_exception ex;

	op->gpa = kvm_mmu_gva_to_gpa_write(vcpu, op->gva, &ex);
        if (op->gpa == UNMAPPED_GVA) {
                kvm_propagate_page_fault(vcpu, &ex);
                return true;
        }
	return false;
}

static int get_encls_epc_page(struct kvm_vcpu *vcpu, struct encls_mem_op *op)
{
	struct x86_exception ex;
	unsigned long hva;

	hva = kvm_vcpu_gfn_to_hva(vcpu, PFN_DOWN(op->gpa));
	if (kvm_is_error_hva(hva))
		goto inject_pf;

	op->p = sgx_virt_get_epc_page(hva);
	if (PTR_ERR(op->p) == -EFAULT)
		goto inject_pf;
	else if (IS_ERR(op->p))
		return PTR_ERR(op->p);

	return 0;

inject_pf:
	ex.vector = PF_VECTOR;
	ex.error_code = PFERR_PRESENT_MASK;
	if (op->write)
		ex.error_code |= PFERR_WRITE_MASK;
	ex.address = op->gva;
	ex.error_code_valid = true;
	ex.nested_page_fault = false;
	kvm_propagate_page_fault(vcpu, &ex);
	return -EFAULT;
}

static inline void put_encls_epc_page(struct encls_mem_op *op)
{
	sgx_virt_put_epc_page((struct sgx_epc_page *)op->p);
}

static int vmx_encls_postamble(struct kvm_vcpu *vcpu, int ret, int trapnr,
			       const struct encls_mem_op *op)
{
	struct x86_exception ex;
	unsigned long rflags;

	if (ret == -EFAULT) {
		if (guest_cpuid_has(vcpu, X86_FEATURE_SGX2) &&
		    trapnr == PF_VECTOR) {
			ex.vector = PF_VECTOR;
			ex.error_code = PFERR_PRESENT_MASK | PFERR_SGX_MASK;
			if (op->write)
				ex.error_code |= PFERR_WRITE_MASK;
			ex.address = op->gva;
			ex.error_code_valid = true;
			ex.nested_page_fault = false;
			kvm_inject_page_fault(vcpu, &ex);
		} else {
			kvm_inject_gp(vcpu, 0);
		}
		return 1;
	}

	rflags = vmx_get_rflags(vcpu) & ~(X86_EFLAGS_CF | X86_EFLAGS_PF |
					  X86_EFLAGS_AF | X86_EFLAGS_SF |
					  X86_EFLAGS_OF);
	if (ret)
		rflags |= X86_EFLAGS_ZF;
	else
		rflags &= ~X86_EFLAGS_ZF;
	vmx_set_rflags(vcpu, rflags);

	kvm_register_write(vcpu, VCPU_REGS_RAX, ret);
	return kvm_skip_emulated_instruction(vcpu);
}

int handle_encls_ecreate(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *sgx_12_0, *sgx_12_1;
	struct sgx_secinfo __secinfo;
	struct sgx_pageinfo __pageinfo;
	struct sgx_secs *__secs;
	struct page *src_page;
	int r, ret, trapnr;

	struct encls_mem_op pageinfo = {
		.reg = VCPU_REGS_RBX,
		.size = sizeof(__pageinfo),
		.align = 32,
		.p = &__pageinfo,
	};
	struct encls_mem_op secs = {
		.reg = VCPU_REGS_RCX,
		.size = 4096,
		.align = 4096,
		.write = true,
	};
	struct encls_mem_op secinfo = {
		.size = sizeof(__secinfo),
		.align = 64,
		.p = &__secinfo,
	};
	struct encls_mem_op srcpge = {
		.size = 4096,
		.align = 4096,
	};

	sgx_12_0 = kvm_find_cpuid_entry(vcpu, 0x12, 0);
	sgx_12_1 = kvm_find_cpuid_entry(vcpu, 0x12, 1);
	if (!sgx_12_0 || !sgx_12_1) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	if (get_encls_mem_op(vcpu, &pageinfo) ||
	    get_encls_mem_op(vcpu, &secs))
		return 1;

	if (get_encls_epc_gpa(vcpu, &secs) ||
	    get_encls_mem_value(vcpu, &pageinfo))
		return 1;

	secinfo.gva = __pageinfo.metadata;
	if (get_encls_mem_value(vcpu, &secinfo))
		return 1;

	src_page = alloc_page(GFP_HIGHUSER);
	if (!src_page)
		return -ENOMEM;

	srcpge.p = kmap(src_page);
	srcpge.gva = __pageinfo.contents;
	if (get_encls_mem_value(vcpu, &srcpge)) {
		ret = 1;
		goto out;
	}

	/* Enforce restrictions on MISCSELECT, ATTRIBUTES and XFRM. */
	__secs = srcpge.p;
	if ((u32)__secs->miscselect & ~sgx_12_0->ebx ||
	    (u32)__secs->attributes & ~sgx_12_1->eax ||
	    (u32)(__secs->attributes >> 32) & ~sgx_12_1->ebx ||
	    (u32)__secs->xfrm & ~sgx_12_1->ecx ||
	    (u32)(__secs->xfrm >> 32) & ~sgx_12_1->edx) {
		kvm_inject_gp(vcpu, 0);
		ret = 1;
		goto out;		
	}

	ret = get_encls_epc_page(vcpu, &secs);
	if (ret)
		goto out;

	__pageinfo.metadata = (uint64_t)secinfo.p;
	__pageinfo.contents = (uint64_t)srcpge.p;

	r = sgx_virt_ecreate(pageinfo.p, secs.p, &trapnr);
	put_encls_epc_page(secs.p);

	ret = vmx_encls_postamble(vcpu, r, trapnr, &secs);
out:
	kunmap(src_page);
	__free_page(src_page);

	return ret;
}
