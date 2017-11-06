/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_SGX_H
#define __KVM_X86_SGX_H

#include <linux/kvm_host.h>

#include "capabilities.h"
#include "ops.h"

#ifdef CONFIG_INTEL_SGX_VIRTUALIZATION
extern bool __read_mostly enable_sgx;

int handle_encls(struct kvm_vcpu *vcpu);
void vmx_write_encls_bitmap(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12);
#else
#define enable_sgx 0
static inline void vmx_write_encls_bitmap(struct kvm_vcpu *vcpu,
					  struct vmcs12 *vmcs12)
{
	/* Nothing to do if hardware doesn't support SGX */
	if (cpu_has_vmx_encls_vmexit())
		vmcs_write64(ENCLS_EXITING_BITMAP, -1ull);
}
#endif

#endif /* __KVM_X86_SGX_H */

