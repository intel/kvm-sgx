/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_SGX_H
#define __KVM_X86_SGX_H

#include <linux/kvm_host.h>

#ifdef CONFIG_INTEL_SGX_VIRTUALIZATION
extern bool __read_mostly enable_sgx;

int handle_encls(struct kvm_vcpu *vcpu);
#else
#define enable_sgx 0
#endif

#endif /* __KVM_X86_SGX_H */

