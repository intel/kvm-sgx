/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
#ifndef _ASM_X86_SGX_VIRT_H
#define _ASM_X86_SGX_VIRT_H

#ifdef CONFIG_INTEL_SGX_VIRTUALIZATION
int __init sgx_virt_epc_init(void);
bool sgx_virt_epc_get_ref(struct sgx_epc_page *epc_page);
void sgx_virt_epc_oom(struct sgx_epc_page *epc_page);
#else
static inline int __init sgx_virt_epc_init(void)
{
	return -ENODEV;
}
static inline bool sgx_virt_epc_get_ref(struct sgx_epc_page *epc_page)
{
	WARN_ON_ONCE(1);
	return false;
}
static inline void sgx_virt_epc_oom(struct sgx_epc_page *epc_page) {}
#endif

#endif /* _ASM_X86_SGX_VIRT_H */
