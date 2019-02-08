/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

struct sgx_epc_page;

#if IS_ENABLED(CONFIG_KVM_INTEL)
struct sgx_epc_page *sgx_virt_get_epc_page(unsigned long addr);

static inline void sgx_virt_put_epc_page(struct sgx_epc_page *epc_page)
{

}
#endif

#endif /* _ASM_X86_SGX_H */
