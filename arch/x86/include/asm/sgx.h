/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SGX_H
#define _ASM_X86_SGX_H

struct sgx_einittoken;
struct sgx_epc_page;
struct sgx_pageinfo;
struct sgx_sigstruct;

#if IS_ENABLED(CONFIG_KVM_INTEL)
struct sgx_epc_page *sgx_virt_get_epc_page(unsigned long addr);

static inline void sgx_virt_put_epc_page(struct sgx_epc_page *epc_page)
{

}

int sgx_virt_ecreate(struct sgx_pageinfo *pginfo, struct sgx_epc_page *secs,
                     int *trapnr);
int sgx_virt_einit(struct sgx_sigstruct *sigstruct,
                   struct sgx_einittoken *token, struct sgx_epc_page *secs,
                   u64 *lepubkeyhash, int *trapnr);
#endif

#endif /* _ASM_X86_SGX_H */
