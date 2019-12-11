/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
#ifndef _ASM_X86_SGX_VIRT_H
#define _ASM_X86_SGX_VIRT_H

#ifdef CONFIG_X86_SGX_VIRTUALIZATION
int __init sgx_virt_epc_init(void);
#else
static inline int __init sgx_virt_epc_init(void)
{
	return -ENODEV;
}
#endif

#endif /* _ASM_X86_SGX_VIRT_H */
