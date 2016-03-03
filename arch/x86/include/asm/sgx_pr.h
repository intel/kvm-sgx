// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#ifndef _ASM_X86_SGX_PR_H
#define _ASM_X86_SGX_PR_H

#include <linux/printk.h>
#include <linux/ratelimit.h>

#undef pr_fmt
#define pr_fmt(fmt) "intel_sgx: " fmt

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

#endif /* _ASM_X86_SGX_PR_H */
