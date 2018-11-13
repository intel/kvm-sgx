/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2016-18 Intel Corporation.
 */

	.section ".rodata", "a"

encl_bin:
	.globl encl_bin
	.incbin	"encl.bin"
encl_bin_end:
	.globl encl_bin_end

encl_ss:
	.globl encl_ss
	.incbin	"encl.ss"
encl_ss_end:
	.globl encl_ss_end
