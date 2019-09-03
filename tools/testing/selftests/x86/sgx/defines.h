/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2016-19 Intel Corporation.
 */

#ifndef DEFINES_H
#define DEFINES_H

#include <stdint.h>

#define __aligned(x) __attribute__((__aligned__(x)))
#define __packed __attribute__((packed))

#include "../../../../../arch/x86/kernel/cpu/sgx/arch.h"
#include "../../../../../arch/x86/include/uapi/asm/sgx.h"

#endif /* DEFINES_H */
