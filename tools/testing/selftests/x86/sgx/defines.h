/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2016-19 Intel Corporation.
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define __aligned(x) __attribute__((__aligned__(x)))
#define __packed __attribute__((packed))

/* Derived from asm-generic/bitsperlong.h. */
#if __x86_64__
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif
#define BITS_PER_LONG_LONG 64

/* Taken from linux/bits.h. */
#define BIT(nr)	(1UL << (nr))
#define BIT_ULL(nr) (1ULL << (nr))
#define GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) \
	(((~0ULL) - (1ULL << (l)) + 1) & \
	 (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

#endif /* TYPES_H */
