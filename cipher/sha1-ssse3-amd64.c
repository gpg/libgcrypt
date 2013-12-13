/* sha1-ssse3-amd64.c - Intel SSSE3 accelerated SHA-1 transform function
 * Copyright © 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * Based on sha1.c:
 *  Copyright (C) 1998, 2001, 2002, 2003, 2008 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Intel SSSE3 accelerated SHA-1 implementation based on white paper:
 *  "Improving the Performance of the Secure Hash Algorithm (SHA-1)"
 *  http://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1
 */

#ifdef __x86_64__
#include <config.h>

#if defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) && \
    defined(HAVE_INTEL_SYNTAX_PLATFORM_AS) && \
    defined(HAVE_GCC_INLINE_ASM_SSSE3) && defined(USE_SHA1)

#ifdef HAVE_STDINT_H
# include <stdint.h> /* uintptr_t */
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#else
/* In this case, uintptr_t is provided by config.h. */
#endif

#include "bithelp.h"


/* Helper macro to force alignment to 16 bytes.  */
#ifdef HAVE_GCC_ATTRIBUTE_ALIGNED
# define ATTR_ALIGNED_16  __attribute__ ((aligned (16)))
#else
# define ATTR_ALIGNED_16
#endif


typedef struct
{
  u32           h0,h1,h2,h3,h4;
} SHA1_STATE;


/* Round function macros. */
#define K1  0x5A827999L
#define K2  0x6ED9EBA1L
#define K3  0x8F1BBCDCL
#define K4  0xCA62C1D6L
#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z)   ( x ^ y ^ z )
#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z)   ( x ^ y ^ z )
#define R(a,b,c,d,e,f,wk)  do { e += rol( a, 5 )	\
				      + f( b, c, d )	\
				      + wk;	 	\
				 b = rol( b, 30 );	\
			       } while(0)

#define WK(i) (wk[i & 15])


static const u32 K_XMM[4][4] ATTR_ALIGNED_16 =
  {
    { K1, K1, K1, K1 },
    { K2, K2, K2, K2 },
    { K3, K3, K3, K3 },
    { K4, K4, K4, K4 },
  };
static const u32 bswap_shufb_ctl[4] ATTR_ALIGNED_16 =
  { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };


/*
 * Transform 64 bytes (16 32-bit words) at DATA.
 */
unsigned int
_gcry_sha1_transform_amd64_ssse3 (void *ctx, const unsigned char *data)
{
  SHA1_STATE *state = ctx;
  register u32 a, b, c, d, e; /* Local copies of the chaining variables.  */
  byte wk_unaligned[4*16+15];  /* The array we work on. */
  u32 *wk = (u32 *)(wk_unaligned
                    + ((16 - ((uintptr_t)wk_unaligned & 15)) & 15));

  /* Get the values of the chaining variables. */
  a = state->h0;
  b = state->h1;
  c = state->h2;
  d = state->h3;
  e = state->h4;

#define Wtmp0 "xmm0"
#define Wtmp1 "xmm1"

#define W0 "xmm2"
#define W1 "xmm3"
#define W2 "xmm4"
#define W3 "xmm5"
#define W4 "xmm6"
#define W5 "xmm7"
#define W6 "xmm8"
#define W7 "xmm9"

#define BSWAP_REG "xmm10"

  __asm__ volatile ("movdqa %[bswap], %%"BSWAP_REG";\n\t"
                    :: [bswap] "m" (bswap_shufb_ctl[0]));

#define W_PRECALC_00_15_0(i, W, tmp0) \
  __asm__ volatile ("movdqu %[data], %%"tmp0";\n\t" \
                    ::[data] "m" (*(data+4*(i))));

#define W_PRECALC_00_15_1(i, W, tmp0) \
  __asm__ volatile ("pshufb %%"BSWAP_REG", %%"tmp0";\n\t" \
                    "movdqa %%"tmp0", %%"W";\n\t" \
                    ::: "cc");

#define W_PRECALC_00_15_2(i, W, tmp0) \
  __asm__ volatile ("paddd %[k_xmm], %%"tmp0";\n\t" \
                    ::[k_xmm] "m" (K_XMM[i / 20][0]));

#define W_PRECALC_00_15_3(i, W, tmp0) \
  __asm__ volatile ("movdqa %%"tmp0", %[wk];\n\t" \
                    :[wk] "=m" (WK(i&~3)));

  /* Precalc 0-15. */
  W_PRECALC_00_15_0(0, W0, Wtmp0);
  W_PRECALC_00_15_1(1, W0, Wtmp0);
  W_PRECALC_00_15_2(2, W0, Wtmp0);
  W_PRECALC_00_15_3(3, W0, Wtmp0);
  W_PRECALC_00_15_0(4, W7, Wtmp0);
  W_PRECALC_00_15_1(5, W7, Wtmp0);
  W_PRECALC_00_15_2(6, W7, Wtmp0);
  W_PRECALC_00_15_3(7, W7, Wtmp0);
  W_PRECALC_00_15_0(8, W6, Wtmp0);
  W_PRECALC_00_15_1(9, W6, Wtmp0);
  W_PRECALC_00_15_2(10, W6, Wtmp0);
  W_PRECALC_00_15_3(11, W6, Wtmp0);
  W_PRECALC_00_15_0(12, W5, Wtmp0);
  W_PRECALC_00_15_1(13, W5, Wtmp0);
  W_PRECALC_00_15_2(14, W5, Wtmp0);
  W_PRECALC_00_15_3(15, W5, Wtmp0);

#define W_PRECALC_16_31_0(i, W, W_m04, W_m08, W_m12, W_m16, tmp0, tmp1) \
  __asm__ volatile ("movdqa %%"W_m12", %%"W";\n\t" \
                    "palignr $8, %%"W_m16", %%"W";\n\t" \
                    "movdqa %%"W_m04", %%"tmp0";\n\t" \
                    "psrldq $4, %%"tmp0";\n\t" \
                    "pxor %%"W_m08", %%"W";\n\t" \
                    :::"cc");

#define W_PRECALC_16_31_1(i, W, W_m04, W_m08, W_m12, W_m16, tmp0, tmp1) \
  __asm__ volatile ("pxor %%"W_m16", %%"tmp0";\n\t" \
                    "pxor %%"tmp0", %%"W";\n\t" \
                    "movdqa %%"W", %%"tmp1";\n\t" \
                    "movdqa %%"W", %%"tmp0";\n\t" \
                    "pslldq $12, %%"tmp1";\n\t" \
                    :::"cc");

#define W_PRECALC_16_31_2(i, W, W_m04, W_m08, W_m12, W_m16, tmp0, tmp1) \
  __asm__ volatile ("psrld $31, %%"W";\n\t" \
                    "pslld $1, %%"tmp0";\n\t" \
                    "por %%"W", %%"tmp0";\n\t" \
                    "movdqa %%"tmp1", %%"W";\n\t" \
                    "psrld $30, %%"tmp1";\n\t" \
                    "pslld $2, %%"W";\n\t" \
                    :::"cc");

#define W_PRECALC_16_31_3(i, W, W_m04, W_m08, W_m12, W_m16, tmp0, tmp1) \
  __asm__ volatile ("pxor %%"W", %%"tmp0";\n\t" \
                    "pxor %%"tmp1", %%"tmp0";\n\t" \
                    "movdqa %%"tmp0", %%"W";\n\t" \
                    "paddd %[k_xmm], %%"tmp0";\n\t" \
                    "movdqa %%"tmp0", %[wk];\n\t" \
                    : [wk] "=m" (WK(i&~3)) \
                    : [k_xmm] "m" (K_XMM[i / 20][0]));

  /* Transform 0-15 + Precalc 16-31. */
  R( a, b, c, d, e, F1, WK( 0) ); W_PRECALC_16_31_0(16, W4, W5, W6, W7, W0, Wtmp0, Wtmp1);
  R( e, a, b, c, d, F1, WK( 1) ); W_PRECALC_16_31_1(17, W4, W5, W6, W7, W0, Wtmp0, Wtmp1);
  R( d, e, a, b, c, F1, WK( 2) ); W_PRECALC_16_31_2(18, W4, W5, W6, W7, W0, Wtmp0, Wtmp1);
  R( c, d, e, a, b, F1, WK( 3) ); W_PRECALC_16_31_3(19, W4, W5, W6, W7, W0, Wtmp0, Wtmp1);
  R( b, c, d, e, a, F1, WK( 4) ); W_PRECALC_16_31_0(20, W3, W4, W5, W6, W7, Wtmp0, Wtmp1);
  R( a, b, c, d, e, F1, WK( 5) ); W_PRECALC_16_31_1(21, W3, W4, W5, W6, W7, Wtmp0, Wtmp1);
  R( e, a, b, c, d, F1, WK( 6) ); W_PRECALC_16_31_2(22, W3, W4, W5, W6, W7, Wtmp0, Wtmp1);
  R( d, e, a, b, c, F1, WK( 7) ); W_PRECALC_16_31_3(23, W3, W4, W5, W6, W7, Wtmp0, Wtmp1);
  R( c, d, e, a, b, F1, WK( 8) ); W_PRECALC_16_31_0(24, W2, W3, W4, W5, W6, Wtmp0, Wtmp1);
  R( b, c, d, e, a, F1, WK( 9) ); W_PRECALC_16_31_1(25, W2, W3, W4, W5, W6, Wtmp0, Wtmp1);
  R( a, b, c, d, e, F1, WK(10) ); W_PRECALC_16_31_2(26, W2, W3, W4, W5, W6, Wtmp0, Wtmp1);
  R( e, a, b, c, d, F1, WK(11) ); W_PRECALC_16_31_3(27, W2, W3, W4, W5, W6, Wtmp0, Wtmp1);
  R( d, e, a, b, c, F1, WK(12) ); W_PRECALC_16_31_0(28, W1, W2, W3, W4, W5, Wtmp0, Wtmp1);
  R( c, d, e, a, b, F1, WK(13) ); W_PRECALC_16_31_1(29, W1, W2, W3, W4, W5, Wtmp0, Wtmp1);
  R( b, c, d, e, a, F1, WK(14) ); W_PRECALC_16_31_2(30, W1, W2, W3, W4, W5, Wtmp0, Wtmp1);
  R( a, b, c, d, e, F1, WK(15) ); W_PRECALC_16_31_3(31, W1, W2, W3, W4, W5, Wtmp0, Wtmp1);

#define W_PRECALC_32_79_0(i, W, W_m04, W_m08, W_m12, W_m16, W_m20, W_m24, W_m28, tmp0) \
  __asm__ volatile ("movdqa %%"W_m04", %%"tmp0";\n\t" \
                    "pxor %%"W_m28", %%"W";\n\t" \
                    "palignr $8, %%"W_m08", %%"tmp0";\n\t" \
                    :::"cc");

#define W_PRECALC_32_79_1(i, W, W_m04, W_m08, W_m12, W_m16, W_m20, W_m24, W_m28, tmp0) \
  __asm__ volatile ("pxor %%"W_m16", %%"W";\n\t" \
                    "pxor %%"tmp0", %%"W";\n\t" \
                    "movdqa %%"W", %%"tmp0";\n\t" \
                    :::"cc");

#define W_PRECALC_32_79_2(i, W, W_m04, W_m08, W_m12, W_m16, W_m20, W_m24, W_m28, tmp0) \
  __asm__ volatile ("psrld $30, %%"W";\n\t" \
                    "pslld $2, %%"tmp0";\n\t" \
                    "por %%"W", %%"tmp0";\n\t" \
                    :::"cc");

#define W_PRECALC_32_79_3(i, W, W_m04, W_m08, W_m12, W_m16, W_m20, W_m24, W_m28, tmp0) \
  __asm__ volatile ("movdqa %%"tmp0", %%"W";\n\t" \
                    "paddd %[k_xmm], %%"tmp0";\n\t" \
                    "movdqa %%"tmp0", %[wk];\n\t" \
                    : [wk] "=m" (WK(i&~3)) \
                    : [k_xmm] "m" (K_XMM[i / 20][0]));

  /* Transform 16-63 + Precalc 32-79. */
  R( e, a, b, c, d, F1, WK(16) ); W_PRECALC_32_79_0(32, W0, W1, W2, W3, W4, W5, W6, W7, Wtmp0);
  R( d, e, a, b, c, F1, WK(17) ); W_PRECALC_32_79_1(33, W0, W1, W2, W3, W4, W5, W6, W7, Wtmp0);
  R( c, d, e, a, b, F1, WK(18) ); W_PRECALC_32_79_2(34, W0, W1, W2, W3, W4, W5, W6, W7, Wtmp0);
  R( b, c, d, e, a, F1, WK(19) ); W_PRECALC_32_79_3(35, W0, W1, W2, W3, W4, W5, W6, W7, Wtmp0);
  R( a, b, c, d, e, F2, WK(20) ); W_PRECALC_32_79_0(36, W7, W0, W1, W2, W3, W4, W5, W6, Wtmp0);
  R( e, a, b, c, d, F2, WK(21) ); W_PRECALC_32_79_1(37, W7, W0, W1, W2, W3, W4, W5, W6, Wtmp0);
  R( d, e, a, b, c, F2, WK(22) ); W_PRECALC_32_79_2(38, W7, W0, W1, W2, W3, W4, W5, W6, Wtmp0);
  R( c, d, e, a, b, F2, WK(23) ); W_PRECALC_32_79_3(39, W7, W0, W1, W2, W3, W4, W5, W6, Wtmp0);
  R( b, c, d, e, a, F2, WK(24) ); W_PRECALC_32_79_0(40, W6, W7, W0, W1, W2, W3, W4, W5, Wtmp0);
  R( a, b, c, d, e, F2, WK(25) ); W_PRECALC_32_79_1(41, W6, W7, W0, W1, W2, W3, W4, W5, Wtmp0);
  R( e, a, b, c, d, F2, WK(26) ); W_PRECALC_32_79_2(42, W6, W7, W0, W1, W2, W3, W4, W5, Wtmp0);
  R( d, e, a, b, c, F2, WK(27) ); W_PRECALC_32_79_3(43, W6, W7, W0, W1, W2, W3, W4, W5, Wtmp0);
  R( c, d, e, a, b, F2, WK(28) ); W_PRECALC_32_79_0(44, W5, W6, W7, W0, W1, W2, W3, W4, Wtmp0);
  R( b, c, d, e, a, F2, WK(29) ); W_PRECALC_32_79_1(45, W5, W6, W7, W0, W1, W2, W3, W4, Wtmp0);
  R( a, b, c, d, e, F2, WK(30) ); W_PRECALC_32_79_2(46, W5, W6, W7, W0, W1, W2, W3, W4, Wtmp0);
  R( e, a, b, c, d, F2, WK(31) ); W_PRECALC_32_79_3(47, W5, W6, W7, W0, W1, W2, W3, W4, Wtmp0);
  R( d, e, a, b, c, F2, WK(32) ); W_PRECALC_32_79_0(48, W4, W5, W6, W7, W0, W1, W2, W3, Wtmp0);
  R( c, d, e, a, b, F2, WK(33) ); W_PRECALC_32_79_1(49, W4, W5, W6, W7, W0, W1, W2, W3, Wtmp0);
  R( b, c, d, e, a, F2, WK(34) ); W_PRECALC_32_79_2(50, W4, W5, W6, W7, W0, W1, W2, W3, Wtmp0);
  R( a, b, c, d, e, F2, WK(35) ); W_PRECALC_32_79_3(51, W4, W5, W6, W7, W0, W1, W2, W3, Wtmp0);
  R( e, a, b, c, d, F2, WK(36) ); W_PRECALC_32_79_0(52, W3, W4, W5, W6, W7, W0, W1, W2, Wtmp0);
  R( d, e, a, b, c, F2, WK(37) ); W_PRECALC_32_79_1(53, W3, W4, W5, W6, W7, W0, W1, W2, Wtmp0);
  R( c, d, e, a, b, F2, WK(38) ); W_PRECALC_32_79_2(54, W3, W4, W5, W6, W7, W0, W1, W2, Wtmp0);
  R( b, c, d, e, a, F2, WK(39) ); W_PRECALC_32_79_3(55, W3, W4, W5, W6, W7, W0, W1, W2, Wtmp0);
  R( a, b, c, d, e, F3, WK(40) ); W_PRECALC_32_79_0(56, W2, W3, W4, W5, W6, W7, W0, W1, Wtmp0);
  R( e, a, b, c, d, F3, WK(41) ); W_PRECALC_32_79_1(57, W2, W3, W4, W5, W6, W7, W0, W1, Wtmp0);
  R( d, e, a, b, c, F3, WK(42) ); W_PRECALC_32_79_2(58, W2, W3, W4, W5, W6, W7, W0, W1, Wtmp0);
  R( c, d, e, a, b, F3, WK(43) ); W_PRECALC_32_79_3(59, W2, W3, W4, W5, W6, W7, W0, W1, Wtmp0);
  R( b, c, d, e, a, F3, WK(44) ); W_PRECALC_32_79_0(60, W1, W2, W3, W4, W5, W6, W7, W0, Wtmp0);
  R( a, b, c, d, e, F3, WK(45) ); W_PRECALC_32_79_1(61, W1, W2, W3, W4, W5, W6, W7, W0, Wtmp0);
  R( e, a, b, c, d, F3, WK(46) ); W_PRECALC_32_79_2(62, W1, W2, W3, W4, W5, W6, W7, W0, Wtmp0);
  R( d, e, a, b, c, F3, WK(47) ); W_PRECALC_32_79_3(63, W1, W2, W3, W4, W5, W6, W7, W0, Wtmp0);
  R( c, d, e, a, b, F3, WK(48) ); W_PRECALC_32_79_0(64, W0, W1, W2, W3, W4, W5, W6, W7, Wtmp0);
  R( b, c, d, e, a, F3, WK(49) ); W_PRECALC_32_79_1(65, W0, W1, W2, W3, W4, W5, W6, W7, Wtmp0);
  R( a, b, c, d, e, F3, WK(50) ); W_PRECALC_32_79_2(66, W0, W1, W2, W3, W4, W5, W6, W7, Wtmp0);
  R( e, a, b, c, d, F3, WK(51) ); W_PRECALC_32_79_3(67, W0, W1, W2, W3, W4, W5, W6, W7, Wtmp0);
  R( d, e, a, b, c, F3, WK(52) ); W_PRECALC_32_79_0(68, W7, W0, W1, W2, W3, W4, W5, W6, Wtmp0);
  R( c, d, e, a, b, F3, WK(53) ); W_PRECALC_32_79_1(69, W7, W0, W1, W2, W3, W4, W5, W6, Wtmp0);
  R( b, c, d, e, a, F3, WK(54) ); W_PRECALC_32_79_2(70, W7, W0, W1, W2, W3, W4, W5, W6, Wtmp0);
  R( a, b, c, d, e, F3, WK(55) ); W_PRECALC_32_79_3(71, W7, W0, W1, W2, W3, W4, W5, W6, Wtmp0);
  R( e, a, b, c, d, F3, WK(56) ); W_PRECALC_32_79_0(72, W6, W7, W0, W1, W2, W3, W4, W5, Wtmp0);
  R( d, e, a, b, c, F3, WK(57) ); W_PRECALC_32_79_1(73, W6, W7, W0, W1, W2, W3, W4, W5, Wtmp0);
  R( c, d, e, a, b, F3, WK(58) ); W_PRECALC_32_79_2(74, W6, W7, W0, W1, W2, W3, W4, W5, Wtmp0);
  R( b, c, d, e, a, F3, WK(59) ); W_PRECALC_32_79_3(75, W6, W7, W0, W1, W2, W3, W4, W5, Wtmp0);
  R( a, b, c, d, e, F4, WK(60) ); W_PRECALC_32_79_0(76, W5, W6, W7, W0, W1, W2, W3, W4, Wtmp0);
  R( e, a, b, c, d, F4, WK(61) ); W_PRECALC_32_79_1(77, W5, W6, W7, W0, W1, W2, W3, W4, Wtmp0);
  R( d, e, a, b, c, F4, WK(62) ); W_PRECALC_32_79_2(78, W5, W6, W7, W0, W1, W2, W3, W4, Wtmp0);
  R( c, d, e, a, b, F4, WK(63) ); W_PRECALC_32_79_3(79, W5, W6, W7, W0, W1, W2, W3, W4, Wtmp0);

#define CLEAR_REG(reg) __asm__ volatile ("pxor %%"reg", %%"reg";\n\t":::"cc");

  /* Transform 64-79 + Clear XMM registers. */
  R( b, c, d, e, a, F4, WK(64) ); CLEAR_REG(BSWAP_REG);
  R( a, b, c, d, e, F4, WK(65) ); CLEAR_REG(Wtmp0);
  R( e, a, b, c, d, F4, WK(66) ); CLEAR_REG(Wtmp1);
  R( d, e, a, b, c, F4, WK(67) ); CLEAR_REG(W0);
  R( c, d, e, a, b, F4, WK(68) ); CLEAR_REG(W1);
  R( b, c, d, e, a, F4, WK(69) ); CLEAR_REG(W2);
  R( a, b, c, d, e, F4, WK(70) ); CLEAR_REG(W3);
  R( e, a, b, c, d, F4, WK(71) ); CLEAR_REG(W4);
  R( d, e, a, b, c, F4, WK(72) ); CLEAR_REG(W5);
  R( c, d, e, a, b, F4, WK(73) ); CLEAR_REG(W6);
  R( b, c, d, e, a, F4, WK(74) ); CLEAR_REG(W7);
  R( a, b, c, d, e, F4, WK(75) );
  R( e, a, b, c, d, F4, WK(76) );
  R( d, e, a, b, c, F4, WK(77) );
  R( c, d, e, a, b, F4, WK(78) );
  R( b, c, d, e, a, F4, WK(79) );

  /* Update the chaining variables. */
  state->h0 += a;
  state->h1 += b;
  state->h2 += c;
  state->h3 += d;
  state->h4 += e;

  return /* burn_stack */ 84+15;
}

#endif
#endif
