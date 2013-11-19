/* cipher-gcm.c  - Generic Galois Counter Mode implementation
 * Copyright (C) 2013 Dmitry Eremin-Solenikov
 * Copyright © 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "ath.h"
#include "bufhelp.h"
#include "./cipher-internal.h"

#ifdef GCM_USE_TABLES
static const u16 gcmR[256] = {
  0x0000, 0x01c2, 0x0384, 0x0246, 0x0708, 0x06ca, 0x048c, 0x054e,
  0x0e10, 0x0fd2, 0x0d94, 0x0c56, 0x0918, 0x08da, 0x0a9c, 0x0b5e,
  0x1c20, 0x1de2, 0x1fa4, 0x1e66, 0x1b28, 0x1aea, 0x18ac, 0x196e,
  0x1230, 0x13f2, 0x11b4, 0x1076, 0x1538, 0x14fa, 0x16bc, 0x177e,
  0x3840, 0x3982, 0x3bc4, 0x3a06, 0x3f48, 0x3e8a, 0x3ccc, 0x3d0e,
  0x3650, 0x3792, 0x35d4, 0x3416, 0x3158, 0x309a, 0x32dc, 0x331e,
  0x2460, 0x25a2, 0x27e4, 0x2626, 0x2368, 0x22aa, 0x20ec, 0x212e,
  0x2a70, 0x2bb2, 0x29f4, 0x2836, 0x2d78, 0x2cba, 0x2efc, 0x2f3e,
  0x7080, 0x7142, 0x7304, 0x72c6, 0x7788, 0x764a, 0x740c, 0x75ce,
  0x7e90, 0x7f52, 0x7d14, 0x7cd6, 0x7998, 0x785a, 0x7a1c, 0x7bde,
  0x6ca0, 0x6d62, 0x6f24, 0x6ee6, 0x6ba8, 0x6a6a, 0x682c, 0x69ee,
  0x62b0, 0x6372, 0x6134, 0x60f6, 0x65b8, 0x647a, 0x663c, 0x67fe,
  0x48c0, 0x4902, 0x4b44, 0x4a86, 0x4fc8, 0x4e0a, 0x4c4c, 0x4d8e,
  0x46d0, 0x4712, 0x4554, 0x4496, 0x41d8, 0x401a, 0x425c, 0x439e,
  0x54e0, 0x5522, 0x5764, 0x56a6, 0x53e8, 0x522a, 0x506c, 0x51ae,
  0x5af0, 0x5b32, 0x5974, 0x58b6, 0x5df8, 0x5c3a, 0x5e7c, 0x5fbe,
  0xe100, 0xe0c2, 0xe284, 0xe346, 0xe608, 0xe7ca, 0xe58c, 0xe44e,
  0xef10, 0xeed2, 0xec94, 0xed56, 0xe818, 0xe9da, 0xeb9c, 0xea5e,
  0xfd20, 0xfce2, 0xfea4, 0xff66, 0xfa28, 0xfbea, 0xf9ac, 0xf86e,
  0xf330, 0xf2f2, 0xf0b4, 0xf176, 0xf438, 0xf5fa, 0xf7bc, 0xf67e,
  0xd940, 0xd882, 0xdac4, 0xdb06, 0xde48, 0xdf8a, 0xddcc, 0xdc0e,
  0xd750, 0xd692, 0xd4d4, 0xd516, 0xd058, 0xd19a, 0xd3dc, 0xd21e,
  0xc560, 0xc4a2, 0xc6e4, 0xc726, 0xc268, 0xc3aa, 0xc1ec, 0xc02e,
  0xcb70, 0xcab2, 0xc8f4, 0xc936, 0xcc78, 0xcdba, 0xcffc, 0xce3e,
  0x9180, 0x9042, 0x9204, 0x93c6, 0x9688, 0x974a, 0x950c, 0x94ce,
  0x9f90, 0x9e52, 0x9c14, 0x9dd6, 0x9898, 0x995a, 0x9b1c, 0x9ade,
  0x8da0, 0x8c62, 0x8e24, 0x8fe6, 0x8aa8, 0x8b6a, 0x892c, 0x88ee,
  0x83b0, 0x8272, 0x8034, 0x81f6, 0x84b8, 0x857a, 0x873c, 0x86fe,
  0xa9c0, 0xa802, 0xaa44, 0xab86, 0xaec8, 0xaf0a, 0xad4c, 0xac8e,
  0xa7d0, 0xa612, 0xa454, 0xa596, 0xa0d8, 0xa11a, 0xa35c, 0xa29e,
  0xb5e0, 0xb422, 0xb664, 0xb7a6, 0xb2e8, 0xb32a, 0xb16c, 0xb0ae,
  0xbbf0, 0xba32, 0xb874, 0xb9b6, 0xbcf8, 0xbd3a, 0xbf7c, 0xbebe,
};

#ifdef GCM_TABLES_USE_U64
static void
bshift (u64 * b0, u64 * b1)
{
  u64 t[2], mask;

  t[0] = *b0;
  t[1] = *b1;
  mask = t[1] & 1 ? 0xe1 : 0;
  mask <<= 56;

  *b1 = (t[1] >> 1) ^ (t[0] << 63);
  *b0 = (t[0] >> 1) ^ mask;
}

static void
do_fillM (unsigned char *h, u64 *M)
{
  int i, j;

  M[0 + 0] = 0;
  M[0 + 16] = 0;

  M[8 + 0] = buf_get_be64 (h + 0);
  M[8 + 16] = buf_get_be64 (h + 8);

  for (i = 4; i > 0; i /= 2)
    {
      M[i + 0] = M[2 * i + 0];
      M[i + 16] = M[2 * i + 16];

      bshift (&M[i], &M[i + 16]);
    }

  for (i = 2; i < 16; i *= 2)
    for (j = 1; j < i; j++)
      {
        M[(i + j) + 0] = M[i + 0] ^ M[j + 0];
        M[(i + j) + 16] = M[i + 16] ^ M[j + 16];
      }
}

static void
do_ghash (unsigned char *result, const unsigned char *buf, const u64 * gcmM)
{
  u64 V[2];
  u64 tmp[2];
  const u64 *M;
  u64 T;
  u32 A;
  int i;

  buf_xor (V, result, buf, 16);
  V[0] = be_bswap64 (V[0]);
  V[1] = be_bswap64 (V[1]);

  /* First round can be manually tweaked based on fact that 'tmp' is zero. */
  i = 15;

  M = &gcmM[(V[1] & 0xf)];
  V[1] >>= 4;
  tmp[0] = (M[0] >> 4) ^ ((u64) gcmR[(M[16] & 0xf) << 4] << 48);
  tmp[1] = (M[16] >> 4) ^ (M[0] << 60);
  tmp[0] ^= gcmM[(V[1] & 0xf) + 0];
  tmp[1] ^= gcmM[(V[1] & 0xf) + 16];
  V[1] >>= 4;

  --i;
  while (1)
    {
      M = &gcmM[(V[1] & 0xf)];
      V[1] >>= 4;

      A = tmp[1] & 0xff;
      T = tmp[0];
      tmp[0] = (T >> 8) ^ ((u64) gcmR[A] << 48) ^ gcmM[(V[1] & 0xf) + 0];
      tmp[1] = (T << 56) ^ (tmp[1] >> 8) ^ gcmM[(V[1] & 0xf) + 16];

      tmp[0] ^= (M[0] >> 4) ^ ((u64) gcmR[(M[16] & 0xf) << 4] << 48);
      tmp[1] ^= (M[16] >> 4) ^ (M[0] << 60);

      if (i == 0)
        break;
      else if (i == 8)
        V[1] = V[0];
      else
        V[1] >>= 4;
      --i;
    }

  buf_put_be64 (result + 0, tmp[0]);
  buf_put_be64 (result + 8, tmp[1]);
}

#else

static void
bshift (u32 * M, int i)
{
  u32 t[4], mask;

  t[0] = M[i * 4 + 0];
  t[1] = M[i * 4 + 1];
  t[2] = M[i * 4 + 2];
  t[3] = M[i * 4 + 3];
  mask = t[3] & 1 ? 0xe1 : 0;

  M[i * 4 + 3] = (t[3] >> 1) ^ (t[2] << 31);
  M[i * 4 + 2] = (t[2] >> 1) ^ (t[1] << 31);
  M[i * 4 + 1] = (t[1] >> 1) ^ (t[0] << 31);
  M[i * 4 + 0] = (t[0] >> 1) ^ (mask << 24);
}

static void
do_fillM (unsigned char *h, u32 *M)
{
  int i, j;

  M[0 * 4 + 0] = 0;
  M[0 * 4 + 1] = 0;
  M[0 * 4 + 2] = 0;
  M[0 * 4 + 3] = 0;

  M[8 * 4 + 0] = buf_get_be32 (h + 0);
  M[8 * 4 + 1] = buf_get_be32 (h + 4);
  M[8 * 4 + 2] = buf_get_be32 (h + 8);
  M[8 * 4 + 3] = buf_get_be32 (h + 12);

  for (i = 4; i > 0; i /= 2)
    {
      M[i * 4 + 0] = M[2 * i * 4 + 0];
      M[i * 4 + 1] = M[2 * i * 4 + 1];
      M[i * 4 + 2] = M[2 * i * 4 + 2];
      M[i * 4 + 3] = M[2 * i * 4 + 3];

      bshift (M, i);
    }

  for (i = 2; i < 16; i *= 2)
    for (j = 1; j < i; j++)
      {
        M[(i + j) * 4 + 0] = M[i * 4 + 0] ^ M[j * 4 + 0];
        M[(i + j) * 4 + 1] = M[i * 4 + 1] ^ M[j * 4 + 1];
        M[(i + j) * 4 + 2] = M[i * 4 + 2] ^ M[j * 4 + 2];
        M[(i + j) * 4 + 3] = M[i * 4 + 3] ^ M[j * 4 + 3];
      }
}

static void
do_ghash (unsigned char *result, const unsigned char *buf, const u32 * gcmM)
{
  byte V[16];
  u32 tmp[4];
  u32 v;
  const u32 *M, *m;
  u32 T[3];
  int i;

  buf_xor (V, result, buf, 16); /* V is big-endian */

  /* First round can be manually tweaked based on fact that 'tmp' is zero. */
  i = 15;

  v = V[i];
  M = &gcmM[(v & 0xf) * 4];
  v = (v & 0xf0) >> 4;
  m = &gcmM[v * 4];
  v = V[--i];

  tmp[0] = (M[0] >> 4) ^ ((u64) gcmR[(M[3] << 4) & 0xf0] << 16) ^ m[0];
  tmp[1] = (M[1] >> 4) ^ (M[0] << 28) ^ m[1];
  tmp[2] = (M[2] >> 4) ^ (M[1] << 28) ^ m[2];
  tmp[3] = (M[3] >> 4) ^ (M[2] << 28) ^ m[3];

  while (1)
    {
      M = &gcmM[(v & 0xf) * 4];
      v = (v & 0xf0) >> 4;
      m = &gcmM[v * 4];

      T[0] = tmp[0];
      T[1] = tmp[1];
      T[2] = tmp[2];
      tmp[0] = (T[0] >> 8) ^ ((u32) gcmR[tmp[3] & 0xff] << 16) ^ m[0];
      tmp[1] = (T[0] << 24) ^ (tmp[1] >> 8) ^ m[1];
      tmp[2] = (T[1] << 24) ^ (tmp[2] >> 8) ^ m[2];
      tmp[3] = (T[2] << 24) ^ (tmp[3] >> 8) ^ m[3];

      tmp[0] ^= (M[0] >> 4) ^ ((u64) gcmR[(M[3] << 4) & 0xf0] << 16);
      tmp[1] ^= (M[1] >> 4) ^ (M[0] << 28);
      tmp[2] ^= (M[2] >> 4) ^ (M[1] << 28);
      tmp[3] ^= (M[3] >> 4) ^ (M[2] << 28);

      if (i == 0)
        break;

      v = V[--i];
    }

  buf_put_be32 (result + 0, tmp[0]);
  buf_put_be32 (result + 4, tmp[1]);
  buf_put_be32 (result + 8, tmp[2]);
  buf_put_be32 (result + 12, tmp[3]);
}
#endif /* !HAVE_U64_TYPEDEF || SIZEOF_UNSIGNED_LONG != 8 */

#define fillM(c, h) do_fillM (h, c->u_mode.gcm.gcm_table)
#define GHASH(c, result, buf) do_ghash (result, buf, c->u_mode.gcm.gcm_table)

#else

static unsigned long
bshift (unsigned long *b)
{
  unsigned long c;
  int i;
  c = b[3] & 1;
  for (i = 3; i > 0; i--)
    {
      b[i] = (b[i] >> 1) | (b[i - 1] << 31);
    }
  b[i] >>= 1;
  return c;
}

static void
do_ghash (unsigned char *hsub, unsigned char *result, const unsigned char *buf)
{
  unsigned long V[4];
  int i, j;
  byte *p;

#ifdef WORDS_BIGENDIAN
  p = result;
#else
  unsigned long T[4];

  buf_xor (V, result, buf, 16);
  for (i = 0; i < 4; i++)
    {
      V[i] = (V[i] & 0x00ff00ff) << 8 | (V[i] & 0xff00ff00) >> 8;
      V[i] = (V[i] & 0x0000ffff) << 16 | (V[i] & 0xffff0000) >> 16;
    }
  p = (byte *) T;
#endif

  memset (p, 0, 16);

  for (i = 0; i < 16; i++)
    {
      for (j = 0x80; j; j >>= 1)
        {
          if (hsub[i] & j)
            buf_xor (p, p, V, 16);
          if (bshift (V))
            V[0] ^= 0xe1000000;
        }
    }
#ifndef WORDS_BIGENDIAN
  for (i = 0, p = (byte *) T; i < 16; i += 4, p += 4)
    {
      result[i + 0] = p[3];
      result[i + 1] = p[2];
      result[i + 2] = p[1];
      result[i + 3] = p[0];
    }
#endif
}

#define fillM(c, h) do { } while (0)
#define GHASH(c, result, buf) do_ghash (c->u_iv.iv, result, buf)

#endif /* !GCM_USE_TABLES */


#ifdef GCM_USE_INTEL_PCLMUL
/*
 Intel PCLMUL ghash based on white paper:
  "Intel® Carry-Less Multiplication Instruction and its Usage for Computing the
   GCM Mode - Rev 2.01"; Shay Gueron, Michael E. Kounavis.
 */
static void
do_ghash_pclmul (gcry_cipher_hd_t c, byte *result, const byte *buf)
{
  static const unsigned char be_mask[16] __attribute__ ((aligned (16))) =
    { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

  asm volatile ("movdqu (%[result]), %%xmm1\n\t"
                "movdqu %[buf], %%xmm2\n\t"
                "movdqa %[hsub], %%xmm0\n\t"
                "pxor %%xmm2, %%xmm1\n\t" /* big endian */

                /* be => le */
                "pshufb %[be_mask], %%xmm1\n\t"

                /* gfmul, xmm0 has operator a and xmm1 has operator b. */
                "pshufd $78, %%xmm0, %%xmm2\n\t"
                "pshufd $78, %%xmm1, %%xmm4\n\t"
                "pxor %%xmm0, %%xmm2\n\t" /* xmm2 holds a0+a1 */
                "pxor %%xmm1, %%xmm4\n\t" /* xmm4 holds b0+b1 */

                "movdqa %%xmm0, %%xmm3\n\t"
                "pclmulqdq $0, %%xmm1, %%xmm3\n\t"  /* xmm3 holds a0*b0 */
                "movdqa %%xmm0, %%xmm6\n\t"
                "pclmulqdq $17, %%xmm1, %%xmm6\n\t" /* xmm6 holds a1*b1 */
                "movdqa %%xmm3, %%xmm5\n\t"
                "pclmulqdq $0, %%xmm2, %%xmm4\n\t"  /* xmm4 holds (a0+a1)*(b0+b1) */

                "pxor %%xmm6, %%xmm5\n\t" /* xmm5 holds a0*b0+a1*b1 */
                "pxor %%xmm5, %%xmm4\n\t" /* xmm4 holds a0*b0+a1*b1+(a0+a1)*(b0+b1) */
                "movdqa %%xmm4, %%xmm5\n\t"
                "psrldq $8, %%xmm4\n\t"
                "pslldq $8, %%xmm5\n\t"
                "pxor %%xmm5, %%xmm3\n\t"
                "pxor %%xmm4, %%xmm6\n\t" /* <xmm6:xmm3> holds the result of the
                                             carry-less multiplication of xmm0
                                             by xmm1 */

                /* shift the result by one bit position to the left cope for
                   the fact that bits are reversed */
                "movdqa %%xmm3, %%xmm7\n\t"
                "movdqa %%xmm6, %%xmm0\n\t"
                "pslld $1, %%xmm3\n\t"
                "pslld $1, %%xmm6\n\t"
                "psrld $31, %%xmm7\n\t"
                "psrld $31, %%xmm0\n\t"
                "movdqa %%xmm7, %%xmm1\n\t"
                "pslldq $4, %%xmm0\n\t"
                "pslldq $4, %%xmm7\n\t"
                "psrldq $12, %%xmm1\n\t"
                "por %%xmm7, %%xmm3\n\t"
                "por %%xmm0, %%xmm6\n\t"
                "por %%xmm1, %%xmm6\n\t"

                /* first phase of the reduction */
                "movdqa %%xmm3, %%xmm7\n\t"
                "movdqa %%xmm3, %%xmm0\n\t"
                "pslld $31, %%xmm7\n\t"  /* packed right shifting << 31 */
                "movdqa %%xmm3, %%xmm1\n\t"
                "pslld $30, %%xmm0\n\t"  /* packed right shifting shift << 30 */
                "pslld $25, %%xmm1\n\t"  /* packed right shifting shift << 25 */
                "pxor %%xmm0, %%xmm7\n\t" /* xor the shifted versions */
                "pxor %%xmm1, %%xmm7\n\t"
                "movdqa %%xmm7, %%xmm0\n\t"
                "pslldq $12, %%xmm7\n\t"
                "psrldq $4, %%xmm0\n\t"
                "pxor %%xmm7, %%xmm3\n\t" /* first phase of the reduction
                                             complete */

                /* second phase of the reduction */
                "movdqa %%xmm3, %%xmm2\n\t"
                "movdqa %%xmm3, %%xmm4\n\t"
                "psrld $1, %%xmm2\n\t"    /* packed left shifting >> 1 */
                "movdqa %%xmm3, %%xmm5\n\t"
                "psrld $2, %%xmm4\n\t"    /* packed left shifting >> 2 */
                "psrld $7, %%xmm5\n\t"    /* packed left shifting >> 7 */
                "pxor %%xmm4, %%xmm2\n\t" /* xor the shifted versions */
                "pxor %%xmm5, %%xmm2\n\t"
                "pxor %%xmm0, %%xmm2\n\t"
                "pxor %%xmm2, %%xmm3\n\t"
                "pxor %%xmm3, %%xmm6\n\t" /* the result is in xmm6 */

                /* le => be */
                "pshufb %[be_mask], %%xmm6\n\t"

                "movdqu %%xmm6, (%[result])\n\t" /* store the result */
                :
                : [result] "r" (result), [buf] "m" (*buf),
                  [hsub] "m" (*c->u_iv.iv), [be_mask] "m" (*be_mask)
                : "memory" );
}

#endif /*GCM_USE_INTEL_PCLMUL*/


static void
ghash (gcry_cipher_hd_t c, unsigned char *result, const unsigned char *buf)
{
  if (0)
    ;
#ifdef GCM_USE_INTEL_PCLMUL
  else if (c->u_mode.gcm.use_intel_pclmul)
    {
      /* TODO: Loop structure, use bit-reflection and add faster bulk
               processing (parallel four blocks). */
      do_ghash_pclmul (c, result, buf);

      /* Clear used registers. */
      asm volatile( "pxor %%xmm0, %%xmm0\n\t"
                    "pxor %%xmm1, %%xmm1\n\t"
                    "pxor %%xmm2, %%xmm2\n\t"
                    "pxor %%xmm3, %%xmm3\n\t"
                    "pxor %%xmm4, %%xmm4\n\t"
                    "pxor %%xmm5, %%xmm5\n\t"
                    "pxor %%xmm6, %%xmm6\n\t"
                    "pxor %%xmm7, %%xmm7\n\t"
                    ::: "cc" );
    }
#endif
  else
    GHASH (c, result, buf);
}

static void
setupM (gcry_cipher_hd_t c, byte *h)
{
  if (0)
    ;
#ifdef GCM_USE_INTEL_PCLMUL
  else if (_gcry_get_hw_features () & HWF_INTEL_PCLMUL)
    {
      u64 tmp[2];

      c->u_mode.gcm.use_intel_pclmul = 1;

      /* Swap endianness of hsub. */
      tmp[0] = buf_get_be64(c->u_iv.iv + 8);
      tmp[1] = buf_get_be64(c->u_iv.iv + 0);
      buf_cpy (c->u_iv.iv, tmp, 16);
    }
#endif
  else
    fillM (c, h);
}


gcry_err_code_t
_gcry_cipher_gcm_encrypt (gcry_cipher_hd_t c,
                          byte * outbuf, unsigned int outbuflen,
                          const byte * inbuf, unsigned int inbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->spec->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (blocksize >= 0x20)
    return GPG_ERR_CIPHER_ALGO;
  if (blocksize != 0x10)
    return GPG_ERR_CIPHER_ALGO;
  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.iv)
    {
      memset (tmp, 0, 16);
      _gcry_cipher_gcm_setiv (c, tmp, 16);
    }

  while (inbuflen)
    {
      for (i = blocksize; i > blocksize - 4; i--)
        {
          c->u_ctr.ctr[i - 1]++;
          if (c->u_ctr.ctr[i - 1] != 0)
            break;
        }

      n = blocksize < inbuflen ? blocksize : inbuflen;

      i = blocksize - 1;
      c->length[i] += n * 8;
      for (; c->length[i] == 0 && i > blocksize / 2; i--)
        c->length[i - 1]++;

      c->spec->encrypt (&c->context.c, tmp, c->u_ctr.ctr);
      if (n < blocksize)
        {
          buf_xor_2dst (outbuf, tmp, inbuf, n);
          memset (tmp + n, 0, blocksize - n);
          ghash (c, c->u_mode.gcm.u_tag.tag, tmp);
        }
      else
        {
          buf_xor (outbuf, tmp, inbuf, n);
          ghash (c, c->u_mode.gcm.u_tag.tag, outbuf);
        }

      inbuflen -= n;
      outbuf += n;
      inbuf += n;
    }

  return 0;
}

gcry_err_code_t
_gcry_cipher_gcm_decrypt (gcry_cipher_hd_t c,
                          byte * outbuf, unsigned int outbuflen,
                          const byte * inbuf, unsigned int inbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->spec->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (blocksize >= 0x20)
    return GPG_ERR_CIPHER_ALGO;
  if (blocksize != 0x10)
    return GPG_ERR_CIPHER_ALGO;
  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.iv)
    {
      memset (tmp, 0, 16);
      _gcry_cipher_gcm_setiv (c, tmp, 16);
    }

  while (inbuflen)
    {
      for (i = blocksize; i > blocksize - 4; i--)
        {
          c->u_ctr.ctr[i - 1]++;
          if (c->u_ctr.ctr[i - 1] != 0)
            break;
        }

      n = blocksize < inbuflen ? blocksize : inbuflen;
      if (n < blocksize)
        {
          memcpy (tmp, inbuf, n);
          memset (tmp + n, 0, blocksize - n);
          ghash (c, c->u_mode.gcm.u_tag.tag, tmp);
        }
      else
        {
          ghash (c, c->u_mode.gcm.u_tag.tag, inbuf);
        }

      i = blocksize - 1;
      c->length[i] += n * 8;
      for (; c->length[i] == 0 && i > blocksize / 2; i--)
        c->length[i - 1]++;

      c->spec->encrypt (&c->context.c, tmp, c->u_ctr.ctr);

      buf_xor (outbuf, inbuf, tmp, n);

      inbuflen -= n;
      outbuf += n;
      inbuf += n;
    }

  return 0;
}

gcry_err_code_t
_gcry_cipher_gcm_authenticate (gcry_cipher_hd_t c,
                               const byte * aadbuf, unsigned int aadbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->spec->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (!c->marks.iv)
    {
      memset (tmp, 0, 16);
      _gcry_cipher_gcm_setiv (c, tmp, 16);
    }

  n = aadbuflen;
  i = blocksize / 2;
  c->length[i - 1] = (n % 0x20) * 8;
  n /= 0x20;
  for (; n && i > 0; i--, n >>= 8)
    c->length[i - 1] = n & 0xff;

  while (aadbuflen >= blocksize)
    {
      ghash (c, c->u_mode.gcm.u_tag.tag, aadbuf);

      aadbuflen -= blocksize;
      aadbuf += blocksize;
    }

  if (aadbuflen != 0)
    {
      memcpy (tmp, aadbuf, aadbuflen);
      memset (tmp + aadbuflen, 0, blocksize - aadbuflen);

      ghash (c, c->u_mode.gcm.u_tag.tag, tmp);
    }

  return 0;
}

void
_gcry_cipher_gcm_setiv (gcry_cipher_hd_t c,
                        const byte * iv, unsigned int ivlen)
{
  memset (c->length, 0, 16);
  memset (c->u_mode.gcm.u_tag.tag, 0, 16);
  c->spec->encrypt (&c->context.c, c->u_iv.iv, c->u_mode.gcm.u_tag.tag);

  setupM (c, c->u_iv.iv);

  if (ivlen != 16 - 4)
    {
      unsigned char tmp[MAX_BLOCKSIZE];
      unsigned n;
      memset (c->u_ctr.ctr, 0, 16);
      for (n = ivlen; n >= 16; n -= 16, iv += 16)
        ghash (c, c->u_ctr.ctr, iv);
      if (n != 0)
        {
          memcpy (tmp, iv, n);
          memset (tmp + n, 0, 16 - n);
          ghash (c, c->u_ctr.ctr, tmp);
        }
      memset (tmp, 0, 16);
      n = 16;
      tmp[n - 1] = (ivlen % 0x20) * 8;
      ivlen /= 0x20;
      n--;
      for (; n > 0; n--, ivlen >>= 8)
        tmp[n - 1] = ivlen & 0xff;
      ghash (c, c->u_ctr.ctr, tmp);
    }
  else
    {
      memcpy (c->u_ctr.ctr, iv, ivlen);
      c->u_ctr.ctr[12] = c->u_ctr.ctr[13] = c->u_ctr.ctr[14] = 0;
      c->u_ctr.ctr[15] = 1;
    }

  c->spec->encrypt (&c->context.c, c->lastiv, c->u_ctr.ctr);
  c->marks.iv = 1;

}

static gcry_err_code_t
_gcry_cipher_gcm_tag (gcry_cipher_hd_t c,
                      byte * outbuf, unsigned int outbuflen, int check)
{
  if (outbuflen < 16)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.tag)
    {
      ghash (c, c->u_mode.gcm.u_tag.tag, c->length);
      buf_xor (c->u_mode.gcm.u_tag.tag, c->lastiv, c->u_mode.gcm.u_tag.tag, 16);
      c->marks.tag = 1;
    }

  if (!check)
    {
      memcpy (outbuf, c->u_mode.gcm.u_tag.tag, outbuflen);
      return GPG_ERR_NO_ERROR;
    }
  else
    {
      return buf_eq_const(outbuf, c->u_mode.gcm.u_tag.tag, outbuflen) ?
               GPG_ERR_NO_ERROR : GPG_ERR_CHECKSUM;
    }

  return 0;
}

gcry_err_code_t
_gcry_cipher_gcm_get_tag (gcry_cipher_hd_t c, unsigned char *outtag,
                          size_t taglen)
{
  return _gcry_cipher_gcm_tag (c, outtag, taglen, 0);
}

gcry_err_code_t
_gcry_cipher_gcm_check_tag (gcry_cipher_hd_t c, const unsigned char *intag,
                            size_t taglen)
{
  return _gcry_cipher_gcm_tag (c, (unsigned char *) intag, taglen, 1);
}
