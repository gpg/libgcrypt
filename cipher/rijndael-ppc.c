/* Rijndael (AES) for GnuPG - PowerPC Vector Crypto AES
 * Copyright (C) 2019 Shawn Landden <shawn@git.icu>
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
 *
 * Alternatively, this code may be used in OpenSSL from The OpenSSL Project,
 * and Cryptogams by Andy Polyakov, and if made part of a release of either
 * or both projects, is thereafter dual-licensed under the license said project
 * is released under.
 */

#include <config.h>

/* PPC AES extensions */
#include <altivec.h>
#include "rijndael-internal.h"
#include "cipher-internal.h"

typedef vector unsigned char block;
static const vector unsigned char backwards =
  { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

#ifdef __LITTLE_ENDIAN__
#define swap_if_le(a) \
  vec_perm(a, a, backwards)
#elif __BIG_ENDIAN__
#define swap_if_le(a) (a)
#else
#error "What endianness?"
#endif

/* Passes in AltiVec registers (big-endian)
 * sadly compilers don't know how to unroll outer loops into
 * inner loops with more registers on static functions,
 * so that this can be properly optimized for OOO multi-issue
 * without having to hand-unroll.
 */
static block _gcry_aes_ppc8_encrypt_altivec (const RIJNDAEL_context *ctx,
                                             block a)
{
  int r;
  int rounds = ctx->rounds;
  block *rk = (block*)ctx->keyschenc;

  a = rk[0] ^ a;
  for (r = 1;r < rounds;r++)
    {
      __asm__ volatile ("vcipher %0, %0, %1\n\t"
        :"+v" (a)
        :"v" (rk[r])
      );
    }
  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
    :"+v" (a)
    :"v" (rk[r])
  );
  return a;
}


static block _gcry_aes_ppc8_decrypt_altivec (const RIJNDAEL_context *ctx,
                                             block a)
{
  int r;
  int rounds = ctx->rounds;
  block *rk = (block*)ctx->keyschdec;

  a = rk[0] ^ a;
  for (r = 1;r < rounds;r++)
    {
      __asm__ volatile ("vncipher %0, %0, %1\n\t"
        :"+v" (a)
        :"v" (rk[r])
      );
    }
  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
    :"+v" (a)
    :"v" (rk[r])
  );
  return a;
}

unsigned int _gcry_aes_ppc8_encrypt (const RIJNDAEL_context *ctx,
				     unsigned char *b,
				     const unsigned char *a)
{
  uintptr_t zero = 0;
  block sa;

  if ((uintptr_t)a % 16 == 0)
    {
      sa = vec_ld (0, a);
    }
  else
    {
      block unalignedprev, unalignedcur;
      unalignedprev = vec_ld (0, a);
      unalignedcur = vec_ld (16, a);
      sa = vec_perm (unalignedprev, unalignedcur, vec_lvsl(0, a));
    }

  sa = swap_if_le(sa);
  sa = _gcry_aes_ppc8_encrypt_altivec(ctx, sa);

  __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
    :
    : "wa" (sa), "r" (zero), "r" ((uintptr_t)b));

  return 0; /* does not use stack */
}

unsigned int _gcry_aes_ppc8_decrypt (const RIJNDAEL_context *ctx,
				     unsigned char *b,
				     const unsigned char *a)
{
  uintptr_t zero = 0;
  block sa, unalignedprev, unalignedcur;

  if ((uintptr_t)a % 16 == 0)
    {
      sa = vec_ld(0, a);
    }
  else
    {
      unalignedprev = vec_ld (0, a);
      unalignedcur = vec_ld (16, a);
      sa = vec_perm (unalignedprev, unalignedcur, vec_lvsl(0, a));
    }

  sa = swap_if_le (sa);
  sa = _gcry_aes_ppc8_decrypt_altivec  (ctx, sa);

  if ((uintptr_t)b % 16 == 0)
    {
      vec_vsx_st(swap_if_le(sa), 0, b);
    }
  else
    {
      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
	:
	: "wa" (sa), "r" (zero), "r" ((uintptr_t)b));
    }
  return 0; /* does not use stack */
}

size_t _gcry_aes_ppc8_ocb_crypt (gcry_cipher_hd_t c, void *outbuf_arg,
                                            const void *inbuf_arg, size_t nblocks,
                                            int encrypt)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  block *in = (block*)inbuf;
  block *out = (block*)outbuf;
  uintptr_t zero = 0;
  int r;
  int rounds = ctx->rounds;

  if (encrypt)
    {
      const int unroll = 8;
      block unalignedprev, ctr, iv;

      if (((uintptr_t)inbuf % 16) != 0)
	{
	  unalignedprev = vec_ld(0, in++);
	}

      iv = vec_ld (0, (block*)&c->u_iv.iv);
      ctr = vec_ld (0, (block*)&c->u_ctr.ctr);

      for ( ;nblocks >= unroll; nblocks -= unroll)
	{
	  u64 i = c->u_mode.ocb.data_nblocks + 1;
	  block l0, l1, l2, l3, l4, l5, l6, l7;
	  block b0, b1, b2, b3, b4, b5, b6, b7;
	  block iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7;
	  const block *rk = (block*)&ctx->keyschenc;

	  c->u_mode.ocb.data_nblocks += unroll;

	  iv0 = iv;
	  if ((uintptr_t)inbuf % 16 == 0)
	    {
	      b0 = vec_ld (0, in++);
	      b1 = vec_ld (0, in++);
	      b2 = vec_ld (0, in++);
	      b3 = vec_ld (0, in++);
	      b4 = vec_ld (0, in++);
	      b5 = vec_ld (0, in++);
	      b6 = vec_ld (0, in++);
	      b7 = vec_ld (0, in++);
	    }
	  else
	    {
	      block unaligned0, unaligned1, unaligned2,
		unaligned3, unaligned4, unaligned5, unaligned6;
	      unaligned0 = vec_ld (0, in++);
	      unaligned1 = vec_ld (0, in++);
	      unaligned2 = vec_ld (0, in++);
	      unaligned3 = vec_ld (0, in++);
	      unaligned4 = vec_ld (0, in++);
	      unaligned5 = vec_ld (0, in++);
	      unaligned6 = vec_ld (0, in++);
	      b0 = vec_perm (unalignedprev, unaligned0, vec_lvsl (0, inbuf));
	      unalignedprev = vec_ld (0, in++);
	      b1 = vec_perm(unaligned0, unaligned1, vec_lvsl (0, inbuf));
	      b2 = vec_perm(unaligned1, unaligned2, vec_lvsl (0, inbuf));
	      b3 = vec_perm(unaligned2, unaligned3, vec_lvsl (0, inbuf));
	      b4 = vec_perm(unaligned3, unaligned4, vec_lvsl (0, inbuf));
	      b5 = vec_perm(unaligned4, unaligned5, vec_lvsl (0, inbuf));
	      b6 = vec_perm(unaligned5, unaligned6, vec_lvsl (0, inbuf));
	      b7 = vec_perm(unaligned6, unalignedprev, vec_lvsl (0, inbuf));
	    }

	  l0 = *(block*)ocb_get_l (c, i++);
	  l1 = *(block*)ocb_get_l (c, i++);
	  l2 = *(block*)ocb_get_l (c, i++);
	  l3 = *(block*)ocb_get_l (c, i++);
	  l4 = *(block*)ocb_get_l (c, i++);
	  l5 = *(block*)ocb_get_l (c, i++);
	  l6 = *(block*)ocb_get_l (c, i++);
	  l7 = *(block*)ocb_get_l (c, i++);

	  ctr ^= b0 ^ b1 ^ b2 ^ b3 ^ b4 ^ b5 ^ b6 ^ b7;

	  iv0 ^= l0;
	  b0 ^= iv0;
	  iv1 = iv0 ^ l1;
	  b1 ^= iv1;
	  iv2 = iv1 ^ l2;
	  b2 ^= iv2;
	  iv3 = iv2 ^ l3;
	  b3 ^= iv3;
	  iv4 = iv3 ^ l4;
	  b4 ^= iv4;
	  iv5 = iv4 ^ l5;
	  b5 ^= iv5;
	  iv6 = iv5 ^ l6;
	  b6 ^= iv6;
	  iv7 = iv6 ^ l7;
	  b7 ^= iv7;

	  b0 = swap_if_le (b0);
	  b1 = swap_if_le (b1);
	  b2 = swap_if_le (b2);
	  b3 = swap_if_le (b3);
	  b4 = swap_if_le (b4);
	  b5 = swap_if_le (b5);
	  b6 = swap_if_le (b6);
	  b7 = swap_if_le (b7);

	  b0 ^= rk[0];
	  b1 ^= rk[0];
	  b2 ^= rk[0];
	  b3 ^= rk[0];
	  b4 ^= rk[0];
	  b5 ^= rk[0];
	  b6 ^= rk[0];
	  b7 ^= rk[0];

	  for (r = 1;r < rounds;r++)
	    {
	      __asm__ volatile ("vcipher %0, %0, %1\n\t"
		:"+v" (b0)
		:"v" (rk[r]));
	      __asm__ volatile ("vcipher %0, %0, %1\n\t"
		:"+v" (b1)
		:"v" (rk[r]));
	      __asm__ volatile ("vcipher %0, %0, %1\n\t"
		:"+v" (b2)
		:"v" (rk[r]));
	      __asm__ volatile ("vcipher %0, %0, %1\n\t"
		:"+v" (b3)
		:"v" (rk[r]));
	      __asm__ volatile ("vcipher %0, %0, %1\n\t"
		:"+v" (b4)
		:"v" (rk[r]));
	      __asm__ volatile ("vcipher %0, %0, %1\n\t"
		:"+v" (b5)
		:"v" (rk[r]));
	      __asm__ volatile ("vcipher %0, %0, %1\n\t"
		:"+v" (b6)
		:"v" (rk[r]));
	      __asm__ volatile ("vcipher %0, %0, %1\n\t"
		:"+v" (b7)
		:"v" (rk[r]));
	    }
	  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
	    :"+v" (b0)
	    :"v" (rk[r]));
	  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
	    :"+v" (b1)
	    :"v" (rk[r]));
	  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
	    :"+v" (b2)
	    :"v" (rk[r]));
	  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
	    :"+v" (b3)
	    :"v" (rk[r]));
	  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
	    :"+v" (b4)
	    :"v" (rk[r]));
	  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
	    :"+v" (b5)
	    :"v" (rk[r]));
	  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
	    :"+v" (b6)
	    :"v" (rk[r]));
	  __asm__ volatile ("vcipherlast %0, %0, %1\n\t"
	    :"+v" (b7)
	    :"v" (rk[r]));

	  iv = iv7;

	  /* The unaligned store stxvb16x writes big-endian,
	     so in the unaligned case we swap the iv instead of the bytes */
	  if ((uintptr_t)outbuf % 16 == 0)
	    {
	      vec_vsx_st (swap_if_le (b0) ^ iv0, 0, out++);
	      vec_vsx_st (swap_if_le (b1) ^ iv1, 0, out++);
	      vec_vsx_st (swap_if_le (b2) ^ iv2, 0, out++);
	      vec_vsx_st (swap_if_le (b3) ^ iv3, 0, out++);
	      vec_vsx_st (swap_if_le (b4) ^ iv4, 0, out++);
	      vec_vsx_st (swap_if_le (b5) ^ iv5, 0, out++);
	      vec_vsx_st (swap_if_le (b6) ^ iv6, 0, out++);
	      vec_vsx_st (swap_if_le (b7) ^ iv7, 0, out++);
	    }
	  else
	    {
	      b0 ^= swap_if_le (iv0);
	      b1 ^= swap_if_le (iv1);
	      b2 ^= swap_if_le (iv2);
	      b3 ^= swap_if_le (iv3);
	      b4 ^= swap_if_le (iv4);
	      b5 ^= swap_if_le (iv5);
	      b6 ^= swap_if_le (iv6);
	      b7 ^= swap_if_le (iv7);
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b0), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b1), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b2), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b3), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b4), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b5), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b6), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b7), "r" (zero), "r" ((uintptr_t)(out++)));
	    }
	}

      for ( ;nblocks; nblocks-- )
	{
	  block b;
	  u64 i = ++c->u_mode.ocb.data_nblocks;
	  const block l = *(block*)ocb_get_l (c, i);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  iv ^= l;
	  if ((uintptr_t)in % 16 == 0)
	    {
	      b = vec_ld (0, in++);
	    }
	  else
	    {
	      block unalignedprevprev;
	      unalignedprevprev = unalignedprev;
	      unalignedprev = vec_ld (0, in++);
	      b = vec_perm (unalignedprevprev, unalignedprev, vec_lvsl (0, inbuf));
	    }

	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr ^= b;
	  /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
	  b ^= iv;
	  b = swap_if_le (b);
	  b = _gcry_aes_ppc8_encrypt_altivec (ctx, b);
	  if ((uintptr_t)out % 16 == 0)
	    {
	      vec_vsx_st (swap_if_le (b) ^ iv, 0, out++);
	    }
	  else
	    {
	      b ^= swap_if_le (iv);
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
	        :
	        : "wa" (b), "r" (zero), "r" ((uintptr_t)out++));
	    }
	}

      /* We want to store iv and ctr big-endian and the unaligned
         store stxvb16x stores them little endian, so we have to swap them. */
      iv = swap_if_le (iv);
      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
	:: "wa" (iv), "r" (zero), "r" ((uintptr_t)&c->u_iv.iv));
      ctr = swap_if_le (ctr);
      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
	:: "wa" (ctr), "r" (zero), "r" ((uintptr_t)&c->u_ctr.ctr));
    }
  else
    {
      const int unroll = 8;
      block unalignedprev, ctr, iv;
      if (((uintptr_t)inbuf % 16) != 0)
	{
	  unalignedprev = vec_ld (0, in++);
	}

      iv = vec_ld (0, (block*)&c->u_iv.iv);
      ctr = vec_ld (0, (block*)&c->u_ctr.ctr);

      for ( ;nblocks >= unroll; nblocks -= unroll)
	{
	  u64 i = c->u_mode.ocb.data_nblocks + 1;
	  block l0, l1, l2, l3, l4, l5, l6, l7;
	  block b0, b1, b2, b3, b4, b5, b6, b7;
	  block iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7;
	  const block *rk = (block*)&ctx->keyschdec;

	  c->u_mode.ocb.data_nblocks += unroll;

	  iv0 = iv;
	  if ((uintptr_t)inbuf % 16 == 0)
	    {
	      b0 = vec_ld (0, in++);
	      b1 = vec_ld (0, in++);
	      b2 = vec_ld (0, in++);
	      b3 = vec_ld (0, in++);
	      b4 = vec_ld (0, in++);
	      b5 = vec_ld (0, in++);
	      b6 = vec_ld (0, in++);
	      b7 = vec_ld (0, in++);
	    }
	  else
	    {
	      block unaligned0, unaligned1, unaligned2,
		unaligned3, unaligned4, unaligned5, unaligned6;
	      unaligned0 = vec_ld (0, in++);
	      unaligned1 = vec_ld (0, in++);
	      unaligned2 = vec_ld (0, in++);
	      unaligned3 = vec_ld (0, in++);
	      unaligned4 = vec_ld (0, in++);
	      unaligned5 = vec_ld (0, in++);
	      unaligned6 = vec_ld (0, in++);
	      b0 = vec_perm (unalignedprev, unaligned0, vec_lvsl (0, inbuf));
	      unalignedprev = vec_ld (0, in++);
	      b1 = vec_perm (unaligned0, unaligned1, vec_lvsl (0, inbuf));
	      b2 = vec_perm (unaligned1, unaligned2, vec_lvsl (0, inbuf));
	      b3 = vec_perm (unaligned2, unaligned3, vec_lvsl (0, inbuf));
	      b4 = vec_perm (unaligned3, unaligned4, vec_lvsl (0, inbuf));
	      b5 = vec_perm (unaligned4, unaligned5, vec_lvsl (0, inbuf));
	      b6 = vec_perm (unaligned5, unaligned6, vec_lvsl (0, inbuf));
	      b7 = vec_perm (unaligned6, unalignedprev, vec_lvsl (0, inbuf));
	    }

	  l0 = *(block*)ocb_get_l (c, i++);
	  l1 = *(block*)ocb_get_l (c, i++);
	  l2 = *(block*)ocb_get_l (c, i++);
	  l3 = *(block*)ocb_get_l (c, i++);
	  l4 = *(block*)ocb_get_l (c, i++);
	  l5 = *(block*)ocb_get_l (c, i++);
	  l6 = *(block*)ocb_get_l (c, i++);
	  l7 = *(block*)ocb_get_l (c, i++);

	  iv0 ^= l0;
	  b0 ^= iv0;
	  iv1 = iv0 ^ l1;
	  b1 ^= iv1;
	  iv2 = iv1 ^ l2;
	  b2 ^= iv2;
	  iv3 = iv2 ^ l3;
	  b3 ^= iv3;
	  iv4 = iv3 ^ l4;
	  b4 ^= iv4;
	  iv5 = iv4 ^ l5;
	  b5 ^= iv5;
	  iv6 = iv5 ^ l6;
	  b6 ^= iv6;
	  iv7 = iv6 ^ l7;
	  b7 ^= iv7;

	  b0 = swap_if_le (b0);
	  b1 = swap_if_le (b1);
	  b2 = swap_if_le (b2);
	  b3 = swap_if_le (b3);
	  b4 = swap_if_le (b4);
	  b5 = swap_if_le (b5);
	  b6 = swap_if_le (b6);
	  b7 = swap_if_le (b7);

	  b0 ^= rk[0];
	  b1 ^= rk[0];
	  b2 ^= rk[0];
	  b3 ^= rk[0];
	  b4 ^= rk[0];
	  b5 ^= rk[0];
	  b6 ^= rk[0];
	  b7 ^= rk[0];

	  for (r = 1;r < rounds;r++)
	    {
	      __asm__ volatile ("vncipher %0, %0, %1\n\t"
		:"+v" (b0)
		:"v" (rk[r]));
	      __asm__ volatile ("vncipher %0, %0, %1\n\t"
		:"+v" (b1)
		:"v" (rk[r]));
	      __asm__ volatile ("vncipher %0, %0, %1\n\t"
		:"+v" (b2)
		:"v" (rk[r]));
	      __asm__ volatile ("vncipher %0, %0, %1\n\t"
		:"+v" (b3)
		:"v" (rk[r]));
	      __asm__ volatile ("vncipher %0, %0, %1\n\t"
		:"+v" (b4)
		:"v" (rk[r]));
	      __asm__ volatile ("vncipher %0, %0, %1\n\t"
		:"+v" (b5)
		:"v" (rk[r]));
	      __asm__ volatile ("vncipher %0, %0, %1\n\t"
		:"+v" (b6)
		:"v" (rk[r]));
	      __asm__ volatile ("vncipher %0, %0, %1\n\t"
		:"+v" (b7)
		:"v" (rk[r]));
	    }
	  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
	    :"+v" (b0)
	    :"v" (rk[r]));
	  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
	    :"+v" (b1)
	    :"v" (rk[r]));
	  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
	    :"+v" (b2)
	    :"v" (rk[r]));
	  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
	    :"+v" (b3)
	    :"v" (rk[r]));
	  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
	    :"+v" (b4)
	    :"v" (rk[r]));
	  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
	    :"+v" (b5)
	    :"v" (rk[r]));
	  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
	    :"+v" (b6)
	    :"v" (rk[r]));
	  __asm__ volatile ("vncipherlast %0, %0, %1\n\t"
	    :"+v" (b7)
	    :"v" (rk[r]));

	  iv = iv7;

	  b0 = swap_if_le (b0) ^ iv0;
	  b1 = swap_if_le (b1) ^ iv1;
	  b2 = swap_if_le (b2) ^ iv2;
	  b3 = swap_if_le (b3) ^ iv3;
	  b4 = swap_if_le (b4) ^ iv4;
	  b5 = swap_if_le (b5) ^ iv5;
	  b6 = swap_if_le (b6) ^ iv6;
	  b7 = swap_if_le (b7) ^ iv7;

	  ctr ^= b0 ^ b1 ^ b2 ^ b3 ^ b4 ^ b5 ^ b6 ^ b7;

	  /* The unaligned store stxvb16x writes big-endian */
	  if ((uintptr_t)outbuf % 16 == 0)
	    {
	      vec_vsx_st (b0, 0, out++);
	      vec_vsx_st (b1, 0, out++);
	      vec_vsx_st (b2, 0, out++);
	      vec_vsx_st (b3, 0, out++);
	      vec_vsx_st (b4, 0, out++);
	      vec_vsx_st (b5, 0, out++);
	      vec_vsx_st (b6, 0, out++);
	      vec_vsx_st (b7, 0, out++);
	    }
	  else
	    {
	      b0 = swap_if_le (b0);
	      b1 = swap_if_le (b1);
	      b2 = swap_if_le (b2);
	      b3 = swap_if_le (b3);
	      b4 = swap_if_le (b4);
	      b5 = swap_if_le (b5);
	      b6 = swap_if_le (b6);
	      b7 = swap_if_le (b7);
	      __asm__ ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b0), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b1), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b2), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b3), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b4), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b5), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b6), "r" (zero), "r" ((uintptr_t)(out++)));
	      __asm__ ("stxvb16x %x0, %1, %2\n\t"
		:: "wa" (b7), "r" (zero), "r" ((uintptr_t)(out++)));
	    }
	}

      for ( ;nblocks; nblocks-- )
	{
	  block b;
	  u64 i = ++c->u_mode.ocb.data_nblocks;
	  const block l = *(block*)ocb_get_l (c, i);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  iv ^= l;
	  if ((uintptr_t)in % 16 == 0)
	    {
	      b = vec_ld (0, in++);
	    }
	  else
	    {
	      block unalignedprevprev;
	      unalignedprevprev = unalignedprev;
	      unalignedprev = vec_ld (0, in++);
	      b = vec_perm (unalignedprevprev, unalignedprev, vec_lvsl (0, inbuf));
	    }

	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
	  b ^= iv;
	  b = swap_if_le (b);
	  b = _gcry_aes_ppc8_decrypt_altivec (ctx, b);
	  b = swap_if_le (b) ^ iv;
	  ctr ^= b;
	  if ((uintptr_t)out % 16 == 0)
	    {
	      vec_vsx_st (b, 0, out++);
	    }
	  else
	    {
	      b = swap_if_le (b);
	      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
		:
		: "wa" (b), "r" (zero), "r" ((uintptr_t)out++));
	    }
	}

      /* We want to store iv and ctr big-endian and the unaligned
         store stxvb16x stores them little endian, so we have to swap them. */
      iv = swap_if_le (iv);
      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
	:: "wa" (iv), "r" (zero), "r" ((uintptr_t)&c->u_iv.iv));
      ctr = swap_if_le(ctr);
      __asm__ volatile ("stxvb16x %x0, %1, %2\n\t"
	:: "wa" (ctr), "r" (zero), "r" ((uintptr_t)&c->u_ctr.ctr));
    }
  return 0;
}

