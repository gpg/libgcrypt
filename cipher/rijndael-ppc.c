/* Rijndael (AES) for GnuPG - PowerPC Vector Crypto AES implementation
 * Copyright (C) 2019 Shawn Landden <shawn@git.icu>
 * Copyright (C) 2019 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#include "rijndael-internal.h"
#include "cipher-internal.h"
#include "bufhelp.h"

#ifdef USE_PPC_CRYPTO

#include <altivec.h>


typedef vector unsigned char block;

typedef union
{
  u32 data32[4];
} __attribute__((packed, aligned(1), may_alias)) u128_t;


#define ALWAYS_INLINE inline __attribute__((always_inline))
#define NO_INLINE __attribute__((noinline))
#define NO_INSTRUMENT_FUNCTION __attribute__((no_instrument_function))

#define ASM_FUNC_ATTR          NO_INSTRUMENT_FUNCTION
#define ASM_FUNC_ATTR_INLINE   ASM_FUNC_ATTR ALWAYS_INLINE
#define ASM_FUNC_ATTR_NOINLINE ASM_FUNC_ATTR NO_INLINE


#define ALIGNED_LOAD(in_ptr) \
  (vec_aligned_ld (0, (const unsigned char *)(in_ptr)))

#define ALIGNED_STORE(out_ptr, vec) \
  (vec_aligned_st ((vec), 0, (unsigned char *)(out_ptr)))

#define VEC_LOAD_BE(in_ptr, bige_const) \
  (vec_load_be (0, (const unsigned char *)(in_ptr), bige_const))

#define VEC_STORE_BE(out_ptr, vec, bige_const) \
  (vec_store_be ((vec), 0, (unsigned char *)(out_ptr), bige_const))


static const block vec_bswap32_const =
  { 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };


static ASM_FUNC_ATTR_INLINE block
vec_aligned_ld(unsigned long offset, const unsigned char *ptr)
{
#ifndef WORDS_BIGENDIAN
  block vec;
  __asm__ ("lvx %0,%1,%2\n\t"
	   : "=v" (vec)
	   : "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory");
  return vec;
#else
  return vec_vsx_ld (offset, ptr);
#endif
}


static ASM_FUNC_ATTR_INLINE block
vec_load_be_const(void)
{
#ifndef WORDS_BIGENDIAN
  return ~ALIGNED_LOAD(&vec_bswap32_const);
#else
  static const block vec_dummy = { 0 };
  return vec_dummy;
#endif
}


static ASM_FUNC_ATTR_INLINE block
vec_load_be(unsigned long offset, const unsigned char *ptr,
	    block be_bswap_const)
{
#ifndef WORDS_BIGENDIAN
  block vec;
  /* GCC vec_vsx_ld is generating two instructions on little-endian. Use
   * lxvw4x directly instead. */
  __asm__ ("lxvw4x %x0,%1,%2\n\t"
	   : "=wa" (vec)
	   : "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory");
  __asm__ ("vperm %0,%1,%1,%2\n\t"
	   : "=v" (vec)
	   : "v" (vec), "v" (be_bswap_const));
  return vec;
#else
  (void)be_bswap_const;
  return vec_vsx_ld (offset, ptr);
#endif
}


static ASM_FUNC_ATTR_INLINE void
vec_aligned_st(block vec, unsigned long offset, unsigned char *ptr)
{
#ifndef WORDS_BIGENDIAN
  __asm__ ("stvx %0,%1,%2\n\t"
	   :
	   : "v" (vec), "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory");
#else
  vec_vsx_st (vec, offset, ptr);
#endif
}


static ASM_FUNC_ATTR_INLINE void
vec_store_be(block vec, unsigned long offset, unsigned char *ptr,
	     block be_bswap_const)
{
#ifndef WORDS_BIGENDIAN
  /* GCC vec_vsx_st is generating two instructions on little-endian. Use
   * stxvw4x directly instead. */
  __asm__ ("vperm %0,%1,%1,%2\n\t"
	   : "=v" (vec)
	   : "v" (vec), "v" (be_bswap_const));
  __asm__ ("stxvw4x %x0,%1,%2\n\t"
	   :
	   : "wa" (vec), "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory");
#else
  (void)be_bswap_const;
  vec_vsx_st (vec, offset, ptr);
#endif
}


static ASM_FUNC_ATTR_INLINE u32
_gcry_aes_sbox4_ppc8(u32 fourbytes)
{
  union
    {
      PROPERLY_ALIGNED_TYPE dummy;
      block data_vec;
      u32 data32[4];
    } u;

  u.data32[0] = fourbytes;
  u.data_vec = vec_sbox_be(u.data_vec);
  return u.data32[0];
}

void
_gcry_aes_ppc8_setkey (RIJNDAEL_context *ctx, const byte *key)
{
  const block bige_const = vec_load_be_const();
  union
    {
      PROPERLY_ALIGNED_TYPE dummy;
      byte data[MAXKC][4];
      u32 data32[MAXKC];
    } tkk[2];
  unsigned int rounds = ctx->rounds;
  int KC = rounds - 6;
  unsigned int keylen = KC * 4;
  u128_t *ekey = (u128_t *)(void *)ctx->keyschenc;
  unsigned int i, r, t;
  byte rcon = 1;
  int j;
#define k      tkk[0].data
#define k_u32  tkk[0].data32
#define tk     tkk[1].data
#define tk_u32 tkk[1].data32
#define W      (ctx->keyschenc)
#define W_u32  (ctx->keyschenc32)

  for (i = 0; i < keylen; i++)
    {
      k[i >> 2][i & 3] = key[i];
    }

  for (j = KC-1; j >= 0; j--)
    {
      tk_u32[j] = k_u32[j];
    }
  r = 0;
  t = 0;
  /* Copy values into round key array.  */
  for (j = 0; (j < KC) && (r < rounds + 1); )
    {
      for (; (j < KC) && (t < 4); j++, t++)
        {
          W_u32[r][t] = le_bswap32(tk_u32[j]);
        }
      if (t == 4)
        {
          r++;
          t = 0;
        }
    }
  while (r < rounds + 1)
    {
      tk_u32[0] ^=
	le_bswap32(
	  _gcry_aes_sbox4_ppc8(rol(le_bswap32(tk_u32[KC - 1]), 24)) ^ rcon);

      if (KC != 8)
        {
          for (j = 1; j < KC; j++)
            {
              tk_u32[j] ^= tk_u32[j-1];
            }
        }
      else
        {
          for (j = 1; j < KC/2; j++)
            {
              tk_u32[j] ^= tk_u32[j-1];
            }

          tk_u32[KC/2] ^=
	    le_bswap32(_gcry_aes_sbox4_ppc8(le_bswap32(tk_u32[KC/2 - 1])));

          for (j = KC/2 + 1; j < KC; j++)
            {
              tk_u32[j] ^= tk_u32[j-1];
            }
        }

      /* Copy values into round key array.  */
      for (j = 0; (j < KC) && (r < rounds + 1); )
        {
          for (; (j < KC) && (t < 4); j++, t++)
            {
              W_u32[r][t] = le_bswap32(tk_u32[j]);
            }
          if (t == 4)
            {
              r++;
              t = 0;
            }
        }

      rcon = (rcon << 1) ^ ((rcon >> 7) * 0x1b);
    }

  /* Store in big-endian order. */
  for (r = 0; r <= rounds; r++)
    {
#ifndef WORDS_BIGENDIAN
      VEC_STORE_BE(&ekey[r], ALIGNED_LOAD(&ekey[r]), bige_const);
#else
      block rvec = ALIGNED_LOAD(&ekey[r]);
      ALIGNED_STORE(&ekey[r],
		    vec_perm(rvec, rvec, vec_bswap32_const));
      (void)bige_const;
#endif
    }

#undef W
#undef tk
#undef k
#undef W_u32
#undef tk_u32
#undef k_u32
  wipememory(&tkk, sizeof(tkk));
}


/* Make a decryption key from an encryption key. */
void
_gcry_aes_ppc8_prepare_decryption (RIJNDAEL_context *ctx)
{
  u128_t *ekey = (u128_t *)(void *)ctx->keyschenc;
  u128_t *dkey = (u128_t *)(void *)ctx->keyschdec;
  int rounds = ctx->rounds;
  int rr;
  int r;

  r = 0;
  rr = rounds;
  for (r = 0, rr = rounds; r <= rounds; r++, rr--)
    {
      ALIGNED_STORE(&dkey[r], ALIGNED_LOAD(&ekey[rr]));
    }
}


static ASM_FUNC_ATTR_INLINE block
aes_ppc8_encrypt_altivec (const RIJNDAEL_context *ctx, block a)
{
  u128_t *rk = (u128_t *)ctx->keyschenc;
  int rounds = ctx->rounds;
  int r;

#define DO_ROUND(r) (a = vec_cipher_be (a, ALIGNED_LOAD (&rk[r])))

  a = ALIGNED_LOAD(&rk[0]) ^ a;
  DO_ROUND(1);
  DO_ROUND(2);
  DO_ROUND(3);
  DO_ROUND(4);
  DO_ROUND(5);
  DO_ROUND(6);
  DO_ROUND(7);
  DO_ROUND(8);
  DO_ROUND(9);
  r = 10;
  if (rounds >= 12)
    {
      DO_ROUND(10);
      DO_ROUND(11);
      r = 12;
      if (rounds > 12)
	{
	  DO_ROUND(12);
	  DO_ROUND(13);
	  r = 14;
	}
    }
  a = vec_cipherlast_be(a, ALIGNED_LOAD(&rk[r]));

#undef DO_ROUND

  return a;
}


static ASM_FUNC_ATTR_INLINE block
aes_ppc8_decrypt_altivec (const RIJNDAEL_context *ctx, block a)
{
  u128_t *rk = (u128_t *)ctx->keyschdec;
  int rounds = ctx->rounds;
  int r;

#define DO_ROUND(r) (a = vec_ncipher_be (a, ALIGNED_LOAD (&rk[r])))

  a = ALIGNED_LOAD(&rk[0]) ^ a;
  DO_ROUND(1);
  DO_ROUND(2);
  DO_ROUND(3);
  DO_ROUND(4);
  DO_ROUND(5);
  DO_ROUND(6);
  DO_ROUND(7);
  DO_ROUND(8);
  DO_ROUND(9);
  r = 10;
  if (rounds >= 12)
    {
      DO_ROUND(10);
      DO_ROUND(11);
      r = 12;
      if (rounds > 12)
	{
	  DO_ROUND(12);
	  DO_ROUND(13);
	  r = 14;
	}
    }
  a = vec_ncipherlast_be(a, ALIGNED_LOAD(&rk[r]));

#undef DO_ROUND

  return a;
}


unsigned int _gcry_aes_ppc8_encrypt (const RIJNDAEL_context *ctx,
				     unsigned char *b,
				     const unsigned char *a)
{
  const block bige_const = vec_load_be_const();
  block sa;

  sa = VEC_LOAD_BE (a, bige_const);
  sa = aes_ppc8_encrypt_altivec (ctx, sa);
  VEC_STORE_BE (b, sa, bige_const);

  return 0; /* does not use stack */
}


unsigned int _gcry_aes_ppc8_decrypt (const RIJNDAEL_context *ctx,
				     unsigned char *b,
				     const unsigned char *a)
{
  const block bige_const = vec_load_be_const();
  block sa;

  sa = VEC_LOAD_BE (a, bige_const);
  sa = aes_ppc8_decrypt_altivec (ctx, sa);
  VEC_STORE_BE (b, sa, bige_const);

  return 0; /* does not use stack */
}


#if 0
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
#endif

#endif /* USE_PPC_CRYPTO */
