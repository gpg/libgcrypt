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


#define ROUND_KEY_VARIABLES \
  block rkey0, rkeylast

#define PRELOAD_ROUND_KEYS(nrounds) \
  do { \
    rkey0 = ALIGNED_LOAD(&rk[0]); \
    rkeylast = ALIGNED_LOAD(&rk[nrounds]); \
  } while (0)


#define AES_ENCRYPT(blk, nrounds) \
  do { \
    blk ^= rkey0; \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[1])); \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[2])); \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[3])); \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[4])); \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[5])); \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[6])); \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[7])); \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[8])); \
    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[9])); \
    if (nrounds >= 12) \
      { \
	blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[10])); \
	blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[11])); \
	if (rounds > 12) \
	  { \
	    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[12])); \
	    blk = vec_cipher_be (blk, ALIGNED_LOAD(&rk[13])); \
	  } \
      } \
    blk = vec_cipherlast_be (blk, rkeylast); \
  } while (0)


#define AES_DECRYPT(blk, nrounds) \
  do { \
    blk ^= rkey0; \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[1])); \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[2])); \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[3])); \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[4])); \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[5])); \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[6])); \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[7])); \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[8])); \
    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[9])); \
    if (nrounds >= 12) \
      { \
	blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[10])); \
	blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[11])); \
	if (rounds > 12) \
	  { \
	    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[12])); \
	    blk = vec_ncipher_be (blk, ALIGNED_LOAD(&rk[13])); \
	  } \
      } \
    blk = vec_ncipherlast_be (blk, rkeylast); \
  } while (0)


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
	   : "memory", "r0");
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
	   : "memory", "r0");
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
	   : "memory", "r0");
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
	   : "memory", "r0");
#else
  (void)be_bswap_const;
  vec_vsx_st (vec, offset, ptr);
#endif
}


static ASM_FUNC_ATTR_INLINE block
vec_add_uint128(block a, block b)
{
#if 1
  block res;
  /* Use assembly as GCC (v8.3) generates slow code for vec_vadduqm. */
  __asm__ ("vadduqm %0,%1,%2\n\t"
	   : "=v" (res)
	   : "v" (a), "v" (b));
  return res;
#else
  return (block)vec_vadduqm((vector __uint128_t)a, (vector __uint128_t)b);
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
static ASM_FUNC_ATTR_INLINE void
aes_ppc8_prepare_decryption (RIJNDAEL_context *ctx)
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


void
_gcry_aes_ppc8_prepare_decryption (RIJNDAEL_context *ctx)
{
  aes_ppc8_prepare_decryption (ctx);
}


unsigned int _gcry_aes_ppc8_encrypt (const RIJNDAEL_context *ctx,
				     unsigned char *out,
				     const unsigned char *in)
{
  const block bige_const = vec_load_be_const();
  const u128_t *rk = (u128_t *)&ctx->keyschenc;
  int rounds = ctx->rounds;
  ROUND_KEY_VARIABLES;
  block b;

  b = VEC_LOAD_BE (in, bige_const);

  PRELOAD_ROUND_KEYS (rounds);

  AES_ENCRYPT (b, rounds);
  VEC_STORE_BE (out, b, bige_const);

  return 0; /* does not use stack */
}


unsigned int _gcry_aes_ppc8_decrypt (const RIJNDAEL_context *ctx,
				     unsigned char *out,
				     const unsigned char *in)
{
  const block bige_const = vec_load_be_const();
  const u128_t *rk = (u128_t *)&ctx->keyschdec;
  int rounds = ctx->rounds;
  ROUND_KEY_VARIABLES;
  block b;

  b = VEC_LOAD_BE (in, bige_const);

  PRELOAD_ROUND_KEYS (rounds);

  AES_DECRYPT (b, rounds);
  VEC_STORE_BE (out, b, bige_const);

  return 0; /* does not use stack */
}


void _gcry_aes_ppc8_cfb_enc (void *context, unsigned char *iv_arg,
			     void *outbuf_arg, const void *inbuf_arg,
			     size_t nblocks)
{
  const block bige_const = vec_load_be_const();
  RIJNDAEL_context *ctx = context;
  const u128_t *rk = (u128_t *)&ctx->keyschenc;
  const u128_t *in = (const u128_t *)inbuf_arg;
  u128_t *out = (u128_t *)outbuf_arg;
  int rounds = ctx->rounds;
  ROUND_KEY_VARIABLES;
  block rkeylast_orig;
  block iv;

  iv = VEC_LOAD_BE (iv_arg, bige_const);

  PRELOAD_ROUND_KEYS (rounds);
  rkeylast_orig = rkeylast;

  for (; nblocks; nblocks--)
    {
      rkeylast = rkeylast_orig ^ VEC_LOAD_BE (in, bige_const);

      AES_ENCRYPT (iv, rounds);

      VEC_STORE_BE (out, iv, bige_const);

      out++;
      in++;
    }

  VEC_STORE_BE (iv_arg, iv, bige_const);
}

void _gcry_aes_ppc8_cfb_dec (void *context, unsigned char *iv_arg,
			     void *outbuf_arg, const void *inbuf_arg,
			     size_t nblocks)
{
  const block bige_const = vec_load_be_const();
  RIJNDAEL_context *ctx = context;
  const u128_t *rk = (u128_t *)&ctx->keyschenc;
  const u128_t *in = (const u128_t *)inbuf_arg;
  u128_t *out = (u128_t *)outbuf_arg;
  int rounds = ctx->rounds;
  ROUND_KEY_VARIABLES;
  block rkeylast_orig;
  block iv, b, bin;
  block in0, in1, in2, in3, in4, in5, in6, in7;
  block b0, b1, b2, b3, b4, b5, b6, b7;
  block rkey;

  iv = VEC_LOAD_BE (iv_arg, bige_const);

  PRELOAD_ROUND_KEYS (rounds);
  rkeylast_orig = rkeylast;

  for (; nblocks >= 8; nblocks -= 8)
    {
      in0 = iv;
      in1 = VEC_LOAD_BE (in + 0, bige_const);
      in2 = VEC_LOAD_BE (in + 1, bige_const);
      in3 = VEC_LOAD_BE (in + 2, bige_const);
      in4 = VEC_LOAD_BE (in + 3, bige_const);
      in5 = VEC_LOAD_BE (in + 4, bige_const);
      in6 = VEC_LOAD_BE (in + 5, bige_const);
      in7 = VEC_LOAD_BE (in + 6, bige_const);
      iv = VEC_LOAD_BE (in + 7, bige_const);

      b0 = rkey0 ^ in0;
      b1 = rkey0 ^ in1;
      b2 = rkey0 ^ in2;
      b3 = rkey0 ^ in3;
      b4 = rkey0 ^ in4;
      b5 = rkey0 ^ in5;
      b6 = rkey0 ^ in6;
      b7 = rkey0 ^ in7;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD(&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey); \
	      b4 = vec_cipher_be (b4, rkey); \
	      b5 = vec_cipher_be (b5, rkey); \
	      b6 = vec_cipher_be (b6, rkey); \
	      b7 = vec_cipher_be (b7, rkey);

      DO_ROUND(1);
      DO_ROUND(2);
      DO_ROUND(3);
      DO_ROUND(4);
      DO_ROUND(5);
      DO_ROUND(6);
      DO_ROUND(7);
      DO_ROUND(8);
      DO_ROUND(9);
      if (rounds >= 12)
	{
	  DO_ROUND(10);
	  DO_ROUND(11);
	  if (rounds > 12)
	    {
	      DO_ROUND(12);
	      DO_ROUND(13);
	    }
	}

#undef DO_ROUND

      rkey = rkeylast;
      b0 = vec_cipherlast_be (b0, rkey ^ in1);
      b1 = vec_cipherlast_be (b1, rkey ^ in2);
      b2 = vec_cipherlast_be (b2, rkey ^ in3);
      b3 = vec_cipherlast_be (b3, rkey ^ in4);
      b4 = vec_cipherlast_be (b4, rkey ^ in5);
      b5 = vec_cipherlast_be (b5, rkey ^ in6);
      b6 = vec_cipherlast_be (b6, rkey ^ in7);
      b7 = vec_cipherlast_be (b7, rkey ^ iv);

      VEC_STORE_BE (out + 0, b0, bige_const);
      VEC_STORE_BE (out + 1, b1, bige_const);
      VEC_STORE_BE (out + 2, b2, bige_const);
      VEC_STORE_BE (out + 3, b3, bige_const);
      VEC_STORE_BE (out + 4, b4, bige_const);
      VEC_STORE_BE (out + 5, b5, bige_const);
      VEC_STORE_BE (out + 6, b6, bige_const);
      VEC_STORE_BE (out + 7, b7, bige_const);

      in += 8;
      out += 8;
    }

  if (nblocks >= 4)
    {
      in0 = iv;
      in1 = VEC_LOAD_BE (in + 0, bige_const);
      in2 = VEC_LOAD_BE (in + 1, bige_const);
      in3 = VEC_LOAD_BE (in + 2, bige_const);
      iv = VEC_LOAD_BE (in + 3, bige_const);

      b0 = rkey0 ^ in0;
      b1 = rkey0 ^ in1;
      b2 = rkey0 ^ in2;
      b3 = rkey0 ^ in3;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD(&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey);

      DO_ROUND(1);
      DO_ROUND(2);
      DO_ROUND(3);
      DO_ROUND(4);
      DO_ROUND(5);
      DO_ROUND(6);
      DO_ROUND(7);
      DO_ROUND(8);
      DO_ROUND(9);
      if (rounds >= 12)
	{
	  DO_ROUND(10);
	  DO_ROUND(11);
	  if (rounds > 12)
	    {
	      DO_ROUND(12);
	      DO_ROUND(13);
	    }
	}

#undef DO_ROUND

      rkey = rkeylast;
      b0 = vec_cipherlast_be (b0, rkey ^ in1);
      b1 = vec_cipherlast_be (b1, rkey ^ in2);
      b2 = vec_cipherlast_be (b2, rkey ^ in3);
      b3 = vec_cipherlast_be (b3, rkey ^ iv);

      VEC_STORE_BE (out + 0, b0, bige_const);
      VEC_STORE_BE (out + 1, b1, bige_const);
      VEC_STORE_BE (out + 2, b2, bige_const);
      VEC_STORE_BE (out + 3, b3, bige_const);

      in += 4;
      out += 4;
      nblocks -= 4;
    }

  for (; nblocks; nblocks--)
    {
      bin = VEC_LOAD_BE (in, bige_const);
      rkeylast = rkeylast_orig ^ bin;
      b = iv;
      iv = bin;

      AES_ENCRYPT (b, rounds);

      VEC_STORE_BE (out, b, bige_const);

      out++;
      in++;
    }

  VEC_STORE_BE (iv_arg, iv, bige_const);
}


void _gcry_aes_ppc8_cbc_enc (void *context, unsigned char *iv_arg,
			     void *outbuf_arg, const void *inbuf_arg,
			     size_t nblocks, int cbc_mac)
{
  const block bige_const = vec_load_be_const();
  RIJNDAEL_context *ctx = context;
  const u128_t *rk = (u128_t *)&ctx->keyschenc;
  const u128_t *in = (const u128_t *)inbuf_arg;
  u128_t *out = (u128_t *)outbuf_arg;
  int rounds = ctx->rounds;
  ROUND_KEY_VARIABLES;
  block lastiv, b;

  lastiv = VEC_LOAD_BE (iv_arg, bige_const);

  PRELOAD_ROUND_KEYS (rounds);

  for (; nblocks; nblocks--)
    {
      b = lastiv ^ VEC_LOAD_BE (in, bige_const);

      AES_ENCRYPT (b, rounds);

      lastiv = b;
      VEC_STORE_BE (out, b, bige_const);

      in++;
      if (!cbc_mac)
	out++;
    }

  VEC_STORE_BE (iv_arg, lastiv, bige_const);
}

void _gcry_aes_ppc8_cbc_dec (void *context, unsigned char *iv_arg,
			     void *outbuf_arg, const void *inbuf_arg,
			     size_t nblocks)
{
  const block bige_const = vec_load_be_const();
  RIJNDAEL_context *ctx = context;
  const u128_t *rk = (u128_t *)&ctx->keyschdec;
  const u128_t *in = (const u128_t *)inbuf_arg;
  u128_t *out = (u128_t *)outbuf_arg;
  int rounds = ctx->rounds;
  ROUND_KEY_VARIABLES;
  block rkeylast_orig;
  block in0, in1, in2, in3, in4, in5, in6, in7;
  block b0, b1, b2, b3, b4, b5, b6, b7;
  block rkey;
  block iv, b;

  if (!ctx->decryption_prepared)
    {
      aes_ppc8_prepare_decryption (ctx);
      ctx->decryption_prepared = 1;
    }

  iv = VEC_LOAD_BE (iv_arg, bige_const);

  PRELOAD_ROUND_KEYS (rounds);
  rkeylast_orig = rkeylast;

  for (; nblocks >= 8; nblocks -= 8)
    {
      in0 = VEC_LOAD_BE (in + 0, bige_const);
      in1 = VEC_LOAD_BE (in + 1, bige_const);
      in2 = VEC_LOAD_BE (in + 2, bige_const);
      in3 = VEC_LOAD_BE (in + 3, bige_const);
      in4 = VEC_LOAD_BE (in + 4, bige_const);
      in5 = VEC_LOAD_BE (in + 5, bige_const);
      in6 = VEC_LOAD_BE (in + 6, bige_const);
      in7 = VEC_LOAD_BE (in + 7, bige_const);

      b0 = rkey0 ^ in0;
      b1 = rkey0 ^ in1;
      b2 = rkey0 ^ in2;
      b3 = rkey0 ^ in3;
      b4 = rkey0 ^ in4;
      b5 = rkey0 ^ in5;
      b6 = rkey0 ^ in6;
      b7 = rkey0 ^ in7;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD(&rk[r]); \
	      b0 = vec_ncipher_be (b0, rkey); \
	      b1 = vec_ncipher_be (b1, rkey); \
	      b2 = vec_ncipher_be (b2, rkey); \
	      b3 = vec_ncipher_be (b3, rkey); \
	      b4 = vec_ncipher_be (b4, rkey); \
	      b5 = vec_ncipher_be (b5, rkey); \
	      b6 = vec_ncipher_be (b6, rkey); \
	      b7 = vec_ncipher_be (b7, rkey);

      DO_ROUND(1);
      DO_ROUND(2);
      DO_ROUND(3);
      DO_ROUND(4);
      DO_ROUND(5);
      DO_ROUND(6);
      DO_ROUND(7);
      DO_ROUND(8);
      DO_ROUND(9);
      if (rounds >= 12)
	{
	  DO_ROUND(10);
	  DO_ROUND(11);
	  if (rounds > 12)
	    {
	      DO_ROUND(12);
	      DO_ROUND(13);
	    }
	}

#undef DO_ROUND

      rkey = rkeylast;
      b0 = vec_ncipherlast_be (b0, rkey ^ iv);
      b1 = vec_ncipherlast_be (b1, rkey ^ in0);
      b2 = vec_ncipherlast_be (b2, rkey ^ in1);
      b3 = vec_ncipherlast_be (b3, rkey ^ in2);
      b4 = vec_ncipherlast_be (b4, rkey ^ in3);
      b5 = vec_ncipherlast_be (b5, rkey ^ in4);
      b6 = vec_ncipherlast_be (b6, rkey ^ in5);
      b7 = vec_ncipherlast_be (b7, rkey ^ in6);
      iv = in7;

      VEC_STORE_BE (out + 0, b0, bige_const);
      VEC_STORE_BE (out + 1, b1, bige_const);
      VEC_STORE_BE (out + 2, b2, bige_const);
      VEC_STORE_BE (out + 3, b3, bige_const);
      VEC_STORE_BE (out + 4, b4, bige_const);
      VEC_STORE_BE (out + 5, b5, bige_const);
      VEC_STORE_BE (out + 6, b6, bige_const);
      VEC_STORE_BE (out + 7, b7, bige_const);

      in += 8;
      out += 8;
    }

  if (nblocks >= 4)
    {
      in0 = VEC_LOAD_BE (in + 0, bige_const);
      in1 = VEC_LOAD_BE (in + 1, bige_const);
      in2 = VEC_LOAD_BE (in + 2, bige_const);
      in3 = VEC_LOAD_BE (in + 3, bige_const);

      b0 = rkey0 ^ in0;
      b1 = rkey0 ^ in1;
      b2 = rkey0 ^ in2;
      b3 = rkey0 ^ in3;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD(&rk[r]); \
	      b0 = vec_ncipher_be (b0, rkey); \
	      b1 = vec_ncipher_be (b1, rkey); \
	      b2 = vec_ncipher_be (b2, rkey); \
	      b3 = vec_ncipher_be (b3, rkey);

      DO_ROUND(1);
      DO_ROUND(2);
      DO_ROUND(3);
      DO_ROUND(4);
      DO_ROUND(5);
      DO_ROUND(6);
      DO_ROUND(7);
      DO_ROUND(8);
      DO_ROUND(9);
      if (rounds >= 12)
	{
	  DO_ROUND(10);
	  DO_ROUND(11);
	  if (rounds > 12)
	    {
	      DO_ROUND(12);
	      DO_ROUND(13);
	    }
	}

#undef DO_ROUND

      rkey = rkeylast;
      b0 = vec_ncipherlast_be (b0, rkey ^ iv);
      b1 = vec_ncipherlast_be (b1, rkey ^ in0);
      b2 = vec_ncipherlast_be (b2, rkey ^ in1);
      b3 = vec_ncipherlast_be (b3, rkey ^ in2);
      iv = in3;

      VEC_STORE_BE (out + 0, b0, bige_const);
      VEC_STORE_BE (out + 1, b1, bige_const);
      VEC_STORE_BE (out + 2, b2, bige_const);
      VEC_STORE_BE (out + 3, b3, bige_const);

      in += 4;
      out += 4;
      nblocks -= 4;
    }

  for (; nblocks; nblocks--)
    {
      rkeylast = rkeylast_orig ^ iv;

      iv = VEC_LOAD_BE (in, bige_const);
      b = iv;
      AES_DECRYPT (b, rounds);

      VEC_STORE_BE (out, b, bige_const);

      in++;
      out++;
    }

  VEC_STORE_BE (iv_arg, iv, bige_const);
}


void _gcry_aes_ppc8_ctr_enc (void *context, unsigned char *ctr_arg,
			     void *outbuf_arg, const void *inbuf_arg,
			     size_t nblocks)
{
  static const unsigned char vec_one_const[16] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
  const block bige_const = vec_load_be_const();
  RIJNDAEL_context *ctx = context;
  const u128_t *rk = (u128_t *)&ctx->keyschenc;
  const u128_t *in = (const u128_t *)inbuf_arg;
  u128_t *out = (u128_t *)outbuf_arg;
  int rounds = ctx->rounds;
  ROUND_KEY_VARIABLES;
  block rkeylast_orig;
  block ctr, b, one;

  ctr = VEC_LOAD_BE (ctr_arg, bige_const);
  one = VEC_LOAD_BE (&vec_one_const, bige_const);

  PRELOAD_ROUND_KEYS (rounds);
  rkeylast_orig = rkeylast;

  if (nblocks >= 4)
    {
      block b0, b1, b2, b3, b4, b5, b6, b7;
      block two, three, four;
      block ctr4;
      block rkey;

      two   = vec_add_uint128 (one, one);
      three = vec_add_uint128 (two, one);
      four  = vec_add_uint128 (two, two);

      for (; nblocks >= 8; nblocks -= 8)
	{
	  ctr4 = vec_add_uint128 (ctr, four);
	  b0 = rkey0 ^ ctr;
	  b1 = rkey0 ^ vec_add_uint128 (ctr, one);
	  b2 = rkey0 ^ vec_add_uint128 (ctr, two);
	  b3 = rkey0 ^ vec_add_uint128 (ctr, three);
	  b4 = rkey0 ^ ctr4;
	  b5 = rkey0 ^ vec_add_uint128 (ctr4, one);
	  b6 = rkey0 ^ vec_add_uint128 (ctr4, two);
	  b7 = rkey0 ^ vec_add_uint128 (ctr4, three);
	  ctr = vec_add_uint128 (ctr4, four);

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD(&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey); \
	      b4 = vec_cipher_be (b4, rkey); \
	      b5 = vec_cipher_be (b5, rkey); \
	      b6 = vec_cipher_be (b6, rkey); \
	      b7 = vec_cipher_be (b7, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast;
	  b0 = vec_cipherlast_be (b0, rkey ^ VEC_LOAD_BE (in + 0, bige_const));
	  b1 = vec_cipherlast_be (b1, rkey ^ VEC_LOAD_BE (in + 1, bige_const));
	  b2 = vec_cipherlast_be (b2, rkey ^ VEC_LOAD_BE (in + 2, bige_const));
	  b3 = vec_cipherlast_be (b3, rkey ^ VEC_LOAD_BE (in + 3, bige_const));
	  b4 = vec_cipherlast_be (b4, rkey ^ VEC_LOAD_BE (in + 4, bige_const));
	  b5 = vec_cipherlast_be (b5, rkey ^ VEC_LOAD_BE (in + 5, bige_const));
	  b6 = vec_cipherlast_be (b6, rkey ^ VEC_LOAD_BE (in + 6, bige_const));
	  b7 = vec_cipherlast_be (b7, rkey ^ VEC_LOAD_BE (in + 7, bige_const));

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);
	  VEC_STORE_BE (out + 4, b4, bige_const);
	  VEC_STORE_BE (out + 5, b5, bige_const);
	  VEC_STORE_BE (out + 6, b6, bige_const);
	  VEC_STORE_BE (out + 7, b7, bige_const);

	  in += 8;
	  out += 8;
	}

      if (nblocks >= 4)
	{
	  b0 = rkey0 ^ ctr;
	  b1 = rkey0 ^ vec_add_uint128 (ctr, one);
	  b2 = rkey0 ^ vec_add_uint128 (ctr, two);
	  b3 = rkey0 ^ vec_add_uint128 (ctr, three);
	  ctr = vec_add_uint128 (ctr, four);

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD(&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast;
	  b0 = vec_cipherlast_be (b0, rkey ^ VEC_LOAD_BE (in + 0, bige_const));
	  b1 = vec_cipherlast_be (b1, rkey ^ VEC_LOAD_BE (in + 1, bige_const));
	  b2 = vec_cipherlast_be (b2, rkey ^ VEC_LOAD_BE (in + 2, bige_const));
	  b3 = vec_cipherlast_be (b3, rkey ^ VEC_LOAD_BE (in + 3, bige_const));

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);
	  in += 4;
	  out += 4;
	  nblocks -= 4;
	}
    }

  for (; nblocks; nblocks--)
    {
      b = ctr;
      ctr = vec_add_uint128 (ctr, one);
      rkeylast = rkeylast_orig ^ VEC_LOAD_BE (in, bige_const);

      AES_ENCRYPT (b, rounds);

      VEC_STORE_BE (out, b, bige_const);

      out++;
      in++;
    }

  VEC_STORE_BE (ctr_arg, ctr, bige_const);
}


size_t _gcry_aes_ppc8_ocb_crypt (gcry_cipher_hd_t c, void *outbuf_arg,
				 const void *inbuf_arg, size_t nblocks,
				 int encrypt)
{
  const block bige_const = vec_load_be_const();
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  const u128_t *in = (const u128_t *)inbuf_arg;
  u128_t *out = (u128_t *)outbuf_arg;
  int rounds = ctx->rounds;
  u64 data_nblocks = c->u_mode.ocb.data_nblocks;
  block l0, l1, l2, l;
  block b0, b1, b2, b3, b4, b5, b6, b7, b;
  block iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7;
  block rkey;
  block ctr, iv;
  ROUND_KEY_VARIABLES;

  iv = VEC_LOAD_BE (c->u_iv.iv, bige_const);
  ctr = VEC_LOAD_BE (c->u_ctr.ctr, bige_const);

  l0 = VEC_LOAD_BE (c->u_mode.ocb.L[0], bige_const);
  l1 = VEC_LOAD_BE (c->u_mode.ocb.L[1], bige_const);
  l2 = VEC_LOAD_BE (c->u_mode.ocb.L[2], bige_const);

  if (encrypt)
    {
      const u128_t *rk = (u128_t *)&ctx->keyschenc;

      PRELOAD_ROUND_KEYS (rounds);

      for (; nblocks >= 8 && data_nblocks % 8; nblocks--)
	{
	  l = VEC_LOAD_BE (ocb_get_l (c, ++data_nblocks), bige_const);
	  b = VEC_LOAD_BE (in, bige_const);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  iv ^= l;
	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr ^= b;
	  /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
	  b ^= iv;
	  AES_ENCRYPT (b, rounds);
	  b ^= iv;

	  VEC_STORE_BE (out, b, bige_const);

	  in += 1;
	  out += 1;
	}

      for (; nblocks >= 8; nblocks -= 8)
	{
	  b0 = VEC_LOAD_BE (in + 0, bige_const);
	  b1 = VEC_LOAD_BE (in + 1, bige_const);
	  b2 = VEC_LOAD_BE (in + 2, bige_const);
	  b3 = VEC_LOAD_BE (in + 3, bige_const);
	  b4 = VEC_LOAD_BE (in + 4, bige_const);
	  b5 = VEC_LOAD_BE (in + 5, bige_const);
	  b6 = VEC_LOAD_BE (in + 6, bige_const);
	  b7 = VEC_LOAD_BE (in + 7, bige_const);

	  l = VEC_LOAD_BE (ocb_get_l (c, data_nblocks += 8), bige_const);

	  ctr ^= b0 ^ b1 ^ b2 ^ b3 ^ b4 ^ b5 ^ b6 ^ b7;

	  iv ^= rkey0;

	  iv0 = iv ^ l0;
	  iv1 = iv ^ l0 ^ l1;
	  iv2 = iv ^ l1;
	  iv3 = iv ^ l1 ^ l2;
	  iv4 = iv ^ l1 ^ l2 ^ l0;
	  iv5 = iv ^ l2 ^ l0;
	  iv6 = iv ^ l2;
	  iv7 = iv ^ l2 ^ l;

	  b0 ^= iv0;
	  b1 ^= iv1;
	  b2 ^= iv2;
	  b3 ^= iv3;
	  b4 ^= iv4;
	  b5 ^= iv5;
	  b6 ^= iv6;
	  b7 ^= iv7;
	  iv = iv7 ^ rkey0;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey); \
	      b4 = vec_cipher_be (b4, rkey); \
	      b5 = vec_cipher_be (b5, rkey); \
	      b6 = vec_cipher_be (b6, rkey); \
	      b7 = vec_cipher_be (b7, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast ^ rkey0;
	  b0 = vec_cipherlast_be (b0, rkey ^ iv0);
	  b1 = vec_cipherlast_be (b1, rkey ^ iv1);
	  b2 = vec_cipherlast_be (b2, rkey ^ iv2);
	  b3 = vec_cipherlast_be (b3, rkey ^ iv3);
	  b4 = vec_cipherlast_be (b4, rkey ^ iv4);
	  b5 = vec_cipherlast_be (b5, rkey ^ iv5);
	  b6 = vec_cipherlast_be (b6, rkey ^ iv6);
	  b7 = vec_cipherlast_be (b7, rkey ^ iv7);

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);
	  VEC_STORE_BE (out + 4, b4, bige_const);
	  VEC_STORE_BE (out + 5, b5, bige_const);
	  VEC_STORE_BE (out + 6, b6, bige_const);
	  VEC_STORE_BE (out + 7, b7, bige_const);

	  in += 8;
	  out += 8;
	}

      if (nblocks >= 4 && (data_nblocks % 4) == 0)
	{
	  b0 = VEC_LOAD_BE (in + 0, bige_const);
	  b1 = VEC_LOAD_BE (in + 1, bige_const);
	  b2 = VEC_LOAD_BE (in + 2, bige_const);
	  b3 = VEC_LOAD_BE (in + 3, bige_const);

	  l = VEC_LOAD_BE (ocb_get_l (c, data_nblocks += 4), bige_const);

	  ctr ^= b0 ^ b1 ^ b2 ^ b3;

	  iv ^= rkey0;

	  iv0 = iv ^ l0;
	  iv1 = iv ^ l0 ^ l1;
	  iv2 = iv ^ l1;
	  iv3 = iv ^ l1 ^ l;

	  b0 ^= iv0;
	  b1 ^= iv1;
	  b2 ^= iv2;
	  b3 ^= iv3;
	  iv = iv3 ^ rkey0;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast ^ rkey0;
	  b0 = vec_cipherlast_be (b0, rkey ^ iv0);
	  b1 = vec_cipherlast_be (b1, rkey ^ iv1);
	  b2 = vec_cipherlast_be (b2, rkey ^ iv2);
	  b3 = vec_cipherlast_be (b3, rkey ^ iv3);

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);

	  in += 4;
	  out += 4;
	  nblocks -= 4;
	}

      for (; nblocks; nblocks--)
	{
	  l = VEC_LOAD_BE (ocb_get_l (c, ++data_nblocks), bige_const);
	  b = VEC_LOAD_BE (in, bige_const);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  iv ^= l;
	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr ^= b;
	  /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
	  b ^= iv;
	  AES_ENCRYPT (b, rounds);
	  b ^= iv;

	  VEC_STORE_BE (out, b, bige_const);

	  in += 1;
	  out += 1;
	}
    }
  else
    {
      const u128_t *rk = (u128_t *)&ctx->keyschdec;

      if (!ctx->decryption_prepared)
	{
	  aes_ppc8_prepare_decryption (ctx);
	  ctx->decryption_prepared = 1;
	}

      PRELOAD_ROUND_KEYS (rounds);

      for (; nblocks >= 8 && data_nblocks % 8; nblocks--)
	{
	  l = VEC_LOAD_BE (ocb_get_l (c, ++data_nblocks), bige_const);
	  b = VEC_LOAD_BE (in, bige_const);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  iv ^= l;
	  /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */
	  b ^= iv;
	  AES_DECRYPT (b, rounds);
	  b ^= iv;
	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr ^= b;

	  VEC_STORE_BE (out, b, bige_const);

	  in += 1;
	  out += 1;
	}

      for (; nblocks >= 8; nblocks -= 8)
	{
	  b0 = VEC_LOAD_BE (in + 0, bige_const);
	  b1 = VEC_LOAD_BE (in + 1, bige_const);
	  b2 = VEC_LOAD_BE (in + 2, bige_const);
	  b3 = VEC_LOAD_BE (in + 3, bige_const);
	  b4 = VEC_LOAD_BE (in + 4, bige_const);
	  b5 = VEC_LOAD_BE (in + 5, bige_const);
	  b6 = VEC_LOAD_BE (in + 6, bige_const);
	  b7 = VEC_LOAD_BE (in + 7, bige_const);

	  l = VEC_LOAD_BE (ocb_get_l (c, data_nblocks += 8), bige_const);

	  iv ^= rkey0;

	  iv0 = iv ^ l0;
	  iv1 = iv ^ l0 ^ l1;
	  iv2 = iv ^ l1;
	  iv3 = iv ^ l1 ^ l2;
	  iv4 = iv ^ l1 ^ l2 ^ l0;
	  iv5 = iv ^ l2 ^ l0;
	  iv6 = iv ^ l2;
	  iv7 = iv ^ l2 ^ l;

	  b0 ^= iv0;
	  b1 ^= iv1;
	  b2 ^= iv2;
	  b3 ^= iv3;
	  b4 ^= iv4;
	  b5 ^= iv5;
	  b6 ^= iv6;
	  b7 ^= iv7;
	  iv = iv7 ^ rkey0;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_ncipher_be (b0, rkey); \
	      b1 = vec_ncipher_be (b1, rkey); \
	      b2 = vec_ncipher_be (b2, rkey); \
	      b3 = vec_ncipher_be (b3, rkey); \
	      b4 = vec_ncipher_be (b4, rkey); \
	      b5 = vec_ncipher_be (b5, rkey); \
	      b6 = vec_ncipher_be (b6, rkey); \
	      b7 = vec_ncipher_be (b7, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast ^ rkey0;
	  b0 = vec_ncipherlast_be (b0, rkey ^ iv0);
	  b1 = vec_ncipherlast_be (b1, rkey ^ iv1);
	  b2 = vec_ncipherlast_be (b2, rkey ^ iv2);
	  b3 = vec_ncipherlast_be (b3, rkey ^ iv3);
	  b4 = vec_ncipherlast_be (b4, rkey ^ iv4);
	  b5 = vec_ncipherlast_be (b5, rkey ^ iv5);
	  b6 = vec_ncipherlast_be (b6, rkey ^ iv6);
	  b7 = vec_ncipherlast_be (b7, rkey ^ iv7);

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);
	  VEC_STORE_BE (out + 4, b4, bige_const);
	  VEC_STORE_BE (out + 5, b5, bige_const);
	  VEC_STORE_BE (out + 6, b6, bige_const);
	  VEC_STORE_BE (out + 7, b7, bige_const);

	  ctr ^= b0 ^ b1 ^ b2 ^ b3 ^ b4 ^ b5 ^ b6 ^ b7;

	  in += 8;
	  out += 8;
	}

      if (nblocks >= 4 && (data_nblocks % 4) == 0)
	{
	  b0 = VEC_LOAD_BE (in + 0, bige_const);
	  b1 = VEC_LOAD_BE (in + 1, bige_const);
	  b2 = VEC_LOAD_BE (in + 2, bige_const);
	  b3 = VEC_LOAD_BE (in + 3, bige_const);

	  l = VEC_LOAD_BE (ocb_get_l (c, data_nblocks += 4), bige_const);

	  iv ^= rkey0;

	  iv0 = iv ^ l0;
	  iv1 = iv ^ l0 ^ l1;
	  iv2 = iv ^ l1;
	  iv3 = iv ^ l1 ^ l;

	  b0 ^= iv0;
	  b1 ^= iv1;
	  b2 ^= iv2;
	  b3 ^= iv3;
	  iv = iv3 ^ rkey0;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_ncipher_be (b0, rkey); \
	      b1 = vec_ncipher_be (b1, rkey); \
	      b2 = vec_ncipher_be (b2, rkey); \
	      b3 = vec_ncipher_be (b3, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast ^ rkey0;
	  b0 = vec_ncipherlast_be (b0, rkey ^ iv0);
	  b1 = vec_ncipherlast_be (b1, rkey ^ iv1);
	  b2 = vec_ncipherlast_be (b2, rkey ^ iv2);
	  b3 = vec_ncipherlast_be (b3, rkey ^ iv3);

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);

	  ctr ^= b0 ^ b1 ^ b2 ^ b3;

	  in += 4;
	  out += 4;
	  nblocks -= 4;
	}

      for (; nblocks; nblocks--)
	{
	  l = VEC_LOAD_BE (ocb_get_l (c, ++data_nblocks), bige_const);
	  b = VEC_LOAD_BE (in, bige_const);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  iv ^= l;
	  /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */
	  b ^= iv;
	  AES_DECRYPT (b, rounds);
	  b ^= iv;
	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr ^= b;

	  VEC_STORE_BE (out, b, bige_const);

	  in += 1;
	  out += 1;
	}
    }

  VEC_STORE_BE (c->u_iv.iv, iv, bige_const);
  VEC_STORE_BE (c->u_ctr.ctr, ctr, bige_const);
  c->u_mode.ocb.data_nblocks = data_nblocks;

  return 0;
}

size_t _gcry_aes_ppc8_ocb_auth (gcry_cipher_hd_t c, void *abuf_arg,
				size_t nblocks)
{
  const block bige_const = vec_load_be_const();
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  const u128_t *rk = (u128_t *)&ctx->keyschenc;
  const u128_t *abuf = (const u128_t *)abuf_arg;
  int rounds = ctx->rounds;
  u64 data_nblocks = c->u_mode.ocb.aad_nblocks;
  block l0, l1, l2, l;
  block b0, b1, b2, b3, b4, b5, b6, b7, b;
  block iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7;
  block rkey, frkey;
  block ctr, iv;
  ROUND_KEY_VARIABLES;

  iv = VEC_LOAD_BE (c->u_mode.ocb.aad_offset, bige_const);
  ctr = VEC_LOAD_BE (c->u_mode.ocb.aad_sum, bige_const);

  l0 = VEC_LOAD_BE (c->u_mode.ocb.L[0], bige_const);
  l1 = VEC_LOAD_BE (c->u_mode.ocb.L[1], bige_const);
  l2 = VEC_LOAD_BE (c->u_mode.ocb.L[2], bige_const);

  PRELOAD_ROUND_KEYS (rounds);

  for (; nblocks >= 8 && data_nblocks % 8; nblocks--)
    {
      l = VEC_LOAD_BE (ocb_get_l (c, ++data_nblocks), bige_const);
      b = VEC_LOAD_BE (abuf, bige_const);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      iv ^= l;
      /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
      b ^= iv;
      AES_ENCRYPT (b, rounds);
      ctr ^= b;

      abuf += 1;
    }

  for (; nblocks >= 8; nblocks -= 8)
    {
      b0 = VEC_LOAD_BE (abuf + 0, bige_const);
      b1 = VEC_LOAD_BE (abuf + 1, bige_const);
      b2 = VEC_LOAD_BE (abuf + 2, bige_const);
      b3 = VEC_LOAD_BE (abuf + 3, bige_const);
      b4 = VEC_LOAD_BE (abuf + 4, bige_const);
      b5 = VEC_LOAD_BE (abuf + 5, bige_const);
      b6 = VEC_LOAD_BE (abuf + 6, bige_const);
      b7 = VEC_LOAD_BE (abuf + 7, bige_const);

      l = VEC_LOAD_BE (ocb_get_l (c, data_nblocks += 8), bige_const);

      frkey = rkey0;
      iv ^= frkey;

      iv0 = iv ^ l0;
      iv1 = iv ^ l0 ^ l1;
      iv2 = iv ^ l1;
      iv3 = iv ^ l1 ^ l2;
      iv4 = iv ^ l1 ^ l2 ^ l0;
      iv5 = iv ^ l2 ^ l0;
      iv6 = iv ^ l2;
      iv7 = iv ^ l2 ^ l;

      b0 ^= iv0;
      b1 ^= iv1;
      b2 ^= iv2;
      b3 ^= iv3;
      b4 ^= iv4;
      b5 ^= iv5;
      b6 ^= iv6;
      b7 ^= iv7;
      iv = iv7 ^ frkey;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey); \
	      b4 = vec_cipher_be (b4, rkey); \
	      b5 = vec_cipher_be (b5, rkey); \
	      b6 = vec_cipher_be (b6, rkey); \
	      b7 = vec_cipher_be (b7, rkey);

      DO_ROUND(1);
      DO_ROUND(2);
      DO_ROUND(3);
      DO_ROUND(4);
      DO_ROUND(5);
      DO_ROUND(6);
      DO_ROUND(7);
      DO_ROUND(8);
      DO_ROUND(9);
      if (rounds >= 12)
	{
	  DO_ROUND(10);
	  DO_ROUND(11);
	  if (rounds > 12)
	    {
	      DO_ROUND(12);
	      DO_ROUND(13);
	    }
	}

#undef DO_ROUND

      rkey = rkeylast;
      b0 = vec_cipherlast_be (b0, rkey);
      b1 = vec_cipherlast_be (b1, rkey);
      b2 = vec_cipherlast_be (b2, rkey);
      b3 = vec_cipherlast_be (b3, rkey);
      b4 = vec_cipherlast_be (b4, rkey);
      b5 = vec_cipherlast_be (b5, rkey);
      b6 = vec_cipherlast_be (b6, rkey);
      b7 = vec_cipherlast_be (b7, rkey);

      ctr ^= b0 ^ b1 ^ b2 ^ b3 ^ b4 ^ b5 ^ b6 ^ b7;

      abuf += 8;
    }

  if (nblocks >= 4 && (data_nblocks % 4) == 0)
    {
      b0 = VEC_LOAD_BE (abuf + 0, bige_const);
      b1 = VEC_LOAD_BE (abuf + 1, bige_const);
      b2 = VEC_LOAD_BE (abuf + 2, bige_const);
      b3 = VEC_LOAD_BE (abuf + 3, bige_const);

      l = VEC_LOAD_BE (ocb_get_l (c, data_nblocks += 4), bige_const);

      frkey = rkey0;
      iv ^= frkey;

      iv0 = iv ^ l0;
      iv1 = iv ^ l0 ^ l1;
      iv2 = iv ^ l1;
      iv3 = iv ^ l1 ^ l;

      b0 ^= iv0;
      b1 ^= iv1;
      b2 ^= iv2;
      b3 ^= iv3;
      iv = iv3 ^ frkey;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey);

      DO_ROUND(1);
      DO_ROUND(2);
      DO_ROUND(3);
      DO_ROUND(4);
      DO_ROUND(5);
      DO_ROUND(6);
      DO_ROUND(7);
      DO_ROUND(8);
      DO_ROUND(9);
      if (rounds >= 12)
	{
	  DO_ROUND(10);
	  DO_ROUND(11);
	  if (rounds > 12)
	    {
	      DO_ROUND(12);
	      DO_ROUND(13);
	    }
	}

#undef DO_ROUND

      rkey = rkeylast;
      b0 = vec_cipherlast_be (b0, rkey);
      b1 = vec_cipherlast_be (b1, rkey);
      b2 = vec_cipherlast_be (b2, rkey);
      b3 = vec_cipherlast_be (b3, rkey);

      ctr ^= b0 ^ b1 ^ b2 ^ b3;

      abuf += 4;
      nblocks -= 4;
    }

  for (; nblocks; nblocks--)
    {
      l = VEC_LOAD_BE (ocb_get_l (c, ++data_nblocks), bige_const);
      b = VEC_LOAD_BE (abuf, bige_const);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      iv ^= l;
      /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
      b ^= iv;
      AES_ENCRYPT (b, rounds);
      ctr ^= b;

      abuf += 1;
    }

  VEC_STORE_BE (c->u_mode.ocb.aad_offset, iv, bige_const);
  VEC_STORE_BE (c->u_mode.ocb.aad_sum, ctr, bige_const);
  c->u_mode.ocb.aad_nblocks = data_nblocks;

  return 0;
}


void _gcry_aes_ppc8_xts_crypt (void *context, unsigned char *tweak_arg,
			       void *outbuf_arg, const void *inbuf_arg,
			       size_t nblocks, int encrypt)
{
  static const block vec_bswap64_const =
    { 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8 };
  static const block vec_bswap128_const =
    { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  static const unsigned char vec_tweak_const[16] =
    { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x87 };
  static const vector unsigned long long vec_shift63_const =
    { 63, 63 };
  static const vector unsigned long long vec_shift1_const =
    { 1, 1 };
  const block bige_const = vec_load_be_const();
  RIJNDAEL_context *ctx = context;
  const u128_t *in = (const u128_t *)inbuf_arg;
  u128_t *out = (u128_t *)outbuf_arg;
  int rounds = ctx->rounds;
  block tweak_tmp, tweak_next, tweak;
  block b0, b1, b2, b3, b4, b5, b6, b7, b, rkey;
  block tweak0, tweak1, tweak2, tweak3, tweak4, tweak5, tweak6, tweak7;
  block tweak_const, bswap64_const, bswap128_const;
  vector unsigned long long shift63_const, shift1_const;
  ROUND_KEY_VARIABLES;

  tweak_const = VEC_LOAD_BE (&vec_tweak_const, bige_const);
  bswap64_const = ALIGNED_LOAD (&vec_bswap64_const);
  bswap128_const = ALIGNED_LOAD (&vec_bswap128_const);
  shift63_const = (vector unsigned long long)ALIGNED_LOAD (&vec_shift63_const);
  shift1_const = (vector unsigned long long)ALIGNED_LOAD (&vec_shift1_const);

  tweak_next = VEC_LOAD_BE (tweak_arg, bige_const);

#define GEN_TWEAK(tweak, tmp) /* Generate next tweak. */ \
    tmp = vec_vperm(tweak, tweak, bswap64_const); \
    tweak = vec_vperm(tweak, tweak, bswap128_const); \
    tmp = (block)(vec_sra((vector unsigned long long)tmp, shift63_const)) & \
	  tweak_const; \
    tweak = (block)vec_sl((vector unsigned long long)tweak, shift1_const); \
    tweak = tweak ^ tmp; \
    tweak = vec_vperm(tweak, tweak, bswap128_const);

  if (encrypt)
    {
      const u128_t *rk = (u128_t *)&ctx->keyschenc;

      PRELOAD_ROUND_KEYS (rounds);

      for (; nblocks >= 8; nblocks -= 8)
	{
	  tweak0 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak1 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak2 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak3 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak4 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak5 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak6 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak7 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);

	  b0 = VEC_LOAD_BE (in + 0, bige_const) ^ tweak0 ^ rkey0;
	  b1 = VEC_LOAD_BE (in + 1, bige_const) ^ tweak1 ^ rkey0;
	  b2 = VEC_LOAD_BE (in + 2, bige_const) ^ tweak2 ^ rkey0;
	  b3 = VEC_LOAD_BE (in + 3, bige_const) ^ tweak3 ^ rkey0;
	  b4 = VEC_LOAD_BE (in + 4, bige_const) ^ tweak4 ^ rkey0;
	  b5 = VEC_LOAD_BE (in + 5, bige_const) ^ tweak5 ^ rkey0;
	  b6 = VEC_LOAD_BE (in + 6, bige_const) ^ tweak6 ^ rkey0;
	  b7 = VEC_LOAD_BE (in + 7, bige_const) ^ tweak7 ^ rkey0;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey); \
	      b4 = vec_cipher_be (b4, rkey); \
	      b5 = vec_cipher_be (b5, rkey); \
	      b6 = vec_cipher_be (b6, rkey); \
	      b7 = vec_cipher_be (b7, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast;
	  b0 = vec_cipherlast_be (b0, rkey ^ tweak0);
	  b1 = vec_cipherlast_be (b1, rkey ^ tweak1);
	  b2 = vec_cipherlast_be (b2, rkey ^ tweak2);
	  b3 = vec_cipherlast_be (b3, rkey ^ tweak3);
	  b4 = vec_cipherlast_be (b4, rkey ^ tweak4);
	  b5 = vec_cipherlast_be (b5, rkey ^ tweak5);
	  b6 = vec_cipherlast_be (b6, rkey ^ tweak6);
	  b7 = vec_cipherlast_be (b7, rkey ^ tweak7);

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);
	  VEC_STORE_BE (out + 4, b4, bige_const);
	  VEC_STORE_BE (out + 5, b5, bige_const);
	  VEC_STORE_BE (out + 6, b6, bige_const);
	  VEC_STORE_BE (out + 7, b7, bige_const);

	  in += 8;
	  out += 8;
	}

      if (nblocks >= 4)
	{
	  tweak0 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak1 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak2 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak3 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);

	  b0 = VEC_LOAD_BE (in + 0, bige_const) ^ tweak0 ^ rkey0;
	  b1 = VEC_LOAD_BE (in + 1, bige_const) ^ tweak1 ^ rkey0;
	  b2 = VEC_LOAD_BE (in + 2, bige_const) ^ tweak2 ^ rkey0;
	  b3 = VEC_LOAD_BE (in + 3, bige_const) ^ tweak3 ^ rkey0;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_cipher_be (b0, rkey); \
	      b1 = vec_cipher_be (b1, rkey); \
	      b2 = vec_cipher_be (b2, rkey); \
	      b3 = vec_cipher_be (b3, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast;
	  b0 = vec_cipherlast_be (b0, rkey ^ tweak0);
	  b1 = vec_cipherlast_be (b1, rkey ^ tweak1);
	  b2 = vec_cipherlast_be (b2, rkey ^ tweak2);
	  b3 = vec_cipherlast_be (b3, rkey ^ tweak3);

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);

	  in += 4;
	  out += 4;
	  nblocks -= 4;
	}

      for (; nblocks; nblocks--)
	{
	  tweak = tweak_next;

	  /* Xor-Encrypt/Decrypt-Xor block. */
	  b = VEC_LOAD_BE (in, bige_const) ^ tweak;

	  /* Generate next tweak. */
	  GEN_TWEAK (tweak_next, tweak_tmp);

	  AES_ENCRYPT (b, rounds);

	  b ^= tweak;
	  VEC_STORE_BE (out, b, bige_const);

	  in++;
	  out++;
	}
    }
  else
    {
      const u128_t *rk = (u128_t *)&ctx->keyschdec;

      if (!ctx->decryption_prepared)
	{
	  aes_ppc8_prepare_decryption (ctx);
	  ctx->decryption_prepared = 1;
	}

      PRELOAD_ROUND_KEYS (rounds);

      for (; nblocks >= 8; nblocks -= 8)
	{
	  tweak0 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak1 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak2 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak3 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak4 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak5 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak6 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak7 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);

	  b0 = VEC_LOAD_BE (in + 0, bige_const) ^ tweak0 ^ rkey0;
	  b1 = VEC_LOAD_BE (in + 1, bige_const) ^ tweak1 ^ rkey0;
	  b2 = VEC_LOAD_BE (in + 2, bige_const) ^ tweak2 ^ rkey0;
	  b3 = VEC_LOAD_BE (in + 3, bige_const) ^ tweak3 ^ rkey0;
	  b4 = VEC_LOAD_BE (in + 4, bige_const) ^ tweak4 ^ rkey0;
	  b5 = VEC_LOAD_BE (in + 5, bige_const) ^ tweak5 ^ rkey0;
	  b6 = VEC_LOAD_BE (in + 6, bige_const) ^ tweak6 ^ rkey0;
	  b7 = VEC_LOAD_BE (in + 7, bige_const) ^ tweak7 ^ rkey0;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_ncipher_be (b0, rkey); \
	      b1 = vec_ncipher_be (b1, rkey); \
	      b2 = vec_ncipher_be (b2, rkey); \
	      b3 = vec_ncipher_be (b3, rkey); \
	      b4 = vec_ncipher_be (b4, rkey); \
	      b5 = vec_ncipher_be (b5, rkey); \
	      b6 = vec_ncipher_be (b6, rkey); \
	      b7 = vec_ncipher_be (b7, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast;
	  b0 = vec_ncipherlast_be (b0, rkey ^ tweak0);
	  b1 = vec_ncipherlast_be (b1, rkey ^ tweak1);
	  b2 = vec_ncipherlast_be (b2, rkey ^ tweak2);
	  b3 = vec_ncipherlast_be (b3, rkey ^ tweak3);
	  b4 = vec_ncipherlast_be (b4, rkey ^ tweak4);
	  b5 = vec_ncipherlast_be (b5, rkey ^ tweak5);
	  b6 = vec_ncipherlast_be (b6, rkey ^ tweak6);
	  b7 = vec_ncipherlast_be (b7, rkey ^ tweak7);

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);
	  VEC_STORE_BE (out + 4, b4, bige_const);
	  VEC_STORE_BE (out + 5, b5, bige_const);
	  VEC_STORE_BE (out + 6, b6, bige_const);
	  VEC_STORE_BE (out + 7, b7, bige_const);

	  in += 8;
	  out += 8;
	}

      if (nblocks >= 4)
	{
	  tweak0 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak1 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak2 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);
	  tweak3 = tweak_next;
	  GEN_TWEAK (tweak_next, tweak_tmp);

	  b0 = VEC_LOAD_BE (in + 0, bige_const) ^ tweak0 ^ rkey0;
	  b1 = VEC_LOAD_BE (in + 1, bige_const) ^ tweak1 ^ rkey0;
	  b2 = VEC_LOAD_BE (in + 2, bige_const) ^ tweak2 ^ rkey0;
	  b3 = VEC_LOAD_BE (in + 3, bige_const) ^ tweak3 ^ rkey0;

#define DO_ROUND(r) \
	      rkey = ALIGNED_LOAD (&rk[r]); \
	      b0 = vec_ncipher_be (b0, rkey); \
	      b1 = vec_ncipher_be (b1, rkey); \
	      b2 = vec_ncipher_be (b2, rkey); \
	      b3 = vec_ncipher_be (b3, rkey);

	  DO_ROUND(1);
	  DO_ROUND(2);
	  DO_ROUND(3);
	  DO_ROUND(4);
	  DO_ROUND(5);
	  DO_ROUND(6);
	  DO_ROUND(7);
	  DO_ROUND(8);
	  DO_ROUND(9);
	  if (rounds >= 12)
	    {
	      DO_ROUND(10);
	      DO_ROUND(11);
	      if (rounds > 12)
		{
		  DO_ROUND(12);
		  DO_ROUND(13);
		}
	    }

#undef DO_ROUND

	  rkey = rkeylast;
	  b0 = vec_ncipherlast_be (b0, rkey ^ tweak0);
	  b1 = vec_ncipherlast_be (b1, rkey ^ tweak1);
	  b2 = vec_ncipherlast_be (b2, rkey ^ tweak2);
	  b3 = vec_ncipherlast_be (b3, rkey ^ tweak3);

	  VEC_STORE_BE (out + 0, b0, bige_const);
	  VEC_STORE_BE (out + 1, b1, bige_const);
	  VEC_STORE_BE (out + 2, b2, bige_const);
	  VEC_STORE_BE (out + 3, b3, bige_const);

	  in += 4;
	  out += 4;
	  nblocks -= 4;
	}

      for (; nblocks; nblocks--)
	{
	  tweak = tweak_next;

	  /* Xor-Encrypt/Decrypt-Xor block. */
	  b = VEC_LOAD_BE (in, bige_const) ^ tweak;

	  /* Generate next tweak. */
	  GEN_TWEAK (tweak_next, tweak_tmp);

	  AES_DECRYPT (b, rounds);

	  b ^= tweak;
	  VEC_STORE_BE (out, b, bige_const);

	  in++;
	  out++;
	}
    }

  VEC_STORE_BE (tweak_arg, tweak_next, bige_const);

#undef GEN_TWEAK
}

#endif /* USE_PPC_CRYPTO */
