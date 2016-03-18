/* poly1305.c  -  Poly1305 internals and generic implementation
 * Copyright (C) 2014 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

/* The code is based on public-domain Poly1305 implementation by
 * Andrew Moon at
 *  https://github.com/floodyberry/poly1305-opt
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "poly1305-internal.h"


static const char *selftest (void);



#ifdef POLY1305_USE_SSE2

void _gcry_poly1305_amd64_sse2_init_ext(void *state, const poly1305_key_t *key)
                                       OPS_FUNC_ABI;
unsigned int _gcry_poly1305_amd64_sse2_finish_ext(void *state, const byte *m,
						  size_t remaining,
						  byte mac[16]) OPS_FUNC_ABI;
unsigned int _gcry_poly1305_amd64_sse2_blocks(void *ctx, const byte *m,
					      size_t bytes) OPS_FUNC_ABI;

static const poly1305_ops_t poly1305_amd64_sse2_ops = {
  POLY1305_SSE2_BLOCKSIZE,
  _gcry_poly1305_amd64_sse2_init_ext,
  _gcry_poly1305_amd64_sse2_blocks,
  _gcry_poly1305_amd64_sse2_finish_ext
};

#endif


#ifdef POLY1305_USE_AVX2

void _gcry_poly1305_amd64_avx2_init_ext(void *state, const poly1305_key_t *key)
                                       OPS_FUNC_ABI;
unsigned int _gcry_poly1305_amd64_avx2_finish_ext(void *state, const byte *m,
						  size_t remaining,
						  byte mac[16]) OPS_FUNC_ABI;
unsigned int _gcry_poly1305_amd64_avx2_blocks(void *ctx, const byte *m,
					      size_t bytes) OPS_FUNC_ABI;

static const poly1305_ops_t poly1305_amd64_avx2_ops = {
  POLY1305_AVX2_BLOCKSIZE,
  _gcry_poly1305_amd64_avx2_init_ext,
  _gcry_poly1305_amd64_avx2_blocks,
  _gcry_poly1305_amd64_avx2_finish_ext
};

#endif


#ifdef POLY1305_USE_NEON

void _gcry_poly1305_armv7_neon_init_ext(void *state, const poly1305_key_t *key)
                                       OPS_FUNC_ABI;
unsigned int _gcry_poly1305_armv7_neon_finish_ext(void *state, const byte *m,
						  size_t remaining,
						  byte mac[16]) OPS_FUNC_ABI;
unsigned int _gcry_poly1305_armv7_neon_blocks(void *ctx, const byte *m,
					      size_t bytes) OPS_FUNC_ABI;

static const poly1305_ops_t poly1305_armv7_neon_ops = {
  POLY1305_NEON_BLOCKSIZE,
  _gcry_poly1305_armv7_neon_init_ext,
  _gcry_poly1305_armv7_neon_blocks,
  _gcry_poly1305_armv7_neon_finish_ext
};

#endif


/* Reference unoptimized poly1305 implementation using 32 bit * 32 bit = 64 bit
 * multiplication and 64 bit addition.
 */

typedef struct poly1305_state_ref32_s
{
  u32 r[5];
  u32 h[5];
  u32 pad[4];
  byte final;
} poly1305_state_ref32_t;


static OPS_FUNC_ABI void
poly1305_init_ext_ref32 (void *state, const poly1305_key_t * key)
{
  poly1305_state_ref32_t *st = (poly1305_state_ref32_t *) state;

  gcry_assert (sizeof (*st) + POLY1305_STATE_ALIGNMENT <=
	       sizeof (((poly1305_context_t *) 0)->state));

  /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
  st->r[0] = (buf_get_le32 (&key->b[0])) & 0x3ffffff;
  st->r[1] = (buf_get_le32 (&key->b[3]) >> 2) & 0x3ffff03;
  st->r[2] = (buf_get_le32 (&key->b[6]) >> 4) & 0x3ffc0ff;
  st->r[3] = (buf_get_le32 (&key->b[9]) >> 6) & 0x3f03fff;
  st->r[4] = (buf_get_le32 (&key->b[12]) >> 8) & 0x00fffff;

  /* h = 0 */
  st->h[0] = 0;
  st->h[1] = 0;
  st->h[2] = 0;
  st->h[3] = 0;
  st->h[4] = 0;

  /* save pad for later */
  st->pad[0] = buf_get_le32 (&key->b[16]);
  st->pad[1] = buf_get_le32 (&key->b[20]);
  st->pad[2] = buf_get_le32 (&key->b[24]);
  st->pad[3] = buf_get_le32 (&key->b[28]);

  st->final = 0;
}


static OPS_FUNC_ABI unsigned int
poly1305_blocks_ref32 (void *state, const byte * m, size_t bytes)
{
  poly1305_state_ref32_t *st = (poly1305_state_ref32_t *) state;
  const u32 hibit = (st->final) ? 0 : (1 << 24);	/* 1 << 128 */
  u32 r0, r1, r2, r3, r4;
  u32 s1, s2, s3, s4;
  u32 h0, h1, h2, h3, h4;
  u64 d0, d1, d2, d3, d4;
  u32 c;

  r0 = st->r[0];
  r1 = st->r[1];
  r2 = st->r[2];
  r3 = st->r[3];
  r4 = st->r[4];

  s1 = r1 * 5;
  s2 = r2 * 5;
  s3 = r3 * 5;
  s4 = r4 * 5;

  h0 = st->h[0];
  h1 = st->h[1];
  h2 = st->h[2];
  h3 = st->h[3];
  h4 = st->h[4];

  while (bytes >= POLY1305_REF_BLOCKSIZE)
    {
      /* h += m[i] */
      h0 += (buf_get_le32 (m + 0)) & 0x3ffffff;
      h1 += (buf_get_le32 (m + 3) >> 2) & 0x3ffffff;
      h2 += (buf_get_le32 (m + 6) >> 4) & 0x3ffffff;
      h3 += (buf_get_le32 (m + 9) >> 6) & 0x3ffffff;
      h4 += (buf_get_le32 (m + 12) >> 8) | hibit;

      /* h *= r */
      d0 =
	((u64) h0 * r0) + ((u64) h1 * s4) +
	((u64) h2 * s3) + ((u64) h3 * s2) + ((u64) h4 * s1);
      d1 =
	((u64) h0 * r1) + ((u64) h1 * r0) +
	((u64) h2 * s4) + ((u64) h3 * s3) + ((u64) h4 * s2);
      d2 =
	((u64) h0 * r2) + ((u64) h1 * r1) +
	((u64) h2 * r0) + ((u64) h3 * s4) + ((u64) h4 * s3);
      d3 =
	((u64) h0 * r3) + ((u64) h1 * r2) +
	((u64) h2 * r1) + ((u64) h3 * r0) + ((u64) h4 * s4);
      d4 =
	((u64) h0 * r4) + ((u64) h1 * r3) +
	((u64) h2 * r2) + ((u64) h3 * r1) + ((u64) h4 * r0);

      /* (partial) h %= p */
      c = (u32) (d0 >> 26);
      h0 = (u32) d0 & 0x3ffffff;
      d1 += c;
      c = (u32) (d1 >> 26);
      h1 = (u32) d1 & 0x3ffffff;
      d2 += c;
      c = (u32) (d2 >> 26);
      h2 = (u32) d2 & 0x3ffffff;
      d3 += c;
      c = (u32) (d3 >> 26);
      h3 = (u32) d3 & 0x3ffffff;
      d4 += c;
      c = (u32) (d4 >> 26);
      h4 = (u32) d4 & 0x3ffffff;
      h0 += c * 5;
      c = (h0 >> 26);
      h0 = h0 & 0x3ffffff;
      h1 += c;

      m += POLY1305_REF_BLOCKSIZE;
      bytes -= POLY1305_REF_BLOCKSIZE;
    }

  st->h[0] = h0;
  st->h[1] = h1;
  st->h[2] = h2;
  st->h[3] = h3;
  st->h[4] = h4;

  return (16 * sizeof (u32) + 5 * sizeof (u64) + 5 * sizeof (void *));
}


static OPS_FUNC_ABI unsigned int
poly1305_finish_ext_ref32 (void *state, const byte * m,
			   size_t remaining, byte mac[POLY1305_TAGLEN])
{
  poly1305_state_ref32_t *st = (poly1305_state_ref32_t *) state;
  u32 h0, h1, h2, h3, h4, c;
  u32 g0, g1, g2, g3, g4;
  u64 f;
  u32 mask;
  unsigned int burn = 0;

  /* process the remaining block */
  if (remaining)
    {
      byte final[POLY1305_REF_BLOCKSIZE] = { 0 };
      size_t i;
      for (i = 0; i < remaining; i++)
	final[i] = m[i];
      final[remaining] = 1;
      st->final = 1;
      burn = poly1305_blocks_ref32 (st, final, POLY1305_REF_BLOCKSIZE);
    }

  /* fully carry h */
  h0 = st->h[0];
  h1 = st->h[1];
  h2 = st->h[2];
  h3 = st->h[3];
  h4 = st->h[4];

  c = h1 >> 26;
  h1 = h1 & 0x3ffffff;
  h2 += c;
  c = h2 >> 26;
  h2 = h2 & 0x3ffffff;
  h3 += c;
  c = h3 >> 26;
  h3 = h3 & 0x3ffffff;
  h4 += c;
  c = h4 >> 26;
  h4 = h4 & 0x3ffffff;
  h0 += c * 5;
  c = h0 >> 26;
  h0 = h0 & 0x3ffffff;
  h1 += c;

  /* compute h + -p */
  g0 = h0 + 5;
  c = g0 >> 26;
  g0 &= 0x3ffffff;
  g1 = h1 + c;
  c = g1 >> 26;
  g1 &= 0x3ffffff;
  g2 = h2 + c;
  c = g2 >> 26;
  g2 &= 0x3ffffff;
  g3 = h3 + c;
  c = g3 >> 26;
  g3 &= 0x3ffffff;
  g4 = h4 + c - (1 << 26);

  /* select h if h < p, or h + -p if h >= p */
  mask = (g4 >> ((sizeof (u32) * 8) - 1)) - 1;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  /* h = h % (2^128) */
  h0 = ((h0) | (h1 << 26)) & 0xffffffff;
  h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
  h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

  /* mac = (h + pad) % (2^128) */
  f = (u64) h0 + st->pad[0];
  h0 = (u32) f;
  f = (u64) h1 + st->pad[1] + (f >> 32);
  h1 = (u32) f;
  f = (u64) h2 + st->pad[2] + (f >> 32);
  h2 = (u32) f;
  f = (u64) h3 + st->pad[3] + (f >> 32);
  h3 = (u32) f;

  buf_put_le32 (mac + 0, h0);
  buf_put_le32 (mac + 4, h1);
  buf_put_le32 (mac + 8, h2);
  buf_put_le32 (mac + 12, h3);

  /* zero out the state */
  st->h[0] = 0;
  st->h[1] = 0;
  st->h[2] = 0;
  st->h[3] = 0;
  st->h[4] = 0;
  st->r[0] = 0;
  st->r[1] = 0;
  st->r[2] = 0;
  st->r[3] = 0;
  st->r[4] = 0;
  st->pad[0] = 0;
  st->pad[1] = 0;
  st->pad[2] = 0;
  st->pad[3] = 0;

  /* burn_stack */
  return (13 * sizeof (u32) + sizeof (u64) +
	  POLY1305_REF_BLOCKSIZE + 6 * sizeof (void *)) + burn;
}


static const poly1305_ops_t poly1305_default_ops = {
  POLY1305_REF_BLOCKSIZE,
  poly1305_init_ext_ref32,
  poly1305_blocks_ref32,
  poly1305_finish_ext_ref32
};




static inline void *
poly1305_get_state (poly1305_context_t * ctx)
{
  byte *c = ctx->state;
  c += POLY1305_STATE_ALIGNMENT - 1;
  c -= (uintptr_t) c & (POLY1305_STATE_ALIGNMENT - 1);
  return c;
}


static void
poly1305_init (poly1305_context_t * ctx, const poly1305_key_t * key)
{
  void *state = poly1305_get_state (ctx);

  ctx->leftover = 0;

  ctx->ops->init_ext (state, key);
}


void
_gcry_poly1305_update (poly1305_context_t * ctx, const byte * m, size_t bytes)
{
  void *state = poly1305_get_state (ctx);
  unsigned int burn = 0;
  size_t block_size = ctx->ops->block_size;

  /* handle leftover */
  if (ctx->leftover)
    {
      size_t want = (block_size - ctx->leftover);
      if (want > bytes)
	want = bytes;
      buf_cpy (ctx->buffer + ctx->leftover, m, want);
      bytes -= want;
      m += want;
      ctx->leftover += want;
      if (ctx->leftover < block_size)
	return;
      burn = ctx->ops->blocks (state, ctx->buffer, block_size);
      ctx->leftover = 0;
    }

  /* process full blocks */
  if (bytes >= block_size)
    {
      size_t want = (bytes & ~(block_size - 1));
      burn = ctx->ops->blocks (state, m, want);
      m += want;
      bytes -= want;
    }

  /* store leftover */
  if (bytes)
    {
      buf_cpy (ctx->buffer + ctx->leftover, m, bytes);
      ctx->leftover += bytes;
    }

  if (burn)
    _gcry_burn_stack (burn);
}


void
_gcry_poly1305_finish (poly1305_context_t * ctx, byte mac[POLY1305_TAGLEN])
{
  void *state = poly1305_get_state (ctx);
  unsigned int burn;

  burn = ctx->ops->finish_ext (state, ctx->buffer, ctx->leftover, mac);

  _gcry_burn_stack (burn);
}


gcry_err_code_t
_gcry_poly1305_init (poly1305_context_t * ctx, const byte * key,
		     size_t keylen)
{
  static int initialized;
  static const char *selftest_failed;
  poly1305_key_t keytmp;
  unsigned int features = _gcry_get_hw_features ();

  if (!initialized)
    {
      initialized = 1;
      selftest_failed = selftest ();
      if (selftest_failed)
	log_error ("Poly1305 selftest failed (%s)\n", selftest_failed);
    }

  if (keylen != POLY1305_KEYLEN)
    return GPG_ERR_INV_KEYLEN;

  if (selftest_failed)
    return GPG_ERR_SELFTEST_FAILED;

#ifdef POLY1305_USE_SSE2
  ctx->ops = &poly1305_amd64_sse2_ops;
#else
  ctx->ops = &poly1305_default_ops;
#endif

#ifdef POLY1305_USE_AVX2
  if (features & HWF_INTEL_AVX2)
    ctx->ops = &poly1305_amd64_avx2_ops;
#endif
#ifdef POLY1305_USE_NEON
  if (features & HWF_ARM_NEON)
    ctx->ops = &poly1305_armv7_neon_ops;
#endif
  (void)features;

  buf_cpy (keytmp.b, key, POLY1305_KEYLEN);
  poly1305_init (ctx, &keytmp);

  wipememory (&keytmp, sizeof (keytmp));

  return 0;
}


static void
poly1305_auth (byte mac[POLY1305_TAGLEN], const byte * m, size_t bytes,
	       const byte * key)
{
  poly1305_context_t ctx;

  memset (&ctx, 0, sizeof (ctx));

  _gcry_poly1305_init (&ctx, key, POLY1305_KEYLEN);
  _gcry_poly1305_update (&ctx, m, bytes);
  _gcry_poly1305_finish (&ctx, mac);

  wipememory (&ctx, sizeof (ctx));
}


static const char *
selftest (void)
{
  /* example from nacl */
  static const byte nacl_key[POLY1305_KEYLEN] = {
    0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91,
    0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d, 0x3c, 0x25,
    0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65,
    0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80,
  };

  static const byte nacl_msg[131] = {
    0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
    0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
    0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
    0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
    0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
    0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
    0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
    0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
    0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
    0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
    0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
    0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
    0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
    0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
    0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
    0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
    0xe3, 0x55, 0xa5
  };

  static const byte nacl_mac[16] = {
    0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
    0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9
  };

  /* generates a final value of (2^130 - 2) == 3 */
  static const byte wrap_key[POLY1305_KEYLEN] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  static const byte wrap_msg[16] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
  };

  static const byte wrap_mac[16] = {
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  /* mac of the macs of messages of length 0 to 256, where the key and messages
   * have all their values set to the length
   */
  static const byte total_key[POLY1305_KEYLEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
  };

  static const byte total_mac[16] = {
    0x64, 0xaf, 0xe2, 0xe8, 0xd6, 0xad, 0x7b, 0xbd,
    0xd2, 0x87, 0xf9, 0x7c, 0x44, 0x62, 0x3d, 0x39
  };

  poly1305_context_t ctx;
  poly1305_context_t total_ctx;
  byte all_key[POLY1305_KEYLEN];
  byte all_msg[256];
  byte mac[16];
  size_t i, j;

  memset (&ctx, 0, sizeof (ctx));
  memset (&total_ctx, 0, sizeof (total_ctx));

  memset (mac, 0, sizeof (mac));
  poly1305_auth (mac, nacl_msg, sizeof (nacl_msg), nacl_key);
  if (memcmp (nacl_mac, mac, sizeof (nacl_mac)) != 0)
    return "Poly1305 test 1 failed.";

  /* SSE2/AVX have a 32 byte block size, but also support 64 byte blocks, so
   * make sure everything still works varying between them */
  memset (mac, 0, sizeof (mac));
  _gcry_poly1305_init (&ctx, nacl_key, POLY1305_KEYLEN);
  _gcry_poly1305_update (&ctx, nacl_msg + 0, 32);
  _gcry_poly1305_update (&ctx, nacl_msg + 32, 64);
  _gcry_poly1305_update (&ctx, nacl_msg + 96, 16);
  _gcry_poly1305_update (&ctx, nacl_msg + 112, 8);
  _gcry_poly1305_update (&ctx, nacl_msg + 120, 4);
  _gcry_poly1305_update (&ctx, nacl_msg + 124, 2);
  _gcry_poly1305_update (&ctx, nacl_msg + 126, 1);
  _gcry_poly1305_update (&ctx, nacl_msg + 127, 1);
  _gcry_poly1305_update (&ctx, nacl_msg + 128, 1);
  _gcry_poly1305_update (&ctx, nacl_msg + 129, 1);
  _gcry_poly1305_update (&ctx, nacl_msg + 130, 1);
  _gcry_poly1305_finish (&ctx, mac);
  if (memcmp (nacl_mac, mac, sizeof (nacl_mac)) != 0)
    return "Poly1305 test 2 failed.";

  memset (mac, 0, sizeof (mac));
  poly1305_auth (mac, wrap_msg, sizeof (wrap_msg), wrap_key);
  if (memcmp (wrap_mac, mac, sizeof (nacl_mac)) != 0)
    return "Poly1305 test 3 failed.";

  _gcry_poly1305_init (&total_ctx, total_key, POLY1305_KEYLEN);
  for (i = 0; i < 256; i++)
    {
      /* set key and message to 'i,i,i..' */
      for (j = 0; j < sizeof (all_key); j++)
	all_key[j] = i;
      for (j = 0; j < i; j++)
	all_msg[j] = i;
      poly1305_auth (mac, all_msg, i, all_key);
      _gcry_poly1305_update (&total_ctx, mac, 16);
    }
  _gcry_poly1305_finish (&total_ctx, mac);
  if (memcmp (total_mac, mac, sizeof (total_mac)) != 0)
    return "Poly1305 test 4 failed.";

  return NULL;
}
