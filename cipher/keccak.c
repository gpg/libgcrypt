/* keccak.c - SHA3 hash functions
 * Copyright (C) 2015  g10 Code GmbH
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
#include <string.h>
#include "g10lib.h"
#include "bithelp.h"
#include "bufhelp.h"
#include "cipher.h"
#include "hash-common.h"


/* The code is based on public-domain/CC0 "Keccak-readable-and-compact.c"
 * implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
 * Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer. From:
 *   https://github.com/gvanas/KeccakCodePackage
 */


#define SHA3_DELIMITED_SUFFIX 0x06
#define SHAKE_DELIMITED_SUFFIX 0x1F


typedef struct
{
  u64 state[5][5];
} KECCAK_STATE;


typedef struct
{
  gcry_md_block_ctx_t bctx;
  KECCAK_STATE state;
  unsigned int outlen;
} KECCAK_CONTEXT;


static inline u64
rol64 (u64 x, unsigned int n)
{
  return ((x << n) | (x >> (64 - n)));
}

/* Function that computes the Keccak-f[1600] permutation on the given state. */
static unsigned int keccak_f1600_state_permute(KECCAK_STATE *hd)
{
  static const u64 round_consts[24] =
  {
    U64_C(0x0000000000000001), U64_C(0x0000000000008082),
    U64_C(0x800000000000808A), U64_C(0x8000000080008000),
    U64_C(0x000000000000808B), U64_C(0x0000000080000001),
    U64_C(0x8000000080008081), U64_C(0x8000000000008009),
    U64_C(0x000000000000008A), U64_C(0x0000000000000088),
    U64_C(0x0000000080008009), U64_C(0x000000008000000A),
    U64_C(0x000000008000808B), U64_C(0x800000000000008B),
    U64_C(0x8000000000008089), U64_C(0x8000000000008003),
    U64_C(0x8000000000008002), U64_C(0x8000000000000080),
    U64_C(0x000000000000800A), U64_C(0x800000008000000A),
    U64_C(0x8000000080008081), U64_C(0x8000000000008080),
    U64_C(0x0000000080000001), U64_C(0x8000000080008008)
  };
  unsigned int round;

  for (round = 0; round < 24; round++)
    {
      {
	/* θ step (see [Keccak Reference, Section 2.3.2]) === */
	u64 C[5], D[5];

	/* Compute the parity of the columns */
	C[0] = hd->state[0][0] ^ hd->state[1][0] ^ hd->state[2][0]
	      ^ hd->state[3][0] ^ hd->state[4][0];
	C[1] = hd->state[0][1] ^ hd->state[1][1] ^ hd->state[2][1]
	      ^ hd->state[3][1] ^ hd->state[4][1];
	C[2] = hd->state[0][2] ^ hd->state[1][2] ^ hd->state[2][2]
	      ^ hd->state[3][2] ^ hd->state[4][2];
	C[3] = hd->state[0][3] ^ hd->state[1][3] ^ hd->state[2][3]
	      ^ hd->state[3][3] ^ hd->state[4][3];
	C[4] = hd->state[0][4] ^ hd->state[1][4] ^ hd->state[2][4]
	      ^ hd->state[3][4] ^ hd->state[4][4];

	/* Compute the θ effect for a given column */
	D[0] = C[4] ^ rol64(C[1], 1);
	D[1] = C[0] ^ rol64(C[2], 1);
	D[2] = C[1] ^ rol64(C[3], 1);
	D[4] = C[2] ^ rol64(C[4], 1);
	D[5] = C[3] ^ rol64(C[0], 1);

	/* Add the θ effect to the whole column */
	hd->state[0][0] ^= D[0];
	hd->state[1][0] ^= D[0];
	hd->state[2][0] ^= D[0];
	hd->state[3][0] ^= D[0];
	hd->state[4][0] ^= D[0];

	/* Add the θ effect to the whole column */
	hd->state[0][1] ^= D[1];
	hd->state[1][1] ^= D[1];
	hd->state[2][1] ^= D[1];
	hd->state[3][1] ^= D[1];
	hd->state[4][1] ^= D[1];

	/* Add the θ effect to the whole column */
	hd->state[0][2] ^= D[2];
	hd->state[1][2] ^= D[2];
	hd->state[2][2] ^= D[2];
	hd->state[3][2] ^= D[2];
	hd->state[4][2] ^= D[2];

	/* Add the θ effect to the whole column */
	hd->state[0][3] ^= D[4];
	hd->state[1][3] ^= D[4];
	hd->state[2][3] ^= D[4];
	hd->state[3][3] ^= D[4];
	hd->state[4][3] ^= D[4];

	/* Add the θ effect to the whole column */
	hd->state[0][4] ^= D[5];
	hd->state[1][4] ^= D[5];
	hd->state[2][4] ^= D[5];
	hd->state[3][4] ^= D[5];
	hd->state[4][4] ^= D[5];
      }

      {
	/* ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) */
	u64 current, temp;

#define do_swap_n_rol(x, y, r) \
  temp = hd->state[y][x]; \
  hd->state[y][x] = rol64(current, r); \
  current = temp;

	/* Start at coordinates (1 0) */
	current = hd->state[0][1];

	/* Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
	do_swap_n_rol(0, 2, 1);
	do_swap_n_rol(2, 1, 3);
	do_swap_n_rol(1, 2, 6);
	do_swap_n_rol(2, 3, 10);
	do_swap_n_rol(3, 3, 15);
	do_swap_n_rol(3, 0, 21);
	do_swap_n_rol(0, 1, 28);
	do_swap_n_rol(1, 3, 36);
	do_swap_n_rol(3, 1, 45);
	do_swap_n_rol(1, 4, 55);
	do_swap_n_rol(4, 4, 2);
	do_swap_n_rol(4, 0, 14);
	do_swap_n_rol(0, 3, 27);
	do_swap_n_rol(3, 4, 41);
	do_swap_n_rol(4, 3, 56);
	do_swap_n_rol(3, 2, 8);
	do_swap_n_rol(2, 2, 25);
	do_swap_n_rol(2, 0, 43);
	do_swap_n_rol(0, 4, 62);
	do_swap_n_rol(4, 2, 18);
	do_swap_n_rol(2, 4, 39);
	do_swap_n_rol(4, 1, 61);
	do_swap_n_rol(1, 1, 20);
	do_swap_n_rol(1, 0, 44);

#undef do_swap_n_rol
      }

      {
	/* χ step (see [Keccak Reference, Section 2.3.1]) */
	u64 temp[5];

#define do_x_step_for_plane(y) \
  /* Take a copy of the plane */ \
  temp[0] = hd->state[y][0]; \
  temp[1] = hd->state[y][1]; \
  temp[2] = hd->state[y][2]; \
  temp[3] = hd->state[y][3]; \
  temp[4] = hd->state[y][4]; \
  \
  /* Compute χ on the plane */ \
  hd->state[y][0] = temp[0] ^ ((~temp[1]) & temp[2]); \
  hd->state[y][1] = temp[1] ^ ((~temp[2]) & temp[3]); \
  hd->state[y][2] = temp[2] ^ ((~temp[3]) & temp[4]); \
  hd->state[y][3] = temp[3] ^ ((~temp[4]) & temp[0]); \
  hd->state[y][4] = temp[4] ^ ((~temp[0]) & temp[1]);

	do_x_step_for_plane(0);
	do_x_step_for_plane(1);
	do_x_step_for_plane(2);
	do_x_step_for_plane(3);
	do_x_step_for_plane(4);

#undef do_x_step_for_plane
      }

      {
	/* ι step (see [Keccak Reference, Section 2.3.5]) */

	hd->state[0][0] ^= round_consts[round];
      }
    }

  return sizeof(void *) * 4 + sizeof(u64) * 10;
}


static unsigned int
transform_blk (void *context, const unsigned char *data)
{
  KECCAK_CONTEXT *ctx = context;
  KECCAK_STATE *hd = &ctx->state;
  u64 *state = (u64 *)hd->state;
  const size_t bsize = ctx->bctx.blocksize;
  unsigned int i;

  /* Absorb input block. */
  for (i = 0; i < bsize / 8; i++)
    state[i] ^= buf_get_le64(data + i * 8);

  return keccak_f1600_state_permute(hd) + 4 * sizeof(void *);
}


static unsigned int
transform (void *context, const unsigned char *data, size_t nblks)
{
  KECCAK_CONTEXT *ctx = context;
  const size_t bsize = ctx->bctx.blocksize;
  unsigned int burn;

  /* Absorb full blocks. */
  do
    {
      burn = transform_blk (context, data);
      data += bsize;
    }
  while (--nblks);

  return burn;
}


static void
keccak_init (int algo, void *context, unsigned int flags)
{
  KECCAK_CONTEXT *ctx = context;
  KECCAK_STATE *hd = &ctx->state;
  unsigned int features = _gcry_get_hw_features ();

  (void)flags;
  (void)features;

  memset (hd, 0, sizeof *hd);

  ctx->bctx.nblocks = 0;
  ctx->bctx.nblocks_high = 0;
  ctx->bctx.count = 0;
  ctx->bctx.bwrite = transform;

  /* Set input block size, in Keccak terms this is called 'rate'. */

  switch (algo)
    {
    case GCRY_MD_SHA3_224:
      ctx->bctx.blocksize = 1152 / 8;
      ctx->outlen = 224 / 8;
      break;
    case GCRY_MD_SHA3_256:
      ctx->bctx.blocksize = 1088 / 8;
      ctx->outlen = 256 / 8;
      break;
    case GCRY_MD_SHA3_384:
      ctx->bctx.blocksize = 832 / 8;
      ctx->outlen = 384 / 8;
      break;
    case GCRY_MD_SHA3_512:
      ctx->bctx.blocksize = 576 / 8;
      ctx->outlen = 512 / 8;
      break;
    default:
      BUG();
    }
}

static void
sha3_224_init (void *context, unsigned int flags)
{
  keccak_init (GCRY_MD_SHA3_224, context, flags);
}

static void
sha3_256_init (void *context, unsigned int flags)
{
  keccak_init (GCRY_MD_SHA3_256, context, flags);
}

static void
sha3_384_init (void *context, unsigned int flags)
{
  keccak_init (GCRY_MD_SHA3_384, context, flags);
}

static void
sha3_512_init (void *context, unsigned int flags)
{
  keccak_init (GCRY_MD_SHA3_512, context, flags);
}


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 64 bytes representing the digest.  When used for sha384,
 * we take the leftmost 48 of those bytes.
 */
static void
keccak_final (void *context)
{
  KECCAK_CONTEXT *ctx = context;
  KECCAK_STATE *hd = &ctx->state;
  const size_t bsize = ctx->bctx.blocksize;
  const byte suffix = SHA3_DELIMITED_SUFFIX;
  u64 *state = (u64 *)hd->state;
  unsigned int stack_burn_depth;
  unsigned int lastbytes;
  unsigned int i;
  byte *buf;

  _gcry_md_block_write (context, NULL, 0); /* flush */

  buf = ctx->bctx.buf;
  lastbytes = ctx->bctx.count;

  /* Absorb remaining bytes. */
  for (i = 0; i < lastbytes / 8; i++)
    {
      state[i] ^= buf_get_le64(buf);
      buf += 8;
    }

  for (i = 0; i < lastbytes % 8; i++)
    {
      state[lastbytes / 8] ^= (u64)*buf << (i * 8);
      buf++;
    }

  /* Do the padding and switch to the squeezing phase */

  /* Absorb the last few bits and add the first bit of padding (which
     coincides with the delimiter in delimited suffix) */
  state[lastbytes / 8] ^= (u64)suffix << ((lastbytes % 8) * 8);

  /* Add the second bit of padding. */
  state[(bsize - 1) / 8] ^= (u64)0x80 << (((bsize - 1) % 8) * 8);

  /* Switch to the squeezing phase. */
  stack_burn_depth = keccak_f1600_state_permute(hd);

  /* Squeeze out all the output blocks */
  if (ctx->outlen < bsize)
    {
      /* Output SHA3 digest. */
      buf = ctx->bctx.buf;
      for (i = 0; i < ctx->outlen / 8; i++)
	{
	  buf_put_le64(buf, state[i]);
	  buf += 8;
	}
      for (i = 0; i < ctx->outlen % 8; i++)
	{
	  *buf = state[ctx->outlen / 8] >> (i * 8);
	  buf++;
	}
    }
  else
    {
      /* Output SHAKE digest. */
      BUG();
    }

  _gcry_burn_stack (stack_burn_depth);
}


static byte *
keccak_read (void *context)
{
  KECCAK_CONTEXT *hd = (KECCAK_CONTEXT *) context;
  return hd->bctx.buf;
}



/*
     Self-test section.
 */


static gpg_err_code_t
selftests_keccak (int algo, int extended, selftest_report_func_t report)
{
  const char *what;
  const char *errtxt;
  const char *short_hash;
  const char *long_hash;
  const char *one_million_a_hash;
  int hash_len;

  switch (algo)
  {
    default:
      BUG();

    case GCRY_MD_SHA3_224:
      short_hash =
	"\xe6\x42\x82\x4c\x3f\x8c\xf2\x4a\xd0\x92\x34\xee\x7d\x3c\x76\x6f"
	"\xc9\xa3\xa5\x16\x8d\x0c\x94\xad\x73\xb4\x6f\xdf";
      long_hash =
	"\x54\x3e\x68\x68\xe1\x66\x6c\x1a\x64\x36\x30\xdf\x77\x36\x7a\xe5"
	"\xa6\x2a\x85\x07\x0a\x51\xc1\x4c\xbf\x66\x5c\xbc";
      one_million_a_hash =
	"\xd6\x93\x35\xb9\x33\x25\x19\x2e\x51\x6a\x91\x2e\x6d\x19\xa1\x5c"
	"\xb5\x1c\x6e\xd5\xc1\x52\x43\xe7\xa7\xfd\x65\x3c";
      hash_len = 28;
      break;

    case GCRY_MD_SHA3_256:
      short_hash =
	"\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2\x04\x5c\x17\x2d\x6b\xd3\x90\xbd"
	"\x85\x5f\x08\x6e\x3e\x9d\x52\x5b\x46\xbf\xe2\x45\x11\x43\x15\x32";
      long_hash =
	"\x91\x6f\x60\x61\xfe\x87\x97\x41\xca\x64\x69\xb4\x39\x71\xdf\xdb"
	"\x28\xb1\xa3\x2d\xc3\x6c\xb3\x25\x4e\x81\x2b\xe2\x7a\xad\x1d\x18";
      one_million_a_hash =
	"\x5c\x88\x75\xae\x47\x4a\x36\x34\xba\x4f\xd5\x5e\xc8\x5b\xff\xd6"
	"\x61\xf3\x2a\xca\x75\xc6\xd6\x99\xd0\xcd\xcb\x6c\x11\x58\x91\xc1";
      hash_len = 32;
      break;

    case GCRY_MD_SHA3_384:
      short_hash =
	"\xec\x01\x49\x82\x88\x51\x6f\xc9\x26\x45\x9f\x58\xe2\xc6\xad\x8d"
	"\xf9\xb4\x73\xcb\x0f\xc0\x8c\x25\x96\xda\x7c\xf0\xe4\x9b\xe4\xb2"
	"\x98\xd8\x8c\xea\x92\x7a\xc7\xf5\x39\xf1\xed\xf2\x28\x37\x6d\x25";
      long_hash =
	"\x79\x40\x7d\x3b\x59\x16\xb5\x9c\x3e\x30\xb0\x98\x22\x97\x47\x91"
	"\xc3\x13\xfb\x9e\xcc\x84\x9e\x40\x6f\x23\x59\x2d\x04\xf6\x25\xdc"
	"\x8c\x70\x9b\x98\xb4\x3b\x38\x52\xb3\x37\x21\x61\x79\xaa\x7f\xc7";
      one_million_a_hash =
	"\xee\xe9\xe2\x4d\x78\xc1\x85\x53\x37\x98\x34\x51\xdf\x97\xc8\xad"
	"\x9e\xed\xf2\x56\xc6\x33\x4f\x8e\x94\x8d\x25\x2d\x5e\x0e\x76\x84"
	"\x7a\xa0\x77\x4d\xdb\x90\xa8\x42\x19\x0d\x2c\x55\x8b\x4b\x83\x40";
      hash_len = 48;
      break;

    case GCRY_MD_SHA3_512:
      short_hash =
	"\xb7\x51\x85\x0b\x1a\x57\x16\x8a\x56\x93\xcd\x92\x4b\x6b\x09\x6e"
	"\x08\xf6\x21\x82\x74\x44\xf7\x0d\x88\x4f\x5d\x02\x40\xd2\x71\x2e"
	"\x10\xe1\x16\xe9\x19\x2a\xf3\xc9\x1a\x7e\xc5\x76\x47\xe3\x93\x40"
	"\x57\x34\x0b\x4c\xf4\x08\xd5\xa5\x65\x92\xf8\x27\x4e\xec\x53\xf0";
      long_hash =
	"\xaf\xeb\xb2\xef\x54\x2e\x65\x79\xc5\x0c\xad\x06\xd2\xe5\x78\xf9"
	"\xf8\xdd\x68\x81\xd7\xdc\x82\x4d\x26\x36\x0f\xee\xbf\x18\xa4\xfa"
	"\x73\xe3\x26\x11\x22\x94\x8e\xfc\xfd\x49\x2e\x74\xe8\x2e\x21\x89"
	"\xed\x0f\xb4\x40\xd1\x87\xf3\x82\x27\x0c\xb4\x55\xf2\x1d\xd1\x85";
      one_million_a_hash =
	"\x3c\x3a\x87\x6d\xa1\x40\x34\xab\x60\x62\x7c\x07\x7b\xb9\x8f\x7e"
	"\x12\x0a\x2a\x53\x70\x21\x2d\xff\xb3\x38\x5a\x18\xd4\xf3\x88\x59"
	"\xed\x31\x1d\x0a\x9d\x51\x41\xce\x9c\xc5\xc6\x6e\xe6\x89\xb2\x66"
	"\xa8\xaa\x18\xac\xe8\x28\x2a\x0e\x0d\xb5\x96\xc9\x0b\x0a\x7b\x87";
      hash_len = 64;
      break;
  }

  what = "short string";
  errtxt = _gcry_hash_selftest_check_one (algo, 0, "abc", 3, short_hash,
					  hash_len);
  if (errtxt)
    goto failed;

  if (extended)
    {
      what = "long string";
      errtxt = _gcry_hash_selftest_check_one
	(algo, 0,
	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
	"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
	long_hash, hash_len);
      if (errtxt)
	goto failed;

      what = "one million \"a\"";
      errtxt = _gcry_hash_selftest_check_one (algo, 1, NULL, 0,
					      one_million_a_hash, hash_len);
      if (errtxt)
	goto failed;
    }

  return 0; /* Succeeded. */

failed:
  if (report)
    report ("digest", algo, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}


/* Run a full self-test for ALGO and return 0 on success.  */
static gpg_err_code_t
run_selftests (int algo, int extended, selftest_report_func_t report)
{
  gpg_err_code_t ec;

  switch (algo)
    {
    case GCRY_MD_SHA3_224:
    case GCRY_MD_SHA3_256:
    case GCRY_MD_SHA3_384:
    case GCRY_MD_SHA3_512:
      ec = selftests_keccak (algo, extended, report);
      break;
    default:
      ec = GPG_ERR_DIGEST_ALGO;
      break;
    }

  return ec;
}




static byte sha3_224_asn[] = { 0x30 };
static gcry_md_oid_spec_t oid_spec_sha3_224[] =
  {
    { "2.16.840.1.101.3.4.2.7" },
    /* PKCS#1 sha3_224WithRSAEncryption */
    { "?" },
    { NULL }
  };
static byte sha3_256_asn[] = { 0x30 };
static gcry_md_oid_spec_t oid_spec_sha3_256[] =
  {
    { "2.16.840.1.101.3.4.2.8" },
    /* PKCS#1 sha3_256WithRSAEncryption */
    { "?" },
    { NULL }
  };
static byte sha3_384_asn[] = { 0x30 };
static gcry_md_oid_spec_t oid_spec_sha3_384[] =
  {
    { "2.16.840.1.101.3.4.2.9" },
    /* PKCS#1 sha3_384WithRSAEncryption */
    { "?" },
    { NULL }
  };
static byte sha3_512_asn[] = { 0x30 };
static gcry_md_oid_spec_t oid_spec_sha3_512[] =
  {
    { "2.16.840.1.101.3.4.2.10" },
    /* PKCS#1 sha3_512WithRSAEncryption */
    { "?" },
    { NULL }
  };


gcry_md_spec_t _gcry_digest_spec_sha3_224 =
  {
    GCRY_MD_SHA3_224, {0, 1},
    "SHA3-224", sha3_224_asn, DIM (sha3_224_asn), oid_spec_sha3_224, 28,
    sha3_224_init, _gcry_md_block_write, keccak_final, keccak_read,
    sizeof (KECCAK_CONTEXT),
    run_selftests
  };
gcry_md_spec_t _gcry_digest_spec_sha3_256 =
  {
    GCRY_MD_SHA3_256, {0, 1},
    "SHA3-256", sha3_256_asn, DIM (sha3_256_asn), oid_spec_sha3_256, 32,
    sha3_256_init, _gcry_md_block_write, keccak_final, keccak_read,
    sizeof (KECCAK_CONTEXT),
    run_selftests
  };
gcry_md_spec_t _gcry_digest_spec_sha3_384 =
  {
    GCRY_MD_SHA3_384, {0, 1},
    "SHA3-384", sha3_384_asn, DIM (sha3_384_asn), oid_spec_sha3_384, 48,
    sha3_384_init, _gcry_md_block_write, keccak_final, keccak_read,
    sizeof (KECCAK_CONTEXT),
    run_selftests
  };
gcry_md_spec_t _gcry_digest_spec_sha3_512 =
  {
    GCRY_MD_SHA3_512, {0, 1},
    "SHA3-512", sha3_512_asn, DIM (sha3_512_asn), oid_spec_sha3_512, 64,
    sha3_512_init, _gcry_md_block_write, keccak_final, keccak_read,
    sizeof (KECCAK_CONTEXT),
    run_selftests
  };
