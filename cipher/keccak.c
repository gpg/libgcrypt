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



typedef struct
{
  u64 h0;
} KECCAK_STATE;


typedef struct
{
  gcry_md_block_ctx_t bctx;
  KECCAK_STATE state;
} KECCAK_CONTEXT;



static void
keccak_init (int algo, void *context, unsigned int flags)
{
  KECCAK_CONTEXT *ctx = context;
  KECCAK_STATE *hd = &ctx->state;
  unsigned int features = _gcry_get_hw_features ();

  (void)flags;

  memset (hd, 0, sizeof *hd);

  ctx->bctx.nblocks = 0;
  ctx->bctx.nblocks_high = 0;
  ctx->bctx.count = 0;
  ctx->bctx.blocksize = 128;
  ctx->bctx.bwrite = NULL;

  (void)features;
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
  KECCAK_CONTEXT *hd = context;
  unsigned int stack_burn_depth;

  _gcry_md_block_write (context, NULL, 0); /* flush */ ;
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
  return 0;
#if 0
  const char *what;
  const char *errtxt;

  /* FIXME: Add a switch(algo) or use several functions.  */
  what = "short string";
  errtxt = _gcry_hash_selftest_check_one
    (GCRY_MD_SHA3_384, 0,
     "abc", 3,
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 48);
  if (errtxt)
    goto failed;

  if (extended)
    {
      what = "long string";
      errtxt = _gcry_hash_selftest_check_one
        (GCRY_MD_SHA3_384, 0,
         "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",48);
      if (errtxt)
        goto failed;

      what = "one million \"a\"";
      errtxt = _gcry_hash_selftest_check_one
        (GCRY_MD_SHA3_384, 1,
         NULL, 0,
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",48);
      if (errtxt)
        goto failed;
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("digest", algo, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
#endif
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
    { "?" },
    /* PKCS#1 sha3_224WithRSAEncryption */
    { "?" },
    { NULL }
  };
static byte sha3_256_asn[] = { 0x30 };
static gcry_md_oid_spec_t oid_spec_sha3_256[] =
  {
    { "?" },
    /* PKCS#1 sha3_256WithRSAEncryption */
    { "?" },
    { NULL }
  };
static byte sha3_384_asn[] = { 0x30 };
static gcry_md_oid_spec_t oid_spec_sha3_384[] =
  {
    { "?" },
    /* PKCS#1 sha3_384WithRSAEncryption */
    { "?" },
    { NULL }
  };
static byte sha3_512_asn[] = { 0x30 };
static gcry_md_oid_spec_t oid_spec_sha3_512[] =
  {
    { "?" },
    /* PKCS#1 sha3_512WithRSAEncryption */
    { "?" },
    { NULL }
  };


gcry_md_spec_t _gcry_digest_spec_sha3_224 =
  {
    GCRY_MD_SHA3_224, {0, 1},
    "SHA3-224", sha3_224_asn, DIM (sha3_224_asn), oid_spec_sha3_224, 64,
    sha3_224_init, _gcry_md_block_write, keccak_final, keccak_read,
    sizeof (KECCAK_CONTEXT),
    run_selftests
  };
gcry_md_spec_t _gcry_digest_spec_sha3_256 =
  {
    GCRY_MD_SHA3_256, {0, 1},
    "SHA3-256", sha3_256_asn, DIM (sha3_256_asn), oid_spec_sha3_256, 64,
    sha3_256_init, _gcry_md_block_write, keccak_final, keccak_read,
    sizeof (KECCAK_CONTEXT),
    run_selftests
  };
gcry_md_spec_t _gcry_digest_spec_sha3_384 =
  {
    GCRY_MD_SHA3_384, {0, 1},
    "SHA3-384", sha3_384_asn, DIM (sha3_384_asn), oid_spec_sha3_384, 64,
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
