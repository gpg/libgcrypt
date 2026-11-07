/* t-sntrup761.c - SNTRUP761 internal arithmetic regression tests
 * Copyright (C) 2026 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
 * Reference functions derived from public domain source, written
 * by (in alphabetical order):
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Redirect internal dependencies so that including implementation does
   not require linking them.  */
#define _gcry_md_hash_buffer   t_sntrup761_md_hash_buffer
#define _gcry_ct_not_memequal  t_sntrup761_ct_not_memequal
#define _gcry_ct_memmov_cond   t_sntrup761_ct_memmov_cond

static void
t_sntrup761_md_hash_buffer (int algo, void *digest, const void *buf,
			    size_t len);

static unsigned int
t_sntrup761_ct_not_memequal (const void *b1, const void *b2, size_t len);

static void
t_sntrup761_ct_memmov_cond (void *dst, const void *src, size_t len,
			    unsigned long op_enable);

/* Include after implementation, as 't-common.h' pulls in public gcrypt.h
   which 'sntrup761.h' refuses to see.  */
#include "../cipher/sntrup761.c"

#define PGM "t-sntrup761"
#define NEED_HEX2BUFFER
#define NEED_MISMATCH
#include "t-common.h"

static void
t_sntrup761_md_hash_buffer (int algo, void *digest, const void *buf,
			    size_t len)
{
  gcry_md_hash_buffer (algo, digest, buf, len);
}

static unsigned int
t_sntrup761_ct_not_memequal (const void *b1, const void *b2, size_t len)
{
  return memcmp (b1, b2, len) != 0;
}

static void
t_sntrup761_ct_memmov_cond (void *dst, const void *src, size_t len,
			    unsigned long op_enable)
{
  if (op_enable)
    memmove (dst, src, len);
}

static uint32_t rng_counter;

static uint32_t
rng (void)
{
  unsigned char ctr[4], dig[20];

  ctr[0] = rng_counter;
  ctr[1] = rng_counter >> 8;
  ctr[2] = rng_counter >> 16;
  ctr[3] = rng_counter >> 24;
  rng_counter++;

  gcry_md_hash_buffer (GCRY_MD_SHA1, dig, ctr, sizeof (ctr));

  return ((uint32_t)dig[0] | ((uint32_t)dig[1] << 8)
	  | ((uint32_t)dig[2] << 16) | ((uint32_t)dig[3] << 24));
}

/* Canonical representative of X modulo M, in [0,M).  */
static long
ref_mod (long long x, long m)
{
  long long r = x % m;

  if (r < 0)
    r += m;
  return (long)r;
}

static int
ref_F3_freeze (long long x)
{
  return ref_mod (x + 1, 3) - 1;
}

static int
ref_Fq_freeze (long long x)
{
  return ref_mod (x + q12, q) - q12;
}

/* Multiplication in Z[x]/(q, x^p - x - 1).  */
static void
ref_Rq_mult_small (Fq *h, const Fq *f, const small *g)
{
  static long long fg[p + p - 1];
  int i, j;

  for (i = 0; i < p + p - 1; i++)
    fg[i] = 0;
  for (i = 0; i < p; i++)
    for (j = 0; j < p; j++)
      fg[i + j] += (long long)f[i] * g[j];
  for (i = p + p - 2; i >= p; i--)
    {
      fg[i - p] += fg[i];
      fg[i - p + 1] += fg[i];
    }
  for (i = 0; i < p; i++)
    h[i] = ref_Fq_freeze (fg[i]);
}

static void
ref_R3_mult (small *h, const small *f, const small *g)
{
  static long long fg[p + p - 1];
  int i, j;

  for (i = 0; i < p + p - 1; i++)
    fg[i] = 0;
  for (i = 0; i < p; i++)
    for (j = 0; j < p; j++)
      fg[i + j] += (long long)f[i] * g[j];
  for (i = p + p - 2; i >= p; i--)
    {
      fg[i - p] += fg[i];
      fg[i - p + 1] += fg[i];
    }
  for (i = 0; i < p; i++)
    h[i] = ref_F3_freeze (fg[i]);
}

static void
test_freeze_helpers (void)
{
  /* Coprime to q, so that sweep hits different residue every step.  */
  static const long sweep_step = 9973;
  static const long fq_extremes[] =
    {
      -2 * (long)q12 * q12, 2 * (long)q12 * q12,
      -2 * (long)q12 * q12 + 1, 2 * (long)q12 * q12 - 1,
      -(long)q12 * q12, (long)q12 * q12,
      -(long)p * q12, (long)p * q12
    };
  long x;
  unsigned int i;

  if (verbose)
    fprintf (stderr, PGM ": checking F3_freeze over all int16_t\n");
  for (x = -32768; x <= 32767; x++)
    {
      int got = F3_freeze ((int16_t)x);
      int want = ref_F3_freeze (x);

      if (got != want)
	fail ("F3_freeze(%ld): got %d, want %d", x, got, want);
    }

  if (verbose)
    fprintf (stderr, PGM ": checking Fq_freeze over reachable range\n");
  for (x = -(2 * (long)q12 + 8); x <= 2 * (long)q12 + 8; x++)
    {
      int got = Fq_freeze ((int32_t)x);
      int want = ref_Fq_freeze (x);

      if (got != want)
	fail ("Fq_freeze(%ld): got %d, want %d", x, got, want);
    }

  /* Widest values callers produce, from Rq_recip3.  */
  for (x = -2 * (long)q12 * q12; x <= 2 * (long)q12 * q12; x += sweep_step)
    {
      int got = Fq_freeze ((int32_t)x);
      int want = ref_Fq_freeze (x);

      if (got != want)
	fail ("Fq_freeze(%ld): got %d, want %d", x, got, want);
    }

  for (i = 0; i < DIM (fq_extremes); i++)
    {
      int got = Fq_freeze ((int32_t)fq_extremes[i]);
      int want = ref_Fq_freeze (fq_extremes[i]);

      if (got != want)
	fail ("Fq_freeze(%ld): got %d, want %d", fq_extremes[i], got, want);
    }
}

/* Input patterns maximize intermediate accumulators.  */
static void
make_inputs (int pattern, Fq *f, small *g)
{
  int i;

  switch (pattern)
    {
    case 0:
      for (i = 0; i < p; i++)
	{
	  f[i] = q12;
	  g[i] = 1;
	}
      break;
    case 1:
      for (i = 0; i < p; i++)
	{
	  f[i] = -q12;
	  g[i] = -1;
	}
      break;
    case 2:
      for (i = 0; i < p; i++)
	{
	  f[i] = q12;
	  g[i] = -1;
	}
      break;
    case 3:
      for (i = 0; i < p; i++)
	{
	  f[i] = q12;
	  g[i] = (i & 1) ? -1 : 1;
	}
      break;
    case 4:
      for (i = 0; i < p; i++)
	{
	  f[i] = (i & 1) ? -q12 : q12;
	  g[i] = 1;
	}
      break;
    case 5:
      for (i = 0; i < p; i++)
	{
	  f[i] = (rng () & 1) ? q12 : -q12;
	  g[i] = 1;
	}
      break;
    case 6:
      for (i = 0; i < p; i++)
	{
	  f[i] = 0;
	  g[i] = 0;
	}
      break;
    case 7:
      for (i = 0; i < p; i++)
	{
	  f[i] = 0;
	  g[i] = 0;
	}
      f[p - 1] = q12;
      g[p - 1] = -1;
      break;
    case 8:
      for (i = 0; i < p; i++)
	{
	  f[i] = q12;
	  g[i] = 0;
	}
      g[0] = 1;
      g[p - 1] = 1;
      break;
    case 9:
      for (i = 0; i < p; i++)
	{
	  f[i] = (int)(rng () % (2 * q12 + 1)) - q12;
	  g[i] = i < w ? ((rng () & 1) ? 1 : -1) : 0;
	}
      break;
    default:
      for (i = 0; i < p; i++)
	{
	  f[i] = (int)(rng () % (2 * q12 + 1)) - q12;
	  g[i] = (int)(rng () % 3) - 1;
	}
      break;
    }
}

static void
test_mult (void)
{
  static Fq f[p], h[p], h_ref[p];
  static small g[p], fs[p], h3[p], h3_ref[p];
  int pattern, i;

  for (pattern = 0; pattern < 32; pattern++)
    {
      rng_counter = pattern << 24;

      make_inputs (pattern, f, g);
      for (i = 0; i < p; i++)
	fs[i] = g[i];

      Rq_mult_small (h, f, g);
      ref_Rq_mult_small (h_ref, f, g);
      if (memcmp (h, h_ref, sizeof (h)))
	{
	  for (i = 0; i < p; i++)
	    if (h[i] != h_ref[i])
	      {
		fail ("Rq_mult_small pattern %d coeff %d: got %d, want %d",
		      pattern, i, (int)h[i], (int)h_ref[i]);
		break;
	      }
	}

      R3_mult (h3, fs, g);
      ref_R3_mult (h3_ref, fs, g);
      if (memcmp (h3, h3_ref, sizeof (h3)))
	{
	  for (i = 0; i < p; i++)
	    if (h3[i] != h3_ref[i])
	      {
		fail ("R3_mult pattern %d coeff %d: got %d, want %d",
		      pattern, i, (int)h3[i], (int)h3_ref[i]);
		break;
	      }
	}
    }
}

/* Inputs and checksums of libntruprime test suite.  */

#define CHECKSUM_RNG_BYTES 736
#define CHECKSUM_CT_BYTES (Ciphertexts_bytes + Confirm_bytes)

static unsigned char checksum_state[64];
static unsigned char known_random_key[32];
static unsigned char known_random_buf[CHECKSUM_RNG_BYTES];
static size_t known_random_pos;
static gcry_cipher_hd_t known_random_hd;
static gcry_cipher_hd_t salsa20_hd;
static uint64_t vector_random_ctr;

static void
salsa20_block (unsigned char *out, const unsigned char *in,
	       const unsigned char *key)
{
  gcry_error_t err;

  err = gcry_cipher_setkey (salsa20_hd, key, 32);
  if (!err)
    err = gcry_cipher_setiv (salsa20_hd, in, 16);
  memset (out, 0, 64);
  if (!err)
    err = gcry_cipher_encrypt (salsa20_hd, out, 64, NULL, 0);
  if (err)
    die ("Salsa20 failed: %s\n", gpg_strerror (err));
}

static void
checksum_clear (void)
{
  memset (checksum_state, 0, sizeof (checksum_state));
  memset (known_random_key, 0, sizeof (known_random_key));
  known_random_pos = CHECKSUM_RNG_BYTES;
  vector_random_ctr = 0;
}

static void
checksum_update (const unsigned char *x, size_t xlen)
{
  unsigned char block[16];

  while (xlen >= 16)
    {
      salsa20_block (checksum_state, x, checksum_state);
      x += 16;
      xlen -= 16;
    }

  memset (block, 0, sizeof (block));
  memcpy (block, x, xlen);
  block[xlen] = 1;
  checksum_state[0] ^= 1;
  salsa20_block (checksum_state, block, checksum_state);
}

static void
known_random (void *ctx, size_t length, uint8_t *dst)
{
  unsigned char block[32 + CHECKSUM_RNG_BYTES];
  gcry_error_t err;

  (void)ctx;

  while (length)
    {
      if (known_random_pos == CHECKSUM_RNG_BYTES)
	{
	  memset (block, 0, sizeof (block));
	  err = gcry_cipher_setkey (known_random_hd, known_random_key,
				    sizeof (known_random_key));
	  if (!err)
	    err = gcry_cipher_encrypt (known_random_hd, block, sizeof (block),
				       NULL, 0);
	  if (err)
	    die ("ChaCha20 failed: %s\n", gpg_strerror (err));
	  memcpy (known_random_key, block, sizeof (known_random_key));
	  memcpy (known_random_buf, block + 32, CHECKSUM_RNG_BYTES);
	  known_random_pos = 0;
	}
      *dst++ = known_random_buf[known_random_pos++];
      length--;
    }
}

static uint64_t
vector_random (void)
{
  static const unsigned char key[33] = "generate inputs for test vectors";
  unsigned char in[16], out[64];
  uint64_t v = le_bswap64 (vector_random_ctr++);

  memset (in, 0, sizeof (in));
  memcpy (in, &v, sizeof (v));

  salsa20_block (out, in, key);

  memcpy (&v, out, sizeof (v));
  return le_bswap64 (v);
}

static void
corrupt_ciphertext (unsigned char *ct)
{
  /* Expected checksums depend on value being drawn before position.  */
  uint64_t value = vector_random ();
  uint64_t pos = vector_random ();

  ct[pos % CHECKSUM_CT_BYTES] += 1 + (value % 255);
}

static void
test_checksums (void)
{
  static const struct
  {
    int loops;
    const char *checksum;
  } tv[] =
    {
      { 8, "4081ab3f61bac9aae91bff7f9b212855177591ec4427dff2a501be124c5bb97d" },
      { 64, "730a572b64fa05a42bce7b1573edc04b70ef75909db309c012aa27f53f1f2f41" }
    };
  static unsigned char pk[PublicKeys_bytes];
  static unsigned char sk[SecretKeys_bytes + PublicKeys_bytes
			  + Inputs_bytes + Hash_bytes];
  static unsigned char ct[CHECKSUM_CT_BYTES];
  unsigned char key1[32], key2[32];
  unsigned char *want;
  size_t wantlen;
  gcry_error_t err;
  unsigned int n;
  int i, loop;

  if (gcry_cipher_test_algo (GCRY_CIPHER_CHACHA20)
      || gcry_cipher_test_algo (GCRY_CIPHER_SALSA20)
      || gcry_md_test_algo (GCRY_MD_SHA512))
    {
      if (verbose)
	info ("ChaCha20, Salsa20 or SHA-512 not available, skipping checksums\n");
      return;
    }

  err = gcry_cipher_open (&known_random_hd, GCRY_CIPHER_CHACHA20,
			  GCRY_CIPHER_MODE_STREAM, 0);
  if (!err)
    err = gcry_cipher_open (&salsa20_hd, GCRY_CIPHER_SALSA20,
			    GCRY_CIPHER_MODE_STREAM, 0);
  if (err)
    die ("gcry_cipher_open failed: %s\n", gpg_strerror (err));

  for (n = 0; n < DIM (tv); n++)
    {
      checksum_clear ();

      for (loop = 0; loop < tv[n].loops; loop++)
	{
	  sntrup761_keypair (pk, sk, NULL, known_random);
	  checksum_update (pk, sizeof (pk));
	  checksum_update (sk, sizeof (sk));

	  sntrup761_enc (ct, key1, pk, NULL, known_random);
	  checksum_update (ct, sizeof (ct));
	  checksum_update (key1, sizeof (key1));

	  sntrup761_dec (key2, ct, sk);
	  if (memcmp (key1, key2, sizeof (key1)))
	    fail ("decapsulation mismatch, loop %d", loop);
	  checksum_update (key2, sizeof (key2));

	  for (i = 0; i < 3; i++)
	    {
	      corrupt_ciphertext (ct);
	      sntrup761_dec (key2, ct, sk);
	      checksum_update (key2, sizeof (key2));
	    }
	}

      want = hex2buffer (tv[n].checksum, &wantlen);
      if (!want)
	die ("invalid checksum string\n");
      if (memcmp (checksum_state, want, wantlen))
	{
	  mismatch (want, wantlen, checksum_state, wantlen);
	  fail ("checksum of %d loops mismatch", tv[n].loops);
	}
      xfree (want);
    }

  gcry_cipher_close (known_random_hd);
  gcry_cipher_close (salsa20_hd);
}

int
main (int argc, char **argv)
{
  int last_argc = -1;

  if (argc)
    {
      argc--;
      argv++;
    }

  while (argc && last_argc != argc)
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
	{
	  argc--;
	  argv++;
	  break;
	}
      else if (!strcmp (*argv, "--help"))
	{
	  fputs ("usage: " PGM " [--verbose]\n", stdout);
	  exit (0);
	}
      else if (!strcmp (*argv, "--verbose"))
	{
	  verbose++;
	  argc--;
	  argv++;
	}
      else if (!strncmp (*argv, "--", 2))
	{
	  fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
	  exit (1);
	}
    }

  xgcry_control ((GCRYCTL_SET_VERBOSITY, (int) verbose));

  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");

  xgcry_control ((GCRYCTL_DISABLE_SECMEM, 0));
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));
  xgcry_control ((GCRYCTL_ENABLE_QUICK_RANDOM, 0));

  test_freeze_helpers ();
  test_mult ();
  test_checksums ();

  if (verbose)
    fprintf (stderr, PGM ": %d error(s)\n", error_count);
  return !!error_count;
}
