/* curves.c -  ECC curves regression tests
 *	Copyright (C) 2011 Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../src/gcrypt-int.h"

/* Number of curves defined in ../cipger/ecc.c */
#define N_CURVES 22

/* A real world sample public key.  */
static char const sample_key_1[] =
"(public-key\n"
" (ecdsa\n"
"  (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)\n"
"  (a #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC#)\n"
"  (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)\n"
"  (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)\n"
"  (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)\n"
"  (q #0442B927242237639A36CE9221B340DB1A9AB76DF2FE3E171277F6A4023DED146EE"
      "86525E38CCECFF3FB8D152CC6334F70D23A525175C1BCBDDE6E023B2228770E#)\n"
"  ))";
static char const sample_key_1_curve[] = "NIST P-256";
static unsigned int sample_key_1_nbits = 256;

/* A made up sample public key.  */
static char const sample_key_2[] =
"(public-key\n"
" (ecdh\n"
"  (p #00e95e4a5f737059dc60dfc7ad95b3d8139515620f#)\n"
"  (a #340e7be2a280eb74e2be61bada745d97e8f7c300#)\n"
"  (b #1e589a8595423412134faa2dbdec95c8d8675e58#)\n"
"  (g #04bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3"
        "1667cb477a1a8ec338f94741669c976316da6321#)\n"
"  (n #00e95e4a5f737059dc60df5991d45029409e60fc09#)\n"
"  (q #041111111111111111111111111111111111111111"
        "2222222222222222222222222222222222222222#)\n"
"  ))";
static char const sample_key_2_curve[] = "brainpoolP160r1";
static unsigned int sample_key_2_nbits = 160;


/* Another sample public key.  */
static char const sample_key_3[] =
"(public-key\n"
" (ecdh\n"
"  (curve Curve25519)\n"
"  (q #040000000000000000000000000000000000000000000000000000000000000000"
"        0000000000000000000000000000000000000000000000000000000000000000#)\n"
"  ))";
static char const sample_key_3_curve[] = "Curve25519";
static unsigned int sample_key_3_nbits = 256;


/* Program option flags.  */
static int verbose;
static int error_count;

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
}

static void
die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
}


static void
list_curves (void)
{
  int idx;
  const char *name;
  unsigned int nbits;

  for (idx=0; (name = gcry_pk_get_curve (NULL, idx, &nbits)); idx++)
    {
      if (verbose)
        printf ("%s - %u bits\n", name, nbits);
    }
  if (idx != N_CURVES)
    fail ("expected %d curves but got %d\n", N_CURVES, idx);
  if (gcry_pk_get_curve (NULL, -1, NULL))
    fail ("curve iteration failed\n");
}


static void
check_matching (void)
{
  gpg_error_t err;
  gcry_sexp_t key;
  const char *name;
  unsigned int nbits;

  err = gcry_sexp_new (&key, sample_key_1, 0, 1);
  if (err)
    die ("parsing s-expression string failed: %s\n", gpg_strerror (err));
  name = gcry_pk_get_curve (key, 0, &nbits);
  if (!name)
    fail ("curve name not found for sample_key_1\n");
  else if (strcmp (name, sample_key_1_curve))
    fail ("expected curve name %s but got %s for sample_key_1\n",
          sample_key_1_curve, name);
  else if (nbits != sample_key_1_nbits)
    fail ("expected curve size %u but got %u for sample_key_1\n",
          sample_key_1_nbits, nbits);

  gcry_sexp_release (key);

  err = gcry_sexp_new (&key, sample_key_2, 0, 1);
  if (err)
    die ("parsing s-expression string failed: %s\n", gpg_strerror (err));
  name = gcry_pk_get_curve (key, 0, &nbits);
  if (!name)
    fail ("curve name not found for sample_key_2\n");
  else if (strcmp (name, sample_key_2_curve))
    fail ("expected curve name %s but got %s for sample_key_2\n",
          sample_key_2_curve, name);
  else if (nbits != sample_key_2_nbits)
    fail ("expected curve size %u but got %u for sample_key_2\n",
          sample_key_2_nbits, nbits);

  gcry_sexp_release (key);
}


static void
check_get_params (void)
{
  gcry_sexp_t param;
  const char *name;

  param = gcry_pk_get_param (GCRY_PK_ECDSA, sample_key_1_curve);
  if (!param)
    fail ("error gerring parameters for `%s'\n", sample_key_1_curve);

  name = gcry_pk_get_curve (param, 0, NULL);
  if (!name)
    fail ("get_param: curve name not found for sample_key_1\n");
  else if (strcmp (name, sample_key_1_curve))
    fail ("get_param: expected curve name %s but got %s for sample_key_1\n",
          sample_key_1_curve, name);

  gcry_sexp_release (param);


  param = gcry_pk_get_param (GCRY_PK_ECDSA, sample_key_2_curve);
  if (!param)
    fail ("error gerring parameters for `%s'\n", sample_key_2_curve);

  name = gcry_pk_get_curve (param, 0, NULL);
  if (!name)
    fail ("get_param: curve name not found for sample_key_2\n");
  else if (strcmp (name, sample_key_2_curve))
    fail ("get_param: expected curve name %s but got %s for sample_key_2\n",
          sample_key_2_curve, name);

  gcry_sexp_release (param);
}


static void
check_montgomery (void)
{
  gpg_error_t err;
  gcry_sexp_t key;
  const char *name;
  unsigned int nbits;

  gcry_ctx_t ctx;
  gcry_mpi_point_t G, Q;
  gcry_mpi_t d;
  gcry_mpi_t x, y, z;

  err = gcry_sexp_new (&key, sample_key_3, 0, 1);
  if (err)
    die ("parsing s-expression string failed: %s\n", gpg_strerror (err));
  name = gcry_pk_get_curve (key, 0, &nbits);
  if (!name)
    fail ("curve name not found for sample_key_3\n");
  else if (strcmp (name, sample_key_3_curve))
    fail ("expected curve name %s but got %s for sample_key_3\n",
          sample_key_3_curve, name);
  else if (nbits != sample_key_3_nbits)
    fail ("expected curve size %u but got %u for sample_key_3\n",
          sample_key_3_nbits, nbits);

  gcry_sexp_release (key);

  Q = gcry_mpi_point_new (0);

  err = gcry_mpi_ec_new (&ctx, NULL, "Curve25519");
  if (err)
    fail ("can't create ec context: %s\n", gpg_strerror (err));

#if 0
  d = hex2mpi ("40000000000000000000000000000000"
               "00000000000000000000000000000000");
  G = gcry_mpi_ec_get_point ("g", ctx, 1);
  if (!G)
    fail ("can't get basepoint of the curve: %s\n", gpg_strerror (err));
#else
  d = hex2mpi ("7d74fb61db3100e11e4d4ae171daf820688f3bcfa631565272a998b8f4e8c290");
  {
    gcry_mpi_t gx;
    gx = hex2mpi ("3dc16d73d4222d12eb54623c85f3fb5ebdab33c1bd5865780654f1b0ed696ddf");

    G = gcry_mpi_point_new (0);
    gcry_mpi_point_snatch_set (G, gx, NULL, NULL);
  }
#endif

  gcry_mpi_ec_mul (Q, d, G, ctx);

  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);

  gcry_mpi_point_get (x, y, z, Q);

  print_mpi ("Q.x", x);
  print_mpi ("Q.y", y);
  print_mpi ("Q.z", z);

  if (gcry_mpi_ec_get_affine (x, NULL, Q, ctx))
    fail ("failed to get affine coordinates\n");

  print_mpi ("q.x", x);
  /* 16B53A046DEEDD81ED6B0D470CE46DD9B5FAC6124F3D22358AA7CD2911FCFABC */

  gcry_mpi_release (z);
  gcry_mpi_release (y);
  gcry_mpi_release (x);

  gcry_mpi_point_release (Q);
  gcry_mpi_release (d);
  gcry_mpi_point_release (G);
  gcry_ctx_release (ctx);
}

int
main (int argc, char **argv)
{
  int debug = 0;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  list_curves ();
  check_matching ();
  check_get_params ();
  check_montgomery ();

  return error_count ? 1 : 0;
}
