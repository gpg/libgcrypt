/* t-mpi-point.c  - Tests for mpi point functions
 * Copyright (C) 2013 g10 Code GmbH
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#define PGM "t-mpi-point"
#include "t-common.h"

static struct
{
  const char *desc;           /* Description of the curve.  */
  const char *p;              /* Order of the prime field.  */
  const char *a, *b;          /* The coefficients. */
  const char *n;              /* The order of the base point.  */
  const char *g_x, *g_y;      /* Base point.  */
  const char *h;              /* Cofactor.  */
} test_curve[] =
  {
    {
      "NIST P-192",
      "0xfffffffffffffffffffffffffffffffeffffffffffffffff",
      "0xfffffffffffffffffffffffffffffffefffffffffffffffc",
      "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
      "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",

      "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
      "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
      "0x01"
    },
    {
      "NIST P-224",
      "0xffffffffffffffffffffffffffffffff000000000000000000000001",
      "0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
      "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
      "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d" ,

      "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
      "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
      "0x01"
    },
    {
      "NIST P-256",
      "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
      "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
      "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",

      "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
      "0x01"
    },
    {
      "NIST P-384",
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
      "ffffffff0000000000000000ffffffff",
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
      "ffffffff0000000000000000fffffffc",
      "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
      "c656398d8a2ed19d2a85c8edd3ec2aef",
      "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
      "581a0db248b0a77aecec196accc52973",

      "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
      "5502f25dbf55296c3a545e3872760ab7",
      "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
      "0a60b1ce1d7e819d7a431d7c90ea0e5f",
      "0x01"
    },
    {
      "NIST P-521",
      "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
      "0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10"
      "9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
      "0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",

      "0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d"
      "baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
      "0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6"
      "62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
      "0x01"
    },
    {
      "Ed25519",
      "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
      "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC",
      "0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3",
      "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
      "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
      "0x6666666666666666666666666666666666666666666666666666666666666658",
      "0x08"
    },
    { NULL, NULL, NULL, NULL, NULL, NULL }
  };

/* A sample public key for NIST P-256.  */
static const char sample_p256_q[] =
  "04"
  "42B927242237639A36CE9221B340DB1A9AB76DF2FE3E171277F6A4023DED146E"
  "E86525E38CCECFF3FB8D152CC6334F70D23A525175C1BCBDDE6E023B2228770E";
static const char sample_p256_q_x[] =
  "42B927242237639A36CE9221B340DB1A9AB76DF2FE3E171277F6A4023DED146E";
static const char sample_p256_q_y[] =
  "00E86525E38CCECFF3FB8D152CC6334F70D23A525175C1BCBDDE6E023B2228770E";


/* A sample public key for Ed25519.  */
static const char sample_ed25519_q[] =
  "04"
  "55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce"
  "1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7";
static const char sample_ed25519_q_x[] =
  "55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce";
static const char sample_ed25519_q_y[] =
  "1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7";
static const char sample_ed25519_q_eddsa[] =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static const char sample_ed25519_d[] =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";


static void
print_mpi_2 (const char *text, const char *text2, gcry_mpi_t a)
{
  gcry_error_t err;
  char *buf;
  void *bufaddr = &buf;

  err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, bufaddr, NULL, a);
  if (err)
    fprintf (stderr, "%s%s: [error printing number: %s]\n",
             text, text2? text2:"", gpg_strerror (err));
  else
    {
      fprintf (stderr, "%s%s: %s\n", text, text2? text2:"", buf);
      gcry_free (buf);
    }
}


static void
print_mpi (const char *text, gcry_mpi_t a)
{
  print_mpi_2 (text, NULL, a);
}


static void
print_point (const char *text, gcry_mpi_point_t a)
{
  gcry_mpi_t x, y, z;

  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);
  gcry_mpi_point_get (x, y, z, a);
  print_mpi_2 (text, ".x", x);
  print_mpi_2 (text, ".y", y);
  print_mpi_2 (text, ".z", z);
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (z);
}


static void
print_sexp (const char *prefix, gcry_sexp_t a)
{
  char *buf;
  size_t size;

  if (prefix)
    fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = gcry_xmalloc (size);

  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  gcry_free (buf);
}


static gcry_mpi_t
hex2mpi (const char *string)
{
  gpg_error_t err;
  gcry_mpi_t val;

  err = gcry_mpi_scan (&val, GCRYMPI_FMT_HEX, string, 0, NULL);
  if (err)
    die ("hex2mpi '%s' failed: %s\n", string, gpg_strerror (err));
  return val;
}


/* Convert STRING consisting of hex characters into its binary
   representation and return it as an allocated buffer. The valid
   length of the buffer is returned at R_LENGTH.  The string is
   delimited by end of string.  The function returns NULL on
   error.  */
static void *
hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        return NULL;           /* Invalid hex digits. */
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static gcry_mpi_t
hex2mpiopa (const char *string)
{
  char *buffer;
  size_t buflen;
  gcry_mpi_t val;

  buffer = hex2buffer (string, &buflen);
  if (!buffer)
    die ("hex2mpiopa '%s' failed: parser error\n", string);
  val = gcry_mpi_set_opaque (NULL, buffer, buflen*8);
  if (!buffer)
    die ("hex2mpiopa '%s' failed: set_opaque error\n", string);
  return val;
}


/* Compare A to B, where B is given as a hex string.  */
static int
cmp_mpihex (gcry_mpi_t a, const char *b)
{
  gcry_mpi_t bval;
  int res;

  if (gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    bval = hex2mpiopa (b);
  else
    bval = hex2mpi (b);
  res = gcry_mpi_cmp (a, bval);
  gcry_mpi_release (bval);
  return res;
}


/* Wrapper to emulate the libgcrypt internal EC context allocation
   function.  */
static gpg_error_t
ec_p_new (gcry_ctx_t *r_ctx, gcry_mpi_t p, gcry_mpi_t a)
{
  gpg_error_t err;
  gcry_sexp_t sexp;

  if (p && a)
    err = gcry_sexp_build (&sexp, NULL, "(ecdsa (p %m)(a %m))", p, a);
  else if (p)
    err = gcry_sexp_build (&sexp, NULL, "(ecdsa (p %m))", p);
  else if (a)
    err = gcry_sexp_build (&sexp, NULL, "(ecdsa (a %m))", a);
  else
    err = gcry_sexp_build (&sexp, NULL, "(ecdsa)");
  if (err)
    return err;
  err = gcry_mpi_ec_new (r_ctx, sexp, NULL);
  gcry_sexp_release (sexp);
  return err;
}



static void
set_get_point (void)
{
  gcry_mpi_point_t point, point2;
  gcry_mpi_t x, y, z;

  wherestr = "set_get_point";
  info ("checking point setting functions\n");

  point = gcry_mpi_point_new (0);
  x = gcry_mpi_set_ui (NULL, 17);
  y = gcry_mpi_set_ui (NULL, 42);
  z = gcry_mpi_set_ui (NULL, 11371);
  gcry_mpi_point_get (x, y, z, point);
  if (gcry_mpi_cmp_ui (x, 0)
      || gcry_mpi_cmp_ui (y, 0) || gcry_mpi_cmp_ui (z, 0))
    fail ("new point not initialized to (0,0,0)\n");
  gcry_mpi_point_snatch_get (x, y, z, point);
  point = NULL;
  if (gcry_mpi_cmp_ui (x, 0)
      || gcry_mpi_cmp_ui (y, 0) || gcry_mpi_cmp_ui (z, 0))
    fail ("snatch_get failed\n");
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (z);

  point = gcry_mpi_point_new (0);
  x = gcry_mpi_set_ui (NULL, 17);
  y = gcry_mpi_set_ui (NULL, 42);
  z = gcry_mpi_set_ui (NULL, 11371);
  gcry_mpi_point_set (point, x, y, z);
  gcry_mpi_set_ui (x, 23);
  gcry_mpi_set_ui (y, 24);
  gcry_mpi_set_ui (z, 25);
  gcry_mpi_point_get (x, y, z, point);
  if (gcry_mpi_cmp_ui (x, 17)
      || gcry_mpi_cmp_ui (y, 42) || gcry_mpi_cmp_ui (z, 11371))
    fail ("point_set/point_get failed\n");
  gcry_mpi_point_snatch_set (point, x, y, z);
  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);
  gcry_mpi_point_get (x, y, z, point);
  if (gcry_mpi_cmp_ui (x, 17)
      || gcry_mpi_cmp_ui (y, 42) || gcry_mpi_cmp_ui (z, 11371))
    fail ("point_snatch_set/point_get failed\n");

  point2 = gcry_mpi_point_copy (point);

  gcry_mpi_point_get (x, y, z, point2);
  if (gcry_mpi_cmp_ui (x, 17)
      || gcry_mpi_cmp_ui (y, 42) || gcry_mpi_cmp_ui (z, 11371))
    fail ("point_copy failed (1)\n");

  gcry_mpi_point_release (point);

  gcry_mpi_point_get (x, y, z, point2);
  if (gcry_mpi_cmp_ui (x, 17)
      || gcry_mpi_cmp_ui (y, 42) || gcry_mpi_cmp_ui (z, 11371))
    fail ("point_copy failed (2)\n");

  gcry_mpi_point_release (point2);

  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (z);
}


static void
context_alloc (void)
{
  gpg_error_t err;
  gcry_ctx_t ctx;
  gcry_mpi_t p, a;

  wherestr = "context_alloc";
  info ("checking context functions\n");

  p = gcry_mpi_set_ui (NULL, 1);
  a = gcry_mpi_set_ui (NULL, 1);
  err = ec_p_new (&ctx, p, a);
  if (err)
    die ("ec_p_new returned an error: %s\n", gpg_strerror (err));
  gcry_mpi_release (p);
  gcry_mpi_release (a);
  gcry_ctx_release (ctx);

  p = NULL;
  a = gcry_mpi_set_ui (NULL, 0);

  err = ec_p_new (&ctx, p, a);
  if (!err || gpg_err_code (err) != GPG_ERR_EINVAL)
    fail ("ec_p_new: bad parameter detection failed (1)\n");

  gcry_mpi_release (a);
  a = NULL;
  err = ec_p_new (&ctx, p, a);
  if (!err || gpg_err_code (err) != GPG_ERR_EINVAL)
    fail ("ec_p_new: bad parameter detection failed (2)\n");

}


static int
get_and_cmp_mpi (const char *name, const char *mpistring, const char *desc,
                 gcry_ctx_t ctx)
{
  gcry_mpi_t mpi;

  mpi = gcry_mpi_ec_get_mpi (name, ctx, 1);
  if (!mpi)
    {
      fail ("error getting parameter '%s' of curve '%s'\n", name, desc);
      return 1;
    }
  if (debug)
    print_mpi (name, mpi);
  if (cmp_mpihex (mpi, mpistring))
    {
      fail ("parameter '%s' of curve '%s' does not match\n", name, desc);
      gcry_mpi_release (mpi);
      return 1;
    }
  gcry_mpi_release (mpi);
  return 0;
}


static int
get_and_cmp_point (const char *name,
                   const char *mpi_x_string, const char *mpi_y_string,
                   const char *desc, gcry_ctx_t ctx)
{
  gcry_mpi_point_t point;
  gcry_mpi_t x, y, z;
  int result = 0;

  point = gcry_mpi_ec_get_point (name, ctx, 1);
  if (!point)
    {
      fail ("error getting point parameter '%s' of curve '%s'\n", name, desc);
      return 1;
    }
  if (debug)
    print_point (name, point);

  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);
  gcry_mpi_point_snatch_get (x, y, z, point);
  if (cmp_mpihex (x, mpi_x_string))
    {
      fail ("x coordinate of '%s' of curve '%s' does not match\n", name, desc);
      result = 1;
    }
  if (cmp_mpihex (y, mpi_y_string))
    {
      fail ("y coordinate of '%s' of curve '%s' does not match\n", name, desc);
      result = 1;
    }
  if (cmp_mpihex (z, "01"))
    {
      fail ("z coordinate of '%s' of curve '%s' is not 1\n", name, desc);
      result = 1;
    }
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (z);
  return result;
}


static void
context_param (void)
{
  gpg_error_t err;
  int idx;
  gcry_ctx_t ctx = NULL;
  gcry_mpi_t q, d;
  gcry_sexp_t keyparam;

  wherestr = "context_param";

  info ("checking standard curves\n");
  for (idx=0; test_curve[idx].desc; idx++)
    {
      /* P-192 and Ed25519 are not supported in fips mode */
      if (gcry_fips_mode_active())
        {
          if (!strcmp(test_curve[idx].desc, "NIST P-192")
              || !strcmp(test_curve[idx].desc, "Ed25519"))
            {
	      info ("skipping %s in fips mode\n", test_curve[idx].desc );
              continue;
            }
        }

      gcry_ctx_release (ctx);
      err = gcry_mpi_ec_new (&ctx, NULL, test_curve[idx].desc);
      if (err)
        {
          fail ("can't create context for curve '%s': %s\n",
                test_curve[idx].desc, gpg_strerror (err));
          continue;
        }
      if (get_and_cmp_mpi ("p", test_curve[idx].p, test_curve[idx].desc, ctx))
        continue;
      if (get_and_cmp_mpi ("a", test_curve[idx].a, test_curve[idx].desc, ctx))
        continue;
      if (get_and_cmp_mpi ("b", test_curve[idx].b, test_curve[idx].desc, ctx))
        continue;
      if (get_and_cmp_mpi ("g.x",test_curve[idx].g_x, test_curve[idx].desc,ctx))
        continue;
      if (get_and_cmp_mpi ("g.y",test_curve[idx].g_y, test_curve[idx].desc,ctx))
        continue;
      if (get_and_cmp_mpi ("n", test_curve[idx].n, test_curve[idx].desc, ctx))
        continue;
      if (get_and_cmp_point ("g", test_curve[idx].g_x, test_curve[idx].g_y,
                             test_curve[idx].desc, ctx))
        continue;
      if (get_and_cmp_mpi ("h", test_curve[idx].h, test_curve[idx].desc, ctx))
        continue;

    }

  info ("checking sample public key (nistp256)\n");
  q = hex2mpi (sample_p256_q);
  err = gcry_sexp_build (&keyparam, NULL,
                        "(public-key(ecc(curve %s)(q %m)))",
                        "NIST P-256", q);
  if (err)
    die ("gcry_sexp_build failed: %s\n", gpg_strerror (err));
  gcry_mpi_release (q);

  /* We can't call gcry_pk_testkey because it is only implemented for
     private keys.  */
  /* err = gcry_pk_testkey (keyparam); */
  /* if (err) */
  /*   fail ("gcry_pk_testkey failed for sample public key: %s\n", */
  /*         gpg_strerror (err)); */

  gcry_ctx_release (ctx);
  err = gcry_mpi_ec_new (&ctx, keyparam, NULL);
  if (err)
    fail ("gcry_mpi_ec_new failed for sample public key (nistp256): %s\n",
          gpg_strerror (err));
  else
    {
      gcry_sexp_t sexp;

      get_and_cmp_mpi ("q", sample_p256_q, "nistp256", ctx);
      get_and_cmp_point ("q", sample_p256_q_x, sample_p256_q_y, "nistp256",
                         ctx);

      /* Delete Q.  */
      err = gcry_mpi_ec_set_mpi ("q", NULL, ctx);
      if (err)
        fail ("clearing Q for nistp256 failed: %s\n", gpg_strerror (err));
      if (gcry_mpi_ec_get_mpi ("q", ctx, 0))
        fail ("clearing Q for nistp256 did not work\n");

      /* Set Q again.  */
      q = hex2mpi (sample_p256_q);
      err = gcry_mpi_ec_set_mpi ("q", q, ctx);
      if (err)
        fail ("setting Q for nistp256 failed: %s\n", gpg_strerror (err));
      get_and_cmp_mpi ("q", sample_p256_q, "nistp256(2)", ctx);
      gcry_mpi_release (q);

      /* Get as s-expression.  */
      err = gcry_pubkey_get_sexp (&sexp, 0, ctx);
      if (err)
        fail ("gcry_pubkey_get_sexp(0) failed: %s\n", gpg_strerror (err));
      else if (debug)
        print_sexp ("Result of gcry_pubkey_get_sexp (0):\n", sexp);
      gcry_sexp_release (sexp);

      err = gcry_pubkey_get_sexp (&sexp, GCRY_PK_GET_PUBKEY, ctx);
      if (err)
        fail ("gcry_pubkey_get_sexp(GET_PUBKEY) failed: %s\n",
              gpg_strerror (err));
      else if (debug)
        print_sexp ("Result of gcry_pubkey_get_sexp (GET_PUBKEY):\n", sexp);
      gcry_sexp_release (sexp);

      err = gcry_pubkey_get_sexp (&sexp, GCRY_PK_GET_SECKEY, ctx);
      if (gpg_err_code (err) != GPG_ERR_NO_SECKEY)
        fail ("gcry_pubkey_get_sexp(GET_SECKEY) returned wrong error: %s\n",
              gpg_strerror (err));
      gcry_sexp_release (sexp);
    }

  /* Skipping Ed25519 if in FIPS mode (it isn't supported) */
  if (gcry_fips_mode_active())
    goto cleanup;

  info ("checking sample public key (Ed25519)\n");
  q = hex2mpi (sample_ed25519_q);
  gcry_sexp_release (keyparam);
  err = gcry_sexp_build (&keyparam, NULL,
                        "(public-key(ecc(curve %s)(flags eddsa)(q %m)))",
                        "Ed25519", q);
  if (err)
    die ("gcry_sexp_build failed: %s\n", gpg_strerror (err));
  gcry_mpi_release (q);

  /* We can't call gcry_pk_testkey because it is only implemented for
     private keys.  */
  /* err = gcry_pk_testkey (keyparam); */
  /* if (err) */
  /*   fail ("gcry_pk_testkey failed for sample public key: %s\n", */
  /*         gpg_strerror (err)); */

  gcry_ctx_release (ctx);
  err = gcry_mpi_ec_new (&ctx, keyparam, NULL);
  if (err)
    fail ("gcry_mpi_ec_new failed for sample public key: %s\n",
          gpg_strerror (err));
  else
    {
      gcry_sexp_t sexp;

      get_and_cmp_mpi ("q", sample_ed25519_q, "Ed25519", ctx);
      get_and_cmp_point ("q", sample_ed25519_q_x, sample_ed25519_q_y,
                         "Ed25519", ctx);
      get_and_cmp_mpi ("q@eddsa", sample_ed25519_q_eddsa, "Ed25519", ctx);

      /* Set d to see whether Q is correctly re-computed.  */
      d = hex2mpi (sample_ed25519_d);
      err = gcry_mpi_ec_set_mpi ("d", d, ctx);
      if (err)
        fail ("setting d for Ed25519 failed: %s\n", gpg_strerror (err));
      gcry_mpi_release (d);
      get_and_cmp_mpi ("q", sample_ed25519_q, "Ed25519(recompute Q)", ctx);

      /* Delete Q by setting d and then clearing d.  The clearing is
         required so that we can check whether Q has been cleared and
         because further tests only expect a public key.  */
      d = hex2mpi (sample_ed25519_d);
      err = gcry_mpi_ec_set_mpi ("d", d, ctx);
      if (err)
        fail ("setting d for Ed25519 failed: %s\n", gpg_strerror (err));
      gcry_mpi_release (d);
      err = gcry_mpi_ec_set_mpi ("d", NULL, ctx);
      if (err)
        fail ("setting d for Ed25519 failed(2): %s\n", gpg_strerror (err));
      if (gcry_mpi_ec_get_mpi ("q", ctx, 0))
        fail ("setting d for Ed25519 did not reset Q\n");

      /* Set Q again.  We need to use an opaque MPI here because
         sample_ed25519_q is in uncompressed format which can only be
         auto-detected if passed opaque.  */
      q = hex2mpiopa (sample_ed25519_q);
      err = gcry_mpi_ec_set_mpi ("q", q, ctx);
      if (err)
        fail ("setting Q for Ed25519 failed: %s\n", gpg_strerror (err));
      gcry_mpi_release (q);
      get_and_cmp_mpi ("q", sample_ed25519_q, "Ed25519(2)", ctx);

      /* Get as s-expression.  */
      err = gcry_pubkey_get_sexp (&sexp, 0, ctx);
      if (err)
        fail ("gcry_pubkey_get_sexp(0) failed: %s\n", gpg_strerror (err));
      else if (debug)
        print_sexp ("Result of gcry_pubkey_get_sexp (0):\n", sexp);
      gcry_sexp_release (sexp);

      err = gcry_pubkey_get_sexp (&sexp, GCRY_PK_GET_PUBKEY, ctx);
      if (err)
        fail ("gcry_pubkey_get_sexp(GET_PUBKEY) failed: %s\n",
              gpg_strerror (err));
      else if (debug)
        print_sexp ("Result of gcry_pubkey_get_sexp (GET_PUBKEY):\n", sexp);
      gcry_sexp_release (sexp);

      err = gcry_pubkey_get_sexp (&sexp, GCRY_PK_GET_SECKEY, ctx);
      if (gpg_err_code (err) != GPG_ERR_NO_SECKEY)
        fail ("gcry_pubkey_get_sexp(GET_SECKEY) returned wrong error: %s\n",
              gpg_strerror (err));
      gcry_sexp_release (sexp);

    }

 cleanup:
  gcry_ctx_release (ctx);
  gcry_sexp_release (keyparam);
}




/* Create a new point from (X,Y,Z) given as hex strings.  */
gcry_mpi_point_t
make_point (const char *x, const char *y, const char *z)
{
  gcry_mpi_point_t point;

  point = gcry_mpi_point_new (0);
  gcry_mpi_point_snatch_set (point, hex2mpi (x), hex2mpi (y), hex2mpi (z));

  return point;
}


/* This tests checks that the low-level EC API yields the same result
   as using the high level API.  The values have been taken from a
   test run using the high level API.  */
static void
basic_ec_math (void)
{
  gpg_error_t err;
  gcry_ctx_t ctx;
  gcry_mpi_t P, A;
  gcry_mpi_point_t G, Q;
  gcry_mpi_t d;
  gcry_mpi_t x, y, z;

  wherestr = "basic_ec_math";
  info ("checking basic math functions for EC\n");

  P = hex2mpi ("0xfffffffffffffffffffffffffffffffeffffffffffffffff");
  A = hex2mpi ("0xfffffffffffffffffffffffffffffffefffffffffffffffc");
  G = make_point ("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
                  "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
                  "1");
  d = hex2mpi ("D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D");
  Q = gcry_mpi_point_new (0);

  err = ec_p_new (&ctx, P, A);
  if (err)
    die ("ec_p_new failed: %s\n", gpg_strerror (err));

  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);

  {
    /* A quick check that multiply by zero works.  */
    gcry_mpi_t tmp;

    tmp = gcry_mpi_new (0);
    gcry_mpi_ec_mul (Q, tmp, G, ctx);
    gcry_mpi_release (tmp);
    gcry_mpi_point_get (x, y, z, Q);
    if (gcry_mpi_cmp_ui (z, 0))
      fail ("multiply a point by zero failed\n");
  }

  gcry_mpi_ec_mul (Q, d, G, ctx);

  if (gcry_mpi_ec_get_affine (x, y, Q, ctx))
    fail ("failed to get affine coordinates\n");
  if (cmp_mpihex (x, "008532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE")
      || cmp_mpihex (y, "00C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966"))
    fail ("computed affine coordinates of public key do not match\n");
  if (debug)
    {
      print_mpi ("q.x", x);
      print_mpi ("q.y", y);
    }

  gcry_mpi_release (z);
  gcry_mpi_release (y);
  gcry_mpi_release (x);
  gcry_mpi_point_release (Q);
  gcry_mpi_release (d);
  gcry_mpi_point_release (G);
  gcry_mpi_release (A);
  gcry_mpi_release (P);
  gcry_ctx_release (ctx);
}


/* This is the same as basic_ec_math but uses more advanced
   features.  */
static void
basic_ec_math_simplified (void)
{
  gpg_error_t err;
  gcry_ctx_t ctx;
  gcry_mpi_point_t G, Q;
  gcry_mpi_t d;
  gcry_mpi_t x, y, z;
  gcry_sexp_t sexp;

  wherestr = "basic_ec_math_simplified";
  info ("checking basic math functions for EC (variant)\n");

  d = hex2mpi ("D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D");
  Q = gcry_mpi_point_new (0);

  err = gcry_mpi_ec_new (&ctx, NULL, "NIST P-192");
  if (err)
    die ("gcry_mpi_ec_new failed: %s\n", gpg_strerror (err));
  G = gcry_mpi_ec_get_point ("g", ctx, 1);
  if (!G)
    die ("gcry_mpi_ec_get_point(G) failed\n");
  gcry_mpi_ec_mul (Q, d, G, ctx);

  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);

  if (gcry_mpi_ec_get_affine (x, y, Q, ctx))
    fail ("failed to get affine coordinates\n");
  if (cmp_mpihex (x, "008532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE")
      || cmp_mpihex (y, "00C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966"))
    fail ("computed affine coordinates of public key do not match\n");
  if (debug)
    {
      print_mpi ("q.x", x);
      print_mpi ("q.y", y);
    }

  gcry_mpi_release (z);
  gcry_mpi_release (y);
  gcry_mpi_release (x);

  /* Let us also check whether we can update the context.  */
  err = gcry_mpi_ec_set_point ("g", G, ctx);
  if (err)
    die ("gcry_mpi_ec_set_point(G) failed\n");
  err = gcry_mpi_ec_set_mpi ("d", d, ctx);
  if (err)
    die ("gcry_mpi_ec_set_mpi(d) failed\n");

  /* FIXME: Below we need to check that the returned S-expression is
     as requested.  For now we use manual inspection using --debug.  */

  /* Does get_sexp return the private key?  */
  err = gcry_pubkey_get_sexp (&sexp, 0, ctx);
  if (err)
    fail ("gcry_pubkey_get_sexp(0) failed: %s\n", gpg_strerror (err));
  else if (debug)
    print_sexp ("Result of gcry_pubkey_get_sexp (0):\n", sexp);
  gcry_sexp_release (sexp);

  /* Does get_sexp return the public key if requested?  */
  err = gcry_pubkey_get_sexp (&sexp, GCRY_PK_GET_PUBKEY, ctx);
  if (err)
    fail ("gcry_pubkey_get_sexp(GET_PUBKEY) failed: %s\n", gpg_strerror (err));
  else if (debug)
    print_sexp ("Result of gcry_pubkey_get_sexp (GET_PUBKEY):\n", sexp);
  gcry_sexp_release (sexp);

  /* Does get_sexp return the public key after d has been deleted?  */
  err = gcry_mpi_ec_set_mpi ("d", NULL, ctx);
  if (err)
    die ("gcry_mpi_ec_set_mpi(d=NULL) failed\n");
  err = gcry_pubkey_get_sexp (&sexp, 0, ctx);
  if (err)
    fail ("gcry_pubkey_get_sexp(0 w/o d) failed: %s\n", gpg_strerror (err));
  else if (debug)
    print_sexp ("Result of gcry_pubkey_get_sexp (0 w/o d):\n", sexp);
  gcry_sexp_release (sexp);

  /* Does get_sexp return an error after d has been deleted?  */
  err = gcry_pubkey_get_sexp (&sexp, GCRY_PK_GET_SECKEY, ctx);
  if (gpg_err_code (err) != GPG_ERR_NO_SECKEY)
    fail ("gcry_pubkey_get_sexp(GET_SECKEY) returned wrong error: %s\n",
          gpg_strerror (err));
  gcry_sexp_release (sexp);

  /* Does get_sexp return an error after d and Q have been deleted?  */
  err = gcry_mpi_ec_set_point ("q", NULL, ctx);
  if (err)
    die ("gcry_mpi_ec_set_point(q=NULL) failed\n");
  err = gcry_pubkey_get_sexp (&sexp, 0, ctx);
  if (gpg_err_code (err) != GPG_ERR_BAD_CRYPT_CTX)
    fail ("gcry_pubkey_get_sexp(0 w/o Q,d) returned wrong error: %s\n",
          gpg_strerror (err));
  gcry_sexp_release (sexp);


  gcry_mpi_point_release (Q);
  gcry_mpi_release (d);
  gcry_mpi_point_release (G);
  gcry_ctx_release (ctx);
}


/* Check the math used with Twisted Edwards curves.  */
static void
twistededwards_math (void)
{
  gpg_error_t err;
  gcry_ctx_t ctx;
  gcry_mpi_point_t G, Q;
  gcry_mpi_t k;
  gcry_mpi_t w, a, x, y, z, p, n, b, I;

  wherestr = "twistededwards_math";
  info ("checking basic Twisted Edwards math\n");

  err = gcry_mpi_ec_new (&ctx, NULL, "Ed25519");
  if (err)
    die ("gcry_mpi_ec_new failed: %s\n", gpg_strerror (err));

  k = hex2mpi
    ("2D3501E723239632802454EE5DDC406EFB0BDF18486A5BDE9C0390A9C2984004"
     "F47252B628C953625B8DEB5DBCB8DA97AA43A1892D11FA83596F42E0D89CB1B6");
  G = gcry_mpi_ec_get_point ("g", ctx, 1);
  if (!G)
    die ("gcry_mpi_ec_get_point(G) failed\n");
  Q = gcry_mpi_point_new (0);


  w = gcry_mpi_new (0);
  a = gcry_mpi_new (0);
  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);
  I = gcry_mpi_new (0);
  p = gcry_mpi_ec_get_mpi ("p", ctx, 1);
  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  b = gcry_mpi_ec_get_mpi ("b", ctx, 1);

  /* Check: 2^{p-1} mod p == 1 */
  gcry_mpi_sub_ui (a, p, 1);
  gcry_mpi_powm (w, GCRYMPI_CONST_TWO, a, p);
  if (gcry_mpi_cmp_ui (w, 1))
    fail ("failed assertion: 2^{p-1} mod p == 1\n");

  /* Check: p % 4 == 1 */
  gcry_mpi_mod (w, p, GCRYMPI_CONST_FOUR);
  if (gcry_mpi_cmp_ui (w, 1))
    fail ("failed assertion: p %% 4 == 1\n");

  /* Check: 2^{n-1} mod n == 1 */
  gcry_mpi_sub_ui (a, n, 1);
  gcry_mpi_powm (w, GCRYMPI_CONST_TWO, a, n);
  if (gcry_mpi_cmp_ui (w, 1))
    fail ("failed assertion: 2^{n-1} mod n == 1\n");

  /* Check: b^{(p-1)/2} mod p == p-1 */
  gcry_mpi_sub_ui (a, p, 1);
  gcry_mpi_div (x, NULL, a, GCRYMPI_CONST_TWO, -1);
  gcry_mpi_powm (w, b, x, p);
  gcry_mpi_abs (w);
  if (gcry_mpi_cmp (w, a))
    fail ("failed assertion: b^{(p-1)/2} mod p == p-1\n");

  /* I := 2^{(p-1)/4} mod p */
  gcry_mpi_sub_ui (a, p, 1);
  gcry_mpi_div (x, NULL, a, GCRYMPI_CONST_FOUR, -1);
  gcry_mpi_powm (I, GCRYMPI_CONST_TWO, x, p);

  /* Check: I^2 mod p == p-1 */
  gcry_mpi_powm (w, I, GCRYMPI_CONST_TWO, p);
  if (gcry_mpi_cmp (w, a))
    fail ("failed assertion: I^2 mod p == p-1\n");

  /* Check: G is on the curve */
  if (!gcry_mpi_ec_curve_point (G, ctx))
    fail ("failed assertion: G is on the curve\n");

  /* Check: nG == (0,1) */
  gcry_mpi_ec_mul (Q, n, G, ctx);
  if (gcry_mpi_ec_get_affine (x, y, Q, ctx))
    fail ("failed to get affine coordinates\n");
  if (gcry_mpi_cmp_ui (x, 0) || gcry_mpi_cmp_ui (y, 1))
    fail ("failed assertion: nG == (0,1)\n");

  /* Now two arbitrary point operations taken from the ed25519.py
     sample data.  */
  gcry_mpi_release (a);
  a = hex2mpi
    ("4f71d012df3c371af3ea4dc38385ca5bb7272f90cb1b008b3ed601c76de1d496"
     "e30cbf625f0a756a678d8f256d5325595cccc83466f36db18f0178eb9925edd3");
  gcry_mpi_ec_mul (Q, a, G, ctx);
  if (gcry_mpi_ec_get_affine (x, y, Q, ctx))
    fail ("failed to get affine coordinates\n");
  if (cmp_mpihex (x, ("157f7361c577aad36f67ed33e38dc7be"
                      "00014fecc2165ca5cee9eee19fe4d2c1"))
      || cmp_mpihex (y, ("5a69dbeb232276b38f3f5016547bb2a2"
                         "4025645f0b820e72b8cad4f0a909a092")))
    {
      fail ("sample point multiply failed:\n");
      print_mpi ("r", a);
      print_mpi ("Rx", x);
      print_mpi ("Ry", y);
    }

  gcry_mpi_release (a);
  a = hex2mpi
    ("2d3501e723239632802454ee5ddc406efb0bdf18486a5bde9c0390a9c2984004"
     "f47252b628c953625b8deb5dbcb8da97aa43a1892d11fa83596f42e0d89cb1b6");
  gcry_mpi_ec_mul (Q, a, G, ctx);
  if (gcry_mpi_ec_get_affine (x, y, Q, ctx))
    fail ("failed to get affine coordinates\n");
  if (cmp_mpihex (x, ("6218e309d40065fcc338b3127f468371"
                      "82324bd01ce6f3cf81ab44e62959c82a"))
      || cmp_mpihex (y, ("5501492265e073d874d9e5b81e7f8784"
                         "8a826e80cce2869072ac60c3004356e5")))
    {
      fail ("sample point multiply failed:\n");
      print_mpi ("r", a);
      print_mpi ("Rx", x);
      print_mpi ("Ry", y);
    }


  gcry_mpi_release (I);
  gcry_mpi_release (b);
  gcry_mpi_release (n);
  gcry_mpi_release (p);
  gcry_mpi_release (w);
  gcry_mpi_release (a);
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (z);
  gcry_mpi_point_release (Q);
  gcry_mpi_point_release (G);
  gcry_mpi_release (k);
  gcry_ctx_release (ctx);
}


/* Check the point on curve function.  */
static void
point_on_curve (void)
{
  static struct {
    const char *curve;
    int oncurve;      /* Point below is on the curve.  */
    const char *qx;
    const char *qy;
  } t[] = {
    {
      "NIST P-256", 0,
      "015B4F6775D68D4D2E2192C6B8027FC5A3D49957E453CB251155AA3FF5D3EC9974",
      "4BC4C87B57A25E1056831208AB5B8F091142F891E9FF19F1E090B030DF1087B3"
    }, {
      "NIST P-256", 0,
      "D22C316E7EBE7B293BD66808E000806F0754398A5D72A4F9BBC21C26EAC0A651",
      "3C8DB80CC3CDE5E530D040536E6A58AAB41C33FA70B30896943513FF3690132D"
    }, {
      "NIST P-256", 0,
      "0130F7E7BC52854CA493A0DE87DC4AB3B4343758F2B634F15B10D70DBC0A5A5291",
      "86F9CA73C25CE86D54CB21C181AECBB52A5971334FF5040F76CAE9845ED46023"
    }, {
      "NIST P-256", 1,
      "14957B602C7849F28858C7407696F014BC091D6D68C449560B7A38147D6E6A9B",
      "A8E09EFEECFE00C797A0848F38B61992D30C61FAB13021E88C8BD3545B3A6C63"
    }, {
      "NIST P-256", 0,
      "923DE4957241DD97780841C76294DB0D4F5DC04C3045081174764D2D32AD2D53",
      "01B4B1A2027C02F0F520A3B01E4CE3C668BF481346A74499C5D1044A53E210B600"
    }, {
      "NIST P-256", 1,
      "9021DFAB8B4DAEAADA634AAA26D6E5FFDF8C0476FF5CA31606C870A1B933FB36",
      "9AFC65EEB24E46C7B75712EF29A981CB09FAC56E2B81D3ED024748CCAB1CB77E"
    }, {
      "NIST P-256", 0,
      "011529F0B26DE5E0EB2DA4BFB6C149C802CB52EE479DD666553286928A4005E990",
      "0EBC63DB2104884456DC0AA81A3F4E99D93B7AE2CD4B1489655EA9BE6289CF9E"
    }, {
      "NIST P-256", 1,
      "216EC5DE8CA989199D31F0DFCD381DCC9270A0785365EC3E34CA347C070A87BE",
      "87A88897BA763509ECC1DBE28D9D37F6F4E70E3B99B1CD3C0B934D4190968A6D"
    }, {
      "NIST P-256", 1,
      "7ABAA44ACBC6016FDB52A6F45F6178E65CBFC35F9920D99149CA9999612CE945",
      "88F7684BDCDA31EAFB6CAD859F8AB29B5D921D7DB2B34DF7E40CE36235F45B63"
    }, {
      "NIST P-256", 0,
      "E765B4272D211DD0064189B55421FB76BB3A7756364A6CB1627FAED848157A84",
      "C13171CFFB243E06B203F0996BBDD16F52292AD11F2DA81106E9C2FD87F4FA0F"
    }, {
      "NIST P-256", 0,
      "EE4999DFC3A1871EE7A592BE26A09BEC9D9B561613EE9EFB6ED42F17985C9CDC",
      "8399E967338A7A618336AF70DA67D9CAC1C19267809652F5C5183C8B129E0902"
    }, {
      "NIST P-256", 0,
      "F755D0CF2642A2C7FBACCC8E9E442B8B047A99C6E052B2FA5AB0544B36B4D51C",
      "AA080F17657B6565D9A4D94BD260B54D92FEE8DC4A78C4FC9C19209933AF39B0"
    } , {
      "NIST P-384", 0,
      "CBFC7DBEBF15BEAD682549757F9BBA0E3F67669DF13FCE0EBE8024B725B38B00"
      "83EC46A8F2FF3203C5C7F8C7E722A5EF",
      "0548FE281BEAB18FD1AB86F59B0CA524479A4A81373C83B78AFFD801FAC75922"
      "96470753DCF46173C9AA4A8A4C2FBE51"
    }, {
      "NIST P-384", 0,
      "1DC8E054A883DB81EAEDE6C487B26816C927B8196780525A6CA8F675D2557752"
      "02CE06CCBE705EA8A38AA2894D4BEEE6",
      "010191050E867AFAA96A199FE9C591CF8B853D81486786DA889124881FB39D2F"
      "8E0875F4C4BB1E3D0F8535C7A52306FB82"
    }, {
      "NIST P-384", 1,
      "2539FC368CE1D5E464B6C0FBB12D557B712327DB086975255AD7D17F7E7E4F23"
      "D719ED4116E2CC907AEB92CF22331A60",
      "8843FDBA742CB64323E49CEBE8DD74908CFC9C3AA0015662DFBB7219E92CF32E"
      "9FC63F61EF19DE9B3CEA98D163ABF254"
    }, {
      "NIST P-384", 0,
      "0B786DACF400D43575394349EDD9F9CD145FC7EF737A3C5F69B253BE7639DB24"
      "EC2F0CA62FF1F90B6515DE356EC2A404",
      "225D6B2939CC7F7133F43353946A682C68DAC6BB75EE9CF6BD9A1609FA915692"
      "72F4D3A87E88529754E109BB9B61B03B"
    }, {
      "NIST P-384", 0,
      "76C660C9F58CF2051F9F8B06049694AB6FE418009DE6F0A0833BC690CEC06CC2"
      "9A440AD51C94CF5BC28817C8C6E2D302",
      "012974E5D9E55304ED294AB6C7A3C65B663E67ABC5E6F6C0F6498B519F2F6CA1"
      "8306976291F3ADC0B5ABA42DED376EA9A5"
    }, {
      "NIST P-384", 0,
      "23D758B1EDB8E12E9E707C53C131A19D9464B20EE05C99766F5ABDF9F906AD03"
      "B958BF28B022E54E320672C4BAD4EEC0",
      "01E9E72870C88F4C82A5AB3CC8A3398E8F006BF3EC05FFBB1EFF8AEE88020FEA"
      "9E558E9F58ED1D324C9DCBCB4E8F2A5970"
    }, {
      "NIST P-384", 0,
      "D062B96D5A10F715ACF361F99262ABF0F7693A8BB60ECB1DF459CF95750E4293"
      "18BCB9FC60499D009F949298F3F9F47B",
      "9089C6328E4B39A73D7EE6FAE1A77E48CE354B83BBCE432082C32C8FD6784B86"
      "CFE9C552E2E720F5DA5806503D3784CD"
    }, {
      "NIST P-384", 0,
      "2A951D4D6EB35C43D94866280D37365B82441BC84D62CBFF3365CAB1FD0A3E20"
      "823CA8F84D2BBF4EA687885437DE7839",
      "01CC7D762AFE613F7B5568BC516568A421159C40599E8D52DE10E8F9488931E1"
      "69F3656C322DE45C4A70DC6DB9A661E599"
    }, {
      "NIST P-384", 1,
      "A4BAEE6CDAF3AEB69032B3FBA811707C54F5753670DA5173D891547E8CBAEEF3"
      "89B92C9A55573A596123415FBFA26991",
      "3241EA716583C11C71BB30AF6C5E3A6637956F17ADBBE641BAB52E8539F9FC7B"
      "F3B04F46DBFFE08151E0F0950CC70081"
    }, {
      "NIST P-384", 0,
      "5C0E18B0DE3261BCBCFC7B702C2D75CF481336BFBADF420BADC616235C1966AB"
      "4C0F876575DDEC1BDB3F3F04061C9AE4",
      "E90C78550D1C922F1D8161D8C9C0576E29BD09CA665376FA887D13FA8DF48352"
      "D7BBEEFB803F6CC8FC7895E47F348D33"
    }, {
      "NIST P-384", 1,
      "2015864CD50F0A1A50E6401F44191665C19E4AD4B4903EA9EB464E95D1070E36"
      "F1D8325E45734D5A0FDD103F4DF6F83E",
      "5FB3E9A5C59DD5C5262A8176CB7032A00AE33AED08485884A3E5D68D9EEB990B"
      "F26E8D87EC175577E782AD51A6A12C02"
    }, {
      "NIST P-384", 1,
      "56EBF5310EEF5A5D8D001F570A18625383ECD4882B3FC738A69874E7C9D8F89C"
      "187BECA23369DFD6C15CC0DA0629958F",
      "C1230B349FB662CB762563DB8F9FCB32D5CCA16120681C474D67D279CCA6F6DB"
      "73DE6AA96140B5C457B7486E06D318CE"
    }, {
      "NIST P-521", 0,
      "01E4D82EE5CD6DA37080252295EFA273BBBA6952012D0120EAF131E73F1E5024"
      "36E3324624471040030E1C345D65490ECEE9B64E03B15B6C7EB69A39C618BAFEED70",
      "03EE3A3C88A6933B7B16016BE4CC4E3BF5EA0625CB3DB2604CDCBBD02CABBC90"
      "8904D9DB42998F6C5101D4D4318ACFC9643C9CD641F636D1810ED86F1840EA74F3C0"
    }, {
      "NIST P-521", 0,
      "01F3DFCB5433387B6B2E3F74177F4F3D7300F05E1AD49DE112630E27B1C8A437"
      "1E742CB020E0039B5477FC897D17332034F9660B3066764EFF5FB440EB8856E782E3",
      "02D337616C9D202DC5E290C486F5855CBD6A8470AE62CA96245834CF49257D8D"
      "96D4041B15007650DEE668C00DDBF749054256C571F60980AC74D0DBCA7FB96C2F48"
    }, {
      "NIST P-521", 1,
      "822A846606DC9E96452CAC373567A8B57D9ACA15B177F75DD7EF10C635F52CE4"
      "EF6ABEEDB90D3F48F50A0C9015A95C955A25C45DE8413DE3BF899B6B1E62CF7CB8",
      "0102771B5F3EC8C36838CEC04DCBC28AD1E38C37DAB0EA89B5EE92D21F7A35CE"
      "ABC8B155EDC70154D6DFA2E77EC1D8C4A3406A6BD0ECF8F1EE2AC33A02464CB70C97"
    }, {
      "NIST P-521", 0,
      "F733D48467912D1FFE46CF442F27FDD218D190E7B8A829D822DA3B6BAF9B987E"
      "5B4BCCE34499248F59EEAF74F63ED15FF73F243C6FC3FD5E5842F6A3BA34C2022D",
      "0281AAAD1B7EEBABEB6EC67932CB7E95717AFA3B4CF7A2DB151CD537C419C3A5"
      "156ED9160758190B47696CDC15E81BBAD12975283907A571604DB23F702AEA4B38FF"
    }, {
      "NIST P-521", 0,
      "03B1B274175AAEB5907152E5114CCAEADA28A7ADD4A2B1831C3D8302E8596489"
      "E2C98B9B8D0CAE98C03BB11E28CE66D4736449758AF58BAFE40EF5A5FA22C9A43117",
      "94C5951F81D544E959EDFC5DC1D5F42FE427871D4FB91A43A0B4A6BEA6B35B9E"
      "BC5FB444C70BE4FD47B4ED16704F8C86EF019FC47C7FF2271F8B0DDEA9E2D3BCDD"
    }, {
      "NIST P-521", 1,
      "F2248C318055DE37CD706D4FCAF7E7D96737A4A7B6B8067A66DCD58B6B8DFC55"
      "90ECE67F6AA67F9C51B57E7B023075F2F42909BF47361CB6881C10F55FB7215B56",
      "0162F735CE6A2ADA54CAF96A12D6888C02DE0A74638CF34CE39DABBACA4D651B"
      "7E6ED1A65B551B36BAE7BE474BB6E6905ED0E33C7BA2021885027C7C6E40C5613004"
    }, {
      "NIST P-521", 0,
      "9F08E97FEADCF0A391CA1EA4D97B5FE62D3B164593E12027EB967BD6E1FA841A"
      "9831158DF164BCAD0BF3ADA96127745E25F349BDDD52EEA1654892B35960C9C023",
      "AE2A25F5440F258AFACA6925C4C9F7AEAD3CB67153C4FACB31AC33F58B43A78C"
      "B14F682FF726CEE2A6B6F6B481AEEB29A9B3150F02D1CFB764672BA8294C477291"
    }, {
      "NIST P-521", 0,
      "01047B52014748C904980716953206A93F0D01B34CA94A997407FA93FE304F86"
      "17BB6E402B2BB8B434C2671ECE953ABE7BADB75713CD9DF950943A33A9A19ACCDABE",
      "7433533F098037DEA616337986887D01C5CC8DEC3DC1FDB9CDF7287EF27CC125"
      "54FCF3A5E212DF9DAD9F8A3A7173B23FC6E15930704F3AEE1B074BDDB0ED6823E4"
    }, {
      "NIST P-521", 0,
      "01C2A9EBF51592FE6589F618EAADA1697D9B2EC7CE5D48C9E80FC597642B23F1"
      "F0EBE953449762BD3F094F57791D9850AFE98BBDA9872BE399B7BDD617860076BB03",
      "0B822E27692F63DB8E12C59BB3CCA172B9BBF613CAE5F9D1474186E45E8B26FF"
      "962084E1C6BE74821EDBB60941A3B75516F603719563433383812BFEA89EC14B89"
    }, {
      "NIST P-521", 0,
      "99390F342C3F0D46E80C5B65C61E8AA8ACA0B6D4E1352404586364A05D8398E9"
      "2BC71A644E8663F0A9B87D0B3ACAEE32F2AB9B321317AD23059D045EBAB91C5D93",
      "82FCF93AE4467EB57766F2B150E736636727E7282500CD482DA70D153D195F2B"
      "DF9B96D689A0DC1BB9137B41557A33F202F1B71840544CBEFF03072E77E4BB6F0B"
    }, {
      "NIST P-521", 1,
      "018E48E80594FF5496D8CC7DF8A19D6AA18805A4EF4490038AED6A1E9AA18056"
      "D0244A97DCF6D132C6804E3F4F369922119544B4C057D783C848FB798B48730A382C",
      "01AF510B4F5E1C40BC9C110216D35E7C6D7A2BEE52914FC98258676288449901"
      "F27A07EE91DF2D5D79259712906C3E18A990CBF35BCAC41A952820CE2BA8D0220080"
    }, {
      "NIST P-521", 1,
      "ADCEF3539B4BC831DC0AFD173137A4426152058AFBAE06A17FCB89F4DB6E48B5"
      "335CB88F8E4DB475A1E390E5656072F06605BFB84CBF9795B7992ECA04A8E10CA1",
      "01BCB985AFD6404B9EDA49B6190AAA346BF7D5909CA440C0F7E505C62FAC8635"
      "31D3EB7B2AC4DD4F4404E4B12E9D6D3C596179587F3724B1EFFF684CFDB4B21826B9"
    }
  };
  gpg_error_t err;
  int tidx;
  const char *lastcurve = NULL;
  gcry_ctx_t ctx = NULL;
  gcry_mpi_t qx = NULL;
  gcry_mpi_t qy = NULL;
  gcry_mpi_point_t Q;
  int oncurve;

  wherestr = "point_on_curve";
  for (tidx=0; tidx < DIM (t); tidx++)
    {
      if (!t[tidx].curve)
        {
          if (!lastcurve || !ctx)
            die ("invalid test vectors at idx %d\n", tidx);
        }
      else if (!ctx || !lastcurve || strcmp (t[tidx].curve, lastcurve))
        {
          lastcurve = t[tidx].curve;
          gcry_ctx_release (ctx);
          err = gcry_mpi_ec_new (&ctx, NULL, lastcurve);
          if (err)
            die ("error creating context for curve %s at idx %d: %s\n",
                 lastcurve, tidx, gpg_strerror (err));

          info ("checking points on curve %s\n", lastcurve);
        }

      gcry_mpi_release (qx);
      gcry_mpi_release (qy);
      qx = hex2mpi (t[tidx].qx);
      qy = hex2mpi (t[tidx].qy);

      Q = gcry_mpi_point_set (NULL, qx, qy, GCRYMPI_CONST_ONE);
      if (!Q)
        die ("gcry_mpi_point_set(Q) failed at idx %d\n", tidx);

      oncurve = gcry_mpi_ec_curve_point (Q, ctx);

      if (t[tidx].oncurve && !oncurve)
        {
          fail ("point expected on curve but not identified as such (i=%d):\n",
                tidx);
          print_point ("  Q", Q);
        }
      else if (!t[tidx].oncurve && oncurve)
        {
          fail ("point not expected on curve but identified as such (i=%d):\n",
                tidx);
          print_point ("  Q", Q);
        }
      gcry_mpi_point_release (Q);
    }

  gcry_mpi_release (qx);
  gcry_mpi_release (qy);
  gcry_ctx_release (ctx);
}


int
main (int argc, char **argv)
{

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");

  xgcry_control ((GCRYCTL_DISABLE_SECMEM, 0));
  xgcry_control ((GCRYCTL_ENABLE_QUICK_RANDOM, 0));
  if (debug)
    xgcry_control ((GCRYCTL_SET_DEBUG_FLAGS, 1u, 0));
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));

  set_get_point ();
  context_alloc ();
  context_param ();
  basic_ec_math ();
  point_on_curve ();

  /* The tests are for P-192 and ed25519 which are not supported in
     FIPS mode.  */
  if (!gcry_fips_mode_active())
    {
      basic_ec_math_simplified ();
      twistededwards_math ();
    }

  info ("All tests completed. Errors: %d\n", error_count);
  return error_count ? 1 : 0;
}
