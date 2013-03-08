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

#include "../src/gcrypt.h"

#define PGM "t-mpi-point"

static const char *wherestr;
static int verbose;
static int debug;
static int error_count;


#define xmalloc(a)    gcry_xmalloc ((a))
#define xcalloc(a,b)  gcry_xcalloc ((a),(b))
#define xfree(a)      gcry_free ((a))
#define pass() do { ; } while (0)

static void
show (const char *format, ...)
{
  va_list arg_ptr;

  if (!verbose)
    return;
  fprintf (stderr, "%s: ", PGM);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
}

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);
  if (wherestr)
    fprintf (stderr, "%s: ", wherestr);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
}

static void
die (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);
  if (wherestr)
    fprintf (stderr, "%s: ", wherestr);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
}


static void
print_mpi (const char *text, gcry_mpi_t a)
{
  gcry_error_t err;
  char *buf;
  void *bufaddr = &buf;

  err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, bufaddr, NULL, a);
  if (err)
    fprintf (stderr, "%s: [error printing number: %s]\n",
             text, gpg_strerror (err));
  else
    {
      fprintf (stderr, "%s: %s\n", text, buf);
      gcry_free (buf);
    }
}


static gcry_mpi_t
hex2mpi (const char *string)
{
  gpg_error_t err;
  gcry_mpi_t val;

  err = gcry_mpi_scan (&val, GCRYMPI_FMT_HEX, string, 0, NULL);
  if (err)
    die ("hex2mpi '%s' failed: %s\n", gpg_strerror (err));
  return val;
}


/* Compare A to B, where B is given as a hex string.  */
static int
cmp_mpihex (gcry_mpi_t a, const char *b)
{
  gcry_mpi_t bval;
  int res;

  bval = hex2mpi (b);
  res = gcry_mpi_cmp (a, bval);
  gcry_mpi_release (bval);
  return res;
}



static void
set_get_point (void)
{
  gcry_mpi_point_t point;
  gcry_mpi_t x, y, z;

  wherestr = "set_get_point";
  show ("checking point setting functions\n");

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

  gcry_mpi_point_release (point);
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (z);
}


static void
context_alloc (void)
{
  gcry_ctx_t ctx;
  gcry_mpi_t p, a;

  wherestr = "context_alloc";
  show ("checking context functions\n");

  p = gcry_mpi_set_ui (NULL, 1);
  a = gcry_mpi_set_ui (NULL, 1);
  ctx = gcry_mpi_ec_p_new (p, a);
  if (!ctx)
    die ("gcry_mpi_ec_p_new returned an error: %s\n",
         gpg_strerror (gpg_error_from_syserror ()));
  gcry_mpi_release (p);
  gcry_mpi_release (a);
  gcry_ctx_release (ctx);

  p = gcry_mpi_set_ui (NULL, 0);
  a = gcry_mpi_set_ui (NULL, 0);
  ctx = gcry_mpi_ec_p_new (p, a);
  if (ctx || gpg_err_code_from_syserror () != GPG_ERR_EINVAL)
    fail ("gcry_mpi_ec_p_new: bad parameter detection failed (1)\n");

  gcry_mpi_set_ui (p, 1);
  ctx = gcry_mpi_ec_p_new (p, a);
  if (ctx || gpg_err_code_from_syserror () != GPG_ERR_EINVAL)
    fail ("gcry_mpi_ec_p_new: bad parameter detection failed (2)\n");

  gcry_mpi_release (p);
  p = NULL;
  ctx = gcry_mpi_ec_p_new (p, a);
  if (ctx || gpg_err_code_from_syserror () != GPG_ERR_EINVAL)
    fail ("gcry_mpi_ec_p_new: bad parameter detection failed (3)\n");

  gcry_mpi_release (a);
  a = NULL;
  ctx = gcry_mpi_ec_p_new (p, a);
  if (ctx || gpg_err_code_from_syserror () != GPG_ERR_EINVAL)
    fail ("gcry_mpi_ec_p_new: bad parameter detection failed (4)\n");

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


static void
basic_ec_math (void)
{
  gcry_ctx_t ctx;
  gcry_mpi_t P, A;
  gcry_mpi_point_t G, Q;
  gcry_mpi_t d;
  gcry_mpi_t x, y, z;

  wherestr = "set_get_point";
  show ("checking basic math functions for EC\n");

  P = hex2mpi ("0xfffffffffffffffffffffffffffffffeffffffffffffffff");
  A = hex2mpi ("0xfffffffffffffffffffffffffffffffefffffffffffffffc");
  G = make_point ("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
                  "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
                  "1");
  d = hex2mpi ("D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D");
  Q = gcry_mpi_point_new (0);

  ctx = gcry_mpi_ec_p_new (P, A);
  gcry_mpi_ec_mul (Q, d, G, ctx);

  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);
  gcry_mpi_point_get (x, y, z, Q);
  if (cmp_mpihex (x, "222D9EC717C89D047E0898C9185B033CD11C0A981EE6DC66")
      || cmp_mpihex (y, "605DE0A82D70D3E0F84A127D0739ED33D657DF0D054BFDE8")
      || cmp_mpihex (z, "00B06B519071BC536999AC8F2D3934B3C1FC9EACCD0A31F88F"))
    fail ("computed public key does not match\n");
  if (debug)
    {
      print_mpi ("Q.x", x);
      print_mpi ("Q.y", y);
      print_mpi ("Q.z", z);
    }

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

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  set_get_point ();
  context_alloc ();
  basic_ec_math ();

  show ("All tests completed. Errors: %d\n", error_count);
  return error_count ? 1 : 0;
}
