/* t-convert.c  - Tests for mpi print and scna functions
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

#include "../src/gcrypt-int.h"

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


/* Check that mpi_print does not return a negative zero.  */
static void
negative_zero (void)
{
  gpg_error_t err;
  gcry_mpi_t a;
  char *buf;
  void *bufaddr = &buf;
  struct { const char *name; enum gcry_mpi_format format; } fmts[] =
    {
      { "STD", GCRYMPI_FMT_STD },
      { "PGP", GCRYMPI_FMT_PGP },
      { "SSH", GCRYMPI_FMT_SSH },
      { "HEX", GCRYMPI_FMT_HEX },
      { "USG", GCRYMPI_FMT_USG },
      { NULL, 0 }
    };
  int i;

  a = gcry_mpi_new (0);
  for (i=0; fmts[i].name; i++)
    {
      err = gcry_mpi_aprint (fmts[i].format, bufaddr, NULL, a);
      if (err)
        fail ("error printing a zero as %s: %s\n",
              fmts[i].name,gpg_strerror (err) );
      else
        gcry_free (buf);
    }

  /* With the current version of libgcrypt the next two statements
     should set a to -0. */
  gcry_mpi_sub_ui (a, a, 1);
  gcry_mpi_add_ui (a, a, 1);

  for (i=0; fmts[i].name; i++)
    {
      err = gcry_mpi_aprint (fmts[i].format, bufaddr, NULL, a);
      if (err)
        fail ("error printing a negative zero as %s: %s\n",
              fmts[i].name,gpg_strerror (err) );
      else
        gcry_free (buf);
    }

  gcry_mpi_release (a);
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

  negative_zero ();

  show ("All tests completed. Errors: %d\n", error_count);
  return error_count ? 1 : 0;
}
