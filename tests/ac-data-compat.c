/* ac-data.c - Public key encryption/decryption tests
 *	Copyright (C) 2005 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define assert_err(err) \
  do \
    if (err) \
      { \
        fprintf (stderr, "Error occured at line %i: %s\n", \
                 __LINE__, gcry_strerror (err)); \
        exit (1); \
      } \
  while (0)

#include "../src/compat/gcrypt.h"
#include "common.h"

unsigned int test_startup_flags = 0;

static int verbose;

static void
check_sexp_conversion (gcry_ac_data_t data)
{
  const char *identifiers[] = { "foo",
				"bar",
				"baz",
				"hello",
				"somemoretexthere",
				"blahblahblah",
				NULL };
  gcry_ac_data_t data2;
  gcry_error_t err;
  gcry_sexp_t sexp;
  unsigned int i;
  const char *label1, *label2;
  gcry_mpi_t mpi1, mpi2;
  size_t length1, length2;

  err = gcry_ac_data_to_sexp (data, &sexp, identifiers);
  assert_err (err);

  err = gcry_ac_data_from_sexp (&data2, sexp, identifiers);
  assert_err (err);

  length1 = gcry_ac_data_length (data);
  length2 = gcry_ac_data_length (data2);
  assert (length1 == length2);

  for (i = 0; i < length1; i++)
    {
      err = gcry_ac_data_get_index (data, 0, i, &label1, &mpi1);
      assert_err (err);
      err = gcry_ac_data_get_index (data2, 0, i, &label2, &mpi2);
      assert_err (err);
      assert (! strcmp (label1, label2));
      assert (! gcry_mpi_cmp (mpi1, mpi2));
    }

  gcry_ac_data_destroy (data2);
  gcry_sexp_release (sexp);
}

void
check_run (void)
{
  gcry_ac_data_t data;
  gcry_error_t err;
  const char *label0;
  const char *label1;
  gcry_mpi_t mpi0;
  gcry_mpi_t mpi1;
  gcry_mpi_t mpi2;

  label0 = "thisisreallylonglabelbutsincethereisnolimitationonthelengthoflabelsitshouldworkjustfine";
  mpi0 = gcry_mpi_new (0);
  assert (mpi0);
  gcry_mpi_set_ui (mpi0, 123456);

  err = gcry_ac_data_new (&data);
  assert_err (err);

  err = gcry_ac_data_set (data, 0, label0, mpi0);
  assert_err (err);
  err = gcry_ac_data_get_index (data, 0, 0, &label1, &mpi1);
  assert_err (err);
  assert (label0 == label1);
  assert (mpi0 == mpi1);
  check_sexp_conversion (data);
  printf ("data-set-test-0 succeeded\n");

  gcry_ac_data_clear (data);

  err = gcry_ac_data_set (data, GCRY_AC_FLAG_COPY, label0, mpi0);
  assert_err (err);
  err = gcry_ac_data_set (data, GCRY_AC_FLAG_COPY | GCRY_AC_FLAG_DEALLOC,
			  "foo", mpi0);
  assert_err (err);
  err = gcry_ac_data_set (data, GCRY_AC_FLAG_COPY | GCRY_AC_FLAG_DEALLOC,
			  "foo", mpi0);
  assert_err (err);
  err = gcry_ac_data_set (data, GCRY_AC_FLAG_COPY | GCRY_AC_FLAG_DEALLOC,
			  "bar", mpi0);
  assert_err (err);
  err = gcry_ac_data_set (data, GCRY_AC_FLAG_COPY | GCRY_AC_FLAG_DEALLOC,
			  "blah1", mpi0);
  assert_err (err);
  check_sexp_conversion (data);
  err = gcry_ac_data_get_name (data, 0, label0, &mpi1);
  assert_err (err);
  assert (mpi0 != mpi1);
  err = gcry_ac_data_get_name (data, GCRY_AC_FLAG_COPY, label0, &mpi2);
  assert_err (err);
  assert (mpi0 != mpi1);
  assert (mpi1 != mpi2);
  err = gcry_ac_data_get_index (data, 0, 0, &label1, &mpi1);
  assert_err (err);
  gcry_free ((void *) label1);	/* FIXME!! */
  gcry_mpi_release (mpi1);
    
  printf ("data-set-test-1 succeeded\n");

  gcry_ac_data_clear (data);
  assert (! gcry_ac_data_length (data));
  check_sexp_conversion (data);
  printf ("data-set-test-2 succeeded\n");
 
  gcry_ac_data_destroy (data);
 

}

int
test_main (int argc, char **argv)
{
  int debug = 0;
  int i = 1;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

  for (; i > 0; i--)
    check_run ();
  
  return 0;
}
