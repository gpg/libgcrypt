/* encoding.c - test encoding/decoding of messages
   Copyright (C) 2003 Free Software Foundation, Inc.

   This file is part of Libgcrypt.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA.  */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/gcrypt.h"

#define TEST_NAME encoding
#include "test-glue.h"

static int verbose;

static void
die (const char *format, ...)
{
  va_list arg_ptr ;

  va_start( arg_ptr, format ) ;
  vfprintf (stderr, format, arg_ptr );
  va_end(arg_ptr);
  exit (1);
}

static gcry_error_t
encoding_check_eme_pkcs_v1_5 (unsigned char *m, size_t m_n)
{
  struct key_mpi
  {
    const char *name;
    const char *mpi_string;
    gcry_mpi_t mpi;
  } key_mpis[] =
    {
      { "n",
	"#00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
	"2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
	"ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
	"891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#" },
      { "e",
	"#010001#" },
    };
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_ac_key_t key_public = NULL;

  gcry_ac_data_t key_data = NULL;
  gcry_ac_handle_t h = NULL;
  unsigned int i = 0;

  unsigned char *em = NULL, *m2 = NULL;
  size_t em_n = 0, m2_n = 0;

  gcry_ac_eme_pkcs_v1_5_t opts;
  
  err = gcry_ac_open (&h, GCRY_AC_RSA, 0);
  if (! err)
    err = gcry_ac_data_new (&key_data);

  for (i = 0; (i < (sizeof (key_mpis) / sizeof (*key_mpis))) && (! err); i++)
    {
      err = gcry_mpi_scan (&key_mpis[i].mpi, GCRYMPI_FMT_USG,
			   key_mpis[i].mpi_string,
			   strlen (key_mpis[i].mpi_string), NULL);
    }

  for (i = 0; (i < (sizeof (key_mpis) / sizeof (*key_mpis))) && (! err); i++)
    err = gcry_ac_data_set (key_data, 0, key_mpis[i].name, key_mpis[i].mpi);
  if (! err)
    err = gcry_ac_key_init (&key_public, NULL, GCRY_AC_KEY_PUBLIC, key_data);

  if (! err)
    {
      opts.handle = h;
      opts.key = key_public;
      
      err = gcry_ac_data_encode (GCRY_AC_EME_PKCS_V1_5, 0, (void *) &opts,
				 m, m_n, &em, &em_n);
    }

  if (! err)
    {
      err = gcry_ac_data_decode (GCRY_AC_EME_PKCS_V1_5, 0, (void *) &opts,
				 em, em_n, &m2, &m2_n);

      assert (m2_n == m_n);
      assert (! strncmp (m, m2, m_n));
    }

  if (key_data)
    gcry_ac_data_destroy (key_data);
  if (key_public)
    gcry_ac_key_destroy (key_public);
  if (h)
    gcry_ac_close (h);

  return err;
}

static gcry_error_t
encoding_check_emsa_pkcs_v1_5 (unsigned char *m, size_t m_n)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_ac_emsa_pkcs_v1_5_t opts;
  unsigned char *em = NULL;
  size_t em_n = 0;

  opts.md = GCRY_MD_SHA1;
  opts.em_n = 50;

  err = gcry_ac_data_encode (GCRY_AC_EMSA_PKCS_V1_5, 0, (void *) &opts,
			     m, m_n, &em, &em_n);

  return err;
}

static gcry_error_t
encoding_check (void)
{
  struct check_list
  {
    gcry_error_t (*func) (unsigned char *m, size_t m_n);
  } check_list[] =
    {
      { encoding_check_eme_pkcs_v1_5 },
      { encoding_check_emsa_pkcs_v1_5 },
    };
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; (i < (sizeof (check_list) / sizeof (*check_list))) && (! err); i++)
    err = (*check_list[i].func) ("foobar", 6);

  return err;
}

static gcry_error_t
check_run (void)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;

  err = encoding_check ();
  
  return err;
}

int
main (int argc, char **argv)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  int debug = 0;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

  err = check_run ();
  if (err)
    fprintf (stderr, "Error: %s\n", gpg_strerror (err));
    
  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

#include "test-glue.h"
