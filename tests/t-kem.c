/* t-kem.c -  KEM regression tests
 * Copyright (C) 2023 Simon Josefsson <simon@josefsson.org>
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
#include <stdint.h>

#include "stopwatch.h"

#define PGM "t-kem"
#include "t-common.h"
#define N_TESTS_SNTRUP761 10
#define N_TESTS_MLKEM 10

static int in_fips_mode;

static void
show_note (const char *format, ...)
{
  va_list arg_ptr;

  if (!verbose && getenv ("srcdir"))
    fputs ("      ", stderr);	/* To align above "PASS: ".  */
  else
    fprintf (stderr, "%s: ", PGM);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  if (*format && format[strlen (format) - 1] != '\n')
    putc ('\n', stderr);
  va_end (arg_ptr);
}


static void
test_kem_sntrup761 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_SNTRUP761_PUBLICKEY_SIZE];
  uint8_t seckey[GCRY_KEM_SNTRUP761_SECRETKEY_SIZE];
  uint8_t ciphertext[GCRY_KEM_SNTRUP761_CIPHERTEXT_SIZE];
  uint8_t key1[GCRY_KEM_SNTRUP761_SHAREDSECRET_SIZE];
  uint8_t key2[GCRY_KEM_SNTRUP761_SHAREDSECRET_SIZE];

  err = gcry_kem_keypair (GCRY_KEM_SNTRUP761, NULL, pubkey, seckey);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_SNTRUP761, NULL, pubkey, ciphertext, key1);
  if (err)
    {
      fail ("gcry_kem_enc %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_SNTRUP761, NULL, seckey, ciphertext, key2);
  if (err)
    {
      fail ("gcry_kem_dec %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, GCRY_KEM_SNTRUP761_SHAREDSECRET_SIZE) != 0)
    {
      size_t i;

      fail ("sntrup761 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < GCRY_KEM_SNTRUP761_SHAREDSECRET_SIZE; i++)
	fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < GCRY_KEM_SNTRUP761_SHAREDSECRET_SIZE; i++)
	fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

static void
test_kem_mlkem_sub (int testno, int algo, size_t size)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_MLKEM1024_PUBLICKEY_SIZE];
  uint8_t seckey[GCRY_KEM_MLKEM1024_SECRETKEY_SIZE];
  uint8_t ciphertext[GCRY_KEM_MLKEM1024_CIPHERTEXT_SIZE];
  uint8_t key1[GCRY_KEM_MLKEM1024_SHAREDSECRET_SIZE];
  uint8_t key2[GCRY_KEM_MLKEM1024_SHAREDSECRET_SIZE];

  err = gcry_kem_keypair (algo, NULL, pubkey, seckey);
  if (err)
    {
      fail ("gcry_kem_keypair %d %d: %s", testno, algo, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (algo, NULL, pubkey, ciphertext, key1);
  if (err)
    {
      fail ("gcry_kem_enc %d %d: %s", testno, algo, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (algo, NULL, seckey, ciphertext, key2);
  if (err)
    {
      fail ("gcry_kem_dec %d %d: %s", testno, algo, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, size) != 0)
    {
      size_t i;

      fail ("mlkem %d test %d failed: mismatch\n", algo, testno);
      fputs ("key1:", stderr);
      for (i = 0; i < size; i++)
	fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < size; i++)
	fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

static void
test_kem_mlkem (int testno)
{
  int algo[3] = { GCRY_KEM_MLKEM512, GCRY_KEM_MLKEM768, GCRY_KEM_MLKEM1024};
  size_t size[3] = {
    GCRY_KEM_MLKEM512_SHAREDSECRET_SIZE,
    GCRY_KEM_MLKEM768_SHAREDSECRET_SIZE,
    GCRY_KEM_MLKEM1024_SHAREDSECRET_SIZE
  };
  int i;

  for (i = 0; i < 3; i++)
    test_kem_mlkem_sub (testno, algo[i], size[i]);
}

static void
check_kem (void)
{
  int ntests;

  info ("Checking KEM.\n");

  for (ntests = 0; ntests < N_TESTS_SNTRUP761; ntests++)
    test_kem_sntrup761 (ntests);

  for (ntests = 0; ntests < N_TESTS_MLKEM; ntests++)
    test_kem_mlkem (ntests + N_TESTS_SNTRUP761);

  show_note ("%d tests done\n", ntests + N_TESTS_SNTRUP761);
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
	  fputs ("usage: " PGM " [options]\n"
		 "Options:\n"
		 "  --verbose       print timings etc.\n"
		 "  --debug         flyswatter\n", stdout);
	  exit (0);
	}
      else if (!strcmp (*argv, "--verbose"))
	{
	  verbose++;
	  argc--;
	  argv++;
	}
      else if (!strcmp (*argv, "--debug"))
	{
	  verbose += 2;
	  debug++;
	  argc--;
	  argv++;
	}
      else if (!strncmp (*argv, "--", 2))
	die ("unknown option '%s'", *argv);
    }

  xgcry_control ((GCRYCTL_DISABLE_SECMEM, 0));
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  if (debug)
    xgcry_control ((GCRYCTL_SET_DEBUG_FLAGS, 1u, 0));
  xgcry_control ((GCRYCTL_ENABLE_QUICK_RANDOM, 0));
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));

  if (gcry_fips_mode_active ())
    in_fips_mode = 1;

  start_timer ();
  check_kem ();
  stop_timer ();

  info ("All tests completed in %s.  Errors: %d\n",
	elapsed_time (1), error_count);
  return !!error_count;
}
