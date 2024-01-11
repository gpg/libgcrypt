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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdint.h>

#include "stopwatch.h"

#define PGM "t-kem"
#define NEED_SHOW_NOTE
#include "t-common.h"
#define N_TESTS 10

static int in_fips_mode;

static void
test_kem_sntrup761 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_SNTRUP761_PUBKEY_LEN];
  uint8_t seckey[GCRY_KEM_SNTRUP761_SECKEY_LEN];
  uint8_t ciphertext[GCRY_KEM_SNTRUP761_ENCAPS_LEN];
  uint8_t key1[GCRY_KEM_SNTRUP761_SHARED_LEN];
  uint8_t key2[GCRY_KEM_SNTRUP761_SHARED_LEN];

  err = gcry_kem_keypair (GCRY_KEM_SNTRUP761,
                          pubkey, GCRY_KEM_SNTRUP761_PUBKEY_LEN,
                          seckey, GCRY_KEM_SNTRUP761_SECKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_SNTRUP761,
                        pubkey, GCRY_KEM_SNTRUP761_PUBKEY_LEN,
                        ciphertext, GCRY_KEM_SNTRUP761_ENCAPS_LEN,
                        key1, GCRY_KEM_SNTRUP761_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_enc %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_SNTRUP761,
                        seckey, GCRY_KEM_SNTRUP761_SECKEY_LEN,
                        ciphertext, GCRY_KEM_SNTRUP761_ENCAPS_LEN,
                        key2, GCRY_KEM_SNTRUP761_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_dec %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, GCRY_KEM_SNTRUP761_SHARED_LEN) != 0)
    {
      size_t i;

      fail ("sntrup761 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < GCRY_KEM_SNTRUP761_SHARED_LEN; i++)
	fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < GCRY_KEM_SNTRUP761_SHARED_LEN; i++)
	fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

static void
test_kem_mlkem512 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_MLKEM512_PUBKEY_LEN];
  uint8_t seckey[GCRY_KEM_MLKEM512_SECKEY_LEN];
  uint8_t ciphertext[GCRY_KEM_MLKEM512_ENCAPS_LEN];
  uint8_t key1[GCRY_KEM_MLKEM512_SHARED_LEN];
  uint8_t key2[GCRY_KEM_MLKEM512_SHARED_LEN];

  err = gcry_kem_keypair (GCRY_KEM_MLKEM512,
                          pubkey, GCRY_KEM_MLKEM512_PUBKEY_LEN,
                          seckey, GCRY_KEM_MLKEM512_SECKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_MLKEM512,
                        pubkey, GCRY_KEM_MLKEM512_PUBKEY_LEN,
                        ciphertext, GCRY_KEM_MLKEM512_ENCAPS_LEN,
                        key1, GCRY_KEM_MLKEM512_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_enc %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_MLKEM512,
                        seckey, GCRY_KEM_MLKEM512_SECKEY_LEN,
                        ciphertext, GCRY_KEM_MLKEM512_ENCAPS_LEN,
                        key2, GCRY_KEM_MLKEM512_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_dec %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, GCRY_KEM_MLKEM512_SHARED_LEN) != 0)
    {
      size_t i;

      fail ("mlkem512 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < GCRY_KEM_MLKEM512_SHARED_LEN; i++)
	fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < GCRY_KEM_MLKEM512_SHARED_LEN; i++)
	fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

static void
test_kem_mlkem768 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_MLKEM768_PUBKEY_LEN];
  uint8_t seckey[GCRY_KEM_MLKEM768_SECKEY_LEN];
  uint8_t ciphertext[GCRY_KEM_MLKEM768_ENCAPS_LEN];
  uint8_t key1[GCRY_KEM_MLKEM768_SHARED_LEN];
  uint8_t key2[GCRY_KEM_MLKEM768_SHARED_LEN];

  err = gcry_kem_keypair (GCRY_KEM_MLKEM768,
                          pubkey, GCRY_KEM_MLKEM768_PUBKEY_LEN,
                          seckey, GCRY_KEM_MLKEM768_SECKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_MLKEM768,
                        pubkey, GCRY_KEM_MLKEM768_PUBKEY_LEN,
                        ciphertext, GCRY_KEM_MLKEM768_ENCAPS_LEN,
                        key1, GCRY_KEM_MLKEM768_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_enc %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_MLKEM768,
                        seckey, GCRY_KEM_MLKEM768_SECKEY_LEN,
                        ciphertext, GCRY_KEM_MLKEM768_ENCAPS_LEN,
                        key2, GCRY_KEM_MLKEM768_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_dec %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, GCRY_KEM_MLKEM768_SHARED_LEN) != 0)
    {
      size_t i;

      fail ("mlkem768 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < GCRY_KEM_MLKEM768_SHARED_LEN; i++)
	fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < GCRY_KEM_MLKEM768_SHARED_LEN; i++)
	fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

static void
test_kem_mlkem1024 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_MLKEM1024_PUBKEY_LEN];
  uint8_t seckey[GCRY_KEM_MLKEM1024_SECKEY_LEN];
  uint8_t ciphertext[GCRY_KEM_MLKEM1024_ENCAPS_LEN];
  uint8_t key1[GCRY_KEM_MLKEM1024_SHARED_LEN];
  uint8_t key2[GCRY_KEM_MLKEM1024_SHARED_LEN];

  err = gcry_kem_keypair (GCRY_KEM_MLKEM1024,
                          pubkey, GCRY_KEM_MLKEM1024_PUBKEY_LEN,
                          seckey, GCRY_KEM_MLKEM1024_SECKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_MLKEM1024,
                        pubkey, GCRY_KEM_MLKEM1024_PUBKEY_LEN,
                        ciphertext, GCRY_KEM_MLKEM1024_ENCAPS_LEN,
                        key1, GCRY_KEM_MLKEM1024_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_enc %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_MLKEM1024,
                        seckey, GCRY_KEM_MLKEM1024_SECKEY_LEN,
                        ciphertext, GCRY_KEM_MLKEM1024_ENCAPS_LEN,
                        key2, GCRY_KEM_MLKEM1024_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_dec %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, GCRY_KEM_MLKEM1024_SHARED_LEN) != 0)
    {
      size_t i;

      fail ("mlkem1024 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < GCRY_KEM_MLKEM1024_SHARED_LEN; i++)
	fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < GCRY_KEM_MLKEM1024_SHARED_LEN; i++)
	fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

static void
check_kem (void)
{
  int ntests;

  info ("Checking KEM.\n");

  for (ntests = 0; ntests < N_TESTS; ntests++)
#if 0
    test_kem_sntrup761 (ntests);
#else
    test_kem_mlkem1024 (ntests);
#endif

  if (ntests != N_TESTS)
    fail ("did %d tests but expected %d", ntests, N_TESTS);
  else if ((ntests % 256))
    show_note ("%d tests done\n", ntests);
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
