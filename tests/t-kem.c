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
test_kem_raw_x25519 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_ECC_X25519_PUBKEY_LEN];
  uint8_t seckey[GCRY_KEM_ECC_X25519_SECKEY_LEN];
  uint8_t ciphertext[GCRY_KEM_ECC_X25519_ENCAPS_LEN];
  uint8_t key1[GCRY_KEM_RAW_X25519_SHARED_LEN];
  uint8_t key2[GCRY_KEM_RAW_X25519_SHARED_LEN];

  err = gcry_kem_keypair (GCRY_KEM_RAW_X25519,
                          pubkey, GCRY_KEM_ECC_X25519_PUBKEY_LEN,
                          seckey, GCRY_KEM_ECC_X25519_SECKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_RAW_X25519,
                        pubkey, GCRY_KEM_ECC_X25519_PUBKEY_LEN,
                        ciphertext, GCRY_KEM_ECC_X25519_ENCAPS_LEN,
                        key1, GCRY_KEM_RAW_X25519_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_encap %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_RAW_X25519,
                        seckey, GCRY_KEM_ECC_X25519_SECKEY_LEN,
                        ciphertext, GCRY_KEM_ECC_X25519_ENCAPS_LEN,
                        key2, GCRY_KEM_RAW_X25519_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, GCRY_KEM_RAW_X25519_SHARED_LEN) != 0)
    {
      size_t i;

      fail ("raw-x25519 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < GCRY_KEM_RAW_X25519_SHARED_LEN; i++)
        fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < GCRY_KEM_RAW_X25519_SHARED_LEN; i++)
        fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}


static void
test_kem_dhkem_x25519 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_DHKEM25519_PUBKEY_LEN];
  uint8_t seckey[GCRY_KEM_DHKEM25519_SECKEY_LEN];
  uint8_t ciphertext[GCRY_KEM_DHKEM25519_ENCAPS_LEN];
  uint8_t key1[GCRY_KEM_DHKEM25519_SHARED_LEN];
  uint8_t key2[GCRY_KEM_DHKEM25519_SHARED_LEN];

  err = gcry_kem_keypair (GCRY_KEM_DHKEM25519,
                          pubkey, GCRY_KEM_DHKEM25519_PUBKEY_LEN,
                          seckey, GCRY_KEM_DHKEM25519_SECKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_DHKEM25519,
                        pubkey, GCRY_KEM_DHKEM25519_PUBKEY_LEN,
                        ciphertext, GCRY_KEM_DHKEM25519_ENCAPS_LEN,
                        key1, GCRY_KEM_DHKEM25519_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      fail ("gcry_kem_encap %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_DHKEM25519,
                        seckey, GCRY_KEM_DHKEM25519_SECKEY_LEN,
                        ciphertext, GCRY_KEM_DHKEM25519_ENCAPS_LEN,
                        key2, GCRY_KEM_DHKEM25519_SHARED_LEN,
                        pubkey, GCRY_KEM_DHKEM25519_PUBKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, GCRY_KEM_DHKEM25519_SHARED_LEN) != 0)
    {
      size_t i;

      fail ("dhkem-x25519 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < GCRY_KEM_DHKEM25519_SHARED_LEN; i++)
        fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < GCRY_KEM_DHKEM25519_SHARED_LEN; i++)
        fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

/* In the following case, with AES128-keywrap, shared secret length is 16.  */
#define MY_KEM_PGP_X25519_SHARED_LEN 16

static void
test_kem_openpgp_x25519 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_ECC_X25519_PUBKEY_LEN];
  uint8_t seckey[GCRY_KEM_ECC_X25519_SECKEY_LEN];
  uint8_t ciphertext[GCRY_KEM_ECC_X25519_ENCAPS_LEN];
  uint8_t key1[MY_KEM_PGP_X25519_SHARED_LEN];
  uint8_t key2[MY_KEM_PGP_X25519_SHARED_LEN];
  const uint8_t kdf_param[56] = {
    0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55,
    0x01, 0x05, 0x01,
    /**/
    0x12,
    /**/
    0x03, 0x01, 0x08 /*SHA256*/, 0x07 /* AES128 */,
    /**/
    0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75,
    0x73, 0x20, 0x53, 0x65, 0x6e, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20, /* "Anonymous Sender    " */
    /**/
    0x25, 0xd4, 0x45, 0xfa, 0xc1, 0x96, 0x49, 0xc4,
    0x6a, 0x6b, 0x2f, 0xb3, 0xcd, 0xfc, 0x22, 0x19,
    0xc5, 0x53, 0xd3, 0x92  /* public key fingerprint */
  };

  err = gcry_kem_keypair (GCRY_KEM_PGP_X25519,
                          pubkey, GCRY_KEM_ECC_X25519_PUBKEY_LEN,
                          seckey, GCRY_KEM_ECC_X25519_SECKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_PGP_X25519,
                        pubkey, GCRY_KEM_ECC_X25519_PUBKEY_LEN,
                        ciphertext, GCRY_KEM_ECC_X25519_ENCAPS_LEN,
                        key1, MY_KEM_PGP_X25519_SHARED_LEN,
                        kdf_param, sizeof (kdf_param));
  if (err)
    {
      fail ("gcry_kem_encap %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_PGP_X25519,
                        seckey, GCRY_KEM_ECC_X25519_SECKEY_LEN,
                        ciphertext, GCRY_KEM_ECC_X25519_ENCAPS_LEN,
                        key2, MY_KEM_PGP_X25519_SHARED_LEN,
                        kdf_param, sizeof (kdf_param));
  if (err)
    {
      fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, MY_KEM_PGP_X25519_SHARED_LEN) != 0)
    {
      size_t i;

      fail ("openpgp-x25519 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < MY_KEM_PGP_X25519_SHARED_LEN; i++)
        fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < MY_KEM_PGP_X25519_SHARED_LEN; i++)
        fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}


/* In the following case, with AES128-keywrap, shared secret length is 16.  */
#define MY_KEM_CMS_X25519_SHARED_LEN 16

static void
test_kem_cms_x25519 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_ECC_X25519_PUBKEY_LEN];
  uint8_t seckey[GCRY_KEM_ECC_X25519_SECKEY_LEN];
  uint8_t ciphertext[GCRY_KEM_ECC_X25519_ENCAPS_LEN];
  uint8_t key1[MY_KEM_CMS_X25519_SHARED_LEN];
  uint8_t key2[MY_KEM_CMS_X25519_SHARED_LEN];
  const uint8_t sharedinfo[23] = {
    0x30, 0x15 , /* SEQUENCE */
          0x30, 0x0B, /* SEQUENCE */
              /* OID */
                0x06, 0x09, /* OBJECT_ID */
                      0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05,
          /* CONTEXT 2*/
          0xA2, 0x06,
                      0x04, 0x04, /* OCTET STRING */
                      0x00, 0x00, 0x00, 0x80
  };

  err = gcry_kem_keypair (GCRY_KEM_CMS_X25519_X963_SHA256,
                          pubkey, GCRY_KEM_ECC_X25519_PUBKEY_LEN,
                          seckey, GCRY_KEM_ECC_X25519_SECKEY_LEN);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_CMS_X25519_X963_SHA256,
                        pubkey, GCRY_KEM_ECC_X25519_PUBKEY_LEN,
                        ciphertext, GCRY_KEM_ECC_X25519_ENCAPS_LEN,
                        key1, MY_KEM_CMS_X25519_SHARED_LEN,
                        sharedinfo, sizeof (sharedinfo));
  if (err)
    {
      fail ("gcry_kem_encap %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_CMS_X25519_X963_SHA256,
                        seckey, GCRY_KEM_ECC_X25519_SECKEY_LEN,
                        ciphertext, GCRY_KEM_ECC_X25519_ENCAPS_LEN,
                        key2, MY_KEM_CMS_X25519_SHARED_LEN,
                        sharedinfo, sizeof (sharedinfo));
  if (err)
    {
      fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, MY_KEM_CMS_X25519_SHARED_LEN) != 0)
    {
      size_t i;

      fail ("openpgp-x25519 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < MY_KEM_CMS_X25519_SHARED_LEN; i++)
        fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < MY_KEM_CMS_X25519_SHARED_LEN; i++)
        fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}


#define SELECTED_ALGO_SNTRUP761  (1 << 0)
#define SELECTED_ALGO_MLKEM512   (1 << 1)
#define SELECTED_ALGO_MLKEM768   (1 << 2)
#define SELECTED_ALGO_MLKEM1024  (1 << 3)
#define SELECTED_ALGO_RAW_X25519 (1 << 4)
#define SELECTED_ALGO_DHKEM25519 (1 << 5)
#define SELECTED_ALGO_PGP_X25519 (1 << 6)
#define SELECTED_ALGO_CMS_X25519 (1 << 7)
static unsigned int selected_algo;

static void
check_kem (int n_loops)
{
  int ntests;
  int testno;

  info ("Checking KEM.\n");

  ntests = 0;
  testno = 0;
  if ((selected_algo & SELECTED_ALGO_SNTRUP761))
    {
      for (; testno < n_loops; testno++)
        test_kem_sntrup761 (testno);
      ntests += n_loops;
    }

  if ((selected_algo & SELECTED_ALGO_MLKEM512))
    {
      for (; testno < ntests + n_loops; testno++)
        test_kem_mlkem512 (testno);
      ntests += n_loops;
    }

  if ((selected_algo & SELECTED_ALGO_MLKEM768))
    {
      for (; testno < ntests + n_loops; testno++)
        test_kem_mlkem768 (testno);
      ntests += n_loops;
    }

  if ((selected_algo & SELECTED_ALGO_MLKEM1024))
    {
      for (; testno < ntests + n_loops; testno++)
        test_kem_mlkem1024 (testno);
      ntests += n_loops;
    }

  if ((selected_algo & SELECTED_ALGO_RAW_X25519))
    {
      for (; testno < ntests + n_loops; testno++)
        test_kem_raw_x25519 (testno);
      ntests += n_loops;
    }

  if ((selected_algo & SELECTED_ALGO_DHKEM25519))
    {
      for (; testno < ntests + n_loops; testno++)
        test_kem_dhkem_x25519 (testno);
      ntests += n_loops;
    }

  if ((selected_algo & SELECTED_ALGO_PGP_X25519))
    {
      for (; testno < ntests + n_loops; testno++)
        test_kem_openpgp_x25519 (testno);
      ntests += n_loops;
    }

  if ((selected_algo & SELECTED_ALGO_CMS_X25519))
    {
      for (; testno < ntests + n_loops; testno++)
        test_kem_cms_x25519 (testno);
      ntests += n_loops;
    }

  show_note ("%d tests done\n", ntests);
}

int
main (int argc, char **argv)
{
  int last_argc = -1;
  int n_loops = N_TESTS;


  if (argc)
    {
      argc--;
      argv++;
    }

  selected_algo = ~0;           /* Default is all algos.  */

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
        usage:
          fputs ("usage: " PGM " [options]\n"
                 "Options:\n"
                 "  --verbose       print timings etc.\n"
                 "  --debug         flyswatter\n"
                 "  --loops N       specify the loop count\n"
                 "  --sntrup761     select SNTRUP761 algo\n"
                 "  --mlkem512      select MLKEM512 algo\n"
                 "  --mlkem768      select MLKEM768 algo\n"
                 "  --mlkem1024     select MLKEM1024 algo\n"
                 "  --dhkem25519    select DHKEM25519 algo\n"
                 "  --pgp-x25519    select PGP_X25519 algo\n"
                 "  --cms-x25519    select CMS_X25519_X963 algo\n",
                 stdout);
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
      else if (!strcmp (*argv, "--loops"))
        {
          argc--; argv++;
          if (!argc)
            goto usage;
          n_loops = atoi (*argv);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--sntrup761"))
        {
          selected_algo = SELECTED_ALGO_SNTRUP761;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--mlkem512"))
        {
          selected_algo = SELECTED_ALGO_MLKEM512;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--mlkem768"))
        {
          selected_algo = SELECTED_ALGO_MLKEM768;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--mlkem1024"))
        {
          selected_algo = SELECTED_ALGO_MLKEM1024;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--raw-x25519"))
        {
          selected_algo = SELECTED_ALGO_RAW_X25519;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--dhkem25519"))
        {
          selected_algo = SELECTED_ALGO_DHKEM25519;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--pgp-x25519"))
        {
          selected_algo = SELECTED_ALGO_PGP_X25519;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--cms-x25519"))
        {
          selected_algo = SELECTED_ALGO_CMS_X25519;
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
  check_kem (n_loops);
  stop_timer ();

  info ("All tests completed in %s.  Errors: %d\n",
        elapsed_time (1), error_count);
  return !!error_count;
}
