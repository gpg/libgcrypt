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
#define N_TESTS_DHKEM_X25519 10
#define N_TESTS_OPENPGP_X25519 10

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

  err = gcry_kem_keypair (GCRY_KEM_SNTRUP761, pubkey, seckey);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_SNTRUP761, pubkey, ciphertext, key1, NULL);
  if (err)
    {
      fail ("gcry_kem_encap %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_SNTRUP761, seckey, ciphertext, key2, NULL);
  if (err)
    {
      fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
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

  err = gcry_kem_keypair (algo, pubkey, seckey);
  if (err)
    {
      fail ("gcry_kem_keypair %d %d: %s", testno, algo, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (algo, pubkey, ciphertext, key1, NULL);
  if (err)
    {
      fail ("gcry_kem_encap %d %d: %s", testno, algo, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (algo, seckey, ciphertext, key2, NULL);
  if (err)
    {
      fail ("gcry_kem_decap %d %d: %s", testno, algo, gpg_strerror (err));
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
test_kem_dhkem_x25519 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[GCRY_KEM_DHKEM_X25519_PUBLICKEY_SIZE];
  uint8_t seckey[GCRY_KEM_DHKEM_X25519_SECRETKEY_SIZE];
  uint8_t ciphertext[GCRY_KEM_DHKEM_X25519_CIPHERTEXT_SIZE];
  uint8_t key1[GCRY_KEM_DHKEM_X25519_SHAREDSECRET_SIZE];
  uint8_t key2[GCRY_KEM_DHKEM_X25519_SHAREDSECRET_SIZE];

  err = gcry_kem_keypair (GCRY_KEM_DHKEM_X25519, pubkey, seckey);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_DHKEM_X25519, pubkey, ciphertext, key1, NULL);
  if (err)
    {
      fail ("gcry_kem_encap %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_DHKEM_X25519, seckey, ciphertext, key2, pubkey);
  if (err)
    {
      fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, GCRY_KEM_DHKEM_X25519_SHAREDSECRET_SIZE) != 0)
    {
      size_t i;

      fail ("dhkem-x25519 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < GCRY_KEM_DHKEM_X25519_SHAREDSECRET_SIZE; i++)
	fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < GCRY_KEM_DHKEM_X25519_SHAREDSECRET_SIZE; i++)
	fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

static void
test_kem_openpgp_x25519 (int testno)
{
  gcry_error_t err;
  uint8_t pubkey[32];
  uint8_t seckey[32];
  uint8_t ciphertext[32];
  uint8_t key1[16];
  uint8_t key2[16];
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

  err = gcry_kem_keypair (GCRY_KEM_OPENPGP_X25519, pubkey, seckey);
  if (err)
    {
      fail ("gcry_kem_keypair %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_encap (GCRY_KEM_OPENPGP_X25519, pubkey, ciphertext, key1,
                        kdf_param);
  if (err)
    {
      fail ("gcry_kem_encap %d: %s", testno, gpg_strerror (err));
      return;
    }

  err = gcry_kem_decap (GCRY_KEM_OPENPGP_X25519, seckey, ciphertext, key2,
                        kdf_param);
  if (err)
    {
      fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
      return;
    }

  if (memcmp (key1, key2, 16) != 0)
    {
      size_t i;

      fail ("openpgp-x25519 test %d failed: mismatch\n", testno);
      fputs ("key1:", stderr);
      for (i = 0; i < 16; i++)
	fprintf (stderr, " %02x", key1[i]);
      putc ('\n', stderr);
      fputs ("key2:", stderr);
      for (i = 0; i < 16; i++)
	fprintf (stderr, " %02x", key2[i]);
      putc ('\n', stderr);
    }
}

static void
check_kem_gen_encap_decap (void)
{
  int ntests;

  info ("Checking KEM.\n");

  for (ntests = 0; ntests < N_TESTS_SNTRUP761; ntests++)
    test_kem_sntrup761 (ntests);

  for (; ntests < N_TESTS_SNTRUP761 + N_TESTS_MLKEM; ntests++)
    test_kem_mlkem (ntests);

  for (; ntests < N_TESTS_SNTRUP761 + N_TESTS_MLKEM + N_TESTS_DHKEM_X25519;
       ntests++)
    test_kem_dhkem_x25519 (ntests);

  for (; ntests < N_TESTS_SNTRUP761 + N_TESTS_MLKEM + N_TESTS_DHKEM_X25519
         + N_TESTS_OPENPGP_X25519;
       ntests++)
    test_kem_openpgp_x25519 (ntests);

  show_note ("%d tests done\n", ntests);
}


#define N_TESTS_DHKEM 3

static void
check_dhkem (void)
{
  int testno;
  gcry_error_t err;
  /* Test vectors from RFC9180 A.1, A.2, and A.7 */
  const uint8_t seckey[N_TESTS_DHKEM][32] = {
    {
      0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad,
      0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa, 0xc5,
      0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9,
      0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e, 0x8a, 0xc8
    },
    {
      0x80, 0x57, 0x99, 0x1e, 0xef, 0x8f, 0x1f, 0x1a,
      0xf1, 0x8f, 0x4a, 0x94, 0x91, 0xd1, 0x6a, 0x1c,
      0xe3, 0x33, 0xf6, 0x95, 0xd4, 0xdb, 0x8e, 0x38,
      0xda, 0x75, 0x97, 0x5c, 0x44, 0x78, 0xe0, 0xfb
    },
    {
      0x33, 0xd1, 0x96, 0xc8, 0x30, 0xa1, 0x2f, 0x9a,
      0xc6, 0x5d, 0x6e, 0x56, 0x5a, 0x59, 0x0d, 0x80,
      0xf0, 0x4e, 0xe9, 0xb1, 0x9c, 0x83, 0xc8, 0x7f,
      0x2c, 0x17, 0x0d, 0x97, 0x2a, 0x81, 0x28, 0x48
    }
  };
  const uint8_t pubkey[N_TESTS_DHKEM][32] = {
    {
      0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69,
      0x5d, 0x78, 0x0e, 0x59, 0x07, 0x71, 0x95, 0xda,
      0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73, 0x29, 0x79,
      0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81, 0x5c, 0x4d
    },
    {
      0x43, 0x10, 0xee, 0x97, 0xd8, 0x8c, 0xc1, 0xf0,
      0x88, 0xa5, 0x57, 0x6c, 0x77, 0xab, 0x0c, 0xf5,
      0xc3, 0xac, 0x79, 0x7f, 0x3d, 0x95, 0x13, 0x9c,
      0x6c, 0x84, 0xb5, 0x42, 0x9c, 0x59, 0x66, 0x2a,
    },
    {
      0x19, 0x41, 0x41, 0xca, 0x6c, 0x3c, 0x3b, 0xeb,
      0x47, 0x92, 0xcd, 0x97, 0xba, 0x0e, 0xa1, 0xfa,
      0xff, 0x09, 0xd9, 0x84, 0x35, 0x01, 0x23, 0x45,
      0x76, 0x6e, 0xe3, 0x3a, 0xae, 0x2d, 0x76, 0x64
    }
  };
  const uint8_t ciphertext[N_TESTS_DHKEM][32] = {
    {
      0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28,
      0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
      0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44,
      0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31
    },
    {
      0x1a, 0xfa, 0x08, 0xd3, 0xde, 0xc0, 0x47, 0xa6,
      0x43, 0x88, 0x51, 0x63, 0xf1, 0x18, 0x04, 0x76,
      0xfa, 0x7d, 0xdb, 0x54, 0xc6, 0xa8, 0x02, 0x9e,
      0xa3, 0x3f, 0x95, 0x79, 0x6b, 0xf2, 0xac, 0x4a
    },
    {
      0xe5, 0xe8, 0xf9, 0xbf, 0xff, 0x6c, 0x2f, 0x29,
      0x79, 0x1f, 0xc3, 0x51, 0xd2, 0xc2, 0x5c, 0xe1,
      0x29, 0x9a, 0xa5, 0xea, 0xca, 0x78, 0xa7, 0x57,
      0xc0, 0xb4, 0xfb, 0x4b, 0xcd, 0x83, 0x09, 0x18
    }
  };
  const uint8_t key1[N_TESTS_DHKEM][32] = {
    {
      0xfe, 0x0e, 0x18, 0xc9, 0xf0, 0x24, 0xce, 0x43,
      0x79, 0x9a, 0xe3, 0x93, 0xc7, 0xe8, 0xfe, 0x8f,
      0xce, 0x9d, 0x21, 0x88, 0x75, 0xe8, 0x22, 0x7b,
      0x01, 0x87, 0xc0, 0x4e, 0x7d, 0x2e, 0xa1, 0xfc
    },
    {
      0x0b, 0xbe, 0x78, 0x49, 0x04, 0x12, 0xb4, 0xbb,
      0xea, 0x48, 0x12, 0x66, 0x6f, 0x79, 0x16, 0x93,
      0x2b, 0x82, 0x8b, 0xba, 0x79, 0x94, 0x24, 0x24,
      0xab, 0xb6, 0x52, 0x44, 0x93, 0x0d, 0x69, 0xa7
    },
    {
      0xe8, 0x17, 0x16, 0xce, 0x8f, 0x73, 0x14, 0x1d,
      0x4f, 0x25, 0xee, 0x90, 0x98, 0xef, 0xc9, 0x68,
      0xc9, 0x1e, 0x5b, 0x8c, 0xe5, 0x2f, 0xff, 0xf5,
      0x9d, 0x64, 0x03, 0x9e, 0x82, 0x91, 0x8b, 0x66
    }
  };
  uint8_t key2[32];
  size_t size = 32;

  info ("Checking DHKEM KAT.\n");

  for (testno = 0; testno < N_TESTS_DHKEM; testno++)
    {
      err = gcry_kem_decap (GCRY_KEM_DHKEM_X25519, seckey[testno],
                            ciphertext[testno], key2, pubkey[testno]);
      if (err)
        {
          fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
          return;
        }
      if (memcmp (key1[testno], key2, size) != 0)
        {
          size_t i;

          fail ("dhkem test %d failed: mismatch\n", testno);
          fputs ("key1:", stderr);
          for (i = 0; i < size; i++)
            fprintf (stderr, " %02x", key1[testno][i]);
          putc ('\n', stderr);
          fputs ("key2:", stderr);
          for (i = 0; i < size; i++)
            fprintf (stderr, " %02x", key2[i]);
          putc ('\n', stderr);
        }
    }

  show_note ("%d tests done\n", testno);
}

#define N_TESTS_OPENPGP 1

/* In OpenPGP, symmetric key is wrapped by AESWRAP.
 *
 * Decapsulating results the key encrypted key for AESWRAP.
 * This test does this phase of decapsulation.
 *
 * In the application, it does unwrap of encrypted data, by AESWRAP,
 * which results PKCS5 padded 8-byte blocks of symmetric key algo +
 * symmetric key.
 */

static void
check_openpgp (void)
{
  int testno;
  gcry_error_t err;
  /* Test seckey and ciphertext from openpgpjs/main/test/general/x25519.js */
  const uint8_t seckey[N_TESTS_OPENPGP][32] = {
    {
      0x10, 0x44, 0xfa, 0x37, 0xf1, 0x8e, 0xac, 0x30,
      0x3c, 0xd0, 0x16, 0x33, 0xbd, 0xd2, 0xa8, 0xe6,
      0x19, 0xc0, 0x97, 0x3e, 0xca, 0xf4, 0xe1, 0x12,
      0xc4, 0x78, 0xee, 0xe4, 0xe2, 0x88, 0x52, 0x4a
    }
  };
  const uint8_t kdf_param[N_TESTS_OPENPGP][56] = {
    {
      0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55,
      0x01, 0x05, 0x01,
      /**/
      0x12,
      /**/
      0x03, 0x01, 0x08 /*SHA256*/, 0x07 /* AES128*/,
      /**/
      0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75,
      0x73, 0x20, 0x53, 0x65, 0x6e, 0x64, 0x65, 0x72,
      0x20, 0x20, 0x20, 0x20, /* "Anonymous Sender    " */
      /**/
      0x25, 0xd4, 0x45, 0xfa, 0xc1, 0x96, 0x49, 0xc4,
      0x6a, 0x6b, 0x2f, 0xb3, 0xcd, 0xfc, 0x22, 0x19,
      0xc5, 0x53, 0xd3, 0x92  /* public key fingerprint */
    }
  };
  const uint8_t ciphertext[N_TESTS_OPENPGP][32] = {
    {
      0x7a, 0xd4, 0x96, 0xa2, 0xd8, 0x06, 0xd3, 0xe3,
      0x13, 0x11, 0xfc, 0x8a, 0xbd, 0xa8, 0x2b, 0x1c,
      0x07, 0x86, 0xc3, 0x40, 0xde, 0x9e, 0x3a, 0x61,
      0xf8, 0xcb, 0xb6, 0x29, 0xca, 0x40, 0x6a, 0x32
    }
  };
  const uint8_t kek1[N_TESTS_OPENPGP][16] = {
    {
      0x31, 0x29, 0x49, 0x04, 0x63, 0x57, 0x24, 0xd6,
      0xe3, 0x2f, 0xe3, 0x6d, 0x4a, 0xcc, 0xe1, 0x67
    }
  };
  uint8_t kek2[16];
  size_t size = 16;

  info ("Checking OpenPGP KAT.\n");

  for (testno = 0; testno < N_TESTS_OPENPGP; testno++)
    {
      err = gcry_kem_decap (GCRY_KEM_OPENPGP_X25519, seckey[testno],
                            ciphertext[testno], kek2, kdf_param[testno]);
      if (err)
        {
          fail ("gcry_kem_decap %d: %s", testno, gpg_strerror (err));
          return;
        }
      if (memcmp (kek1[testno], kek2, size) != 0)
        {
          size_t i;

          fail ("OpenPGP test %d failed: mismatch\n", testno);
          fputs ("kek1:", stderr);
          for (i = 0; i < size; i++)
            fprintf (stderr, " %02x", kek1[testno][i]);
          putc ('\n', stderr);
          fputs ("kek2:", stderr);
          for (i = 0; i < size; i++)
            fprintf (stderr, " %02x", kek2[i]);
          putc ('\n', stderr);
        }
    }

  show_note ("%d tests done\n", testno);
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
  check_kem_gen_encap_decap ();
  check_dhkem ();
  check_openpgp ();
  stop_timer ();

  info ("All tests completed in %s.  Errors: %d\n",
	elapsed_time (1), error_count);
  return !!error_count;
}
