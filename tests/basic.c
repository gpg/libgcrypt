/* basic.c  -  basic regression tests
 * Copyright (C) 2001, 2002, 2003, 2005, 2008,
 *               2009 Free Software Foundation, Inc.
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
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "../src/gcrypt-int.h"

#ifndef DIM
# define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif


typedef struct test_spec_pubkey_key
{
  const char *secret;
  const char *public;
  const char *grip;
}
test_spec_pubkey_key_t;

typedef struct test_spec_pubkey
{
  int id;
  int flags;
  test_spec_pubkey_key_t key;
}
test_spec_pubkey_t;

#define FLAG_CRYPT (1 << 0)
#define FLAG_SIGN  (1 << 1)
#define FLAG_GRIP  (1 << 2)

static int verbose;
static int error_count;
static int in_fips_mode;
static int die_on_error;

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
  if (die_on_error)
    exit (1);
}

static void
mismatch (const void *expected, size_t expectedlen,
          const void *computed, size_t computedlen)
{
  const unsigned char *p;

  fprintf (stderr, "expected:");
  for (p = expected; expectedlen; p++, expectedlen--)
    fprintf (stderr, " %02x", *p);
  fprintf (stderr, "\ncomputed:");
  for (p = computed; computedlen; p++, computedlen--)
    fprintf (stderr, " %02x", *p);
  fprintf (stderr, "\n");
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
show_sexp (const char *prefix, gcry_sexp_t a)
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


#define MAX_DATA_LEN 100

void
progress_handler (void *cb_data, const char *what, int printchar,
		  int current, int total)
{
  (void)cb_data;
  (void)what;
  (void)current;
  (void)total;

  if (printchar == '\n')
    fputs ( "<LF>", stdout);
  else
    putchar (printchar);
  fflush (stdout);
}

static void
check_cbc_mac_cipher (void)
{
  static const struct tv
  {
    int algo;
    char key[MAX_DATA_LEN];
    unsigned char plaintext[MAX_DATA_LEN];
    size_t plaintextlen;
    char mac[MAX_DATA_LEN];
  }
  tv[] =
    {
      { GCRY_CIPHER_AES,
	"chicken teriyaki",
	"This is a sample plaintext for CBC MAC of sixtyfour bytes.......",
	0, "\x23\x8f\x6d\xc7\x53\x6a\x62\x97\x11\xc4\xa5\x16\x43\xea\xb0\xb6" },
      { GCRY_CIPHER_3DES,
	"abcdefghABCDEFGH01234567",
	"This is a sample plaintext for CBC MAC of sixtyfour bytes.......",
	0, "\x5c\x11\xf0\x01\x47\xbd\x3d\x3a" },
      { GCRY_CIPHER_DES,
	"abcdefgh",
	"This is a sample plaintext for CBC MAC of sixtyfour bytes.......",
	0, "\xfa\x4b\xdf\x9d\xfa\xab\x01\x70" }
    };
  gcry_cipher_hd_t hd;
  unsigned char out[MAX_DATA_LEN];
  int i, blklen, keylen;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "  Starting CBC MAC checks.\n");

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      if (gcry_cipher_test_algo (tv[i].algo) && in_fips_mode)
        {
          if (verbose)
            fprintf (stderr, "  algorithm %d not available in fips mode\n",
                     tv[i].algo);
          continue;
        }

      err = gcry_cipher_open (&hd,
			      tv[i].algo,
			      GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_MAC);
      if (!hd)
	{
	  fail ("cbc-mac algo %d, gcry_cipher_open failed: %s\n",
		tv[i].algo, gpg_strerror (err));
	  return;
	}

      blklen = gcry_cipher_get_algo_blklen(tv[i].algo);
      if (!blklen)
	{
	  fail ("cbc-mac algo %d, gcry_cipher_get_algo_blklen failed\n",
		 tv[i].algo);
	  gcry_cipher_close (hd);
	  return;
	}

      keylen = gcry_cipher_get_algo_keylen (tv[i].algo);
      if (!keylen)
	{
	  fail ("cbc-mac algo %d, gcry_cipher_get_algo_keylen failed\n",
		tv[i].algo);
	  return;
	}

      err = gcry_cipher_setkey (hd, tv[i].key, keylen);
      if (err)
	{
	  fail ("cbc-mac algo %d, gcry_cipher_setkey failed: %s\n",
		tv[i].algo, gpg_strerror (err));
	  gcry_cipher_close (hd);
	  return;
	}

      err = gcry_cipher_setiv (hd, NULL, 0);
      if (err)
	{
	  fail ("cbc-mac algo %d, gcry_cipher_setiv failed: %s\n",
		tv[i].algo, gpg_strerror (err));
	  gcry_cipher_close (hd);
	  return;
	}

      if (verbose)
	fprintf (stderr, "    checking CBC MAC for %s [%i]\n",
		 gcry_cipher_algo_name (tv[i].algo),
		 tv[i].algo);
      err = gcry_cipher_encrypt (hd,
				 out, blklen,
				 tv[i].plaintext,
				 tv[i].plaintextlen ?
				 tv[i].plaintextlen :
				 strlen ((char*)tv[i].plaintext));
      if (err)
	{
	  fail ("cbc-mac algo %d, gcry_cipher_encrypt failed: %s\n",
		tv[i].algo, gpg_strerror (err));
	  gcry_cipher_close (hd);
	  return;
	}

#if 0
      {
	int j;
	for (j = 0; j < gcry_cipher_get_algo_blklen (tv[i].algo); j++)
	  printf ("\\x%02x", out[j] & 0xFF);
	printf ("\n");
      }
#endif

      if (memcmp (tv[i].mac, out, blklen))
	fail ("cbc-mac algo %d, encrypt mismatch entry %d\n", tv[i].algo, i);

      gcry_cipher_close (hd);
    }
  if (verbose)
    fprintf (stderr, "  Completed CBC MAC checks.\n");
}

static void
check_aes128_cbc_cts_cipher (void)
{
  static const char key[128 / 8] = "chicken teriyaki";
  static const unsigned char plaintext[] =
    "I would like the General Gau's Chicken, please, and wonton soup.";
  static const struct tv
  {
    unsigned char out[MAX_DATA_LEN];
    int inlen;
  } tv[] =
    {
      { "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f"
	"\x97",
	17 },
      { "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22"
	"\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5",
	31 },
      { "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
	"\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84",
	32 },
      { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
	"\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e"
	"\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5",
	47 },
      { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
	"\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"
	"\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8",
	48 },
      { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
	"\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
	"\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40"
	"\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8",
	64 },
    };
  gcry_cipher_hd_t hd;
  unsigned char out[MAX_DATA_LEN];
  int i;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "  Starting AES128 CBC CTS checks.\n");
  err = gcry_cipher_open (&hd,
			  GCRY_CIPHER_AES,
			  GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
  if (err)
    {
      fail ("aes-cbc-cts, gcry_cipher_open failed: %s\n", gpg_strerror (err));
      return;
    }

  err = gcry_cipher_setkey (hd, key, 128 / 8);
  if (err)
    {
      fail ("aes-cbc-cts, gcry_cipher_setkey failed: %s\n",
	    gpg_strerror (err));
      gcry_cipher_close (hd);
      return;
    }

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      err = gcry_cipher_setiv (hd, NULL, 0);
      if (err)
	{
	  fail ("aes-cbc-cts, gcry_cipher_setiv failed: %s\n",
		gpg_strerror (err));
	  gcry_cipher_close (hd);
	  return;
	}

      if (verbose)
	fprintf (stderr, "    checking encryption for length %i\n", tv[i].inlen);
      err = gcry_cipher_encrypt (hd, out, MAX_DATA_LEN,
				 plaintext, tv[i].inlen);
      if (err)
	{
	  fail ("aes-cbc-cts, gcry_cipher_encrypt failed: %s\n",
		gpg_strerror (err));
	  gcry_cipher_close (hd);
	  return;
	}

      if (memcmp (tv[i].out, out, tv[i].inlen))
	fail ("aes-cbc-cts, encrypt mismatch entry %d\n", i);

      err = gcry_cipher_setiv (hd, NULL, 0);
      if (err)
	{
	  fail ("aes-cbc-cts, gcry_cipher_setiv failed: %s\n",
		gpg_strerror (err));
	  gcry_cipher_close (hd);
	  return;
	}
      if (verbose)
	fprintf (stderr, "    checking decryption for length %i\n", tv[i].inlen);
      err = gcry_cipher_decrypt (hd, out, tv[i].inlen, NULL, 0);
      if (err)
	{
	  fail ("aes-cbc-cts, gcry_cipher_decrypt failed: %s\n",
		gpg_strerror (err));
	  gcry_cipher_close (hd);
	  return;
	}

      if (memcmp (plaintext, out, tv[i].inlen))
	fail ("aes-cbc-cts, decrypt mismatch entry %d\n", i);
    }

  gcry_cipher_close (hd);
  if (verbose)
    fprintf (stderr, "  Completed AES128 CBC CTS checks.\n");
}

static void
check_ctr_cipher (void)
{
  static const struct tv
  {
    int algo;
    char key[MAX_DATA_LEN];
    char ctr[MAX_DATA_LEN];
    struct data
    {
      unsigned char plaintext[MAX_DATA_LEN];
      int inlen;
      char out[MAX_DATA_LEN];
    } data[8];
  } tv[] =
    {
      /* http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf */
      {	GCRY_CIPHER_AES,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{ { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
	    16,
	    "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce" },
	  { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
	    16,
	    "\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff" },
	  { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
	    16,
	    "\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab" },
	  { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
	    16,
	    "\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee" },

          { "", 0, "" }
	}
      },
      {	GCRY_CIPHER_AES192,
	"\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b"
	"\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{ { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
	    16,
	    "\x1a\xbc\x93\x24\x17\x52\x1c\xa2\x4f\x2b\x04\x59\xfe\x7e\x6e\x0b" },
	  { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
	    16,
	    "\x09\x03\x39\xec\x0a\xa6\xfa\xef\xd5\xcc\xc2\xc6\xf4\xce\x8e\x94" },
	  { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
	    16,
	    "\x1e\x36\xb2\x6b\xd1\xeb\xc6\x70\xd1\xbd\x1d\x66\x56\x20\xab\xf7" },
	  { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
	    16,
	    "\x4f\x78\xa7\xf6\xd2\x98\x09\x58\x5a\x97\xda\xec\x58\xc6\xb0\x50" },
          { "", 0, "" }
	}
      },
      {	GCRY_CIPHER_AES256,
	"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
	"\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{ { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
	    16,
	    "\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28" },
	  { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
	    16,
	    "\xf4\x43\xe3\xca\x4d\x62\xb5\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5" },
	  { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
	    16,
	    "\x2b\x09\x30\xda\xa2\x3d\xe9\x4c\xe8\x70\x17\xba\x2d\x84\x98\x8d" },
	  { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
	    16,
	    "\xdf\xc9\xc5\x8d\xb6\x7a\xad\xa6\x13\xc2\xdd\x08\x45\x79\x41\xa6" },
          { "", 0, "" }
	}
      },
      /* Some truncation tests.  With a truncated second block and
         also with a single truncated block.  */
      {	GCRY_CIPHER_AES,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{{"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
          16,
          "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce" },
         {"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e",
          15,
          "\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd" },
         {"", 0, "" }
	}
      },
      {	GCRY_CIPHER_AES,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{{"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
          16,
          "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce" },
         {"\xae",
          1,
          "\x98" },
         {"", 0, "" }
	}
      },
      {	GCRY_CIPHER_AES,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{{"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17",
          15,
          "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6" },
         {"", 0, "" }
	}
      },
      {	GCRY_CIPHER_AES,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{{"\x6b",
          1,
          "\x87" },
         {"", 0, "" }
	}
      },
      /* Tests to see whether it works correctly as a stream cipher.  */
      {	GCRY_CIPHER_AES,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{{"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
          16,
          "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce" },
         {"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e",
          15,
          "\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd" },
         {"\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
          17,
          "\xff\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab" },
         {"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
          16,
          "\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee" },

          { "", 0, "" }
	}
      },
      {	GCRY_CIPHER_AES,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	{{"\x6b",
          1,
          "\x87" },
	 {"\xc1\xbe",
          2,
          "\x4d\x61" },
	 {"\xe2\x2e\x40",
          3,
          "\x91\xb6\x20" },
	 {"\x9f",
          1,
          "\xe3" },
	 {"\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
          9,
          "\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce" },
         {"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e",
          15,
          "\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd" },
         {"\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11",
          9,
          "\xff\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e" },

          { "", 0, "" }
	}
      },
#if USE_CAST5
      /* A selfmade test vector using an 64 bit block cipher.  */
      {	GCRY_CIPHER_CAST5,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8",
        {{"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
          16,
          "\xe8\xa7\xac\x68\xca\xca\xa0\x20\x10\xcb\x1b\xcc\x79\x2c\xc4\x48" },
         {"\xae\x2d\x8a\x57\x1e\x03\xac\x9c",
          8,
          "\x16\xe8\x72\x77\xb0\x98\x29\x68" },
         {"\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
          8,
          "\x9a\xb3\xa8\x03\x3b\xb4\x14\xba" },
         {"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\xa1\x00",
          10,
          "\x31\x5e\xd3\xfb\x1b\x8d\xd1\xf9\xb0\x83" },
         { "", 0, "" }
	}
      },
#endif /*USE_CAST5*/
      {	0,
	"",
	"",
	{
         {"", 0, "" }
	}
      }
    };
  gcry_cipher_hd_t hde, hdd;
  unsigned char out[MAX_DATA_LEN];
  int i, j, keylen, blklen;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "  Starting CTR cipher checks.\n");
  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      if (!tv[i].algo)
        continue;

      err = gcry_cipher_open (&hde, tv[i].algo, GCRY_CIPHER_MODE_CTR, 0);
      if (!err)
	err = gcry_cipher_open (&hdd, tv[i].algo, GCRY_CIPHER_MODE_CTR, 0);
      if (err)
	{
	  fail ("aes-ctr, gcry_cipher_open failed: %s\n", gpg_strerror (err));
	  return;
	}

      keylen = gcry_cipher_get_algo_keylen(tv[i].algo);
      if (!keylen)
	{
	  fail ("aes-ctr, gcry_cipher_get_algo_keylen failed\n");
	  return;
	}

      err = gcry_cipher_setkey (hde, tv[i].key, keylen);
      if (!err)
	err = gcry_cipher_setkey (hdd, tv[i].key, keylen);
      if (err)
	{
	  fail ("aes-ctr, gcry_cipher_setkey failed: %s\n",
		gpg_strerror (err));
	  gcry_cipher_close (hde);
	  gcry_cipher_close (hdd);
	  return;
	}

      blklen = gcry_cipher_get_algo_blklen(tv[i].algo);
      if (!blklen)
	{
	  fail ("aes-ctr, gcry_cipher_get_algo_blklen failed\n");
	  return;
	}

      err = gcry_cipher_setctr (hde, tv[i].ctr, blklen);
      if (!err)
	err = gcry_cipher_setctr (hdd, tv[i].ctr, blklen);
      if (err)
	{
	  fail ("aes-ctr, gcry_cipher_setctr failed: %s\n",
		gpg_strerror (err));
	  gcry_cipher_close (hde);
	  gcry_cipher_close (hdd);
	  return;
	}

      if (verbose)
	fprintf (stderr, "    checking CTR mode for %s [%i]\n",
		 gcry_cipher_algo_name (tv[i].algo),
		 tv[i].algo);
      for (j = 0; tv[i].data[j].inlen; j++)
	{
	  err = gcry_cipher_encrypt (hde, out, MAX_DATA_LEN,
				     tv[i].data[j].plaintext,
				     tv[i].data[j].inlen == -1 ?
				     strlen ((char*)tv[i].data[j].plaintext) :
				     tv[i].data[j].inlen);
	  if (err)
	    {
	      fail ("aes-ctr, gcry_cipher_encrypt (%d, %d) failed: %s\n",
		    i, j, gpg_strerror (err));
	      gcry_cipher_close (hde);
	      gcry_cipher_close (hdd);
	      return;
	    }

	  if (memcmp (tv[i].data[j].out, out, tv[i].data[j].inlen))
            {
              fail ("aes-ctr, encrypt mismatch entry %d:%d\n", i, j);
              mismatch (tv[i].data[j].out, tv[i].data[j].inlen,
                        out, tv[i].data[j].inlen);
            }

	  err = gcry_cipher_decrypt (hdd, out, tv[i].data[j].inlen, NULL, 0);
	  if (err)
	    {
	      fail ("aes-ctr, gcry_cipher_decrypt (%d, %d) failed: %s\n",
		    i, j, gpg_strerror (err));
	      gcry_cipher_close (hde);
	      gcry_cipher_close (hdd);
	      return;
	    }

	  if (memcmp (tv[i].data[j].plaintext, out, tv[i].data[j].inlen))
            {
              fail ("aes-ctr, decrypt mismatch entry %d:%d\n", i, j);
              mismatch (tv[i].data[j].plaintext, tv[i].data[j].inlen,
                        out, tv[i].data[j].inlen);
            }

        }

      /* Now check that we get valid return codes back for good and
         bad inputs.  */
      err = gcry_cipher_encrypt (hde, out, MAX_DATA_LEN,
                                 "1234567890123456", 16);
      if (err)
        fail ("aes-ctr, encryption failed for valid input");

      err = gcry_cipher_encrypt (hde, out, 15,
                                 "1234567890123456", 16);
      if (gpg_err_code (err) != GPG_ERR_BUFFER_TOO_SHORT)
        fail ("aes-ctr, too short output buffer returned wrong error: %s\n",
              gpg_strerror (err));

      err = gcry_cipher_encrypt (hde, out, 0,
                                 "1234567890123456", 16);
      if (gpg_err_code (err) != GPG_ERR_BUFFER_TOO_SHORT)
        fail ("aes-ctr, 0 length output buffer returned wrong error: %s\n",
              gpg_strerror (err));

      err = gcry_cipher_encrypt (hde, out, 16,
                                 "1234567890123456", 16);
      if (err)
        fail ("aes-ctr, correct length output buffer returned error: %s\n",
              gpg_strerror (err));

      /* Again, now for decryption.  */
      err = gcry_cipher_decrypt (hde, out, MAX_DATA_LEN,
                                 "1234567890123456", 16);
      if (err)
        fail ("aes-ctr, decryption failed for valid input");

      err = gcry_cipher_decrypt (hde, out, 15,
                                 "1234567890123456", 16);
      if (gpg_err_code (err) != GPG_ERR_BUFFER_TOO_SHORT)
        fail ("aes-ctr, too short output buffer returned wrong error: %s\n",
              gpg_strerror (err));

      err = gcry_cipher_decrypt (hde, out, 0,
                                 "1234567890123456", 16);
      if (gpg_err_code (err) != GPG_ERR_BUFFER_TOO_SHORT)
        fail ("aes-ctr, 0 length output buffer returned wrong error: %s\n",
              gpg_strerror (err));

      err = gcry_cipher_decrypt (hde, out, 16,
                                 "1234567890123456", 16);
      if (err)
        fail ("aes-ctr, correct length output buffer returned error: %s\n",
              gpg_strerror (err));

      gcry_cipher_close (hde);
      gcry_cipher_close (hdd);
    }
  if (verbose)
    fprintf (stderr, "  Completed CTR cipher checks.\n");
}

static void
check_cfb_cipher (void)
{
  static const struct tv
  {
    int algo;
    char key[MAX_DATA_LEN];
    char iv[MAX_DATA_LEN];
    struct data
    {
      unsigned char plaintext[MAX_DATA_LEN];
      int inlen;
      char out[MAX_DATA_LEN];
    }
    data[MAX_DATA_LEN];
  } tv[] =
    {
      /* http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf */
      { GCRY_CIPHER_AES,
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        { { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
            16,
            "\x3b\x3f\xd9\x2e\xb7\x2d\xad\x20\x33\x34\x49\xf8\xe8\x3c\xfb\x4a" },
          { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
            16,
            "\xc8\xa6\x45\x37\xa0\xb3\xa9\x3f\xcd\xe3\xcd\xad\x9f\x1c\xe5\x8b"},
          { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
            16,
            "\x26\x75\x1f\x67\xa3\xcb\xb1\x40\xb1\x80\x8c\xf1\x87\xa4\xf4\xdf" },
          { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
            16,
            "\xc0\x4b\x05\x35\x7c\x5d\x1c\x0e\xea\xc4\xc6\x6f\x9f\xf7\xf2\xe6" },
        }
      },
      { GCRY_CIPHER_AES192,
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b"
        "\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        { { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
            16,
            "\xcd\xc8\x0d\x6f\xdd\xf1\x8c\xab\x34\xc2\x59\x09\xc9\x9a\x41\x74" },
          { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
            16,
            "\x67\xce\x7f\x7f\x81\x17\x36\x21\x96\x1a\x2b\x70\x17\x1d\x3d\x7a" },
          { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
            16,
            "\x2e\x1e\x8a\x1d\xd5\x9b\x88\xb1\xc8\xe6\x0f\xed\x1e\xfa\xc4\xc9" },
          { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
            16,
            "\xc0\x5f\x9f\x9c\xa9\x83\x4f\xa0\x42\xae\x8f\xba\x58\x4b\x09\xff" },
        }
      },
      { GCRY_CIPHER_AES256,
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        { { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
            16,
            "\xdc\x7e\x84\xbf\xda\x79\x16\x4b\x7e\xcd\x84\x86\x98\x5d\x38\x60" },
          { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
            16,
            "\x39\xff\xed\x14\x3b\x28\xb1\xc8\x32\x11\x3c\x63\x31\xe5\x40\x7b" },
          { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
            16,
            "\xdf\x10\x13\x24\x15\xe5\x4b\x92\xa1\x3e\xd0\xa8\x26\x7a\xe2\xf9" },
          { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
            16,
            "\x75\xa3\x85\x74\x1a\xb9\xce\xf8\x20\x31\x62\x3d\x55\xb1\xe4\x71" }
        }
      }
    };
  gcry_cipher_hd_t hde, hdd;
  unsigned char out[MAX_DATA_LEN];
  int i, j, keylen, blklen;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "  Starting CFB checks.\n");

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      if (verbose)
        fprintf (stderr, "    checking CFB mode for %s [%i]\n",
		 gcry_cipher_algo_name (tv[i].algo),
		 tv[i].algo);
      err = gcry_cipher_open (&hde, tv[i].algo, GCRY_CIPHER_MODE_CFB, 0);
      if (!err)
        err = gcry_cipher_open (&hdd, tv[i].algo, GCRY_CIPHER_MODE_CFB, 0);
      if (err)
        {
          fail ("aes-cfb, gcry_cipher_open failed: %s\n", gpg_strerror (err));
          return;
        }

      keylen = gcry_cipher_get_algo_keylen(tv[i].algo);
      if (!keylen)
        {
          fail ("aes-cfb, gcry_cipher_get_algo_keylen failed\n");
          return;
        }

      err = gcry_cipher_setkey (hde, tv[i].key, keylen);
      if (!err)
        err = gcry_cipher_setkey (hdd, tv[i].key, keylen);
      if (err)
        {
          fail ("aes-cfb, gcry_cipher_setkey failed: %s\n",
                gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      blklen = gcry_cipher_get_algo_blklen(tv[i].algo);
      if (!blklen)
        {
          fail ("aes-cfb, gcry_cipher_get_algo_blklen failed\n");
          return;
        }

      err = gcry_cipher_setiv (hde, tv[i].iv, blklen);
      if (!err)
        err = gcry_cipher_setiv (hdd, tv[i].iv, blklen);
      if (err)
        {
          fail ("aes-cfb, gcry_cipher_setiv failed: %s\n",
                gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      for (j = 0; tv[i].data[j].inlen; j++)
        {
          err = gcry_cipher_encrypt (hde, out, MAX_DATA_LEN,
                                     tv[i].data[j].plaintext,
                                     tv[i].data[j].inlen);
          if (err)
            {
              fail ("aes-cfb, gcry_cipher_encrypt (%d, %d) failed: %s\n",
                    i, j, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          if (memcmp (tv[i].data[j].out, out, tv[i].data[j].inlen)) {
            fail ("aes-cfb, encrypt mismatch entry %d:%d\n", i, j);
	  }
          err = gcry_cipher_decrypt (hdd, out, tv[i].data[j].inlen, NULL, 0);
          if (err)
            {
              fail ("aes-cfb, gcry_cipher_decrypt (%d, %d) failed: %s\n",
                    i, j, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          if (memcmp (tv[i].data[j].plaintext, out, tv[i].data[j].inlen))
            fail ("aes-cfb, decrypt mismatch entry %d:%d\n", i, j);
        }

      gcry_cipher_close (hde);
      gcry_cipher_close (hdd);
    }
  if (verbose)
    fprintf (stderr, "  Completed CFB checks.\n");
}

static void
check_ofb_cipher (void)
{
  static const struct tv
  {
    int algo;
    char key[MAX_DATA_LEN];
    char iv[MAX_DATA_LEN];
    struct data
    {
      unsigned char plaintext[MAX_DATA_LEN];
      int inlen;
      char out[MAX_DATA_LEN];
    }
    data[MAX_DATA_LEN];
  } tv[] =
    {
      /* http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf */
      { GCRY_CIPHER_AES,
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        { { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
            16,
            "\x3b\x3f\xd9\x2e\xb7\x2d\xad\x20\x33\x34\x49\xf8\xe8\x3c\xfb\x4a" },
          { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
            16,
            "\x77\x89\x50\x8d\x16\x91\x8f\x03\xf5\x3c\x52\xda\xc5\x4e\xd8\x25"},
          { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
            16,
            "\x97\x40\x05\x1e\x9c\x5f\xec\xf6\x43\x44\xf7\xa8\x22\x60\xed\xcc" },
          { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
            16,
            "\x30\x4c\x65\x28\xf6\x59\xc7\x78\x66\xa5\x10\xd9\xc1\xd6\xae\x5e" },
        }
      },
      { GCRY_CIPHER_AES192,
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b"
        "\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        { { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
            16,
            "\xcd\xc8\x0d\x6f\xdd\xf1\x8c\xab\x34\xc2\x59\x09\xc9\x9a\x41\x74" },
          { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
            16,
            "\xfc\xc2\x8b\x8d\x4c\x63\x83\x7c\x09\xe8\x17\x00\xc1\x10\x04\x01" },
          { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
            16,
            "\x8d\x9a\x9a\xea\xc0\xf6\x59\x6f\x55\x9c\x6d\x4d\xaf\x59\xa5\xf2" },
          { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
            16,
            "\x6d\x9f\x20\x08\x57\xca\x6c\x3e\x9c\xac\x52\x4b\xd9\xac\xc9\x2a" },
        }
      },
      { GCRY_CIPHER_AES256,
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        { { "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
            16,
            "\xdc\x7e\x84\xbf\xda\x79\x16\x4b\x7e\xcd\x84\x86\x98\x5d\x38\x60" },
          { "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
            16,
            "\x4f\xeb\xdc\x67\x40\xd2\x0b\x3a\xc8\x8f\x6a\xd8\x2a\x4f\xb0\x8d" },
          { "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
            16,
            "\x71\xab\x47\xa0\x86\xe8\x6e\xed\xf3\x9d\x1c\x5b\xba\x97\xc4\x08" },
          { "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
            16,
            "\x01\x26\x14\x1d\x67\xf3\x7b\xe8\x53\x8f\x5a\x8b\xe7\x40\xe4\x84" }
        }
      }
    };
  gcry_cipher_hd_t hde, hdd;
  unsigned char out[MAX_DATA_LEN];
  int i, j, keylen, blklen;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "  Starting OFB checks.\n");

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      if (verbose)
        fprintf (stderr, "    checking OFB mode for %s [%i]\n",
		 gcry_cipher_algo_name (tv[i].algo),
		 tv[i].algo);
      err = gcry_cipher_open (&hde, tv[i].algo, GCRY_CIPHER_MODE_OFB, 0);
      if (!err)
        err = gcry_cipher_open (&hdd, tv[i].algo, GCRY_CIPHER_MODE_OFB, 0);
      if (err)
        {
          fail ("aes-ofb, gcry_cipher_open failed: %s\n", gpg_strerror (err));
          return;
        }

      keylen = gcry_cipher_get_algo_keylen(tv[i].algo);
      if (!keylen)
        {
          fail ("aes-ofb, gcry_cipher_get_algo_keylen failed\n");
          return;
        }

      err = gcry_cipher_setkey (hde, tv[i].key, keylen);
      if (!err)
        err = gcry_cipher_setkey (hdd, tv[i].key, keylen);
      if (err)
        {
          fail ("aes-ofb, gcry_cipher_setkey failed: %s\n",
                gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      blklen = gcry_cipher_get_algo_blklen(tv[i].algo);
      if (!blklen)
        {
          fail ("aes-ofb, gcry_cipher_get_algo_blklen failed\n");
          return;
        }

      err = gcry_cipher_setiv (hde, tv[i].iv, blklen);
      if (!err)
        err = gcry_cipher_setiv (hdd, tv[i].iv, blklen);
      if (err)
        {
          fail ("aes-ofb, gcry_cipher_setiv failed: %s\n",
                gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      for (j = 0; tv[i].data[j].inlen; j++)
        {
          err = gcry_cipher_encrypt (hde, out, MAX_DATA_LEN,
                                     tv[i].data[j].plaintext,
                                     tv[i].data[j].inlen);
          if (err)
            {
              fail ("aes-ofb, gcry_cipher_encrypt (%d, %d) failed: %s\n",
                    i, j, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          if (memcmp (tv[i].data[j].out, out, tv[i].data[j].inlen))
            fail ("aes-ofb, encrypt mismatch entry %d:%d\n", i, j);

          err = gcry_cipher_decrypt (hdd, out, tv[i].data[j].inlen, NULL, 0);
          if (err)
            {
              fail ("aes-ofb, gcry_cipher_decrypt (%d, %d) failed: %s\n",
                    i, j, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          if (memcmp (tv[i].data[j].plaintext, out, tv[i].data[j].inlen))
            fail ("aes-ofb, decrypt mismatch entry %d:%d\n", i, j);
        }

      err = gcry_cipher_reset(hde);
      if (!err)
	err = gcry_cipher_reset(hdd);
      if (err)
	{
	  fail ("aes-ofb, gcry_cipher_reset (%d, %d) failed: %s\n",
		i, j, gpg_strerror (err));
	  gcry_cipher_close (hde);
	  gcry_cipher_close (hdd);
	  return;
	}

      /* gcry_cipher_reset clears the IV */
      err = gcry_cipher_setiv (hde, tv[i].iv, blklen);
      if (!err)
        err = gcry_cipher_setiv (hdd, tv[i].iv, blklen);
      if (err)
        {
          fail ("aes-ofb, gcry_cipher_setiv failed: %s\n",
                gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      /* this time we encrypt and decrypt one byte at a time */
      for (j = 0; tv[i].data[j].inlen; j++)
        {
	  int byteNum;
	  for (byteNum = 0; byteNum < tv[i].data[j].inlen; ++byteNum)
	    {
	      err = gcry_cipher_encrypt (hde, out+byteNum, 1,
					 (tv[i].data[j].plaintext) + byteNum,
					 1);
	      if (err)
		{
		  fail ("aes-ofb, gcry_cipher_encrypt (%d, %d) failed: %s\n",
			i, j, gpg_strerror (err));
		  gcry_cipher_close (hde);
		  gcry_cipher_close (hdd);
		  return;
		}
	    }

          if (memcmp (tv[i].data[j].out, out, tv[i].data[j].inlen))
            fail ("aes-ofb, encrypt mismatch entry %d:%d\n", i, j);

	  for (byteNum = 0; byteNum < tv[i].data[j].inlen; ++byteNum)
	    {
	      err = gcry_cipher_decrypt (hdd, out+byteNum, 1, NULL, 0);
	      if (err)
		{
		  fail ("aes-ofb, gcry_cipher_decrypt (%d, %d) failed: %s\n",
			i, j, gpg_strerror (err));
		  gcry_cipher_close (hde);
		  gcry_cipher_close (hdd);
		  return;
		}
	    }

          if (memcmp (tv[i].data[j].plaintext, out, tv[i].data[j].inlen))
            fail ("aes-ofb, decrypt mismatch entry %d:%d\n", i, j);
        }

      gcry_cipher_close (hde);
      gcry_cipher_close (hdd);
    }
  if (verbose)
    fprintf (stderr, "  Completed OFB checks.\n");
}

static void
_check_gcm_cipher (unsigned int step)
{
  struct tv
  {
    int algo;
    char key[MAX_DATA_LEN];
    char iv[MAX_DATA_LEN];
    int ivlen;
    unsigned char aad[MAX_DATA_LEN];
    int aadlen;
    unsigned char plaintext[MAX_DATA_LEN];
    int inlen;
    char out[MAX_DATA_LEN];
    char tag[MAX_DATA_LEN];
  } tv[] =
    {
      /* http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf */
      { GCRY_CIPHER_AES,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12,
        "", 0,
        "",
        0,
        "",
        "\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a" },
      { GCRY_CIPHER_AES,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12,
        "", 0,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        16,
        "\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
        "\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf" },
      { GCRY_CIPHER_AES,
        "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
        "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88", 12,
        "", 0,
        "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
        "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
        "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
        "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55",
        64,
        "\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
        "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
        "\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
        "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91\x47\x3f\x59\x85",
        "\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4" },
      { GCRY_CIPHER_AES,
        "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
        "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88", 12,
        "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef"
        "\xab\xad\xda\xd2", 20,
        "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
        "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
        "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
        "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
        60,
        "\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
        "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
        "\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
        "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91\x47\x3f\x59\x85",
        "\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47" },
      { GCRY_CIPHER_AES,
        "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
        "\xca\xfe\xba\xbe\xfa\xce\xdb\xad", 8,
        "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef"
        "\xab\xad\xda\xd2", 20,
        "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
        "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
        "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
        "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
        60,
        "\x61\x35\x3b\x4c\x28\x06\x93\x4a\x77\x7f\xf5\x1f\xa2\x2a\x47\x55"
        "\x69\x9b\x2a\x71\x4f\xcd\xc6\xf8\x37\x66\xe5\xf9\x7b\x6c\x74\x23"
        "\x73\x80\x69\x00\xe4\x9f\x24\xb2\x2b\x09\x75\x44\xd4\x89\x6b\x42"
        "\x49\x89\xb5\xe1\xeb\xac\x0f\x07\xc2\x3f\x45\x98",
        "\x36\x12\xd2\xe7\x9e\x3b\x07\x85\x56\x1b\xe1\x4a\xac\xa2\xfc\xcb" },
      { GCRY_CIPHER_AES,
        "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
        "\x93\x13\x22\x5d\xf8\x84\x06\xe5\x55\x90\x9c\x5a\xff\x52\x69\xaa"
        "\x6a\x7a\x95\x38\x53\x4f\x7d\xa1\xe4\xc3\x03\xd2\xa3\x18\xa7\x28"
        "\xc3\xc0\xc9\x51\x56\x80\x95\x39\xfc\xf0\xe2\x42\x9a\x6b\x52\x54"
        "\x16\xae\xdb\xf5\xa0\xde\x6a\x57\xa6\x37\xb3\x9b", 60,
        "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef"
        "\xab\xad\xda\xd2", 20,
        "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
        "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
        "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
        "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
        60,
        "\x8c\xe2\x49\x98\x62\x56\x15\xb6\x03\xa0\x33\xac\xa1\x3f\xb8\x94"
        "\xbe\x91\x12\xa5\xc3\xa2\x11\xa8\xba\x26\x2a\x3c\xca\x7e\x2c\xa7"
        "\x01\xe4\xa9\xa4\xfb\xa4\x3c\x90\xcc\xdc\xb2\x81\xd4\x8c\x7c\x6f"
        "\xd6\x28\x75\xd2\xac\xa4\x17\x03\x4c\x34\xae\xe5",
        "\x61\x9c\xc5\xae\xff\xfe\x0b\xfa\x46\x2a\xf4\x3c\x16\x99\xd0\x50" },
      { GCRY_CIPHER_AES192,
        "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
        "\xfe\xff\xe9\x92\x86\x65\x73\x1c",
        "\x93\x13\x22\x5d\xf8\x84\x06\xe5\x55\x90\x9c\x5a\xff\x52\x69\xaa"
        "\x6a\x7a\x95\x38\x53\x4f\x7d\xa1\xe4\xc3\x03\xd2\xa3\x18\xa7\x28"
        "\xc3\xc0\xc9\x51\x56\x80\x95\x39\xfc\xf0\xe2\x42\x9a\x6b\x52\x54"
        "\x16\xae\xdb\xf5\xa0\xde\x6a\x57\xa6\x37\xb3\x9b", 60,
        "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef"
        "\xab\xad\xda\xd2", 20,
        "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
        "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
        "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
        "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
        60,
        "\xd2\x7e\x88\x68\x1c\xe3\x24\x3c\x48\x30\x16\x5a\x8f\xdc\xf9\xff"
        "\x1d\xe9\xa1\xd8\xe6\xb4\x47\xef\x6e\xf7\xb7\x98\x28\x66\x6e\x45"
        "\x81\xe7\x90\x12\xaf\x34\xdd\xd9\xe2\xf0\x37\x58\x9b\x29\x2d\xb3"
        "\xe6\x7c\x03\x67\x45\xfa\x22\xe7\xe9\xb7\x37\x3b",
        "\xdc\xf5\x66\xff\x29\x1c\x25\xbb\xb8\x56\x8f\xc3\xd3\x76\xa6\xd9" },
      { GCRY_CIPHER_AES256,
        "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
        "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
        "\x93\x13\x22\x5d\xf8\x84\x06\xe5\x55\x90\x9c\x5a\xff\x52\x69\xaa"
        "\x6a\x7a\x95\x38\x53\x4f\x7d\xa1\xe4\xc3\x03\xd2\xa3\x18\xa7\x28"
        "\xc3\xc0\xc9\x51\x56\x80\x95\x39\xfc\xf0\xe2\x42\x9a\x6b\x52\x54"
        "\x16\xae\xdb\xf5\xa0\xde\x6a\x57\xa6\x37\xb3\x9b", 60,
        "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef"
        "\xab\xad\xda\xd2", 20,
        "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
        "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
        "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
        "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
        60,
        "\x5a\x8d\xef\x2f\x0c\x9e\x53\xf1\xf7\x5d\x78\x53\x65\x9e\x2a\x20"
        "\xee\xb2\xb2\x2a\xaf\xde\x64\x19\xa0\x58\xab\x4f\x6f\x74\x6b\xf4"
        "\x0f\xc0\xc3\xb7\x80\xf2\x44\x45\x2d\xa3\xeb\xf1\xc5\xd8\x2c\xde"
        "\xa2\x41\x89\x97\x20\x0e\xf8\x2e\x44\xae\x7e\x3f",
        "\xa4\x4a\x82\x66\xee\x1c\x8e\xb0\xc8\xb5\xd4\xcf\x5a\xe9\xf1\x9a" }
    };

  gcry_cipher_hd_t hde, hdd;
  unsigned char out[MAX_DATA_LEN];
  unsigned char tag[GCRY_GCM_BLOCK_LEN];
  int i, keylen;
  gcry_error_t err = 0;
  size_t pos, poslen;
  int byteNum;

  if (verbose)
    fprintf (stderr, "  Starting GCM checks.\n");

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      if (verbose)
        fprintf (stderr, "    checking GCM mode for %s [%i]\n",
                 gcry_cipher_algo_name (tv[i].algo),
                 tv[i].algo);
      err = gcry_cipher_open (&hde, tv[i].algo, GCRY_CIPHER_MODE_GCM, 0);
      if (!err)
        err = gcry_cipher_open (&hdd, tv[i].algo, GCRY_CIPHER_MODE_GCM, 0);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_open failed: %s\n", gpg_strerror (err));
          return;
        }

      keylen = gcry_cipher_get_algo_keylen(tv[i].algo);
      if (!keylen)
        {
          fail ("aes-gcm, gcry_cipher_get_algo_keylen failed\n");
          return;
        }

      err = gcry_cipher_setkey (hde, tv[i].key, keylen);
      if (!err)
        err = gcry_cipher_setkey (hdd, tv[i].key, keylen);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_setkey failed: %s\n",
                gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      err = gcry_cipher_setiv (hde, tv[i].iv, tv[i].ivlen);
      if (!err)
        err = gcry_cipher_setiv (hdd, tv[i].iv, tv[i].ivlen);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_setiv failed: %s\n",
                gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      for (pos = 0; pos < tv[i].aadlen; pos += step)
        {
          poslen = (pos + step < tv[i].aadlen) ? step : tv[i].aadlen - pos;

          err = gcry_cipher_authenticate(hde, tv[i].aad + pos, poslen);
          if (err)
            {
              fail ("aes-gcm, gcry_cipher_authenticate (%d) (%d:%d) failed: "
                    "%s\n", i, pos, step, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }
          err = gcry_cipher_authenticate(hdd, tv[i].aad + pos, poslen);
          if (err)
            {
              fail ("aes-gcm, de gcry_cipher_authenticate (%d) (%d:%d) failed: "
	            "%s\n", i, pos, step, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }
        }

      for (pos = 0; pos < tv[i].inlen; pos += step)
        {
          poslen = (pos + step < tv[i].inlen) ? step : tv[i].inlen - pos;

          err = gcry_cipher_encrypt (hde, out + pos, poslen,
                                     tv[i].plaintext + pos, poslen);
          if (err)
            {
              fail ("aes-gcm, gcry_cipher_encrypt (%d) (%d:%d) failed: %s\n",
                    i, pos, step, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }
        }

      if (memcmp (tv[i].out, out, tv[i].inlen))
        fail ("aes-gcm, encrypt mismatch entry %d (step %d)\n", i, step);

      for (pos = 0; pos < tv[i].inlen; pos += step)
        {
          poslen = (pos + step < tv[i].inlen) ? step : tv[i].inlen - pos;

          err = gcry_cipher_decrypt (hdd, out + pos, poslen, NULL, 0);
          if (err)
            {
              fail ("aes-gcm, gcry_cipher_decrypt (%d) (%d:%d) failed: %s\n",
                    i, pos, step, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }
        }

      if (memcmp (tv[i].plaintext, out, tv[i].inlen))
        fail ("aes-gcm, decrypt mismatch entry %d (step %d)\n", i, step);

      err = gcry_cipher_gettag (hde, out, GCRY_GCM_BLOCK_LEN);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_gettag(%d) failed: %s\n",
                i, gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      if (memcmp (tv[i].tag, out, GCRY_GCM_BLOCK_LEN))
        fail ("aes-gcm, encrypt tag mismatch entry %d\n", i);


      err = gcry_cipher_checktag (hdd, out, GCRY_GCM_BLOCK_LEN);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_checktag(%d) failed: %s\n",
                i, gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      err = gcry_cipher_reset(hde);
      if (!err)
        err = gcry_cipher_reset(hdd);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_reset (%d) failed: %s\n",
                i, gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      /* gcry_cipher_reset clears the IV */
      err = gcry_cipher_setiv (hde, tv[i].iv, tv[i].ivlen);
      if (!err)
        err = gcry_cipher_setiv (hdd, tv[i].iv, tv[i].ivlen);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_setiv failed: %s\n",
                gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      /* this time we authenticate, encrypt and decrypt one byte at a time */
      for (byteNum = 0; byteNum < tv[i].aadlen; ++byteNum)
        {
          err = gcry_cipher_authenticate(hde, tv[i].aad + byteNum, 1);
          if (err)
            {
              fail ("aes-gcm, gcry_cipher_authenticate (%d) (byte-buf) failed: "
                    "%s\n", i, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }
          err = gcry_cipher_authenticate(hdd, tv[i].aad + byteNum, 1);
          if (err)
            {
              fail ("aes-gcm, de gcry_cipher_authenticate (%d) (byte-buf) "
	            "failed: %s\n", i, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }
        }

      for (byteNum = 0; byteNum < tv[i].inlen; ++byteNum)
        {
          err = gcry_cipher_encrypt (hde, out+byteNum, 1,
                                     (tv[i].plaintext) + byteNum,
                                     1);
          if (err)
            {
              fail ("aes-gcm, gcry_cipher_encrypt (%d) (byte-buf) failed: %s\n",
                    i,  gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }
        }

      if (memcmp (tv[i].out, out, tv[i].inlen))
        fail ("aes-gcm, encrypt mismatch entry %d, (byte-buf)\n", i);

      err = gcry_cipher_gettag (hde, tag, GCRY_GCM_BLOCK_LEN);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_gettag(%d) (byte-buf) failed: %s\n",
                i, gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      if (memcmp (tv[i].tag, tag, GCRY_GCM_BLOCK_LEN))
        fail ("aes-gcm, encrypt tag mismatch entry %d, (byte-buf)\n", i);

      for (byteNum = 0; byteNum < tv[i].inlen; ++byteNum)
        {
          err = gcry_cipher_decrypt (hdd, out+byteNum, 1, NULL, 0);
          if (err)
            {
              fail ("aes-gcm, gcry_cipher_decrypt (%d) (byte-buf) failed: %s\n",
                    i, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }
        }

      if (memcmp (tv[i].plaintext, out, tv[i].inlen))
        fail ("aes-gcm, decrypt mismatch entry %d\n", i);

      err = gcry_cipher_checktag (hdd, tag, GCRY_GCM_BLOCK_LEN);
      if (err)
        {
          fail ("aes-gcm, gcry_cipher_checktag(%d) (byte-buf) failed: %s\n",
                i, gpg_strerror (err));
          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
          return;
        }

      gcry_cipher_close (hde);
      gcry_cipher_close (hdd);
    }
  if (verbose)
    fprintf (stderr, "  Completed GCM checks.\n");
}


static void
check_gcm_cipher (void)
{
  /* Large buffers, no splitting. */
  _check_gcm_cipher(0xffffffff);
  /* Split input to one byte buffers. */
  _check_gcm_cipher(1);
  /* Split input to 7 byte buffers. */
  _check_gcm_cipher(7);
  /* Split input to 16 byte buffers. */
  _check_gcm_cipher(16);
}


static void
check_ccm_cipher (void)
{
#ifdef HAVE_U64_TYPEDEF
  static const struct tv
  {
    int algo;
    int keylen;
    const char *key;
    int noncelen;
    const char *nonce;
    int aadlen;
    const char *aad;
    int plainlen;
    const char *plaintext;
    int cipherlen;
    const char *ciphertext;
  } tv[] =
    {
      /* RFC 3610 */
      { GCRY_CIPHER_AES, /* Packet Vector #1 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x03\x02\x01\x00\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          23,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
          31,
          "\x58\x8C\x97\x9A\x61\xC6\x63\xD2\xF0\x66\xD0\xC2\xC0\xF9\x89\x80\x6D\x5F\x6B\x61\xDA\xC3\x84\x17\xE8\xD1\x2C\xFD\xF9\x26\xE0"},
      { GCRY_CIPHER_AES, /* Packet Vector #2 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x04\x03\x02\x01\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          24,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
          32,
          "\x72\xC9\x1A\x36\xE1\x35\xF8\xCF\x29\x1C\xA8\x94\x08\x5C\x87\xE3\xCC\x15\xC4\x39\xC9\xE4\x3A\x3B\xA0\x91\xD5\x6E\x10\x40\x09\x16"},
      { GCRY_CIPHER_AES, /* Packet Vector #3 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x05\x04\x03\x02\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          25,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
          33,
          "\x51\xB1\xE5\xF4\x4A\x19\x7D\x1D\xA4\x6B\x0F\x8E\x2D\x28\x2A\xE8\x71\xE8\x38\xBB\x64\xDA\x85\x96\x57\x4A\xDA\xA7\x6F\xBD\x9F\xB0\xC5"},
      { GCRY_CIPHER_AES, /* Packet Vector #4 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x06\x05\x04\x03\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          19,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
          27,
          "\xA2\x8C\x68\x65\x93\x9A\x9A\x79\xFA\xAA\x5C\x4C\x2A\x9D\x4A\x91\xCD\xAC\x8C\x96\xC8\x61\xB9\xC9\xE6\x1E\xF1"},
      { GCRY_CIPHER_AES, /* Packet Vector #5 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x07\x06\x05\x04\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          20,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
          28,
          "\xDC\xF1\xFB\x7B\x5D\x9E\x23\xFB\x9D\x4E\x13\x12\x53\x65\x8A\xD8\x6E\xBD\xCA\x3E\x51\xE8\x3F\x07\x7D\x9C\x2D\x93"},
      { GCRY_CIPHER_AES, /* Packet Vector #6 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x08\x07\x06\x05\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          21,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
          29,
          "\x6F\xC1\xB0\x11\xF0\x06\x56\x8B\x51\x71\xA4\x2D\x95\x3D\x46\x9B\x25\x70\xA4\xBD\x87\x40\x5A\x04\x43\xAC\x91\xCB\x94"},
      { GCRY_CIPHER_AES, /* Packet Vector #7 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x09\x08\x07\x06\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          23,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
          33,
          "\x01\x35\xD1\xB2\xC9\x5F\x41\xD5\xD1\xD4\xFE\xC1\x85\xD1\x66\xB8\x09\x4E\x99\x9D\xFE\xD9\x6C\x04\x8C\x56\x60\x2C\x97\xAC\xBB\x74\x90"},
      { GCRY_CIPHER_AES, /* Packet Vector #8 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0A\x09\x08\x07\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          24,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
          34,
          "\x7B\x75\x39\x9A\xC0\x83\x1D\xD2\xF0\xBB\xD7\x58\x79\xA2\xFD\x8F\x6C\xAE\x6B\x6C\xD9\xB7\xDB\x24\xC1\x7B\x44\x33\xF4\x34\x96\x3F\x34\xB4"},
      { GCRY_CIPHER_AES, /* Packet Vector #9 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0B\x0A\x09\x08\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          25,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
          35,
          "\x82\x53\x1A\x60\xCC\x24\x94\x5A\x4B\x82\x79\x18\x1A\xB5\xC8\x4D\xF2\x1C\xE7\xF9\xB7\x3F\x42\xE1\x97\xEA\x9C\x07\xE5\x6B\x5E\xB1\x7E\x5F\x4E"},
      { GCRY_CIPHER_AES, /* Packet Vector #10 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0C\x0B\x0A\x09\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          19,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
          29,
          "\x07\x34\x25\x94\x15\x77\x85\x15\x2B\x07\x40\x98\x33\x0A\xBB\x14\x1B\x94\x7B\x56\x6A\xA9\x40\x6B\x4D\x99\x99\x88\xDD"},
      { GCRY_CIPHER_AES, /* Packet Vector #11 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0D\x0C\x0B\x0A\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          20,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
          30,
          "\x67\x6B\xB2\x03\x80\xB0\xE3\x01\xE8\xAB\x79\x59\x0A\x39\x6D\xA7\x8B\x83\x49\x34\xF5\x3A\xA2\xE9\x10\x7A\x8B\x6C\x02\x2C"},
      { GCRY_CIPHER_AES, /* Packet Vector #12 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0E\x0D\x0C\x0B\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          21,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
          31,
          "\xC0\xFF\xA0\xD6\xF0\x5B\xDB\x67\xF2\x4D\x43\xA4\x33\x8D\x2A\xA4\xBE\xD7\xB2\x0E\x43\xCD\x1A\xA3\x16\x62\xE7\xAD\x65\xD6\xDB"},
      { GCRY_CIPHER_AES, /* Packet Vector #13 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x41\x2B\x4E\xA9\xCD\xBE\x3C\x96\x96\x76\x6C\xFA",
          8, "\x0B\xE1\xA8\x8B\xAC\xE0\x18\xB1",
          23,
          "\x08\xE8\xCF\x97\xD8\x20\xEA\x25\x84\x60\xE9\x6A\xD9\xCF\x52\x89\x05\x4D\x89\x5C\xEA\xC4\x7C",
          31,
          "\x4C\xB9\x7F\x86\xA2\xA4\x68\x9A\x87\x79\x47\xAB\x80\x91\xEF\x53\x86\xA6\xFF\xBD\xD0\x80\xF8\xE7\x8C\xF7\xCB\x0C\xDD\xD7\xB3"},
      { GCRY_CIPHER_AES, /* Packet Vector #14 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x33\x56\x8E\xF7\xB2\x63\x3C\x96\x96\x76\x6C\xFA",
          8, "\x63\x01\x8F\x76\xDC\x8A\x1B\xCB",
          24,
          "\x90\x20\xEA\x6F\x91\xBD\xD8\x5A\xFA\x00\x39\xBA\x4B\xAF\xF9\xBF\xB7\x9C\x70\x28\x94\x9C\xD0\xEC",
          32,
          "\x4C\xCB\x1E\x7C\xA9\x81\xBE\xFA\xA0\x72\x6C\x55\xD3\x78\x06\x12\x98\xC8\x5C\x92\x81\x4A\xBC\x33\xC5\x2E\xE8\x1D\x7D\x77\xC0\x8A"},
      { GCRY_CIPHER_AES, /* Packet Vector #15 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x10\x3F\xE4\x13\x36\x71\x3C\x96\x96\x76\x6C\xFA",
          8, "\xAA\x6C\xFA\x36\xCA\xE8\x6B\x40",
          25,
          "\xB9\x16\xE0\xEA\xCC\x1C\x00\xD7\xDC\xEC\x68\xEC\x0B\x3B\xBB\x1A\x02\xDE\x8A\x2D\x1A\xA3\x46\x13\x2E",
          33,
          "\xB1\xD2\x3A\x22\x20\xDD\xC0\xAC\x90\x0D\x9A\xA0\x3C\x61\xFC\xF4\xA5\x59\xA4\x41\x77\x67\x08\x97\x08\xA7\x76\x79\x6E\xDB\x72\x35\x06"},
      { GCRY_CIPHER_AES, /* Packet Vector #16 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x76\x4C\x63\xB8\x05\x8E\x3C\x96\x96\x76\x6C\xFA",
          12, "\xD0\xD0\x73\x5C\x53\x1E\x1B\xEC\xF0\x49\xC2\x44",
          19,
          "\x12\xDA\xAC\x56\x30\xEF\xA5\x39\x6F\x77\x0C\xE1\xA6\x6B\x21\xF7\xB2\x10\x1C",
          27,
          "\x14\xD2\x53\xC3\x96\x7B\x70\x60\x9B\x7C\xBB\x7C\x49\x91\x60\x28\x32\x45\x26\x9A\x6F\x49\x97\x5B\xCA\xDE\xAF"},
      { GCRY_CIPHER_AES, /* Packet Vector #17 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\xF8\xB6\x78\x09\x4E\x3B\x3C\x96\x96\x76\x6C\xFA",
          12, "\x77\xB6\x0F\x01\x1C\x03\xE1\x52\x58\x99\xBC\xAE",
          20,
          "\xE8\x8B\x6A\x46\xC7\x8D\x63\xE5\x2E\xB8\xC5\x46\xEF\xB5\xDE\x6F\x75\xE9\xCC\x0D",
          28,
          "\x55\x45\xFF\x1A\x08\x5E\xE2\xEF\xBF\x52\xB2\xE0\x4B\xEE\x1E\x23\x36\xC7\x3E\x3F\x76\x2C\x0C\x77\x44\xFE\x7E\x3C"},
      { GCRY_CIPHER_AES, /* Packet Vector #18 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\xD5\x60\x91\x2D\x3F\x70\x3C\x96\x96\x76\x6C\xFA",
          12, "\xCD\x90\x44\xD2\xB7\x1F\xDB\x81\x20\xEA\x60\xC0",
          21,
          "\x64\x35\xAC\xBA\xFB\x11\xA8\x2E\x2F\x07\x1D\x7C\xA4\xA5\xEB\xD9\x3A\x80\x3B\xA8\x7F",
          29,
          "\x00\x97\x69\xEC\xAB\xDF\x48\x62\x55\x94\xC5\x92\x51\xE6\x03\x57\x22\x67\x5E\x04\xC8\x47\x09\x9E\x5A\xE0\x70\x45\x51"},
      { GCRY_CIPHER_AES, /* Packet Vector #19 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x42\xFF\xF8\xF1\x95\x1C\x3C\x96\x96\x76\x6C\xFA",
          8, "\xD8\x5B\xC7\xE6\x9F\x94\x4F\xB8",
          23,
          "\x8A\x19\xB9\x50\xBC\xF7\x1A\x01\x8E\x5E\x67\x01\xC9\x17\x87\x65\x98\x09\xD6\x7D\xBE\xDD\x18",
          33,
          "\xBC\x21\x8D\xAA\x94\x74\x27\xB6\xDB\x38\x6A\x99\xAC\x1A\xEF\x23\xAD\xE0\xB5\x29\x39\xCB\x6A\x63\x7C\xF9\xBE\xC2\x40\x88\x97\xC6\xBA"},
      { GCRY_CIPHER_AES, /* Packet Vector #20 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x92\x0F\x40\xE5\x6C\xDC\x3C\x96\x96\x76\x6C\xFA",
          8, "\x74\xA0\xEB\xC9\x06\x9F\x5B\x37",
          24,
          "\x17\x61\x43\x3C\x37\xC5\xA3\x5F\xC1\xF3\x9F\x40\x63\x02\xEB\x90\x7C\x61\x63\xBE\x38\xC9\x84\x37",
          34,
          "\x58\x10\xE6\xFD\x25\x87\x40\x22\xE8\x03\x61\xA4\x78\xE3\xE9\xCF\x48\x4A\xB0\x4F\x44\x7E\xFF\xF6\xF0\xA4\x77\xCC\x2F\xC9\xBF\x54\x89\x44"},
      { GCRY_CIPHER_AES, /* Packet Vector #21 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x27\xCA\x0C\x71\x20\xBC\x3C\x96\x96\x76\x6C\xFA",
          8, "\x44\xA3\xAA\x3A\xAE\x64\x75\xCA",
          25,
          "\xA4\x34\xA8\xE5\x85\x00\xC6\xE4\x15\x30\x53\x88\x62\xD6\x86\xEA\x9E\x81\x30\x1B\x5A\xE4\x22\x6B\xFA",
          35,
          "\xF2\xBE\xED\x7B\xC5\x09\x8E\x83\xFE\xB5\xB3\x16\x08\xF8\xE2\x9C\x38\x81\x9A\x89\xC8\xE7\x76\xF1\x54\x4D\x41\x51\xA4\xED\x3A\x8B\x87\xB9\xCE"},
      { GCRY_CIPHER_AES, /* Packet Vector #22 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x5B\x8C\xCB\xCD\x9A\xF8\x3C\x96\x96\x76\x6C\xFA",
          12, "\xEC\x46\xBB\x63\xB0\x25\x20\xC3\x3C\x49\xFD\x70",
          19,
          "\xB9\x6B\x49\xE2\x1D\x62\x17\x41\x63\x28\x75\xDB\x7F\x6C\x92\x43\xD2\xD7\xC2",
          29,
          "\x31\xD7\x50\xA0\x9D\xA3\xED\x7F\xDD\xD4\x9A\x20\x32\xAA\xBF\x17\xEC\x8E\xBF\x7D\x22\xC8\x08\x8C\x66\x6B\xE5\xC1\x97"},
      { GCRY_CIPHER_AES, /* Packet Vector #23 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x3E\xBE\x94\x04\x4B\x9A\x3C\x96\x96\x76\x6C\xFA",
          12, "\x47\xA6\x5A\xC7\x8B\x3D\x59\x42\x27\xE8\x5E\x71",
          20,
          "\xE2\xFC\xFB\xB8\x80\x44\x2C\x73\x1B\xF9\x51\x67\xC8\xFF\xD7\x89\x5E\x33\x70\x76",
          30,
          "\xE8\x82\xF1\xDB\xD3\x8C\xE3\xED\xA7\xC2\x3F\x04\xDD\x65\x07\x1E\xB4\x13\x42\xAC\xDF\x7E\x00\xDC\xCE\xC7\xAE\x52\x98\x7D"},
      { GCRY_CIPHER_AES, /* Packet Vector #24 */
          16, "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
          13, "\x00\x8D\x49\x3B\x30\xAE\x8B\x3C\x96\x96\x76\x6C\xFA",
          12, "\x6E\x37\xA6\xEF\x54\x6D\x95\x5D\x34\xAB\x60\x59",
          21,
          "\xAB\xF2\x1C\x0B\x02\xFE\xB8\x8F\x85\x6D\xF4\xA3\x73\x81\xBC\xE3\xCC\x12\x85\x17\xD4",
          31,
          "\xF3\x29\x05\xB8\x8A\x64\x1B\x04\xB9\xC9\xFF\xB5\x8C\xC3\x90\x90\x0F\x3D\xA1\x2A\xB1\x6D\xCE\x9E\x82\xEF\xA1\x6D\xA6\x20\x59"},
      /* RFC 5528 */
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #1 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x03\x02\x01\x00\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          23,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
          31,
          "\xBA\x73\x71\x85\xE7\x19\x31\x04\x92\xF3\x8A\x5F\x12\x51\xDA\x55\xFA\xFB\xC9\x49\x84\x8A\x0D\xFC\xAE\xCE\x74\x6B\x3D\xB9\xAD"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #2 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x04\x03\x02\x01\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          24,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
          32,
          "\x5D\x25\x64\xBF\x8E\xAF\xE1\xD9\x95\x26\xEC\x01\x6D\x1B\xF0\x42\x4C\xFB\xD2\xCD\x62\x84\x8F\x33\x60\xB2\x29\x5D\xF2\x42\x83\xE8"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #3 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x05\x04\x03\x02\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          25,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
          33,
          "\x81\xF6\x63\xD6\xC7\x78\x78\x17\xF9\x20\x36\x08\xB9\x82\xAD\x15\xDC\x2B\xBD\x87\xD7\x56\xF7\x92\x04\xF5\x51\xD6\x68\x2F\x23\xAA\x46"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #4 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x06\x05\x04\x03\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          19,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
          27,
          "\xCA\xEF\x1E\x82\x72\x11\xB0\x8F\x7B\xD9\x0F\x08\xC7\x72\x88\xC0\x70\xA4\xA0\x8B\x3A\x93\x3A\x63\xE4\x97\xA0"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #5 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x07\x06\x05\x04\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          20,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
          28,
          "\x2A\xD3\xBA\xD9\x4F\xC5\x2E\x92\xBE\x43\x8E\x82\x7C\x10\x23\xB9\x6A\x8A\x77\x25\x8F\xA1\x7B\xA7\xF3\x31\xDB\x09"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #6 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x08\x07\x06\x05\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          21,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
          29,
          "\xFE\xA5\x48\x0B\xA5\x3F\xA8\xD3\xC3\x44\x22\xAA\xCE\x4D\xE6\x7F\xFA\x3B\xB7\x3B\xAB\xAB\x36\xA1\xEE\x4F\xE0\xFE\x28"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #7 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x09\x08\x07\x06\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          23,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
          33,
          "\x54\x53\x20\x26\xE5\x4C\x11\x9A\x8D\x36\xD9\xEC\x6E\x1E\xD9\x74\x16\xC8\x70\x8C\x4B\x5C\x2C\xAC\xAF\xA3\xBC\xCF\x7A\x4E\xBF\x95\x73"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #8 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0A\x09\x08\x07\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          24,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
          34,
          "\x8A\xD1\x9B\x00\x1A\x87\xD1\x48\xF4\xD9\x2B\xEF\x34\x52\x5C\xCC\xE3\xA6\x3C\x65\x12\xA6\xF5\x75\x73\x88\xE4\x91\x3E\xF1\x47\x01\xF4\x41"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #9 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0B\x0A\x09\x08\xA0\xA1\xA2\xA3\xA4\xA5",
          8, "\x00\x01\x02\x03\x04\x05\x06\x07",
          25,
          "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
          35,
          "\x5D\xB0\x8D\x62\x40\x7E\x6E\x31\xD6\x0F\x9C\xA2\xC6\x04\x74\x21\x9A\xC0\xBE\x50\xC0\xD4\xA5\x77\x87\x94\xD6\xE2\x30\xCD\x25\xC9\xFE\xBF\x87"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #10 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0C\x0B\x0A\x09\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          19,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
          29,
          "\xDB\x11\x8C\xCE\xC1\xB8\x76\x1C\x87\x7C\xD8\x96\x3A\x67\xD6\xF3\xBB\xBC\x5C\xD0\x92\x99\xEB\x11\xF3\x12\xF2\x32\x37"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #11 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0D\x0C\x0B\x0A\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          20,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
          30,
          "\x7C\xC8\x3D\x8D\xC4\x91\x03\x52\x5B\x48\x3D\xC5\xCA\x7E\xA9\xAB\x81\x2B\x70\x56\x07\x9D\xAF\xFA\xDA\x16\xCC\xCF\x2C\x4E"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #12 */
          16, "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
          13, "\x00\x00\x00\x0E\x0D\x0C\x0B\xA0\xA1\xA2\xA3\xA4\xA5",
          12, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
          21,
          "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
          31,
          "\x2C\xD3\x5B\x88\x20\xD2\x3E\x7A\xA3\x51\xB0\xE9\x2F\xC7\x93\x67\x23\x8B\x2C\xC7\x48\xCB\xB9\x4C\x29\x47\x79\x3D\x64\xAF\x75"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #13 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\xA9\x70\x11\x0E\x19\x27\xB1\x60\xB6\xA3\x1C\x1C",
          8, "\x6B\x7F\x46\x45\x07\xFA\xE4\x96",
          23,
          "\xC6\xB5\xF3\xE6\xCA\x23\x11\xAE\xF7\x47\x2B\x20\x3E\x73\x5E\xA5\x61\xAD\xB1\x7D\x56\xC5\xA3",
          31,
          "\xA4\x35\xD7\x27\x34\x8D\xDD\x22\x90\x7F\x7E\xB8\xF5\xFD\xBB\x4D\x93\x9D\xA6\x52\x4D\xB4\xF6\x45\x58\xC0\x2D\x25\xB1\x27\xEE"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #14 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\x83\xCD\x8C\xE0\xCB\x42\xB1\x60\xB6\xA3\x1C\x1C",
          8, "\x98\x66\x05\xB4\x3D\xF1\x5D\xE7",
          24,
          "\x01\xF6\xCE\x67\x64\xC5\x74\x48\x3B\xB0\x2E\x6B\xBF\x1E\x0A\xBD\x26\xA2\x25\x72\xB4\xD8\x0E\xE7",
          32,
          "\x8A\xE0\x52\x50\x8F\xBE\xCA\x93\x2E\x34\x6F\x05\xE0\xDC\x0D\xFB\xCF\x93\x9E\xAF\xFA\x3E\x58\x7C\x86\x7D\x6E\x1C\x48\x70\x38\x06"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #15 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\x5F\x54\x95\x0B\x18\xF2\xB1\x60\xB6\xA3\x1C\x1C",
          8, "\x48\xF2\xE7\xE1\xA7\x67\x1A\x51",
          25,
          "\xCD\xF1\xD8\x40\x6F\xC2\xE9\x01\x49\x53\x89\x70\x05\xFB\xFB\x8B\xA5\x72\x76\xF9\x24\x04\x60\x8E\x08",
          33,
          "\x08\xB6\x7E\xE2\x1C\x8B\xF2\x6E\x47\x3E\x40\x85\x99\xE9\xC0\x83\x6D\x6A\xF0\xBB\x18\xDF\x55\x46\x6C\xA8\x08\x78\xA7\x90\x47\x6D\xE5"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #16 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\xEC\x60\x08\x63\x31\x9A\xB1\x60\xB6\xA3\x1C\x1C",
          12, "\xDE\x97\xDF\x3B\x8C\xBD\x6D\x8E\x50\x30\xDA\x4C",
          19,
          "\xB0\x05\xDC\xFA\x0B\x59\x18\x14\x26\xA9\x61\x68\x5A\x99\x3D\x8C\x43\x18\x5B",
          27,
          "\x63\xB7\x8B\x49\x67\xB1\x9E\xDB\xB7\x33\xCD\x11\x14\xF6\x4E\xB2\x26\x08\x93\x68\xC3\x54\x82\x8D\x95\x0C\xC5"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #17 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\x60\xCF\xF1\xA3\x1E\xA1\xB1\x60\xB6\xA3\x1C\x1C",
          12, "\xA5\xEE\x93\xE4\x57\xDF\x05\x46\x6E\x78\x2D\xCF",
          20,
          "\x2E\x20\x21\x12\x98\x10\x5F\x12\x9D\x5E\xD9\x5B\x93\xF7\x2D\x30\xB2\xFA\xCC\xD7",
          28,
          "\x0B\xC6\xBB\xE2\xA8\xB9\x09\xF4\x62\x9E\xE6\xDC\x14\x8D\xA4\x44\x10\xE1\x8A\xF4\x31\x47\x38\x32\x76\xF6\x6A\x9F"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #18 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\x0F\x85\xCD\x99\x5C\x97\xB1\x60\xB6\xA3\x1C\x1C",
          12, "\x24\xAA\x1B\xF9\xA5\xCD\x87\x61\x82\xA2\x50\x74",
          21,
          "\x26\x45\x94\x1E\x75\x63\x2D\x34\x91\xAF\x0F\xC0\xC9\x87\x6C\x3B\xE4\xAA\x74\x68\xC9",
          29,
          "\x22\x2A\xD6\x32\xFA\x31\xD6\xAF\x97\x0C\x34\x5F\x7E\x77\xCA\x3B\xD0\xDC\x25\xB3\x40\xA1\xA3\xD3\x1F\x8D\x4B\x44\xB7"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #19 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\xC2\x9B\x2C\xAA\xC4\xCD\xB1\x60\xB6\xA3\x1C\x1C",
          8, "\x69\x19\x46\xB9\xCA\x07\xBE\x87",
          23,
          "\x07\x01\x35\xA6\x43\x7C\x9D\xB1\x20\xCD\x61\xD8\xF6\xC3\x9C\x3E\xA1\x25\xFD\x95\xA0\xD2\x3D",
          33,
          "\x05\xB8\xE1\xB9\xC4\x9C\xFD\x56\xCF\x13\x0A\xA6\x25\x1D\xC2\xEC\xC0\x6C\xCC\x50\x8F\xE6\x97\xA0\x06\x6D\x57\xC8\x4B\xEC\x18\x27\x68"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #20 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\x2C\x6B\x75\x95\xEE\x62\xB1\x60\xB6\xA3\x1C\x1C",
          8, "\xD0\xC5\x4E\xCB\x84\x62\x7D\xC4",
          24,
          "\xC8\xC0\x88\x0E\x6C\x63\x6E\x20\x09\x3D\xD6\x59\x42\x17\xD2\xE1\x88\x77\xDB\x26\x4E\x71\xA5\xCC",
          34,
          "\x54\xCE\xB9\x68\xDE\xE2\x36\x11\x57\x5E\xC0\x03\xDF\xAA\x1C\xD4\x88\x49\xBD\xF5\xAE\x2E\xDB\x6B\x7F\xA7\x75\xB1\x50\xED\x43\x83\xC5\xA9"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #21 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\xC5\x3C\xD4\xC2\xAA\x24\xB1\x60\xB6\xA3\x1C\x1C",
          8, "\xE2\x85\xE0\xE4\x80\x8C\xDA\x3D",
          25,
          "\xF7\x5D\xAA\x07\x10\xC4\xE6\x42\x97\x79\x4D\xC2\xB7\xD2\xA2\x07\x57\xB1\xAA\x4E\x44\x80\x02\xFF\xAB",
          35,
          "\xB1\x40\x45\x46\xBF\x66\x72\x10\xCA\x28\xE3\x09\xB3\x9B\xD6\xCA\x7E\x9F\xC8\x28\x5F\xE6\x98\xD4\x3C\xD2\x0A\x02\xE0\xBD\xCA\xED\x20\x10\xD3"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #22 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\xBE\xE9\x26\x7F\xBA\xDC\xB1\x60\xB6\xA3\x1C\x1C",
          12, "\x6C\xAE\xF9\x94\x11\x41\x57\x0D\x7C\x81\x34\x05",
          19,
          "\xC2\x38\x82\x2F\xAC\x5F\x98\xFF\x92\x94\x05\xB0\xAD\x12\x7A\x4E\x41\x85\x4E",
          29,
          "\x94\xC8\x95\x9C\x11\x56\x9A\x29\x78\x31\xA7\x21\x00\x58\x57\xAB\x61\xB8\x7A\x2D\xEA\x09\x36\xB6\xEB\x5F\x62\x5F\x5D"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #23 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\xDF\xA8\xB1\x24\x50\x07\xB1\x60\xB6\xA3\x1C\x1C",
          12, "\x36\xA5\x2C\xF1\x6B\x19\xA2\x03\x7A\xB7\x01\x1E",
          20,
          "\x4D\xBF\x3E\x77\x4A\xD2\x45\xE5\xD5\x89\x1F\x9D\x1C\x32\xA0\xAE\x02\x2C\x85\xD7",
          30,
          "\x58\x69\xE3\xAA\xD2\x44\x7C\x74\xE0\xFC\x05\xF9\xA4\xEA\x74\x57\x7F\x4D\xE8\xCA\x89\x24\x76\x42\x96\xAD\x04\x11\x9C\xE7"},
      { GCRY_CIPHER_CAMELLIA128, /* Packet Vector #24 */
          16, "\xD7\x5C\x27\x78\x07\x8C\xA9\x3D\x97\x1F\x96\xFD\xE7\x20\xF4\xCD",
          13, "\x00\x3B\x8F\xD8\xD3\xA9\x37\xB1\x60\xB6\xA3\x1C\x1C",
          12, "\xA4\xD4\x99\xF7\x84\x19\x72\x8C\x19\x17\x8B\x0C",
          21,
          "\x9D\xC9\xED\xAE\x2F\xF5\xDF\x86\x36\xE8\xC6\xDE\x0E\xED\x55\xF7\x86\x7E\x33\x33\x7D",
          31,
          "\x4B\x19\x81\x56\x39\x3B\x0F\x77\x96\x08\x6A\xAF\xB4\x54\xF8\xC3\xF0\x34\xCC\xA9\x66\x94\x5F\x1F\xCE\xA7\xE1\x1B\xEE\x6A\x2F"}
    };
  static const int cut[] = { 0, 1, 8, 10, 16, 19, -1 };
  gcry_cipher_hd_t hde, hdd;
  unsigned char out[MAX_DATA_LEN];
  u64 ctl_params[3];
  int split, aadsplit;
  size_t j, i, keylen, blklen, authlen;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "  Starting CCM checks.\n");

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      if (verbose)
        fprintf (stderr, "    checking CCM mode for %s [%i]\n",
                 gcry_cipher_algo_name (tv[i].algo),
                 tv[i].algo);

      for (j = 0; j < sizeof (cut) / sizeof (cut[0]); j++)
        {
          split = cut[j] < 0 ? tv[i].plainlen : cut[j];
          if (tv[i].plainlen < split)
            continue;

          err = gcry_cipher_open (&hde, tv[i].algo, GCRY_CIPHER_MODE_CCM, 0);
          if (!err)
            err = gcry_cipher_open (&hdd, tv[i].algo, GCRY_CIPHER_MODE_CCM, 0);
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_open failed: %s\n",
                    gpg_strerror (err));
              return;
            }

          keylen = gcry_cipher_get_algo_keylen(tv[i].algo);
          if (!keylen)
            {
              fail ("cipher-ccm, gcry_cipher_get_algo_keylen failed\n");
              return;
            }

          err = gcry_cipher_setkey (hde, tv[i].key, keylen);
          if (!err)
            err = gcry_cipher_setkey (hdd, tv[i].key, keylen);
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_setkey failed: %s\n",
                    gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          blklen = gcry_cipher_get_algo_blklen(tv[i].algo);
          if (!blklen)
            {
              fail ("cipher-ccm, gcry_cipher_get_algo_blklen failed\n");
              return;
            }

          err = gcry_cipher_setiv (hde, tv[i].nonce, tv[i].noncelen);
          if (!err)
            err = gcry_cipher_setiv (hdd, tv[i].nonce, tv[i].noncelen);
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_setiv failed: %s\n",
                    gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          authlen = tv[i].cipherlen - tv[i].plainlen;
          ctl_params[0] = tv[i].plainlen; /* encryptedlen */
          ctl_params[1] = tv[i].aadlen; /* aadlen */
          ctl_params[2] = authlen; /* authtaglen */
          err = gcry_cipher_ctl (hde, GCRYCTL_SET_CCM_LENGTHS, ctl_params,
                                 sizeof(ctl_params));
          if (!err)
            err = gcry_cipher_ctl (hdd, GCRYCTL_SET_CCM_LENGTHS, ctl_params,
                                   sizeof(ctl_params));
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_ctl GCRYCTL_SET_CCM_LENGTHS "
                    "failed: %s\n", gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          aadsplit = split > tv[i].aadlen ? 0 : split;

          err = gcry_cipher_authenticate (hde, tv[i].aad,
                                          tv[i].aadlen - aadsplit);
          if (!err)
            err = gcry_cipher_authenticate (hde,
                                            &tv[i].aad[tv[i].aadlen - aadsplit],
                                            aadsplit);
          if (!err)
            err = gcry_cipher_authenticate (hdd, tv[i].aad,
                                            tv[i].aadlen - aadsplit);
          if (!err)
            err = gcry_cipher_authenticate (hdd,
                                            &tv[i].aad[tv[i].aadlen - aadsplit],
                                            aadsplit);
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_authenticate failed: %s\n",
                   gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          err = gcry_cipher_encrypt (hde, out, MAX_DATA_LEN, tv[i].plaintext,
                                     tv[i].plainlen - split);
          if (!err)
            err = gcry_cipher_encrypt (hde, &out[tv[i].plainlen - split],
                                       MAX_DATA_LEN - (tv[i].plainlen - split),
                                       &tv[i].plaintext[tv[i].plainlen - split],
                                       split);
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_encrypt (%d:%d) failed: %s\n",
                    i, j, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          err = gcry_cipher_gettag (hde, &out[tv[i].plainlen], authlen);
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_gettag (%d:%d) failed: %s\n",
                    i, j, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          if (memcmp (tv[i].ciphertext, out, tv[i].cipherlen))
            fail ("cipher-ccm, encrypt mismatch entry %d:%d\n", i, j);

          err = gcry_cipher_decrypt (hdd, out, tv[i].plainlen - split, NULL, 0);
          if (!err)
            err = gcry_cipher_decrypt (hdd, &out[tv[i].plainlen - split], split,
                                       NULL, 0);
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_decrypt (%d:%d) failed: %s\n",
                    i, j, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          if (memcmp (tv[i].plaintext, out, tv[i].plainlen))
            fail ("cipher-ccm, decrypt mismatch entry %d:%d\n", i, j);

          err = gcry_cipher_checktag (hdd, &out[tv[i].plainlen], authlen);
          if (err)
            {
              fail ("cipher-ccm, gcry_cipher_checktag (%d:%d) failed: %s\n",
                    i, j, gpg_strerror (err));
              gcry_cipher_close (hde);
              gcry_cipher_close (hdd);
              return;
            }

          gcry_cipher_close (hde);
          gcry_cipher_close (hdd);
        }
    }

  /* Large buffer tests.  */

  /* Test encoding of aadlen > 0xfeff.  */
  {
    static const char key[]={0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
                             0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f};
    static const char iv[]={0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19};
    static const char tag[]={0x9C,0x76,0xE7,0x33,0xD5,0x15,0xB3,0x6C,
                             0xBA,0x76,0x95,0xF7,0xFB,0x91};
    char buf[1024];
    size_t enclen = 0x20000;
    size_t aadlen = 0x20000;
    size_t taglen = sizeof(tag);

    err = gcry_cipher_open (&hde, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0);
    if (err)
      {
        fail ("cipher-ccm-large, gcry_cipher_open failed: %s\n",
              gpg_strerror (err));
        return;
      }

    err = gcry_cipher_setkey (hde, key, sizeof (key));
    if (err)
      {
         fail ("cipher-ccm-large, gcry_cipher_setkey failed: %s\n",
               gpg_strerror (err));
         gcry_cipher_close (hde);
         return;
      }

    err = gcry_cipher_setiv (hde, iv, sizeof (iv));
    if (err)
      {
        fail ("cipher-ccm-large, gcry_cipher_setiv failed: %s\n",
              gpg_strerror (err));
        gcry_cipher_close (hde);
        return;
      }

    ctl_params[0] = enclen; /* encryptedlen */
    ctl_params[1] = aadlen; /* aadlen */
    ctl_params[2] = taglen; /* authtaglen */
    err = gcry_cipher_ctl (hde, GCRYCTL_SET_CCM_LENGTHS, ctl_params,
                           sizeof(ctl_params));
    if (err)
      {
        fail ("cipher-ccm-large, gcry_cipher_ctl GCRYCTL_SET_CCM_LENGTHS "
              "failed: %s\n", gpg_strerror (err));
        gcry_cipher_close (hde);
        return;
      }

    memset (buf, 0xaa, sizeof(buf));

    for (i = 0; i < aadlen; i += sizeof(buf))
      {
        err = gcry_cipher_authenticate (hde, buf, sizeof (buf));
        if (err)
          {
            fail ("cipher-ccm-large, gcry_cipher_authenticate failed: %s\n",
                 gpg_strerror (err));
            gcry_cipher_close (hde);
            return;
          }
      }

    for (i = 0; i < enclen; i += sizeof(buf))
      {
        memset (buf, 0xee, sizeof(buf));
        err = gcry_cipher_encrypt (hde, buf, sizeof (buf), NULL, 0);
        if (err)
          {
            fail ("cipher-ccm-large, gcry_cipher_encrypt failed: %s\n",
                 gpg_strerror (err));
            gcry_cipher_close (hde);
            return;
          }
      }

    err = gcry_cipher_gettag (hde, buf, taglen);
    if (err)
      {
        fail ("cipher-ccm-large, gcry_cipher_gettag failed: %s\n",
              gpg_strerror (err));
        gcry_cipher_close (hde);
        return;
      }

    if (memcmp (buf, tag, taglen) != 0)
      fail ("cipher-ccm-large, encrypt mismatch entry\n");

    gcry_cipher_close (hde);
  }

#if 0
  /* Test encoding of aadlen > 0xffffffff.  */
  {
    static const char key[]={0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
                             0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f};
    static const char iv[]={0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19};
    static const char tag[]={0x01,0xB2,0xC3,0x4A,0xA6,0x6A,0x07,0x6D,
                             0xBC,0xBD,0xEA,0x17,0xD3,0x73,0xD7,0xD4};
    char buf[1024];
    size_t enclen = (size_t)0xffffffff + 1 + 1024;
    size_t aadlen = (size_t)0xffffffff + 1 + 1024;
    size_t taglen = sizeof(tag);

    err = gcry_cipher_open (&hde, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0);
    if (err)
      {
        fail ("cipher-ccm-huge, gcry_cipher_open failed: %s\n",
              gpg_strerror (err));
        return;
      }

    err = gcry_cipher_setkey (hde, key, sizeof (key));
    if (err)
      {
         fail ("cipher-ccm-huge, gcry_cipher_setkey failed: %s\n",
               gpg_strerror (err));
         gcry_cipher_close (hde);
         return;
      }

    err = gcry_cipher_setiv (hde, iv, sizeof (iv));
    if (err)
      {
        fail ("cipher-ccm-huge, gcry_cipher_setiv failed: %s\n",
              gpg_strerror (err));
        gcry_cipher_close (hde);
        return;
      }

    ctl_params[0] = enclen; /* encryptedlen */
    ctl_params[1] = aadlen; /* aadlen */
    ctl_params[2] = taglen; /* authtaglen */
    err = gcry_cipher_ctl (hde, GCRYCTL_SET_CCM_LENGTHS, ctl_params,
                           sizeof(ctl_params));
    if (err)
      {
        fail ("cipher-ccm-huge, gcry_cipher_ctl GCRYCTL_SET_CCM_LENGTHS failed:"
              "%s\n", gpg_strerror (err));
        gcry_cipher_close (hde);
        return;
      }

    memset (buf, 0xaa, sizeof(buf));

    for (i = 0; i < aadlen; i += sizeof(buf))
      {
        err = gcry_cipher_authenticate (hde, buf, sizeof (buf));
        if (err)
          {
            fail ("cipher-ccm-huge, gcry_cipher_authenticate failed: %s\n",
                 gpg_strerror (err));
            gcry_cipher_close (hde);
            return;
          }
      }

    for (i = 0; i < enclen; i += sizeof(buf))
      {
        memset (buf, 0xee, sizeof(buf));
        err = gcry_cipher_encrypt (hde, buf, sizeof (buf), NULL, 0);
        if (err)
          {
            fail ("cipher-ccm-huge, gcry_cipher_encrypt failed: %s\n",
                 gpg_strerror (err));
            gcry_cipher_close (hde);
            return;
          }
      }

    err = gcry_cipher_gettag (hde, buf, taglen);
    if (err)
      {
        fail ("cipher-ccm-huge, gcry_cipher_gettag failed: %s\n",
              gpg_strerror (err));
        gcry_cipher_close (hde);
        return;
      }

    if (memcmp (buf, tag, taglen) != 0)
      fail ("cipher-ccm-huge, encrypt mismatch entry\n");

    gcry_cipher_close (hde);
  }

  if (verbose)
    fprintf (stderr, "  Completed CCM checks.\n");
#endif
#endif /*HAVE_U64_TYPEDEF*/
}


static void
check_stream_cipher (void)
{
  static const struct tv
  {
    const char *name;
    int algo;
    int keylen;
    int ivlen;
    const char *key;
    const char *iv;
    struct data
    {
      int inlen;
      const char *plaintext;
      const char *out;
    } data[MAX_DATA_LEN];
  } tv[] = {
#ifdef USE_SALSA20
    {
      "Salsa20 128 bit, test 1",
      GCRY_CIPHER_SALSA20, 16, 8,
      "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x00\x00\x00\x00\x00\x00\x00\x00",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x4D\xFA\x5E\x48\x1D\xA2\x3E\xA0"
        }
      }
    },
    {
      "Salsa20 128 bit, test 2",
      GCRY_CIPHER_SALSA20, 16, 8,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x80\x00\x00\x00\x00\x00\x00\x00",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\xB6\x6C\x1E\x44\x46\xDD\x95\x57"
        }
      }
    },
    {
      "Salsa20 128 bit, test 3",
      GCRY_CIPHER_SALSA20, 16, 8,
      "\x00\x53\xA6\xF9\x4C\x9F\xF2\x45\x98\xEB\x3E\x91\xE4\x37\x8A\xDD",
      "\x0D\x74\xDB\x42\xA9\x10\x77\xDE",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x05\xE1\xE7\xBE\xB6\x97\xD9\x99"
        }
      }
    },
    {
      "Salsa20 256 bit, test 1",
      GCRY_CIPHER_SALSA20, 32, 8,
      "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x00\x00\x00\x00\x00\x00\x00\x00",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\xE3\xBE\x8F\xDD\x8B\xEC\xA2\xE3"
        }
      }
    },
    {
      "Salsa20 256 bit, test 2",
      GCRY_CIPHER_SALSA20, 32, 8,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x80\x00\x00\x00\x00\x00\x00\x00",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x2A\xBA\x3D\xC4\x5B\x49\x47\x00"
        }
      }
    },
    {
      "Salsa20 256 bit, ecrypt verified, set 6, vector 0",
      GCRY_CIPHER_SALSA20, 32, 8,
      "\x00\x53\xA6\xF9\x4C\x9F\xF2\x45\x98\xEB\x3E\x91\xE4\x37\x8A\xDD"
      "\x30\x83\xD6\x29\x7C\xCF\x22\x75\xC8\x1B\x6E\xC1\x14\x67\xBA\x0D",
      "\x0D\x74\xDB\x42\xA9\x10\x77\xDE",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\xF5\xFA\xD5\x3F\x79\xF9\xDF\x58"
        },
        { 64,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          "\xF5\xFA\xD5\x3F\x79\xF9\xDF\x58\xC4\xAE\xA0\xD0\xED\x9A\x96\x01"
          "\xF2\x78\x11\x2C\xA7\x18\x0D\x56\x5B\x42\x0A\x48\x01\x96\x70\xEA"
          "\xF2\x4C\xE4\x93\xA8\x62\x63\xF6\x77\xB4\x6A\xCE\x19\x24\x77\x3D"
          "\x2B\xB2\x55\x71\xE1\xAA\x85\x93\x75\x8F\xC3\x82\xB1\x28\x0B\x71"
        }
      }
    },
    {
      "Salsa20/12 128 bit, test 1",
      GCRY_CIPHER_SALSA20R12, 16, 8,
      "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x00\x00\x00\x00\x00\x00\x00\x00",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\xFC\x20\x7D\xBF\xC7\x6C\x5E\x17"
        }
      }
    },
    {
      "Salsa20/12 128 bit, test 2",
      GCRY_CIPHER_SALSA20R12, 16, 8,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x80\x00\x00\x00\x00\x00\x00\x00",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x08\x28\x39\x9A\x6F\xEF\x20\xDA"
        }
      }
    },
    {
      "Salsa20/12 128 bit, test 3",
      GCRY_CIPHER_SALSA20R12, 16, 8,
      "\x00\x53\xA6\xF9\x4C\x9F\xF2\x45\x98\xEB\x3E\x91\xE4\x37\x8A\xDD",
      "\x0D\x74\xDB\x42\xA9\x10\x77\xDE",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\xAD\x9E\x60\xE6\xD2\xA2\x64\xB8"
        }
      }
    },
    {
      "Salsa20/12 256 bit, test 1",
      GCRY_CIPHER_SALSA20R12, 32, 8,
      "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x00\x00\x00\x00\x00\x00\x00\x00",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\xAF\xE4\x11\xED\x1C\x4E\x07\xE4"
        }
      }
    },
    {
      "Salsa20/12 256 bit, test 2",
      GCRY_CIPHER_SALSA20R12, 32, 8,
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x80\x00\x00\x00\x00\x00\x00\x00",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x17\x2C\x51\x92\xCB\x6E\x64\x5B"
        }
      }
    },
    {
      "Salsa20/12 256 bit, ecrypt verified, set 6, vector 0",
      GCRY_CIPHER_SALSA20R12, 32, 8,
      "\x00\x53\xA6\xF9\x4C\x9F\xF2\x45\x98\xEB\x3E\x91\xE4\x37\x8A\xDD"
      "\x30\x83\xD6\x29\x7C\xCF\x22\x75\xC8\x1B\x6E\xC1\x14\x67\xBA\x0D",
      "\x0D\x74\xDB\x42\xA9\x10\x77\xDE",
      {
        { 8,
          "\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x52\xE2\x0C\xF8\x77\x5A\xE8\x82"
        },
        { 64,
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          "\x52\xE2\x0C\xF8\x77\x5A\xE8\x82\xF2\x00\xC2\x99\x9F\xE4\xBA\x31"
          "\xA7\xA1\x8F\x1D\x5C\x97\x16\x19\x1D\x12\x31\x75\xE1\x47\xBD\x4E"
          "\x8C\xA6\xED\x16\x6C\xE0\xFC\x8E\x65\xA5\xCA\x60\x84\x20\xFC\x65"
          "\x44\xC9\x70\x0A\x0F\x21\x38\xE8\xC1\xA2\x86\xFB\x8C\x1F\xBF\xA0"
        }
      }
    }
#endif /*USE_SALSA20*/
  };

  gcry_cipher_hd_t hde, hdd;
  unsigned char out[MAX_DATA_LEN];
  int i, j;
  gcry_error_t err = 0;


  if (verbose)
    fprintf (stderr, "  Starting stream cipher checks.\n");

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      if (verbose)
        fprintf (stderr, "    checking stream mode for %s [%i] (%s)\n",
		 gcry_cipher_algo_name (tv[i].algo), tv[i].algo, tv[i].name);

      if (gcry_cipher_get_algo_blklen(tv[i].algo) != 1)
        {
          fail ("stream, gcry_cipher_get_algo_blklen: bad block length\n");
          continue;
        }

      err = gcry_cipher_open (&hde, tv[i].algo, GCRY_CIPHER_MODE_STREAM, 0);
      if (!err)
        err = gcry_cipher_open (&hdd, tv[i].algo, GCRY_CIPHER_MODE_STREAM, 0);
      if (err)
        {
          fail ("stream, gcry_cipher_open for stream mode failed: %s\n",
                gpg_strerror (err));
          continue;
        }

      /* Now loop over all the data samples.  */
      for (j = 0; tv[i].data[j].inlen; j++)
        {
          err = gcry_cipher_setkey (hde, tv[i].key, tv[i].keylen);
          if (!err)
            err = gcry_cipher_setkey (hdd, tv[i].key, tv[i].keylen);
          if (err)
            {
              fail ("stream, gcry_cipher_setkey failed: %s\n",
                    gpg_strerror (err));
              goto next;
            }

          err = gcry_cipher_setiv (hde, tv[i].iv, tv[i].ivlen);
          if (!err)
            err = gcry_cipher_setiv (hdd, tv[i].iv, tv[i].ivlen);
          if (err)
            {
              fail ("stream, gcry_cipher_setiv failed: %s\n",
                    gpg_strerror (err));
              goto next;
            }

          err = gcry_cipher_encrypt (hde, out, MAX_DATA_LEN,
                                     tv[i].data[j].plaintext,
                                     tv[i].data[j].inlen);
          if (err)
            {
              fail ("stream, gcry_cipher_encrypt (%d, %d) failed: %s\n",
                    i, j, gpg_strerror (err));
              goto next;
            }

          if (memcmp (tv[i].data[j].out, out, tv[i].data[j].inlen))
            {
              fail ("stream, encrypt mismatch entry %d:%d\n", i, j);
              mismatch (tv[i].data[j].out, tv[i].data[j].inlen,
                        out, tv[i].data[j].inlen);
            }

          err = gcry_cipher_decrypt (hdd, out, tv[i].data[j].inlen, NULL, 0);
          if (err)
            {
              fail ("stream, gcry_cipher_decrypt (%d, %d) failed: %s\n",
                    i, j, gpg_strerror (err));
              goto next;
            }

          if (memcmp (tv[i].data[j].plaintext, out, tv[i].data[j].inlen))
            fail ("stream, decrypt mismatch entry %d:%d\n", i, j);
        }


      /* This time we encrypt and decrypt one byte at a time */
      for (j = 0; tv[i].data[j].inlen; j++)
        {
          int byteNum;

          err = gcry_cipher_setkey (hde, tv[i].key, tv[i].keylen);
          if (!err)
            err = gcry_cipher_setkey (hdd, tv[i].key, tv[i].keylen);
          if (err)
            {
              fail ("stream, gcry_cipher_setkey failed: %s\n",
                    gpg_strerror (err));
              goto next;
            }

          err = gcry_cipher_setiv (hde, tv[i].iv, tv[i].ivlen);
          if (!err)
            err = gcry_cipher_setiv (hdd, tv[i].iv, tv[i].ivlen);
          if (err)
            {
              fail ("stream, gcry_cipher_setiv failed: %s\n",
                    gpg_strerror (err));
              goto next;
            }

          for (byteNum = 0; byteNum < tv[i].data[j].inlen; ++byteNum)
            {
              err = gcry_cipher_encrypt (hde, out+byteNum, 1,
                                         (tv[i].data[j].plaintext) + byteNum,
                                         1);
              if (err)
                {
                  fail ("stream, gcry_cipher_encrypt (%d, %d) failed: %s\n",
                        i, j, gpg_strerror (err));
                  goto next;
                }
            }

          if (memcmp (tv[i].data[j].out, out, tv[i].data[j].inlen))
            fail ("stream, encrypt mismatch entry %d:%d (byte-wise)\n", i, j);

          for (byteNum = 0; byteNum < tv[i].data[j].inlen; ++byteNum)
            {
              err = gcry_cipher_decrypt (hdd, out+byteNum, 1, NULL, 0);
              if (err)
                {
                  fail ("stream, gcry_cipher_decrypt (%d, %d) failed: %s\n",
                        i, j, gpg_strerror (err));
                  goto next;
                }
            }

          if (memcmp (tv[i].data[j].plaintext, out, tv[i].data[j].inlen))
            fail ("stream, decrypt mismatch entry %d:%d (byte-wise)\n", i, j);
        }

    next:
      gcry_cipher_close (hde);
      gcry_cipher_close (hdd);
    }
  if (verbose)
    fprintf (stderr, "  Completed stream cipher checks.\n");
}


static void
check_stream_cipher_large_block (void)
{
  static const struct tv
  {
    const char *name;
    int algo;
    int keylen;
    int ivlen;
    const char *key;
    const char *iv;
    struct data
    {
      int offset, length;
      const char *result;
    } data[MAX_DATA_LEN];
  } tv[] = {
#ifdef USE_SALSA20
    {
      "Salsa20 256 bit, ecrypt verified, set 6, vector 0",
      GCRY_CIPHER_SALSA20, 32, 8,
      "\x00\x53\xA6\xF9\x4C\x9F\xF2\x45\x98\xEB\x3E\x91\xE4\x37\x8A\xDD"
      "\x30\x83\xD6\x29\x7C\xCF\x22\x75\xC8\x1B\x6E\xC1\x14\x67\xBA\x0D",
      "\x0D\x74\xDB\x42\xA9\x10\x77\xDE",
      {
        { 0, 64,
          "\xF5\xFA\xD5\x3F\x79\xF9\xDF\x58\xC4\xAE\xA0\xD0\xED\x9A\x96\x01"
          "\xF2\x78\x11\x2C\xA7\x18\x0D\x56\x5B\x42\x0A\x48\x01\x96\x70\xEA"
          "\xF2\x4C\xE4\x93\xA8\x62\x63\xF6\x77\xB4\x6A\xCE\x19\x24\x77\x3D"
          "\x2B\xB2\x55\x71\xE1\xAA\x85\x93\x75\x8F\xC3\x82\xB1\x28\x0B\x71"
        },
        { 65472, 64,
         "\xB7\x0C\x50\x13\x9C\x63\x33\x2E\xF6\xE7\x7A\xC5\x43\x38\xA4\x07"
         "\x9B\x82\xBE\xC9\xF9\xA4\x03\xDF\xEA\x82\x1B\x83\xF7\x86\x07\x91"
         "\x65\x0E\xF1\xB2\x48\x9D\x05\x90\xB1\xDE\x77\x2E\xED\xA4\xE3\xBC"
         "\xD6\x0F\xA7\xCE\x9C\xD6\x23\xD9\xD2\xFD\x57\x58\xB8\x65\x3E\x70"
        },
        { 65536, 64,
         "\x81\x58\x2C\x65\xD7\x56\x2B\x80\xAE\xC2\xF1\xA6\x73\xA9\xD0\x1C"
         "\x9F\x89\x2A\x23\xD4\x91\x9F\x6A\xB4\x7B\x91\x54\xE0\x8E\x69\x9B"
         "\x41\x17\xD7\xC6\x66\x47\x7B\x60\xF8\x39\x14\x81\x68\x2F\x5D\x95"
         "\xD9\x66\x23\xDB\xC4\x89\xD8\x8D\xAA\x69\x56\xB9\xF0\x64\x6B\x6E"
        },
        { 131008, 64,
         "\xA1\x3F\xFA\x12\x08\xF8\xBF\x50\x90\x08\x86\xFA\xAB\x40\xFD\x10"
         "\xE8\xCA\xA3\x06\xE6\x3D\xF3\x95\x36\xA1\x56\x4F\xB7\x60\xB2\x42"
         "\xA9\xD6\xA4\x62\x8C\xDC\x87\x87\x62\x83\x4E\x27\xA5\x41\xDA\x2A"
         "\x5E\x3B\x34\x45\x98\x9C\x76\xF6\x11\xE0\xFE\xC6\xD9\x1A\xCA\xCC"
        }
      }
    },
    {
      "Salsa20 256 bit, ecrypt verified, set 6, vector 1",
      GCRY_CIPHER_SALSA20, 32, 8,
      "\x05\x58\xAB\xFE\x51\xA4\xF7\x4A\x9D\xF0\x43\x96\xE9\x3C\x8F\xE2"
      "\x35\x88\xDB\x2E\x81\xD4\x27\x7A\xCD\x20\x73\xC6\x19\x6C\xBF\x12",
      "\x16\x7D\xE4\x4B\xB2\x19\x80\xE7",
      {
        { 0, 64,
          "\x39\x44\xF6\xDC\x9F\x85\xB1\x28\x08\x38\x79\xFD\xF1\x90\xF7\xDE"
          "\xE4\x05\x3A\x07\xBC\x09\x89\x6D\x51\xD0\x69\x0B\xD4\xDA\x4A\xC1"
          "\x06\x2F\x1E\x47\xD3\xD0\x71\x6F\x80\xA9\xB4\xD8\x5E\x6D\x60\x85"
          "\xEE\x06\x94\x76\x01\xC8\x5F\x1A\x27\xA2\xF7\x6E\x45\xA6\xAA\x87"
        },
        { 65472, 64,
          "\x36\xE0\x3B\x4B\x54\xB0\xB2\xE0\x4D\x06\x9E\x69\x00\x82\xC8\xC5"
          "\x92\xDF\x56\xE6\x33\xF5\xD8\xC7\x68\x2A\x02\xA6\x5E\xCD\x13\x71"
          "\x8C\xA4\x35\x2A\xAC\xCB\x0D\xA2\x0E\xD6\xBB\xBA\x62\xE1\x77\xF2"
          "\x10\xE3\x56\x0E\x63\xBB\x82\x2C\x41\x58\xCA\xA8\x06\xA8\x8C\x82"
        },
        { 65536, 64,
          "\x1B\x77\x9E\x7A\x91\x7C\x8C\x26\x03\x9F\xFB\x23\xCF\x0E\xF8\xE0"
          "\x8A\x1A\x13\xB4\x3A\xCD\xD9\x40\x2C\xF5\xDF\x38\x50\x10\x98\xDF"
          "\xC9\x45\xA6\xCC\x69\xA6\xA1\x73\x67\xBC\x03\x43\x1A\x86\xB3\xED"
          "\x04\xB0\x24\x5B\x56\x37\x9B\xF9\x97\xE2\x58\x00\xAD\x83\x7D\x7D"
        },
        { 131008, 64,
          "\x7E\xC6\xDA\xE8\x1A\x10\x5E\x67\x17\x2A\x0B\x8C\x4B\xBE\x7D\x06"
          "\xA7\xA8\x75\x9F\x91\x4F\xBE\xB1\xAF\x62\xC8\xA5\x52\xEF\x4A\x4F"
          "\x56\x96\x7E\xA2\x9C\x74\x71\xF4\x6F\x3B\x07\xF7\xA3\x74\x6E\x95"
          "\x3D\x31\x58\x21\xB8\x5B\x6E\x8C\xB4\x01\x22\xB9\x66\x35\x31\x3C"
        }
      }
    },
    {
      "Salsa20 256 bit, ecrypt verified, set 6, vector 2",
      GCRY_CIPHER_SALSA20, 32, 8,
      "\x0A\x5D\xB0\x03\x56\xA9\xFC\x4F\xA2\xF5\x48\x9B\xEE\x41\x94\xE7"
      "\x3A\x8D\xE0\x33\x86\xD9\x2C\x7F\xD2\x25\x78\xCB\x1E\x71\xC4\x17",
      "\x1F\x86\xED\x54\xBB\x22\x89\xF0",
      {
        { 0, 64,
          "\x3F\xE8\x5D\x5B\xB1\x96\x0A\x82\x48\x0B\x5E\x6F\x4E\x96\x5A\x44"
          "\x60\xD7\xA5\x45\x01\x66\x4F\x7D\x60\xB5\x4B\x06\x10\x0A\x37\xFF"
          "\xDC\xF6\xBD\xE5\xCE\x3F\x48\x86\xBA\x77\xDD\x5B\x44\xE9\x56\x44"
          "\xE4\x0A\x8A\xC6\x58\x01\x15\x5D\xB9\x0F\x02\x52\x2B\x64\x40\x23"
        },
        { 65472, 64,
          "\xC8\xD6\xE5\x4C\x29\xCA\x20\x40\x18\xA8\x30\xE2\x66\xCE\xEE\x0D"
          "\x03\x7D\xC4\x7E\x92\x19\x47\x30\x2A\xCE\x40\xD1\xB9\x96\xA6\xD8"
          "\x0B\x59\x86\x77\xF3\x35\x2F\x1D\xAA\x6D\x98\x88\xF8\x91\xAD\x95"
          "\xA1\xC3\x2F\xFE\xB7\x1B\xB8\x61\xE8\xB0\x70\x58\x51\x51\x71\xC9"
        },
        { 65536, 64,
          "\xB7\x9F\xD7\x76\x54\x2B\x46\x20\xEF\xCB\x88\x44\x95\x99\xF2\x34"
          "\x03\xE7\x4A\x6E\x91\xCA\xCC\x50\xA0\x5A\x8F\x8F\x3C\x0D\xEA\x8B"
          "\x00\xE1\xA5\xE6\x08\x1F\x55\x26\xAE\x97\x5B\x3B\xC0\x45\x0F\x1A"
          "\x0C\x8B\x66\xF8\x08\xF1\x90\x4B\x97\x13\x61\x13\x7C\x93\x15\x6F"
        },
        { 131008, 64,
          "\x79\x98\x20\x4F\xED\x70\xCE\x8E\x0D\x02\x7B\x20\x66\x35\xC0\x8C"
          "\x8B\xC4\x43\x62\x26\x08\x97\x0E\x40\xE3\xAE\xDF\x3C\xE7\x90\xAE"
          "\xED\xF8\x9F\x92\x26\x71\xB4\x53\x78\xE2\xCD\x03\xF6\xF6\x23\x56"
          "\x52\x9C\x41\x58\xB7\xFF\x41\xEE\x85\x4B\x12\x35\x37\x39\x88\xC8"
        }
      }
    },
    {
      "Salsa20 256 bit, ecrypt verified, set 6, vector 3",
      GCRY_CIPHER_SALSA20, 32, 8,
      "\x0F\x62\xB5\x08\x5B\xAE\x01\x54\xA7\xFA\x4D\xA0\xF3\x46\x99\xEC"
      "\x3F\x92\xE5\x38\x8B\xDE\x31\x84\xD7\x2A\x7D\xD0\x23\x76\xC9\x1C",
      "\x28\x8F\xF6\x5D\xC4\x2B\x92\xF9",
      {
        { 0, 64,
          "\x5E\x5E\x71\xF9\x01\x99\x34\x03\x04\xAB\xB2\x2A\x37\xB6\x62\x5B"
          "\xF8\x83\xFB\x89\xCE\x3B\x21\xF5\x4A\x10\xB8\x10\x66\xEF\x87\xDA"
          "\x30\xB7\x76\x99\xAA\x73\x79\xDA\x59\x5C\x77\xDD\x59\x54\x2D\xA2"
          "\x08\xE5\x95\x4F\x89\xE4\x0E\xB7\xAA\x80\xA8\x4A\x61\x76\x66\x3F"
        },
        { 65472, 64,
          "\x2D\xA2\x17\x4B\xD1\x50\xA1\xDF\xEC\x17\x96\xE9\x21\xE9\xD6\xE2"
          "\x4E\xCF\x02\x09\xBC\xBE\xA4\xF9\x83\x70\xFC\xE6\x29\x05\x6F\x64"
          "\x91\x72\x83\x43\x6E\x2D\x3F\x45\x55\x62\x25\x30\x7D\x5C\xC5\xA5"
          "\x65\x32\x5D\x89\x93\xB3\x7F\x16\x54\x19\x5C\x24\x0B\xF7\x5B\x16"
        },
        { 65536, 64,
          "\xAB\xF3\x9A\x21\x0E\xEE\x89\x59\x8B\x71\x33\x37\x70\x56\xC2\xFE"
          "\xF4\x2D\xA7\x31\x32\x75\x63\xFB\x67\xC7\xBE\xDB\x27\xF3\x8C\x7C"
          "\x5A\x3F\xC2\x18\x3A\x4C\x6B\x27\x7F\x90\x11\x52\x47\x2C\x6B\x2A"
          "\xBC\xF5\xE3\x4C\xBE\x31\x5E\x81\xFD\x3D\x18\x0B\x5D\x66\xCB\x6C"
        },
        { 131008, 64,
          "\x1B\xA8\x9D\xBD\x3F\x98\x83\x97\x28\xF5\x67\x91\xD5\xB7\xCE\x23"
          "\x50\x36\xDE\x84\x3C\xCC\xAB\x03\x90\xB8\xB5\x86\x2F\x1E\x45\x96"
          "\xAE\x8A\x16\xFB\x23\xDA\x99\x7F\x37\x1F\x4E\x0A\xAC\xC2\x6D\xB8"
          "\xEB\x31\x4E\xD4\x70\xB1\xAF\x6B\x9F\x8D\x69\xDD\x79\xA9\xD7\x50"
        }
      }
    },
    {
      "Salsa20/12 256 bit, ecrypt verified, set 6, vector 0",
      GCRY_CIPHER_SALSA20R12, 32, 8,
      "\x00\x53\xA6\xF9\x4C\x9F\xF2\x45\x98\xEB\x3E\x91\xE4\x37\x8A\xDD"
      "\x30\x83\xD6\x29\x7C\xCF\x22\x75\xC8\x1B\x6E\xC1\x14\x67\xBA\x0D",
      "\x0D\x74\xDB\x42\xA9\x10\x77\xDE",
      {
        { 0, 64,
          "\x52\xE2\x0C\xF8\x77\x5A\xE8\x82\xF2\x00\xC2\x99\x9F\xE4\xBA\x31"
          "\xA7\xA1\x8F\x1D\x5C\x97\x16\x19\x1D\x12\x31\x75\xE1\x47\xBD\x4E"
          "\x8C\xA6\xED\x16\x6C\xE0\xFC\x8E\x65\xA5\xCA\x60\x84\x20\xFC\x65"
          "\x44\xC9\x70\x0A\x0F\x21\x38\xE8\xC1\xA2\x86\xFB\x8C\x1F\xBF\xA0"
        },
        { 65472, 64,
          "\x8F\xBC\x9F\xE8\x69\x1B\xD4\xF0\x82\xB4\x7F\x54\x05\xED\xFB\xC1"
          "\x6F\x4D\x5A\x12\xDD\xCB\x2D\x75\x4E\x8A\x99\x98\xD0\xB2\x19\x55"
          "\x7D\xFE\x29\x84\xF4\xA1\xD2\xDD\xA7\x6B\x95\x96\x92\x8C\xCE\x05"
          "\x56\xF5\x00\x66\xCD\x59\x9E\x44\xEF\x5C\x14\xB2\x26\x68\x3A\xEF"
        },
        { 65536, 64,
          "\xBC\xBD\x01\xDD\x28\x96\x1C\xC7\xAD\x30\x47\x38\x6C\xBC\xC6\x7C"
          "\x10\x8D\x6A\xF1\x11\x67\xE4\x0D\x7A\xE1\xB2\xFC\x45\x18\xA8\x67"
          "\xEF\xE4\x02\x65\x1D\x1D\x88\x51\xC4\xFD\x23\x30\xC5\x97\xB3\x6A"
          "\x46\xD5\x68\x9E\x00\xFC\x96\xFE\xCF\x9C\xE3\xE2\x21\x1D\x44\xBE"
        },
        { 131008, 64,
          "\x91\x66\xF3\x1C\xD8\x5B\x5B\xB1\x8F\xC6\x14\xE5\x4E\x4A\xD6\x7F"
          "\xB8\x65\x8E\x3B\xF9\xFB\x19\xB7\xA8\x2F\x0F\xE7\xDC\x90\x2D\xF5"
          "\x63\xC6\xAC\x4F\x44\x67\x48\xC4\xBC\x3E\x14\x05\xE1\x24\x82\x0D"
          "\xC4\x09\x41\x99\x8F\x44\xA8\x10\xE7\x22\x78\x7F\xCD\x47\x78\x4C"
        }
      }
    },
    {
      "Salsa20/12 256 bit, ecrypt verified, set 6, vector 1",
      GCRY_CIPHER_SALSA20R12, 32, 8,
      "\x05\x58\xAB\xFE\x51\xA4\xF7\x4A\x9D\xF0\x43\x96\xE9\x3C\x8F\xE2"
      "\x35\x88\xDB\x2E\x81\xD4\x27\x7A\xCD\x20\x73\xC6\x19\x6C\xBF\x12",
      "\x16\x7D\xE4\x4B\xB2\x19\x80\xE7",
      {
        { 0, 64,
          "\xC0\x75\x60\xB3\xE7\x76\xB4\x71\xC5\xE2\x93\x14\x26\xCA\xF1\xED"
          "\x3A\xE4\xB8\x67\x08\x76\x82\xCA\x9D\xFD\xC2\xBA\xE8\x93\x50\xBD"
          "\x84\x82\x1C\xAE\xFF\x85\xAA\xC4\x9D\x74\x35\xA7\xD9\x88\x93\x52"
          "\xF5\x27\x9E\x36\x12\x3F\x41\x72\x8A\x14\xEF\x26\x9F\xCB\x94\x4B"
        },
        { 65472, 64,
          "\xEE\xD1\xBB\x58\xF9\x0C\x89\xE0\x5C\xC6\x8B\x2D\xB6\x05\x58\x49"
          "\xB3\xD2\xB1\x87\xB7\xF0\x2F\x9A\x24\xCE\x34\x2A\xF0\xFC\x47\xA3"
          "\x74\xBD\x75\x90\xFB\xF4\xFD\x9E\xE5\x9B\x1A\x38\x1E\xBF\xD2\x29"
          "\xAD\x2A\x29\x01\xB3\xFB\x61\x08\x12\x90\x0B\x92\x30\xE6\x22\xE9"
        },
        { 65536, 64,
          "\x70\xF0\x49\x3A\x1B\x62\x53\xCC\x5E\xD3\x45\x0A\x31\xCF\x37\x7D"
          "\x83\x4B\xAD\x20\x72\x30\x29\x27\xCC\xD8\x30\x10\x4B\xD3\x05\xFF"
          "\x59\xD2\x94\x17\xB2\x32\x88\x4E\xC9\x59\x19\x4D\x60\x47\xC3\xDD"
          "\x66\x56\xC4\x7E\x32\x00\x64\xEB\x01\x44\xF7\x34\x1B\xC3\xD6\x97"
        },
        { 131008, 64,
          "\xD2\xCC\xF7\xC1\xAF\x2A\xB4\x66\xE6\x27\xDB\x44\x08\x40\x96\x9A"
          "\xBD\xAB\x68\xD8\x86\xAE\x6A\x38\xA1\x3F\xEE\x17\x50\xCA\x97\xB5"
          "\xD3\x31\x5B\x84\x08\x47\x28\x86\x2F\xBC\xC7\xD4\xA9\x7C\x75\xC8"
          "\x65\x5F\xF9\xD6\xBB\xC2\x61\x88\x63\x6F\x3E\xDF\xE1\x5C\x7D\x30"
        }
      }
    },
    {
      "Salsa20/12 256 bit, ecrypt verified, set 6, vector 2",
      GCRY_CIPHER_SALSA20R12, 32, 8,
      "\x0A\x5D\xB0\x03\x56\xA9\xFC\x4F\xA2\xF5\x48\x9B\xEE\x41\x94\xE7"
      "\x3A\x8D\xE0\x33\x86\xD9\x2C\x7F\xD2\x25\x78\xCB\x1E\x71\xC4\x17",
      "\x1F\x86\xED\x54\xBB\x22\x89\xF0",
      {
        { 0, 64,
          "\x51\x22\x52\x91\x01\x90\xD1\x54\xD1\x4D\x0B\x92\x32\xB8\x84\x31"
          "\x8C\xCB\x43\x81\x9B\xD5\x42\x19\x32\xC0\x3A\x13\xF0\x7B\x40\x10"
          "\x83\xD7\x89\x72\x5A\xA9\xDA\x0B\x41\xCB\x62\x24\x94\x5E\xDC\xB0"
          "\xFB\x6F\xD7\xC2\x34\x22\x35\xC9\x70\xF6\x4E\x10\x1C\x25\x68\x64"
        },
        { 65472, 64,
          "\x97\x96\x74\x55\x84\x0A\x4A\xE5\xC1\xCA\xCE\x49\x15\x19\x13\x8A"
          "\xA3\x5E\x5F\x02\x40\x7D\x4A\x1F\xE5\x08\x6D\x35\xF3\x55\x1E\xF4"
          "\x77\xD9\x28\x9D\x17\x23\x79\x7C\x1A\x49\xEC\x26\x62\x9A\xFA\xDC"
          "\x56\xA0\x38\xA3\x8C\x75\x88\x1B\x62\x17\xFD\x74\x67\x25\x59\x09"
        },
        { 65536, 64,
          "\x1B\xF8\x2E\x3D\x5C\x54\xDA\xAB\xCF\x84\x15\xF8\xA2\xA1\xA2\x2E"
          "\x86\x88\x06\x33\x4F\xF3\x11\x36\x04\x74\x1C\x1D\xF2\xB9\x84\x0F"
          "\x87\xDE\xEF\xB0\x07\x23\xA8\xA1\xB2\x4A\x4D\xA1\x7E\xCD\xAD\x00"
          "\x01\xF9\x79\xDD\xAE\x2D\xF0\xC5\xE1\xE5\x32\xC4\x8F\x8E\x0D\x34"
        },
        { 131008, 64,
          "\x06\xD8\x4F\x6A\x71\x34\x84\x20\x32\x9F\xCD\x0C\x41\x75\x9A\xD1"
          "\x8F\x99\x57\xA3\x8F\x22\x89\x3B\xA5\x58\xC5\x05\x11\x97\x28\x5C"
          "\x6B\xE2\xFD\x6C\x96\xA5\xC6\x62\xAF\xD3\x11\x78\xE7\x0F\x96\x0A"
          "\xAB\x3F\x47\x96\x23\xA4\x44\xB6\x81\x91\xE4\xC5\x28\x46\x93\x88"
        }
      }
    },
    {
      "Salsa20/12 256 bit, ecrypt verified, set 6, vector 3",
      GCRY_CIPHER_SALSA20R12, 32, 8,
      "\x0F\x62\xB5\x08\x5B\xAE\x01\x54\xA7\xFA\x4D\xA0\xF3\x46\x99\xEC"
      "\x3F\x92\xE5\x38\x8B\xDE\x31\x84\xD7\x2A\x7D\xD0\x23\x76\xC9\x1C",
      "\x28\x8F\xF6\x5D\xC4\x2B\x92\xF9",
      {
        { 0, 64,
          "\x99\xDB\x33\xAD\x11\xCE\x0C\xCB\x3B\xFD\xBF\x8D\x0C\x18\x16\x04"
          "\x52\xD0\x14\xCD\xE9\x89\xB4\xC4\x11\xA5\x59\xFF\x7C\x20\xA1\x69"
          "\xE6\xDC\x99\x09\xD8\x16\xBE\xCE\xDC\x40\x63\xCE\x07\xCE\xA8\x28"
          "\xF4\x4B\xF9\xB6\xC9\xA0\xA0\xB2\x00\xE1\xB5\x2A\xF4\x18\x59\xC5"
        },
        { 65472, 64,
          "\x2F\xF2\x02\x64\xEE\xAF\x47\xAB\x7D\x57\xC3\x62\x24\x53\x54\x51"
          "\x73\x5A\xC8\x36\xD3\x2D\xD2\x8A\xE6\x36\x45\xCE\x95\x2F\x7F\xDB"
          "\xE6\x68\x9C\x69\x59\x77\xB1\xC7\x6E\x60\xDD\x5B\x27\xAC\xA4\x76"
          "\xD2\x62\x0F\xDC\x93\x13\xE8\x48\x9B\xA5\x6A\x70\xC9\xF4\xC3\xA8"
        },
        { 65536, 64,
          "\xEB\x30\xCD\xA7\x27\xC0\xF8\xB7\xE4\x5D\x5E\xF3\x0D\xB7\xCB\xE0"
          "\x21\xF2\x29\x1E\x5F\x56\x93\x8D\x56\xF6\x87\xB7\x37\xC3\xB4\x27"
          "\x54\x5C\x56\xA6\xD3\xA0\xBF\x2B\x2F\x47\xB4\x84\x93\xFA\xE4\x5E"
          "\xD5\x0C\x2E\x9B\xBE\x49\xFD\x92\xD6\x7C\x76\x49\x05\x5F\x06\xFD"
        },
        { 131008, 64,
          "\x0E\xBF\x6C\xC3\xCB\xCB\xE7\x4E\x6E\xE8\x07\x47\x1B\x49\x2A\x67"
          "\x39\xA5\x2F\x57\x11\x31\xA2\x50\xBC\xDF\xA0\x76\xA2\x65\x90\xD7"
          "\xED\xE6\x75\x1C\x03\x26\xA0\x2C\xB1\x1C\x58\x77\x35\x52\x80\x4F"
          "\xD8\x68\x67\x15\x35\x5C\x5A\x5C\xC5\x91\x96\x3A\x75\xE9\x94\xB4"
        }
      }
    }
#endif /*USE_SALSA20*/
  };


  char zeroes[512];
  gcry_cipher_hd_t hde;
  unsigned char *buffer;
  unsigned char *p;
  size_t buffersize;
  unsigned int n;
  int i, j;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "  Starting large block stream cipher checks.\n");

  memset (zeroes, 0, 512);

  buffersize = 128 * 1024;
  buffer = gcry_xmalloc (buffersize+1024);
  memset (buffer+buffersize, 0x5a, 1024);

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      if (verbose)
        fprintf (stderr, "    checking large block stream for %s [%i] (%s)\n",
		 gcry_cipher_algo_name (tv[i].algo), tv[i].algo, tv[i].name);

      err = gcry_cipher_open (&hde, tv[i].algo, GCRY_CIPHER_MODE_STREAM, 0);
      if (err)
        {
          fail ("large stream, gcry_cipher_open for stream mode failed: %s\n",
                gpg_strerror (err));
          continue;
        }

      err = gcry_cipher_setkey (hde, tv[i].key, tv[i].keylen);
      if (err)
        {
          fail ("large stream, gcry_cipher_setkey failed: %s\n",
                gpg_strerror (err));
          goto next;
        }

      err = gcry_cipher_setiv (hde, tv[i].iv, tv[i].ivlen);
      if (err)
        {
          fail ("large stream, gcry_cipher_setiv failed: %s\n",
                gpg_strerror (err));
          goto next;
        }

      for (j=0, p=buffer; j < buffersize/512; j++, p += 512)
        {
          err = gcry_cipher_encrypt (hde, p, 512, zeroes, 512);
          if (err)
            {
              fail ("large stream, "
                    "gcry_cipher_encrypt (%d) block %d failed: %s\n",
                    i, j, gpg_strerror (err));
              goto next;
            }
        }
      for (j=0, p=buffer+buffersize; j < 1024; j++, p++)
        if (*p != 0x5a)
          die ("large stream, buffer corrupted at j=%d\n", j);

      /* Now loop over all the data samples.  */
      for (j = 0; tv[i].data[j].length; j++)
        {
          assert (tv[i].data[j].offset + tv[i].data[j].length <= buffersize);

          if (memcmp (tv[i].data[j].result,
                      buffer + tv[i].data[j].offset, tv[i].data[j].length))
            {
              fail ("large stream, encrypt mismatch entry %d:%d\n", i, j);
              mismatch (tv[i].data[j].result, tv[i].data[j].length,
                        buffer + tv[i].data[j].offset, tv[i].data[j].length);
            }
        }

      /*
       *  Let's do the same thing again but using changing block sizes.
       */
      err = gcry_cipher_setkey (hde, tv[i].key, tv[i].keylen);
      if (err)
        {
          fail ("large stream, gcry_cipher_setkey failed: %s\n",
                gpg_strerror (err));
          goto next;
        }

      err = gcry_cipher_setiv (hde, tv[i].iv, tv[i].ivlen);
      if (err)
        {
          fail ("large stream, gcry_cipher_setiv failed: %s\n",
                gpg_strerror (err));
          goto next;
        }

      for (n=0, p=buffer, j = 0; n < buffersize; n += j, p += j)
        {
          switch (j)
            {
            case   0: j =   1;  break;
            case   1: j =  64; break;
            case  64: j=  384; break;
            case 384: j =  63; break;
            case  63: j = 512; break;
            case 512: j =  32; break;
            case  32: j = 503; break;
            default:  j = 509; break;
            }
          if ( n + j >= buffersize )
            j = buffersize - n;
          assert (j <= 512);
          err = gcry_cipher_encrypt (hde, p, j, zeroes, j);
          if (err)
            {
              fail ("large stream, "
                    "gcry_cipher_encrypt (%d) offset %u failed: %s\n",
                    i, n, gpg_strerror (err));
              goto next;
            }
        }
      for (j=0, p=buffer+buffersize; j < 1024; j++, p++)
        if (*p != 0x5a)
          die ("large stream, buffer corrupted at j=%d (line %d)\n",
               j, __LINE__);

      /* Now loop over all the data samples.  */
      for (j = 0; tv[i].data[j].length; j++)
        {
          assert (tv[i].data[j].offset + tv[i].data[j].length <= buffersize);

          if (memcmp (tv[i].data[j].result,
                      buffer + tv[i].data[j].offset, tv[i].data[j].length))
            {
              fail ("large stream var, encrypt mismatch entry %d:%d\n", i, j);
              mismatch (tv[i].data[j].result, tv[i].data[j].length,
                        buffer + tv[i].data[j].offset, tv[i].data[j].length);
            }
        }

    next:
      gcry_cipher_close (hde);
    }

  gcry_free (buffer);
  if (verbose)
    fprintf (stderr, "  Completed large block stream cipher checks.\n");
}



/* Check that our bulk encryption fucntions work properly.  */
static void
check_bulk_cipher_modes (void)
{
  static const struct
  {
    int algo;
    int mode;
    const char *key;
    int  keylen;
    const char *iv;
    int ivlen;
    char t1_hash[20];
  } tv[] = {
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[0]*/
      { 0x53, 0xda, 0x27, 0x3c, 0x78, 0x3d, 0x54, 0x66, 0x19, 0x63,
        0xd7, 0xe6, 0x20, 0x10, 0xcd, 0xc0, 0x5a, 0x0b, 0x06, 0xcc }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[1]*/
      { 0xc7, 0xb1, 0xd0, 0x09, 0x95, 0x04, 0x34, 0x61, 0x2b, 0xd9,
        0xcb, 0xb3, 0xc7, 0xcb, 0xef, 0xea, 0x16, 0x19, 0x9b, 0x3e }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[2]*/
      { 0x31, 0xe1, 0x1f, 0x63, 0x65, 0x47, 0x8c, 0x3f, 0x53, 0xdb,
        0xd9, 0x4d, 0x91, 0x1d, 0x02, 0x9c, 0x05, 0x25, 0x58, 0x29 }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[3]*/
      { 0xdc, 0x0c, 0xc2, 0xd9, 0x6b, 0x47, 0xf9, 0xeb, 0x06, 0xb4,
        0x2f, 0x6e, 0xec, 0x72, 0xbf, 0x55, 0x26, 0x7f, 0xa9, 0x97 }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[4]*/
      { 0x2b, 0x90, 0x9b, 0xe6, 0x40, 0xab, 0x6e, 0xc2, 0xc5, 0xb1,
        0x87, 0xf5, 0x43, 0x84, 0x7b, 0x04, 0x06, 0x47, 0xd1, 0x8f }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[5]*/
      { 0xaa, 0xa8, 0xdf, 0x03, 0xb0, 0xba, 0xc4, 0xe3, 0xc1, 0x02,
        0x38, 0x31, 0x8d, 0x86, 0xcb, 0x49, 0x6d, 0xad, 0xae, 0x01 }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[6]*/
      { 0x65, 0xfe, 0xde, 0x48, 0xd0, 0xa1, 0xa6, 0xf9, 0x24, 0x6b,
        0x52, 0x5f, 0x21, 0x8a, 0x6f, 0xc7, 0x70, 0x3b, 0xd8, 0x4a }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[7]*/
      { 0x59, 0x5b, 0x02, 0xa2, 0x88, 0xc0, 0xbe, 0x94, 0x43, 0xaa,
        0x39, 0xf6, 0xbd, 0xcc, 0x83, 0x99, 0xee, 0x00, 0xa1, 0x91 }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[8]*/
      { 0x38, 0x8c, 0xe1, 0xe2, 0xbe, 0x67, 0x60, 0xe8, 0xeb, 0xce,
        0xd0, 0xc6, 0xaa, 0xd6, 0xf6, 0x26, 0x15, 0x56, 0xd0, 0x2b }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CTR,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[9]*/
      { 0x9a, 0x48, 0x94, 0xd6, 0x50, 0x46, 0x81, 0xdb, 0x68, 0x34,
        0x3b, 0xc5, 0x9e, 0x66, 0x94, 0x81, 0x98, 0xa0, 0xf9, 0xff }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[10]*/
      { 0x2c, 0x2c, 0xd3, 0x75, 0x81, 0x2a, 0x59, 0x07, 0xeb, 0x08,
        0xce, 0x28, 0x4c, 0x0c, 0x6a, 0xa8, 0x8f, 0xa3, 0x98, 0x7e }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[11]*/
      { 0x64, 0xce, 0x73, 0x03, 0xc7, 0x89, 0x99, 0x1f, 0xf1, 0xce,
        0xfe, 0xfb, 0xb9, 0x42, 0x30, 0xdf, 0xbb, 0x68, 0x6f, 0xd3 }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[12]*/
      { 0x51, 0xae, 0xf5, 0xac, 0x22, 0xa0, 0xba, 0x11, 0xc5, 0xaa,
        0xb4, 0x70, 0x99, 0xce, 0x18, 0x08, 0x12, 0x9b, 0xb1, 0xc5 }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[13]*/
      { 0x57, 0x91, 0xea, 0x48, 0xd8, 0xbf, 0x9e, 0xc1, 0xae, 0x33,
        0xb3, 0xfd, 0xf7, 0x7a, 0xeb, 0x30, 0xb1, 0x62, 0x0d, 0x82 }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[14]*/
      { 0x2d, 0x71, 0x54, 0xb9, 0xc5, 0x28, 0x76, 0xff, 0x76, 0xb5,
        0x99, 0x37, 0x99, 0x9d, 0xf7, 0x10, 0x6d, 0x86, 0x4f, 0x3f }
    }
  };
  gcry_cipher_hd_t hde = NULL;
  gcry_cipher_hd_t hdd = NULL;
  unsigned char *buffer_base, *outbuf_base; /* Allocated buffers.  */
  unsigned char *buffer, *outbuf;           /* Aligned buffers.  */
  size_t buflen;
  unsigned char hash[20];
  int i, j, keylen, blklen;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "Starting bulk cipher checks.\n");

  buflen = 16*100;  /* We check a 1600 byte buffer.  */
  buffer_base = gcry_xmalloc (buflen+16);
  buffer = buffer_base + (16 - ((size_t)buffer_base & 0x0f));
  outbuf_base = gcry_xmalloc (buflen+16);
  outbuf = outbuf_base + (16 - ((size_t)outbuf_base & 0x0f));


  for (i = 0; i < DIM (tv); i++)
    {
      if (verbose)
        fprintf (stderr, "    checking bulk encryption for %s [%i], mode %d\n",
		 gcry_cipher_algo_name (tv[i].algo),
		 tv[i].algo, tv[i].mode);
      err = gcry_cipher_open (&hde, tv[i].algo, tv[i].mode, 0);
      if (!err)
        err = gcry_cipher_open (&hdd, tv[i].algo, tv[i].mode, 0);
      if (err)
        {
          fail ("gcry_cipher_open failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      keylen = gcry_cipher_get_algo_keylen(tv[i].algo);
      if (!keylen)
        {
          fail ("gcry_cipher_get_algo_keylen failed\n");
          goto leave;
        }

      err = gcry_cipher_setkey (hde, tv[i].key, tv[i].keylen);
      if (!err)
        err = gcry_cipher_setkey (hdd, tv[i].key, tv[i].keylen);
      if (err)
        {
          fail ("gcry_cipher_setkey failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      blklen = gcry_cipher_get_algo_blklen(tv[i].algo);
      if (!blklen)
        {
          fail ("gcry_cipher_get_algo_blklen failed\n");
          goto leave;
        }

      err = gcry_cipher_setiv (hde, tv[i].iv, tv[i].ivlen);
      if (!err)
        err = gcry_cipher_setiv (hdd, tv[i].iv,  tv[i].ivlen);
      if (err)
        {
          fail ("gcry_cipher_setiv failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      /* Fill the buffer with our test pattern.  */
      for (j=0; j < buflen; j++)
        buffer[j] = ((j & 0xff) ^ ((j >> 8) & 0xff));

      err = gcry_cipher_encrypt (hde, outbuf, buflen, buffer, buflen);
      if (err)
        {
          fail ("gcry_cipher_encrypt (algo %d, mode %d) failed: %s\n",
                tv[i].algo, tv[i].mode, gpg_strerror (err));
          goto leave;
        }

      gcry_md_hash_buffer (GCRY_MD_SHA1, hash, outbuf, buflen);
#if 0
      printf ("/*[%d]*/\n", i);
      fputs ("      {", stdout);
      for (j=0; j < 20; j++)
        printf (" 0x%02x%c%s", hash[j], j==19? ' ':',', j == 9? "\n       ":"");
      puts ("}");
#endif

      if (memcmp (hash, tv[i].t1_hash, 20))
        fail ("encrypt mismatch (algo %d, mode %d)\n",
              tv[i].algo, tv[i].mode);

      err = gcry_cipher_decrypt (hdd, outbuf, buflen, NULL, 0);
      if (err)
        {
          fail ("gcry_cipher_decrypt (algo %d, mode %d) failed: %s\n",
                tv[i].algo, tv[i].mode, gpg_strerror (err));
          goto leave;
        }

      if (memcmp (buffer, outbuf, buflen))
        fail ("decrypt mismatch (algo %d, mode %d)\n",
              tv[i].algo, tv[i].mode);

      gcry_cipher_close (hde); hde = NULL;
      gcry_cipher_close (hdd); hdd = NULL;
    }

  if (verbose)
    fprintf (stderr, "Completed bulk cipher checks.\n");
 leave:
  gcry_cipher_close (hde);
  gcry_cipher_close (hdd);
  gcry_free (buffer_base);
  gcry_free (outbuf_base);
}


/* The core of the cipher check.  In addition to the parameters passed
   to check_one_cipher it also receives the KEY and the plain data.
   PASS is printed with error messages.  The function returns 0 on
   success.  */
static int
check_one_cipher_core (int algo, int mode, int flags,
                       const char *key, size_t nkey,
                       const unsigned char *plain, size_t nplain,
                       int bufshift, int pass)
{
  gcry_cipher_hd_t hd;
  unsigned char in_buffer[1040+1], out_buffer[1040+1];
  unsigned char *in, *out;
  int keylen;
  gcry_error_t err = 0;

  assert (nkey == 32);
  assert (nplain == 1040);
  assert (sizeof(in_buffer) == nplain + 1);
  assert (sizeof(out_buffer) == sizeof(in_buffer));

  if (!bufshift)
    {
      in = in_buffer;
      out = out_buffer;
    }
  else if (bufshift == 1)
    {
      in = in_buffer+1;
      out = out_buffer;
    }
  else if (bufshift == 2)
    {
      in = in_buffer+1;
      out = out_buffer+1;
    }
  else
    {
      in = in_buffer;
      out = out_buffer+1;
    }

  keylen = gcry_cipher_get_algo_keylen (algo);
  if (!keylen)
    {
      fail ("pass %d, algo %d, mode %d, gcry_cipher_get_algo_keylen failed\n",
	    pass, algo, mode);
      return -1;
    }

  if (keylen < 40 / 8 || keylen > 32)
    {
      fail ("pass %d, algo %d, mode %d, keylength problem (%d)\n", pass, algo, mode, keylen);
      return -1;
    }

  err = gcry_cipher_open (&hd, algo, mode, flags);
  if (err)
    {
      fail ("pass %d, algo %d, mode %d, gcry_cipher_open failed: %s\n",
	    pass, algo, mode, gpg_strerror (err));
      return -1;
    }

  err = gcry_cipher_setkey (hd, key, keylen);
  if (err)
    {
      fail ("pass %d, algo %d, mode %d, gcry_cipher_setkey failed: %s\n",
	    pass, algo, mode, gpg_strerror (err));
      gcry_cipher_close (hd);
      return -1;
    }

  err = gcry_cipher_encrypt (hd, out, nplain, plain, nplain);
  if (err)
    {
      fail ("pass %d, algo %d, mode %d, gcry_cipher_encrypt failed: %s\n",
	    pass, algo, mode, gpg_strerror (err));
      gcry_cipher_close (hd);
      return -1;
    }

  gcry_cipher_reset (hd);

  err = gcry_cipher_decrypt (hd, in, nplain, out, nplain);
  if (err)
    {
      fail ("pass %d, algo %d, mode %d, gcry_cipher_decrypt failed: %s\n",
	    pass, algo, mode, gpg_strerror (err));
      gcry_cipher_close (hd);
      return -1;
    }

  if (memcmp (plain, in, nplain))
    fail ("pass %d, algo %d, mode %d, encrypt-decrypt mismatch\n",
          pass, algo, mode);

  /* Again, using in-place encryption.  */
  gcry_cipher_reset (hd);

  memcpy (out, plain, nplain);
  err = gcry_cipher_encrypt (hd, out, nplain, NULL, 0);
  if (err)
    {
      fail ("pass %d, algo %d, mode %d, in-place, gcry_cipher_encrypt failed:"
            " %s\n",
	    pass, algo, mode, gpg_strerror (err));
      gcry_cipher_close (hd);
      return -1;
    }

  gcry_cipher_reset (hd);

  err = gcry_cipher_decrypt (hd, out, nplain, NULL, 0);
  if (err)
    {
      fail ("pass %d, algo %d, mode %d, in-place, gcry_cipher_decrypt failed:"
            " %s\n",
	    pass, algo, mode, gpg_strerror (err));
      gcry_cipher_close (hd);
      return -1;
    }

  if (memcmp (plain, out, nplain))
    fail ("pass %d, algo %d, mode %d, in-place, encrypt-decrypt mismatch\n",
          pass, algo, mode);


  gcry_cipher_close (hd);

  return 0;
}



static void
check_one_cipher (int algo, int mode, int flags)
{
  char key[32+1];
  unsigned char plain[1040+1];
  int bufshift, i;

  for (bufshift=0; bufshift < 4; bufshift++)
    {
      /* Pass 0: Standard test.  */
      memcpy (key, "0123456789abcdef.,;/[]{}-=ABCDEF", 32);
      memcpy (plain, "foobar42FOOBAR17", 16);
      for (i = 16; i < 1040; i += 16)
        {
          memcpy (&plain[i], &plain[i-16], 16);
          if (!++plain[i+7])
            plain[i+6]++;
          if (!++plain[i+15])
            plain[i+14]++;
        }

      if (check_one_cipher_core (algo, mode, flags, key, 32, plain, 1040,
                                 bufshift, 0+10*bufshift))
        return;

      /* Pass 1: Key not aligned.  */
      memmove (key+1, key, 32);
      if (check_one_cipher_core (algo, mode, flags, key+1, 32, plain, 1040,
                                 bufshift, 1+10*bufshift))
        return;

      /* Pass 2: Key not aligned and data not aligned.  */
      memmove (plain+1, plain, 1040);
      if (check_one_cipher_core (algo, mode, flags, key+1, 32, plain+1, 1040,
                                 bufshift, 2+10*bufshift))
        return;

      /* Pass 3: Key aligned and data not aligned.  */
      memmove (key, key+1, 32);
      if (check_one_cipher_core (algo, mode, flags, key, 32, plain+1, 1040,
                                 bufshift, 3+10*bufshift))
        return;
    }

  return;
}



static void
check_ciphers (void)
{
  static const int algos[] = {
#if USE_BLOWFISH
    GCRY_CIPHER_BLOWFISH,
#endif
#if USE_DES
    GCRY_CIPHER_DES,
    GCRY_CIPHER_3DES,
#endif
#if USE_CAST5
    GCRY_CIPHER_CAST5,
#endif
#if USE_AES
    GCRY_CIPHER_AES,
    GCRY_CIPHER_AES192,
    GCRY_CIPHER_AES256,
#endif
#if USE_TWOFISH
    GCRY_CIPHER_TWOFISH,
    GCRY_CIPHER_TWOFISH128,
#endif
#if USE_SERPENT
    GCRY_CIPHER_SERPENT128,
    GCRY_CIPHER_SERPENT192,
    GCRY_CIPHER_SERPENT256,
#endif
#if USE_RFC2268
    GCRY_CIPHER_RFC2268_40,
#endif
#if USE_SEED
    GCRY_CIPHER_SEED,
#endif
#if USE_CAMELLIA
    GCRY_CIPHER_CAMELLIA128,
    GCRY_CIPHER_CAMELLIA192,
    GCRY_CIPHER_CAMELLIA256,
#endif
#if USE_IDEA
    GCRY_CIPHER_IDEA,
#endif
#if USE_GOST28147
    GCRY_CIPHER_GOST28147,
#endif
    0
  };
  static const int algos2[] = {
#if USE_ARCFOUR
    GCRY_CIPHER_ARCFOUR,
#endif
#if USE_SALSA20
    GCRY_CIPHER_SALSA20,
    GCRY_CIPHER_SALSA20R12,
#endif
    0
  };
  int i;

  if (verbose)
    fprintf (stderr, "Starting Cipher checks.\n");
  for (i = 0; algos[i]; i++)
    {
      if (gcry_cipher_test_algo (algos[i]) && in_fips_mode)
        {
          if (verbose)
            fprintf (stderr, "  algorithm %d not available in fips mode\n",
		     algos[i]);
          continue;
        }
      if (verbose)
	fprintf (stderr, "  checking %s [%i]\n",
		 gcry_cipher_algo_name (algos[i]),
		 gcry_cipher_map_name (gcry_cipher_algo_name (algos[i])));

      check_one_cipher (algos[i], GCRY_CIPHER_MODE_ECB, 0);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CFB, 0);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_OFB, 0);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CBC, 0);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CTR, 0);
      if (gcry_cipher_get_algo_blklen (algos[i]) == GCRY_GCM_BLOCK_LEN)
        check_one_cipher (algos[i], GCRY_CIPHER_MODE_GCM, 0);
    }

  for (i = 0; algos2[i]; i++)
    {
      if (gcry_cipher_test_algo (algos[i]) && in_fips_mode)
        {
          if (verbose)
            fprintf (stderr, "  algorithm %d not available in fips mode\n",
		     algos[i]);
          continue;
        }
      if (verbose)
	fprintf (stderr, "  checking %s\n",
		 gcry_cipher_algo_name (algos2[i]));

      check_one_cipher (algos2[i], GCRY_CIPHER_MODE_STREAM, 0);
    }
  /* we have now run all cipher's selftests */

  if (verbose)
    fprintf (stderr, "Completed Cipher checks.\n");

  /* TODO: add some extra encryption to test the higher level functions */
}


static void
check_cipher_modes(void)
{
  if (verbose)
    fprintf (stderr, "Starting Cipher Mode checks.\n");

  check_aes128_cbc_cts_cipher ();
  check_cbc_mac_cipher ();
  check_ctr_cipher ();
  check_cfb_cipher ();
  check_ofb_cipher ();
  check_ccm_cipher ();
  check_gcm_cipher ();
  check_stream_cipher ();
  check_stream_cipher_large_block ();

  if (verbose)
    fprintf (stderr, "Completed Cipher Mode checks.\n");
}

static void
check_one_md (int algo, const char *data, int len, const char *expect)
{
  gcry_md_hd_t hd, hd2;
  unsigned char *p;
  int mdlen;
  int i;
  gcry_error_t err = 0;

  err = gcry_md_open (&hd, algo, 0);
  if (err)
    {
      fail ("algo %d, gcry_md_open failed: %s\n", algo, gpg_strerror (err));
      return;
    }

  mdlen = gcry_md_get_algo_dlen (algo);
  if (mdlen < 1 || mdlen > 500)
    {
      fail ("algo %d, gcry_md_get_algo_dlen failed: %d\n", algo, mdlen);
      return;
    }

  if (*data == '!' && !data[1])
    {				/* hash one million times a "a" */
      char aaa[1000];

      /* Write in odd size chunks so that we test the buffering.  */
      memset (aaa, 'a', 1000);
      for (i = 0; i < 1000; i++)
        gcry_md_write (hd, aaa, 1000);
    }
  else
    gcry_md_write (hd, data, len);

  err = gcry_md_copy (&hd2, hd);
  if (err)
    {
      fail ("algo %d, gcry_md_copy failed: %s\n", algo, gpg_strerror (err));
    }

  gcry_md_close (hd);

  p = gcry_md_read (hd2, algo);

  if (memcmp (p, expect, mdlen))
    {
      printf ("computed: ");
      for (i = 0; i < mdlen; i++)
	printf ("%02x ", p[i] & 0xFF);
      printf ("\nexpected: ");
      for (i = 0; i < mdlen; i++)
	printf ("%02x ", expect[i] & 0xFF);
      printf ("\n");

      fail ("algo %d, digest mismatch\n", algo);
    }

  gcry_md_close (hd2);
}


static void
check_one_md_multi (int algo, const char *data, int len, const char *expect)
{
  gpg_error_t err;
  gcry_buffer_t iov[3];
  int iovcnt;
  char digest[64];
  int mdlen;
  int i;

  mdlen = gcry_md_get_algo_dlen (algo);
  if (mdlen < 1 || mdlen > 64)
    {
      fail ("check_one_md_multi: algo %d, gcry_md_get_algo_dlen failed: %d\n",
            algo, mdlen);
      return;
    }

  if (*data == '!' && !data[1])
    return;  /* We can't do that here.  */

  memset (iov, 0, sizeof iov);

  iov[0].data = (void*)data;
  if (len)
    {
      iov[0].len = 1;
      len--;
      data++;
    }
  iovcnt = 1;
  if (len >= 4)
    {
      iov[iovcnt].data = (void*)data;
      iov[iovcnt].len = 4;
      iovcnt++;
      data += 4;
      len  -= 4;
    }
  iov[iovcnt].data = (void*)data;
  iov[iovcnt].len = len;
  iovcnt++;
  assert (iovcnt <= DIM (iov));

  err = gcry_md_hash_buffers (algo, 0, digest, iov, iovcnt);
  if (err)
    {
      fail ("check_one_md_multi: algo %d, gcry_hash_buffers failed: %s\n",
            algo, gpg_strerror (err));
      return;
    }
  if (memcmp (digest, expect, mdlen))
    {
      printf ("computed: ");
      for (i = 0; i < mdlen; i++)
	printf ("%02x ", digest[i] & 0xFF);
      printf ("\nexpected: ");
      for (i = 0; i < mdlen; i++)
	printf ("%02x ", expect[i] & 0xFF);
      printf ("\n");

      fail ("check_one_md_multi: algo %d, digest mismatch\n", algo);
    }
}


static void
check_digests (void)
{
  static const struct algos
  {
    int md;
    const char *data;
    const char *expect;
  } algos[] =
    {
      { GCRY_MD_MD4, "",
	"\x31\xD6\xCF\xE0\xD1\x6A\xE9\x31\xB7\x3C\x59\xD7\xE0\xC0\x89\xC0" },
      { GCRY_MD_MD4, "a",
	"\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24" },
      {	GCRY_MD_MD4, "message digest",
	"\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b" },
      {	GCRY_MD_MD5, "",
	"\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\x09\x98\xEC\xF8\x42\x7E" },
      {	GCRY_MD_MD5, "a",
	"\x0C\xC1\x75\xB9\xC0\xF1\xB6\xA8\x31\xC3\x99\xE2\x69\x77\x26\x61" },
      { GCRY_MD_MD5, "abc",
	"\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72" },
      { GCRY_MD_MD5, "message digest",
	"\xF9\x6B\x69\x7D\x7C\xB7\x93\x8D\x52\x5A\x2F\x31\xAA\xF1\x61\xD0" },
      { GCRY_MD_SHA1, "abc",
	"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E"
	"\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D" },
      {	GCRY_MD_SHA1,
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE"
	"\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1" },
      { GCRY_MD_SHA1, "!" /* kludge for "a"*1000000 */ ,
	"\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E"
	"\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F" },
      /* From RFC3874 */
      {	GCRY_MD_SHA224, "abc",
	"\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2\x55\xb3"
	"\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7" },
      {	GCRY_MD_SHA224,
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"\x75\x38\x8b\x16\x51\x27\x76\xcc\x5d\xba\x5d\xa1\xfd\x89\x01\x50"
	"\xb0\xc6\x45\x5c\xb4\xf5\x8b\x19\x52\x52\x25\x25" },
      {	GCRY_MD_SHA224, "!",
	"\x20\x79\x46\x55\x98\x0c\x91\xd8\xbb\xb4\xc1\xea\x97\x61\x8a\x4b"
	"\xf0\x3f\x42\x58\x19\x48\xb2\xee\x4e\xe7\xad\x67" },
      {	GCRY_MD_SHA256, "abc",
	"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
	"\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" },
      {	GCRY_MD_SHA256,
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
	"\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
      {	GCRY_MD_SHA256, "!",
	"\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67"
	"\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0" },
      {	GCRY_MD_SHA384, "abc",
	"\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07"
	"\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
	"\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7" },
      {	GCRY_MD_SHA512, "abc",
	"\xDD\xAF\x35\xA1\x93\x61\x7A\xBA\xCC\x41\x73\x49\xAE\x20\x41\x31"
	"\x12\xE6\xFA\x4E\x89\xA9\x7E\xA2\x0A\x9E\xEE\xE6\x4B\x55\xD3\x9A"
	"\x21\x92\x99\x2A\x27\x4F\xC1\xA8\x36\xBA\x3C\x23\xA3\xFE\xEB\xBD"
	"\x45\x4D\x44\x23\x64\x3C\xE8\x0E\x2A\x9A\xC9\x4F\xA5\x4C\xA4\x9F" },
      {	GCRY_MD_RMD160, "",
	"\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28"
	"\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31" },
      {	GCRY_MD_RMD160, "a",
	"\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae"
	"\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe" },
      {	GCRY_MD_RMD160, "abc",
	"\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04"
	"\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc" },
      {	GCRY_MD_RMD160, "message digest",
	"\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8"
	"\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36" },
      {	GCRY_MD_CRC32, "", "\x00\x00\x00\x00" },
      {	GCRY_MD_CRC32, "foo", "\x8c\x73\x65\x21" },
      { GCRY_MD_CRC32_RFC1510, "", "\x00\x00\x00\x00" },
      {	GCRY_MD_CRC32_RFC1510, "foo", "\x73\x32\xbc\x33" },
      {	GCRY_MD_CRC32_RFC1510, "test0123456789", "\xb8\x3e\x88\xd6" },
      {	GCRY_MD_CRC32_RFC1510, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
	"\xe3\x41\x80\xf7" },
#if 0
      {	GCRY_MD_CRC32_RFC1510, "\x80\x00", "\x3b\x83\x98\x4b" },
      {	GCRY_MD_CRC32_RFC1510, "\x00\x08", "\x0e\xdb\x88\x32" },
      {	GCRY_MD_CRC32_RFC1510, "\x00\x80", "\xed\xb8\x83\x20" },
#endif
      {	GCRY_MD_CRC32_RFC1510, "\x80", "\xed\xb8\x83\x20" },
#if 0
      {	GCRY_MD_CRC32_RFC1510, "\x80\x00\x00\x00", "\xed\x59\xb6\x3b" },
      {	GCRY_MD_CRC32_RFC1510, "\x00\x00\x00\x01", "\x77\x07\x30\x96" },
#endif
      {	GCRY_MD_CRC24_RFC2440, "", "\xb7\x04\xce" },
      {	GCRY_MD_CRC24_RFC2440, "foo", "\x4f\xc2\x55" },

      {	GCRY_MD_TIGER, "",
	"\x24\xF0\x13\x0C\x63\xAC\x93\x32\x16\x16\x6E\x76"
	"\xB1\xBB\x92\x5F\xF3\x73\xDE\x2D\x49\x58\x4E\x7A" },
      {	GCRY_MD_TIGER, "abc",
	"\xF2\x58\xC1\xE8\x84\x14\xAB\x2A\x52\x7A\xB5\x41"
	"\xFF\xC5\xB8\xBF\x93\x5F\x7B\x95\x1C\x13\x29\x51" },
      {	GCRY_MD_TIGER, "Tiger",
	"\x9F\x00\xF5\x99\x07\x23\x00\xDD\x27\x6A\xBB\x38"
	"\xC8\xEB\x6D\xEC\x37\x79\x0C\x11\x6F\x9D\x2B\xDF" },
      {	GCRY_MD_TIGER, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"
	"hijklmnopqrstuvwxyz0123456789+-",
	"\x87\xFB\x2A\x90\x83\x85\x1C\xF7\x47\x0D\x2C\xF8"
	"\x10\xE6\xDF\x9E\xB5\x86\x44\x50\x34\xA5\xA3\x86" },
      {	GCRY_MD_TIGER, "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdef"
	"ghijklmnopqrstuvwxyz+0123456789",
	"\x46\x7D\xB8\x08\x63\xEB\xCE\x48\x8D\xF1\xCD\x12"
	"\x61\x65\x5D\xE9\x57\x89\x65\x65\x97\x5F\x91\x97" },
      {	GCRY_MD_TIGER, "Tiger - A Fast New Hash Function, "
	"by Ross Anderson and Eli Biham",
	"\x0C\x41\x0A\x04\x29\x68\x86\x8A\x16\x71\xDA\x5A"
	"\x3F\xD2\x9A\x72\x5E\xC1\xE4\x57\xD3\xCD\xB3\x03" },
      {	GCRY_MD_TIGER, "Tiger - A Fast New Hash Function, "
	"by Ross Anderson and Eli Biham, proceedings of Fa"
	"st Software Encryption 3, Cambridge.",
	"\xEB\xF5\x91\xD5\xAF\xA6\x55\xCE\x7F\x22\x89\x4F"
	"\xF8\x7F\x54\xAC\x89\xC8\x11\xB6\xB0\xDA\x31\x93" },
      {	GCRY_MD_TIGER, "Tiger - A Fast New Hash Function, "
	"by Ross Anderson and Eli Biham, proceedings of Fa"
	"st Software Encryption 3, Cambridge, 1996.",
	"\x3D\x9A\xEB\x03\xD1\xBD\x1A\x63\x57\xB2\x77\x4D"
	"\xFD\x6D\x5B\x24\xDD\x68\x15\x1D\x50\x39\x74\xFC" },
      {	GCRY_MD_TIGER, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
	"ijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRS"
	"TUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
	"\x00\xB8\x3E\xB4\xE5\x34\x40\xC5\x76\xAC\x6A\xAE"
	"\xE0\xA7\x48\x58\x25\xFD\x15\xE7\x0A\x59\xFF\xE4" },

      {	GCRY_MD_TIGER1, "",
        "\x32\x93\xAC\x63\x0C\x13\xF0\x24\x5F\x92\xBB\xB1"
        "\x76\x6E\x16\x16\x7A\x4E\x58\x49\x2D\xDE\x73\xF3" },
      {	GCRY_MD_TIGER1, "a",
	"\x77\xBE\xFB\xEF\x2E\x7E\xF8\xAB\x2E\xC8\xF9\x3B"
        "\xF5\x87\xA7\xFC\x61\x3E\x24\x7F\x5F\x24\x78\x09" },
      {	GCRY_MD_TIGER1, "abc",
        "\x2A\xAB\x14\x84\xE8\xC1\x58\xF2\xBF\xB8\xC5\xFF"
        "\x41\xB5\x7A\x52\x51\x29\x13\x1C\x95\x7B\x5F\x93" },
      {	GCRY_MD_TIGER1, "message digest",
	"\xD9\x81\xF8\xCB\x78\x20\x1A\x95\x0D\xCF\x30\x48"
        "\x75\x1E\x44\x1C\x51\x7F\xCA\x1A\xA5\x5A\x29\xF6" },
      {	GCRY_MD_TIGER1, "abcdefghijklmnopqrstuvwxyz",
	"\x17\x14\xA4\x72\xEE\xE5\x7D\x30\x04\x04\x12\xBF"
        "\xCC\x55\x03\x2A\x0B\x11\x60\x2F\xF3\x7B\xEE\xE9" },
      {	GCRY_MD_TIGER1,
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"\x0F\x7B\xF9\xA1\x9B\x9C\x58\xF2\xB7\x61\x0D\xF7"
        "\xE8\x4F\x0A\xC3\xA7\x1C\x63\x1E\x7B\x53\xF7\x8E" },
      {	GCRY_MD_TIGER1,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz" "0123456789",
        "\x8D\xCE\xA6\x80\xA1\x75\x83\xEE\x50\x2B\xA3\x8A"
        "\x3C\x36\x86\x51\x89\x0F\xFB\xCC\xDC\x49\xA8\xCC" },
      {	GCRY_MD_TIGER1,
        "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890",
        "\x1C\x14\x79\x55\x29\xFD\x9F\x20\x7A\x95\x8F\x84"
        "\xC5\x2F\x11\xE8\x87\xFA\x0C\xAB\xDF\xD9\x1B\xFD" },
      {	GCRY_MD_TIGER1, "!",
	"\x6D\xB0\xE2\x72\x9C\xBE\xAD\x93\xD7\x15\xC6\xA7"
        "\xD3\x63\x02\xE9\xB3\xCE\xE0\xD2\xBC\x31\x4B\x41" },

      {	GCRY_MD_TIGER2, "",
        "\x44\x41\xBE\x75\xF6\x01\x87\x73\xC2\x06\xC2\x27"
        "\x45\x37\x4B\x92\x4A\xA8\x31\x3F\xEF\x91\x9F\x41" },
      {	GCRY_MD_TIGER2, "a",
        "\x67\xE6\xAE\x8E\x9E\x96\x89\x99\xF7\x0A\x23\xE7"
        "\x2A\xEA\xA9\x25\x1C\xBC\x7C\x78\xA7\x91\x66\x36" },
      {	GCRY_MD_TIGER2, "abc",
        "\xF6\x8D\x7B\xC5\xAF\x4B\x43\xA0\x6E\x04\x8D\x78"
        "\x29\x56\x0D\x4A\x94\x15\x65\x8B\xB0\xB1\xF3\xBF" },
      {	GCRY_MD_TIGER2, "message digest",
        "\xE2\x94\x19\xA1\xB5\xFA\x25\x9D\xE8\x00\x5E\x7D"
        "\xE7\x50\x78\xEA\x81\xA5\x42\xEF\x25\x52\x46\x2D" },
      {	GCRY_MD_TIGER2, "abcdefghijklmnopqrstuvwxyz",
        "\xF5\xB6\xB6\xA7\x8C\x40\x5C\x85\x47\xE9\x1C\xD8"
        "\x62\x4C\xB8\xBE\x83\xFC\x80\x4A\x47\x44\x88\xFD" },
      {	GCRY_MD_TIGER2,
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "\xA6\x73\x7F\x39\x97\xE8\xFB\xB6\x3D\x20\xD2\xDF"
        "\x88\xF8\x63\x76\xB5\xFE\x2D\x5C\xE3\x66\x46\xA9" },
      {	GCRY_MD_TIGER2,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz" "0123456789",
        "\xEA\x9A\xB6\x22\x8C\xEE\x7B\x51\xB7\x75\x44\xFC"
        "\xA6\x06\x6C\x8C\xBB\x5B\xBA\xE6\x31\x95\x05\xCD" },
      {	GCRY_MD_TIGER2,
        "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890",
        "\xD8\x52\x78\x11\x53\x29\xEB\xAA\x0E\xEC\x85\xEC"
        "\xDC\x53\x96\xFD\xA8\xAA\x3A\x58\x20\x94\x2F\xFF" },
      {	GCRY_MD_TIGER2, "!",
        "\xE0\x68\x28\x1F\x06\x0F\x55\x16\x28\xCC\x57\x15"
        "\xB9\xD0\x22\x67\x96\x91\x4D\x45\xF7\x71\x7C\xF4" },

      { GCRY_MD_WHIRLPOOL, "",
	"\x19\xFA\x61\xD7\x55\x22\xA4\x66\x9B\x44\xE3\x9C\x1D\x2E\x17\x26"
	"\xC5\x30\x23\x21\x30\xD4\x07\xF8\x9A\xFE\xE0\x96\x49\x97\xF7\xA7"
	"\x3E\x83\xBE\x69\x8B\x28\x8F\xEB\xCF\x88\xE3\xE0\x3C\x4F\x07\x57"
	"\xEA\x89\x64\xE5\x9B\x63\xD9\x37\x08\xB1\x38\xCC\x42\xA6\x6E\xB3" },
      { GCRY_MD_WHIRLPOOL, "a",
	"\x8A\xCA\x26\x02\x79\x2A\xEC\x6F\x11\xA6\x72\x06\x53\x1F\xB7\xD7"
	"\xF0\xDF\xF5\x94\x13\x14\x5E\x69\x73\xC4\x50\x01\xD0\x08\x7B\x42"
	"\xD1\x1B\xC6\x45\x41\x3A\xEF\xF6\x3A\x42\x39\x1A\x39\x14\x5A\x59"
	"\x1A\x92\x20\x0D\x56\x01\x95\xE5\x3B\x47\x85\x84\xFD\xAE\x23\x1A" },
      { GCRY_MD_WHIRLPOOL, "a",
	"\x8A\xCA\x26\x02\x79\x2A\xEC\x6F\x11\xA6\x72\x06\x53\x1F\xB7\xD7"
	"\xF0\xDF\xF5\x94\x13\x14\x5E\x69\x73\xC4\x50\x01\xD0\x08\x7B\x42"
	"\xD1\x1B\xC6\x45\x41\x3A\xEF\xF6\x3A\x42\x39\x1A\x39\x14\x5A\x59"
	"\x1A\x92\x20\x0D\x56\x01\x95\xE5\x3B\x47\x85\x84\xFD\xAE\x23\x1A" },
      { GCRY_MD_WHIRLPOOL,
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"\xDC\x37\xE0\x08\xCF\x9E\xE6\x9B\xF1\x1F\x00\xED\x9A\xBA\x26\x90"
	"\x1D\xD7\xC2\x8C\xDE\xC0\x66\xCC\x6A\xF4\x2E\x40\xF8\x2F\x3A\x1E"
	"\x08\xEB\xA2\x66\x29\x12\x9D\x8F\xB7\xCB\x57\x21\x1B\x92\x81\xA6"
	"\x55\x17\xCC\x87\x9D\x7B\x96\x21\x42\xC6\x5F\x5A\x7A\xF0\x14\x67" },
      { GCRY_MD_WHIRLPOOL,
        "!",
        "\x0C\x99\x00\x5B\xEB\x57\xEF\xF5\x0A\x7C\xF0\x05\x56\x0D\xDF\x5D"
        "\x29\x05\x7F\xD8\x6B\x20\xBF\xD6\x2D\xEC\xA0\xF1\xCC\xEA\x4A\xF5"
        "\x1F\xC1\x54\x90\xED\xDC\x47\xAF\x32\xBB\x2B\x66\xC3\x4F\xF9\xAD"
        "\x8C\x60\x08\xAD\x67\x7F\x77\x12\x69\x53\xB2\x26\xE4\xED\x8B\x01" },
#ifdef USE_GOST_R_3411_94
      { GCRY_MD_GOSTR3411_94,
	"This is message, length=32 bytes",
	"\xB1\xC4\x66\xD3\x75\x19\xB8\x2E\x83\x19\x81\x9F\xF3\x25\x95\xE0"
	"\x47\xA2\x8C\xB6\xF8\x3E\xFF\x1C\x69\x16\xA8\x15\xA6\x37\xFF\xFA" },
      { GCRY_MD_GOSTR3411_94,
	"Suppose the original message has length = 50 bytes",
	"\x47\x1A\xBA\x57\xA6\x0A\x77\x0D\x3A\x76\x13\x06\x35\xC1\xFB\xEA"
	"\x4E\xF1\x4D\xE5\x1F\x78\xB4\xAE\x57\xDD\x89\x3B\x62\xF5\x52\x08" },
      { GCRY_MD_GOSTR3411_94,
	"",
	"\xCE\x85\xB9\x9C\xC4\x67\x52\xFF\xFE\xE3\x5C\xAB\x9A\x7B\x02\x78"
	"\xAB\xB4\xC2\xD2\x05\x5C\xFF\x68\x5A\xF4\x91\x2C\x49\x49\x0F\x8D" },
      { GCRY_MD_GOSTR3411_94,
	"!",
	"\x5C\x00\xCC\xC2\x73\x4C\xDD\x33\x32\xD3\xD4\x74\x95\x76\xE3\xC1"
	"\xA7\xDB\xAF\x0E\x7E\xA7\x4E\x9F\xA6\x02\x41\x3C\x90\xA1\x29\xFA" },
#endif
#ifdef USE_GOST_R_3411_12
      { GCRY_MD_STRIBOG512,
        "012345678901234567890123456789012345678901234567890123456789012",
        "\x1b\x54\xd0\x1a\x4a\xf5\xb9\xd5\xcc\x3d\x86\xd6\x8d\x28\x54\x62"
        "\xb1\x9a\xbc\x24\x75\x22\x2f\x35\xc0\x85\x12\x2b\xe4\xba\x1f\xfa"
        "\x00\xad\x30\xf8\x76\x7b\x3a\x82\x38\x4c\x65\x74\xf0\x24\xc3\x11"
        "\xe2\xa4\x81\x33\x2b\x08\xef\x7f\x41\x79\x78\x91\xc1\x64\x6f\x48" },
      { GCRY_MD_STRIBOG256,
        "012345678901234567890123456789012345678901234567890123456789012",
        "\x9d\x15\x1e\xef\xd8\x59\x0b\x89\xda\xa6\xba\x6c\xb7\x4a\xf9\x27"
        "\x5d\xd0\x51\x02\x6b\xb1\x49\xa4\x52\xfd\x84\xe5\xe5\x7b\x55\x00" },
      { GCRY_MD_STRIBOG512,
        "\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
        "\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
        "\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
        "\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
        "\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
        "\x1e\x88\xe6\x22\x26\xbf\xca\x6f\x99\x94\xf1\xf2\xd5\x15\x69\xe0"
        "\xda\xf8\x47\x5a\x3b\x0f\xe6\x1a\x53\x00\xee\xe4\x6d\x96\x13\x76"
        "\x03\x5f\xe8\x35\x49\xad\xa2\xb8\x62\x0f\xcd\x7c\x49\x6c\xe5\xb3"
        "\x3f\x0c\xb9\xdd\xdc\x2b\x64\x60\x14\x3b\x03\xda\xba\xc9\xfb\x28" },
      { GCRY_MD_STRIBOG256,
        "\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
        "\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
        "\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
        "\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
        "\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
        "\x9d\xd2\xfe\x4e\x90\x40\x9e\x5d\xa8\x7f\x53\x97\x6d\x74\x05\xb0"
        "\xc0\xca\xc6\x28\xfc\x66\x9a\x74\x1d\x50\x06\x3c\x55\x7e\x8f\x50" },
#endif
      {	0 }
    };
  gcry_error_t err;
  int i;

  if (verbose)
    fprintf (stderr, "Starting hash checks.\n");

  for (i = 0; algos[i].md; i++)
    {
      if ((gcry_md_test_algo (algos[i].md) || algos[i].md == GCRY_MD_MD5)
          && in_fips_mode)
        {
          if (verbose)
            fprintf (stderr, "  algorithm %d not available in fips mode\n",
		     algos[i].md);
          continue;
        }
      if (verbose)
	fprintf (stderr, "  checking %s [%i] for length %d\n",
		 gcry_md_algo_name (algos[i].md),
		 algos[i].md,
                 !strcmp (algos[i].data, "!")?
                 1000000 : (int)strlen(algos[i].data));

      check_one_md (algos[i].md, algos[i].data, strlen (algos[i].data),
		    algos[i].expect);
      check_one_md_multi (algos[i].md, algos[i].data, strlen (algos[i].data),
                          algos[i].expect);
    }

  /* Check the Whirlpool bug emulation.  */
  if (!gcry_md_test_algo (GCRY_MD_WHIRLPOOL) && !in_fips_mode)
    {
      static const char expect[] =
        "\x35\x28\xd6\x4c\x56\x2c\x55\x2e\x3b\x91\x93\x95\x7b\xdd\xcc\x6e"
        "\x6f\xb7\xbf\x76\x22\x9c\xc6\x23\xda\x3e\x09\x9b\x36\xe8\x6d\x76"
        "\x2f\x94\x3b\x0c\x63\xa0\xba\xa3\x4d\x66\x71\xe6\x5d\x26\x67\x28"
        "\x36\x1f\x0e\x1a\x40\xf0\xce\x83\x50\x90\x1f\xfa\x3f\xed\x6f\xfd";
      gcry_md_hd_t hd;
      int algo = GCRY_MD_WHIRLPOOL;
      unsigned char *p;
      int mdlen;

      err = gcry_md_open (&hd, GCRY_MD_WHIRLPOOL, GCRY_MD_FLAG_BUGEMU1);
      if (err)
        {
          fail ("algo %d, gcry_md_open failed: %s\n", algo, gpg_strerror (err));
          goto leave;
        }

      mdlen = gcry_md_get_algo_dlen (algo);
      if (mdlen < 1 || mdlen > 500)
        {
          fail ("algo %d, gcry_md_get_algo_dlen failed: %d\n", algo, mdlen);
          gcry_md_close (hd);
          goto leave;
        }

      /* Hash 62 byes in chunks.  */
      gcry_md_write (hd, "1234567890", 10);
      gcry_md_write (hd, "1234567890123456789012345678901234567890123456789012",
                     52);

      p = gcry_md_read (hd, algo);

      if (memcmp (p, expect, mdlen))
        {
          printf ("computed: ");
          for (i = 0; i < mdlen; i++)
            printf ("%02x ", p[i] & 0xFF);
          printf ("\nexpected: ");
          for (i = 0; i < mdlen; i++)
            printf ("%02x ", expect[i] & 0xFF);
          printf ("\n");

          fail ("algo %d, digest mismatch\n", algo);
        }

      gcry_md_close (hd);
    }

 leave:
  if (verbose)
    fprintf (stderr, "Completed hash checks.\n");
}

static void
check_one_hmac (int algo, const char *data, int datalen,
		const char *key, int keylen, const char *expect)
{
  gcry_md_hd_t hd, hd2;
  unsigned char *p;
  int mdlen;
  int i;
  gcry_error_t err = 0;

  err = gcry_md_open (&hd, algo, GCRY_MD_FLAG_HMAC);
  if (err)
    {
      fail ("algo %d, gcry_md_open failed: %s\n", algo, gpg_strerror (err));
      return;
    }

  mdlen = gcry_md_get_algo_dlen (algo);
  if (mdlen < 1 || mdlen > 500)
    {
      fail ("algo %d, gcry_md_get_algo_dlen failed: %d\n", algo, mdlen);
      return;
    }

  gcry_md_setkey( hd, key, keylen );

  gcry_md_write (hd, data, datalen);

  err = gcry_md_copy (&hd2, hd);
  if (err)
    {
      fail ("algo %d, gcry_md_copy failed: %s\n", algo, gpg_strerror (err));
    }

  gcry_md_close (hd);

  p = gcry_md_read (hd2, algo);
  if (!p)
    fail("algo %d, hmac gcry_md_read failed\n", algo);

  if (memcmp (p, expect, mdlen))
    {
      printf ("computed: ");
      for (i = 0; i < mdlen; i++)
	printf ("%02x ", p[i] & 0xFF);
      printf ("\nexpected: ");
      for (i = 0; i < mdlen; i++)
	printf ("%02x ", expect[i] & 0xFF);
      printf ("\n");

      fail ("algo %d, digest mismatch\n", algo);
    }

  gcry_md_close (hd2);
}

static void
check_hmac (void)
{
  static const struct algos
  {
    int md;
    const char *data;
    const char *key;
    const char *expect;
  } algos[] =
    {
      { GCRY_MD_MD5, "what do ya want for nothing?", "Jefe",
	"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38" },
      { GCRY_MD_MD5,
	"Hi There",
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
	"\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d" },
      { GCRY_MD_MD5,
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd",
	"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
	"\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6" },
      { GCRY_MD_MD5,
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd",
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
	"\x69\x7e\xaf\x0a\xca\x3a\x3a\xea\x3a\x75\x16\x47\x46\xff\xaa\x79" },
      { GCRY_MD_MD5, "Test With Truncation",
	"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
	"\x56\x46\x1e\xf2\x34\x2e\xdc\x00\xf9\xba\xb9\x95\x69\x0e\xfd\x4c" },
      { GCRY_MD_MD5, "Test Using Larger Than Block-Size Key - Hash Key First",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa",
	"\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f\x0b\x62\xe6\xce\x61\xb9\xd0\xcd" },
      { GCRY_MD_MD5,
	"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa",
	"\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e", },
      { GCRY_MD_SHA256, "what do ya want for nothing?", "Jefe",
	"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a"
	"\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43" },
      { GCRY_MD_SHA256,
	"Hi There",
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	"\x0b\x0b\x0b",
	"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88"
	"\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7" },
      { GCRY_MD_SHA256,
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd",
	"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	"\xAA\xAA\xAA\xAA",
	"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7"
	"\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe" },
      { GCRY_MD_SHA256,
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd",
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
	"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08"
	"\x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b" },
      { GCRY_MD_SHA256,
	"Test Using Larger Than Block-Size Key - Hash Key First",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa",
	"\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f"
	"\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54" },
      { GCRY_MD_SHA256,
	"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa",
	"\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44"
	"\xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2" },
      { GCRY_MD_SHA224, "what do ya want for nothing?", "Jefe",
	"\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e\x6d\x0f"
	"\x8b\xbe\xa2\xa3\x9e\x61\x48\x00\x8f\xd0\x5e\x44" },
      { GCRY_MD_SHA224,
	"Hi There",
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	"\x0b\x0b\x0b",
	"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47"
	"\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22" },
      { GCRY_MD_SHA224,
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd",
	"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	"\xAA\xAA\xAA\xAA",
	"\x7f\xb3\xcb\x35\x88\xc6\xc1\xf6\xff\xa9\x69\x4d\x7d\x6a\xd2\x64"
	"\x93\x65\xb0\xc1\xf6\x5d\x69\xd1\xec\x83\x33\xea" },
      { GCRY_MD_SHA224,
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd",
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
	"\x6c\x11\x50\x68\x74\x01\x3c\xac\x6a\x2a\xbc\x1b\xb3\x82\x62"
	"\x7c\xec\x6a\x90\xd8\x6e\xfc\x01\x2d\xe7\xaf\xec\x5a" },
      { GCRY_MD_SHA224,
	"Test Using Larger Than Block-Size Key - Hash Key First",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa",
	"\x95\xe9\xa0\xdb\x96\x20\x95\xad\xae\xbe\x9b\x2d\x6f\x0d\xbc\xe2"
	"\xd4\x99\xf1\x12\xf2\xd2\xb7\x27\x3f\xa6\x87\x0e" },
      { GCRY_MD_SHA224,
	"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa",
	"\x3a\x85\x41\x66\xac\x5d\x9f\x02\x3f\x54\xd5\x17\xd0\xb3\x9d\xbd"
	"\x94\x67\x70\xdb\x9c\x2b\x95\xc9\xf6\xf5\x65\xd1" },
      { GCRY_MD_SHA384, "what do ya want for nothing?", "Jefe",
	"\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b"
	"\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e"
	"\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49" },
      { GCRY_MD_SHA384,
	"Hi There",
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	"\x0b\x0b\x0b",
	"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15"
	"\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea"
	"\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6" },
      { GCRY_MD_SHA384,
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd",
	"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	"\xAA\xAA\xAA\xAA",
	"\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f"
	"\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b"
	"\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27" },
      { GCRY_MD_SHA384,
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd",
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
	"\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7"
	"\x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e"
	"\x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb" },
      { GCRY_MD_SHA384,
	"Test Using Larger Than Block-Size Key - Hash Key First",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa",
	"\x4e\xce\x08\x44\x85\x81\x3e\x90\x88\xd2\xc6\x3a\x04\x1b\xc5\xb4"
	"\x4f\x9e\xf1\x01\x2a\x2b\x58\x8f\x3c\xd1\x1f\x05\x03\x3a\xc4\xc6"
	"\x0c\x2e\xf6\xab\x40\x30\xfe\x82\x96\x24\x8d\xf1\x63\xf4\x49\x52" },
      { GCRY_MD_SHA384,
	"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa",
	"\x66\x17\x17\x8e\x94\x1f\x02\x0d\x35\x1e\x2f\x25\x4e\x8f\xd3\x2c"
	"\x60\x24\x20\xfe\xb0\xb8\xfb\x9a\xdc\xce\xbb\x82\x46\x1e\x99\xc5"
	"\xa6\x78\xcc\x31\xe7\x99\x17\x6d\x38\x60\xe6\x11\x0c\x46\x52\x3e" },
      { GCRY_MD_SHA512, "what do ya want for nothing?", "Jefe",
	"\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3"
	"\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54"
	"\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd"
	"\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37" },
      { GCRY_MD_SHA512,
	"Hi There",
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	"\x0b\x0b\x0b",
	"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0"
	"\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde"
	"\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4"
	"\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54" },
      { GCRY_MD_SHA512,
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd",
	"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	"\xAA\xAA\xAA\xAA",
	"\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9"
	"\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39"
	"\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07"
	"\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb"  },
      { GCRY_MD_SHA512,
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd",
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
	"\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7"
	"\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb"
	"\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63"
	"\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd" },
      { GCRY_MD_SHA512,
	"Test Using Larger Than Block-Size Key - Hash Key First",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa",
	"\x80\xb2\x42\x63\xc7\xc1\xa3\xeb\xb7\x14\x93\xc1\xdd\x7b\xe8\xb4"
	"\x9b\x46\xd1\xf4\x1b\x4a\xee\xc1\x12\x1b\x01\x37\x83\xf8\xf3\x52"
	"\x6b\x56\xd0\x37\xe0\x5f\x25\x98\xbd\x0f\xd2\x21\x5d\x6a\x1e\x52"
	"\x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98" },
      { GCRY_MD_SHA512,
	"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa",
	"\xe3\x7b\x6a\x77\x5d\xc8\x7d\xba\xa4\xdf\xa9\xf9\x6e\x5e\x3f\xfd"
	"\xde\xbd\x71\xf8\x86\x72\x89\x86\x5d\xf5\xa3\x2d\x20\xcd\xc9\x44"
	"\xb6\x02\x2c\xac\x3c\x49\x82\xb1\x0d\x5e\xeb\x55\xc3\xe4\xde\x15"
	"\x13\x46\x76\xfb\x6d\xe0\x44\x60\x65\xc9\x74\x40\xfa\x8c\x6a\x58" },
      {	0 },
    };
  int i;

  if (verbose)
    fprintf (stderr, "Starting hashed MAC checks.\n");

  for (i = 0; algos[i].md; i++)
    {
      if ((gcry_md_test_algo (algos[i].md) || algos[i].md == GCRY_MD_MD5)
          && in_fips_mode)
        {
          if (verbose)
            fprintf (stderr, "  algorithm %d not available in fips mode\n",
		     algos[i].md);
          continue;
        }
      if (verbose)
	fprintf (stderr,
                 "  checking %s [%i] for %d byte key and %d byte data\n",
		 gcry_md_algo_name (algos[i].md),
		 algos[i].md,
		 (int)strlen(algos[i].key), (int)strlen(algos[i].data));

      check_one_hmac (algos[i].md, algos[i].data, strlen (algos[i].data),
		      algos[i].key, strlen(algos[i].key),
		      algos[i].expect);
    }

  if (verbose)
    fprintf (stderr, "Completed hashed MAC checks.\n");
}


static void
check_one_mac (int algo, const char *data, int datalen,
	       const char *key, int keylen, const char *iv, int ivlen,
	       const char *expect, int test_buffering)
{
  gcry_mac_hd_t hd;
  unsigned char *p;
  unsigned int maclen;
  size_t macoutlen;
  int i;
  gcry_error_t err = 0;

  err = gcry_mac_open (&hd, algo, 0, NULL);
  if (err)
    {
      fail ("algo %d, gcry_mac_open failed: %s\n", algo, gpg_strerror (err));
      return;
    }

  maclen = gcry_mac_get_algo_maclen (algo);
  if (maclen < 1 || maclen > 500)
    {
      fail ("algo %d, gcry_mac_get_algo_maclen failed: %d\n", algo, maclen);
      return;
    }

  p = malloc(maclen);
  if (!p)
    {
      fail ("algo %d, could not malloc %d bytes\n", algo, maclen);
      return;
    }

  err = gcry_mac_setkey (hd, key, keylen);
  if (err)
    fail("algo %d, mac gcry_mac_setkey failed: %s\n", algo, gpg_strerror (err));
  if (err)
    goto out;

  if (ivlen && iv)
    {
      err = gcry_mac_setiv (hd, iv, ivlen);
      if (err)
        fail("algo %d, mac gcry_mac_ivkey failed: %s\n", algo,
             gpg_strerror (err));
      if (err)
        goto out;
    }

  if (test_buffering)
    {
      for (i = 0; i < datalen; i++)
        {
          err = gcry_mac_write (hd, &data[i], 1);
          if (err)
            fail("algo %d, mac gcry_mac_write [buf-offset: %d] failed: %s\n",
                 algo, i, gpg_strerror (err));
          if (err)
            goto out;
        }
    }
  else
    {
      err = gcry_mac_write (hd, data, datalen);
      if (err)
        fail("algo %d, mac gcry_mac_write failed: %s\n", algo, gpg_strerror (err));
      if (err)
        goto out;
    }

  err = gcry_mac_verify (hd, expect, maclen);
  if (err)
    fail("algo %d, mac gcry_mac_verify failed: %s\n", algo, gpg_strerror (err));
  if (err)
    goto out;

  macoutlen = maclen;
  err = gcry_mac_read (hd, p, &macoutlen);
  if (err)
    fail("algo %d, mac gcry_mac_read failed: %s\n", algo, gpg_strerror (err));
  if (err)
    goto out;

  if (memcmp (p, expect, maclen))
    {
      printf ("computed: ");
      for (i = 0; i < maclen; i++)
	printf ("%02x ", p[i] & 0xFF);
      printf ("\nexpected: ");
      for (i = 0; i < maclen; i++)
	printf ("%02x ", expect[i] & 0xFF);
      printf ("\n");

      fail ("algo %d, digest mismatch\n", algo);
    }
  if (err)
    goto out;

out:
  free (p);
  gcry_mac_close (hd);
}

static void
check_mac (void)
{
  static const struct algos
  {
    int algo;
    const char *data;
    const char *key;
    const char *expect;
    const char *iv;
  } algos[] =
    {
      { GCRY_MAC_HMAC_MD5, "what do ya want for nothing?", "Jefe",
        "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38" },
      { GCRY_MAC_HMAC_MD5,
        "Hi There",
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d" },
      { GCRY_MAC_HMAC_MD5,
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
        "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6" },
      { GCRY_MAC_HMAC_MD5,
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd",
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
        "\x69\x7e\xaf\x0a\xca\x3a\x3a\xea\x3a\x75\x16\x47\x46\xff\xaa\x79" },
      { GCRY_MAC_HMAC_MD5, "Test With Truncation",
        "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
        "\x56\x46\x1e\xf2\x34\x2e\xdc\x00\xf9\xba\xb9\x95\x69\x0e\xfd\x4c" },
      { GCRY_MAC_HMAC_MD5, "Test Using Larger Than Block-Size Key - Hash Key First",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa",
        "\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f\x0b\x62\xe6\xce\x61\xb9\xd0\xcd" },
      { GCRY_MAC_HMAC_MD5,
        "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa",
        "\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e", },
      { GCRY_MAC_HMAC_SHA256, "what do ya want for nothing?", "Jefe",
        "\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a"
        "\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43" },
      { GCRY_MAC_HMAC_SHA256,
        "Hi There",
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b",
        "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88"
        "\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7" },
      { GCRY_MAC_HMAC_SHA256,
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        "\xAA\xAA\xAA\xAA",
        "\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7"
        "\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe" },
      { GCRY_MAC_HMAC_SHA256,
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd",
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
        "\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08"
        "\x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b" },
      { GCRY_MAC_HMAC_SHA256,
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
        "\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f"
        "\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54" },
      { GCRY_MAC_HMAC_SHA256,
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
        "\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44"
        "\xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2" },
      { GCRY_MAC_HMAC_SHA224, "what do ya want for nothing?", "Jefe",
        "\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e\x6d\x0f"
        "\x8b\xbe\xa2\xa3\x9e\x61\x48\x00\x8f\xd0\x5e\x44" },
      { GCRY_MAC_HMAC_SHA224,
        "Hi There",
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b",
        "\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47"
        "\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22" },
      { GCRY_MAC_HMAC_SHA224,
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        "\xAA\xAA\xAA\xAA",
        "\x7f\xb3\xcb\x35\x88\xc6\xc1\xf6\xff\xa9\x69\x4d\x7d\x6a\xd2\x64"
        "\x93\x65\xb0\xc1\xf6\x5d\x69\xd1\xec\x83\x33\xea" },
      { GCRY_MAC_HMAC_SHA224,
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd",
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
        "\x6c\x11\x50\x68\x74\x01\x3c\xac\x6a\x2a\xbc\x1b\xb3\x82\x62"
        "\x7c\xec\x6a\x90\xd8\x6e\xfc\x01\x2d\xe7\xaf\xec\x5a" },
      { GCRY_MAC_HMAC_SHA224,
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
        "\x95\xe9\xa0\xdb\x96\x20\x95\xad\xae\xbe\x9b\x2d\x6f\x0d\xbc\xe2"
        "\xd4\x99\xf1\x12\xf2\xd2\xb7\x27\x3f\xa6\x87\x0e" },
      { GCRY_MAC_HMAC_SHA224,
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
        "\x3a\x85\x41\x66\xac\x5d\x9f\x02\x3f\x54\xd5\x17\xd0\xb3\x9d\xbd"
        "\x94\x67\x70\xdb\x9c\x2b\x95\xc9\xf6\xf5\x65\xd1" },
      { GCRY_MAC_HMAC_SHA384, "what do ya want for nothing?", "Jefe",
        "\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b"
        "\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e"
        "\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49" },
      { GCRY_MAC_HMAC_SHA384,
        "Hi There",
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b",
        "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15"
        "\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea"
        "\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6" },
      { GCRY_MAC_HMAC_SHA384,
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        "\xAA\xAA\xAA\xAA",
        "\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f"
        "\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b"
        "\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27" },
      { GCRY_MAC_HMAC_SHA384,
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd",
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
        "\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7"
        "\x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e"
        "\x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb" },
      { GCRY_MAC_HMAC_SHA384,
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
        "\x4e\xce\x08\x44\x85\x81\x3e\x90\x88\xd2\xc6\x3a\x04\x1b\xc5\xb4"
        "\x4f\x9e\xf1\x01\x2a\x2b\x58\x8f\x3c\xd1\x1f\x05\x03\x3a\xc4\xc6"
        "\x0c\x2e\xf6\xab\x40\x30\xfe\x82\x96\x24\x8d\xf1\x63\xf4\x49\x52" },
      { GCRY_MAC_HMAC_SHA384,
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
        "\x66\x17\x17\x8e\x94\x1f\x02\x0d\x35\x1e\x2f\x25\x4e\x8f\xd3\x2c"
        "\x60\x24\x20\xfe\xb0\xb8\xfb\x9a\xdc\xce\xbb\x82\x46\x1e\x99\xc5"
        "\xa6\x78\xcc\x31\xe7\x99\x17\x6d\x38\x60\xe6\x11\x0c\x46\x52\x3e" },
      { GCRY_MAC_HMAC_SHA512, "what do ya want for nothing?", "Jefe",
        "\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3"
        "\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54"
        "\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd"
        "\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37" },
      { GCRY_MAC_HMAC_SHA512,
        "Hi There",
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b",
        "\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0"
        "\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde"
        "\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4"
        "\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54" },
      { GCRY_MAC_HMAC_SHA512,
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        "\xAA\xAA\xAA\xAA",
        "\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9"
        "\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39"
        "\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07"
        "\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb"  },
      { GCRY_MAC_HMAC_SHA512,
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd",
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
        "\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7"
        "\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb"
        "\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63"
        "\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd" },
      { GCRY_MAC_HMAC_SHA512,
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
        "\x80\xb2\x42\x63\xc7\xc1\xa3\xeb\xb7\x14\x93\xc1\xdd\x7b\xe8\xb4"
        "\x9b\x46\xd1\xf4\x1b\x4a\xee\xc1\x12\x1b\x01\x37\x83\xf8\xf3\x52"
        "\x6b\x56\xd0\x37\xe0\x5f\x25\x98\xbd\x0f\xd2\x21\x5d\x6a\x1e\x52"
        "\x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98" },
      { GCRY_MAC_HMAC_SHA512,
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
        "\xe3\x7b\x6a\x77\x5d\xc8\x7d\xba\xa4\xdf\xa9\xf9\x6e\x5e\x3f\xfd"
        "\xde\xbd\x71\xf8\x86\x72\x89\x86\x5d\xf5\xa3\x2d\x20\xcd\xc9\x44"
        "\xb6\x02\x2c\xac\x3c\x49\x82\xb1\x0d\x5e\xeb\x55\xc3\xe4\xde\x15"
        "\x13\x46\x76\xfb\x6d\xe0\x44\x60\x65\xc9\x74\x40\xfa\x8c\x6a\x58" },
      /* CMAC AES and DES test vectors from
         http://web.archive.org/web/20130930212819/http://csrc.nist.gov/publica\
         tions/nistpubs/800-38B/Updated_CMAC_Examples.pdf */
      { GCRY_MAC_CMAC_AES,
        "",
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\xbb\x1d\x69\x29\xe9\x59\x37\x28\x7f\xa3\x7d\x12\x9b\x75\x67\x46" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\x07\x0a\x16\xb4\x6b\x4d\x41\x44\xf7\x9b\xdd\x9d\xd0\x4a\x28\x7c" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11",
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\xdf\xa6\x67\x47\xde\x9a\xe6\x30\x30\xca\x32\x61\x14\x97\xc8\x27" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
        "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\x51\xf0\xbe\xbf\x7e\x3b\x9d\x92\xfc\x49\x74\x17\x79\x36\x3c\xfe" },
      { GCRY_MAC_CMAC_AES,
        "",
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
        "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\xd1\x7d\xdf\x46\xad\xaa\xcd\xe5\x31\xca\xc4\x83\xde\x7a\x93\x67" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
        "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\x9e\x99\xa7\xbf\x31\xe7\x10\x90\x06\x62\xf6\x5e\x61\x7c\x51\x84" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11",
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
        "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\x8a\x1d\xe5\xbe\x2e\xb3\x1a\xad\x08\x9a\x82\xe6\xee\x90\x8b\x0e" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
        "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
        "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\xa1\xd5\xdf\x0e\xed\x79\x0f\x79\x4d\x77\x58\x96\x59\xf3\x9a\x11" },
      { GCRY_MAC_CMAC_AES,
        "",
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\x02\x89\x62\xf6\x1b\x7b\xf8\x9e\xfc\x6b\x55\x1f\x46\x67\xd9\x83" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\x28\xa7\x02\x3f\x45\x2e\x8f\x82\xbd\x4b\xf2\x8d\x8c\x37\xc3\x5c" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11",
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\xaa\xf3\xd8\xf1\xde\x56\x40\xc2\x32\xf5\xb1\x69\xb9\xc9\x11\xe6" },
      { GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
        "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\xe1\x99\x21\x90\x54\x9f\x6e\xd5\x69\x6a\x2c\x05\x6c\x31\x54\x10" },
      { GCRY_MAC_CMAC_3DES,
        "",
        "\x8a\xa8\x3b\xf8\xcb\xda\x10\x62\x0b\xc1\xbf\x19\xfb\xb6\xcd\x58"
        "\xbc\x31\x3d\x4a\x37\x1c\xa8\xb5",
        "\xb7\xa6\x88\xe1\x22\xff\xaf\x95" },
      { GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96",
        "\x8a\xa8\x3b\xf8\xcb\xda\x10\x62\x0b\xc1\xbf\x19\xfb\xb6\xcd\x58"
        "\xbc\x31\x3d\x4a\x37\x1c\xa8\xb5",
        "\x8e\x8f\x29\x31\x36\x28\x37\x97" },
      { GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57",
        "\x8a\xa8\x3b\xf8\xcb\xda\x10\x62\x0b\xc1\xbf\x19\xfb\xb6\xcd\x58"
        "\xbc\x31\x3d\x4a\x37\x1c\xa8\xb5",
        "\x74\x3d\xdb\xe0\xce\x2d\xc2\xed" },
      { GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
        "\x8a\xa8\x3b\xf8\xcb\xda\x10\x62\x0b\xc1\xbf\x19\xfb\xb6\xcd\x58"
        "\xbc\x31\x3d\x4a\x37\x1c\xa8\xb5",
        "\x33\xe6\xb1\x09\x24\x00\xea\xe5" },
      { GCRY_MAC_CMAC_3DES,
        "",
        "\x4c\xf1\x51\x34\xa2\x85\x0d\xd5\x8a\x3d\x10\xba\x80\x57\x0d\x38"
        "\x4c\xf1\x51\x34\xa2\x85\x0d\xd5",
        "\xbd\x2e\xbf\x9a\x3b\xa0\x03\x61" },
      { GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96",
        "\x4c\xf1\x51\x34\xa2\x85\x0d\xd5\x8a\x3d\x10\xba\x80\x57\x0d\x38"
        "\x4c\xf1\x51\x34\xa2\x85\x0d\xd5",
        "\x4f\xf2\xab\x81\x3c\x53\xce\x83" },
      { GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57",
        "\x4c\xf1\x51\x34\xa2\x85\x0d\xd5\x8a\x3d\x10\xba\x80\x57\x0d\x38"
        "\x4c\xf1\x51\x34\xa2\x85\x0d\xd5",
        "\x62\xdd\x1b\x47\x19\x02\xbd\x4e" },
      { GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
        "\x4c\xf1\x51\x34\xa2\x85\x0d\xd5\x8a\x3d\x10\xba\x80\x57\x0d\x38"
        "\x4c\xf1\x51\x34\xa2\x85\x0d\xd5",
        "\x31\xb1\xe4\x31\xda\xbc\x4e\xb8" },
      /* CMAC Camellia test vectors from
         http://tools.ietf.org/html/draft-kato-ipsec-camellia-cmac96and128-05 */
      { GCRY_MAC_CMAC_CAMELLIA,
        "",
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\xba\x92\x57\x82\xaa\xa1\xf5\xd9\xa0\x0f\x89\x64\x80\x94\xfc\x71" },
      { GCRY_MAC_CMAC_CAMELLIA,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\x6d\x96\x28\x54\xa3\xb9\xfd\xa5\x6d\x7d\x45\xa9\x5e\xe1\x79\x93" },
      { GCRY_MAC_CMAC_CAMELLIA,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11",
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\x5c\x18\xd1\x19\xcc\xd6\x76\x61\x44\xac\x18\x66\x13\x1d\x9f\x22" },
      { GCRY_MAC_CMAC_CAMELLIA,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
        "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        "\xc2\x69\x9a\x6e\xba\x55\xce\x9d\x93\x9a\x8a\x4e\x19\x46\x6e\xe9" },
      /* http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip */
      { GCRY_MAC_GMAC_AES,
        "",
        "\x11\x75\x4c\xd7\x2a\xec\x30\x9b\xf5\x2f\x76\x87\x21\x2e\x89\x57",
        "\x25\x03\x27\xc6\x74\xaa\xf4\x77\xae\xf2\x67\x57\x48\xcf\x69\x71",
        "\x3c\x81\x9d\x9a\x9b\xed\x08\x76\x15\x03\x0b\x65" },
      { GCRY_MAC_GMAC_AES,
        "\x2b\x63\x26\x64\x29\x67\x4a\xb5\xe2\xea\xff\x63\x9c\x23\x14\x66"
        "\x2f\x92\x57\x4b\x29\x8f\x57\x7a\xcf\x7d\x6f\x99\x1a\x87\x92\x1f"
        "\xc2\x32\xea\xfc\xc7\xb1\x46\x48\x96\x63\x2d\x6c\x8a\xbe\x88\xc2"
        "\xcc\xa4\x04\xdb\xf8\x7c\x20\x6a\x19\xd3\x73\xed\x99\x50\x17\x34"
        "\x69\x13\x4d\x7c\x14\xc2\x84\x7d\xf2\x4a\x88\xc1\xc5\x3b\x4d\xe4"
        "\x9d\xb3\x66\x39\x2b\x6d\xc6\x51\x27\x6e",
        "\x0f\x3b\x17\xde\xae\x62\x13\x64\x55\x4a\xe5\x39\xdb\x09\xde\x11",
        "\xff\xb0\xbb\x6d\xfc\x23\x58\x75\x4f\x17\x78\x48\x5b\x59\x65\x7f",
        "\xa7\xf6\x07\x4c\xda\x56\x1c\xd2\xaa\x15\xba\x8c\x2f\xa6\x39\x42"
        "\x59\x3e\x7c\xcf\x45\xc2\x9a\x57\xda\xd8\xa6\xe2\xea\x63\x54\xce"
        "\x8a\xde\x39\xdd\xde\x4a\xc4\x5b\xbd\xc6\x63\xf0\xa5\x37\xc9\x48"
        "\x18\x23\x5a\x73\xd8\xa0\x8b\xd8\x98\xab\xd0\x99\xe1\x5c\x08\x8c"
        "\x6e\x21\x17\x5a\xf4\xe9\xa4\x99\x70\x12\x82\xed\x32\x81\x50\xa6"
        "\xd9\x90\xe8\xec\x87\x85\xce\x26\x1b\xe1\xb8\x3f\xd8\x59\x1e\x57"
        "\x76\x5f\x3d\xc1\x11\x3f\xd0\x2a\x40\xf5\x01\x6a\xd0\xd0\xed\xc4"
        "\x92\x9a\x02\xe0\x17\xb2\xc5\xf4\x18\xd2\x96\xab\xd6\xc2\xea\x2e" },
      { GCRY_MAC_GMAC_AES,
        "\x61\x14\x60\x11\x90\xf6\xef\x5e\x59\x23\x5d\xc0\x42\x8c\x09\xe3"
        "\x27\x0b\x19\xea",
        "\x15\xa4\x14\x46\x6a\x7f\x90\xea\x32\xbf\xd7\xf6\xe5\x8b\xfa\x06"
        "\xe9\x07\xfc\x41\x66\x89\xd9\x60\x39\x45\xd7\x94\x54\xd4\x23\x17",
        "\x19\x6e\x0e\x01\x0f\x08\x56\xf9\x82\xb4\x08\x92\x41\xd6\x24\x84",
        "\xab" },
      { GCRY_MAC_GMAC_AES,
        "\x8b\x5c\x12\x4b\xef\x6e\x2f\x0f\xe4\xd8\xc9\x5c\xd5\xfa\x4c\xf1",
        "\x41\xc5\xda\x86\x67\xef\x72\x52\x20\xff\xe3\x9a\xe0\xac\x59\x0a"
        "\xc9\xfc\xa7\x29\xab\x60\xad\xa0",
        "\x20\x4b\xdb\x1b\xd6\x21\x54\xbf\x08\x92\x2a\xaa\x54\xee\xd7\x05",
        "\x05\xad\x13\xa5\xe2\xc2\xab\x66\x7e\x1a\x6f\xbc" },
      { 0 },
    };
  int i;

  if (verbose)
    fprintf (stderr, "Starting MAC checks.\n");

  for (i = 0; algos[i].algo; i++)
    {
      if ((gcry_mac_test_algo (algos[i].algo)
	   || algos[i].algo == GCRY_MAC_HMAC_MD5) && in_fips_mode)
        {
          if (verbose)
            fprintf (stderr, "  algorithm %d not available in fips mode\n",
		     algos[i].algo);
          continue;
        }
      if (verbose)
	fprintf (stderr,
                 "  checking %s [%i] for %d byte key and %d byte data\n",
		 gcry_mac_algo_name (algos[i].algo),
		 algos[i].algo,
		 (int)strlen(algos[i].key), (int)strlen(algos[i].data));

      check_one_mac (algos[i].algo, algos[i].data, strlen (algos[i].data),
		     algos[i].key, strlen(algos[i].key), algos[i].iv,
		     algos[i].iv ? strlen(algos[i].iv) : 0,
		     algos[i].expect, 0);
      check_one_mac (algos[i].algo, algos[i].data, strlen (algos[i].data),
		     algos[i].key, strlen(algos[i].key), algos[i].iv,
		     algos[i].iv ? strlen(algos[i].iv) : 0,
		     algos[i].expect, 1);
    }

  if (verbose)
    fprintf (stderr, "Completed MAC checks.\n");
}

/* Check that the signature SIG matches the hash HASH. PKEY is the
   public key used for the verification. BADHASH is a hash value which
   should result in a bad signature status. */
static void
verify_one_signature (gcry_sexp_t pkey, gcry_sexp_t hash,
		      gcry_sexp_t badhash, gcry_sexp_t sig)
{
  gcry_error_t rc;

  rc = gcry_pk_verify (sig, hash, pkey);
  if (rc)
    fail ("gcry_pk_verify failed: %s\n", gpg_strerror (rc));
  rc = gcry_pk_verify (sig, badhash, pkey);
  if (gcry_err_code (rc) != GPG_ERR_BAD_SIGNATURE)
    fail ("gcry_pk_verify failed to detect a bad signature: %s\n",
	  gpg_strerror (rc));
}


/* Test the public key sign function using the private ket SKEY. PKEY
   is used for verification. */
static void
check_pubkey_sign (int n, gcry_sexp_t skey, gcry_sexp_t pkey, int algo)
{
  gcry_error_t rc;
  gcry_sexp_t sig, badhash, hash;
  int dataidx;
  static const char baddata[] =
    "(data\n (flags pkcs1)\n"
    " (hash sha1 #11223344556677889900AABBCCDDEEFF10203041#))\n";
  static const struct
  {
    const char *data;
    int algo;
    int expected_rc;
  } datas[] =
    {
      { "(data\n (flags pkcs1)\n"
	" (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
	GCRY_PK_RSA,
	0 },
      { "(data\n (flags oaep)\n"
	" (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
	0,
	GPG_ERR_CONFLICT },
      /* This test is to see whether hash algorithms not hard wired in
         pubkey.c are detected:  */
      { "(data\n (flags pkcs1)\n"
	" (hash oid.1.3.14.3.2.29 "
        "       #11223344556677889900AABBCCDDEEFF10203040#))\n",
	GCRY_PK_RSA,
	0 },
      {	"(data\n (flags )\n"
	" (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
	0,
	GPG_ERR_CONFLICT },
      {	"(data\n (flags pkcs1)\n"
	" (hash foo #11223344556677889900AABBCCDDEEFF10203040#))\n",
	GCRY_PK_RSA,
	GPG_ERR_DIGEST_ALGO },
      {	"(data\n (flags )\n" " (value #11223344556677889900AA#))\n",
	0,
	0 },
      {	"(data\n (flags )\n" " (value #0090223344556677889900AA#))\n",
	0,
	0 },
      { "(data\n (flags raw)\n" " (value #11223344556677889900AA#))\n",
	0,
	0 },
      {	"(data\n (flags pkcs1)\n"
	" (value #11223344556677889900AA#))\n",
	GCRY_PK_RSA,
	GPG_ERR_CONFLICT },
      { "(data\n (flags raw foo)\n"
	" (value #11223344556677889900AA#))\n",
	0,
	GPG_ERR_INV_FLAG },
      { "(data\n (flags pss)\n"
	" (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
	GCRY_PK_RSA,
	0 },
      { "(data\n (flags pss)\n"
	" (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#)\n"
        " (random-override #4253647587980912233445566778899019283747#))\n",
	GCRY_PK_RSA,
	0 },
      { NULL }
    };

  rc = gcry_sexp_sscan (&badhash, NULL, baddata, strlen (baddata));
  if (rc)
    die ("converting data failed: %s\n", gpg_strerror (rc));

  for (dataidx = 0; datas[dataidx].data; dataidx++)
    {
      if (datas[dataidx].algo && datas[dataidx].algo != algo)
	continue;

      if (verbose)
	fprintf (stderr, "  test %d, signature test %d (%s)\n",
                 n, dataidx, gcry_pk_algo_name (algo));

      rc = gcry_sexp_sscan (&hash, NULL, datas[dataidx].data,
			    strlen (datas[dataidx].data));
      if (rc)
	die ("converting data failed: %s\n", gpg_strerror (rc));

      rc = gcry_pk_sign (&sig, hash, skey);
      if (gcry_err_code (rc) != datas[dataidx].expected_rc)
	fail ("gcry_pk_sign failed: %s\n", gpg_strerror (rc));

      if (!rc)
	verify_one_signature (pkey, hash, badhash, sig);

      gcry_sexp_release (sig);
      sig = NULL;
      gcry_sexp_release (hash);
      hash = NULL;
    }

  gcry_sexp_release (badhash);
}


/* Test the public key sign function using the private ket SKEY. PKEY
   is used for verification.  This variant is only used for ECDSA.  */
static void
check_pubkey_sign_ecdsa (int n, gcry_sexp_t skey, gcry_sexp_t pkey)
{
  gcry_error_t rc;
  gcry_sexp_t sig, badhash, hash;
  unsigned int nbits;
  int dataidx;
  static const struct
  {
    unsigned int nbits;
    const char *data;
    int expected_rc;
    const char *baddata;
    int dummy;
  } datas[] =
    {
      { 192,
        "(data (flags raw)\n"
        " (value #00112233445566778899AABBCCDDEEFF0001020304050607#))",
        0,
        "(data (flags raw)\n"
        " (value #80112233445566778899AABBCCDDEEFF0001020304050607#))",
        0
      },
      { 256,
        "(data (flags raw)\n"
        " (value #00112233445566778899AABBCCDDEEFF"
        /* */    "000102030405060708090A0B0C0D0E0F#))",
        0,
        "(data (flags raw)\n"
        " (value #80112233445566778899AABBCCDDEEFF"
        /* */    "000102030405060708090A0B0C0D0E0F#))",
        0
      },
      { 256,
        "(data (flags raw)\n"
        " (hash sha256 #00112233445566778899AABBCCDDEEFF"
        /* */          "000102030405060708090A0B0C0D0E0F#))",
        0,
        "(data (flags raw)\n"
        " (hash sha256 #80112233445566778899AABBCCDDEEFF"
        /* */          "000102030405060708090A0B0C0D0E0F#))",
        0
      },
      { 256,
        "(data (flags gost)\n"
        " (value #00112233445566778899AABBCCDDEEFF"
        /* */    "000102030405060708090A0B0C0D0E0F#))",
        0,
        "(data (flags gost)\n"
        " (value #80112233445566778899AABBCCDDEEFF"
        /* */    "000102030405060708090A0B0C0D0E0F#))",
        0
      },
      { 512,
        "(data (flags gost)\n"
        " (value #00112233445566778899AABBCCDDEEFF"
        /* */    "000102030405060708090A0B0C0D0E0F"
        /* */    "000102030405060708090A0B0C0D0E0F"
        /* */    "000102030405060708090A0B0C0D0E0F#))",
        0,
        "(data (flags gost)\n"
        " (value #80112233445566778899AABBCCDDEEFF"
        /* */    "000102030405060708090A0B0C0D0E0F"
        /* */    "000102030405060708090A0B0C0D0E0F"
        /* */    "000102030405060708090A0B0C0D0E0F#))",
        0
      },
      { 0, NULL }
    };

  nbits = gcry_pk_get_nbits (skey);

  for (dataidx = 0; datas[dataidx].data; dataidx++)
    {
      if (datas[dataidx].nbits != nbits)
	continue;

      if (verbose)
	fprintf (stderr, "  test %d, signature test %d (%u bit ecdsa)\n",
                 n, dataidx, nbits);

      rc = gcry_sexp_sscan (&hash, NULL, datas[dataidx].data,
			    strlen (datas[dataidx].data));
      if (rc)
	die ("converting data failed: %s\n", gpg_strerror (rc));
      rc = gcry_sexp_sscan (&badhash, NULL, datas[dataidx].baddata,
                            strlen (datas[dataidx].baddata));
      if (rc)
        die ("converting data failed: %s\n", gpg_strerror (rc));

      rc = gcry_pk_sign (&sig, hash, skey);
      if (gcry_err_code (rc) != datas[dataidx].expected_rc)
	fail ("gcry_pk_sign failed: %s\n", gpg_strerror (rc));

      if (!rc && verbose > 1)
        show_sexp ("ECDSA signature:\n", sig);

      if (!rc)
        verify_one_signature (pkey, hash, badhash, sig);

      gcry_sexp_release (sig);
      sig = NULL;
      gcry_sexp_release (badhash);
      badhash = NULL;
      gcry_sexp_release (hash);
      hash = NULL;
    }
}


static void
check_pubkey_crypt (int n, gcry_sexp_t skey, gcry_sexp_t pkey, int algo)
{
  gcry_error_t rc;
  gcry_sexp_t plain = NULL;
  gcry_sexp_t ciph = NULL;
  gcry_sexp_t data = NULL;
  int dataidx;
  static const struct
  {
    int algo;    /* If not 0 run test only if ALGO matches.  */
    const char *data;
    const char *hint;
    int unpadded;
    int encrypt_expected_rc;
    int decrypt_expected_rc;
    int special;
  } datas[] =
    {
      {	GCRY_PK_RSA,
        "(data\n (flags pkcs1)\n"
	" (value #11223344556677889900AA#))\n",
	NULL,
	0,
	0,
	0 },
      {	GCRY_PK_RSA,
        "(data\n (flags pkcs1)\n"
	" (value #11223344556677889900AA#))\n",
	"(flags pkcs1)",
	1,
	0,
	0 },
      { GCRY_PK_RSA,
        "(data\n (flags oaep)\n"
	" (value #11223344556677889900AA#))\n",
	"(flags oaep)",
	1,
	0,
	0 },
      { GCRY_PK_RSA,
        "(data\n (flags oaep)\n (hash-algo sha1)\n"
	" (value #11223344556677889900AA#))\n",
	"(flags oaep)(hash-algo sha1)",
	1,
	0,
	0 },
      { GCRY_PK_RSA,
        "(data\n (flags oaep)\n (hash-algo sha1)\n (label \"test\")\n"
	" (value #11223344556677889900AA#))\n",
	"(flags oaep)(hash-algo sha1)(label \"test\")",
	1,
	0,
	0 },
      { GCRY_PK_RSA,
        "(data\n (flags oaep)\n (hash-algo sha1)\n (label \"test\")\n"
	" (value #11223344556677889900AA#)\n"
        " (random-override #4253647587980912233445566778899019283747#))\n",
	"(flags oaep)(hash-algo sha1)(label \"test\")",
	1,
	0,
	0 },
      {	0,
        "(data\n (flags )\n" " (value #11223344556677889900AA#))\n",
	NULL,
	1,
	0,
	0 },
      {	0,
        "(data\n (flags )\n" " (value #0090223344556677889900AA#))\n",
	NULL,
	1,
	0,
	0 },
      { 0,
        "(data\n (flags raw)\n" " (value #11223344556677889900AA#))\n",
	NULL,
	1,
	0,
	0 },
      { GCRY_PK_RSA,
        "(data\n (flags pkcs1)\n"
	" (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
	NULL,
	0,
	GPG_ERR_CONFLICT,
	0},
      { 0,
        "(data\n (flags raw foo)\n"
	" (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
	NULL,
	0,
	GPG_ERR_INV_FLAG,
	0},
      { 0,
        "(data\n (flags raw)\n"
	" (value #11223344556677889900AA#))\n",
	"(flags oaep)",
	1,
	0,
	GPG_ERR_ENCODING_PROBLEM, 1 },
      { GCRY_PK_RSA,
        "(data\n (flags oaep)\n"
	" (value #11223344556677889900AA#))\n",
	"(flags pkcs1)",
	1,
	0,
	GPG_ERR_ENCODING_PROBLEM, 1 },
      {	0,
        "(data\n (flags pss)\n"
	" (value #11223344556677889900AA#))\n",
	NULL,
	0,
	GPG_ERR_CONFLICT },
      { 0, NULL }
    };

  (void)n;

  for (dataidx = 0; datas[dataidx].data; dataidx++)
    {
      if (datas[dataidx].algo && datas[dataidx].algo != algo)
	continue;

      if (verbose)
	fprintf (stderr, "  encryption/decryption test %d (algo %d)\n",
                 dataidx, algo);

      rc = gcry_sexp_sscan (&data, NULL, datas[dataidx].data,
			    strlen (datas[dataidx].data));
      if (rc)
	die ("converting data failed: %s\n", gpg_strerror (rc));

      rc = gcry_pk_encrypt (&ciph, data, pkey);
      if (gcry_err_code (rc) != datas[dataidx].encrypt_expected_rc)
	fail ("gcry_pk_encrypt failed: %s\n", gpg_strerror (rc));

      if (!rc)
	{
          int expect_mismatch = 0;

	  /* Insert decoding hint to CIPH. */
	  if (datas[dataidx].hint)
	    {
	      size_t hint_len, len;
	      char *hint, *buf;
	      gcry_sexp_t list;

	      /* Convert decoding hint into canonical sexp. */
	      hint_len = gcry_sexp_new (&list, datas[dataidx].hint,
					strlen (datas[dataidx].hint), 1);
	      hint_len = gcry_sexp_sprint (list, GCRYSEXP_FMT_CANON, NULL, 0);
	      hint = gcry_malloc (hint_len);
	      if (!hint)
		die ("can't allocate memory\n");
	      hint_len = gcry_sexp_sprint (list, GCRYSEXP_FMT_CANON, hint,
					   hint_len);
	      gcry_sexp_release (list);

	      /* Convert CIPH into canonical sexp. */
	      len = gcry_sexp_sprint (ciph, GCRYSEXP_FMT_CANON, NULL, 0);
	      buf = gcry_malloc (len + hint_len);
	      if (!buf)
		die ("can't allocate memory\n");
	      len = gcry_sexp_sprint (ciph, GCRYSEXP_FMT_CANON, buf, len);
	      /* assert (!strcmp (buf, "(7:enc-val", 10)); */

	      /* Copy decoding hint into CIPH. */
	      memmove (buf + 10 + hint_len, buf + 10, len - 10);
	      memcpy (buf + 10, hint, hint_len);
	      gcry_free (hint);
	      gcry_sexp_new (&list, buf, len + hint_len, 1);
	      gcry_free (buf);
	      gcry_sexp_release (ciph);
	      ciph = list;
	    }
	  rc = gcry_pk_decrypt (&plain, ciph, skey);
          if (!rc && datas[dataidx].special == 1)
            {
              /* It may happen that OAEP formatted data which is
                 decrypted as pkcs#1 data returns a valid pkcs#1
                 frame.  However, the returned value will not be
                 identical - thus we expect a mismatch and test further on
                 whether this mismatch actually happened.  */
              expect_mismatch = 1;
            }
	  else if (gcry_err_code (rc) != datas[dataidx].decrypt_expected_rc)
            {
              if (verbose)
                {
                  show_sexp ("  data:\n", data);
                  show_sexp ("  ciph:\n", ciph);
                  show_sexp ("   key:\n", skey);
                }
              fail ("gcry_pk_decrypt failed: expected %d (%s), got %d (%s)\n",
                    datas[dataidx].decrypt_expected_rc,
                    gpg_strerror (datas[dataidx].decrypt_expected_rc),
                    rc, gpg_strerror (rc));
            }

	  if (!rc && datas[dataidx].unpadded)
	    {
	      gcry_sexp_t p1, p2;

	      p1 = gcry_sexp_find_token (data, "value", 0);
	      p2 = gcry_sexp_find_token (plain, "value", 0);
	      if (p1 && p2)
		{
		  const char *s1, *s2;
		  size_t n1, n2;

		  s1 = gcry_sexp_nth_data (p1, 1, &n1);
		  s2 = gcry_sexp_nth_data (p2, 1, &n2);
		  if (n1 != n2 || memcmp (s1, s2, n1))
                    {
                      if (expect_mismatch)
                        expect_mismatch = 0;
                      else
                        fail ("gcry_pk_encrypt/gcry_pk_decrypt "
                              "do not roundtrip\n");
                    }
		}

              if (expect_mismatch)
                fail ("gcry_pk_encrypt/gcry_pk_decrypt "
                      "expected mismatch did not happen\n");

	      gcry_sexp_release (p1);
	      gcry_sexp_release (p2);
	    }
	}

      gcry_sexp_release (plain);
      plain = NULL;
      gcry_sexp_release (ciph);
      ciph = NULL;
      gcry_sexp_release (data);
      data = NULL;
    }
}

static void
check_pubkey_grip (int n, const unsigned char *grip,
		   gcry_sexp_t skey, gcry_sexp_t pkey, int algo)
{
  unsigned char sgrip[20], pgrip[20];

  (void)algo;

  if (!gcry_pk_get_keygrip (skey, sgrip))
    die ("get keygrip for private RSA key failed\n");
  if (!gcry_pk_get_keygrip (pkey, pgrip))
    die ("[%i] get keygrip for public RSA key failed\n", n);
  if (memcmp (sgrip, pgrip, 20))
    fail ("[%i] keygrips don't match\n", n);
  if (memcmp (sgrip, grip, 20))
    fail ("wrong keygrip for RSA key\n");
}

static void
do_check_one_pubkey (int n, gcry_sexp_t skey, gcry_sexp_t pkey,
		     const unsigned char *grip, int algo, int flags)
{
 if (flags & FLAG_SIGN)
   {
     if (algo == GCRY_PK_ECDSA)
       check_pubkey_sign_ecdsa (n, skey, pkey);
     else
       check_pubkey_sign (n, skey, pkey, algo);
   }
 if (flags & FLAG_CRYPT)
   check_pubkey_crypt (n, skey, pkey, algo);
 if (grip && (flags & FLAG_GRIP))
   check_pubkey_grip (n, grip, skey, pkey, algo);
}

static void
check_one_pubkey (int n, test_spec_pubkey_t spec)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t skey, pkey;

  err = gcry_sexp_sscan (&skey, NULL, spec.key.secret,
			 strlen (spec.key.secret));
  if (!err)
    err = gcry_sexp_sscan (&pkey, NULL, spec.key.public,
			   strlen (spec.key.public));
  if (err)
    die ("converting sample key failed: %s\n", gpg_strerror (err));

  do_check_one_pubkey (n, skey, pkey,
                       (const unsigned char*)spec.key.grip,
		       spec.id, spec.flags);

  gcry_sexp_release (skey);
  gcry_sexp_release (pkey);
}

static void
get_keys_new (gcry_sexp_t *pkey, gcry_sexp_t *skey)
{
  gcry_sexp_t key_spec, key, pub_key, sec_key;
  int rc;
  if (verbose)
    fprintf (stderr, "  generating RSA key:");
  rc = gcry_sexp_new (&key_spec,
		      in_fips_mode ? "(genkey (rsa (nbits 4:1024)))"
                      : "(genkey (rsa (nbits 4:1024)(transient-key)))",
                      0, 1);
  if (rc)
    die ("error creating S-expression: %s\n", gpg_strerror (rc));
  rc = gcry_pk_genkey (&key, key_spec);
  gcry_sexp_release (key_spec);
  if (rc)
    die ("error generating RSA key: %s\n", gpg_strerror (rc));

  pub_key = gcry_sexp_find_token (key, "public-key", 0);
  if (! pub_key)
    die ("public part missing in key\n");

  sec_key = gcry_sexp_find_token (key, "private-key", 0);
  if (! sec_key)
    die ("private part missing in key\n");

  gcry_sexp_release (key);
  *pkey = pub_key;
  *skey = sec_key;
}

static void
check_one_pubkey_new (int n)
{
  gcry_sexp_t skey, pkey;

  get_keys_new (&pkey, &skey);
  do_check_one_pubkey (n, skey, pkey, NULL,
		       GCRY_PK_RSA, FLAG_SIGN | FLAG_CRYPT);
  gcry_sexp_release (pkey);
  gcry_sexp_release (skey);
}

/* Run all tests for the public key functions. */
static void
check_pubkey (void)
{
  static const test_spec_pubkey_t pubkeys[] = {
  {
    GCRY_PK_RSA, FLAG_CRYPT | FLAG_SIGN,
    {
      "(private-key\n"
      " (rsa\n"
      "  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "      2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "      ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "      891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea2"
      "      51#)\n"
      "  (e #010001#)\n"
      "  (d #046129F2489D71579BE0A75FE029BD6CDB574EBF57EA8A5B0FDA942CAB943B11"
      "      7D7BB95E5D28875E0F9FC5FCC06A72F6D502464DABDED78EF6B716177B83D5BD"
      "      C543DC5D3FED932E59F5897E92E6F58A0F33424106A3B6FA2CBF877510E4AC21"
      "      C3EE47851E97D12996222AC3566D4CCB0B83D164074ABF7DE655FC2446DA1781"
      "      #)\n"
      "  (p #00e861b700e17e8afe6837e7512e35b6ca11d0ae47d8b85161c67baf64377213"
      "      fe52d772f2035b3ca830af41d8a4120e1c1c70d12cc22f00d28d31dd48a8d424"
      "      f1#)\n"
      "  (q #00f7a7ca5367c661f8e62df34f0d05c10c88e5492348dd7bddc942c9a8f369f9"
      "      35a07785d2db805215ed786e4285df1658eed3ce84f469b81b50d358407b4ad3"
      "      61#)\n"
      "  (u #304559a9ead56d2309d203811a641bb1a09626bc8eb36fffa23c968ec5bd891e"
      "      ebbafc73ae666e01ba7c8990bae06cc2bbe10b75e69fcacb353a6473079d8e9b"
      "      #)))\n",

      "(public-key\n"
      " (rsa\n"
      "  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "      2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "      ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "      891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea2"
      "      51#)\n"
      "  (e #010001#)))\n",

      "\x32\x10\x0c\x27\x17\x3e\xf6\xe9\xc4\xe9"
      "\xa2\x5d\x3d\x69\xf8\x6d\x37\xa4\xf9\x39"}
  },
  {
    GCRY_PK_DSA, FLAG_SIGN,
    {
      "(private-key\n"
      " (DSA\n"
      "  (p #00AD7C0025BA1A15F775F3F2D673718391D00456978D347B33D7B49E7F32EDAB"
      "      96273899DD8B2BB46CD6ECA263FAF04A28903503D59062A8865D2AE8ADFB5191"
      "      CF36FFB562D0E2F5809801A1F675DAE59698A9E01EFE8D7DCFCA084F4C6F5A44"
      "      44D499A06FFAEA5E8EF5E01F2FD20A7B7EF3F6968AFBA1FB8D91F1559D52D877"
      "      7B#)\n"
      "  (q #00EB7B5751D25EBBB7BD59D920315FD840E19AEBF9#)\n"
      "  (g #1574363387FDFD1DDF38F4FBE135BB20C7EE4772FB94C337AF86EA8E49666503"
      "      AE04B6BE81A2F8DD095311E0217ACA698A11E6C5D33CCDAE71498ED35D13991E"
      "      B02F09AB40BD8F4C5ED8C75DA779D0AE104BC34C960B002377068AB4B5A1F984"
      "      3FBA91F537F1B7CAC4D8DD6D89B0D863AF7025D549F9C765D2FC07EE208F8D15"
      "      #)\n"
      "  (y #64B11EF8871BE4AB572AA810D5D3CA11A6CDBC637A8014602C72960DB135BF46"
      "      A1816A724C34F87330FC9E187C5D66897A04535CC2AC9164A7150ABFA8179827"
      "      6E45831AB811EEE848EBB24D9F5F2883B6E5DDC4C659DEF944DCFD80BF4D0A20"
      "      42CAA7DC289F0C5A9D155F02D3D551DB741A81695B74D4C8F477F9C7838EB0FB"
      "      #)\n"
      "  (x #11D54E4ADBD3034160F2CED4B7CD292A4EBF3EC0#)))\n",

      "(public-key\n"
      " (DSA\n"
      "  (p #00AD7C0025BA1A15F775F3F2D673718391D00456978D347B33D7B49E7F32EDAB"
      "      96273899DD8B2BB46CD6ECA263FAF04A28903503D59062A8865D2AE8ADFB5191"
      "      CF36FFB562D0E2F5809801A1F675DAE59698A9E01EFE8D7DCFCA084F4C6F5A44"
      "      44D499A06FFAEA5E8EF5E01F2FD20A7B7EF3F6968AFBA1FB8D91F1559D52D877"
      "      7B#)\n"
      "  (q #00EB7B5751D25EBBB7BD59D920315FD840E19AEBF9#)\n"
      "  (g #1574363387FDFD1DDF38F4FBE135BB20C7EE4772FB94C337AF86EA8E49666503"
      "      AE04B6BE81A2F8DD095311E0217ACA698A11E6C5D33CCDAE71498ED35D13991E"
      "      B02F09AB40BD8F4C5ED8C75DA779D0AE104BC34C960B002377068AB4B5A1F984"
      "      3FBA91F537F1B7CAC4D8DD6D89B0D863AF7025D549F9C765D2FC07EE208F8D15"
      "      #)\n"
      "  (y #64B11EF8871BE4AB572AA810D5D3CA11A6CDBC637A8014602C72960DB135BF46"
      "      A1816A724C34F87330FC9E187C5D66897A04535CC2AC9164A7150ABFA8179827"
      "      6E45831AB811EEE848EBB24D9F5F2883B6E5DDC4C659DEF944DCFD80BF4D0A20"
      "      42CAA7DC289F0C5A9D155F02D3D551DB741A81695B74D4C8F477F9C7838EB0FB"
      "      #)))\n",

      "\xc6\x39\x83\x1a\x43\xe5\x05\x5d\xc6\xd8"
      "\x4a\xa6\xf9\xeb\x23\xbf\xa9\x12\x2d\x5b" }
  },
  {
    GCRY_PK_ELG, FLAG_SIGN | FLAG_CRYPT,
    {
      "(private-key\n"
      " (ELG\n"
      "  (p #00B93B93386375F06C2D38560F3B9C6D6D7B7506B20C1773F73F8DE56E6CD65D"
      "      F48DFAAA1E93F57A2789B168362A0F787320499F0B2461D3A4268757A7B27517"
      "      B7D203654A0CD484DEC6AF60C85FEB84AAC382EAF2047061FE5DAB81A20A0797"
      "      6E87359889BAE3B3600ED718BE61D4FC993CC8098A703DD0DC942E965E8F18D2"
      "      A7#)\n"
      "  (g #05#)\n"
      "  (y #72DAB3E83C9F7DD9A931FDECDC6522C0D36A6F0A0FEC955C5AC3C09175BBFF2B"
      "      E588DB593DC2E420201BEB3AC17536918417C497AC0F8657855380C1FCF11C5B"
      "      D20DB4BEE9BDF916648DE6D6E419FA446C513AAB81C30CB7B34D6007637BE675"
      "      56CE6473E9F9EE9B9FADD275D001563336F2186F424DEC6199A0F758F6A00FF4"
      "      #)\n"
      "  (x #03C28900087B38DABF4A0AB98ACEA39BB674D6557096C01D72E31C16BDD32214"
      "      #)))\n",

      "(public-key\n"
      " (ELG\n"
      "  (p #00B93B93386375F06C2D38560F3B9C6D6D7B7506B20C1773F73F8DE56E6CD65D"
      "      F48DFAAA1E93F57A2789B168362A0F787320499F0B2461D3A4268757A7B27517"
      "      B7D203654A0CD484DEC6AF60C85FEB84AAC382EAF2047061FE5DAB81A20A0797"
      "      6E87359889BAE3B3600ED718BE61D4FC993CC8098A703DD0DC942E965E8F18D2"
      "      A7#)\n"
      "  (g #05#)\n"
      "  (y #72DAB3E83C9F7DD9A931FDECDC6522C0D36A6F0A0FEC955C5AC3C09175BBFF2B"
      "      E588DB593DC2E420201BEB3AC17536918417C497AC0F8657855380C1FCF11C5B"
      "      D20DB4BEE9BDF916648DE6D6E419FA446C513AAB81C30CB7B34D6007637BE675"
      "      56CE6473E9F9EE9B9FADD275D001563336F2186F424DEC6199A0F758F6A00FF4"
      "      #)))\n",

      "\xa7\x99\x61\xeb\x88\x83\xd2\xf4\x05\xc8"
      "\x4f\xba\x06\xf8\x78\x09\xbc\x1e\x20\xe5" }
  },
  { /* ECDSA test.  */
    GCRY_PK_ECDSA, FLAG_SIGN,
    {
      "(private-key\n"
      " (ecdsa\n"
      "  (curve nistp192)\n"
      "  (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE"
      "        C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)\n"
      "  (d #00D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D#)))\n",

      "(public-key\n"
      " (ecdsa\n"
      "  (curve nistp192)\n"
      "  (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE"
      "        C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)))\n",

      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
  },
  { /* ECDSA test with the public key algorithm given as "ecc".  */
    GCRY_PK_ECDSA, FLAG_SIGN,
    {
      "(private-key\n"
      " (ecdsa\n"
      "  (curve nistp192)\n"
      "  (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE"
      "        C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)\n"
      "  (d #00D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D#)))\n",

      "(public-key\n"
      " (ecc\n"
      "  (curve nistp192)\n"
      "  (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE"
      "        C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)))\n",

      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
  },
  { /* ECDSA test with the private key algorithm given as "ecc".  */
    GCRY_PK_ECDSA, FLAG_SIGN,
    {
      "(private-key\n"
      " (ecc\n"
      "  (curve nistp192)\n"
      "  (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE"
      "        C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)\n"
      "  (d #00D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D#)))\n",

      "(public-key\n"
      " (ecdsa\n"
      "  (curve nistp192)\n"
      "  (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE"
      "        C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)))\n",

      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
  },
  { /* ECDSA test with the key algorithms given as "ecc".  */
    GCRY_PK_ECDSA, FLAG_SIGN,
    {
      "(private-key\n"
      " (ecc\n"
      "  (curve nistp192)\n"
      "  (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE"
      "        C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)\n"
      "  (d #00D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D#)))\n",

      "(public-key\n"
      " (ecc\n"
      "  (curve nistp192)\n"
      "  (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE"
      "        C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)))\n",

      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
  },
  { /* ECDSA test 256 bit.  */
    GCRY_PK_ECDSA, FLAG_SIGN,
    {
      "(private-key\n"
      " (ecc\n"
      "  (curve nistp256)\n"
      "  (q #04D4F6A6738D9B8D3A7075C1E4EE95015FC0C9B7E4272D2B"
      "      EB6644D3609FC781B71F9A8072F58CB66AE2F89BB1245187"
      "      3ABF7D91F9E1FBF96BF2F70E73AAC9A283#)\n"
      "  (d #5A1EF0035118F19F3110FB81813D3547BCE1E5BCE77D1F74"
      "      4715E1D5BBE70378#)))\n",

      "(public-key\n"
      " (ecc\n"
      "  (curve nistp256)\n"
      "  (q #04D4F6A6738D9B8D3A7075C1E4EE95015FC0C9B7E4272D2B"
      "      EB6644D3609FC781B71F9A8072F58CB66AE2F89BB1245187"
      "      3ABF7D91F9E1FBF96BF2F70E73AAC9A283#)))\n",

      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
  },
  { /* GOST R 34.10-2001/2012 test 256 bit.  */
    GCRY_PK_ECDSA, FLAG_SIGN,
    {
      "(private-key\n"
      " (ecc\n"
      "  (curve GOST2001-test)\n"
      "  (q #047F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B78"
      "      8F6689DBD8E56FD80B26F1B489D6701DD185C8413A977B3C"
      "      BBAF64D1C593D26627DFFB101A87FF77DA#)\n"
      "  (d #7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE"
      "      1D19CE9891EC3B28#)))\n",

      "(public-key\n"
      " (ecc\n"
      "  (curve GOST2001-test)\n"
      "  (q #047F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B78"
      "      8F6689DBD8E56FD80B26F1B489D6701DD185C8413A977B3C"
      "      BBAF64D1C593D26627DFFB101A87FF77DA#)))\n",

      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
  },
  { /* GOST R 34.10-2012 test 512 bit.  */
    GCRY_PK_ECDSA, FLAG_SIGN,
    {
      "(private-key\n"
      " (ecc\n"
      "  (curve GOST2012-test)\n"
      "  (q #04115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1"
      "        815B5C320C854621DD5A515856D13314AF69BC5B924C8B"
      "        4DDFF75C45415C1D9DD9DD33612CD530EFE137C7C90CD4"
      "        0B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7F"
      "        B72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E"
      "        1F9339FDF27F35ECA93677BEEC#)\n"
      "  (d #0BA6048AADAE241BA40936D47756D7C93091A0E851466970"
      "      0EE7508E508B102072E8123B2200A0563322DAD2827E2714"
      "      A2636B7BFD18AADFC62967821FA18DD4#)))\n",

      "(public-key\n"
      " (ecc\n"
      "  (curve GOST2001-test)\n"
      "  (q #04115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1"
      "        815B5C320C854621DD5A515856D13314AF69BC5B924C8B"
      "        4DDFF75C45415C1D9DD9DD33612CD530EFE137C7C90CD4"
      "        0B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7F"
      "        B72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E"
      "        1F9339FDF27F35ECA93677BEEC#)))\n"

      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
    }
  };
  int i;

  if (verbose)
    fprintf (stderr, "Starting public key checks.\n");
  for (i = 0; i < sizeof (pubkeys) / sizeof (*pubkeys); i++)
    if (pubkeys[i].id)
      {
        if (gcry_pk_test_algo (pubkeys[i].id) && in_fips_mode)
          {
            if (verbose)
              fprintf (stderr, "  algorithm %d not available in fips mode\n",
                       pubkeys[i].id);
            continue;
          }
        check_one_pubkey (i, pubkeys[i]);
      }
  if (verbose)
    fprintf (stderr, "Completed public key checks.\n");

  if (verbose)
    fprintf (stderr, "Starting additional public key checks.\n");
  for (i = 0; i < sizeof (pubkeys) / sizeof (*pubkeys); i++)
    if (pubkeys[i].id)
      {
        if (gcry_pk_test_algo (pubkeys[i].id) && in_fips_mode)
          {
            if (verbose)
              fprintf (stderr, "  algorithm %d not available in fips mode\n",
                       pubkeys[i].id);
            continue;
          }
        check_one_pubkey_new (i);
      }
  if (verbose)
    fprintf (stderr, "Completed additional public key checks.\n");

}

int
main (int argc, char **argv)
{
  gpg_error_t err;
  int last_argc = -1;
  int debug = 0;
  int use_fips = 0;
  int selftest_only = 0;
  int pubkey_only = 0;
  int loop = 0;
  unsigned int loopcount = 0;

  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--fips"))
        {
          use_fips = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--selftest"))
        {
          selftest_only = 1;
          verbose += 2;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--pubkey"))
        {
          pubkey_only = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--die"))
        {
          die_on_error = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--loop"))
        {
          argc--; argv++;
          if (argc)
            {
              loop = atoi (*argv);
              argc--; argv++;
            }
        }
    }

  gcry_control (GCRYCTL_SET_VERBOSITY, (int)verbose);

  if (use_fips)
    gcry_control (GCRYCTL_FORCE_FIPS_MODE, 0);

  /* Check that we test exactly our version - including the patchlevel.  */
  if (strcmp (GCRYPT_VERSION, gcry_check_version (NULL)))
    die ("version mismatch; pgm=%s, library=%s\n",
         GCRYPT_VERSION,gcry_check_version (NULL));

  if ( gcry_fips_mode_active () )
    in_fips_mode = 1;

  if (!in_fips_mode)
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

  if (verbose)
    gcry_set_progress_handler (progress_handler, NULL);

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  /* No valuable keys are create, so we can speed up our RNG. */
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  do
    {
      if (pubkey_only)
        check_pubkey ();
      else if (!selftest_only)
        {
          check_ciphers ();
          check_cipher_modes ();
          check_bulk_cipher_modes ();
          check_digests ();
          check_hmac ();
          check_mac ();
          check_pubkey ();
        }
      loopcount++;
      if (loop)
        {
          fprintf (stderr, "Test iteration %u completed.\n", loopcount);
          if (loop != -1)
            loop--;
        }
    }
  while (loop);

  if (in_fips_mode && !selftest_only)
    {
      /* If we are in fips mode do some more tests. */
      gcry_md_hd_t md;

      /* First trigger a self-test.  */
      gcry_control (GCRYCTL_FORCE_FIPS_MODE, 0);
      if (!gcry_control (GCRYCTL_OPERATIONAL_P, 0))
        fail ("not in operational state after self-test\n");

      /* Get us into the error state.  */
      err = gcry_md_open (&md, GCRY_MD_SHA1, 0);
      if (err)
        fail ("failed to open SHA-1 hash context: %s\n", gpg_strerror (err));
      else
        {
          err = gcry_md_enable (md, GCRY_MD_SHA256);
          if (err)
            fail ("failed to add SHA-256 hash context: %s\n",
                  gpg_strerror (err));
          else
            {
              /* gcry_md_get_algo is only defined for a context with
                 just one digest algorithm.  With our setup it should
                 put the oibrary intoerror state.  */
              fputs ("Note: Two lines with error messages follow "
                     "- this is expected\n", stderr);
              gcry_md_get_algo (md);
              gcry_md_close (md);
              if (gcry_control (GCRYCTL_OPERATIONAL_P, 0))
                fail ("expected error state but still in operational state\n");
              else
                {
                  /* Now run a self-test and to get back into
                     operational state.  */
                  gcry_control (GCRYCTL_FORCE_FIPS_MODE, 0);
                  if (!gcry_control (GCRYCTL_OPERATIONAL_P, 0))
                    fail ("did not reach operational after error "
                          "and self-test\n");
                }
            }
        }

    }
  else
    {
      /* If in standard mode, run selftests.  */
      if (gcry_control (GCRYCTL_SELFTEST, 0))
        fail ("running self-test failed\n");
    }

  if (verbose)
    fprintf (stderr, "\nAll tests completed. Errors: %i\n", error_count);

  if (in_fips_mode && !gcry_fips_mode_active ())
    fprintf (stderr, "FIPS mode is not anymore active\n");

  return error_count ? 1 : 0;
}
