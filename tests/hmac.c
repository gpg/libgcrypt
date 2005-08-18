/* hmac.c -  HMAC regression tests
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../src/gcrypt.h"

static int verbose;
static int error_count;

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
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
check_one_mac (int algo,
               void *key, size_t keylen,
               void *data, size_t datalen,
               char *expect)
{
  gcry_md_hd_t hd;
  char *p;
  int mdlen;
  int i;
  gcry_error_t err = 0;

  err = gcry_md_open (&hd, algo, GCRY_MD_FLAG_HMAC);
  if (err)
    {
      fail ("algo %d, grcy_md_open failed: %s\n", algo, gpg_strerror (err));
      return;
    }

  mdlen = gcry_md_get_algo_dlen (algo);
  if (mdlen < 1 || mdlen > 500)
    {
      fail ("algo %d, grcy_md_get_algo_dlen failed: %d\n", algo, mdlen);
      return;
    }

  err = gcry_md_setkey (hd, key, keylen);
  if (err)
    {
      fail ("algo %d, grcy_md_setkey failed: %s\n", algo, gpg_strerror (err));
      return;
    }

  gcry_md_write (hd, data, datalen);

  p = gcry_md_read (hd, 0);

  if (memcmp (p, expect, mdlen))
    {
      printf ("computed: ");
      for (i = 0; i < mdlen; i++)
	printf ("%02x ", p[i] & 0xFF);
      printf ("\nexpected: ");
      for (i = 0; i < mdlen; i++)
	printf ("%02x ", expect[i] & 0xFF);
      printf ("\n");

      fail ("algo %d, MAC does not match\n", algo);
    }

  gcry_md_close (hd);
}

static void
check_hmac (void)
{
  unsigned char key[64];
  int i, j;

  /* FIPS 198a, A.1 */
  for (i=0; i < 64; i++)
    key[i] = i;
  check_one_mac (GCRY_MD_SHA1, key, 64, "Sample #1", 9,
                 "\x4f\x4c\xa3\xd5\xd6\x8b\xa7\xcc\x0a\x12"
                 "\x08\xc9\xc6\x1e\x9c\x5d\xa0\x40\x3c\x0a");

  /* FIPS 198a, A.2 */
  for (i=0, j=0x30; i < 20; i++)
    key[i] = j++;
  check_one_mac (GCRY_MD_SHA1, key, 20, "Sample #2", 9,
                 "\x09\x22\xd3\x40\x5f\xaa\x3d\x19\x4f\x82"
                 "\xa4\x58\x30\x73\x7d\x5c\xc6\xc7\x5d\x24");

}

int
main (int argc, char **argv)
{
  int debug = 0;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  check_hmac ();

  return error_count ? 1 : 0;
}
