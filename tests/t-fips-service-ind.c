/* t-fips-service-ind.c - FIPS service indicator regression tests
 * Copyright (C) 2024 g10 Code GmbH
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define PGM "t-fips-service-ind"

#include "t-common.h"
static int in_fips_mode;
#define MAX_DATA_LEN 1040

/* Mingw requires us to include windows.h after winsock2.h which is
   included by gcrypt.h.  */
#ifdef _WIN32
# include <windows.h>
#endif

/* Check gcry_cipher_open, gcry_cipher_setkey, gcry_cipher_encrypt,
   gcry_cipher_decrypt, gcry_cipher_close API.  */
static void
check_cipher_o_s_e_d_c (void)
{
  static struct {
    int algo;
    const char *key;
    int keylen;
    const char *expect;
    int expect_failure;
    unsigned int flags;
  } tv[] = {
#if USE_DES
      { GCRY_CIPHER_3DES,
	"\xe3\x34\x7a\x6b\x0b\xc1\x15\x2c\x64\x2a\x25\xcb\xd3\xbc\x31\xab"
	"\xfb\xa1\x62\xa8\x1f\x19\x7c\x15", 24,
        "\x3f\x1a\xb8\x83\x18\x8b\xb5\x97", 1 },
      { GCRY_CIPHER_3DES,
	"\xe3\x34\x7a\x6b\x0b\xc1\x15\x2c\x64\x2a\x25\xcb\xd3\xbc\x31\xab"
	"\xfb\xa1\x62\xa8\x1f\x19\x7c\x15", 24,
        "\x3f\x1a\xb8\x83\x18\x8b\xb5\x97",
        1, GCRY_CIPHER_FLAG_REJECT_NON_FIPS },
#endif
      { GCRY_CIPHER_AES,
	"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16,
        "\x5c\x71\xd8\x5d\x26\x5e\xcd\xb5\x95\x40\x41\xab\xff\x25\x6f\xd1" }
  };
  const char *pt = "Shohei Ohtani 2024: 54 HR, 59 SB";
  int ptlen;
  int tvidx;
  unsigned char out[MAX_DATA_LEN];
  gpg_error_t err;

  ptlen = strlen (pt);
  assert (ptlen == 32);
  for (tvidx=0; tvidx < DIM(tv); tvidx++)
    {
      gpg_err_code_t ec;
      gcry_cipher_hd_t h;
      size_t blklen;

      if (verbose)
        fprintf (stderr, "checking gcry_cipher_open test %d\n",
                 tvidx);

      blklen = gcry_cipher_get_algo_blklen (tv[tvidx].algo);
      assert (blklen != 0);
      assert (blklen <= ptlen);
      assert (blklen <= DIM (out));
      err = gcry_cipher_open (&h, tv[tvidx].algo, GCRY_CIPHER_MODE_ECB,
                              tv[tvidx].flags);
      if (err)
        {
          if (in_fips_mode && (tv[tvidx].flags & GCRY_CIPHER_FLAG_REJECT_NON_FIPS)
              && tv[tvidx].expect_failure)
            /* Here, an error is expected */
            ;
          else
            fail ("gcry_cipher_open test %d unexpectedly failed: %s\n",
                  tvidx, gpg_strerror (err));
          continue;
        }
      else
        {
          if (in_fips_mode && (tv[tvidx].flags & GCRY_CIPHER_FLAG_REJECT_NON_FIPS)
              && tv[tvidx].expect_failure)
            /* This case, an error is expected, but we observed success */
            fail ("gcry_cipher_open test %d unexpectedly succeeded\n", tvidx);
        }

      ec = gcry_get_fips_service_indicator ();
      if (ec == GPG_ERR_INV_OP)
        {
          /* libgcrypt is old, no support of the FIPS service indicator.  */
          fail ("gcry_cipher_open test %d unexpectedly failed to check the FIPS service indicator.\n",
                tvidx);
          continue;
        }

      if (in_fips_mode && !tv[tvidx].expect_failure && ec)
        {
          /* Success with the FIPS service indicator == 0 expected, but != 0.  */
          fail ("gcry_cipher_open test %d unexpectedly set the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }
      else if (in_fips_mode && tv[tvidx].expect_failure && !ec)
        {
          /* Success with the FIPS service indicator != 0 expected, but == 0.  */
          fail ("gcry_cipher_open test %d unexpectedly cleared the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }

      err = gcry_cipher_setkey (h, tv[tvidx].key, tv[tvidx].keylen);
      if (err)
        {
          fail ("gcry_cipher_setkey %d failed: %s\n", tvidx,
                gpg_strerror (err));
          gcry_cipher_close (h);
          continue;
        }

      err = gcry_cipher_encrypt (h, out, MAX_DATA_LEN, pt, blklen);
      if (err)
        {
          fail ("gcry_cipher_encrypt %d failed: %s\n", tvidx,
                gpg_strerror (err));
          gcry_cipher_close (h);
          continue;
        }

      if (memcmp (out, tv[tvidx].expect, blklen))
        {
          int i;

          fail ("gcry_cipher_open test %d failed: encryption mismatch\n", tvidx);
          fputs ("got:", stderr);
          for (i=0; i < blklen; i++)
            fprintf (stderr, " %02x", out[i]);
          putc ('\n', stderr);
        }

      err = gcry_cipher_decrypt (h, out, blklen, NULL, 0);
      if (err)
        {
          fail ("gcry_cipher_decrypt %d failed: %s\n", tvidx,
                gpg_strerror (err));
          gcry_cipher_close (h);
          continue;
        }

      if (memcmp (out, pt, blklen))
        {
          int i;

          fail ("gcry_cipher_open test %d failed: decryption mismatch\n", tvidx);
          fputs ("got:", stderr);
          for (i=0; i < blklen; i++)
            fprintf (stderr, " %02x", out[i]);
          putc ('\n', stderr);
        }

      gcry_cipher_close (h);
    }
}

/* Check gcry_mac_open, gcry_mac_write, gcry_mac_write, gcry_mac_read,
   gcry_mac_close API.  */
static void
check_mac_o_w_r_c (void)
{
  static struct {
    int algo;
    const char *data;
    int datalen;
    const char *key;
    int keylen;
    const char *expect;
    int expect_failure;
    unsigned int flags;
  } tv[] = {
#if USE_MD5
    { GCRY_MAC_HMAC_MD5, "hmac input abc", 14, "hmac key input", 14,
      "\x0d\x72\xd0\x60\xaf\x34\xf2\xca\x33\x58\xa9\xcc\xd3\x5a\xac\xb5", 1 },
    { GCRY_MAC_HMAC_MD5, "hmac input abc", 14, "hmac key input", 14,
      "\x0d\x72\xd0\x60\xaf\x34\xf2\xca\x33\x58\xa9\xcc\xd3\x5a\xac\xb5", 1,
      GCRY_MAC_FLAG_REJECT_NON_FIPS },
#endif
#if USE_SHA1
    { GCRY_MAC_HMAC_SHA1, "hmac input abc", 14, "hmac key input", 14,
      "\xc9\x62\x9d\x16\x0f\xc2\xc4\xcd\x38\xac\x3a\x00\xdc\x29\x61\x03"
      "\x69\x50\xd7\x3a" },
#endif
    { GCRY_MAC_HMAC_SHA256, "hmac input abc", 14, "hmac key input", 14,
      "\x6a\xda\x4d\xd5\xf3\xa7\x32\x9d\xd2\x55\xc0\x7f\xe6\x0a\x93\xb8"
      "\x7a\x6e\x76\x68\x46\x34\x67\xf9\xc2\x29\xb8\x24\x2e\xc8\xe3\xb4" },
    { GCRY_MAC_HMAC_SHA384, "hmac input abc", 14, "hmac key input", 14,
      "\xc6\x59\x14\x4a\xac\x4d\xd5\x62\x09\x2c\xbd\x5e\xbf\x41\x94\xf9"
      "\xa4\x78\x18\x46\xfa\xd6\xd1\x12\x90\x4f\x65\xd4\xe8\x44\xcc\xcc"
      "\x3d\xcc\xf3\xe4\x27\xd8\xf0\xff\x01\xe8\x70\xcd\xfb\xfa\x24\x45" },
    { GCRY_MAC_HMAC_SHA512, "hmac input abc", 14, "hmac key input", 14,
      "\xfa\x77\x49\x49\x24\x3d\x7e\x03\x1b\x0e\xd1\xfc\x20\x81\xcf\x95"
      "\x81\x21\xa4\x4f\x3b\xe5\x69\x9a\xe6\x67\x27\x10\xbc\x62\xc7\xb3"
      "\xb3\xcf\x2b\x1e\xda\x20\x48\x25\xc5\x6a\x52\xc7\xc9\xd9\x77\xf6"
      "\xf6\x49\x9d\x70\xe6\x04\x33\xab\x6a\xdf\x7e\x9f\xf4\xd1\x59\x6e" },
    { GCRY_MAC_HMAC_SHA3_256, "hmac input abc", 14, "hmac key input", 14,
      "\x2b\xe9\x02\x92\xc2\x37\xbe\x91\x06\xbf\x9c\x8e\x7b\xa3\xf2\xfc"
      "\x68\x10\x8a\x71\xd5\xc7\x84\x3c\x0b\xdd\x7d\x1e\xdf\xa5\xf6\xa7" },
    { GCRY_MAC_HMAC_SHA3_384, "hmac input abc", 14, "hmac key input", 14,
      "\x9f\x6b\x9f\x49\x95\x57\xed\x33\xb1\xe7\x22\x2f\xda\x40\x68\xb0"
      "\x28\xd2\xdb\x6f\x73\x3c\x2e\x2b\x29\x51\x64\x53\xc4\xc5\x63\x8a"
      "\x98\xca\x78\x1a\xe7\x1b\x7d\xf6\xbf\xf3\x6a\xf3\x2a\x0e\xa0\x5b" },
    { GCRY_MAC_HMAC_SHA3_512, "hmac input abc", 14, "hmac key input", 14,
      "\xf3\x19\x70\x54\x25\xdf\x0f\xde\x09\xe9\xea\x3b\x34\x67\x14\x32"
      "\xe6\xe2\x58\x9d\x76\x38\xa4\xbd\x90\x35\x4c\x07\x7c\xa3\xdb\x23"
      "\x3c\x78\x0c\x45\xee\x8e\x39\xd5\x81\xd8\x5c\x13\x20\x40\xba\x34"
      "\xd0\x0b\x75\x31\x38\x4b\xe7\x74\x87\xa9\xc5\x68\x7f\xbc\x19\xa1" }
#if USE_RMD160
    ,
    { GCRY_MAC_HMAC_RMD160, "hmac input abc", 14, "hmac key input", 14,
      "\xf2\x45\x5c\x7e\x48\x1a\xbb\xe5\xe8\xec\x40\xa4\x1b\x89\x26\x2b"
      "\xdc\xa1\x79\x59", 1 }
#endif
  };
  int tvidx;
  unsigned char mac[64];
  int expectlen;
  gpg_error_t err;
  size_t buflen;

  for (tvidx=0; tvidx < DIM(tv); tvidx++)
    {
      gpg_err_code_t ec;
      gcry_mac_hd_t h;

      if (verbose)
        fprintf (stderr, "checking gcry_mac_open test %d\n",
                 tvidx);

      expectlen = gcry_mac_get_algo_maclen (tv[tvidx].algo);
      assert (expectlen != 0);
      assert (expectlen <= DIM (mac));
      err = gcry_mac_open (&h, tv[tvidx].algo, tv[tvidx].flags, NULL);
      if (err)
        {
          if (in_fips_mode && (tv[tvidx].flags & GCRY_MAC_FLAG_REJECT_NON_FIPS)
              && tv[tvidx].expect_failure)
            /* Here, an error is expected */
            ;
          else
            fail ("gcry_mac_open test %d unexpectedly failed: %s\n",
                  tvidx, gpg_strerror (err));
          continue;
        }
      else
        {
          if (in_fips_mode && (tv[tvidx].flags & GCRY_MAC_FLAG_REJECT_NON_FIPS)
              && tv[tvidx].expect_failure)
            /* This case, an error is expected, but we observed success */
            fail ("gcry_mac_open test %d unexpectedly succeeded\n", tvidx);
        }


      ec = gcry_get_fips_service_indicator ();
      if (ec == GPG_ERR_INV_OP)
        {
          /* libgcrypt is old, no support of the FIPS service indicator.  */
          fail ("gcry_mac_open test %d unexpectedly failed to check the FIPS service indicator.\n",
                tvidx);
          continue;
        }

      if (in_fips_mode && !tv[tvidx].expect_failure && ec)
        {
          /* Success with the FIPS service indicator == 0 expected, but != 0.  */
          fail ("gcry_mac_open test %d unexpectedly set the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }
      else if (in_fips_mode && tv[tvidx].expect_failure && !ec)
        {
          /* Success with the FIPS service indicator != 0 expected, but == 0.  */
          fail ("gcry_mac_open test %d unexpectedly cleared the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }

      err = gcry_mac_setkey (h, tv[tvidx].key, tv[tvidx].keylen);
      if (err)
        {
          fail ("gcry_mac_setkey test %d unexpectedly failed: %s\n",
                tvidx, gpg_strerror (err));
          gcry_mac_close (h);
          continue;
        }

      err = gcry_mac_write (h, tv[tvidx].data, tv[tvidx].datalen);
      if (err)
        {
          fail ("gcry_mac_write test %d unexpectedly failed: %s\n",
                tvidx, gpg_strerror (err));
          gcry_mac_close (h);
          continue;
        }

      buflen = expectlen;
      err = gcry_mac_read (h, mac, &buflen);
      if (err || buflen != expectlen)
        {
          fail ("gcry_mac_read test %d unexpectedly failed: %s\n",
                tvidx, gpg_strerror (err));
          gcry_mac_close (h);
          continue;
        }

      if (memcmp (mac, tv[tvidx].expect, expectlen))
        {
          int i;

          fail ("gcry_mac_open test %d failed: mismatch\n", tvidx);
          fputs ("got:", stderr);
          for (i=0; i < expectlen; i++)
            fprintf (stderr, " %02x", mac[i]);
          putc ('\n', stderr);
        }

      gcry_mac_close (h);
    }
}


/* Check gcry_md_open, gcry_md_write, gcry_md_write, gcry_md_read,
   gcry_md_close API.  */
static void
check_md_o_w_r_c (void)
{
  static struct {
    int algo;
    const char *data;
    int datalen;
    const char *expect;
    int expect_failure;
    unsigned int flags;
  } tv[] = {
#if USE_MD5
    { GCRY_MD_MD5, "abc", 3,
      "\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72", 1 },
    { GCRY_MD_MD5, "abc", 3,
      "\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72", 1,
      GCRY_MD_FLAG_REJECT_NON_FIPS },
#endif
#if USE_SHA1
    { GCRY_MD_SHA1, "abc", 3,
      "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E"
      "\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D" },
#endif
    { GCRY_MD_SHA256, "abc", 3,
      "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
      "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" },
    { GCRY_MD_SHA384, "abc", 3,
      "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07"
      "\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
      "\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7" },
    { GCRY_MD_SHA512, "abc", 3,
      "\xDD\xAF\x35\xA1\x93\x61\x7A\xBA\xCC\x41\x73\x49\xAE\x20\x41\x31"
      "\x12\xE6\xFA\x4E\x89\xA9\x7E\xA2\x0A\x9E\xEE\xE6\x4B\x55\xD3\x9A"
      "\x21\x92\x99\x2A\x27\x4F\xC1\xA8\x36\xBA\x3C\x23\xA3\xFE\xEB\xBD"
      "\x45\x4D\x44\x23\x64\x3C\xE8\x0E\x2A\x9A\xC9\x4F\xA5\x4C\xA4\x9F" },
    { GCRY_MD_SHA3_256, "abc", 3,
      "\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2\x04\x5c\x17\x2d\x6b\xd3\x90\xbd"
      "\x85\x5f\x08\x6e\x3e\x9d\x52\x5b\x46\xbf\xe2\x45\x11\x43\x15\x32" },
    { GCRY_MD_SHA3_384, "abc", 3,
      "\xec\x01\x49\x82\x88\x51\x6f\xc9\x26\x45\x9f\x58\xe2\xc6\xad\x8d"
      "\xf9\xb4\x73\xcb\x0f\xc0\x8c\x25\x96\xda\x7c\xf0\xe4\x9b\xe4\xb2"
      "\x98\xd8\x8c\xea\x92\x7a\xc7\xf5\x39\xf1\xed\xf2\x28\x37\x6d\x25" },
    { GCRY_MD_SHA3_512, "abc", 3,
      "\xb7\x51\x85\x0b\x1a\x57\x16\x8a\x56\x93\xcd\x92\x4b\x6b\x09\x6e"
      "\x08\xf6\x21\x82\x74\x44\xf7\x0d\x88\x4f\x5d\x02\x40\xd2\x71\x2e"
      "\x10\xe1\x16\xe9\x19\x2a\xf3\xc9\x1a\x7e\xc5\x76\x47\xe3\x93\x40"
      "\x57\x34\x0b\x4c\xf4\x08\xd5\xa5\x65\x92\xf8\x27\x4e\xec\x53\xf0" }
#if USE_RMD160
    ,
    { GCRY_MD_RMD160, "abc", 3,
      "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04"
      "\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc", 1 }
#endif
  };
  int tvidx;
  unsigned char *hash;
  int expectlen;
  gpg_error_t err;

  for (tvidx=0; tvidx < DIM(tv); tvidx++)
    {
      gpg_err_code_t ec;
      gcry_md_hd_t h;

      if (verbose)
        fprintf (stderr, "checking gcry_md_open test %d\n",
                 tvidx);

      expectlen = gcry_md_get_algo_dlen (tv[tvidx].algo);
      assert (expectlen != 0);
      err = gcry_md_open (&h, tv[tvidx].algo, tv[tvidx].flags);
      if (err)
        {
          if (in_fips_mode && (tv[tvidx].flags & GCRY_MD_FLAG_REJECT_NON_FIPS)
              && tv[tvidx].expect_failure)
            /* Here, an error is expected */
            ;
          else
            fail ("gcry_md_open test %d unexpectedly failed: %s\n",
                  tvidx, gpg_strerror (err));
          continue;
        }
      else
        {
          if (in_fips_mode && (tv[tvidx].flags & GCRY_MD_FLAG_REJECT_NON_FIPS)
              && tv[tvidx].expect_failure)
            /* This case, an error is expected, but we observed success */
            fail ("gcry_md_open test %d unexpectedly succeeded\n", tvidx);
        }


      ec = gcry_get_fips_service_indicator ();
      if (ec == GPG_ERR_INV_OP)
        {
          /* libgcrypt is old, no support of the FIPS service indicator.  */
          fail ("gcry_md_open test %d unexpectedly failed to check the FIPS service indicator.\n",
                tvidx);
          continue;
        }

      if (in_fips_mode && !tv[tvidx].expect_failure && ec)
        {
          /* Success with the FIPS service indicator == 0 expected, but != 0.  */
          fail ("gcry_md_open test %d unexpectedly set the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }
      else if (in_fips_mode && tv[tvidx].expect_failure && !ec)
        {
          /* Success with the FIPS service indicator != 0 expected, but == 0.  */
          fail ("gcry_md_open test %d unexpectedly cleared the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }

      gcry_md_write (h, tv[tvidx].data, tv[tvidx].datalen);
      hash = gcry_md_read (h, tv[tvidx].algo);
      if (memcmp (hash, tv[tvidx].expect, expectlen))
        {
          int i;

          fail ("gcry_md_open test %d failed: mismatch\n", tvidx);
          fputs ("got:", stderr);
          for (i=0; i < expectlen; i++)
            fprintf (stderr, " %02x", hash[i]);
          putc ('\n', stderr);
        }

      gcry_md_close (h);
    }
}

static void
check_hash_buffer (void)
{
  static struct {
    int algo;
    const char *data;
    int datalen;
    const char *expect;
    int expect_failure;
  } tv[] = {
#if USE_MD5
    { GCRY_MD_MD5, "abc", 3,
      "\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72", 1 },
#endif
#if USE_SHA1
    { GCRY_MD_SHA1, "abc", 3,
      "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E"
      "\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D" },
#endif
    { GCRY_MD_SHA256, "abc", 3,
      "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
      "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" },
    { GCRY_MD_SHA384, "abc", 3,
      "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07"
      "\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
      "\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7" },
    { GCRY_MD_SHA512, "abc", 3,
      "\xDD\xAF\x35\xA1\x93\x61\x7A\xBA\xCC\x41\x73\x49\xAE\x20\x41\x31"
      "\x12\xE6\xFA\x4E\x89\xA9\x7E\xA2\x0A\x9E\xEE\xE6\x4B\x55\xD3\x9A"
      "\x21\x92\x99\x2A\x27\x4F\xC1\xA8\x36\xBA\x3C\x23\xA3\xFE\xEB\xBD"
      "\x45\x4D\x44\x23\x64\x3C\xE8\x0E\x2A\x9A\xC9\x4F\xA5\x4C\xA4\x9F" },
    { GCRY_MD_SHA3_256, "abc", 3,
      "\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2\x04\x5c\x17\x2d\x6b\xd3\x90\xbd"
      "\x85\x5f\x08\x6e\x3e\x9d\x52\x5b\x46\xbf\xe2\x45\x11\x43\x15\x32" },
    { GCRY_MD_SHA3_384, "abc", 3,
      "\xec\x01\x49\x82\x88\x51\x6f\xc9\x26\x45\x9f\x58\xe2\xc6\xad\x8d"
      "\xf9\xb4\x73\xcb\x0f\xc0\x8c\x25\x96\xda\x7c\xf0\xe4\x9b\xe4\xb2"
      "\x98\xd8\x8c\xea\x92\x7a\xc7\xf5\x39\xf1\xed\xf2\x28\x37\x6d\x25" },
    { GCRY_MD_SHA3_512, "abc", 3,
      "\xb7\x51\x85\x0b\x1a\x57\x16\x8a\x56\x93\xcd\x92\x4b\x6b\x09\x6e"
      "\x08\xf6\x21\x82\x74\x44\xf7\x0d\x88\x4f\x5d\x02\x40\xd2\x71\x2e"
      "\x10\xe1\x16\xe9\x19\x2a\xf3\xc9\x1a\x7e\xc5\x76\x47\xe3\x93\x40"
      "\x57\x34\x0b\x4c\xf4\x08\xd5\xa5\x65\x92\xf8\x27\x4e\xec\x53\xf0" }
#if USE_RMD160
    ,
    { GCRY_MD_RMD160, "abc", 3,
      "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04"
      "\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc", 1 }
#endif
  };
  int tvidx;
  unsigned char hash[64];
  int expectlen;

  for (tvidx=0; tvidx < DIM(tv); tvidx++)
    {
      gpg_err_code_t ec;

      if (verbose)
        fprintf (stderr, "checking gcry_md_hash_buffer test %d\n",
                 tvidx);

      expectlen = gcry_md_get_algo_dlen (tv[tvidx].algo);
      assert (expectlen != 0);
      assert (expectlen <= sizeof hash);
      gcry_md_hash_buffer (tv[tvidx].algo, hash,
                           tv[tvidx].data, tv[tvidx].datalen);

      ec = gcry_get_fips_service_indicator ();
      if (ec == GPG_ERR_INV_OP)
        {
          /* libgcrypt is old, no support of the FIPS service indicator.  */
          fail ("gcry_md_hash_buffer test %d unexpectedly failed to check the FIPS service indicator.\n",
                tvidx);
          continue;
        }

      if (in_fips_mode && !tv[tvidx].expect_failure && ec)
        {
          /* Success with the FIPS service indicator == 0 expected, but != 0.  */
          fail ("gcry_md_hash_buffer test %d unexpectedly set the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }
      else if (in_fips_mode && tv[tvidx].expect_failure && !ec)
        {
          /* Success with the FIPS service indicator != 0 expected, but == 0.  */
          fail ("gcry_md_hash_buffer test %d unexpectedly cleared the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }

      if (memcmp (hash, tv[tvidx].expect, expectlen))
        {
          int i;

          fail ("gcry_md_hash_buffer test %d failed: mismatch\n", tvidx);
          fputs ("got:", stderr);
          for (i=0; i < expectlen; i++)
            fprintf (stderr, " %02x", hash[i]);
          putc ('\n', stderr);
        }
    }
}

static void
check_hash_buffers (void)
{
  static struct {
    int algo;
    const char *data;
    int datalen;
    const char *key;
    int keylen;
    const char *expect;
    int expect_failure;
  } tv[] = {
#if USE_MD5
    { GCRY_MD_MD5, "abc", 3,
      "key", 3,
      "\xd2\xfe\x98\x06\x3f\x87\x6b\x03\x19\x3a\xfb\x49\xb4\x97\x95\x91", 1 },
#endif
#if USE_SHA1
    { GCRY_MD_SHA1, "abc", 3,
      "key", 3,
      "\x4f\xd0\xb2\x15\x27\x6e\xf1\x2f\x2b\x3e"
      "\x4c\x8e\xca\xc2\x81\x14\x98\xb6\x56\xfc" },
#endif
    { GCRY_MD_SHA256, "abc", 3,
      "key", 3,
      "\x9c\x19\x6e\x32\xdc\x01\x75\xf8\x6f\x4b\x1c\xb8\x92\x89\xd6\x61"
      "\x9d\xe6\xbe\xe6\x99\xe4\xc3\x78\xe6\x83\x09\xed\x97\xa1\xa6\xab" },
    { GCRY_MD_SHA384, "abc", 3,
      "key", 3,
      "\x30\xdd\xb9\xc8\xf3\x47\xcf\xfb\xfb\x44\xe5\x19\xd8\x14\xf0\x74"
      "\xcf\x40\x47\xa5\x5d\x6f\x56\x33\x24\xf1\xc6\xa3\x39\x20\xe5\xed"
      "\xfb\x2a\x34\xba\xc6\x0b\xdc\x96\xcd\x33\xa9\x56\x23\xd7\xd6\x38" },
    { GCRY_MD_SHA512, "abc", 3,
      "key", 3,
      "\x39\x26\xa2\x07\xc8\xc4\x2b\x0c\x41\x79\x2c\xbd\x3e\x1a\x1a\xaa"
      "\xf5\xf7\xa2\x57\x04\xf6\x2d\xfc\x93\x9c\x49\x87\xdd\x7c\xe0\x60"
      "\x00\x9c\x5b\xb1\xc2\x44\x73\x55\xb3\x21\x6f\x10\xb5\x37\xe9\xaf"
      "\xa7\xb6\x4a\x4e\x53\x91\xb0\xd6\x31\x17\x2d\x07\x93\x9e\x08\x7a" },
    { GCRY_MD_SHA3_256, "abc", 3,
      "key", 3,
      "\x09\xb6\xdb\xab\x8d\x11\x79\x5c\xa7\xc8\xd8\x2f\x1c\xf9\x16\x82"
      "\x01\x3c\x7c\xb9\x80\xab\xbb\x25\x47\x3b\xe4\xae\x7f\x7b\x56\x83" },
    { GCRY_MD_SHA3_384, "abc", 3,
      "key", 3,
      "\x94\xf2\xaa\x7a\xe7\xc4\xb7\xb8\xfa\x4c\x61\x2f\xdb\x42\x2b\x33"
      "\x43\x81\x1b\x13\xc8\x88\x82\x57\x90\x4f\x54\x39\x95\xcd\xbc\xba"
      "\x5e\x49\xf1\x0f\x8e\xd6\xf7\xb9\xdd\xc1\xb3\x0b\x38\x28\x81\x5c" },
    { GCRY_MD_SHA3_512, "abc", 3,
      "key", 3,
      "\x08\x5e\x4e\x83\x50\x3f\x40\xb8\x2f\xef\x38\x43\x8b\xc4\x90\x5a"
      "\x55\xdb\xaa\x8c\x88\x78\x09\x7a\x89\x9d\xb0\xb5\x7c\xe7\xda\x57"
      "\xa3\x68\x25\x1c\x34\x47\x4f\x60\xb3\xeb\xac\xb3\x9b\x2e\xda\xca"
      "\x4b\x29\x04\x56\x41\x1c\x76\xec\x7a\xb6\x19\x44\xcf\xe2\x28\x8e" }
#if USE_RMD160
    ,
    { GCRY_MD_RMD160, "abc", 3,
      "key", 3,
      "\x67\xfd\xce\x73\x8e\xbf\xc7\x37\x2b\xcd"
      "\x38\xf0\x3c\x02\x3b\x57\x46\x72\x4d\x18", 1 }
#endif
  };
  int tvidx;
  unsigned char hash[64];
  int expectlen;
  gcry_buffer_t iov[2];
  gpg_error_t err;

  for (tvidx=0; tvidx < DIM(tv); tvidx++)
    {
      gpg_err_code_t ec;

      if (verbose)
        fprintf (stderr, "checking gcry_md_hash_buffers test %d\n",
                 tvidx);

      expectlen = gcry_md_get_algo_dlen (tv[tvidx].algo);
      assert (expectlen != 0);
      assert (expectlen <= sizeof hash);
      memset (iov, 0, sizeof iov);
      iov[0].data = (void *)tv[tvidx].key;
      iov[0].len = tv[tvidx].keylen;
      iov[1].data = (void *)tv[tvidx].data;
      iov[1].len = tv[tvidx].datalen;
      err = gcry_md_hash_buffers (tv[tvidx].algo, GCRY_MD_FLAG_HMAC, hash,
                                  iov, 2);
      if (err)
        {
          fail ("gcry_md_hash_buffers test %d unexpectedly failed\n", tvidx);
          continue;
        }

      ec = gcry_get_fips_service_indicator ();
      if (ec == GPG_ERR_INV_OP)
        {
          /* libgcrypt is old, no support of the FIPS service indicator.  */
          fail ("gcry_md_hash_buffers test %d unexpectedly failed to check the FIPS service indicator.\n",
                tvidx);
          continue;
        }

      if (in_fips_mode && !tv[tvidx].expect_failure && ec)
        {
          /* Success with the FIPS service indicator == 0 expected, but != 0.  */
          fail ("gcry_md_hash_buffers test %d unexpectedly set the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }
      else if (in_fips_mode && tv[tvidx].expect_failure && !ec)
        {
          /* Success with the FIPS service indicator != 0 expected, but == 0.  */
          fail ("gcry_md_hash_buffers test %d unexpectedly cleared the indicator in FIPS mode.\n",
                tvidx);
          continue;
        }

      if (memcmp (hash, tv[tvidx].expect, expectlen))
        {
          int i;

          fail ("gcry_md_hash_buffers test %d failed: mismatch\n", tvidx);
          fputs ("got:", stderr);
          for (i=0; i < expectlen; i++)
            fprintf (stderr, " %02x", hash[i]);
          putc ('\n', stderr);
        }
    }
}


static void
check_kdf_derive (void)
{
  static struct {
    const char *p;   /* Passphrase.  */
    size_t plen;     /* Length of P. */
    int algo;
    int subalgo;
    const char *salt;
    size_t saltlen;
    unsigned long iterations;
    int dklen;       /* Requested key length.  */
    const char *dk;  /* Derived key.  */
    int expect_failure;
  } tv[] = {
    {
      "passwordPASSWORDpassword", 24,
      GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
      "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
      4096,
      25,
      "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8"
      "\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96"
      "\x4c\xf2\xf0\x70\x38",
      0
    },
    {
      "pleaseletmein", 13,
      GCRY_KDF_SCRYPT, 16384,
      "SodiumChloride", 14,
      1,
      64,
      "\x70\x23\xbd\xcb\x3a\xfd\x73\x48\x46\x1c\x06\xcd\x81\xfd\x38\xeb"
      "\xfd\xa8\xfb\xba\x90\x4f\x8e\x3e\xa9\xb5\x43\xf6\x54\x5d\xa1\xf2"
      "\xd5\x43\x29\x55\x61\x3f\x0f\xcf\x62\xd4\x97\x05\x24\x2a\x9a\xf9"
      "\xe6\x1e\x85\xdc\x0d\x65\x1e\x40\xdf\xcf\x01\x7b\x45\x57\x58\x87",
      1 /* not-compliant because unallowed algo */
    },
    {
      "passwor", 7,
      GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
      "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
      4096,
      25,
      "\xf4\x93\xee\x2b\xbf\x44\x0b\x9e\x64\x53"
      "\xc2\xb3\x87\xdc\x73\xf8\xfd\xe6\x97\xda"
      "\xb8\x24\xa0\x26\x50",
      1 /* not-compliant because passphrase len is too small */
    },
    {
      "passwordPASSWORDpassword", 24,
      GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
      "saltSALTsaltSAL", 15,
      4096,
      25,
      "\x14\x05\xa4\x2a\xf4\xa8\x12\x14\x7b\x65"
      "\x8f\xaa\xf0\x7f\x25\xe5\x0f\x0b\x2b\xb7"
      "\xcf\x8d\x29\x23\x4b",
      1 /* not-compliant because salt len is too small */
    },
    {
      "passwordPASSWORDpassword", 24,
      GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
      "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
      999,
      25,
      "\xac\xf8\xb4\x67\x41\xc7\xf3\xd1\xa0\xc0"
      "\x08\xbe\x9b\x23\x96\x78\xbd\x93\xda\x4a"
      "\x30\xd4\xfb\xf0\x33",
      1 /* not-compliant because too few iterations */
    },
    {
      "passwordPASSWORDpassword", 24,
      GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
      "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
      4096,
      13,
      "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8"
      "\xd8\x36\x62",
      1 /* not-compliant because key size too small */
    },
    {
      "passwordPASSWORDpassword", 24,
      GCRY_KDF_PBKDF2, GCRY_MD_BLAKE2B_512,
      "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
      4096,
      60,
      "\xa4\x6b\x53\x35\xdb\xdd\xa3\xd2\x5d\x19\xbb\x11\xfe\xdd\xd9\x9e"
      "\x45\x2a\x7c\x34\x47\x41\x98\xca\x31\x74\xb6\x34\x22\xac\x83\xb0"
      "\x38\x6e\xf5\x93\x0f\xf5\x16\x46\x0b\x97\xdc\x6c\x27\x5b\xe7\x25"
      "\xc2\xcb\xec\x50\x02\xc6\x52\x8b\x34\x68\x53\x65",
      1 /* not-compliant because subalgo is not the one of approved */
    }
  };

  int tvidx;
  gpg_error_t err;
  unsigned char outbuf[100];
  int i;

  for (tvidx=0; tvidx < DIM(tv); tvidx++)
    {
      if (verbose)
        fprintf (stderr, "checking gcry_kdf_derive test vector %d algo %d for FIPS\n",
                 tvidx, tv[tvidx].algo);
      assert (tv[tvidx].dklen <= sizeof outbuf);
      err = gcry_kdf_derive (tv[tvidx].p, tv[tvidx].plen,
                             tv[tvidx].algo, tv[tvidx].subalgo,
                             tv[tvidx].salt, tv[tvidx].saltlen,
                             tv[tvidx].iterations, tv[tvidx].dklen, outbuf);

      if (err)
        {
          fail ("gcry_kdf_derive test %d unexpectedly returned an error in FIPS mode: %s\n",
                tvidx, gpg_strerror (err));
        }
      else
        {
          gpg_err_code_t ec;

          ec = gcry_get_fips_service_indicator ();
          if (ec == GPG_ERR_INV_OP)
            {
              /* libgcrypt is old, no support of the FIPS service indicator.  */
              fail ("gcry_kdf_derive test %d unexpectedly failed to check the FIPS service indicator.\n",
                    tvidx);
              continue;
            }

          if (!tv[tvidx].expect_failure && ec)
            {
              /* Success with the FIPS service indicator == 0 expected, but != 0.  */
              fail ("gcry_kdf_derive test %d unexpectedly set the indicator in FIPS mode.\n",
                    tvidx);
              continue;
            }
          else if (tv[tvidx].expect_failure && !ec && in_fips_mode)
            {
              /* Success with the FIPS service indicator != 0 expected, but == 0.  */
              fail ("gcry_kdf_derive test %d unexpectedly cleared the indicator in FIPS mode.\n",
                    tvidx);
              continue;
            }

          if (memcmp (outbuf, tv[tvidx].dk, tv[tvidx].dklen))
            {
              fail ("gcry_kdf_derive test %d failed: mismatch\n", tvidx);
              fputs ("got:", stderr);
              for (i=0; i < tv[tvidx].dklen; i++)
                fprintf (stderr, " %02x", outbuf[i]);
              putc ('\n', stderr);
            }
        }
    }
}


int
main (int argc, char **argv)
{
  int last_argc = -1;

  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc)
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " [options]\n"
                 "Options:\n"
                 "  --verbose       print timings etc.\n"
                 "  --debug         flyswatter\n",
                 stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        die ("unknown option '%s'", *argv);
    }

  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");

  if (gcry_fips_mode_active ())
    in_fips_mode = 1;

  if (!in_fips_mode)
    xgcry_control ((GCRYCTL_DISABLE_SECMEM, 0));

  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));
  if (debug)
    xgcry_control ((GCRYCTL_SET_DEBUG_FLAGS, 1u , 0));

  check_kdf_derive ();
  check_hash_buffer ();
  check_hash_buffers ();
  check_md_o_w_r_c ();
  check_mac_o_w_r_c ();
  check_cipher_o_s_e_d_c ();

  return !!error_count;
}
