/* hmac-tests.c - HMAC selftests.
 * Copyright (C) 2008 Free Software Foundation, Inc.
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

/* 
   Although algorithm self-tests are usually implemented in the module
   implementing the algorithm, the case for HMAC is different because
   HMAC is implemnetd on a higher level using a special feature of the
   gcry_md_ functions.  It would be possible to do this also in the
   digest algorithm modules, but that would blow up the code too much
   and spread the hmac tests over several modules.

    Thus we implement all HMAC tests in this test module and provide a
    function to run the tests.
*/

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDINT_H 
# include <stdint.h>
#endif

#include "g10lib.h"
#include "cipher.h"
#include "hmac256.h"

/* Check one HMAC with digest ALGO using the regualr HAMC
   API. (DATA,DATALEN) is the data to be MACed, (KEY,KEYLEN) the key
   and (EXPECT,EXPECTLEN) the expected result.  Returns NULL on
   succdess or a string describing the failure.  */
static const char *
check_one (int algo,
           const void *data, size_t datalen, 
           const void *key, size_t keylen,
           const void *expect, size_t expectlen)
{
  gcry_md_hd_t hd;
  const unsigned char *digest;

  if (_gcry_md_get_algo_dlen (algo) != expectlen)
    return "invalid tests data";
  if (_gcry_md_open (&hd, algo, GCRY_MD_FLAG_HMAC))
    return "gcry_md_open failed";
  if (_gcry_md_setkey (hd, key, keylen))
    {
      _gcry_md_close (hd);
      return "gcry_md_setkey failed";
    }
  _gcry_md_write (hd, data, datalen);
  digest = _gcry_md_read (hd, algo);
  if (!digest)
    {
      _gcry_md_close (hd);
      return "gcry_md_read failed";
    }
  if (memcmp (digest, expect, expectlen))
    {
      _gcry_md_close (hd);
      return "does not match";
    }
  _gcry_md_close (hd);
  return NULL;  
}


static gpg_err_code_t
selftests_sha1 (selftest_report_func_t report)
{
  static struct 
  {
    const char * const desc;
    const char * const data;
    const char * const key;
    const char expect[20];
  } tv[] =
    {
      { NULL }
    };
  const char *what;
  const char *errtxt;
  int tvidx;
  
  for (tvidx=0; tv[tvidx].desc; tvidx++)
    {
      what = tv[tvidx].desc;
      errtxt = check_one (GCRY_MD_SHA1,
                          tv[tvidx].data, strlen (tv[tvidx].data),
                          tv[tvidx].key, strlen (tv[tvidx].key),
                          tv[tvidx].expect, DIM (tv[tvidx].expect) );
      if (errtxt)
        goto failed;
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("hmac", GCRY_MD_SHA1, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}



static gpg_err_code_t
selftests_sha224 (selftest_report_func_t report)
{
  static struct 
  {
    const char * const desc;
    const char * const data;
    const char * const key;
    const char expect[28];
  } tv[] =
    {
      { NULL }
    };
  const char *what;
  const char *errtxt;
  int tvidx;
  
  for (tvidx=0; tv[tvidx].desc; tvidx++)
    {
      what = tv[tvidx].desc;
      errtxt = check_one (GCRY_MD_SHA224,
                          tv[tvidx].data, strlen (tv[tvidx].data),
                          tv[tvidx].key, strlen (tv[tvidx].key),
                          tv[tvidx].expect, DIM (tv[tvidx].expect) );
      if (errtxt)
        goto failed;
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("hmac", GCRY_MD_SHA224, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}


static gpg_err_code_t
selftests_sha256 (selftest_report_func_t report)
{
  static struct 
  {
    const char * const desc;
    const char * const data;
    const char * const key;
    const char expect[32];
  } tv[] =
    {
      { "data-28 key-4",
        "what do ya want for nothing?", 
        "Jefe",
	{ 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
          0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
          0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
          0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43 } },

      { "data-9 key-20",
        "Hi There",
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b\x0b",
        { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
          0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
          0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
          0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 } },

      { "data-50 key-20",
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
        "\xdd\xdd",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa",
        { 0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
          0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
          0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
          0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe } },

      { "data-50 key-26",
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd",
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        "\x11\x12\x13\x14\x15\x16\x17\x18\x19",
	{ 0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e,
          0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
          0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
          0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b } },

      { "data-54 key-131",
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
	{ 0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
          0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
          0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
          0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54 } },

      { "data-152 key-131",
        "This is a test using a larger than block-size key and a larger "
        "than block-size data. The key needs to be hashed before being "
        "used by the HMAC algorithm.",
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa",
	{ 0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb,
          0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
          0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
          0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2 } },

      { NULL }
    };
  const char *what;
  const char *errtxt;
  int tvidx;
  
  for (tvidx=0; tv[tvidx].desc; tvidx++)
    {
      hmac256_context_t hmachd;
      const unsigned char *digest;
      size_t dlen;

      what = tv[tvidx].desc;
      errtxt = check_one (GCRY_MD_SHA256,
                          tv[tvidx].data, strlen (tv[tvidx].data),
                          tv[tvidx].key, strlen (tv[tvidx].key),
                          tv[tvidx].expect, DIM (tv[tvidx].expect) );
      if (errtxt)
        goto failed;

      hmachd = _gcry_hmac256_new (tv[tvidx].key, strlen (tv[tvidx].key));
      if (!hmachd)
        {
          errtxt = "_gcry_hmac256_new failed";
          goto failed;
        }
      _gcry_hmac256_update (hmachd, tv[tvidx].data, strlen (tv[tvidx].data));
      digest = _gcry_hmac256_finalize (hmachd, &dlen);
      if (!digest)
        {
          errtxt = "_gcry_hmac256_finalize failed";
          _gcry_hmac256_release (hmachd);
          goto failed;
        }
      if (dlen != DIM (tv[tvidx].expect)
          || memcmp (digest, tv[tvidx].expect, DIM (tv[tvidx].expect)))
        {
          errtxt = "does not match in second implementation";
          _gcry_hmac256_release (hmachd);
          goto failed;
        }
      _gcry_hmac256_release (hmachd);
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("hmac", GCRY_MD_SHA256, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}


static gpg_err_code_t
selftests_sha384 (selftest_report_func_t report)
{
  static struct 
  {
    const char * const desc;
    const char * const data;
    const char * const key;
    const char expect[48];
  } tv[] =
    {
      { NULL }
    };
  const char *what;
  const char *errtxt;
  int tvidx;
  
  for (tvidx=0; tv[tvidx].desc; tvidx++)
    {
      what = tv[tvidx].desc;
      errtxt = check_one (GCRY_MD_SHA384,
                          tv[tvidx].data, strlen (tv[tvidx].data),
                          tv[tvidx].key, strlen (tv[tvidx].key),
                          tv[tvidx].expect, DIM (tv[tvidx].expect) );
      if (errtxt)
        goto failed;
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("hmac", GCRY_MD_SHA384, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}


static gpg_err_code_t
selftests_sha512 (selftest_report_func_t report)
{
  static struct 
  {
    const char * const desc;
    const char * const data;
    const char * const key;
    const char expect[64];
  } tv[] =
    {
      { NULL }
    };
  const char *what;
  const char *errtxt;
  int tvidx;
  
  for (tvidx=0; tv[tvidx].desc; tvidx++)
    {
      what = tv[tvidx].desc;
      errtxt = check_one (GCRY_MD_SHA512,
                          tv[tvidx].data, strlen (tv[tvidx].data),
                          tv[tvidx].key, strlen (tv[tvidx].key),
                          tv[tvidx].expect, DIM (tv[tvidx].expect) );
      if (errtxt)
        goto failed;
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("hmac", GCRY_MD_SHA512, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}



/* Run a full self-test for ALGO and return 0 on success.  */
static gpg_err_code_t
run_selftests (int algo, selftest_report_func_t report)
{
  gpg_err_code_t ec;

  switch (algo)
    {
    case GCRY_MD_SHA1:
      ec = selftests_sha1 (report);
      break;
    case GCRY_MD_SHA224:
      ec = selftests_sha224 (report);
      break;
    case GCRY_MD_SHA256:
      ec = selftests_sha256 (report);
      break;
    case GCRY_MD_SHA384:
      ec = selftests_sha384 (report);
      break;
    case GCRY_MD_SHA512:
      ec = selftests_sha512 (report);
      break;
    default:
      ec = GPG_ERR_DIGEST_ALGO;
      break;
    }
  return ec;
}




/* Run the selftests for HMAC with digest algorithm ALGO with optional
   reporting function REPORT.  */
gpg_error_t
_gcry_hmac_selftest (int algo, selftest_report_func_t report)
{
  gcry_err_code_t ec = 0;

  if (!gcry_md_test_algo (algo))
    {
      ec = run_selftests (algo, report);
    }
  else
    {
      ec = GPG_ERR_DIGEST_ALGO;
      if (report)
        report ("hmac", algo, "module", "algorithm not available");
    }
  return gpg_error (ec);
}
