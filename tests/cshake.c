/* cshake.c  -  cSHAKE xof hash regression tests
 * Copyright (C) 2001, 2002, 2003, 2005, 2008,
 *               2009 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
 * Copyright (C) 2023 MTG AG
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
#ifdef HAVE_STDINT_H
#include <stdint.h> /* uintptr_t */
#elif defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#else
/* In this case, uintptr_t is provided by config.h. */
#endif

// #include "../src/gcrypt-int.h"
// #include "../src/gcrypt-testapi.h"

#define PGM "cSHAKE"
#include "t-common.h"
#include "gcrypt.h"

#if __GNUC__ >= 4
#define ALWAYS_INLINE __attribute__ ((always_inline))
#else
#define ALWAYS_INLINE
#endif

typedef struct
{

  enum gcry_md_algos algo;
  const char *data_hex;
  const char *n;
  const char *s;
  unsigned output_size_bytes;
  const char *expected_output_hex;

} test_vec_t;

test_vec_t test_vecs[] = {

  { /* from
       https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
     */
    GCRY_MD_CSHAKE128,
    "00010203",
    "",
    "Email Signature",
    32,
    "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5" },
  { /* from
       https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
     */
    GCRY_MD_CSHAKE128,
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222"
    "32"
    "425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454647"
    "48"
    "494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6"
    "C6"
    "D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90"
    "91"
    "92939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B"
    "5B"
    "6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
    "",
    "Email Signature",
    32,
    "C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B" },

  { /* from
       https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
     */
    GCRY_MD_CSHAKE256,
    "00010203",
    "",
    "Email Signature",
    64,
    "D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD164020E2"
    "BE"
    "0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C" },

  { /* from
       https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
     */
    GCRY_MD_CSHAKE256,
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222"
    "32"
    "425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454647"
    "48"
    "494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6"
    "C6"
    "D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90"
    "91"
    "92939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B"
    "5B"
    "6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
    "",
    "Email Signature",
    64,
    "07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC86430273091727F42B1"
    "7ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB" },
  { /* Created with https://asecuritysite.com/golang/cs */
    GCRY_MD_CSHAKE128,
    "00010203",
    "ABC",
    "Email Signature",
    32,
    "5CF74DC523ADC0B97EC3614E703835277E9F818879AA1EAE5B2B4E4472EB6A68" },
  { /* Created with https://asecuritysite.com/golang/cs */
    GCRY_MD_CSHAKE256,
    "00010203",
    "ABC",
    "Email Signature",
    32,
    "0C34C14C4A56E5FC01BE8C04C759DA61437E86B88DF3E21A934436D427A85E9D" },
  { /* Created with https://asecuritysite.com/golang/cs */
    GCRY_MD_CSHAKE128,
    "00010203",
    "ABC",
    "",
    32,
    "266035DF0BEC07A61073571CB3DEB195002955D8A7C88B821A0B1D20ECAC6B5B" },
  { /* Created with https://asecuritysite.com/golang/cs */
    GCRY_MD_CSHAKE256,
    "00010203",
    "ABC",
    "",
    32,
    "89D888D030A5CF82CAFB3D9D2B7869C91B46D186700306265606CC97D3DAE42A" }
};


static void *
hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = xmalloc (strlen (string) / 2 + 1);
  length = 0;
  for (s = string; *s; s += 2)
    {
      if (!hexdigitp (s) || !hexdigitp (s + 1))
        die ("invalid hex digits in \"%s\"\n", string);
      ((unsigned char *)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


int
main (int argc, char **argv)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  int last_argc   = -1;

  unsigned test_cnt = 0;

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
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--;
          argv++;
        }
    }
  for (unsigned i = 0; i < DIM (test_vecs); i++)
    {
      gcry_md_hd_t hd, hd2;
      enum gcry_md_algos algo = test_vecs[i].algo;
      test_vec_t *test        = &test_vecs[i];
      unsigned char result_buf[256];
      unsigned char result_buf2[256];
      void *compare_buf, *data_buf;
      size_t compare_len, data_len;
      /* vary the secure flag in each test */
      int flags = i % 2 ? GCRY_MD_FLAG_SECURE : 0;
      err       = gcry_md_open (&hd, algo, flags);
      if (err)
        {
          fail (
              "algo %d, gcry_md_open failed: %s\n", algo, gpg_strerror (err));
          goto leave;
        }
      if (strlen (test->n))
        {
          err = gcry_md_ctl(
              hd, GCRYCTL_CSHAKE_N, (unsigned char*) test->n, strlen (test->n));
          if (err)
            {
              fail ("algo %d, gcry_md_set_add_input (N) failed: %s\n",
                    algo,
                    gpg_strerror (err));
              goto leave;
            }
        }
      if (strlen (test->s))
        {
          err = gcry_md_ctl(
              hd, GCRYCTL_CSHAKE_S, (unsigned char*) test->s, strlen (test->s));
          if (err)
            {
              fail ("algo %d, gcry_md_set_add_input (S) failed: %s\n",
                    algo,
                    gpg_strerror (err));
              goto leave;
            }
        }
      {
        gcry_err_code_t exp_err = GPG_ERR_INV_STATE;
        if (strlen (test->n))
          {
            /* try to set n or s again */
            exp_err = gcry_md_ctl(
                hd, GCRYCTL_CSHAKE_N, (unsigned char*) test->n, strlen (test->n));
          }
        else if (strlen (test->s))
          {
            exp_err = gcry_md_ctl(
                hd, GCRYCTL_CSHAKE_S, (unsigned char*) test->s, strlen (test->s));
          }

        if (exp_err != gpg_error(GPG_ERR_INV_STATE))
          {
            fail ("algo %d: wrong error code when setting additional "
                  "input in wrong order: "
                  "%d (%s), but "
                  "expected %d (%s)\n",
                  algo,
                  exp_err,
                  gpg_strerror (exp_err),
                  gpg_error(GPG_ERR_INV_STATE),
                  gpg_strerror (GPG_ERR_INV_STATE));
          }
      }
      data_buf = hex2buffer (test->data_hex, &data_len);
      gcry_md_write (hd, data_buf, data_len);
      err = gcry_md_copy (&hd2, hd);
      if (err)
        {
          fail ("algo %d, problem with copying of hash context object\n",
                algo);
        }
      else
        {
          gcry_md_extract (hd2, algo, result_buf2, test->output_size_bytes);
        }
      gcry_md_extract (hd, algo, result_buf, test->output_size_bytes);
      if (!err)
        {
          if (memcmp (result_buf, result_buf2, test->output_size_bytes))
            {
              fail ("algo %d, result comparison with that copied of copied MD "
                    "CTX object failed in test %u\n",
                    algo,
                    i);
            }
        }
      /* restore the clean error state after the copy operation */
      err         = GPG_ERR_NO_ERROR;
      compare_buf = hex2buffer (test->expected_output_hex, &compare_len);
      test_cnt++;
      if (compare_len != test->output_size_bytes)
        {
          fail ("algo %d, internal problem with test data lengths\n", algo);
          goto leave;
        }
      if (memcmp (compare_buf, result_buf, test->output_size_bytes))
        {

          fail ("algo %d, result comparison failed in test %u\n", algo, i);
        }
      xfree (compare_buf);
      xfree (data_buf);
      gcry_md_close (hd);
      gcry_md_close (hd2);
    }


  if (verbose)
    fprintf (stderr, "\nAll %u tests completed. \n", test_cnt);
  if (error_count || verbose)
    {
      fprintf (stderr, "\nThere were %i errors\n", error_count);
    }
leave:
  return err;
}
