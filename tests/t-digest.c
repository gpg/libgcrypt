/* t-digest.c - MD regression tests
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

#define PGM "t-digest"

#include "t-common.h"
static int in_fips_mode;

/* Mingw requires us to include windows.h after winsock2.h which is
   included by gcrypt.h.  */
#ifdef _WIN32
# include <windows.h>
#endif

static void
check_digests (void)
{
  static struct {
    int algo;
    const char *data;
    int datalen;
    const char *expect;
    int expect_failure;
  } tv[] = {
#undef ENABLE_THIS_AFTER_T6376_CHANGE_REVISED
#ifdef ENABLE_THIS_AFTER_T6376_CHANGE_REVISED
    { GCRY_MD_MD5, "abc", 3,
      "\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72", 1 },
#endif
    { GCRY_MD_SHA1, "abc", 3,
      "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E"
      "\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D" },
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
      "\x57\x34\x0b\x4c\xf4\x08\xd5\xa5\x65\x92\xf8\x27\x4e\xec\x53\xf0" },
    { GCRY_MD_RMD160, "abc", 3,
      "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04"
      "\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc", 1 },
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

  check_digests ();

  return !!error_count;
}
