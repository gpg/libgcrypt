/* basic.c  -  basic regression tests
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "../src/gcrypt.h"

static int verbose;
static int error_count;

static void
fail ( const char *format, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, format ) ;
    vfprintf (stderr, format, arg_ptr );
    va_end(arg_ptr);
    error_count++;
}

static void
die ( const char *format, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, format ) ;
    vfprintf (stderr, format, arg_ptr );
    va_end(arg_ptr);
    exit (1);
}

#define MAX_DATA_LEN 100

static void
check_aes128_cbc_cts_cipher ()
{
  char key[128/8] = "chicken teriyaki";
  char plaintext[] = "I would like the General Gau's Chicken, please, and wonton soup.";
  struct tv {
    char out[MAX_DATA_LEN];
    int inlen;
  } tv[] = {
    {  "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f"
      "\x97", 17 },
    { "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22"
      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5", 31 },
    { "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84", 32 },
    { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
      "\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e"
      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5", 47 },
    { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
      "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"
      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8", 48 },
    { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
      "\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40"
      "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8", 64 }
  };
  GCRY_CIPHER_HD hd;
  char out[MAX_DATA_LEN];
  int i;

  hd = gcry_cipher_open (GCRY_CIPHER_AES, 
			 GCRY_CIPHER_MODE_CBC, 
			 GCRY_CIPHER_CBC_CTS);
  if (!hd) {
    fail ("aes-cbc-cts, grcy_open_cipher failed: %s\n", gcry_strerror (-1) );
    return;
  }

  if (gcry_cipher_setkey (hd, key, 128/8)) { 
    fail ("aes-cbc-cts, gcry_cipher_setkey failed: %s\n", gcry_strerror (-1) );
    gcry_cipher_close (hd);
    return;
  }

  for (i = 0; i < sizeof(tv) / sizeof(tv[0]); i++)
    {
      if (gcry_cipher_setiv (hd, NULL, 0)) { 
        fail ("aes-cbc-cts, gcry_cipher_setiv failed: %s\n",
	      gcry_strerror (-1) );
        gcry_cipher_close (hd);
        return;
      }

      if ( gcry_cipher_encrypt (hd, out, MAX_DATA_LEN, 
				plaintext, tv[i].inlen)) { 
	fail ("aes-cbc-cts, gcry_cipher_encrypt failed: %s\n",
	      gcry_strerror (-1) );
	gcry_cipher_close (hd);
	return;
      }

      if ( memcmp (tv[i].out, out, tv[i].inlen) )
        fail ("aes-cbc-cts, encrypt mismatch entry %d\n", i);

      if (gcry_cipher_setiv (hd, NULL, 0)) { 
        fail ("aes-cbc-cts, gcry_cipher_setiv failed: %s\n",
	      gcry_strerror (-1) );
        gcry_cipher_close (hd);
        return;
      }
      if ( gcry_cipher_decrypt (hd, out, tv[i].inlen, NULL, 0)) { 
	fail ("aes-cbc-cts, gcry_cipher_decrypt failed: %s\n",
	      gcry_strerror (-1) );
	gcry_cipher_close (hd);
	return;
      }

      if ( memcmp (plaintext, out, tv[i].inlen) )
        fail ("aes-cbc-cts, decrypt mismatch entry %d\n", i);
    }

  gcry_cipher_close (hd);
}

static void
check_one_cipher (int algo, int mode, int flags)
{
    GCRY_CIPHER_HD hd;
    char key[32], plain[16], in[16], out[16];
    int keylen;

    memcpy (key, "0123456789abcdef.,;/[]{}-=ABCDEF", 32);
    memcpy (plain, "foobar42FOOBAR17", 16);

    keylen = gcry_cipher_get_algo_keylen (algo);
    if (keylen < 40/8 || keylen > 32 ) {
        fail ("algo %d, mode %d, keylength problem (%d)\n",
              algo, mode, keylen );
        return;
    }

    hd = gcry_cipher_open (algo, mode, flags);
    if (!hd) {
        fail ("algo %d, mode %d, grcy_open_cipher failed: %s\n",
              algo, mode, gcry_strerror (-1) );
        return;
    }

    
    if (gcry_cipher_setkey (hd, key, keylen)) { 
        fail ("algo %d, mode %d, gcry_cipher_setkey failed: %s\n",
              algo, mode, gcry_strerror (-1) );
        gcry_cipher_close (hd);
        return;
    }
    
    if ( gcry_cipher_encrypt (hd, out, 16, plain, 16)) { 
        fail ("algo %d, mode %d, gcry_cipher_encrypt failed: %s\n",
              algo, mode, gcry_strerror (-1) );
        gcry_cipher_close (hd);
        return;
    }

    gcry_cipher_close (hd);
    hd = gcry_cipher_open (algo, mode, flags);
    if (!hd) {
        fail ("algo %d, mode %d, grcy_open_cipher failed: %s\n",
              algo, mode, gcry_strerror (-1) );
        return;
    }

    if (gcry_cipher_setkey (hd, key, keylen)) { 
        fail ("algo %d, mode %d, gcry_cipher_setkey[2] failed: %s\n",
              algo, mode, gcry_strerror (-1) );
        gcry_cipher_close (hd);
        return;
    }
    
    if ( gcry_cipher_decrypt (hd, in, 16, out, 16)) { 
        fail ("algo %d, mode %d, gcry_cipher_decrypt failed: %s\n",
              algo, mode, gcry_strerror (-1) );
        gcry_cipher_close (hd);
        return;
    }

    gcry_cipher_close (hd);

    if ( memcmp (plain, in, 16) )
        fail ("algo %d, mode %d, encrypt-decrypt mismatch\n", algo, mode);
}


static void
check_ciphers (void)
{
  static int algos[] = {
    GCRY_CIPHER_3DES,
    GCRY_CIPHER_CAST5,
    GCRY_CIPHER_BLOWFISH,
    GCRY_CIPHER_AES,
    GCRY_CIPHER_AES192,
    GCRY_CIPHER_AES256,
    GCRY_CIPHER_TWOFISH,
    GCRY_CIPHER_DES,
    0
  };
  static int algos2[] = {
    GCRY_CIPHER_ARCFOUR,
    0
  };
  int i;

  for (i=0; algos[i]; i++ ) 
    {
      if (verbose)
        fprintf (stderr, "checking `%s'\n", gcry_cipher_algo_name (algos[i]));
                 
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_ECB, 0);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CFB, 0);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CBC, 0);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    }

  for (i=0; algos2[i]; i++ ) 
    {
      if (verbose)
        fprintf (stderr, "checking `%s'\n", gcry_cipher_algo_name (algos2[i]));
                 
      check_one_cipher (algos2[i], GCRY_CIPHER_MODE_STREAM, 0);
    }
  /* we have now run all cipher's selftests */

  /* TODO: add some extra encryption to test the higher level functions */
}

static void
check_one_md (int algo, char *data, int len, char *expect)
{
    GCRY_MD_HD hd;
    char *p;
    int mdlen;

    hd = gcry_md_open (algo, 0);
    if (!hd) {
        fail ("algo %d, grcy_md_open failed: %s\n",
              algo, gcry_strerror (-1) );
        return;
    }

    mdlen = gcry_md_get_algo_dlen(algo);
    if (mdlen < 1 || mdlen > 500) {
        fail ("algo %d, grcy_md_get_algo_dlen failed: %d\n", algo, mdlen);
        return;
    }
    
    gcry_md_write (hd, data, len);

    p = gcry_md_read (hd, algo);

    if ( memcmp (p, expect, mdlen) )
        fail ("algo %d, digest mismatch\n", algo);

    gcry_md_close (hd);
}

static void
check_digests ()
{
  static struct algos {
    int md;
    char *data;
    char *expect;
  } algos[] = {
    { GCRY_MD_MD4, "",
      "\x31\xD6\xCF\xE0\xD1\x6A\xE9\x31\xB7\x3C\x59\xD7\xE0\xC0\x89\xC0" },
    { GCRY_MD_MD4, "a",
      "\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24" },
    { GCRY_MD_MD4, "message digest",
      "\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b" },
    { GCRY_MD_MD5, "",
      "\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\x09\x98\xEC\xF8\x42\x7E" },
    { GCRY_MD_MD5, "a", 
      "\x0C\xC1\x75\xB9\xC0\xF1\xB6\xA8\x31\xC3\x99\xE2\x69\x77\x26\x61" },
    { GCRY_MD_MD5, "abc",
      "\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72" },
    { GCRY_MD_MD5, "message digest", 
      "\xF9\x6B\x69\x7D\x7C\xB7\x93\x8D\x52\x5A\x2F\x31\xAA\xF1\x61\xD0"},
    { GCRY_MD_SHA1, "abc",
      "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E"
      "\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D"},
    { GCRY_MD_SHA1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE"
      "\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1" },
    { GCRY_MD_RMD160, "",
      "\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28"
      "\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31" },
    { GCRY_MD_RMD160, "a",
      "\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae"
      "\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe" },
    { GCRY_MD_RMD160, "abc",
      "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04"
      "\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc" },
    { GCRY_MD_RMD160, "message digest",
      "\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8"
      "\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36" },
#if 0
    { GCRY_MD_TIGER, "",
      "\x24\xF0\x13\x0C\x63\xAC\x93\x32\x16\x16\x6E\x76"
      "\xB1\xBB\x92\x5F\xF3\x73\xDE\x2D\x49\x58\x4E\x7A" },
    { GCRY_MD_TIGER, "abc",
      "\xF2\x58\xC1\xE8\x84\x14\xAB\x2A\x52\x7A\xB5\x41"
      "\xFF\xC5\xB8\xBF\x93\x5F\x7B\x95\x1C\x13\x29\x51" },
    { GCRY_MD_TIGER, "Tiger",
      "\x9F\x00\xF5\x99\x07\x23\x00\xDD\x27\x6A\xBB\x38"
      "\xC8\xEB\x6D\xEC\x37\x79\x0C\x11\x6F\x9D\x2B\xDF" },
    { GCRY_MD_TIGER, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"
      "hijklmnopqrstuvwxyz0123456789+-",
      "\x87\xFB\x2A\x90\x83\x85\x1C\xF7\x47\x0D\x2C\xF8"
      "\x10\xE6\xDF\x9E\xB5\x86\x44\x50\x34\xA5\xA3\x86" },
    { GCRY_MD_TIGER, "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdef"
      "ghijklmnopqrstuvwxyz+0123456789",
      "467DB80863EBCE488DF1CD1261655DE957896565975F9197" },
    { GCRY_MD_TIGER, "Tiger - A Fast New Hash Function, "
      "by Ross Anderson and Eli Biham",
      "0C410A042968868A1671DA5A3FD29A725EC1E457D3CDB303" },
    { GCRY_MD_TIGER, "Tiger - A Fast New Hash Function, "
      "by Ross Anderson and Eli Biham, proceedings of Fa"
      "st Software Encryption 3, Cambridge.",
      "EBF591D5AFA655CE7F22894FF87F54AC89C811B6B0DA3193" },
    { GCRY_MD_TIGER, "Tiger - A Fast New Hash Function, "
      "by Ross Anderson and Eli Biham, proceedings of Fa"
      "st Software Encryption 3, Cambridge, 1996.",
      "3D9AEB03D1BD1A6357B2774DFD6D5B24DD68151D503974FC" },
    { GCRY_MD_TIGER, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
      "ijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRS"
      "TUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
      "00B83EB4E53440C5 76AC6AAEE0A74858 25FD15E70A59FFE4" },
#endif
    { 0 }
  };
  int i;

  for (i=0; algos[i].md; i++ ) 
    {
      if (verbose)
        fprintf (stderr, "checking `%s'\n", gcry_md_algo_name (algos[i].md));
                 
      check_one_md (algos[i].md, algos[i].data, strlen(algos[i].data), 
		    algos[i].expect);
    }

  /* TODO: test HMAC mode */
}


int
main (int argc, char **argv)
{
  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;

  /*gcry_control (GCRYCTL_DISABLE_INTERNAL_LOCKING, NULL, 0);*/
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  check_ciphers ();
  check_aes128_cbc_cts_cipher ();
  check_digests ();
  
  return error_count? 1:0;
}


