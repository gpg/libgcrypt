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


static const char sample_private_key_1[] =
"(private-key\n"
" (rsa\n"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)\n"
"  (e #010001#)\n"
"  (d #046129F2489D71579BE0A75FE029BD6CDB574EBF57EA8A5B0FDA942CAB943B11"
      "7D7BB95E5D28875E0F9FC5FCC06A72F6D502464DABDED78EF6B716177B83D5BD"
      "C543DC5D3FED932E59F5897E92E6F58A0F33424106A3B6FA2CBF877510E4AC21"
      "C3EE47851E97D12996222AC3566D4CCB0B83D164074ABF7DE655FC2446DA1781#)\n"
"  (p #00e861b700e17e8afe6837e7512e35b6ca11d0ae47d8b85161c67baf64377213"
      "fe52d772f2035b3ca830af41d8a4120e1c1c70d12cc22f00d28d31dd48a8d424f1#)\n"
"  (q #00f7a7ca5367c661f8e62df34f0d05c10c88e5492348dd7bddc942c9a8f369f9"
      "35a07785d2db805215ed786e4285df1658eed3ce84f469b81b50d358407b4ad361#)\n"
"  (u #304559a9ead56d2309d203811a641bb1a09626bc8eb36fffa23c968ec5bd891e"
      "ebbafc73ae666e01ba7c8990bae06cc2bbe10b75e69fcacb353a6473079d8e9b#)\n"
" )\n"
")\n";
static const char sample_public_key_1[] =
"(public-key\n"
" (rsa\n"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)\n"
"  (e #010001#)\n"
" )\n"
")\n";
static const unsigned char sample_grip_key_1[] =
"\x32\x10\x0c\x27\x17\x3e\xf6\xe9\xc4\xe9"
"\xa2\x5d\x3d\x69\xf8\x6d\x37\xa4\xf9\x39";


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
    int i;

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

    if (*data == '!' && !data[1])
      { /* hash one million times a "a" */
        char aaa[1000];
        
        memset (aaa, 'a', 1000);
        for (i=0; i < 1000; i++)
          gcry_md_write (hd, aaa, 1000);
      }
    else
      gcry_md_write (hd, data, len);

    p = gcry_md_read (hd, algo);

    if ( memcmp (p, expect, mdlen) )
      {
	printf("computed: ");
	for (i=0; i < mdlen; i++)
	  printf("%02x ", p[i] & 0xFF);
	printf("\nexpected: ");
	for (i=0; i < mdlen; i++)
	  printf("%02x ", expect[i] & 0xFF);
	printf("\n");

	fail ("algo %d, digest mismatch\n", algo);
      }

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
    { GCRY_MD_SHA1, "!" /* kludge for "a"*1000000 */,
      "\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E"
      "\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F" },
    { GCRY_MD_SHA256, "abc",
      "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
      "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" },
    { GCRY_MD_SHA256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
      "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
    { GCRY_MD_SHA256, "!",
      "\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67" 
      "\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0" },
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
    { GCRY_MD_CRC32, "",
      "\x00\x00\x00\x00" },
    { GCRY_MD_CRC32, "foo",
      "\x8c\x73\x65\x21" },
    { GCRY_MD_CRC32_RFC1510, "",
      "\x00\x00\x00\x00" },
    { GCRY_MD_CRC32_RFC1510, "foo",
      "\x73\x32\xbc\x33" }, 
    { GCRY_MD_CRC32_RFC1510, "test0123456789",
      "\xb8\x3e\x88\xd6" },
    { GCRY_MD_CRC32_RFC1510, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
      "\xe3\x41\x80\xf7" },
#if 0
    { GCRY_MD_CRC32_RFC1510, "\x80\x00",
      "\x3b\x83\x98\x4b" },
    { GCRY_MD_CRC32_RFC1510, "\x00\x08",
      "\x0e\xdb\x88\x32" },
    { GCRY_MD_CRC32_RFC1510, "\x00\x80",
      "\xed\xb8\x83\x20" },
#endif
    { GCRY_MD_CRC32_RFC1510, "\x80",
      "\xed\xb8\x83\x20" },
#if 0
    { GCRY_MD_CRC32_RFC1510, "\x80\x00\x00\x00",
      "\xed\x59\xb6\x3b" },
    { GCRY_MD_CRC32_RFC1510, "\x00\x00\x00\x01",
      "\x77\x07\x30\x96" },
#endif
    { GCRY_MD_CRC24_RFC2440, "",
      "\xb7\x04\xce" },
    { GCRY_MD_CRC24_RFC2440, "foo",
      "\x4f\xc2\x55" },
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

/* Check that the signature SIG matches the hash HASH. PKEY is the
   public key used for the verification. BADHASH is a hasvalue which
   should; result in a bad signature status. */
static void
verify_one_signature (GcrySexp pkey, GcrySexp hash,
                      GcrySexp badhash, GcrySexp sig)
{
  int rc;

  rc = gcry_pk_verify (sig, hash, pkey);
  if (rc)
    fail ("gcry_pk_verify failed: %s\n", gcry_strerror (rc));
  rc = gcry_pk_verify (sig, badhash, pkey);
  if (rc != GCRYERR_BAD_SIGNATURE)
    fail ("gcry_pk_verify failed to detect a bad signature: %s\n",
          gcry_strerror (rc));
}


/* Test the public key sign function using the private ket SKEY. PKEY
   is used for verification. */
static void
check_pubkey_sign (GcrySexp skey, GcrySexp pkey)
{
  int rc;
  GcrySexp sig, badhash, hash;
  int dataidx;
  static const char baddata[] =
    "(data\n (flags pkcs1)\n"
    " (hash sha1 #11223344556677889900AABBCCDDEEFF10203041#))\n";
  static struct { const char *data; int expected_rc; } datas[] = {
    { "(data\n (flags pkcs1)\n"
      " (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
      0 },
    { "(data\n (flags )\n"
      " (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
      GCRYERR_CONFLICT },

    { "(data\n (flags pkcs1)\n"
      " (hash foo #11223344556677889900AABBCCDDEEFF10203040#))\n",
      GCRYERR_INV_MD_ALGO },

    { "(data\n (flags )\n"
      " (value #11223344556677889900AA#))\n",
      0 },

    { "(data\n (flags raw)\n"
      " (value #11223344556677889900AA#))\n",
      0 },

    { "(data\n (flags pkcs1)\n"
      " (value #11223344556677889900AA#))\n",
      GCRYERR_CONFLICT },

    { "(data\n (flags raw foo)\n"
      " (value #11223344556677889900AA#))\n",
      GCRYERR_INV_FLAG },
    
    { NULL }
  };

  rc = gcry_sexp_sscan (&badhash, NULL, baddata, strlen (baddata));
  if (rc)
      die ("converting data failed: %s\n", gcry_strerror (rc));
      
  for (dataidx=0; datas[dataidx].data; dataidx++)
    {
      if (verbose)
        fprintf (stderr, "signature test %d\n", dataidx);

      rc = gcry_sexp_sscan (&hash, NULL, datas[dataidx].data,
                            strlen (datas[dataidx].data));
      if (rc)
        die ("converting data failed: %s\n", gcry_strerror (rc));
  
      rc = gcry_pk_sign (&sig, hash, skey);
      if (rc != datas[dataidx].expected_rc)
        fail ("gcry_pk_sign failed: %s\n", gcry_strerror (rc));
      
      if (!rc)
        verify_one_signature (pkey, hash, badhash, sig);

      gcry_sexp_release (sig); sig= NULL;
      gcry_sexp_release (hash); hash= NULL;
    }

  gcry_sexp_release (badhash);
}

/* Run all tests for the public key fucntions. */
static void
check_pubkey (void)
{
  int rc;
  GcrySexp skey, pkey;
  unsigned char grip1[20], grip2[20];
  
  rc = gcry_sexp_sscan (&skey, NULL, sample_private_key_1,
                        strlen (sample_private_key_1));
  if (!rc)
    rc = gcry_sexp_sscan (&pkey, NULL, sample_public_key_1,
                          strlen (sample_public_key_1));
  if (rc)
    die ("converting sample key failed: %s\n", gcry_strerror (rc));

  if (!gcry_pk_get_keygrip (pkey, grip1))
    die ("get keygrip for public RSA key failed\n");
  if (!gcry_pk_get_keygrip (skey, grip2))
    die ("get keygrip for private RSA key failed\n");
  if (memcmp (grip1, grip2, 20))
    fail ("keygrips for RSA key don't match\n");
  if (memcmp (grip1, sample_grip_key_1, 20))
    fail ("wrong keygrip for RSA key\n");

  /* FIXME: we need DSA and ElGamal example keys. */

/*    for (rc=0; rc < 20; rc++) */
/*      printf ("\\x%02x", grip1[rc]); */
/*    putchar ('\n'); */

  check_pubkey_sign (skey, pkey);

  gcry_sexp_release (skey);
  gcry_sexp_release (pkey);
}



int
main (int argc, char **argv)
{
  int debug = 0;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  /*gcry_control (GCRYCTL_DISABLE_INTERNAL_LOCKING,0);*/
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);
  check_ciphers ();
  check_aes128_cbc_cts_cipher ();
  check_digests ();
  check_pubkey ();
  
  return error_count? 1:0;
}
