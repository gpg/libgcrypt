/* basic.c  -  basic regression tests
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
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


static void
check_one_cipher (int algo, int mode)
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

    hd = gcry_cipher_open (algo, mode, 0);
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
    hd = gcry_cipher_open (algo, mode, 0);
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
                 
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_ECB);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CFB);
      check_one_cipher (algos[i], GCRY_CIPHER_MODE_CBC);
    }

  for (i=0; algos2[i]; i++ ) 
    {
      if (verbose)
        fprintf (stderr, "checking `%s'\n", gcry_cipher_algo_name (algos2[i]));
                 
      check_one_cipher (algos2[i], GCRY_CIPHER_MODE_STREAM);
    }
  /* we have now run all cipher's selftests */

  /* TODO: add some extra encryption to test the higher level functions */
}


static void
check_digests ()
{
    /* TODO */
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
  check_digests ();
  
  return error_count? 1:0;
}


