/* mpitests.c  -  basic mpi tests
 *	Copyright (C) 2001, 2002, 2003, 2006 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA. 
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
static int debug;


/* Set up some test patterns */

/* 48 bytes with value 1: this results in 8 limbs for 64bit limbs, 16limb for 32 bit limbs */
unsigned char ones[] = {
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

/* 48 bytes with value 2: this results in 8 limbs for 64bit limbs, 16limb for 32 bit limbs */
unsigned char twos[] = {
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
};

/* 48 bytes with value 3: this results in 8 limbs for 64bit limbs, 16limb for 32 bit limbs */
unsigned char threes[] = {
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
};

/* 48 bytes with value 0x80: this results in 8 limbs for 64bit limbs, 16limb for 32 bit limbs */
unsigned char eighties[] = {
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
};

/* 48 bytes with value 0xff: this results in 8 limbs for 64bit limbs, 16limb for 32 bit limbs */
unsigned char manyff[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};



static int 
test_add (void)
{
  gcry_mpi_t one;
  gcry_mpi_t two;
  gcry_mpi_t ff;
  gcry_mpi_t result;
  unsigned char* pc;
  
  gcry_mpi_scan(&one, GCRYMPI_FMT_USG, ones, sizeof(ones), NULL);
  gcry_mpi_scan(&two, GCRYMPI_FMT_USG, twos, sizeof(twos), NULL);
  gcry_mpi_scan(&ff, GCRYMPI_FMT_USG, manyff, sizeof(manyff), NULL);
  result = gcry_mpi_new(0);
  
  gcry_mpi_add(result, one, two);
  gcry_mpi_aprint(GCRYMPI_FMT_HEX, &pc, NULL, result);
  if (verbose)
    printf("Result of one plus two:\n%s\n", pc);
  gcry_free(pc);

  gcry_mpi_add(result, ff, one);
  gcry_mpi_aprint(GCRYMPI_FMT_HEX, &pc, NULL, result);
  if (verbose)
    printf("Result of ff plus one:\n%s\n", pc);
  gcry_free(pc);
  
  gcry_mpi_release(one);
  gcry_mpi_release(two);
  gcry_mpi_release(ff);
  gcry_mpi_release(result);
  return 1;
}


static int 
test_sub (void)
{
  gcry_mpi_t one;
  gcry_mpi_t two;
  gcry_mpi_t result;
  unsigned char* pc;
  
  gcry_mpi_scan(&one, GCRYMPI_FMT_USG, ones, sizeof(ones), NULL);
  gcry_mpi_scan(&two, GCRYMPI_FMT_USG, twos, sizeof(twos), NULL);
  result = gcry_mpi_new(0);
  gcry_mpi_sub(result, two, one);
  
  gcry_mpi_aprint(GCRYMPI_FMT_HEX, &pc, NULL, result);
  if (verbose)
    printf("Result of two minus one:\n%s\n", pc);
  gcry_free(pc);
  
  gcry_mpi_release(one);
  gcry_mpi_release(two);
  gcry_mpi_release(result);
  return 1;
}


static int 
test_mul (void)
{
  gcry_mpi_t two;
  gcry_mpi_t three;
  gcry_mpi_t result;
  unsigned char* pc;
  
  gcry_mpi_scan(&two, GCRYMPI_FMT_USG, twos, sizeof(twos), NULL);
  gcry_mpi_scan(&three, GCRYMPI_FMT_USG, threes, sizeof(threes), NULL);
  result = gcry_mpi_new(0);
  gcry_mpi_mul(result, two, three);
  
  gcry_mpi_aprint(GCRYMPI_FMT_HEX, &pc, NULL, result);
  if (verbose)
    printf("Result of two mul three:\n%s\n", pc);
  gcry_free(pc);
  
  gcry_mpi_release(two);
  gcry_mpi_release(three);
  gcry_mpi_release(result);
  return 1;
}


int 
main (int argc, char* argv[])
{
  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fputs ("version mismatch\n", stderr);
      exit (1);
    }
  gcry_control(GCRYCTL_DISABLE_SECMEM);

  test_add ();
  test_sub ();
  test_mul ();

  return 0;
}

