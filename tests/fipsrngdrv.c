/* fipsrngdrv.c  -  A driver to test the FIPS RNG.
   Copyright (C) 2008 Free Software Foundation, Inc.

   This file is part of Libgcrypt.
  
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
  
   Libgcrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../src/gcrypt.h"

#define PGM "fipsrngdrv"


static void
die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  fputs (PGM ": ", stderr);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
}


static gcry_error_t
init_external_test (void **r_context, 
                    unsigned int flags,
                    const void *key, size_t keylen,
                    const void *seed, size_t seedlen,
                    const void *dt, size_t dtlen)
{
  return gcry_control (58, 
                       r_context, flags,
                       key, keylen,
                       seed, seedlen,
                       dt, dtlen);
}

static gcry_error_t
run_external_test (void *context, void *buffer, size_t buflen)
{
  return gcry_control (59, context, buffer, buflen);
}

static void
deinit_external_test (void *context)
{
  gcry_control (60, context);
}


static void
print_buffer (const unsigned char *buffer, size_t length)
{
  while (length--)
    printf ("%02X", *buffer++);
}


int
main (int argc, char **argv)
{
  void *context;
  gpg_error_t err;
  int block;
  unsigned char buffer[16];

  (void)argc;
  (void)argv;

  gcry_control (GCRYCTL_FORCE_FIPS_MODE, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_SET_VERBOSITY, 2);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  err = init_external_test (&context, 0,
                            "1234567890123456", 16,
                            "abcdefghijklmnop", 16,
                            "XXXXXXXXXXXXXXXX", 16);
  if (err)
    die ("init external test failed: %s\n", gpg_strerror (err));

  for (block=0; block < 10; block++)
    {
      err = run_external_test (context, buffer, sizeof buffer);
      if (err)
        die ("run external test failed: %s\n", gpg_strerror (err));
      print_buffer (buffer, sizeof buffer);
      putchar ('\n');
    }

  deinit_external_test (context);

  return 0;
}

