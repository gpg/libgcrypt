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
#include <errno.h>
#include <ctype.h>
#ifndef HAVE_W32_SYSTEM
# include <signal.h>
#endif

#include <gcrypt.h>

#define PGM "fipsrngdrv"

#define my_isascii(c) (!((c) & 0x80))
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))


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


/* Convert STRING consisting of hex characters into its binary
   representation and store that at BUFFER.  BUFFER needs to be of
   LENGTH bytes.  The function checks that the STRING will convert
   exactly to LENGTH bytes. The string is delimited by either end of
   string or a white space character.  The function returns -1 on
   error or the length of the parsed string.  */
static int
hex2bin (const char *string, void *buffer, size_t length)
{
  int i;
  const char *s = string;

  for (i=0; i < length; )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        return -1;           /* Invalid hex digits. */
      ((unsigned char*)buffer)[i++] = xtoi_2 (s);
      s += 2;
    }
  if (*s && (!my_isascii (*s) || !isspace (*s)) )
    return -1;             /* Not followed by Nul or white space.  */
  if (i != length)
    return -1;             /* Not of expected length.  */
  if (*s)
    s++; /* Skip the delimiter. */
  return s - string;
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
  int last_argc = -1;
  int verbose = 0;
  int binary = 0;
  int loop = 0;
  int progress = 0;
  int no_fips = 0;
  unsigned char key[16];
  unsigned char seed[16];
  unsigned char dt[16];
  void *context;
  gpg_error_t err;
  unsigned char buffer[16];

  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM
                 " [--verbose] [--binary] [--loop] [--progress] KEY V DT\n",
                 stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-fips"))
        {
          no_fips++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--binary"))
        {
          binary = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--loop"))
        {
          loop = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--progress"))
        {
          progress = 1;
          argc--; argv++;
        }
    }

  if (!argc)
    {
      memcpy (key,  "1234567890123456", 16);
      memcpy (seed, "abcdefghijklmnop", 16);
      memcpy (dt,   "XXXXXXXXXXXXXXXX", 16);
    }
  else if (argc == 3)
    {
      if (    hex2bin (argv[0], key, 16) < 0
           || hex2bin (argv[1], seed, 16) < 0
           || hex2bin (argv[2], dt, 16) < 0 )
        die ("args are not 32 hex digits each\n");
    }
  else
    die ("invalid usage (try --help)\n");

#ifndef HAVE_W32_SYSTEM
  if (loop)
    signal (SIGPIPE, SIG_IGN);
#endif

  if (verbose)
    fputs (PGM ": started\n", stderr);

  gcry_control (GCRYCTL_SET_VERBOSITY, (int)verbose);
  if (!no_fips)
    gcry_control (GCRYCTL_FORCE_FIPS_MODE, 0);
  if (!gcry_check_version ("1.4.3"))
    die ("version mismatch\n");
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  /* The flag value 1 disables the dup check, so that the RNG returns
     all generated data.  */
  err = init_external_test (&context, 1, key, 16, seed, 16, dt, 16);
  if (err)
    die ("init external test failed: %s\n", gpg_strerror (err));

  do
    {
      int writerr = 0;

      err = run_external_test (context, buffer, sizeof buffer);
      if (err)
        die ("run external test failed: %s\n", gpg_strerror (err));
      if (binary)
        {
          if (fwrite (buffer, 16, 1, stdout) != 1)
            writerr = 1;
          else
            fflush (stdout);
        }
      else
        {
          print_buffer (buffer, sizeof buffer);
          if (putchar ('\n') == EOF)
            writerr = 1;
        }
      if (writerr)
        {
#ifndef HAVE_W32_SYSTEM
          if (loop && errno == EPIPE)
            break;
#endif
          die ("writing output failed: %s\n", strerror (errno));
        }

      if (progress)
        {
          putc ('.', stderr);
          fflush (stderr);
        }
    }
  while (loop);

  if (progress)
    putc ('\n', stderr);

  deinit_external_test (context);

  if (verbose)
    fputs (PGM ": ready\n", stderr);

  return 0;
}
