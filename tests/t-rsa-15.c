/* t-rsa-15.c - Check the RSA PKCS#1 Ver1.5 crypto
 * Copyright (C) 2021 g10 Code GmbH
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "stopwatch.h"

#define PGM "t-rsa-15"
#include "t-common.h"
#define N_TESTS 120

static int no_verify;
static int custom_data_file;
static int in_fips_mode = 0;


static void
show_note (const char *format, ...)
{
  va_list arg_ptr;

  if (!verbose && getenv ("srcdir"))
    fputs ("      ", stderr);  /* To align above "PASS: ".  */
  else
    fprintf (stderr, "%s: ", PGM);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
  va_end (arg_ptr);
}


/* Prepend FNAME with the srcdir environment variable's value and
 * return an allocated filename.  */
char *
prepend_srcdir (const char *fname)
{
  static const char *srcdir;
  char *result;

  if (!srcdir && !(srcdir = getenv ("srcdir")))
    srcdir = ".";

  result = xmalloc (strlen (srcdir) + 1 + strlen (fname) + 1);
  strcpy (result, srcdir);
  strcat (result, "/");
  strcat (result, fname);
  return result;
}


/* Read next line but skip over empty and comment lines.  Caller must
   xfree the result.  */
static char *
read_textline (FILE *fp, int *lineno)
{
  char line[4096];
  char *p;

  do
    {
      if (!fgets (line, sizeof line, fp))
        {
          if (feof (fp))
            return NULL;
          die ("error reading input line: %s\n", strerror (errno));
        }
      ++*lineno;
      p = strchr (line, '\n');
      if (!p)
        die ("input line %d not terminated or too long\n", *lineno);
      *p = 0;
      for (p--;p > line && my_isascii (*p) && isspace (*p); p--)
        *p = 0;
    }
  while (!*line || *line == '#');
  /* if (debug) */
  /*   info ("read line: '%s'\n", line); */
  return xstrdup (line);
}


/* Copy the data after the tag to BUFFER.  BUFFER will be allocated as
   needed.  */
static void
copy_data (char **buffer, const char *line, int lineno)
{
  const char *s;

  xfree (*buffer);
  *buffer = NULL;

  s = strchr (line, '=');
  if (!s)
    {
      fail ("syntax error at input line %d", lineno);
      return;
    }
  for (s++; my_isascii (*s) && isspace (*s); s++)
    ;
  *buffer = xstrdup (s);
}


/* Convert STRING consisting of hex characters into its binary
   representation and return it as an allocated buffer. The valid
   length of the buffer is returned at R_LENGTH.  The string is
   delimited by end of string.  The function returns NULL on
   error.  */
static void *
hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        return NULL;           /* Invalid hex digits. */
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static void
one_test (const char *n, const char *e, const char *d,
          const char *sha_alg, const char *msg, const char *s)
{
  gpg_error_t err;
  int i;
  char *p;
  void *buffer = NULL;
  void *buffer2 = NULL;
  void *buffer3 = NULL;
  size_t buflen, buflen2, buflen3;
  gcry_pkey_hd_t h0 = NULL;
  gcry_pkey_hd_t h1 = NULL;
  char *sig_string = NULL;
  const unsigned char *in[3];
  size_t in_len[3];
  unsigned char *out[1] = { NULL };
  size_t out_len[1] = { 0 };
  unsigned int flags = 0;
  int md_algo;

  if (verbose > 1)
    info ("Running test %s\n", sha_alg);

  if (!strcmp (sha_alg, "SHA224"))
    md_algo = GCRY_MD_SHA224;
  else if (!strcmp (sha_alg, "SHA256"))
    md_algo = GCRY_MD_SHA256;
  else if (!strcmp (sha_alg, "SHA384"))
    md_algo = GCRY_MD_SHA384;
  else if (!strcmp (sha_alg, "SHA512"))
    md_algo = GCRY_MD_SHA512;
  else if (!strcmp (sha_alg, "SHA512224"))
    md_algo = GCRY_MD_SHA512_224;
  else if (!strcmp (sha_alg, "SHA512256"))
    md_algo = GCRY_MD_SHA512_256;
  else
    {
      fail ("error for test, %s: %s",
            "d", "invalid hex string");
      goto leave;
    }

  if (!(buffer = hex2buffer (n, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "n", "invalid hex string");
      goto leave;
    }
  if (!(buffer2 = hex2buffer (e, &buflen2)))
    {
      fail ("error parsing for test, %s: %s",
            "e", "invalid hex string");
      goto leave;
    }
  if (!(buffer3 = hex2buffer (d, &buflen3)))
    {
      fail ("error parsing for test, %s: %s",
            "d", "invalid hex string");
      goto leave;
    }

  flags |= GCRY_PKEY_FLAG_SECRET;
  err = gcry_pkey_open (&h0, GCRY_PKEY_RSA, flags, GCRY_PKEY_RSA_15, md_algo,
                        buffer, buflen, buffer2, buflen2, buffer3, buflen3);
  if (err)
    {
      fail ("error opening PKEY for test, %s: %s",
            "sk", gpg_strerror (err));
      goto leave;
    }

  flags &= ~GCRY_PKEY_FLAG_SECRET;
  err = gcry_pkey_open (&h1, GCRY_PKEY_RSA, flags, GCRY_PKEY_RSA_15, md_algo,
                        buffer, buflen, buffer2, buflen2);
  if (err)
    {
      fail ("error opening PKEY for test, %s: %s",
            "pk", gpg_strerror (err));
      goto leave;
    }

  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  buffer = buffer2 = buffer3 = NULL;

  if (!(buffer = hex2buffer (msg, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "msg", "invalid hex string");
      goto leave;
    }

  in[0] = buffer;
  in_len[0] = buflen;

  err = gcry_pkey_op (h0, GCRY_PKEY_OP_SIGN, 1, in, in_len, 1, out, out_len);
  if (err)
    fail ("gcry_pkey_op failed: %s", gpg_strerror (err));

  sig_string = xmalloc (2*out_len[0]+1);
  p = sig_string;
  *p = 0;
  for (i=0; i < out_len[0]; i++, p += 2)
    snprintf (p, 3, "%02x", out[0][i]);
  if (strcmp (sig_string, s))
    {
      fail ("gcry_pkey_op failed: %s",
            "wrong value returned");
      info ("  expected: '%s'", s);
      info ("       got: '%s'", sig_string);
    }

  if (!no_verify)
    {
      in[1] = out[0];
      in_len[1] = out_len[0];

      if ((err = gcry_pkey_op (h1, GCRY_PKEY_OP_VERIFY,
                               2, in, in_len, 0, NULL, 0)))
        fail ("GCRY_PKEY_OP_VERIFY failed for test: %s",
              gpg_strerror (err));
    }

 leave:
  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  xfree (out[0]);
  xfree (sig_string);
  gcry_pkey_close (h0);
  gcry_pkey_close (h1);
}


static void
check_rsa_15 (const char *fname)
{
  FILE *fp;
  int lineno, ntests;
  char *line;
  char *n, *e, *d;
  char *sha_alg, *msg, *s;

  info ("Checking RSA PKCS#1 Ver1.5.\n");

  fp = fopen (fname, "r");
  if (!fp)
    die ("error opening '%s': %s\n", fname, strerror (errno));

  n = e = d = NULL;
  sha_alg = msg = s = NULL;
  lineno = ntests = 0;
  while ((line = read_textline (fp, &lineno)))
    {
      if (!strncmp (line, "[mod", 4))
        /* Skip the annotation for modulus.  */
        ;
      else if (!strncmp (line, "n =", 3))
        copy_data (&n, line, lineno);
      else if (!strncmp (line, "e =", 3))
        copy_data (&e, line, lineno);
      else if (!strncmp (line, "d =", 3))
        copy_data (&d, line, lineno);
      else if (!strncmp (line, "SHAAlg =", 8))
        copy_data (&sha_alg, line, lineno);
      else if (!strncmp (line, "Msg =", 5))
        copy_data (&msg, line, lineno);
      else if (!strncmp (line, "S =", 3))
        copy_data (&s, line, lineno);
      else
        fail ("unknown tag at input line %d", lineno);

      xfree (line);
      if (n && e && d && sha_alg && msg && s)
        {
          one_test (n, e, d, sha_alg, msg, s);
          ntests++;
          if (!(ntests % 256))
            show_note ("%d of %d tests done\n", ntests, N_TESTS);
          xfree (sha_alg);  sha_alg = NULL;
          xfree (msg); msg = NULL;
          xfree (s); s = NULL;
        }

    }
  xfree (n);
  xfree (e);
  xfree (d);
  xfree (sha_alg);
  xfree (msg);
  xfree (s);

  if (ntests != N_TESTS && !custom_data_file)
    fail ("did %d tests but expected %d", ntests, N_TESTS);
  else if ((ntests % 256))
    show_note ("%d tests done\n", ntests);

  fclose (fp);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  char *fname = NULL;

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
          fputs ("usage: " PGM " [options]\n"
                 "Options:\n"
                 "  --verbose       print timings etc.\n"
                 "  --debug         flyswatter\n"
                 "  --no-verify     skip the verify test\n"
                 "  --data FNAME    take test data from file FNAME\n",
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
      else if (!strcmp (*argv, "--no-verify"))
        {
          no_verify = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--data"))
        {
          argc--; argv++;
          if (argc)
            {
              xfree (fname);
              fname = xstrdup (*argv);
              argc--; argv++;
            }
        }
      else if (!strncmp (*argv, "--", 2))
        die ("unknown option '%s'", *argv);

    }

  if (!fname)
    fname = prepend_srcdir ("t-rsa-15.inp");
  else
    custom_data_file = 1;

  xgcry_control ((GCRYCTL_DISABLE_SECMEM, 0));
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  if (debug)
    xgcry_control ((GCRYCTL_SET_DEBUG_FLAGS, 1u , 0));
  xgcry_control ((GCRYCTL_ENABLE_QUICK_RANDOM, 0));
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));

  if (gcry_fips_mode_active ())
    in_fips_mode = 1;

  start_timer ();
  check_rsa_15 (fname);
  stop_timer ();

  xfree (fname);

  info ("All tests completed in %s.  Errors: %d\n",
        elapsed_time (1), error_count);
  return !!error_count;
}
