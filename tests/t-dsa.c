/* t-dsa.c - Check the DSA crypto
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

#define PGM "t-dsa"
#include "t-common.h"
#define N_TESTS 300

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


/*
 * The input line is like:
 *
 *      [mod = L=2048, N=256, SHA-384]
 *
 */
static void
parse_annotation (char **buffer, const char *line, int lineno)
{
  const char *s;

  xfree (*buffer);
  *buffer = NULL;

  s = strchr (line, '-');
  if (!s)
    {
      fail ("syntax error at input line %d", lineno);
      return;
    }
  *buffer = xstrdup (s-3);
  (*buffer)[strlen (*buffer) - 1] = 0; /* Remove ']'.  */
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
one_test (const char *sha_alg, const char *p, const char *q, const char *g,
          const char *x, const char *y,
          const char *msg, const char *k,
          const char *r, const char *s)
{
  gpg_error_t err;
  int i;
  char *p0;
  void *buffer = NULL;
  void *buffer2 = NULL;
  void *buffer3 = NULL;
  void *buffer4 = NULL;
  void *buffer5 = NULL;
  size_t buflen, buflen2, buflen3, buflen4, buflen5;
  gcry_pkey_hd_t h0 = NULL;
  gcry_pkey_hd_t h1 = NULL;
  char *sig_r_string = NULL;
  char *sig_s_string = NULL;
  const unsigned char *in[4];
  size_t in_len[4];
  unsigned char *out[2] = { NULL, NULL };
  size_t out_len[2] = { 0, 0 };
  unsigned int flags = 0;
  int md_algo;

  if (verbose > 1)
    info ("Running test %s\n", sha_alg);

  if (!strcmp (sha_alg, "SHA-1"))
    md_algo = GCRY_MD_SHA1;
  else if (!strcmp (sha_alg, "SHA-224"))
    md_algo = GCRY_MD_SHA224;
  else if (!strcmp (sha_alg, "SHA-256"))
    md_algo = GCRY_MD_SHA256;
  else if (!strcmp (sha_alg, "SHA-384"))
    md_algo = GCRY_MD_SHA384;
  else if (!strcmp (sha_alg, "SHA-512"))
    md_algo = GCRY_MD_SHA512;
  else
    {
      fail ("error for test, %s: %s: %s",
            "SHA algo", "invalid string", sha_alg);
      goto leave;
    }

  if (!(buffer = hex2buffer (p, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "p", "invalid hex string");
      goto leave;
    }
  if (!(buffer2 = hex2buffer (q, &buflen2)))
    {
      fail ("error parsing for test, %s: %s",
            "q", "invalid hex string");
      goto leave;
    }
  if (!(buffer3 = hex2buffer (g, &buflen3)))
    {
      fail ("error parsing for test, %s: %s",
            "g", "invalid hex string");
      goto leave;
    }
  if (!(buffer4 = hex2buffer (y, &buflen4)))
    {
      fail ("error parsing for test, %s: %s",
            "y", "invalid hex string");
      goto leave;
    }
  if (!(buffer5 = hex2buffer (x, &buflen5)))
    {
      fail ("error parsing for test, %s: %s",
            "x", "invalid hex string");
      goto leave;
    }

  flags |= GCRY_PKEY_FLAG_SECRET;
  err = gcry_pkey_open (&h0, GCRY_PKEY_DSA, flags, md_algo,
                        buffer, buflen, buffer2, buflen2, buffer3, buflen3,
                        buffer4, buflen4, buffer5, buflen5);
  if (err)
    {
      fail ("error opening PKEY for test, %s: %s",
            "sk", gpg_strerror (err));
      goto leave;
    }

  flags &= ~GCRY_PKEY_FLAG_SECRET;
  err = gcry_pkey_open (&h1, GCRY_PKEY_DSA, flags, md_algo,
                        buffer, buflen, buffer2, buflen2, buffer3, buflen3,
                        buffer4, buflen4);
  if (err)
    {
      fail ("error opening PKEY for test, %s: %s",
            "pk", gpg_strerror (err));
      goto leave;
    }

  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  xfree (buffer4);
  xfree (buffer5);
  buffer = buffer2 = buffer3 = buffer4 = buffer5 = NULL;

  if (!(buffer = hex2buffer (msg, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "msg", "invalid hex string");
      goto leave;
    }

  in[0] = buffer;
  in_len[0] = buflen;

  if (!(buffer2 = hex2buffer (k, &buflen2)))
    {
      fail ("error parsing for test, %s: %s",
            "salt_val", "invalid hex string");
      goto leave;
    }

  in[1] = buffer2;
  in_len[1] = buflen2;

  err = gcry_pkey_op (h0, GCRY_PKEY_OP_SIGN, 2, in, in_len, 2, out, out_len);
  if (err)
    fail ("gcry_pkey_op failed: %s", gpg_strerror (err));

  sig_r_string = xmalloc (2*out_len[0]+1);
  p0 = sig_r_string;
  *p0 = 0;
  for (i=0; i < out_len[0]; i++, p0 += 2)
    snprintf (p0, 3, "%02x", out[0][i]);

  sig_s_string = xmalloc (2*out_len[1]+1);
  p0 = sig_s_string;
  *p0 = 0;
  for (i=0; i < out_len[0]; i++, p0 += 2)
    snprintf (p0, 3, "%02x", out[1][i]);

  if (strcmp (sig_r_string, r) || strcmp (sig_s_string, s))
    {
      fail ("gcry_pkey_op failed: %s",
            "wrong value returned");
      info ("  expected: '%s'", r);
      info ("       got: '%s'", sig_r_string);
      info ("  expected: '%s'", s);
      info ("       got: '%s'", sig_s_string);
    }

  if (!no_verify)
    {
      in[2] = out[0];
      in_len[2] = out_len[0];
      in[3] = out[1];
      in_len[3] = out_len[1];

      if ((err = gcry_pkey_op (h1, GCRY_PKEY_OP_VERIFY,
                               4, in, in_len, 0, NULL, 0)))
        fail ("GCRY_PKEY_OP_VERIFY failed for test: %s",
              gpg_strerror (err));
    }

 leave:
  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  xfree (buffer4);
  xfree (buffer5);
  xfree (out[0]);
  xfree (out[1]);
  xfree (sig_r_string);
  xfree (sig_s_string);
  gcry_pkey_close (h0);
  gcry_pkey_close (h1);
}


static void
check_dsa (const char *fname)
{
  FILE *fp;
  int lineno, ntests;
  char *line;
  char *sha_alg;
  char *p, *q, *g;
  char *msg, *x, *y, *k, *r, *s;

  info ("Checking DSA.\n");

  fp = fopen (fname, "r");
  if (!fp)
    die ("error opening '%s': %s\n", fname, strerror (errno));

  sha_alg = NULL;
  p = q = g = NULL;
  msg = x = y = k = r = s = NULL;
  lineno = ntests = 0;
  while ((line = read_textline (fp, &lineno)))
    {
      if (!strncmp (line, "[mod", 4))
        parse_annotation (&sha_alg, line, lineno);
      else if (!strncmp (line, "P =", 3))
        copy_data (&p, line, lineno);
      else if (!strncmp (line, "Q =", 3))
        copy_data (&q, line, lineno);
      else if (!strncmp (line, "G =", 3))
        copy_data (&g, line, lineno);
      else if (!strncmp (line, "Msg =", 5))
        copy_data (&msg, line, lineno);
      else if (!strncmp (line, "X =", 3))
        copy_data (&x, line, lineno);
      else if (!strncmp (line, "Y =", 3))
        copy_data (&y, line, lineno);
      else if (!strncmp (line, "K =", 3))
        copy_data (&k, line, lineno);
      else if (!strncmp (line, "R =", 3))
        copy_data (&r, line, lineno);
      else if (!strncmp (line, "S =", 3))
        copy_data (&s, line, lineno);
      else
        fail ("unknown tag at input line %d", lineno);

      xfree (line);
      if (sha_alg && p && q && g && msg && x && y && k && r && s)
        {
          one_test (sha_alg, p, q, g, x, y, msg, k, r, s);
          ntests++;
          if (!(ntests % 256))
            show_note ("%d of %d tests done\n", ntests, N_TESTS);
          xfree (msg); msg = NULL;
          xfree (x); x = NULL;
          xfree (y); y = NULL;
          xfree (k); k = NULL;
          xfree (r); r = NULL;
          xfree (s); s = NULL;
        }

    }
  xfree (p);
  xfree (q);
  xfree (g);
  xfree (sha_alg);
  xfree (msg);
  xfree (x);
  xfree (y);
  xfree (k);
  xfree (r);
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
    fname = prepend_srcdir ("t-dsa.inp");
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
  check_dsa (fname);
  stop_timer ();

  xfree (fname);

  info ("All tests completed in %s.  Errors: %d\n",
        elapsed_time (1), error_count);
  return !!error_count;
}
