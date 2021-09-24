/* t-ecc-cdh.c - Check the ECC CDH crypto
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

#define PGM "t-ecc-cdh"
#include "t-common.h"
#define N_TESTS 125

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
 *      [P-224]
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
  *buffer = xstrdup (s-1);
  (*buffer)[5] = 0; /* Remove ']'.  */
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
  int odd;

  odd = ((strlen (string) & 1));

  buffer = xmalloc (strlen (string)/2 + odd + 1);
  if (odd)
    {
      length = 1;
      s = string;
      buffer[0] = xtoi_1 (s);
      s++;
    }
  else
    {
      length = 0;
      s = string;
    }
  for (; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        return NULL;           /* Invalid hex digits. */
      buffer[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static void
one_test (int testno, const char *curvename,
          const char *x0, const char *y0, const char *d,
          const char *x1, const char *y1, const char *z)
{
  gpg_error_t err;
  int i;
  char *p0;
  void *buffer = NULL;
  void *buffer2 = NULL;
  void *buffer3 = NULL;
  size_t buflen, buflen2, buflen3;
  gcry_pkey_hd_t h0 = NULL;
  gcry_pkey_hd_t h1 = NULL;
  char *z_string = NULL;
  const unsigned char *in[2];
  size_t in_len[2];
  unsigned char *out[1];
  size_t out_len[1];
  unsigned int flags = 0;
  int curve;

  if (verbose > 1)
    info ("Running test %d\n", testno);

  if (!strcmp (curvename, "P-192"))
    curve = GCRY_PKEY_CURVE_NIST_P192;
  else if (!strcmp (curvename, "P-224"))
    curve = GCRY_PKEY_CURVE_NIST_P224;
  else if (!strcmp (curvename, "P-256"))
    curve = GCRY_PKEY_CURVE_NIST_P256;
  else if (!strcmp (curvename, "P-384"))
    curve = GCRY_PKEY_CURVE_NIST_P384;
  else if (!strcmp (curvename, "P-521"))
    curve = GCRY_PKEY_CURVE_NIST_P521;
  else
    {
      fail ("error for test, %s: %s: %s",
            "ECC curve", "invalid", curvename);
      goto leave;
    }

  if (!(buffer = hex2buffer (x1, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "x1", "invalid hex string");
      goto leave;
    }
  if (!(buffer2 = hex2buffer (y1, &buflen2)))
    {
      fail ("error parsing for test, %s: %s",
            "y1", "invalid hex string");
      goto leave;
    }
  if (!(buffer3 = hex2buffer (d, &buflen3)))
    {
      fail ("error parsing for test, %s: %s",
            "d", "invalid hex string");
      goto leave;
    }

  flags |= GCRY_PKEY_FLAG_SECRET;
  err = gcry_pkey_open (&h0, GCRY_PKEY_ECC, flags, curve, GCRY_MD_SHA256,
                        buffer, buflen, buffer2, buflen2, buffer3, buflen3);
  if (err)
    {
      fail ("error opening PKEY for test, %s: %s",
            "sk", gpg_strerror (err));
      goto leave;
    }

  flags &= ~GCRY_PKEY_FLAG_SECRET;
  err = gcry_pkey_open (&h1, GCRY_PKEY_ECC, flags, curve, GCRY_MD_SHA256,
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

  if (!(buffer = hex2buffer (x0, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "x0", "invalid hex string");
      goto leave;
    }

  in[0] = buffer;
  in_len[0] = buflen;

  if (!(buffer2 = hex2buffer (y0, &buflen2)))
    {
      fail ("error parsing for test, %s: %s",
            "y0", "invalid hex string");
      goto leave;
    }

  in[1] = buffer2;
  in_len[1] = buflen2;

  out[0] = NULL;
  err = gcry_pkey_op (h0, GCRY_PKEY_OP_ECDH, 2, in, in_len, 1, out, out_len);
  if (err)
    {
      fail ("gcry_pkey_op failed: %s", gpg_strerror (err));
      goto leave;
    }

  z_string = xmalloc (2*out_len[0]+1);
  p0 = z_string;
  *p0 = 0;
  for (i=0; i < out_len[0]; i++, p0 += 2)
    snprintf (p0, 3, "%02x", out[0][i]);

  i = strlen (z);
  if (i < 2*out_len[0])
    {
      int diff = 2*out_len[0] - i;

      if (strcmp (z_string+diff, z))
	goto bad;

      for (i = 0; i < diff; i++)
	if (z_string[0] != '0')
	  goto bad;
    }
  else if (strcmp (z_string, z))
    {
    bad:
      fail ("gcry_pkey_op failed: %s",
            "wrong value returned");
      info ("  expected: '%s'", z);
      info ("       got: '%s'", z_string);
    }

 leave:
  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  xfree (out[0]);
  xfree (z_string);
  gcry_pkey_close (h0);
  gcry_pkey_close (h1);
}


static void
check_ecdh (const char *fname)
{
  FILE *fp;
  int lineno, ntests;
  char *line;
  char *curve;
  int testno;
  char *x0, *y0;
  char *d;
  char *x1, *y1;
  char *z;

  info ("Checking ECC CDH.\n");

  fp = fopen (fname, "r");
  if (!fp)
    die ("error opening '%s': %s\n", fname, strerror (errno));

  curve = NULL;
  x0 = y0 = d = NULL;
  x1 = y1 = z = NULL;
  lineno = ntests = 0;
  testno = 0;
  while ((line = read_textline (fp, &lineno)))
    {
      if (!strncmp (line, "[", 1))
        parse_annotation (&curve, line, lineno);
      else if (!strncmp (line, "COUNT =", 7))
        testno = atoi (line+8);
      else if (!strncmp (line, "QCAVSx =", 8))
        copy_data (&x0, line, lineno);
      else if (!strncmp (line, "QCAVSy =", 8))
        copy_data (&y0, line, lineno);
      else if (!strncmp (line, "dIUT =", 6))
        copy_data (&d, line, lineno);
      else if (!strncmp (line, "QIUTx =", 7))
        copy_data (&x1, line, lineno);
      else if (!strncmp (line, "QIUTy =", 7))
        copy_data (&y1, line, lineno);
      else if (!strncmp (line, "ZIUT =", 6))
        copy_data (&z, line, lineno);
      else
        fail ("unknown tag at input line %d", lineno);

      xfree (line);
      if (curve && x0 && y0 && d && x1 && y1 && z)
        {
          one_test (testno, curve, x0, y0, d, x1, y1, z);
          ntests++;
          if (!(ntests % 256))
            show_note ("%d of %d tests done\n", ntests, N_TESTS);
          xfree (x0); x0 = NULL;
          xfree (y0); y0 = NULL;
          xfree (d); d = NULL;
          xfree (x1); x1 = NULL;
          xfree (y1); y1 = NULL;
          xfree (z); z = NULL;
        }

    }
  xfree (curve);
  xfree (x0);
  xfree (y0);
  xfree (d);
  xfree (x1);
  xfree (y1);
  xfree (z);

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
    fname = prepend_srcdir ("t-ecc-cdh.inp");
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
  check_ecdh (fname);
  stop_timer ();

  xfree (fname);

  info ("All tests completed in %s.  Errors: %d\n",
        elapsed_time (1), error_count);
  return !!error_count;
}
