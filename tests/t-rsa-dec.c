/* t-rsa-dec.c - Check the RSA decrypt
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

#define PGM "t-rsa-dec"
#include "t-common.h"
#define N_TESTS 60

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
one_test (int testno,
	  const char *n, const char *e, const char *d,
          const char *c, int failure_expected, const char *k)
{
  gpg_error_t err;
  void *buffer = NULL;
  void *buffer2 = NULL;
  void *buffer3 = NULL;
  size_t buflen, buflen2, buflen3;
  gcry_pkey_hd_t h0 = NULL;
  const unsigned char *in[3];
  size_t in_len[3];
  unsigned char *out[1] = { NULL };
  size_t out_len[1] = { 0 };
  unsigned int flags = 0;

  if (verbose > 1)
    info ("Running test %d\n", testno);

  if (!(buffer = hex2buffer (n, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "n", "invalid hex string");
      goto leave;
    }
  if (!(buffer2 = hex2buffer (e, &buflen2)))
    {
      fail ("error parsing for test, %s: %s %d",
            "e", "invalid hex string", testno);
      goto leave;
    }
  if (!(buffer3 = hex2buffer (d, &buflen3)))
    {
      fail ("error parsing for test, %s: %s",
            "d", "invalid hex string");
      goto leave;
    }

  flags |= GCRY_PKEY_FLAG_SECRET;
  err = gcry_pkey_open (&h0, GCRY_PKEY_RSA, flags, GCRY_PKEY_RSA_15, 0,
                        buffer, buflen, buffer2, buflen2, buffer3, buflen3);
  if (err)
    {
      fail ("error opening PKEY for test, %s: %s",
            "sk", gpg_strerror (err));
      goto leave;
    }

  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  buffer = buffer2 = buffer3 = NULL;

  if (!(buffer = hex2buffer (c, &buflen)))
    {
      fail ("error parsing for test, %s: %s",
            "c", "invalid hex string");
      goto leave;
    }

  in[0] = buffer;
  in_len[0] = buflen;

  err = gcry_pkey_op (h0, GCRY_PKEY_OP_DECRYPT, 1, in, in_len, 1, out, out_len);
  if (err && !failure_expected)
    fail ("gcry_pkey_op failed: %s", gpg_strerror (err));

  if (!failure_expected)
    {
      char *pt_string = xmalloc (2*out_len[0]+1);
      int i;
      char *p;

      p = pt_string;
      *p = 0;
      for (i=0; i < out_len[0]; i++, p += 2)
	snprintf (p, 3, "%02x", out[0][i]);
      if (strcmp (pt_string, k))
	{
	  fail ("gcry_pkey_op failed: %s",
		"wrong value returned");
	  info ("  expected: '%s'", k);
	  info ("       got: '%s'", pt_string);
	}

      xfree (pt_string);
    }

 leave:
  xfree (buffer);
  xfree (buffer2);
  xfree (buffer3);
  xfree (out[0]);
  gcry_pkey_close (h0);
}


static void
check_rsa_dec (const char *fname)
{
  FILE *fp;
  int lineno, ntests;
  char *line;
  int testno;
  char *n, *e, *d;
  char *c, *k;
  char *r;
  char *c_d, *k_e;
  int expected_result;

  info ("Checking RSA Decrypt.\n");

  fp = fopen (fname, "r");
  if (!fp)
    die ("error opening '%s': %s\n", fname, strerror (errno));

  n = e = d = NULL;
  c = k = NULL;
  c_d = k_e = NULL;
  lineno = ntests = 0;
  testno = 0;
  expected_result = -1;
  while ((line = read_textline (fp, &lineno)))
    {
      if (!strncmp (line, "[mod", 4))
        /* Skip the annotation for modulus.  */
        ;
      else if (!strncmp (line, "COUNT =", 7))
        testno = atoi (line+8);
      else if (!strncmp (line, "n =", 3))
        copy_data (&n, line, lineno);
      else if (!strncmp (line, "e =", 3))
        copy_data (&e, line, lineno);
      else if (!strncmp (line, "d =", 3))
        copy_data (&d, line, lineno);
      else if (!strncmp (line, "c =", 3))
        copy_data (&c, line, lineno);
      else if (!strncmp (line, "k =", 3))
        copy_data (&k, line, lineno);
      else if (!strncmp (line, "Result =", 8))
	{
	  copy_data (&r, line, lineno);
	  if (!strcmp (r, "Pass"))
	    expected_result = 0;
	  else if (!strcmp (r, "Fail"))
	    expected_result = 1;
	  else
	    fail ("Wrong Result: %s, %d", r, lineno);

          xfree (r); r = NULL;
	}
      else if (!strncmp (line, "c^d =", 5))
        copy_data (&c_d, line, lineno);
      else if (!strncmp (line, "k^e =", 5))
        copy_data (&k_e, line, lineno);
      else
        fail ("unknown tag at input line %d", lineno);

      xfree (line);
      if (n && e && d && c && expected_result >= 0)
	{
	  if (expected_result == 0
	      && (k == NULL || c_d == NULL || k_e == NULL))
	    continue;
	  else
	    {
	      one_test (testno, n, e, d, c, expected_result, k);
	      ntests++;
	      if (!(ntests % 256))
		show_note ("%d of %d tests done\n", ntests, N_TESTS);
	      xfree (c); c = NULL;
	      xfree (k); k = NULL;
	      expected_result = -1;
	      xfree (c_d); c_d = NULL;
	      xfree (k_e); k_e = NULL;
	    }
	}
    }
  xfree (n);
  xfree (e);
  xfree (d);
  xfree (c);
  xfree (k);
  xfree (r);
  xfree (c_d);
  xfree (k_e);

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
    fname = prepend_srcdir ("t-rsa-dec.inp");
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
  check_rsa_dec (fname);
  stop_timer ();

  xfree (fname);

  info ("All tests completed in %s.  Errors: %d\n",
        elapsed_time (1), error_count);
  return !!error_count;
}
