/* random.c - part of the Libgcrypt test suite.
   Copyright (C) 2005 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#ifndef HAVE_W32_SYSTEM
# include <signal.h>
# include <unistd.h>
# include <sys/wait.h>
#endif

#include "../src/gcrypt-int.h"

#define PGM "random"


static int verbose;
static int debug;
static int with_progress;

static void
die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  fputs ( PGM ": ", stderr);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
}


static void
inf (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  fputs ( PGM ": ", stderr);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
}


static void
print_hex (const char *text, const void *buf, size_t n)
{
  const unsigned char *p = buf;

  inf ("%s", text);
  for (; n; n--, p++)
    fprintf (stderr, "%02X", *p);
  putc ('\n', stderr);
}


static void
progress_cb (void *cb_data, const char *what, int printchar,
             int current, int total)
{
  (void)cb_data;

  inf ("progress (%s %c %d %d)\n", what, printchar, current, total);
  fflush (stderr);
}



static int
writen (int fd, const void *buf, size_t nbytes)
{
  size_t nleft = nbytes;
  int nwritten;

  while (nleft > 0)
    {
      nwritten = write (fd, buf, nleft);
      if (nwritten < 0)
        {
          if (errno == EINTR)
            nwritten = 0;
          else
            return -1;
        }
      nleft -= nwritten;
      buf = (const char*)buf + nwritten;
    }

  return 0;
}

static int
readn (int fd, void *buf, size_t buflen, size_t *ret_nread)
{
  size_t nleft = buflen;
  int nread;

  while ( nleft > 0 )
    {
      nread = read ( fd, buf, nleft );
      if (nread < 0)
        {
          if (nread == EINTR)
            nread = 0;
          else
            return -1;
        }
      else if (!nread)
        break; /* EOF */
      nleft -= nread;
      buf = (char*)buf + nread;
    }
  if (ret_nread)
    *ret_nread = buflen - nleft;
  return 0;
}



/* Check that forking won't return the same random. */
static void
check_forking (void)
{
#ifdef HAVE_W32_SYSTEM
  if (verbose)
    inf ("check_forking skipped: not applicable on Windows\n");
#else /*!HAVE_W32_SYSTEM*/
  pid_t pid;
  int rp[2];
  int i, status;
  size_t nread;
  char tmp1[16], tmp1c[16], tmp1p[16];

  if (verbose)
    inf ("checking that a fork won't cause the same random output\n");

  /* We better make sure that the RNG has been initialzied. */
  gcry_randomize (tmp1, sizeof tmp1, GCRY_STRONG_RANDOM);
  if (verbose)
    print_hex ("initial random: ", tmp1, sizeof tmp1);

  if (pipe (rp) == -1)
    die ("pipe failed: %s\n", strerror (errno));

  pid = fork ();
  if (pid == (pid_t)(-1))
    die ("fork failed: %s\n", strerror (errno));
  if (!pid)
    {
      gcry_randomize (tmp1c, sizeof tmp1c, GCRY_STRONG_RANDOM);
      if (writen (rp[1], tmp1c, sizeof tmp1c))
        die ("write failed: %s\n", strerror (errno));
      if (verbose)
        {
          print_hex ("  child random: ", tmp1c, sizeof tmp1c);
          fflush (stdout);
        }
      _exit (0);
    }
  gcry_randomize (tmp1p, sizeof tmp1p, GCRY_STRONG_RANDOM);
  if (verbose)
    print_hex (" parent random: ", tmp1p, sizeof tmp1p);

  close (rp[1]);
  if (readn (rp[0], tmp1c, sizeof tmp1c, &nread))
    die ("read failed: %s\n", strerror (errno));
  if (nread != sizeof tmp1c)
    die ("read too short\n");

  while ( (i=waitpid (pid, &status, 0)) == -1 && errno == EINTR)
    ;
  if (i != (pid_t)(-1)
      && WIFEXITED (status) && !WEXITSTATUS (status))
    ;
  else
    die ("child failed\n");

  if (!memcmp (tmp1p, tmp1c, sizeof tmp1c))
    die ("parent and child got the same random number\n");
#endif  /*!HAVE_W32_SYSTEM*/
}



/* Check that forking won't return the same nonce. */
static void
check_nonce_forking (void)
{
#ifdef HAVE_W32_SYSTEM
  if (verbose)
    inf ("check_nonce_forking skipped: not applicable on Windows\n");
#else /*!HAVE_W32_SYSTEM*/
  pid_t pid;
  int rp[2];
  int i, status;
  size_t nread;
  char nonce1[10], nonce1c[10], nonce1p[10];

  if (verbose)
    inf ("checking that a fork won't cause the same nonce output\n");

  /* We won't get the same nonce back if we never initialized the
     nonce subsystem, thus we get one nonce here and forget about
     it. */
  gcry_create_nonce (nonce1, sizeof nonce1);
  if (verbose)
    print_hex ("initial nonce: ", nonce1, sizeof nonce1);

  if (pipe (rp) == -1)
    die ("pipe failed: %s\n", strerror (errno));

  pid = fork ();
  if (pid == (pid_t)(-1))
    die ("fork failed: %s\n", strerror (errno));
  if (!pid)
    {
      gcry_create_nonce (nonce1c, sizeof nonce1c);
      if (writen (rp[1], nonce1c, sizeof nonce1c))
        die ("write failed: %s\n", strerror (errno));
      if (verbose)
        {
          print_hex ("  child nonce: ", nonce1c, sizeof nonce1c);
          fflush (stdout);
        }
      _exit (0);
    }
  gcry_create_nonce (nonce1p, sizeof nonce1p);
  if (verbose)
    print_hex (" parent nonce: ", nonce1p, sizeof nonce1p);

  close (rp[1]);
  if (readn (rp[0], nonce1c, sizeof nonce1c, &nread))
    die ("read failed: %s\n", strerror (errno));
  if (nread != sizeof nonce1c)
    die ("read too short\n");

  while ( (i=waitpid (pid, &status, 0)) == -1 && errno == EINTR)
    ;
  if (i != (pid_t)(-1)
      && WIFEXITED (status) && !WEXITSTATUS (status))
    ;
  else
    die ("child failed\n");

  if (!memcmp (nonce1p, nonce1c, sizeof nonce1c))
    die ("parent and child got the same nonce\n");
#endif  /*!HAVE_W32_SYSTEM*/
}


static int
rng_type (void)
{
  int rngtype;
  if (gcry_control (GCRYCTL_GET_CURRENT_RNG_TYPE, &rngtype))
    die ("retrieving RNG type failed\n");
  return rngtype;
}


static void
check_rng_type_switching (void)
{
  int rngtype, initial;
  char tmp1[4];

  if (verbose)
    inf ("checking whether RNG type switching works\n");

  rngtype = rng_type ();
  if (debug)
    inf ("rng type: %d\n", rngtype);
  initial = rngtype;
  gcry_randomize (tmp1, sizeof tmp1, GCRY_STRONG_RANDOM);
  if (debug)
    print_hex ("  sample: ", tmp1, sizeof tmp1);
  if (rngtype != rng_type ())
    die ("RNG type unexpectedly changed\n");

  gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM);

  rngtype = rng_type ();
  if (debug)
    inf ("rng type: %d\n", rngtype);
  if (rngtype != initial)
    die ("switching to System RNG unexpectedly succeeded\n");
  gcry_randomize (tmp1, sizeof tmp1, GCRY_STRONG_RANDOM);
  if (debug)
    print_hex ("  sample: ", tmp1, sizeof tmp1);
  if (rngtype != rng_type ())
    die ("RNG type unexpectedly changed\n");

  gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_FIPS);

  rngtype = rng_type ();
  if (debug)
    inf ("rng type: %d\n", rngtype);
  if (rngtype != initial)
    die ("switching to FIPS RNG unexpectedly succeeded\n");
  gcry_randomize (tmp1, sizeof tmp1, GCRY_STRONG_RANDOM);
  if (debug)
    print_hex ("  sample: ", tmp1, sizeof tmp1);
  if (rngtype != rng_type ())
    die ("RNG type unexpectedly changed\n");

  gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_STANDARD);

  rngtype = rng_type ();
  if (debug)
    inf ("rng type: %d\n", rngtype);
  if (rngtype != GCRY_RNG_TYPE_STANDARD)
    die ("switching to standard RNG failed\n");
  gcry_randomize (tmp1, sizeof tmp1, GCRY_STRONG_RANDOM);
  if (debug)
    print_hex ("  sample: ", tmp1, sizeof tmp1);
  if (rngtype != rng_type ())
    die ("RNG type unexpectedly changed\n");
}


static void
check_early_rng_type_switching (void)
{
  int rngtype, initial;

  if (verbose)
    inf ("checking whether RNG type switching works in the early stage\n");

  rngtype = rng_type ();
  if (debug)
    inf ("rng type: %d\n", rngtype);
  initial = rngtype;

  gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM);

  rngtype = rng_type ();
  if (debug)
    inf ("rng type: %d\n", rngtype);
  if (initial >= GCRY_RNG_TYPE_SYSTEM && rngtype != GCRY_RNG_TYPE_SYSTEM)
    die ("switching to System RNG failed\n");

  gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_FIPS);

  rngtype = rng_type ();
  if (debug)
    inf ("rng type: %d\n", rngtype);
  if (initial >= GCRY_RNG_TYPE_FIPS && rngtype != GCRY_RNG_TYPE_FIPS)
    die ("switching to FIPS RNG failed\n");

  gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_STANDARD);

  rngtype = rng_type ();
  if (debug)
    inf ("rng type: %d\n", rngtype);
  if (rngtype != GCRY_RNG_TYPE_STANDARD)
    die ("switching to standard RNG failed\n");
}


/* Because we want to check initialization behaviour, we need to
   fork/exec this program with several command line arguments.  We use
   system, so that these tests work also on Windows.  */
static void
run_all_rng_tests (const char *program)
{
  static const char *options[] = {
    "--early-rng-check",
    "--early-rng-check --prefer-standard-rng",
    "--early-rng-check --prefer-fips-rng",
    "--early-rng-check --prefer-system-rng",
    "--prefer-standard-rng",
    "--prefer-fips-rng",
    "--prefer-system-rng",
    NULL
  };
  int idx;
  size_t len, maxlen;
  char *cmdline;

  maxlen = 0;
  for (idx=0; options[idx]; idx++)
    {
      len = strlen (options[idx]);
      if (len > maxlen)
        maxlen = len;
    }
  maxlen += strlen (program);
  maxlen += strlen (" --in-recursion --verbose --debug --progress");
  maxlen++;
  cmdline = malloc (maxlen + 1);
  if (!cmdline)
    die ("out of core\n");

  for (idx=0; options[idx]; idx++)
    {
      if (verbose)
        inf ("now running with options '%s'\n", options[idx]);
      strcpy (cmdline, program);
      strcat (cmdline, " --in-recursion");
      if (verbose)
        strcat (cmdline, " --verbose");
      if (debug)
        strcat (cmdline, " --debug");
      if (with_progress)
        strcat (cmdline, " --progress");
      strcat (cmdline, " ");
      strcat (cmdline, options[idx]);
      if (system (cmdline))
        die ("running '%s' failed\n", cmdline);
    }

  free (cmdline);
}

int
main (int argc, char **argv)
{
  int last_argc = -1;
  int early_rng = 0;
  int in_recursion = 0;
  const char *program = NULL;

  if (argc)
    {
      program = *argv;
      argc--; argv++;
    }
  else
    die ("argv[0] missing\n");

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
          fputs ("usage: random [options]\n", stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          debug = verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--progress"))
        {
          argc--; argv++;
          with_progress = 1;
        }
      else if (!strcmp (*argv, "--in-recursion"))
        {
          in_recursion = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--early-rng-check"))
        {
          early_rng = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--prefer-standard-rng"))
        {
          /* This is anyway the default, but we may want to use it for
             debugging. */
          gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_STANDARD);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--prefer-fips-rng"))
        {
          gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_FIPS);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--prefer-system-rng"))
        {
          gcry_control (GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM);
          argc--; argv++;
        }
    }

#ifndef HAVE_W32_SYSTEM
  signal (SIGPIPE, SIG_IGN);
#endif

  if (early_rng)
    check_early_rng_type_switching ();

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");

  if (with_progress)
    gcry_set_progress_handler (progress_cb, NULL);

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);

  if (!in_recursion)
    {
      check_forking ();
      check_nonce_forking ();
    }
  check_rng_type_switching ();

  if (!in_recursion)
    run_all_rng_tests (program);

  return 0;
}
