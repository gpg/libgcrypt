/* test.h - Code shared between the benchmark and the standalone versions.
   Copyright (C) 2003 Free Software Foundation, Inc.

   This file is part of Libgcrypt.

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

#include <config.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 		/* For asprintf().  */
#endif

#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <sys/times.h>
#include <unistd.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "test.h"



#define TEST_SPEC_SYMBOL_NAME "test_spec_%s"



static const char *program_name;
static int test_mode_flags;

#define TEST_MODE_VERBOSE (1 << 0)



/* Timestamp holders.  */
static clock_t timestamp_start, timestamp_stop;



static void
timer_start (void)
{
  struct tms tmp;

  times (&tmp);
  timestamp_start = tmp.tms_utime;
}

static void
timer_stop (void)
{
  struct tms tmp;

  times (&tmp);
  timestamp_stop = tmp.tms_utime;
}

static const char *
timer_delta (void)
{
  static char buf[50];

  sprintf (buf, "%5.0fms",
           (((double) (timestamp_stop - timestamp_start)) / CLOCKS_PER_SEC) * 10000000);
  
  return buf;
}



static const char *
test_name_sanitize (char *identifier)
{
  char *identifier_new = identifier;
  char substitutions[] =
    {
      '-', '_',
    };
  unsigned int i = 0, j = 0;

  if (! strncmp (identifier, "lt-", 3))
    identifier_new += 3;

  for (i = 0; identifier_new[i]; i++)
    for (j = 0; j < (DIM (substitutions) / 2); j += 2)
      if (identifier_new[i] == substitutions[j])
	{
	  identifier_new[i] = substitutions[j + 1];
	  break;
	}
  
  return identifier_new;
}

static test_t *
test_lookup (const char *identifier)
{
  char *identifier_cp = NULL;
  const char *identifier_sanitized = NULL;
  char *symbol_name = NULL;
  void *handle = NULL;
  test_t *test = NULL;
  int ret = 0;

  identifier_cp = strdup (identifier);
  test_assert (identifier_cp);

  identifier_sanitized = test_name_sanitize (identifier_cp);

  ret = asprintf (&symbol_name, TEST_SPEC_SYMBOL_NAME, identifier_sanitized);
  if (! (ret < 0))
    {
      handle = dlopen (NULL, RTLD_LAZY);
      if (! handle)
	{
	  test = NULL;
	  dlerror ();
	}
      else
	{
	  test = dlsym (handle, symbol_name);
	  dlerror ();
	  dlclose (handle);
	}

      free (symbol_name);
    }
  free (identifier_cp);

  return test;
}

typedef void (*test_mode_run_t) (int argc, char **argv, test_mode_t mode);

typedef struct test_mode_spec
{
  test_mode_t mode;
  test_mode_run_t run;
} test_mode_spec_t;

typedef void (*test_mode_implementation_t) (test_t *test, const char *identifier);

static void
test_implementation_standalone (test_t *test, const char *identifier)
{
  test_context_t context = NULL;
  unsigned int i = 0;

  if (test->context_init)
    (*test->context_init) (identifier, &context);
  for (i = 0; i < test->actions_n; i++)
    (*test->actions[i].func) (context, TEST_ACTION_FLAG_RUN);
  if (context)
    (*test->context_destroy) (context);
}

static void
test_implementation_benchmark (test_t *test, const char *identifier)
{
  const char *time_delta = NULL;
  test_context_t context = NULL;
  unsigned int i = 0, j = 0;

  if (test->context_init)
    (*test->context_init) (identifier, &context);

  for (i = 0; i < test->actions_n; i++)
    {
      timer_start ();
      for (j = 0; j < test->actions[i].loop; j++)
	{
	  (*test->actions[i].func) (context,
				    TEST_ACTION_FLAG_BENCHMARK | TEST_ACTION_FLAG_RUN);
	  if (j + 1 < test->actions[i].loop)
	    (*test->actions[i].func) (context,
				      TEST_ACTION_FLAG_BENCHMARK
				      | TEST_ACTION_FLAG_DEALLOCATE);
	}
      timer_stop ();

      time_delta = timer_delta ();
      printf ("%16s: %10s\t(%5i)\n",
	      test->actions[i].name, time_delta, test->actions[i].loop);
    }

  if (context)
    (*test->context_destroy) (context);
}

static void
test_show_version (void)
{
  printf ("%s (%s) %s\n", program_name, PACKAGE_NAME, PACKAGE_VERSION);
  exit (EXIT_SUCCESS);
}

static void
test_execute (test_mode_implementation_t implementation, test_t *test,
	      char **identifiers, size_t identifiers_n)
{
  unsigned int i = 0;

  printf ("Test: %s\n\n", test->name);
  
  if (identifiers)
    for (i = 0; i < identifiers_n; i++)
      {
	printf (" * %s\n", identifiers[i]);
	(*implementation) (test, identifiers[i]);
      }
  else
    (*implementation) (test, NULL);

  printf ("\nDone.\n");
}

static void
test_show_help (test_mode_t mode)
{
  printf ("\
Usage: %s [OPTION]... %s[IDENTIFIER]...\n\
\n\
  -h, --help     Display this help and exit\n\
  -v, --verbose  Be more verbose\n\
      --version  Display version information and exit\n\
\n\
Report bugs to %s.\n", program_name,
	  (mode == TEST_MODE_BENCHMARK) ? "<TEST NAME> " : "",
	  PACKAGE_BUGREPORT);

  exit (EXIT_SUCCESS);
}

static char *
test_path_component_extract_last (const char *path)
{
  char *component_last = NULL;
  char *component_last_cp = NULL;
  char *component_second_last = NULL;
  char *delimiter = NULL;
  char *path_cp = NULL;

  path_cp = strdup (path);
  if (path_cp)
    {
      component_last = path_cp;

      do
	{
	  delimiter = strchr (component_last, '/');
	  if (delimiter)
	    {
	      component_second_last = component_last;
	      component_last = delimiter;
	      *component_last++ = 0;
	      while (*component_last == '/')
		component_last++;
	      if (! *component_last)
		{
		  component_last = component_second_last;
		  delimiter = NULL;
		}
	    }
	}
      while (delimiter);
  
      component_last_cp = strdup (component_last);
      test_assert (component_last_cp);
      free (path_cp);
    }

  return component_last_cp;
}

static void
test_arguments_parse_default (int argc, char **argv, test_mode_t mode,
			      test_mode_implementation_t implementation)
{
  unsigned int flag_verbose = 0;
  char **identifiers = NULL;
  size_t identifiers_n = 0;
  char *test_name = NULL;
  test_t *test = NULL;

#ifdef HAVE_GETOPT_H
  struct option options_long[] =
    {
      { "verbose", no_argument, &flag_verbose, 1 },
      { "version", no_argument, 0, 'v' },
      { "help", no_argument, 0, 'h' },
      { NULL }
    };
  int option_index = 0;
#endif
  const char *options_short = "hv";
  int c = 0;

  do
    {
#ifdef HAVE_GETOPT_H
      c = getopt_long (argc, argv, options_short, options_long, &option_index);
#else
      c = getopt (argc, argv, options_short);
#endif

      switch (c)
	{
	case 'v':
	  test_show_version ();
	  break;

	case 'h':
	  test_show_help (mode);
	  break;
	}
    }
  while (c != -1);

  if (flag_verbose)
    test_mode_flags = TEST_MODE_VERBOSE;
  
  switch (mode)
    {
    case TEST_MODE_STANDALONE:
      test_name = test_path_component_extract_last (argv[0]);
      break;

    case TEST_MODE_BENCHMARK:
      if (optind < argc)
	test_name = argv[optind++];
      break;
    }

  test_assert (test_name);
  test = test_lookup (test_name);
  test_assert (test);

  if (test->type == TEST_TYPE_GLUED)
    {
      /* Special handling for glued-in tests.  */

      test_assert (test->arguments_set);

      switch (mode)
	{
	case TEST_MODE_STANDALONE:
	  (*test->arguments_set) (argc, argv);
	  break;

	case TEST_MODE_BENCHMARK:
	  test_assert (optind == 2);
	  (*test->arguments_set) (argc - 1, argv + 1);
	  break;
	}
    }
  else
    {
      if (optind < argc)
	{
	  test_assert (test->type == TEST_TYPE_MAPPING);
	  
	  /* Use identifiers provided as arguments.  */
	  identifiers = argv + optind;
	  identifiers_n = argc - optind;
	}
      else
	{
	  /* Get a list of all supported identifiers.  */
	  (*test->identifiers_get) (&identifiers, &identifiers_n);
	}
    }

  test_execute (implementation, test, identifiers, identifiers_n);

  if (identifiers != argv + optind)
    free (identifiers);
  
  if (mode == TEST_MODE_STANDALONE)
    free (test_name);
}

static void
test_run_common (int argc, char **argv, test_mode_t mode,
		 test_mode_implementation_t implementation)
{
  test_arguments_parse_default (argc, argv, mode, implementation);
}

static void
test_run_standalone (int argc, char **argv, test_mode_t mode)
{
  test_run_common (argc, argv, mode, test_implementation_standalone);
}

static void
test_run_benchmark (int argc, char **argv, test_mode_t mode)
{
  test_run_common (argc, argv, mode, test_implementation_benchmark);
}

static test_mode_spec_t test_modes[] =
  {
    { TEST_MODE_STANDALONE, test_run_standalone },
    { TEST_MODE_BENCHMARK,  test_run_benchmark  },
  };

static test_mode_run_t
test_mode_run_get (test_mode_t mode)
{
  test_mode_run_t run = NULL;
  unsigned int i = 0;

  for (i = 0; (i < (sizeof (test_modes) / sizeof (*test_modes))) && (! run); i++)
    if (test_modes[i].mode == mode)
      run = test_modes[i].run;

  return run;
}

static void
test_init (void)
{
  gcry_check_version (NULL);
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
}

gcry_error_t
test_run (int argc, char **argv, test_mode_t mode)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  test_mode_run_t run = NULL;

  program_name = argv[0];

  test_init ();
  
  run = test_mode_run_get (mode);
  test_assert (run);

  (*run) (argc, argv, mode);
  
  return err;
}
