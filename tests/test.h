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

#ifndef GCRYPT_INCLUDED_TEST_H
#define GCRYPT_INCLUDED_TEST_H

/* This test suite makes it possible to use the individual tests in
   two different ways:

   1) First, they can be used as `standalone' programs, which means
      that they will be run once in order to verify the correct
      behaviour of the library.

   2) Second, they can be used in a `benchmark' mode, which means that
      certain parts of the code will be run several times in order to
      time the library functions.

   The test suite is splitted up into `tests'; each test, one per
   file, consists of one or several `test actions'.  */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <gcrypt.h>



#define TEST_ACTION_FLAG_RUN        (1 << 0)
#define TEST_ACTION_FLAG_DEALLOCATE (1 << 1)
#define TEST_ACTION_FLAG_BENCHMARK  (1 << 2)



/* Valid test types.  */
typedef enum test_type
  {
    TEST_TYPE_SINGLE,
    TEST_TYPE_MAPPING,
    TEST_TYPE_GLUED,
  }
test_type_t;

/* Context, passed to each execution of a test action.  */
typedef void *test_context_t;

/* Type for a test action implementation.  */
typedef void (*test_action_func_t) (test_context_t context, unsigned int flags);

/* Information for each test action.  */
typedef struct test_action
{
  const char *name;
  test_action_func_t func;
  unsigned int loop;
} test_action_t;

/* Initialize the context for a test.  If the test is a mapping one,
   identifier has to be a valid string, otherwise it should be
   NULL.  */
typedef void (*test_context_init_t) (const char *identifier, test_context_t *context);

/* Destroy a test context.  */
typedef void (*test_context_destroy_t) (test_context_t context);

/* Receive a list of all supported identifiers for a mapping test.  */
typedef void (*test_identifiers_get_t) (char ***identifier, unsigned int *identifier_n);

typedef void (*test_arguments_set_t) (int argc, char **argv);

typedef struct test
{
  const char *name;
  test_type_t type;
  test_context_init_t context_init;
  test_context_destroy_t context_destroy;
  test_identifiers_get_t identifiers_get;
  test_arguments_set_t arguments_set;
  test_action_t *actions;
  unsigned int actions_n;
} test_t;

/* Valid test modes.  */
typedef enum test_mode
  {
    TEST_MODE_STANDALONE,
    TEST_MODE_BENCHMARK,
  }
test_mode_t;



/* Stringify X.  */
#define _stringify(s) # s
#define stringify(s) _stringify (s)

/* Make sure that EXPR evaluates to true.  */
#define test_assert(expr) \
  if (! (expr)) \
    { \
      fprintf (stderr, "Test: %s:%i: Assertion `%s' failed.\n", \
               __FILE__, __LINE__, stringify (expr)); \
      exit (EXIT_FAILURE); \
    }

/* Make sure that ERR is zero.  */
#define test_assert_err(err) \
  if (err) \
    { \
      fprintf (stderr, "Test: %s:%i: Error: %s\n", \
               __FILE__, __LINE__, gpg_strerror (err)); \
      exit (EXIT_FAILURE); \
    }



#ifndef DIM
#define DIM(array) sizeof (array) / sizeof (*array)
#endif

#define TEST_GROUP_DEFINE(type, identifier) \
test_t test_spec_##identifier = \
  { \
    #identifier, \
    TEST_TYPE_##type, \
    test_context_##identifier##_init, \
    test_context_##identifier##_destroy, \
    test_##identifier##_identifiers_get, \
    NULL, \
    test_actions_##identifier, \
    DIM (test_actions_##identifier) \
  }



/* Parse arguments, run the according test.  */
gcry_error_t test_run (int argc, char **argv, test_mode_t mode);

#endif
