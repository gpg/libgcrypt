/* test-glue.h - Glue in old tests into the new Libgcrypt test suite.
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

/* The purpose of this file is to integrate test programs into the
   test suite, without much modification.  */

#ifndef TEST_GLUE_H
#define TEST_GLUE_H

#include "test.h"

#ifndef TEST_NAME
# error TEST_NAME has to be defined
#endif

#define _concat_3(a, b, c) a ## b ## c
#define concat_3(a, b, c) _concat_3 (a, b, c)

#define main concat_3 (main_wrapped_, TEST_NAME, )

#else

static int test_argc;
static char **test_argv;

static void
concat_3 (test_, TEST_NAME, _arguments_set) (int argc, char **argv)
{
  test_argc = argc;
  test_argv = argv;
}

static void
test_action_main (test_context_t ctx, unsigned int flags)
{
  int ret = concat_3 (main_wrapped_, TEST_NAME, ) (test_argc, test_argv);
  test_assert (! ret);
}

test_action_t concat_3 (test_actions_, TEST_NAME, )[] =
  {
    { "main", test_action_main, 2 },
  };

test_t concat_3 (test_spec_, TEST_NAME, ) =
{
  stringify (concat_3 (TEST_NAME, , )),
  TEST_TYPE_GLUED,
  NULL,
  NULL,
  NULL,
  concat_3 (test_, TEST_NAME, _arguments_set),
  concat_3 (test_actions_, TEST_NAME, ),
  DIM (concat_3 (test_actions_, TEST_NAME, ))
};

#endif
