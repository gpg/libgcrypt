/* standalone.c - Standalone wrapper for Libgcrypt tests.
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

#include "test.h"

int
main (int argc, char **argv)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;

  err = test_run (argc, argv, TEST_MODE_STANDALONE);

  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
