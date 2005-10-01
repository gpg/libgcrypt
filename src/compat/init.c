/* init.c - Libgcrypt-compat initialization
   Copyright (C) 2005 g10 Code GmbH

   This file is part of Libgcrypt.
 
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
 
   Libgcrypt is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU Lesser General Public
   License along with Libgcrypt; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <gcrypt-internal.h>

#include <gcrypt-secmem-internal.h>
#include <gcrypt-mpi-internal.h>
#include <gcrypt-md-internal.h>
#include <gcrypt-cipher-internal.h>
#include <gcrypt-random-internal.h>
#include <gcrypt-sexp-internal.h>
#include <gcrypt-prime-internal.h>

#include <gcrypt-ath-internal.h>

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

gcry_core_context_t context;

static void _gcry_init_do (void);
void (*_gcry_init) (void) = _gcry_init_do;

static void
_gcry_init_stage1 (void)
{
  if (! context)
    {
      size_t context_size;

      /* Create context.  */
      context_size = gcry_core_context_size ();
      context = malloc (context_size);
      assert (context);
      gcry_core_context_init (context);
    }
}

static void
_gcry_init_stage2 (void)
{
  gcry_error_t err = 0;

  /* Install included subsystems.  */

  gcry_core_set_subsystem_secmem (context, gcry_core_subsystem_secmem);
  gcry_core_set_subsystem_mpi (context, gcry_core_subsystem_mpi);
  gcry_core_set_subsystem_md (context, gcry_core_subsystem_md);
  gcry_core_set_subsystem_cipher (context, gcry_core_subsystem_cipher);
  gcry_core_set_subsystem_ac (context, gcry_core_subsystem_ac);
  gcry_core_set_subsystem_random (context, gcry_core_subsystem_random);
  gcry_core_set_subsystem_sexp (context, gcry_core_subsystem_sexp);
  gcry_core_context_set_prime (context, gcry_core_subsystem_prime);

  /* Install included handlers.  */

  gcry_core_set_handler_mem (context, malloc, realloc, free, NULL, NULL);
  gcry_core_set_handler_log (context, gcry_core_default_log_handler, stderr);

  /* Prepare context for actual use.  */

  gcry_core_context_prepare (context);

  /* Initialize subsystem wrappers.  */
  
  err = _gcry_cipher_init ();
  if (! err)
    err = _gcry_md_init ();
  if (! err)
    err = _gcry_ac_init ();

  if (err)
    BUG (context);
}



static void
_gcry_init_noop (void)
{
}

static void
_gcry_init_do (void )
{
  _gcry_init_stage1 ();
  _gcry_init_stage2 ();
  _gcry_init = _gcry_init_noop;
}



void
_gcry_init_stage1_only (void)
{
  _gcry_init_stage1 ();
}

unsigned int
_gcry_init_done_p (void)
{
  return _gcry_init == _gcry_init_noop;
}

/* END. */
