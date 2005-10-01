/* mpiutil.ac  -  Utility functions for MPI
 * Copyright (C) 1998, 2000, 2001, 2002, 2003,
 *               2005 Free Software Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gcrypt-mpi-internal.h>
#include <gcrypt-random-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>



void
_gcry_mpi_randomize( gcry_core_context_t ctx, gcry_core_mpi_t w,
		     unsigned int nbits, enum gcry_random_level level )
{
  char *p;
  size_t nbytes = (nbits+7)/8;
  
  if (level == GCRY_WEAK_RANDOM)
    {
      p = (mpi_is_secure(w)
	   ? gcry_core_xmalloc_secure (ctx, nbytes)
	   : gcry_core_xmalloc (ctx, nbytes));
      gcry_core_random_create_nonce (ctx, p, nbytes);
    }
  else
    {
      p = mpi_is_secure(w) ? gcry_core_random_bytes_secure (ctx, nbytes, level)
                           : gcry_core_random_bytes (ctx, nbytes, level);
    }
  _gcry_mpi_set_buffer( ctx, w, p, nbytes, 0 );
  gcry_core_free (ctx, p);
}

/* END. */
