/* mpiapi.ac  -  MPI function interface
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#ifdef _GCRYPT_H
  #error  gcrypt.h already in libc
#endif

#define GCRYPT_NO_MPI_MACROS 1
#include "gcrypt.h"
#include "mpi.h"



int
gcry_mpi_api( enum gcry_mpi_opcode opcode, int n_args, ... )
{
    switch( opcode ) {
      case GCRYMPI_NOOP:
	return 0;

      default:
	return GCRYERR_INV_OP;
    }
}


struct gcry_mpi *
gcry_mpi_new( enum gcry_mpi_opcode opcode,
	      unsigned int nbits, struct gcry_mpi *val)
{
    switch( opcode ) {
      case GCRYMPI_NEW:
	return mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );

      case GCRYMPI_SNEW:
	return mpi_alloc_secure( (nbits+BITS_PER_MPI_LIMB-1)
				 / BITS_PER_MPI_LIMB );
      case GCRYMPI_COPY:
	return mpi_copy( val );

      default:
	return NULL;
    }
}

