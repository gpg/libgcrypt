/* mpiapi.a  -	MPI function interface
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

#define GCRYPT_NO_MPI_MACROS 1
#include "g10lib.h"
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


int
gcry_mpi_scan( struct gcry_mpi **ret_mpi, enum gcry_mpi_format format,
		const char *buffer, size_t *nbytes )
{
    struct gcry_mpi *a = NULL;
    unsigned int len;

    len = nbytes? *nbytes : strlen(buffer);

    /* TODO: add formats to allocate the MPI in secure memory */
    if( format == GCRYMPI_FMT_STD ) {
	a = mpi_read_from_buffer( (char*)buffer, &len, 0 );
	if( nbytes )
	    *nbytes = len;
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return a? 0 : GCRYERR_INV_OBJ;
    }
    else if( format == GCRYMPI_FMT_SSH ) {
	const byte *s = buffer;
	size_t n;

	if( len < 4 )
	    return GCRYERR_TOO_SHORT;
	n = s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3];
	s += 4; len -= 4;
	if( n > len )
	    return GCRYERR_TOO_LARGE; /* or should it be too_short */

	a = mpi_alloc( (n+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
	if( len ) { /* not zero */
	    a->sign = *s & 0x80;
	    if( a->sign ) {
		/* FIXME: we have to convert from 2compl to magnitude format */
		mpi_free(a);
		return GCRYERR_INTERNAL;
	    }
	    else
		mpi_set_buffer( a, s, n, 0 );
	}
	if( nbytes )
	    *nbytes = n+4;
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return 0;
    }
    else
	return GCRYERR_INV_ARG;
}

/****************
 * Write a in format into buffer which has a length of *NBYTES.
 * Return the number of bytes actually written in nbytes.
 * TODO: Move this stuff to mpicoder.c or replace mpicoder.c
 */
int
gcry_mpi_print( enum gcry_mpi_format format, char *buffer, size_t *nbytes,
		 struct gcry_mpi *a )
{
    unsigned int nbits = mpi_get_nbits(a);
    size_t len;

    if( !nbytes )
	return GCRYERR_INV_ARG;

    len = *nbytes;
    if( format == GCRYMPI_FMT_STD ) {
	unsigned int n = (nbits + 7)/8;
	byte *s = buffer;
	char *tmp;

	if( a->sign )
	    return GCRYERR_INV_ARG; /* pgp format can only handle unsigned */

	if( n+2 > len )
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	s[0] = nbits >> 8;
	s[1] = nbits;

	tmp = mpi_get_buffer( a, &n, NULL );
	memcpy( s+2, tmp, n );
	m_free(tmp);
	*nbytes = n+2;
	return 0;
    }
    else if( format == GCRYMPI_FMT_SSH ) {
	byte *s = buffer;
	char *tmp;
	int extra = 0;
	unsigned int n;

	if( a->sign )
	    return GCRYERR_INTERNAL; /* can't handle it yet */

	tmp = mpi_get_buffer( a, &n, NULL );
	if( n && (*tmp & 0x80) ) {
	    n++;
	    extra=1;
	}

	if( n+4 > len ) {
	    m_free(tmp);
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	}
	*s++ = n >> 24;
	*s++ = n >> 16;
	*s++ = n >> 8;
	*s++ = n;
	if( extra )
	    *s++ = 0;

	memcpy( s, tmp, n-extra );
	m_free(tmp);
	*nbytes = 4+n;
	return 0;
    }
    else if( format == GCRYMPI_FMT_HEX ) {
	byte *s = buffer;
	byte *tmp;
	int i;
	int extra = 0;
	unsigned int n=0;

	if( a->sign )
	    return GCRYERR_INTERNAL; /* can't handle it yet */

	tmp = mpi_get_buffer( a, &n, NULL );
	if( n && (*tmp & 0x80) ) {
	    n++;
	    extra=1;
	}

	if( 2*n+2+1 > len ) {
	    m_free(tmp);
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	}
	if( extra || !n ) {
	    *s++ = '0';
	    *s++ = '0';
	    n += 2;
	}

       #if BYTES_PER_MPI_LIMB == 2
	  #define X "4"
       #elif BYTES_PER_MPI_LIMB == 4
	  #define X "8"
       #elif BYTES_PER_MPI_LIMB == 8
	  #define X "16"
       #else
	  #error please define the format here
       #endif
	for(i=0; i < n; i++ ) {
	    unsigned int c = tmp[i];
	    *s++ = (c >> 4) < 10? '0'+(c>>4) : 'A'+(c>>4)-10 ;
	    c &= 15;
	    *s++ = c < 10? '0'+c : 'A'+c-10 ;
	}
	*s++ = 0;
	*nbytes = (char*)s - buffer;
       #undef X
	return 0;
    }
    else
	return GCRYERR_INV_ARG;
}

