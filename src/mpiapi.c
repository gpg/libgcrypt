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
#include "../cipher/random.h"


GCRY_MPI
gcry_mpi_new( unsigned int nbits )
{
    return mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}


GCRY_MPI
gcry_mpi_snew( unsigned int nbits )
{
    return mpi_alloc_secure( (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}

void
gcry_mpi_release( GCRY_MPI a )
{
    mpi_free( a );
}

GCRY_MPI
gcry_mpi_copy( const GCRY_MPI a )
{
    return mpi_copy( (GCRY_MPI)a );
}

GCRY_MPI
gcry_mpi_set( GCRY_MPI w, const GCRY_MPI u )
{
    if( !w )
	w = mpi_alloc( mpi_get_nlimbs(u) );
    mpi_set( w, (GCRY_MPI)u );
    return w;
}

GCRY_MPI
gcry_mpi_set_ui( GCRY_MPI w, unsigned long u )
{
    if( !w )
	w = mpi_alloc(1);
    mpi_set_ui( w, u );
    return w;
}


int
gcry_mpi_cmp( const GCRY_MPI u, const GCRY_MPI v )
{
    return mpi_cmp( (GCRY_MPI)u, (GCRY_MPI)v );
}

int
gcry_mpi_cmp_ui( const GCRY_MPI u, unsigned long v )
{
    return mpi_cmp_ui( (GCRY_MPI)u, v );
}


void
gcry_mpi_randomize( GCRY_MPI w,
		    unsigned int nbits, enum gcry_random_level level )
{
    char *p = get_random_bits( nbits, level, mpi_is_secure(w) );
    mpi_set_buffer( w, p, (nbits+7)/8, 0 );
    m_free(p);
}



int
gcry_mpi_scan( struct gcry_mpi **ret_mpi, enum gcry_mpi_format format,
		const char *buffer, size_t *nbytes )
{
    struct gcry_mpi *a = NULL;
    unsigned int len;

    len = nbytes? *nbytes : strlen(buffer);

    /* TODO: add a way to allocate the MPI in secure memory
     * Hmmm: maybe it is better to retrieve this information from
     * the provided buffer. */
    if( format == GCRYMPI_FMT_STD ) {
	const byte *s = buffer;

	a = mpi_alloc( (len+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
	if( len ) { /* not zero */
	    a->sign = *s & 0x80;
	    if( a->sign ) {
		/* FIXME: we have to convert from 2compl to magnitude format */
		mpi_free(a);
		return GCRYERR_INTERNAL;
	    }
	    else
		mpi_set_buffer( a, s, len, 0 );
	}
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return 0;
    }
    else if( format == GCRYMPI_FMT_USG ) {
	a = mpi_alloc( (len+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
	if( len )  /* not zero */
	    mpi_set_buffer( a, buffer, len, 0 );
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return 0;
    }
    else if( format == GCRYMPI_FMT_PGP ) {
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
    else if( format == GCRYMPI_FMT_HEX ) {
	if( nbytes )
	    return GCRYERR_INV_ARG; /* can only handle C strings for now */
	a = mpi_alloc(0);
	if( mpi_fromstr( a, buffer ) )
	    return GCRYERR_INV_OBJ;
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

	if( n > len ) {
	    m_free(tmp);
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	}
	if( extra )
	    *s++ = 0;

	memcpy( s, tmp, n-extra );
	m_free(tmp);
	*nbytes = n;
	return 0;
    }
    else if( format == GCRYMPI_FMT_PGP ) {
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

	tmp = mpi_get_buffer( a, &n, NULL );
	if( !n || (*tmp & 0x80) )
	    extra=1;

	if( 2*n+3+1 > len ) {
	    m_free(tmp);
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	}
	if( a->sign )
	    *s++ = '-';
	if( extra ) {
	    *s++ = '0';
	    *s++ = '0';
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


void
gcry_mpi_powm( MPI w, MPI b, MPI e, MPI m )
{
    mpi_powm( w, b, e, m );
}


