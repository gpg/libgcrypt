/* mpiutil.ac  -  Utility functions for MPI
 * Copyright (C) 1998, 2000, 2001, 2002 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "g10lib.h"
#include "mpi-internal.h"
#include "memory.h"

/****************
 * Note:  It was a bad idea to use the number of limbs to allocate
 *	  because on a alpha the limbs are large but we normally need
 *	  integers of n bits - So we should chnage this to bits (or bytes).
 *
 *	  But mpi_alloc is used in a lot of places :-)
 */
MPI
_gcry_mpi_alloc( unsigned nlimbs )
{
    MPI a;

    a = gcry_xmalloc( sizeof *a );
    a->d = nlimbs? mpi_alloc_limb_space( nlimbs, 0 ) : NULL;
    a->alloced = nlimbs;
    a->nlimbs = 0;
    a->sign = 0;
    a->flags = 0;
    return a;
}

void
_gcry_mpi_m_check( MPI a )
{
    _gcry_check_heap(a);
    _gcry_check_heap(a->d);
}

MPI
_gcry_mpi_alloc_secure( unsigned nlimbs )
{
    MPI a;

    a = gcry_xmalloc( sizeof *a );
    a->d = nlimbs? mpi_alloc_limb_space( nlimbs, 1 ) : NULL;
    a->alloced = nlimbs;
    a->flags = 1;
    a->nlimbs = 0;
    a->sign = 0;
    return a;
}



mpi_ptr_t
_gcry_mpi_alloc_limb_space( unsigned nlimbs, int secure )
{
    size_t len = nlimbs * sizeof(mpi_limb_t);
    mpi_ptr_t p;

    p = secure? gcry_xmalloc_secure( len ) : gcry_xmalloc( len );

    return p;
}

void
_gcry_mpi_free_limb_space( mpi_ptr_t a )
{
    if( !a )
	return;
    gcry_free(a);
}


void
_gcry_mpi_assign_limb_space( MPI a, mpi_ptr_t ap, unsigned nlimbs )
{
    mpi_free_limb_space(a->d);
    a->d = ap;
    a->alloced = nlimbs;
}



/****************
 * Resize the array of A to NLIMBS. the additional space is cleared
 * (set to 0) [done by gcry_realloc()]
 */
void
_gcry_mpi_resize( MPI a, unsigned nlimbs )
{
    if( nlimbs <= a->alloced )
	return; /* no need to do it */
    /* Note: a->secure is not used - instead the realloc functions
     * take care of it. Maybe we should drop a->secure completely
     * and rely on a mpi_is_secure function, which would be
     * a wrapper around gcry_is_secure
     */
    if( a->d )
	a->d = gcry_xrealloc(a->d, nlimbs * sizeof(mpi_limb_t) );
    else  /* FIXME: It may not be allocted in secure memory */
	a->d = gcry_xcalloc( nlimbs , sizeof(mpi_limb_t) );
    a->alloced = nlimbs;
}

void
_gcry_mpi_clear( MPI a )
{
    a->nlimbs = 0;
    a->flags = 0;
}


void
_gcry_mpi_free( MPI a )
{
    if( !a )
	return;
    if( a->flags & 4 )
	gcry_free( a->d );
    else {
	mpi_free_limb_space(a->d);
    }
    if( a->flags & ~7 )
	log_bug("invalid flag value in mpi\n");
    gcry_free(a);
}

static void
mpi_set_secure( MPI a )
{
    mpi_ptr_t ap, bp;

    if( (a->flags & 1) )
	return;
    a->flags |= 1;
    ap = a->d;
    if( !a->nlimbs ) {
	assert(!ap);
	return;
    }
    bp = mpi_alloc_limb_space( a->nlimbs, 1 );
    MPN_COPY( bp, ap, a->nlimbs );
    a->d = bp;
    mpi_free_limb_space(ap);
}


MPI
gcry_mpi_set_opaque( MPI a, void *p, unsigned int nbits )
{
    if( !a ) {
	a = mpi_alloc(0);
    }

    if( a->flags & 4 )
	gcry_free( a->d );
    else {
	mpi_free_limb_space(a->d);
    }

    a->d = p;
    a->alloced = 0;
    a->nlimbs = 0;
    a->sign  = nbits;
    a->flags = 4;
    return a;
}


void *
gcry_mpi_get_opaque( MPI a, unsigned int *nbits )
{
    if( !(a->flags & 4) )
	log_bug("mpi_get_opaque on normal mpi\n");
    if( nbits )
	*nbits = a->sign;
    return a->d;
}


/****************
 * Note: This copy function should not interpret the MPI
 *	 but copy it transparently.
 */
MPI
_gcry_mpi_copy( MPI a )
{
    int i;
    MPI b;

    if( a && (a->flags & 4) ) {
	void *p = gcry_is_secure(a->d)? gcry_xmalloc_secure( (a->sign+7)/8 )
				     : gcry_xmalloc( (a->sign+7)/8 );
	memcpy( p, a->d, (a->sign+7)/8 );
	b = gcry_mpi_set_opaque( NULL, p, a->sign );
    }
    else if( a ) {
	b = mpi_is_secure(a)? mpi_alloc_secure( a->nlimbs )
			    : mpi_alloc( a->nlimbs );
	b->nlimbs = a->nlimbs;
	b->sign = a->sign;
	b->flags  = a->flags;
	for(i=0; i < b->nlimbs; i++ )
	    b->d[i] = a->d[i];
    }
    else
	b = NULL;
    return b;
}


/****************
 * This function allocates an MPI which is optimized to hold
 * a value as large as the one given in the argument and allocates it
 * with the same flags as A.
 */
MPI
_gcry_mpi_alloc_like( MPI a )
{
    MPI b;

    if( a && (a->flags & 4) ) {
	int n = (a->sign+7)/8;
	void *p = gcry_is_secure(a->d)? gcry_malloc_secure( n )
				     : gcry_malloc( n );
	memcpy( p, a->d, n );
	b = gcry_mpi_set_opaque( NULL, p, a->sign );
    }
    else if( a ) {
	b = mpi_is_secure(a)? mpi_alloc_secure( a->nlimbs )
			    : mpi_alloc( a->nlimbs );
	b->nlimbs = 0;
	b->sign = 0;
	b->flags = a->flags;
    }
    else
	b = NULL;
    return b;
}


void
_gcry_mpi_set( MPI w, MPI u)
{
    mpi_ptr_t wp, up;
    mpi_size_t usize = u->nlimbs;
    int usign = u->sign;

    RESIZE_IF_NEEDED(w, usize);
    wp = w->d;
    up = u->d;
    MPN_COPY( wp, up, usize );
    w->nlimbs = usize;
    w->flags = u->flags;
    w->sign = usign;
}


void
_gcry_mpi_set_ui( MPI w, unsigned long u)
{
    RESIZE_IF_NEEDED(w, 1);
    w->d[0] = u;
    w->nlimbs = u? 1:0;
    w->sign = 0;
    w->flags = 0;
}


MPI
_gcry_mpi_alloc_set_ui( unsigned long u)
{
    MPI w = mpi_alloc(1);
    w->d[0] = u;
    w->nlimbs = u? 1:0;
    w->sign = 0;
    return w;
}


void
_gcry_mpi_swap( MPI a, MPI b)
{
    struct gcry_mpi tmp;

    tmp = *a; *a = *b; *b = tmp;
}

void
gcry_mpi_swap( MPI a, MPI b)
{
  _gcry_mpi_swap (a, b);
}


GCRY_MPI
gcry_mpi_new( unsigned int nbits )
{
    return _gcry_mpi_alloc( (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}


GCRY_MPI
gcry_mpi_snew( unsigned int nbits )
{
    return _gcry_mpi_alloc_secure( (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}

void
gcry_mpi_release( GCRY_MPI a )
{
    _gcry_mpi_free( a );
}

GCRY_MPI
gcry_mpi_copy( const GCRY_MPI a )
{
    return _gcry_mpi_copy( (GCRY_MPI)a );
}

GCRY_MPI
gcry_mpi_set( GCRY_MPI w, const GCRY_MPI u )
{
    if( !w )
	w = _gcry_mpi_alloc( mpi_get_nlimbs(u) );
    _gcry_mpi_set( w, (GCRY_MPI)u );
    return w;
}

GCRY_MPI
gcry_mpi_set_ui( GCRY_MPI w, unsigned long u )
{
    if( !w )
	w = _gcry_mpi_alloc(1);
    _gcry_mpi_set_ui( w, u );
    return w;
}


void
gcry_mpi_randomize( GCRY_MPI w,
		    unsigned int nbits, enum gcry_random_level level )
{
    char *p = mpi_is_secure(w) ? gcry_random_bytes( (nbits+7)/8, level )
			       : gcry_random_bytes_secure( (nbits+7)/8, level );
    _gcry_mpi_set_buffer( w, p, (nbits+7)/8, 0 );
    gcry_free(p);
}


void
gcry_mpi_set_flag( GCRY_MPI a, enum gcry_mpi_flag flag )
{
    switch( flag ) {
      case GCRYMPI_FLAG_SECURE:  mpi_set_secure(a); break;
      case GCRYMPI_FLAG_OPAQUE:
      default: log_bug("invalid flag value\n");
    }
}

void
gcry_mpi_clear_flag( GCRY_MPI a, enum gcry_mpi_flag flag )
{
    switch( flag ) {
      case GCRYMPI_FLAG_SECURE:
      case GCRYMPI_FLAG_OPAQUE:
      default: log_bug("invalid flag value\n");
    }
}

int
gcry_mpi_get_flag( GCRY_MPI a, enum gcry_mpi_flag flag )
{
    switch( flag ) {
      case GCRYMPI_FLAG_SECURE: return (a->flags & 1);
      case GCRYMPI_FLAG_OPAQUE: return (a->flags & 4);
      default: log_bug("invalid flag value\n");
    }
}

