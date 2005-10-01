/* mpiutil.c  -  Utility functions for MPI
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>



/****************
 * Note:  It was a bad idea to use the number of limbs to allocate
 *	  because on a alpha the limbs are large but we normally need
 *	  integers of n bits - So we should chnage this to bits (or bytes).
 *
 *	  But _gcry_mpi_alloc is used in a lot of places :-)
 */
gcry_core_mpi_t
_gcry_mpi_alloc(gcry_core_context_t ctx,  unsigned nlimbs )
{
    gcry_core_mpi_t a;

    a = gcry_core_xmalloc(ctx, sizeof *a );
    a->d = nlimbs? _gcry_mpi_alloc_limb_space(ctx, nlimbs, 0 ) : NULL;
    a->alloced = nlimbs;
    a->nlimbs = 0;
    a->sign = 0;
    a->flags = 0;
    return a;
}

void
_gcry_mpi_m_check( gcry_core_mpi_t a )
{
#if 0
  /* FIXME, implement?  */
    _gcry_check_heap(a);
    _gcry_check_heap(a->d);
#endif
}

gcry_core_mpi_t
_gcry_mpi_alloc_secure(gcry_core_context_t ctx, unsigned nlimbs )
{
    gcry_core_mpi_t a;

    a = gcry_core_xmalloc(ctx, sizeof *a );
    a->d = nlimbs? _gcry_mpi_alloc_limb_space(ctx, nlimbs, 1 ) : NULL;
    a->alloced = nlimbs;
    a->flags = 1;
    a->nlimbs = 0;
    a->sign = 0;
    return a;
}



mpi_ptr_t
_gcry_mpi_alloc_limb_space(gcry_core_context_t ctx,  unsigned int nlimbs, int secure )
{
    mpi_ptr_t p;
    size_t len;

    len = (nlimbs ? nlimbs : 1) * sizeof (mpi_limb_t);
    p = secure ? gcry_core_xmalloc_secure (ctx, len) : gcry_core_xmalloc (ctx, len);
    if (! nlimbs)
      *p = 0;

    return p;
}

void
_gcry_mpi_free_limb_space(gcry_core_context_t ctx,  mpi_ptr_t a, unsigned int nlimbs)
{
  if (a)
    {
      size_t len = nlimbs * sizeof(mpi_limb_t);
      
      /* If we have information on the number of allocated limbs, we
         better wipe that space out.  This is a failsafe feature if
         secure memory has been disabled or was not properly
         implemented in user provided allocation functions. */
      if (len)
        wipememory (a, len);
      gcry_core_free(ctx, a);
    }
}


void
_gcry_mpi_assign_limb_space( gcry_core_context_t ctx, gcry_core_mpi_t a, mpi_ptr_t ap, unsigned int nlimbs )
{
  _gcry_mpi_free_limb_space (ctx, a->d, a->alloced);
  a->d = ap;
  a->alloced = nlimbs;
}



/****************
 * Resize the array of A to NLIMBS. the additional space is cleared
 * (set to 0) [done by gcry_realloc()]
 */
void
_gcry_mpi_resize (gcry_core_context_t ctx, gcry_core_mpi_t a, unsigned nlimbs)
{
  if (nlimbs <= a->alloced)
    return; /* no need to do it */

  if (a->d)
    a->d = gcry_core_xrealloc (ctx, a->d, nlimbs * sizeof (mpi_limb_t));
  else
    {
      if (a->flags & 1)
	/* Secure memory is wanted.  */
	a->d = gcry_core_xcalloc_secure (ctx, nlimbs , sizeof (mpi_limb_t));
      else
	/* Standard memory.  */
	a->d = gcry_core_xcalloc (ctx, nlimbs , sizeof (mpi_limb_t));
    }
  a->alloced = nlimbs;
}

void
_gcry_mpi_clear( gcry_core_mpi_t a )
{
    a->nlimbs = 0;
    a->flags = 0;
}


void
_gcry_mpi_free(gcry_core_context_t ctx,  gcry_core_mpi_t a )
{
  if (!a )
    return;
  if ((a->flags & 4))
    gcry_core_free(ctx, a->d );
  else
    {
      _gcry_mpi_free_limb_space(ctx, a->d, a->alloced);
    }
  if ((a->flags & ~7))
    log_bug(ctx, "invalid flag value in mpi\n");
  gcry_core_free(ctx, a);
}

static void
mpi_set_secure(gcry_core_context_t ctx,  gcry_core_mpi_t a )
{
  mpi_ptr_t ap, bp;

  if ( (a->flags & 1) )
    return;
  a->flags |= 1;
  ap = a->d;
  if (!a->nlimbs)
    {
      assert(!ap);
      return;
    }
  bp = _gcry_mpi_alloc_limb_space (ctx, a->nlimbs, 1);
  MPN_COPY( bp, ap, a->nlimbs );
  a->d = bp;
  _gcry_mpi_free_limb_space (ctx, ap, a->alloced);
}


gcry_core_mpi_t
_gcry_mpi_set_opaque(gcry_core_context_t ctx,  gcry_core_mpi_t a, void *p, unsigned int nbits )
{
  if (!a) 
    a = _gcry_mpi_alloc(ctx, 0);
    
  if( a->flags & 4 )
    gcry_core_free( ctx, a->d );
  else 
    _gcry_mpi_free_limb_space (ctx, a->d, a->alloced);

  a->d = p;
  a->alloced = 0;
  a->nlimbs = 0;
  a->sign  = nbits;
  a->flags = 4;
  return a;
}


void *
_gcry_mpi_get_opaque(gcry_core_context_t ctx, gcry_core_mpi_t a, unsigned int *nbits )
{
    if( !(a->flags & 4) )
	log_bug(ctx, "_gcry_mpi_get_opaque on normal mpi\n");
    if( nbits )
	*nbits = a->sign;
    return a->d;
}


/****************
 * Note: This copy function should not interpret the MPI
 *	 but copy it transparently.
 */
gcry_core_mpi_t
_gcry_mpi_copy_do ( gcry_core_context_t ctx,  gcry_core_mpi_t a )
{
    int i;
    gcry_core_mpi_t b;

    if( a && (a->flags & 4) ) {
	void *p = (gcry_core_is_secure(ctx, a->d)
		   ? gcry_core_xmalloc_secure(ctx, (a->sign+7)/8 )
		   : gcry_core_xmalloc(ctx, (a->sign+7)/8 ));
	memcpy( p, a->d, (a->sign+7)/8 );
	b = gcry_core_mpi_set_opaque( ctx, NULL, p, a->sign );
    }
    else if( a ) {
	b = mpi_is_secure(a)? _gcry_mpi_alloc_secure(ctx, a->nlimbs )
			    : _gcry_mpi_alloc(ctx, a->nlimbs );
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
gcry_core_mpi_t
_gcry_mpi_alloc_like(gcry_core_context_t ctx,  gcry_core_mpi_t a )
{
    gcry_core_mpi_t b;

    if( a && (a->flags & 4) ) {
	int n = (a->sign+7)/8;
	void *p = gcry_core_is_secure(ctx, a->d)? gcry_core_malloc_secure( ctx, n )
				     : gcry_core_malloc( ctx, n );
	memcpy( p, a->d, n );
	b = gcry_core_mpi_set_opaque( ctx, NULL, p, a->sign );
    }
    else if( a ) {
	b = mpi_is_secure(a)? _gcry_mpi_alloc_secure(ctx, a->nlimbs )
			    : _gcry_mpi_alloc(ctx, a->nlimbs );
	b->nlimbs = 0;
	b->sign = 0;
	b->flags = a->flags;
    }
    else
	b = NULL;
    return b;
}

void
_gcry_mpi_set_do (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u)
{
    mpi_ptr_t wp, up;
    mpi_size_t usize = u->nlimbs;
    int usign = u->sign;

    RESIZE_IF_NEEDED(ctx, w, usize);
    wp = w->d;
    up = u->d;
    MPN_COPY( wp, up, usize );
    w->nlimbs = usize;
    w->flags = u->flags;
    w->sign = usign;
}


void
_gcry_mpi_set_ui_do(gcry_core_context_t ctx, gcry_core_mpi_t w, unsigned long u)
{
    RESIZE_IF_NEEDED(ctx, w, 1);
    w->d[0] = u;
    w->nlimbs = u? 1:0;
    w->sign = 0;
    w->flags = 0;
}

gcry_error_t
_gcry_mpi_get_ui (gcry_core_context_t ctx,
		       gcry_core_mpi_t w, unsigned long *u)
{
  gcry_error_t err = 0;
  unsigned long x = 0;

  if (w->nlimbs > 1)
    err = gpg_error (GPG_ERR_TOO_LARGE);
  else if (w->nlimbs == 1)
    x = w->d[0];
  else
    x = 0;

  if (! err)
    *u = x;
  
  return err;
}

gcry_core_mpi_t
_gcry_mpi_alloc_set_ui( gcry_core_context_t ctx,  unsigned long u)
{
    gcry_core_mpi_t w = _gcry_mpi_alloc(ctx, 1);
    w->d[0] = u;
    w->nlimbs = u? 1:0;
    w->sign = 0;
    return w;
}

void
_gcry_mpi_swap( gcry_core_context_t ctx, gcry_core_mpi_t a, gcry_core_mpi_t b)
{
    struct gcry_mpi tmp;

    tmp = *a; *a = *b; *b = tmp;
}

gcry_core_mpi_t
_gcry_mpi_new(gcry_core_context_t ctx, unsigned int nbits )
{
    return _gcry_mpi_alloc(ctx,
			   (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}


gcry_core_mpi_t
_gcry_mpi_secure_new(gcry_core_context_t ctx, unsigned int nbits )
{
    return _gcry_mpi_alloc_secure(ctx, (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB );
}

void
_gcry_mpi_release(gcry_core_context_t ctx,  gcry_core_mpi_t a )
{
    _gcry_mpi_free(ctx, a );
}

gcry_core_mpi_t
_gcry_mpi_copy (gcry_core_context_t ctx, const gcry_core_mpi_t a )
{
    return _gcry_mpi_copy_do (ctx, (gcry_core_mpi_t)a );
}

gcry_core_mpi_t
_gcry_mpi_set( gcry_core_context_t ctx,  gcry_core_mpi_t w, const gcry_core_mpi_t u )
{
    if( !w )
	w = _gcry_mpi_alloc( ctx, mpi_get_nlimbs(u) );
    _gcry_mpi_set_do (ctx, w, (gcry_core_mpi_t)u );
    return w;
}

gcry_core_mpi_t
_gcry_mpi_set_ui( gcry_core_context_t ctx,  gcry_core_mpi_t w, unsigned long u )
{
    if( !w )
	w = _gcry_mpi_alloc(ctx, 1);
    _gcry_mpi_set_ui_do (ctx, w, u );
    return w;
}

void
_gcry_mpi_set_flag(gcry_core_context_t ctx, gcry_core_mpi_t a, enum gcry_mpi_flag flag )
{
    switch( flag ) {
      case GCRYMPI_FLAG_SECURE:  mpi_set_secure(ctx, a); break;
      case GCRYMPI_FLAG_OPAQUE:
      default: log_bug(ctx, "invalid flag value\n");
    }
}

void
_gcry_mpi_clear_flag( gcry_core_context_t ctx, gcry_core_mpi_t a, enum gcry_mpi_flag flag )
{
    switch( flag ) {
      case GCRYMPI_FLAG_SECURE:
      case GCRYMPI_FLAG_OPAQUE:
      default: log_bug(ctx, "invalid flag value\n");
    }
}

int
_gcry_mpi_get_flag( gcry_core_context_t ctx,gcry_core_mpi_t a, enum gcry_mpi_flag flag )
{
    switch( flag ) {
      case GCRYMPI_FLAG_SECURE: return (a->flags & 1);
      case GCRYMPI_FLAG_OPAQUE: return (a->flags & 4);
      default: log_bug(ctx, "invalid flag value\n");
    }
}

/* END. */
