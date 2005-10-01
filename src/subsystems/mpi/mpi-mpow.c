/* mpi-mpow.c  -  MPI functions
 *	Copyright (C) 1998, 1999, 2001, 2002, 2003 Free Software Foundation, Inc.
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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "longlong.h"

/* Barrett is slower than the classical way.  It can be tweaked by
 * using partial multiplications
 */
/*#define USE_BARRETT*/



#ifdef USE_BARRETT
static void barrett_mulm(gcry_core_context_t ctx,  gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m, gcry_core_mpi_t y, int k, gcry_core_mpi_t r1, gcry_core_mpi_t r2 );
static gcry_core_mpi_t init_barrett( gcry_core_context_t ctx,gcry_core_mpi_t m, int *k, gcry_core_mpi_t *r1, gcry_core_mpi_t *r2 );
static int calc_barrett( gcry_core_context_t ctx,gcry_core_mpi_t r, gcry_core_mpi_t x, gcry_core_mpi_t m, gcry_core_mpi_t y, int k, gcry_core_mpi_t r1, gcry_core_mpi_t r2  );
#else
#define barrett_mulm( c, w, u, v, m, y, k, r1, r2 ) gcry_core_mpi_mulm( (c), (w), (u), (v), (m) )
#endif


static int
build_index( gcry_core_context_t ctx, gcry_core_mpi_t *exparray, int k, int i, int t )
{
    int j, bitno;
    int idx = 0;

    bitno = t-i;
    for(j=k-1; j >= 0; j-- ) {
	idx <<= 1;
	if( _gcry_mpi_test_bit( ctx, exparray[j], bitno ) )
	    idx |= 1;
    }
    /*log_debug("t=%d i=%d idx=%d\n", t, i, idx );*/
    return idx;
}

/****************
 * RES = (BASE[0] ^ EXP[0]) *  (BASE[1] ^ EXP[1]) * ... * mod M
 */
void
_gcry_mpi_mulpowm(gcry_core_context_t ctx, gcry_core_mpi_t res, gcry_core_mpi_t *basearray, gcry_core_mpi_t *exparray, gcry_core_mpi_t m)
{
    int k;	/* number of elements */
    int t;	/* bit size of largest exponent */
    int i, j, idx;
    gcry_core_mpi_t *G;	/* table with precomputed values of size 2^k */
    gcry_core_mpi_t tmp;
#ifdef USE_BARRETT
    gcry_core_mpi_t barrett_y, barrett_r1, barrett_r2;
    int barrett_k;
#endif

    for(k=0; basearray[k]; k++ )
	;
    assert(k);
    for(t=0, i=0; (tmp=exparray[i]); i++ ) {
	/*_gcry_log_mpidump("exp: ", tmp );*/
	j = _gcry_mpi_get_nbits(ctx,tmp);
	if( j > t )
	    t = j;
    }
    /*_gcry_log_mpidump("mod: ", m );*/
    assert(i==k);
    assert(t);
    assert( k < 10 );

    G = gcry_core_xcalloc(ctx, (1<<k) , sizeof *G );
#ifdef USE_BARRETT
    barrett_y = init_barrett(ctx, m, &barrett_k, &barrett_r1, &barrett_r2 );
#endif
    /* and calculate */
    tmp =  _gcry_mpi_alloc(ctx, mpi_get_nlimbs(m)+1 );
    _gcry_mpi_set_ui_do (ctx, res, 1 );
    for(i = 1; i <= t; i++ ) {
	barrett_mulm(ctx, tmp, res, res, m, barrett_y, barrett_k,
				       barrett_r1, barrett_r2 );
	idx = build_index( ctx, exparray, k, i, t );
	assert( idx >= 0 && idx < (1<<k) );
	if( !G[idx] ) {
	    if( !idx )
		 G[0] = _gcry_mpi_alloc_set_ui( ctx, 1 );
	    else {
		for(j=0; j < k; j++ ) {
		    if( (idx & (1<<j) ) ) {
			if( !G[idx] )
			    G[idx] = _gcry_mpi_copy_do( ctx, basearray[j] );
			else
			    barrett_mulm(ctx, G[idx], G[idx], basearray[j],
					       m, barrett_y, barrett_k, barrett_r1, barrett_r2	);
		    }
		}
		if( !G[idx] )
		    G[idx] = _gcry_mpi_alloc(ctx, 0);
	    }
	}
	barrett_mulm(ctx, res, tmp, G[idx], m, barrett_y, barrett_k, barrett_r1, barrett_r2	);
    }

    /* cleanup */
    _gcry_mpi_free(ctx, tmp);
#ifdef USE_BARRETT
    _gcry_mpi_free(ctx, barrett_y);
    _gcry_mpi_free(ctx, barrett_r1);
    _gcry_mpi_free(ctx, barrett_r2);
#endif
    for(i=0; i < (1<<k); i++ )
	_gcry_mpi_free(ctx, G[i]);
    gcry_core_free(ctx,G);
}

#ifdef USE_BARRETT
static void
barrett_mulm( gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m, gcry_core_mpi_t y, int k, gcry_core_mpi_t r1, gcry_core_mpi_t r2	)
{
    _gcry_mpi_mul(ctx, w, u, v);
    if( calc_barrett(ctx, w, w, m, y, k, r1, r2 ) )
	_gcry_mpi_fdiv_r(ctx, w, w, m );
}

/****************
 * Barrett precalculation: y = floor(b^(2k) / m)
 */
static gcry_core_mpi_t
init_barrett(gcry_core_context_t ctx, gcry_core_mpi_t m, int *k, gcry_core_mpi_t *r1, gcry_core_mpi_t *r2 )
{
    gcry_core_mpi_t tmp;

    _gcry_mpi_normalize( m );
    *k = mpi_get_nlimbs( m );
    tmp = _gcry_mpi_alloc(ctx, *k + 1 );
    _gcry_mpi_set_ui_do (ctx, tmp, 1 );
    mpi_lshift_limbs( ctx, tmp, 2 * *k );
    _gcry_mpi_fdiv_q(ctx, tmp, tmp, m );
    *r1 = _gcry_mpi_alloc(ctx, 2* *k + 1 );
    *r2 = _gcry_mpi_alloc(ctx, 2* *k + 1 );
    return tmp;
}

/****************
 * Barrett reduction: We assume that these conditions are met:
 * Given x =(x_2k-1 ...x_0)_b
 *	 m =(m_k-1 ....m_0)_b	  with m_k-1 != 0
 * Output r = x mod m
 * Before using this function init_barret must be used to calucalte y and k.
 * Returns: false = no error
 *	    true = can't perform barret reduction
 */
static int
calc_barrett(gcry_core_context_t ctx, gcry_core_mpi_t r, gcry_core_mpi_t x, gcry_core_mpi_t m, gcry_core_mpi_t y, int k, gcry_core_mpi_t r1, gcry_core_mpi_t r2 )
{
    int xx = k > 3 ? k-3:0;

    _gcry_mpi_normalize( x );
    if( mpi_get_nlimbs(x) > 2*k )
	return 1; /* can't do it */

    /* 1. q1 = floor( x / b^k-1)
     *	  q2 = q1 * y
     *	  q3 = floor( q2 / b^k+1 )
     * Actually, we don't need qx, we can work direct on r2
     */
    _gcry_mpi_set_do(ctx, r2, x );
    mpi_rshift_limbs( ctx, r2, k-1 );
    _gcry_mpi_mul( ctx, r2, r2, y );
    mpi_rshift_limbs( ctx, r2, k+1 );

    /* 2. r1 = x mod b^k+1
     *	  r2 = q3 * m mod b^k+1
     *	  r  = r1 - r2
     * 3. if r < 0 then  r = r + b^k+1
     */
    _gcry_mpi_set_do(ctx, r1, x );
    if( r1->nlimbs > k+1 ) /* quick modulo operation */
	r1->nlimbs = k+1;
    _gcry_mpi_mul( ctx, r2, r2, m );
    if( r2->nlimbs > k+1 ) /* quick modulo operation */
	r2->nlimbs = k+1;
    _gcry_mpi_sub( ctx, r, r1, r2 );

    if( mpi_is_neg( r ) ) {
	gcry_core_mpi_t tmp;

	tmp = _gcry_mpi_alloc(ctx, k + 2 );
	_gcry_mpi_set_ui_do (ctx, tmp, 1 );
	mpi_lshift_limbs( ctx, tmp, k+1 );
	_gcry_mpi_add( ctx, r, r, tmp );
	_gcry_mpi_free(ctx, tmp);
    }

    /* 4. while r >= m do r = r - m */
    while( _gcry_mpi_cmp( ctx, r, m ) >= 0 )
	_gcry_mpi_sub( ctx, r, r, m );

    return 0;
}
#endif /* USE_BARRETT */
