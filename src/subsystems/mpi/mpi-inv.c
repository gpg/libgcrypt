/* mpi-inv.c  -  MPI functions
 *	Copyright (C) 1998, 2001, 2002, 2003,
 *                    2005 Free Software Foundation, Inc.
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

/****************
 * Calculate the multiplicative inverse X of A mod N
 * That is: Find the solution x for
 *		1 = (a*x) mod n
 */
int
_gcry_mpi_invm(gcry_core_context_t ctx,   gcry_core_mpi_t x, gcry_core_mpi_t a, gcry_core_mpi_t n )
{
#if 0
    gcry_core_mpi_t u, v, u1, u2, u3, v1, v2, v3, q, t1, t2, t3;
    gcry_core_mpi_t ta, tb, tc;

    u = _gcry_mpi_copy_do(a);
    v = _gcry_mpi_copy_do(n);
    u1 = _gcry_mpi_alloc_set_ui(ctx, 1);
    u2 = _gcry_mpi_alloc_set_ui(ctx, 0);
    u3 = _gcry_mpi_copy_do(u);
    v1 = _gcry_mpi_alloc_set_ui(ctx, 0);
    v2 = _gcry_mpi_alloc_set_ui(ctx, 1);
    v3 = _gcry_mpi_copy_do(v);
    q  = _gcry_mpi_alloc(ctx, mpi_get_nlimbs(u)+1 );
    t1 = _gcry_mpi_alloc(ctx, mpi_get_nlimbs(u)+1 );
    t2 = _gcry_mpi_alloc(ctx, mpi_get_nlimbs(u)+1 );
    t3 = _gcry_mpi_alloc(ctx, mpi_get_nlimbs(u)+1 );
    while( _gcry_mpi_cmp_ui( ctx, v3, 0 ) ) {
	_gcry_mpi_fdiv_q( ctx, q, u3, v3 );
	_gcry_mpi_mul(t1, v1, q); _gcry_mpi_mul(t2, v2, q); _gcry_mpi_mul(t3, v3, q);
	_gcry_mpi_sub(t1, u1, t1); _gcry_mpi_sub(t2, u2, t2); _gcry_mpi_sub(t3, u3, t3);
	_gcry_mpi_set_do(u1, v1); _gcry_mpi_set_do(u2, v2); _gcry_mpi_set_do(u3, v3);
	_gcry_mpi_set_do(v1, t1); _gcry_mpi_set_do(v2, t2); _gcry_mpi_set_do(v3, t3);
    }
    /*	log_debug("result:\n");
	_gcry_log_mpidump("q =", q );
	_gcry_log_mpidump("u1=", u1);
	_gcry_log_mpidump("u2=", u2);
	_gcry_log_mpidump("u3=", u3);
	_gcry_log_mpidump("v1=", v1);
	_gcry_log_mpidump("v2=", v2); */
    _gcry_mpi_set_do(x, u1);

    _gcry_mpi_free(ctx, u1);
    _gcry_mpi_free(ctx, u2);
    _gcry_mpi_free(ctx, u3);
    _gcry_mpi_free(ctx, v1);
    _gcry_mpi_free(ctx, v2);
    _gcry_mpi_free(ctx, v3);
    _gcry_mpi_free(ctx, q);
    _gcry_mpi_free(ctx, t1);
    _gcry_mpi_free(ctx, t2);
    _gcry_mpi_free(ctx, t3);
    _gcry_mpi_free(ctx, u);
    _gcry_mpi_free(ctx, v);
#elif 0
    /* Extended Euclid's algorithm (See TAOCP Vol II, 4.5.2, Alg X)
     * modified according to Michael Penk's solution for Exercise 35 */

    /* FIXME: we can simplify this in most cases (see Knuth) */
    gcry_core_mpi_t u, v, u1, u2, u3, v1, v2, v3, t1, t2, t3;
    unsigned k;
    int sign;

    u = _gcry_mpi_copy_do(a);
    v = _gcry_mpi_copy_do(n);
    for(k=0; !_gcry_mpi_test_bit(u,0) && !_gcry_mpi_test_bit(v,0); k++ ) {
	_gcry_mpi_rshift(u, u, 1);
	_gcry_mpi_rshift(v, v, 1);
    }


    u1 = _gcry_mpi_alloc_set_ui(ctx, 1);
    u2 = _gcry_mpi_alloc_set_ui(ctx, 0);
    u3 = _gcry_mpi_copy_do(u);
    v1 = _gcry_mpi_copy_do(v);				   /* !-- used as const 1 */
    v2 = _gcry_mpi_alloc(ctx, mpi_get_nlimbs(u) ); _gcry_mpi_sub( v2, u1, u );
    v3 = _gcry_mpi_copy_do(v);
    if( _gcry_mpi_test_bit(u, 0) ) { /* u is odd */
	t1 = _gcry_mpi_alloc_set_ui(0);
	t2 = _gcry_mpi_alloc_set_ui(1); t2->sign = 1;
	t3 = _gcry_mpi_copy_do(v); t3->sign = !t3->sign;
	goto Y4;
    }
    else {
	t1 = _gcry_mpi_alloc_set_ui(1);
	t2 = _gcry_mpi_alloc_set_ui(0);
	t3 = _gcry_mpi_copy_do(u);
    }
    do {
	do {
	    if( _gcry_mpi_test_bit(t1, 0) || _gcry_mpi_test_bit(t2, 0) ) { /* one is odd */
		_gcry_mpi_add(t1, t1, v);
		_gcry_mpi_sub(t2, t2, u);
	    }
	    _gcry_mpi_rshift(t1, t1, 1);
	    _gcry_mpi_rshift(t2, t2, 1);
	    _gcry_mpi_rshift(t3, t3, 1);
	  Y4:
	    ;
	} while( !_gcry_mpi_test_bit( t3, 0 ) ); /* while t3 is even */

	if( !t3->sign ) {
	    _gcry_mpi_set_do(u1, t1);
	    _gcry_mpi_set_do(u2, t2);
	    _gcry_mpi_set_do(u3, t3);
	}
	else {
	    _gcry_mpi_sub(v1, v, t1);
	    sign = u->sign; u->sign = !u->sign;
	    _gcry_mpi_sub(v2, u, t2);
	    u->sign = sign;
	    sign = t3->sign; t3->sign = !t3->sign;
	    _gcry_mpi_set_do(v3, t3);
	    t3->sign = sign;
	}
	_gcry_mpi_sub(t1, u1, v1);
	_gcry_mpi_sub(t2, u2, v2);
	_gcry_mpi_sub(t3, u3, v3);
	if( t1->sign ) {
	    _gcry_mpi_add(t1, t1, v);
	    _gcry_mpi_sub(t2, t2, u);
	}
    } while( _gcry_mpi_cmp_ui( ctx, t3, 0 ) ); /* while t3 != 0 */
    /* mpi_lshift( u3, k ); */
    _gcry_mpi_set_do(x, u1);

    _gcry_mpi_free(ctx, u1);
    _gcry_mpi_free(ctx, u2);
    _gcry_mpi_free(ctx, u3);
    _gcry_mpi_free(ctx, v1);
    _gcry_mpi_free(ctx, v2);
    _gcry_mpi_free(ctx, v3);
    _gcry_mpi_free(ctx, t1);
    _gcry_mpi_free(ctx, t2);
    _gcry_mpi_free(ctx, t3);
#else
    /* Extended Euclid's algorithm (See TAOCP Vol II, 4.5.2, Alg X)
     * modified according to Michael Penk's solution for Exercise 35
     * with further enhancement */
    gcry_core_mpi_t u, v, u1, u2=NULL, u3, v1, v2=NULL, v3, t1, t2=NULL, t3;
    unsigned k;
    int sign;
    int odd ;

    u = _gcry_mpi_copy_do(ctx, a);
    v = _gcry_mpi_copy_do(ctx, n);

    for(k=0; !_gcry_mpi_test_bit(ctx,u,0) && !_gcry_mpi_test_bit(ctx,v,0); k++ ) {
	_gcry_mpi_rshift(ctx, u, u, 1);
	_gcry_mpi_rshift(ctx,v, v, 1);
    }
    odd = _gcry_mpi_test_bit(ctx,v,0);

    u1 = _gcry_mpi_alloc_set_ui(ctx, 1);
    if( !odd )
	u2 = _gcry_mpi_alloc_set_ui(ctx, 0);
    u3 = _gcry_mpi_copy_do(ctx, u);
    v1 = _gcry_mpi_copy_do(ctx, v);
    if( !odd ) {
	v2 = _gcry_mpi_alloc(ctx, mpi_get_nlimbs(u) );
	_gcry_mpi_sub( ctx,v2, u1, u ); /* U is used as const 1 */
    }
    v3 = _gcry_mpi_copy_do(ctx, v);
    if( _gcry_mpi_test_bit(ctx,u, 0) ) { /* u is odd */
	t1 = _gcry_mpi_alloc_set_ui(ctx, 0);
	if( !odd ) {
	    t2 = _gcry_mpi_alloc_set_ui(ctx, 1); t2->sign = 1;
	}
	t3 = _gcry_mpi_copy_do(ctx, v); t3->sign = !t3->sign;
	goto Y4;
    }
    else {
	t1 = _gcry_mpi_alloc_set_ui(ctx, 1);
	if( !odd )
	  t2 = _gcry_mpi_alloc_set_ui(ctx, 0);
	t3 = _gcry_mpi_copy_do(ctx, u);
    }
    do {
	do {
	    if( !odd ) {
		if( _gcry_mpi_test_bit(ctx,t1, 0) || _gcry_mpi_test_bit(ctx,t2, 0) ) { /* one is odd */
		    _gcry_mpi_add(ctx,t1, t1, v);
		    _gcry_mpi_sub(ctx,t2, t2, u);
		}
		_gcry_mpi_rshift(ctx,t1, t1, 1);
		_gcry_mpi_rshift(ctx,t2, t2, 1);
		_gcry_mpi_rshift(ctx,t3, t3, 1);
	    }
	    else {
		if( _gcry_mpi_test_bit(ctx,t1, 0) )
		    _gcry_mpi_add(ctx,t1, t1, v);
		_gcry_mpi_rshift(ctx,t1, t1, 1);
		_gcry_mpi_rshift(ctx,t3, t3, 1);
	    }
	  Y4:
	    ;
	} while( !_gcry_mpi_test_bit(ctx, t3, 0 ) ); /* while t3 is even */

	if( !t3->sign ) {
	    _gcry_mpi_set_do(ctx, u1, t1);
	    if( !odd )
		_gcry_mpi_set_do(ctx, u2, t2);
	    _gcry_mpi_set_do(ctx, u3, t3);
	}
	else {
	    _gcry_mpi_sub(ctx,v1, v, t1);
	    sign = u->sign; u->sign = !u->sign;
	    if( !odd )
		_gcry_mpi_sub(ctx,v2, u, t2);
	    u->sign = sign;
	    sign = t3->sign; t3->sign = !t3->sign;
	    _gcry_mpi_set_do(ctx, v3, t3);
	    t3->sign = sign;
	}
	_gcry_mpi_sub(ctx,t1, u1, v1);
	if( !odd )
	    _gcry_mpi_sub(ctx,t2, u2, v2);
	_gcry_mpi_sub(ctx,t3, u3, v3);
	if( t1->sign ) {
	    _gcry_mpi_add(ctx,t1, t1, v);
	    if( !odd )
		_gcry_mpi_sub(ctx,t2, t2, u);
	}
    } while( _gcry_mpi_cmp_ui( ctx, t3, 0 ) ); /* while t3 != 0 */
    /* mpi_lshift( u3, k ); */
    _gcry_mpi_set_do(ctx, x, u1);

    _gcry_mpi_free(ctx, u1);
    _gcry_mpi_free(ctx, v1);
    _gcry_mpi_free(ctx, t1);
    if( !odd ) {
	_gcry_mpi_free(ctx, u2);
	_gcry_mpi_free(ctx, v2);
	_gcry_mpi_free(ctx, t2);
    }
    _gcry_mpi_free(ctx, u3);
    _gcry_mpi_free(ctx, v3);
    _gcry_mpi_free(ctx, t3);

    _gcry_mpi_free(ctx, u);
    _gcry_mpi_free(ctx, v);
#endif

    return 1;
}

/* END. */
