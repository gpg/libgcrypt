/* mpi-inv.c  -  MPI functions
 *	Copyright (C) 1998, 2001, 2002, 2003 Free Software Foundation, Inc.
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "mpi-internal.h"
#include "g10lib.h"

/*
 *  W = U + V when OP_ENABLED=1
 *  otherwise, W = U
 */
static mpi_limb_t
mpih_add_n_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_ptr_t vp, mpi_size_t usize,
                 unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t cy;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;

  cy = 0;
  for (i = 0; i < usize; i++)
    {
      mpi_limb_t x = up[i] + (vp[i] & mask);
      mpi_limb_t cy1 = x < up[i];
      mpi_limb_t cy2;

      x = x + cy;
      cy2 = x < cy;
      cy = cy1 | cy2;
      wp[i] = x;
    }

  return cy;
}


/*
 *  W = U - V when OP_ENABLED=1
 *  otherwise, W = U
 */
static mpi_limb_t
mpih_sub_n_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_ptr_t vp, mpi_size_t usize,
                 unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t cy;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;

  cy = 0;
  for (i = 0; i < usize; i++)
    {
      mpi_limb_t x = up[i] - (vp[i] & mask);
      mpi_limb_t cy1 = x > up[i];
      mpi_limb_t cy2;

      cy2 = x < cy;
      x = x - cy;
      cy = cy1 | cy2;
      wp[i] = x;
    }

  return cy;
}


/*
 *  Swap value of U and V when OP_ENABLED=1
 *  otherwise, no change
 */
static void
mpih_swap_cond (mpi_ptr_t up, mpi_ptr_t vp, mpi_size_t usize,
                unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;

  for (i = 0; i < usize; i++)
    {
      mpi_limb_t x = mask & (up[i] ^ vp[i]);

      up[i] = up[i] ^ x;
      vp[i] = vp[i] ^ x;
    }
}


/*
 *  W = -U when OP_ENABLED=1
 *  otherwise, W = U
 */
static void
mpih_abs_cond (mpi_limb_t *wp, const mpi_limb_t *up, mpi_size_t usize,
               unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;
  mpi_limb_t cy = op_enable;

  for (i = 0; i < usize; i++)
    {
      mpi_limb_t x = ~up[i] + cy;

      cy = (x < ~up[i]);
      wp[i] = up[i] ^ (mask & (x ^ up[i]));
    }
}


/*
 * This uses a modular inversion algorithm designed by Niels Möller
 * which was implemented in Nettle.  The same algorithm was later also
 * adapted to GMP in mpn_sec_invert.
 *
 * For the description of the algorithm, see Algorithm 5 in Appendix A
 * of "Fast Software Polynomial Multiplication on ARM Processors using
 * the NEON Engine" by Danilo Câmara, Conrado P. L. Gouvêa, Julio
 * López, and Ricardo Dahab:
 *   https://hal.inria.fr/hal-01506572/document
 *
 * Note that in the reference above, at the line 2 of Algorithm 5,
 * initial value of V was described as V:=1 wrongly.  It must be V:=0.
 */
static int
mpi_invm_odd (gcry_mpi_t x, gcry_mpi_t a_orig, gcry_mpi_t n)
{
  mpi_size_t nsize;
  gcry_mpi_t a, b, n1h;
  gcry_mpi_t u;
  unsigned int iterations;
  mpi_ptr_t ap, bp, n1hp;
  mpi_ptr_t up, vp;
  int is_gcd_one;

  nsize = n->nlimbs;

  a = mpi_copy (a_orig);
  mpi_resize (a, nsize);
  ap = a->d;

  b = mpi_copy (n);
  bp = b->d;

  u = mpi_alloc_set_ui (1);
  mpi_resize (u, nsize);
  up = u->d;

  mpi_resize (x, nsize);
  x->nlimbs = nsize;
  vp = x->d;
  memset (vp, 0, nsize * BYTES_PER_MPI_LIMB);

  n1h = mpi_copy (n);
  mpi_rshift (n1h, n1h, 1);
  mpi_add_ui (n1h, n1h, 1);
  mpi_resize (n1h, nsize);

  n1hp = n1h->d;

  iterations = 2 * nsize * BITS_PER_MPI_LIMB;

  while (iterations-- > 0)
    {
      mpi_limb_t odd_a, odd_u, underflow, borrow;

      odd_a = ap[0] & 1;

      underflow = mpih_sub_n_cond (ap, ap, bp, nsize, odd_a);
      mpih_add_n_cond (bp, bp, ap, nsize, underflow);
      mpih_abs_cond (ap, ap, nsize, underflow);
      mpih_swap_cond (up, vp, nsize, underflow);

      _gcry_mpih_rshift (ap, ap, nsize, 1);

      borrow = mpih_sub_n_cond (up, up, vp, nsize, odd_a);
      mpih_add_n_cond (up, up, n->d, nsize, borrow);

      odd_u = _gcry_mpih_rshift (up, up, nsize, 1) != 0;
      mpih_add_n_cond (up, up, n1hp, nsize, odd_u);
    }

  is_gcd_one = (mpi_cmp_ui (b, 1) == 0);

  mpi_free (n1h);
  mpi_free (u);
  mpi_free (b);
  mpi_free (a);

  return is_gcd_one;
}

/****************
 * Calculate the multiplicative inverse X of A mod N
 * That is: Find the solution x for
 *		1 = (a*x) mod n
 */
static int
mpi_invm_generic (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t n)
{
    int is_gcd_one;
#if 0
    /* Extended Euclid's algorithm (See TAOCP Vol II, 4.5.2, Alg X) */
    gcry_mpi_t u, v, u1, u2, u3, v1, v2, v3, q, t1, t2, t3;

    u = mpi_copy(a);
    v = mpi_copy(n);
    u1 = mpi_alloc_set_ui(1);
    u2 = mpi_alloc_set_ui(0);
    u3 = mpi_copy(u);
    v1 = mpi_alloc_set_ui(0);
    v2 = mpi_alloc_set_ui(1);
    v3 = mpi_copy(v);
    q  = mpi_alloc( mpi_get_nlimbs(u)+1 );
    t1 = mpi_alloc( mpi_get_nlimbs(u)+1 );
    t2 = mpi_alloc( mpi_get_nlimbs(u)+1 );
    t3 = mpi_alloc( mpi_get_nlimbs(u)+1 );
    while( mpi_cmp_ui( v3, 0 ) ) {
	mpi_fdiv_q( q, u3, v3 );
	mpi_mul(t1, v1, q); mpi_mul(t2, v2, q); mpi_mul(t3, v3, q);
	mpi_sub(t1, u1, t1); mpi_sub(t2, u2, t2); mpi_sub(t3, u3, t3);
	mpi_set(u1, v1); mpi_set(u2, v2); mpi_set(u3, v3);
	mpi_set(v1, t1); mpi_set(v2, t2); mpi_set(v3, t3);
    }
    /*	log_debug("result:\n");
	log_mpidump("q =", q );
	log_mpidump("u1=", u1);
	log_mpidump("u2=", u2);
	log_mpidump("u3=", u3);
	log_mpidump("v1=", v1);
	log_mpidump("v2=", v2); */
    mpi_set(x, u1);

    is_gcd_one = (mpi_cmp_ui (u3, 1) == 0);

    mpi_free(u1);
    mpi_free(u2);
    mpi_free(u3);
    mpi_free(v1);
    mpi_free(v2);
    mpi_free(v3);
    mpi_free(q);
    mpi_free(t1);
    mpi_free(t2);
    mpi_free(t3);
    mpi_free(u);
    mpi_free(v);
#elif 0
    /* Extended Euclid's algorithm (See TAOCP Vol II, 4.5.2, Alg X)
     * modified according to Michael Penk's solution for Exercise 35
     * (in the first edition)
     * In the third edition, it's Exercise 39, and it is described in
     * page 646 of ANSWERS TO EXERCISES chapter.
     */

    /* FIXME: we can simplify this in most cases (see Knuth) */
    gcry_mpi_t u, v, u1, u2, u3, v1, v2, v3, t1, t2, t3;
    unsigned k;
    int sign;

    u = mpi_copy(a);
    v = mpi_copy(n);
    for(k=0; !mpi_test_bit(u,0) && !mpi_test_bit(v,0); k++ ) {
	mpi_rshift(u, u, 1);
	mpi_rshift(v, v, 1);
    }


    u1 = mpi_alloc_set_ui(1);
    u2 = mpi_alloc_set_ui(0);
    u3 = mpi_copy(u);
    v1 = mpi_copy(v);				   /* !-- used as const 1 */
    v2 = mpi_alloc( mpi_get_nlimbs(u) ); mpi_sub( v2, u1, u );
    v3 = mpi_copy(v);
    if( mpi_test_bit(u, 0) ) { /* u is odd */
	t1 = mpi_alloc_set_ui(0);
	t2 = mpi_alloc_set_ui(1); t2->sign = 1;
	t3 = mpi_copy(v); t3->sign = !t3->sign;
	goto Y4;
    }
    else {
	t1 = mpi_alloc_set_ui(1);
	t2 = mpi_alloc_set_ui(0);
	t3 = mpi_copy(u);
    }
    do {
	do {
	    if( mpi_test_bit(t1, 0) || mpi_test_bit(t2, 0) ) { /* one is odd */
		mpi_add(t1, t1, v);
		mpi_sub(t2, t2, u);
	    }
	    mpi_rshift(t1, t1, 1);
	    mpi_rshift(t2, t2, 1);
	    mpi_rshift(t3, t3, 1);
	  Y4:
	    ;
	} while( !mpi_test_bit( t3, 0 ) ); /* while t3 is even */

	if( !t3->sign ) {
	    mpi_set(u1, t1);
	    mpi_set(u2, t2);
	    mpi_set(u3, t3);
	}
	else {
	    mpi_sub(v1, v, t1);
	    sign = u->sign; u->sign = !u->sign;
	    mpi_sub(v2, u, t2);
	    u->sign = sign;
	    sign = t3->sign; t3->sign = !t3->sign;
	    mpi_set(v3, t3);
	    t3->sign = sign;
	}
	mpi_sub(t1, u1, v1);
	mpi_sub(t2, u2, v2);
	mpi_sub(t3, u3, v3);
	if( t1->sign ) {
	    mpi_add(t1, t1, v);
	    mpi_sub(t2, t2, u);
	}
    } while( mpi_cmp_ui( t3, 0 ) ); /* while t3 != 0 */
    /* mpi_lshift( u3, u3, k ); */
    is_gcd_one = (k == 0 && mpi_cmp_ui (u3, 1) == 0);
    mpi_set(x, u1);

    mpi_free(u1);
    mpi_free(u2);
    mpi_free(u3);
    mpi_free(v1);
    mpi_free(v2);
    mpi_free(v3);
    mpi_free(t1);
    mpi_free(t2);
    mpi_free(t3);
#else
    /* Extended Euclid's algorithm (See TAOCP Vol II, 4.5.2, Alg X)
     * modified according to Michael Penk's solution for Exercise 35
     * with further enhancement */
    /* The reference in the comment above is for the first edition.
     * In the third edition, it's Exercise 39, and it is described in
     * page 646 of ANSWERS TO EXERCISES chapter.
     */
    gcry_mpi_t u, v, u1, u2=NULL, u3, v1, v2=NULL, v3, t1, t2=NULL, t3;
    unsigned k;
    int sign;
    int odd ;

    u = mpi_copy(a);
    v = mpi_copy(n);

    for(k=0; !mpi_test_bit(u,0) && !mpi_test_bit(v,0); k++ ) {
	mpi_rshift(u, u, 1);
	mpi_rshift(v, v, 1);
    }
    odd = mpi_test_bit(v,0);

    u1 = mpi_alloc_set_ui(1);
    if( !odd )
	u2 = mpi_alloc_set_ui(0);
    u3 = mpi_copy(u);
    v1 = mpi_copy(v);
    if( !odd ) {
	v2 = mpi_alloc( mpi_get_nlimbs(u) );
	mpi_sub( v2, u1, u ); /* U is used as const 1 */
    }
    v3 = mpi_copy(v);
    if( mpi_test_bit(u, 0) ) { /* u is odd */
	t1 = mpi_alloc_set_ui(0);
	if( !odd ) {
	    t2 = mpi_alloc_set_ui(1); t2->sign = 1;
	}
	t3 = mpi_copy(v); t3->sign = !t3->sign;
	goto Y4;
    }
    else {
	t1 = mpi_alloc_set_ui(1);
	if( !odd )
	    t2 = mpi_alloc_set_ui(0);
	t3 = mpi_copy(u);
    }
    do {
	do {
	    if( !odd ) {
		if( mpi_test_bit(t1, 0) || mpi_test_bit(t2, 0) ) { /* one is odd */
		    mpi_add(t1, t1, v);
		    mpi_sub(t2, t2, u);
		}
		mpi_rshift(t1, t1, 1);
		mpi_rshift(t2, t2, 1);
		mpi_rshift(t3, t3, 1);
	    }
	    else {
		if( mpi_test_bit(t1, 0) )
		    mpi_add(t1, t1, v);
		mpi_rshift(t1, t1, 1);
		mpi_rshift(t3, t3, 1);
	    }
	  Y4:
	    ;
	} while( !mpi_test_bit( t3, 0 ) ); /* while t3 is even */

	if( !t3->sign ) {
	    mpi_set(u1, t1);
	    if( !odd )
		mpi_set(u2, t2);
	    mpi_set(u3, t3);
	}
	else {
	    mpi_sub(v1, v, t1);
	    sign = u->sign; u->sign = !u->sign;
	    if( !odd )
		mpi_sub(v2, u, t2);
	    u->sign = sign;
	    sign = t3->sign; t3->sign = !t3->sign;
	    mpi_set(v3, t3);
	    t3->sign = sign;
	}
	mpi_sub(t1, u1, v1);
	if( !odd )
	    mpi_sub(t2, u2, v2);
	mpi_sub(t3, u3, v3);
	if( t1->sign ) {
	    mpi_add(t1, t1, v);
	    if( !odd )
		mpi_sub(t2, t2, u);
	}
    } while( mpi_cmp_ui( t3, 0 ) ); /* while t3 != 0 */
    /* mpi_lshift( u3, u3, k ); */
    is_gcd_one = (k == 0 && mpi_cmp_ui (u3, 1) == 0);
    mpi_set(x, u1);

    mpi_free(u1);
    mpi_free(v1);
    mpi_free(t1);
    if( !odd ) {
	mpi_free(u2);
	mpi_free(v2);
	mpi_free(t2);
    }
    mpi_free(u3);
    mpi_free(v3);
    mpi_free(t3);

    mpi_free(u);
    mpi_free(v);
#endif
    return is_gcd_one;
}


/*
 * Set X to the multiplicative inverse of A mod M.  Return true if the
 * inverse exists.
 */
int
_gcry_mpi_invm (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t n)
{
  if (!mpi_cmp_ui (a, 0))
    return 0; /* Inverse does not exists.  */
  if (!mpi_cmp_ui (n, 1))
    return 0; /* Inverse does not exists.  */

  if (mpi_test_bit (n, 0) && mpi_cmp (a, n) < 0)
    return mpi_invm_odd (x, a, n);
  else
    return mpi_invm_generic (x, a, n);
}
