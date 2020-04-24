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
static mpi_ptr_t
mpih_invm_odd (mpi_ptr_t ap, mpi_ptr_t np, mpi_size_t nsize)
{
  int secure;
  unsigned int iterations;
  mpi_ptr_t n1hp;
  mpi_ptr_t bp;
  mpi_ptr_t up, vp;

  secure = _gcry_is_secure (ap);
  up = mpi_alloc_limb_space (nsize, secure);
  MPN_ZERO (up, nsize);
  up[0] = 1;

  vp = mpi_alloc_limb_space (nsize, secure);
  MPN_ZERO (vp, nsize);

  secure = _gcry_is_secure (np);
  bp = mpi_alloc_limb_space (nsize, secure);
  MPN_COPY (bp, np, nsize);

  n1hp = mpi_alloc_limb_space (nsize, secure);
  MPN_COPY (n1hp, np, nsize);
  _gcry_mpih_rshift (n1hp, n1hp, nsize, 1);
  _gcry_mpih_add_1 (n1hp, n1hp, nsize, 1);

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
      mpih_add_n_cond (up, up, np, nsize, borrow);

      odd_u = _gcry_mpih_rshift (up, up, nsize, 1) != 0;
      mpih_add_n_cond (up, up, n1hp, nsize, odd_u);
    }

  _gcry_mpi_free_limb_space (n1hp, nsize);
  _gcry_mpi_free_limb_space (up, nsize);

  if (_gcry_mpih_cmp_ui (bp, nsize, 1) == 0)
    {
      /* Inverse exists.  */
      _gcry_mpi_free_limb_space (bp, nsize);
      return vp;
    }
  else
    {
      _gcry_mpi_free_limb_space (bp, nsize);
      _gcry_mpi_free_limb_space (vp, nsize);
      return NULL;
    }
}


/*
 * Calculate the multiplicative inverse X of A mod 2^K
 * A must be positive.
 *
 * See section 7 in "A New Algorithm for Inversion mod p^k" by Çetin
 * Kaya Koç: https://eprint.iacr.org/2017/411.pdf
 */
static int
mpi_invm_pow2 (gcry_mpi_t x, gcry_mpi_t a_orig, unsigned int k)
{
  gcry_mpi_t a, b, tb;
  unsigned int i, iterations;
  mpi_ptr_t wp, up, vp;
  mpi_size_t usize;

  if (!mpi_test_bit (a_orig, 0))
    return 0;

  iterations = ((k + BITS_PER_MPI_LIMB - 1) / BITS_PER_MPI_LIMB)
    * BITS_PER_MPI_LIMB;
  usize = iterations / BITS_PER_MPI_LIMB;

  a = mpi_copy (a_orig);
  mpi_clear_highbit (a, k);
  mpi_resize (a, usize);

  b = mpi_alloc_set_ui (1);
  mpi_resize (b, usize);
  b->nlimbs = usize;

  tb = mpi_copy (b);

  mpi_set_ui (x, 0);
  mpi_resize (x, usize);
  x->nlimbs = usize;

  up = b->d;
  vp = a->d;
  wp = tb->d;

  /*
   * In the loop, B can be negative, but in the MPI
   * representation, we don't set b->sign.
   */
  for (i = 0; i < iterations; i++)
    {
      int b0 = mpi_test_bit (b, 0);

      mpi_set_bit_cond (x, i, b0);

      _gcry_mpih_sub_n (wp, up, vp, usize);
      mpih_set_cond (up, wp, usize, b0);
      _gcry_mpih_rshift (up, up, usize, 1);
    }

  mpi_free (tb);
  mpi_free (b);
  mpi_free (a);

  mpi_clear_highbit (x, k);
  return 1;
}


/****************
 * Calculate the multiplicative inverse X of A mod N
 * That is: Find the solution x for
 *		1 = (a*x) mod n
 */
static int
mpi_invm_generic (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t n)
{
#if 0
    gcry_mpi_t u, v, u1, u2, u3, v1, v2, v3, q, t1, t2, t3;
    gcry_mpi_t ta, tb, tc;

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
     * modified according to Michael Penk's solution for Exercise 35 */

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
    /* mpi_lshift( u3, k ); */
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
    /* mpi_lshift( u3, k ); */
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
    return 1;
}


int
_gcry_mpi_invm (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t n)
{
  if (!mpi_cmp_ui (a, 0))
    return 0; /* Inverse does not exists.  */
  if (!mpi_cmp_ui (n, 1))
    return 0; /* Inverse does not exists.  */

  if (mpi_test_bit (n, 0))
    {
      mpi_ptr_t ap, xp;

      if (a->nlimbs <= n->nlimbs)
        {
          ap = mpi_alloc_limb_space (n->nlimbs, _gcry_is_secure (a->d));
          MPN_ZERO (ap, n->nlimbs);
          MPN_COPY (ap, a->d, a->nlimbs);
        }
      else
        ap = _gcry_mpih_mod (a->d, a->nlimbs, n->d, n->nlimbs);

      xp = mpih_invm_odd (ap, n->d, n->nlimbs);
      _gcry_mpi_free_limb_space (ap, n->nlimbs);

      if (xp)
        {
          _gcry_mpi_assign_limb_space (x, xp, n->nlimbs);
          x->nlimbs = n->nlimbs;
          return 1;
        }
      else
        return 0; /* Inverse does not exists.  */
    }
  else if (!a->sign && !n->sign)
    {
      unsigned int k = mpi_trailing_zeros (n);
      gcry_mpi_t q, x1, q_inv, h;
      mpi_ptr_t ap, xp;

      if (k == _gcry_mpi_get_nbits (n) - 1)
        return mpi_invm_pow2 (x, a, k);

      /* N can be expressed as P * Q, where P = 2^K.  P and Q are coprime.  */
      /*
       * Compute X1 = invm (A, P) and X2 = invm (A, Q), and combine
       * them by Garner's formula, to get X = invm (A, P*Q).
       * A special case of Chinese Remainder Theorem.
       */

      /* X1 = invm (A, P) */
      x1 = mpi_new (0);
      if (!mpi_invm_pow2 (x1, a, k))
        return 0;               /* Inverse does not exists.  */

      /* Q = N / P          */
      q = mpi_new (0);
      mpi_rshift (q, n, k);

      /* X2 = invm (A%Q, Q), stored in X */
      ap = _gcry_mpih_mod (a->d, a->nlimbs, q->d, q->nlimbs);
      xp = mpih_invm_odd (ap, q->d, q->nlimbs);
      _gcry_mpi_free_limb_space (ap, q->nlimbs);
      if (!xp)
        {
          mpi_free (x1);
          mpi_free (q);
          return 0;             /* Inverse does not exists.  */
        }
      _gcry_mpi_assign_limb_space (x, xp, q->nlimbs);
      x->nlimbs = q->nlimbs;

      /* Q_inv = Q^(-1) = invm (Q, P) */
      q_inv = mpi_new (0);
      mpi_invm_pow2 (q_inv, q, k);

      /* H = (X1 - X2) * Q_inv % P */
      h = mpi_new (0);
      mpi_sub (h, x1, x);
      if (h->sign)
        {
          mpi_size_t i;

          h->sign = 0;
          for (i = 0; i < h->nlimbs; i++)
            h->d[i] = ~h->d[i];
          mpi_add_ui (h, h, 1);
          mpi_clear_highbit (h, k);
        }
      mpi_mul (h, h, q_inv);
      mpi_clear_highbit (h, k);

      mpi_free (x1);
      mpi_free (q_inv);

      /* X = X2 + (H * Q) */
      mpi_mul (h, h, q);
      mpi_add (x, h, x);

      mpi_free (q);
      mpi_free (h);

      return 1;
    }
  else
    return mpi_invm_generic (x, a, n);
}
