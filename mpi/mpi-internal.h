/* mpi-internal.h  -  Internal to the Multi Precision Integers
 * Copyright (C) 1994, 1996, 1998, 2000, 2002,
 *               2003 Free Software Foundation, Inc.
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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Note: This code is heavily based on the GNU MP Library.
 *	 Actually it's the same code with only minor changes in the
 *	 way the data is stored; this is to support the abstraction
 *	 of an optional secure memory allocation which may be used
 *	 to avoid revealing of sensitive data due to paging etc.
 */

#ifndef G10_MPI_INTERNAL_H
#define G10_MPI_INTERNAL_H

#include "mpi-asm-defs.h"

#ifndef BITS_PER_MPI_LIMB
#if BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_INT
  typedef unsigned int mpi_limb_t;
  typedef   signed int mpi_limb_signed_t;
#elif BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_LONG
  typedef unsigned long int mpi_limb_t;
  typedef   signed long int mpi_limb_signed_t;
#elif BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_LONG_LONG
  typedef unsigned long long int mpi_limb_t;
  typedef   signed long long int mpi_limb_signed_t;
#elif BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_SHORT
  typedef unsigned short int mpi_limb_t;
  typedef   signed short int mpi_limb_signed_t;
#else
#error BYTES_PER_MPI_LIMB does not match any C type
#endif
#define BITS_PER_MPI_LIMB    (8*BYTES_PER_MPI_LIMB)
#endif /*BITS_PER_MPI_LIMB*/

#include "mpi.h"
#include "const-time.h"

/* If KARATSUBA_THRESHOLD is not already defined, define it to a
 * value which is good on most machines.  */

/* tested 4, 16, 32 and 64, where 16 gave the best performance when
 * checking a 768 and a 1024 bit ElGamal signature.
 * (wk 22.12.97) */
#ifndef KARATSUBA_THRESHOLD
#define KARATSUBA_THRESHOLD 16
#endif

/* The code can't handle KARATSUBA_THRESHOLD smaller than 2.  */
#if KARATSUBA_THRESHOLD < 2
#undef KARATSUBA_THRESHOLD
#define KARATSUBA_THRESHOLD 2
#endif


#define ABS(x) (x >= 0 ? x : -x)
#define MIN(l,o) ((l) < (o) ? (l) : (o))
#define MAX(h,i) ((h) > (i) ? (h) : (i))
#define RESIZE_IF_NEEDED(a,b) \
    do {			   \
	if( (a)->alloced < (b) )   \
	    mpi_resize((a), (b));  \
    } while(0)
#define RESIZE_AND_CLEAR_IF_NEEDED(a,b) \
    do {			   \
	if( (a)->nlimbs < (b) )   \
	    mpi_resize((a), (b));  \
    } while(0)

/* Copy N limbs from S to D.  */
#define MPN_COPY( d, s, n) \
    do {				\
	mpi_size_t _i;			\
	for( _i = 0; _i < (n); _i++ )	\
	    (d)[_i] = (s)[_i];		\
    } while(0)

#define MPN_COPY_INCR( d, s, n) 	\
    do {				\
	mpi_size_t _i;			\
	for( _i = 0; _i < (n); _i++ )	\
	    (d)[_i] = (s)[_i];		\
    } while (0)

#define MPN_COPY_DECR( d, s, n ) \
    do {				\
	mpi_size_t _i;			\
	for( _i = (n)-1; _i >= 0; _i--) \
	   (d)[_i] = (s)[_i];		\
    } while(0)

/* Zero N limbs at D */
#define MPN_ZERO(d, n) \
    do {				  \
	int  _i;			  \
	for( _i = 0; _i < (n); _i++ )  \
	    (d)[_i] = 0;		    \
    } while (0)

#define MPN_NORMALIZE(d, n)  \
    do {		       \
	while( (n) > 0 ) {     \
	    if( (d)[(n)-1] ) \
		break;	       \
	    (n)--;	       \
	}		       \
    } while(0)

#define MPN_NORMALIZE_NOT_ZERO(d, n) \
    do {				    \
	for(;;) {			    \
	    if( (d)[(n)-1] )		    \
		break;			    \
	    (n)--;			    \
	}				    \
    } while(0)

#define MPN_MUL_N_RECURSE(prodp, up, vp, size, tspace) \
    do {						\
	if( (size) < KARATSUBA_THRESHOLD )		\
	    mul_n_basecase (prodp, up, vp, size);	\
	else						\
	    mul_n (prodp, up, vp, size, tspace);	\
    } while (0)


/* Divide the two-limb number in (NH,,NL) by D, with DI being the largest
 * limb not larger than (2**(2*BITS_PER_MP_LIMB))/D - (2**BITS_PER_MP_LIMB).
 * If this would yield overflow, DI should be the largest possible number
 * (i.e., only ones).  For correct operation, the most significant bit of D
 * has to be set.  Put the quotient in Q and the remainder in R.
 */
#define UDIV_QRNND_PREINV(q, r, nh, nl, d, di) \
    do {							    \
        mpi_limb_t _ql GCC_ATTR_UNUSED;                               \
	mpi_limb_t _q, _r;                                          \
	mpi_limb_t _xh, _xl;					    \
	umul_ppmm (_q, _ql, (nh), (di));			    \
	_q += (nh);	/* DI is 2**BITS_PER_MPI_LIMB too small */  \
	umul_ppmm (_xh, _xl, _q, (d));				    \
	sub_ddmmss (_xh, _r, (nh), (nl), _xh, _xl);		    \
	if( _xh ) {						    \
	    sub_ddmmss (_xh, _r, _xh, _r, 0, (d));		    \
	    _q++;						    \
	    if( _xh) {						    \
		sub_ddmmss (_xh, _r, _xh, _r, 0, (d));		    \
		_q++;						    \
	    }							    \
	}							    \
	if( _r >= (d) ) {					    \
	    _r -= (d);						    \
	    _q++;						    \
	}							    \
	(r) = _r;						    \
	(q) = _q;						    \
    } while (0)


/*-- mpiutil.c --*/
#define mpi_alloc_limb_space(n,f)  _gcry_mpi_alloc_limb_space((n),(f))
mpi_ptr_t _gcry_mpi_alloc_limb_space( unsigned nlimbs, int sec );
void _gcry_mpi_free_limb_space( mpi_ptr_t a, unsigned int nlimbs );
void _gcry_mpi_assign_limb_space( gcry_mpi_t a, mpi_ptr_t ap, unsigned nlimbs );

/*-- mpi-bit.c --*/
#define mpi_rshift_limbs(a,n)  _gcry_mpi_rshift_limbs ((a), (n))
#define mpi_lshift_limbs(a,n)  _gcry_mpi_lshift_limbs ((a), (n))

void _gcry_mpi_rshift_limbs( gcry_mpi_t a, unsigned int count );
void _gcry_mpi_lshift_limbs( gcry_mpi_t a, unsigned int count );


/*-- mpih-add.c --*/
mpi_limb_t _gcry_mpih_add_1(mpi_ptr_t res_ptr,  mpi_ptr_t s1_ptr,
			 mpi_size_t s1_size, mpi_limb_t s2_limb );
mpi_limb_t _gcry_mpih_add_n( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			  mpi_ptr_t s2_ptr,  mpi_size_t size);
mpi_limb_t _gcry_mpih_add(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr, mpi_size_t s1_size,
		       mpi_ptr_t s2_ptr, mpi_size_t s2_size);

/*-- mpih-sub.c --*/
mpi_limb_t _gcry_mpih_sub_1( mpi_ptr_t res_ptr,  mpi_ptr_t s1_ptr,
			  mpi_size_t s1_size, mpi_limb_t s2_limb );
mpi_limb_t _gcry_mpih_sub_n( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			  mpi_ptr_t s2_ptr, mpi_size_t size);
mpi_limb_t _gcry_mpih_sub(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr, mpi_size_t s1_size,
		       mpi_ptr_t s2_ptr, mpi_size_t s2_size);

/*-- mpih-cmp.c --*/
int _gcry_mpih_cmp( mpi_ptr_t op1_ptr, mpi_ptr_t op2_ptr, mpi_size_t size );

/*-- mpih-mul.c --*/

struct karatsuba_ctx {
    struct karatsuba_ctx *next;
    mpi_ptr_t tspace;
    unsigned int tspace_nlimbs;
    mpi_size_t tspace_size;
    mpi_ptr_t tp;
    unsigned int tp_nlimbs;
    mpi_size_t tp_size;
};

void _gcry_mpih_release_karatsuba_ctx( struct karatsuba_ctx *ctx );

mpi_limb_t _gcry_mpih_addmul_1( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			     mpi_size_t s1_size, mpi_limb_t s2_limb);
mpi_limb_t _gcry_mpih_submul_1( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			     mpi_size_t s1_size, mpi_limb_t s2_limb);
void _gcry_mpih_mul_n( mpi_ptr_t prodp, mpi_ptr_t up, mpi_ptr_t vp,
						   mpi_size_t size);
mpi_limb_t _gcry_mpih_mul( mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t usize,
					 mpi_ptr_t vp, mpi_size_t vsize);
mpi_limb_t _gcry_mpih_mul_lli(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t usize,
                              mpi_ptr_t vp, mpi_size_t vsize);
void _gcry_mpih_sqr_n_basecase( mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size );
void _gcry_mpih_sqr_n( mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size,
						mpi_ptr_t tspace);

void _gcry_mpih_mul_karatsuba_case( mpi_ptr_t prodp,
				 mpi_ptr_t up, mpi_size_t usize,
				 mpi_ptr_t vp, mpi_size_t vsize,
				 struct karatsuba_ctx *ctx );


/*-- mpih-mul_1.c (or xxx/cpu/ *.S) --*/
mpi_limb_t _gcry_mpih_mul_1( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			  mpi_size_t s1_size, mpi_limb_t s2_limb);

/*-- mpih-div.c --*/
mpi_limb_t _gcry_mpih_mod_1(mpi_ptr_t dividend_ptr, mpi_size_t dividend_size,
						 mpi_limb_t divisor_limb);
mpi_limb_t _gcry_mpih_divrem( mpi_ptr_t qp, mpi_size_t qextra_limbs,
			   mpi_ptr_t np, mpi_size_t nsize,
			   mpi_ptr_t dp, mpi_size_t dsize);
mpi_limb_t _gcry_mpih_divmod_1( mpi_ptr_t quot_ptr,
			     mpi_ptr_t dividend_ptr, mpi_size_t dividend_size,
			     mpi_limb_t divisor_limb);

/*-- mpih-shift.c --*/
mpi_limb_t _gcry_mpih_lshift( mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
							   unsigned cnt);
mpi_limb_t _gcry_mpih_rshift( mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
							   unsigned cnt);
/*-- mpih-pow.c --*/
void _gcry_mpih_powm_lli (mpi_ptr_t rp, mpi_ptr_t bp, mpi_ptr_t mp,
                          mpi_size_t n, mpi_ptr_t ep, mpi_size_t en);

/*-- mpih-const-time.c --*/
#define mpih_set_cond(w,u,s,o) _gcry_mpih_set_cond ((w),(u),(s),(o))
#define mpih_add_n_cond(w,u,v,s,o) _gcry_mpih_add_n_cond ((w),(u),(v),(s),(o))
#define mpih_sub_n_cond(w,u,v,s,o) _gcry_mpih_sub_n_cond ((w),(u),(v),(s),(o))
#define mpih_swap_cond(u,v,s,o) _gcry_mpih_swap_cond ((u),(v),(s),(o))
#define mpih_abs_cond(w,u,s,o) _gcry_mpih_abs_cond ((w),(u),(s),(o))
#define mpih_mod_lli(v,vs,u,us) _gcry_mpih_mod_lli ((v),(vs),(u),(us))

DEFINE_CT_TYPE_GEN_MASK(limb, mpi_limb_t)
DEFINE_CT_TYPE_GEN_INV_MASK(limb, mpi_limb_t)
DEFINE_CT_TYPE_SELECT_FUNC(limb, mpi_limb_t)

static inline int
mpih_limb_is_zero (mpi_limb_t a)
{
  /* Sign bit set if A == 0. */
  a = ~a & ~(-a);

  return a >> (BITS_PER_MPI_LIMB - 1);
}

static inline int
mpih_limb_is_not_zero (mpi_limb_t a)
{
  /* Sign bit set if A != 0. */
  a = a | (-a);

  return a >> (BITS_PER_MPI_LIMB - 1);
}

void _gcry_mpih_set_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
                          unsigned long op_enable);
mpi_limb_t _gcry_mpih_add_n_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_ptr_t vp,
                                  mpi_size_t usize, unsigned long op_enable);
mpi_limb_t _gcry_mpih_sub_n_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_ptr_t vp,
                                  mpi_size_t usize, unsigned long op_enable);
void _gcry_mpih_swap_cond (mpi_ptr_t up, mpi_ptr_t vp, mpi_size_t usize,
                           unsigned long op_enable);
void _gcry_mpih_abs_cond (mpi_ptr_t wp, mpi_ptr_t up,
                          mpi_size_t usize, unsigned long op_enable);
void _gcry_mpih_lookup_lli (mpi_ptr_t rp, const mpi_limb_t *table,
                            mpi_size_t n, mpi_size_t nents, mpi_size_t idx);
mpi_ptr_t _gcry_mpih_mod_lli (mpi_ptr_t vp, mpi_size_t vsize,
                              mpi_ptr_t up, mpi_size_t usize);


/* Define stuff for longlong.h.  */
#define W_TYPE_SIZE BITS_PER_MPI_LIMB
  typedef mpi_limb_t   UWtype;
  typedef unsigned int UHWtype;
#if defined (__GNUC__)
  typedef unsigned int UQItype	  __attribute__ ((mode (QI)));
  typedef	   int SItype	  __attribute__ ((mode (SI)));
  typedef unsigned int USItype	  __attribute__ ((mode (SI)));
  typedef	   int DItype	  __attribute__ ((mode (DI)));
  typedef unsigned int UDItype	  __attribute__ ((mode (DI)));
#else
  typedef unsigned char UQItype;
  typedef	   long SItype;
  typedef unsigned long USItype;
#endif

#ifdef __GNUC__
#include "mpi-inline.h"
#endif

#endif /*G10_MPI_INTERNAL_H*/
