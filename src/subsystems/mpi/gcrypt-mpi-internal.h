/* gcrypt-mpi-internal.h - internal MPI interface
   Copyright (C) 1994, 1996, 1998,
                 2001, 2002, 2003, 2005 Free Software Foundation, Inc.

   This file is part of Libgcrypt.

   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   Libgcrypt is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef _GCRYPT_MPI_INTERNAL_H
#define _GCRYPT_MPI_INTERNAL_H

#include <gcrypt-common-internal.h>
#include <gcrypt-mpi-common.h>

#include "mpi-asm-defs.h"



#ifndef BITS_PER_MPI_LIMB
#if BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_INT
typedef unsigned int mpi_limb_t;
typedef signed int mpi_limb_signed_t;
#elif BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_LONG
typedef unsigned long int mpi_limb_t;
typedef signed long int mpi_limb_signed_t;
#elif BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_LONG_LONG
typedef unsigned long long int mpi_limb_t;
typedef signed long long int mpi_limb_signed_t;
#elif BYTES_PER_MPI_LIMB == SIZEOF_UNSIGNED_SHORT
typedef unsigned short int mpi_limb_t;
typedef signed short int mpi_limb_signed_t;
#else
#error BYTES_PER_MPI_LIMB does not match any C type
#endif
#define BITS_PER_MPI_LIMB    (8*BYTES_PER_MPI_LIMB)
#endif /*BITS_PER_MPI_LIMB */

#define MPI_NULL NULL

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

#define RESIZE_IF_NEEDED(context, a,b) \
    do {			   \
	if( (a)->alloced < (b) )   \
	    _gcry_mpi_resize((context), (a), (b));  \
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
	    (d)[_i] = (d)[_i];		\
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
    } while (0);


/* Divide the two-limb number in (NH,,NL) by D, with DI being the largest
 * limb not larger than (2**(2*BITS_PER_MP_LIMB))/D - (2**BITS_PER_MP_LIMB).
 * If this would yield overflow, DI should be the largest possible number
 * (i.e., only ones).  For correct operation, the most significant bit of D
 * has to be set.  Put the quotient in Q and the remainder in R.
 */
#define UDIV_QRNND_PREINV(q, r, nh, nl, d, di) \
    do {							    \
	mpi_limb_t _q, _ql, _r; 				    \
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



typedef mpi_limb_t *mpi_ptr_t;	/* pointer to a limb */
typedef int mpi_size_t;		/* (must be a signed type) */

struct gcry_mpi
{
  int alloced;			/* array size (# of allocated limbs) */
  int nlimbs;			/* number of valid limbs */
  int sign;			/* indicates a negative number and is used for opaque
				 * MPIs to store the length */
  unsigned flags;		/* bit 0: array must be allocated in secure memory space */
  /* bit 2: the limb is a pointer to some m_alloced data (FIXME:
     shouldn't we define symbolic names for these flags?) */
  mpi_limb_t *d;		/* array with the limbs */
};

struct karatsuba_ctx
{
  struct karatsuba_ctx *next;
  mpi_ptr_t tspace;
  unsigned int tspace_nlimbs;
  mpi_size_t tspace_size;
  mpi_ptr_t tp;
  unsigned int tp_nlimbs;
  mpi_size_t tp_size;
};



/* File: mpi-add.c  */

void _gcry_mpi_add_ui (gcry_core_context_t ctx, gcry_core_mpi_t w,
			    gcry_core_mpi_t u, unsigned long v);

void _gcry_mpi_add (gcry_core_context_t ctx, gcry_core_mpi_t w,
			 gcry_core_mpi_t u, gcry_core_mpi_t v);

void _gcry_mpi_sub_ui (gcry_core_context_t ctx, gcry_core_mpi_t w,
			    gcry_core_mpi_t u, unsigned long v);

void _gcry_mpi_sub (gcry_core_context_t ctx, gcry_core_mpi_t w,
			 gcry_core_mpi_t u, gcry_core_mpi_t v);

void _gcry_mpi_addm (gcry_core_context_t ctx, gcry_core_mpi_t w,
			  gcry_core_mpi_t u, gcry_core_mpi_t v,
			  gcry_core_mpi_t m);

void _gcry_mpi_subm (gcry_core_context_t ctx, gcry_core_mpi_t w,
			  gcry_core_mpi_t u, gcry_core_mpi_t v,
			  gcry_core_mpi_t m);



/* File: mpi-bit.c  */

void _gcry_mpi_normalize (gcry_core_mpi_t a);

unsigned int _gcry_mpi_get_nbits (gcry_core_context_t ctx,
				       gcry_core_mpi_t a);
int _gcry_mpi_test_bit (gcry_core_context_t ctx, gcry_core_mpi_t a,
			     unsigned int n);
void _gcry_mpi_set_bit (gcry_core_context_t ctx, gcry_core_mpi_t a,
			     unsigned int n);
void _gcry_mpi_set_highbit (gcry_core_context_t ctx, gcry_core_mpi_t a,
				 unsigned int n);
void _gcry_mpi_clear_highbit (gcry_core_context_t ctx, gcry_core_mpi_t a,
				   unsigned int n);
void _gcry_mpi_clear_bit (gcry_core_context_t ctx, gcry_core_mpi_t a,
			       unsigned int n);
void _gcry_mpi_rshift (gcry_core_context_t ctx, gcry_core_mpi_t x,
			    gcry_core_mpi_t a, unsigned n);
void _gcry_mpi_lshift_limbs (gcry_core_context_t ctx, gcry_core_mpi_t a,
			     unsigned int count);
void _gcry_mpi_rshift_limbs (gcry_core_context_t ctx, gcry_core_mpi_t a,
			     unsigned int count);

/* File: mpi-cmp.c  */

int _gcry_mpi_cmp_ui (gcry_core_context_t ctx, gcry_core_mpi_t u,
			   unsigned long v);
int _gcry_mpi_cmp (gcry_core_context_t ctx, gcry_core_mpi_t u,
			gcry_core_mpi_t v);

/* File: mpicoder.c  */

void _gcry_mpi_dump (gcry_core_context_t ctx, const gcry_core_mpi_t a);
void _gcry_log_mpidump (gcry_core_context_t ctx, const char *text,
			gcry_core_mpi_t a);
byte *_gcry_mpi_get_buffer (gcry_core_context_t ctx, gcry_core_mpi_t a,
			    unsigned *nbytes, int *sign);
byte *_gcry_mpi_get_secure_buffer (gcry_core_context_t ctx, gcry_core_mpi_t a,
				   unsigned *nbytes, int *sign);
void _gcry_mpi_set_buffer (gcry_core_context_t ctx, gcry_core_mpi_t a,
			   const byte * buffer, unsigned nbytes, int sign);
gcry_error_t _gcry_mpi_scan (gcry_core_context_t ctx,
				  struct gcry_mpi **ret_mpi,
				  enum gcry_mpi_format format,
				  const unsigned char *buffer, size_t buflen,
				  size_t * nscanned);
gcry_error_t _gcry_mpi_print (gcry_core_context_t ctx,
				   enum gcry_mpi_format format,
				   unsigned char *buffer, size_t buflen,
				   size_t * nwritten, struct gcry_mpi *a);
gcry_error_t _gcry_mpi_aprint (gcry_core_context_t ctx,
				    enum gcry_mpi_format format,
				    unsigned char **buffer, size_t * nwritten,
				    struct gcry_mpi *a);

/* File: mpi-div.c  */

void _gcry_mpi_fdiv_r (gcry_core_context_t ctx, gcry_core_mpi_t rem,
			    gcry_core_mpi_t dividend,
			    gcry_core_mpi_t divisor);
ulong _gcry_mpi_fdiv_r_ui (gcry_core_context_t ctx, gcry_core_mpi_t rem,
				gcry_core_mpi_t dividend, ulong divisor);
void _gcry_mpi_fdiv_q (gcry_core_context_t ctx, gcry_core_mpi_t quot,
			    gcry_core_mpi_t dividend,
			    gcry_core_mpi_t divisor);
void _gcry_mpi_tdiv_q_2exp (gcry_core_context_t ctx, gcry_core_mpi_t w,
			    gcry_core_mpi_t u, unsigned int count);
void _gcry_mpi_tdiv_q_2exp (gcry_core_context_t ctx, gcry_core_mpi_t w,
				 gcry_core_mpi_t u, unsigned int count);
int _gcry_mpi_divisible_ui (gcry_core_context_t ctx,
				 gcry_core_mpi_t dividend, ulong divisor);
void _gcry_mpi_tdiv (gcry_core_context_t ctx,
			 gcry_core_mpi_t quot, gcry_core_mpi_t rem,
			 gcry_core_mpi_t dividend, gcry_core_mpi_t divisor,
			 int round);
void _gcry_mpi_mod (gcry_core_context_t ctx, gcry_core_mpi_t rem,
			 gcry_core_mpi_t dividend, gcry_core_mpi_t divisor);

/* File: mpi-gcd.c  */

int _gcry_mpi_gcd (gcry_core_context_t ctx, gcry_core_mpi_t g,
			gcry_core_mpi_t xa, gcry_core_mpi_t xb);

/* File: mpih-div.c  */

mpi_limb_t _gcry_mpih_mod_1 (mpi_ptr_t dividend_ptr, mpi_size_t dividend_size,
			     mpi_limb_t divisor_limb);
mpi_limb_t _gcry_mpih_divrem (mpi_ptr_t qp, mpi_size_t qextra_limbs,
			      mpi_ptr_t np, mpi_size_t nsize, mpi_ptr_t dp,
			      mpi_size_t dsize);
mpi_limb_t _gcry_mpih_divmod_1 (mpi_ptr_t quot_ptr, mpi_ptr_t dividend_ptr,
				mpi_size_t dividend_size,
				mpi_limb_t divisor_limb);

/* File: mpih-mul.c  */

void _gcry_mpih_sqr_n_basecase (mpi_ptr_t prodp, mpi_ptr_t up,
				mpi_size_t size);
void _gcry_mpih_sqr_n (mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size,
		       mpi_ptr_t tspace);
void _gcry_mpih_mul_n (gcry_core_context_t ctx, mpi_ptr_t prodp, mpi_ptr_t up,
		       mpi_ptr_t vp, mpi_size_t size);
void _gcry_mpih_mul_karatsuba_case (gcry_core_context_t ctx, mpi_ptr_t prodp,
				    mpi_ptr_t up, mpi_size_t usize,
				    mpi_ptr_t vp, mpi_size_t vsize,
				    struct karatsuba_ctx *karat_ctx);
void _gcry_mpih_release_karatsuba_ctx (gcry_core_context_t ctx,
				       struct karatsuba_ctx *karat_ctx);
mpi_limb_t _gcry_mpih_mul (gcry_core_context_t ctx, mpi_ptr_t prodp,
			   mpi_ptr_t up, mpi_size_t usize, mpi_ptr_t vp,
			   mpi_size_t vsize);

/* File: mpi-inv.c  */
int _gcry_mpi_invm (gcry_core_context_t ctx, gcry_core_mpi_t x,
		     gcry_core_mpi_t a, gcry_core_mpi_t n);

/* File: mpi-mpow.c  */

void _gcry_mpi_mulpowm (gcry_core_context_t ctx, gcry_core_mpi_t res,
			     gcry_core_mpi_t * basearray,
			     gcry_core_mpi_t * exparray, gcry_core_mpi_t m);

/* File: mpi-mul.c  */

void _gcry_mpi_mul_ui (gcry_core_context_t ctx, gcry_core_mpi_t prod,
			    gcry_core_mpi_t mult, unsigned long small_mult);
void _gcry_mpi_mul_2exp( gcry_core_context_t ctx,
			 gcry_core_mpi_t w, gcry_core_mpi_t u,
			 unsigned long cnt);
void _gcry_mpi_mul (gcry_core_context_t ctx, gcry_core_mpi_t w,
			 gcry_core_mpi_t u, gcry_core_mpi_t v);
void _gcry_mpi_mulm (gcry_core_context_t ctx, gcry_core_mpi_t w,
			  gcry_core_mpi_t u, gcry_core_mpi_t v,
			  gcry_core_mpi_t m);

/* File: mpi-pow.c  */

void _gcry_mpi_powm (gcry_core_context_t ctx, gcry_core_mpi_t res,
			  gcry_core_mpi_t base, gcry_core_mpi_t expo,
			  gcry_core_mpi_t mod);

/* File: mpi-random.c  */

void _gcry_mpi_randomize (gcry_core_context_t ctx, gcry_core_mpi_t w,
			       unsigned int nbits,
			       enum gcry_random_level level);

/* File: mpi-scan.c  */

int _gcry_mpi_getbyte (gcry_core_mpi_t a, unsigned idx);
void _gcry_mpi_putbyte (gcry_core_mpi_t a, unsigned idx, int xc);
unsigned _gcry_mpi_trailing_zeros (gcry_core_context_t ctx,
				   gcry_core_mpi_t a);

/* File: mpiutil.c  */

gcry_core_mpi_t _gcry_mpi_alloc (gcry_core_context_t ctx, unsigned nlimbs);
void _gcry_mpi_m_check (gcry_core_mpi_t a);
gcry_core_mpi_t _gcry_mpi_alloc_secure (gcry_core_context_t ctx,
					unsigned nlimbs);
mpi_ptr_t _gcry_mpi_alloc_limb_space (gcry_core_context_t ctx,
				      unsigned int nlimbs, int secure);
void _gcry_mpi_free_limb_space (gcry_core_context_t ctx, mpi_ptr_t a,
				unsigned int nlimbs);
void _gcry_mpi_assign_limb_space (gcry_core_context_t ctx, gcry_core_mpi_t a,
				  mpi_ptr_t ap, unsigned int nlimbs);
void _gcry_mpi_resize (gcry_core_context_t ctx, gcry_core_mpi_t a,
		       unsigned nlimbs);
void _gcry_mpi_clear (gcry_core_mpi_t a);
void _gcry_mpi_free (gcry_core_context_t ctx, gcry_core_mpi_t a);
gcry_core_mpi_t _gcry_mpi_set_opaque (gcry_core_context_t ctx,
					   gcry_core_mpi_t a, void *p,
					   unsigned int nbits);
void *_gcry_mpi_get_opaque (gcry_core_context_t ctx, gcry_core_mpi_t a,
				 unsigned int *nbits);
gcry_core_mpi_t _gcry_mpi_copy (gcry_core_context_t ctx, const gcry_core_mpi_t a);
gcry_core_mpi_t _gcry_mpi_alloc_like (gcry_core_context_t ctx,
				      gcry_core_mpi_t a);
gcry_core_mpi_t _gcry_mpi_alloc_set_ui (gcry_core_context_t ctx,
					     unsigned long u);
void _gcry_mpi_swap (gcry_core_context_t ctx, gcry_core_mpi_t a,
			  gcry_core_mpi_t b);
gcry_core_mpi_t _gcry_mpi_new (gcry_core_context_t ctx,
				    unsigned int nbits);
gcry_core_mpi_t _gcry_mpi_secure_new (gcry_core_context_t ctx,
				     unsigned int nbits);
void _gcry_mpi_release (gcry_core_context_t ctx, gcry_core_mpi_t a);
gcry_core_mpi_t _gcry_mpi_copy (gcry_core_context_t ctx,
				     const gcry_core_mpi_t a);
gcry_core_mpi_t _gcry_mpi_set (gcry_core_context_t ctx,
			       gcry_core_mpi_t w,
			       const gcry_core_mpi_t u);
gcry_core_mpi_t _gcry_mpi_set_ui (gcry_core_context_t ctx,
				  gcry_core_mpi_t w, unsigned long u);
gcry_error_t _gcry_mpi_get_ui (gcry_core_context_t ctx,
			       gcry_core_mpi_t w, unsigned long *u);
void _gcry_mpi_set_flag (gcry_core_context_t ctx, gcry_core_mpi_t a,
			      enum gcry_mpi_flag flag);
void _gcry_mpi_clear_flag (gcry_core_context_t ctx, gcry_core_mpi_t a,
				enum gcry_mpi_flag flag);
int _gcry_mpi_get_flag (gcry_core_context_t ctx, gcry_core_mpi_t a,
			     enum gcry_mpi_flag flag);
gcry_core_mpi_t _gcry_mpi_copy_do ( gcry_core_context_t ctx,  gcry_core_mpi_t a );
void _gcry_mpi_set_do (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u);
void _gcry_mpi_set_ui_do(gcry_core_context_t ctx, gcry_core_mpi_t w, unsigned long u);

/* File: mpi-inline.h  */

mpi_limb_t _gcry_mpih_add_1 (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			     mpi_size_t s1_size, mpi_limb_t s2_limb);
mpi_limb_t _gcry_mpih_add (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			   mpi_size_t s1_size, mpi_ptr_t s2_ptr,
			   mpi_size_t s2_size);
mpi_limb_t _gcry_mpih_sub_1 (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			     mpi_size_t s1_size, mpi_limb_t s2_limb);
mpi_limb_t _gcry_mpih_sub (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			   mpi_size_t s1_size, mpi_ptr_t s2_ptr,
			   mpi_size_t s2_size);
int _gcry_mpih_cmp (mpi_ptr_t op1_ptr, mpi_ptr_t op2_ptr, mpi_size_t size);

/* File: mpih-add1  */

mpi_limb_t _gcry_mpih_add_n (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			     mpi_ptr_t s2_ptr, mpi_size_t size);

/* File: mpih-sub1  */
mpi_limb_t _gcry_mpih_sub_n (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			     mpi_ptr_t s2_ptr, mpi_size_t size);

/* File: mpih-mul2 */

mpi_limb_t _gcry_mpih_addmul_1 (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
				mpi_size_t s1_size, mpi_limb_t s2_limb);

/* File: mpih-mul3  */
mpi_limb_t _gcry_mpih_submul_1 (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
				mpi_size_t s1_size, mpi_limb_t s2_limb);

/* File: mpih-mul1  */

mpi_limb_t _gcry_mpih_mul_1 (mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			     mpi_size_t s1_size, mpi_limb_t s2_limb);

/* File: mpih-lshift  */
mpi_limb_t _gcry_mpih_lshift (mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			      unsigned cnt);

/* File: mpih-rsifht  */
mpi_limb_t _gcry_mpih_rshift (mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			      unsigned cnt);



#define mpi_is_opaque(a) ((a) && ((a)->flags&4))
#define mpi_is_secure(a) ((a) && ((a)->flags&1))
#define mpi_get_nlimbs(a)     ((a)->nlimbs)
#define mpi_is_neg(a)	      ((a)->sign)

/* FIXME.  */
#define mpi_release(a)      \
  do \
    { \
      gcry_core_mpi_release ((a)); \
      (a) = NULL; \
    } \
  while (0)


/* Define stuff for longlong.h.  */
#define W_TYPE_SIZE BITS_PER_MPI_LIMB
typedef mpi_limb_t UWtype;
typedef unsigned int UHWtype;
#if defined (__GNUC__)
typedef unsigned int UQItype __attribute__ ((mode (QI)));
typedef int SItype __attribute__ ((mode (SI)));
typedef unsigned int USItype __attribute__ ((mode (SI)));
typedef int DItype __attribute__ ((mode (DI)));
typedef unsigned int UDItype __attribute__ ((mode (DI)));
#else
typedef unsigned char UQItype;
typedef long SItype;
typedef unsigned long USItype;
#endif

#ifdef __GNUC__
#include "mpi-inline.h"
#endif



#endif

/* END. */
