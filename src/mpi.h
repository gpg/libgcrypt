/* mpi.h  -  Multi Precision Integers
 * Copyright (C) 1994, 1996, 1998, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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
 *
 * Note: This code is heavily based on the GNU MP Library.
 *	 Actually it's the same code with only minor changes in the
 *	 way the data is stored; this is to support the abstraction
 *	 of an optional secure memory allocation which may be used
 *	 to avoid revealing of sensitive data due to paging etc.
 */

#ifndef G10_MPI_H
#define G10_MPI_H

#include <config.h>
#include <stdio.h>
#include "types.h"
#include "memory.h"
#include "../mpi/mpi-asm-defs.h"

#ifndef _GCRYPT_IN_LIBGCRYPT
 #error this file should only be used inside libgcrypt
#endif

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

#define DBG_MPI     _gcry_get_debug_flag( 2 );

struct gcry_mpi {
    int alloced;    /* array size (# of allocated limbs) */
    int nlimbs;     /* number of valid limbs */
    int sign;	    /* indicates a negative number and is used for opaque
		     * MPIs to store the length */
    unsigned flags; /* bit 0: array must be allocated in secure memory space */
		    /* bit 2: the limb is a pointer to some m_alloced data */
    mpi_limb_t *d;  /* array with the limbs */
};

#ifndef DID_MPI_TYPEDEF
  typedef struct gcry_mpi *MPI;
  #define DID_MPI_TYPEDEF
#endif

#define MPI_NULL NULL

#define mpi_get_nlimbs(a)     ((a)->nlimbs)
#define mpi_is_neg(a)	      ((a)->sign)

/*-- mpiutil.c --*/

#ifdef M_DEBUG
  #define mpi_alloc(n)	_gcry_mpi_debug_alloc((n), M_DBGINFO( __LINE__ ) )
  #define mpi_alloc_secure(n)  _gcry_mpi_debug_alloc_secure((n), M_DBGINFO( __LINE__ ) )
  #define mpi_free(a)	_gcry_mpi_debug_free((a), M_DBGINFO(__LINE__) )
  #define mpi_resize(a,b) _gcry_mpi_debug_resize((a),(b), M_DBGINFO(__LINE__) )
  #define mpi_copy(a)	  _gcry_mpi_debug_copy((a), M_DBGINFO(__LINE__) )
  MPI _gcry_mpi_debug_alloc( unsigned nlimbs, const char *info );
  MPI _gcry_mpi_debug_alloc_secure( unsigned nlimbs, const char *info );
  void _gcry_mpi_debug_free( MPI a, const char *info );
  void _gcry_mpi_debug_resize( MPI a, unsigned nlimbs, const char *info );
  MPI  _gcry_mpi_debug_copy( MPI a, const char *info	);
#else
  #define mpi_alloc(n)	       _gcry_mpi_alloc((n) )
  #define mpi_alloc_secure(n)  _gcry_mpi_alloc_secure((n) )
  #define mpi_free(a)	       _gcry_mpi_free((a) )
  #define mpi_resize(a,b)      _gcry_mpi_resize((a),(b))
  #define mpi_copy(a)	       _gcry_mpi_copy((a))
  MPI  _gcry_mpi_alloc( unsigned nlimbs );
  MPI  _gcry_mpi_alloc_secure( unsigned nlimbs );
  void _gcry_mpi_free( MPI a );
  void _gcry_mpi_resize( MPI a, unsigned nlimbs );
  MPI  _gcry_mpi_copy( MPI a );
#endif
#define mpi_is_opaque(a) ((a) && ((a)->flags&4))
#define mpi_is_secure(a) ((a) && ((a)->flags&1))
#define mpi_clear(a)          _gcry_mpi_clear ((a))
#define mpi_alloc_like(a)     _gcry_mpi_alloc_like((a))  
#define mpi_set(a,b)          _gcry_mpi_set ((a),(b))        
#define mpi_set_ui(a,b)       _gcry_mpi_set_ui ((a),(b))      
#define mpi_alloc_set_ui(a)   _gcry_mpi_alloc_set_ui ((a))
#define mpi_m_check(a)        _gcry_mpi_m_check ((a))     
#define mpi_swap(a,b)         _gcry_mpi_swap ((a),(b))       

void _gcry_mpi_clear( MPI a );
MPI  _gcry_mpi_alloc_like( MPI a );
void _gcry_mpi_set( MPI w, MPI u);
void _gcry_mpi_set_ui( MPI w, ulong u);
MPI  _gcry_mpi_alloc_set_ui( unsigned long u);
void _gcry_mpi_m_check( MPI a );
void _gcry_mpi_swap( MPI a, MPI b);

/*-- mpicoder.c --*/
void  _gcry_log_mpidump( const char *text, MPI a );
u32   _gcry_mpi_get_keyid( MPI a, u32 *keyid );
byte *_gcry_mpi_get_buffer( MPI a, unsigned *nbytes, int *sign );
byte *_gcry_mpi_get_secure_buffer( MPI a, unsigned *nbytes, int *sign );
void  _gcry_mpi_set_buffer( MPI a, const byte *buffer, unsigned nbytes, int sign );

#define log_mpidump _gcry_log_mpidump

/*-- mpi-add.c --*/
#define mpi_add_ui(w,u,v) gcry_mpi_add_ui((w),(u),(v))
#define mpi_add(w,u,v)    gcry_mpi_add ((w),(u),(v))
#define mpi_addm(w,u,v,m) gcry_mpi_addm ((w),(u),(v),(m))
#define mpi_sub_ui(w,u,v) gcry_mpi_sub_ui ((w),(u),(v))
#define mpi_sub(w,u,v)    gcry_mpi_sub ((w),(u),(v))
#define mpi_subm(w,u,v,m) gcry_mpi_subm ((w),(u),(v),(m))


/*-- mpi-mul.c --*/
#define mpi_mul_ui(w,u,v)   gcry_mpi_mul_ui ((w),(u),(v))
#define mpi_mul_2exp(w,u,v) gcry_mpi_mul_2exp ((w),(u),(v))
#define mpi_mul(w,u,v)      gcry_mpi_mul ((w),(u),(v))
#define mpi_mulm(w,u,v,m)   gcry_mpi_mulm ((w),(u),(v),(m))


/*-- mpi-div.c --*/
#define mpi_fdiv_r_ui(a,b,c)   _gcry_mpi_fdiv_r_ui((a),(b),(c))
#define mpi_fdiv_r(a,b,c)      _gcry_mpi_fdiv_r((a),(b),(c))
#define mpi_fdiv_q(a,b,c)      _gcry_mpi_fdiv_q((a),(b),(c))
#define mpi_fdiv_qr(a,b,c,d)   _gcry_mpi_fdiv_qr((a),(b),(c),(d))
#define mpi_tdiv_r(a,b,c)      _gcry_mpi_tdiv_r((a),(b),(c))
#define mpi_tdiv_qr(a,b,c,d)   _gcry_mpi_tdiv_qr((a),(b),(c),(d))
#define mpi_tdiv_q_2exp(a,b,c) _gcry_mpi_tdiv_q_2exp((a),(b),(c))
#define mpi_divisible_ui(a,b)  _gcry_mpi_divisible_ui((a),(b))
ulong _gcry_mpi_fdiv_r_ui( MPI rem, MPI dividend, ulong divisor );
void  _gcry_mpi_fdiv_r( MPI rem, MPI dividend, MPI divisor );
void  _gcry_mpi_fdiv_q( MPI quot, MPI dividend, MPI divisor );
void  _gcry_mpi_fdiv_qr( MPI quot, MPI rem, MPI dividend, MPI divisor );
void  _gcry_mpi_tdiv_r( MPI rem, MPI num, MPI den);
void  _gcry_mpi_tdiv_qr( MPI quot, MPI rem, MPI num, MPI den);
void  _gcry_mpi_tdiv_q_2exp( MPI w, MPI u, unsigned count );
int   _gcry_mpi_divisible_ui(MPI dividend, ulong divisor );

/*-- mpi-gcd.c --*/

/*-- mpi-mpow.c --*/
#define mpi_mulpowm(a,b,c,d) _gcry_mpi_mulpowm ((a),(b),(c),(d))
void _gcry_mpi_mulpowm( MPI res, MPI *basearray, MPI *exparray, MPI mod);

/*-- mpi-cmp.c --*/
#define mpi_cmp_ui(a,b) gcry_mpi_cmp_ui ((a),(b))
#define mpi_cmp(a,b)    gcry_mpi_cmp ((a),(b))
int gcry_mpi_cmp_ui( MPI u, ulong v );
int gcry_mpi_cmp( MPI u, MPI v );

/*-- mpi-scan.c --*/
#define mpi_trailing_zeros(a) _gcry_mpi_trailing_zeros ((a))
int      _gcry_mpi_getbyte( MPI a, unsigned idx );
void     _gcry_mpi_putbyte( MPI a, unsigned idx, int value );
unsigned _gcry_mpi_trailing_zeros( MPI a );

/*-- mpi-bit.c --*/
#define mpi_normalize(a)       _gcry_mpi_normalize ((a))
#define mpi_get_nbits(a)       gcry_mpi_get_nbits ((a))
#define mpi_test_bit(a,b)      gcry_mpi_test_bit ((a),(b))
#define mpi_set_bit(a,b)       gcry_mpi_set_bit ((a),(b))
#define mpi_set_highbit(a,b)   gcry_mpi_set_highbit ((a),(b))
#define mpi_clear_bit(a,b)     gcry_mpi_clear_bit ((a),(b))
#define mpi_clear_highbit(a,b) gcry_mpi_clear_highbit ((a),(b))
#define mpi_rshift(a,b,c)      gcry_mpi_rshift ((a),(b),(c))

void _gcry_mpi_normalize( MPI a );

/*-- mpi-inv.c --*/
#define mpi_invm(a,b,c) _gcry_mpi_invm ((a),(b),(c))
void _gcry_mpi_invm( MPI x, MPI u, MPI v );


#endif /*G10_MPI_H*/
