/* gcrypt-mpi-common.h - Common defintions for the MPI subsystem
   Copyright (C) 2005 Free Software Foundation, Inc.
 
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

#ifndef _GCRYPT_MPI_COMMON_H
#define _GCRYPT_MPI_COMMON_H

#include <gcrypt-random-common.h>

/* The data object used to hold a multi precision integer.  */
struct gcry_mpi;
typedef struct gcry_mpi *gcry_core_mpi_t;

/* Different formats of external big integer representation. */
enum gcry_mpi_format 
  {
    GCRYMPI_FMT_NONE= 0,
    GCRYMPI_FMT_STD = 1,    /* twos complement stored without length */
    GCRYMPI_FMT_PGP = 2,    /* As used by OpenPGP (only defined as unsigned)*/
    GCRYMPI_FMT_SSH = 3,    /* As used by SSH (same as 1 but with length)*/
    GCRYMPI_FMT_HEX = 4,    /* hex format */
    GCRYMPI_FMT_USG = 5     /* like STD but this is an unsigned one */
  };

/* Flags used for creating big integers.  */
enum gcry_mpi_flag 
  {
    GCRYMPI_FLAG_SECURE = 1,  /* Allocate the number in "secure" memory. */
    GCRYMPI_FLAG_OPAQUE = 2   /* The number is not a real one but just a
                               way to store some bytes.  This is
                               useful for encrypted big integers. */
  };



typedef gcry_core_mpi_t (*gcry_subsystem_mpi_new_t) (gcry_core_context_t ctx, unsigned int nbits);
typedef gcry_core_mpi_t (*gcry_subsystem_mpi_snew_t) (gcry_core_context_t ctx, unsigned int nbits);
typedef void (*gcry_subsystem_mpi_release_t) (gcry_core_context_t ctx, gcry_core_mpi_t a);
typedef gcry_core_mpi_t (*gcry_subsystem_mpi_copy_t) (gcry_core_context_t ctx, const gcry_core_mpi_t a);
typedef gcry_core_mpi_t (*gcry_subsystem_mpi_set_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, const gcry_core_mpi_t u);
typedef gcry_core_mpi_t (*gcry_subsystem_mpi_set_ui_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, unsigned long u);
typedef gcry_error_t (*gcry_subsystem_mpi_get_ui_t) (gcry_core_context_t ctx,
						     gcry_core_mpi_t w, unsigned long *u);
typedef void (*gcry_subsystem_mpi_set_buffer_t) (gcry_core_context_t ctx,
						 gcry_core_mpi_t a, const unsigned char *buffer,
						 unsigned nbytes, int sign);
typedef void (*gcry_subsystem_mpi_swap_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, gcry_core_mpi_t b);
typedef int (*gcry_subsystem_mpi_cmp_t) (gcry_core_context_t ctx, const gcry_core_mpi_t u, const gcry_core_mpi_t v);
typedef int (*gcry_subsystem_mpi_cmp_ui_t) (gcry_core_context_t ctx, const gcry_core_mpi_t u, unsigned long v);
typedef gcry_error_t (*gcry_subsystem_mpi_scan_t) (gcry_core_context_t ctx, gcry_core_mpi_t *ret_mpi, enum gcry_mpi_format format,
						   const unsigned char *buffer, size_t buflen, 
						   size_t *nscanned);
typedef gcry_error_t (*gcry_subsystem_mpi_print_t) (gcry_core_context_t ctx, enum gcry_mpi_format format,
						    unsigned char *buffer, size_t buflen,
						    size_t *nwritten,
						    const gcry_core_mpi_t a);
typedef gcry_error_t (*gcry_subsystem_mpi_aprint_t) (gcry_core_context_t ctx, enum gcry_mpi_format format,
						     unsigned char **buffer, size_t *nwritten,
						     const gcry_core_mpi_t a);
typedef void (*gcry_subsystem_mpi_dump_t) (gcry_core_context_t ctx, const gcry_core_mpi_t a);
typedef void (*gcry_subsystem_mpi_add_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v);
typedef void (*gcry_subsystem_mpi_add_ui_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v);
typedef void (*gcry_subsystem_mpi_addm_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m);
typedef void (*gcry_subsystem_mpi_sub_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v);
typedef void (*gcry_subsystem_mpi_sub_ui_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v );
typedef void (*gcry_subsystem_mpi_subm_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m);
typedef void (*gcry_subsystem_mpi_mul_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v);
typedef void (*gcry_subsystem_mpi_mul_ui_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v );
typedef void (*gcry_subsystem_mpi_mulm_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m);
typedef void (*gcry_subsystem_mpi_mul_2exp_t) (gcry_core_context_t ctx, gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long cnt);
typedef void (*gcry_subsystem_mpi_div_t) (gcry_core_context_t ctx, gcry_core_mpi_t q, gcry_core_mpi_t r,
					  gcry_core_mpi_t dividend, gcry_core_mpi_t divisor, int round);
typedef void (*gcry_subsystem_mpi_fdiv_r_t) (gcry_core_context_t ctx,
					     gcry_core_mpi_t rem, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor);
typedef void (*gcry_subsystem_mpi_fdiv_q_t) (gcry_core_context_t ctx,
					     gcry_core_mpi_t quot, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor);
typedef ulong (*gcry_subsystem_mpi_fdiv_r_ui_t) (gcry_core_context_t ctx,
						 gcry_core_mpi_t rem, gcry_core_mpi_t dividend, ulong divisor);
typedef void (*gcry_subsystem_mpi_tdiv_q_2exp_t) (gcry_core_context_t ctx,
						  gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned int count);
typedef void (*gcry_subsystem_mpi_mod_t) (gcry_core_context_t ctx, gcry_core_mpi_t r, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor);
typedef void (*gcry_subsystem_mpi_powm_t) (gcry_core_context_t ctx, gcry_core_mpi_t w,
					   const gcry_core_mpi_t b, const gcry_core_mpi_t e,
					   const gcry_core_mpi_t m);
typedef void (*gcry_subsystem_mpi_mulpowm_t) (gcry_core_context_t ctx,
					      gcry_core_mpi_t res, gcry_core_mpi_t *basearray,
					      gcry_core_mpi_t *exparray, gcry_core_mpi_t m);
typedef int (*gcry_subsystem_mpi_gcd_t) (gcry_core_context_t ctx, gcry_core_mpi_t g, gcry_core_mpi_t a, gcry_core_mpi_t b);
typedef int (*gcry_subsystem_mpi_invm_t) (gcry_core_context_t ctx, gcry_core_mpi_t x, gcry_core_mpi_t a, gcry_core_mpi_t m);
typedef unsigned int (*gcry_subsystem_mpi_get_nbits_t) (gcry_core_context_t ctx, gcry_core_mpi_t a);
typedef int (*gcry_subsystem_mpi_test_bit_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, unsigned int n);
typedef void (*gcry_subsystem_mpi_set_bit_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, unsigned int n);
typedef void (*gcry_subsystem_mpi_clear_bit_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, unsigned int n);
typedef void (*gcry_subsystem_mpi_set_highbit_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, unsigned int n);
typedef void (*gcry_subsystem_mpi_clear_highbit_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, unsigned int n);
typedef void (*gcry_subsystem_mpi_rshift_t) (gcry_core_context_t ctx, gcry_core_mpi_t x, gcry_core_mpi_t a, unsigned int n);
typedef gcry_core_mpi_t (*gcry_subsystem_mpi_set_opaque_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, void *p, unsigned int nbits);
typedef void *(*gcry_subsystem_mpi_get_opaque_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, unsigned int *nbits);
typedef void (*gcry_subsystem_mpi_set_flag_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, enum gcry_mpi_flag flag);
typedef void (*gcry_subsystem_mpi_clear_flag_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, enum gcry_mpi_flag flag);
typedef int (*gcry_subsystem_mpi_get_flag_t) (gcry_core_context_t ctx, gcry_core_mpi_t a, enum gcry_mpi_flag flag);
typedef unsigned (*gcry_subsystem_mpi_trailing_zeros_t) (gcry_core_context_t ctx, gcry_core_mpi_t a);
typedef gcry_core_mpi_t (*gcry_subsystem_mpi_alloc_set_ui_t) (gcry_core_context_t ctx,
							 unsigned long u);
typedef gcry_core_mpi_t (*gcry_subsystem_mpi_alloc_like_t) (gcry_core_context_t ctx,
						       gcry_core_mpi_t a);
typedef void (*gcry_subsystem_mpi_randomize_t) (gcry_core_context_t ctx,
						gcry_core_mpi_t w, unsigned int nbits,
						enum gcry_random_level level);
typedef int (*gcry_subsystem_mpi_divisible_ui_t) (gcry_core_context_t ctx,
						  gcry_core_mpi_t dividend, ulong divisor);



typedef struct gcry_core_subsystem_mpi
{
  gcry_subsystem_mpi_new_t new;
  gcry_subsystem_mpi_snew_t snew;
  gcry_subsystem_mpi_release_t release;
  gcry_subsystem_mpi_copy_t copy;
  gcry_subsystem_mpi_set_t set;
  gcry_subsystem_mpi_set_ui_t set_ui;
  gcry_subsystem_mpi_get_ui_t get_ui;
  gcry_subsystem_mpi_set_buffer_t set_buffer;
  gcry_subsystem_mpi_swap_t swap;
  gcry_subsystem_mpi_cmp_t cmp;
  gcry_subsystem_mpi_cmp_ui_t cmp_ui;
  gcry_subsystem_mpi_scan_t scan;
  gcry_subsystem_mpi_print_t print;
  gcry_subsystem_mpi_aprint_t aprint;
  gcry_subsystem_mpi_dump_t dump;
  gcry_subsystem_mpi_add_t add;
  gcry_subsystem_mpi_add_ui_t add_ui;
  gcry_subsystem_mpi_addm_t addm;
  gcry_subsystem_mpi_sub_t sub;
  gcry_subsystem_mpi_sub_ui_t sub_ui;
  gcry_subsystem_mpi_subm_t subm;
  gcry_subsystem_mpi_mul_t mul;
  gcry_subsystem_mpi_mul_ui_t mul_ui;
  gcry_subsystem_mpi_mulm_t mulm;
  gcry_subsystem_mpi_mul_2exp_t mul_2exp;
  gcry_subsystem_mpi_div_t div;
  gcry_subsystem_mpi_fdiv_q_t fdiv_q;
  gcry_subsystem_mpi_fdiv_r_t fdiv_r;
  gcry_subsystem_mpi_fdiv_r_ui_t fdiv_r_ui;
  gcry_subsystem_mpi_tdiv_q_2exp_t tdiv_q_2exp;
  gcry_subsystem_mpi_mod_t mod;
  gcry_subsystem_mpi_powm_t powm;
  gcry_subsystem_mpi_mulpowm_t mulpowm;
  gcry_subsystem_mpi_gcd_t gcd;
  gcry_subsystem_mpi_invm_t invm;
  gcry_subsystem_mpi_get_nbits_t get_nbits;
  gcry_subsystem_mpi_test_bit_t test_bit;
  gcry_subsystem_mpi_set_bit_t set_bit;
  gcry_subsystem_mpi_clear_bit_t clear_bit;
  gcry_subsystem_mpi_set_highbit_t set_highbit;
  gcry_subsystem_mpi_clear_highbit_t clear_highbit;
  gcry_subsystem_mpi_rshift_t rshift;
  gcry_subsystem_mpi_set_opaque_t set_opaque;
  gcry_subsystem_mpi_get_opaque_t get_opaque;
  gcry_subsystem_mpi_set_flag_t set_flag;
  gcry_subsystem_mpi_clear_flag_t clear_flag;
  gcry_subsystem_mpi_get_flag_t get_flag;
  gcry_subsystem_mpi_trailing_zeros_t trailing_zeros;
  gcry_subsystem_mpi_alloc_set_ui_t alloc_set_ui;
  gcry_subsystem_mpi_alloc_like_t alloc_like;
  gcry_subsystem_mpi_randomize_t randomize;
  gcry_subsystem_mpi_divisible_ui_t divisible_ui;
} *gcry_core_subsystem_mpi_t;

void gcry_core_set_subsystem_mpi (gcry_core_context_t ctx, gcry_core_subsystem_mpi_t mpi);

/* Allocate a new big integer object, initialize it with 0 and
   initially allocate memory for a number of at least NBITS. */
gcry_core_mpi_t gcry_core_mpi_new (gcry_core_context_t ctx, unsigned int nbits);

/* Same as gcry_mpi_new() but allocate in "secure" memory. */
gcry_core_mpi_t gcry_core_mpi_snew (gcry_core_context_t ctx, unsigned int nbits);

/* Release the number A and free all associated resources. */
void gcry_core_mpi_release (gcry_core_context_t ctx, gcry_core_mpi_t a);

/* Create a new number with the same value as A. */
gcry_core_mpi_t gcry_core_mpi_copy (gcry_core_context_t ctx, const gcry_core_mpi_t a);

/* Store the big integer value U in W. */
gcry_core_mpi_t gcry_core_mpi_set (gcry_core_context_t ctx,
			      gcry_core_mpi_t w, const gcry_core_mpi_t u);

/* Store the unsigned integer value U in W. */
gcry_core_mpi_t gcry_core_mpi_set_ui (gcry_core_context_t ctx,
				 gcry_core_mpi_t w, unsigned long u);

gcry_error_t gcry_core_mpi_get_ui (gcry_core_context_t ctx,
				   gcry_core_mpi_t w, unsigned long *u);

/* Swap the values of A and B. */
void gcry_core_mpi_swap (gcry_core_context_t ctx,
			 gcry_core_mpi_t a, gcry_core_mpi_t b);

/* Compare the big integer number U and V returning 0 for equality, a
   positive value for U > V and a negative for U < V. */
int gcry_core_mpi_cmp (gcry_core_context_t ctx,
		       const gcry_core_mpi_t u, const gcry_core_mpi_t v);

/* Compare the big integer number U with the unsigned integer V
   returning 0 for equality, a positive value for U > V and a negative
   for U < V. */
int gcry_core_mpi_cmp_ui (gcry_core_context_t ctx,
			  const gcry_core_mpi_t u, unsigned long v);

/* Convert the external representation of an integer stored in BUFFER
   with a length of BUFLEN into a newly create MPI returned in
   RET_MPI.  If NSCANNED is not NULL, it will receive the number of
   bytes actually scanned after a successful operation. */
gcry_error_t gcry_core_mpi_scan (gcry_core_context_t ctx,
				 gcry_core_mpi_t *ret_mpi, enum gcry_mpi_format format,
				 const unsigned char *buffer, size_t buflen, 
				 size_t *nscanned);

/* Convert the big integer A into the external representation
   described by FORMAT and store it in the provided BUFFER which has
   been allocated by the user with a size of BUFLEN bytes.  NWRITTEN
   receives the actual length of the external representation unless it
   has been passed as NULL. */
gcry_error_t gcry_core_mpi_print (gcry_core_context_t ctx,
				  enum gcry_mpi_format format,
				  unsigned char *buffer, size_t buflen,
				  size_t *nwritten,
				  const gcry_core_mpi_t a);

/* Convert the big integer A int the external representation described
   by FORMAT and store it in a newly allocated buffer which address
   will be put into BUFFER.  NWRITTEN receives the actual lengths of the
   external representation. */
gcry_error_t gcry_core_mpi_aprint (gcry_core_context_t ctx,
				   enum gcry_mpi_format format,
				   unsigned char **buffer, size_t *nwritten,
				   const gcry_core_mpi_t a);

/* Dump the value of A in a format suitable for debugging to
   Libgcrypt's logging stream.  Note that one leading space but no
   trailing space or linefeed will be printed.  It is okay to pass
   NULL for A. */
void gcry_core_mpi_dump (gcry_core_context_t ctx, const gcry_core_mpi_t a);


/* W = U + V.  */
void gcry_core_mpi_add (gcry_core_context_t ctx,
			gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v);

/* W = U + V.  V is an unsigned integer. */
void gcry_core_mpi_add_ui (gcry_core_context_t ctx,
			   gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v);

/* W = U + V mod M. */
void gcry_core_mpi_addm (gcry_core_context_t ctx,
			 gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m);

/* W = U - V. */
void gcry_core_mpi_sub (gcry_core_context_t ctx,
			gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v);

/* W = U - V.  V is an unsigned integer. */
void gcry_core_mpi_sub_ui (gcry_core_context_t ctx,
			   gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v );

/* W = U - V mod M */
void gcry_core_mpi_subm (gcry_core_context_t ctx,
			 gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m);

/* W = U * V. */
void gcry_core_mpi_mul (gcry_core_context_t ctx,
			gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v);

/* W = U * V.  V is an unsigned integer. */
void gcry_core_mpi_mul_ui (gcry_core_context_t ctx,
			   gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v );

/* W = U * V mod M. */
void gcry_core_mpi_mulm (gcry_core_context_t ctx,
			 gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m);

/* W = U * (2 ^ CNT). */
void gcry_core_mpi_mul_2exp (gcry_core_context_t ctx,
			     gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long cnt);

/* Q = DIVIDEND / DIVISOR, R = DIVIDEND % DIVISOR,
   Q or R may be passed as NULL.  ROUND should be negative or 0. */
void gcry_core_mpi_div (gcry_core_context_t ctx,
			gcry_core_mpi_t q, gcry_core_mpi_t r,
			gcry_core_mpi_t dividend, gcry_core_mpi_t divisor, int round);

void gcry_core_mpi_fdiv_q (gcry_core_context_t ctx,
			   gcry_core_mpi_t quot, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor);

void gcry_core_mpi_fdiv_r (gcry_core_context_t ctx,
			   gcry_core_mpi_t rem, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor);

ulong gcry_core_mpi_fdiv_r_ui (gcry_core_context_t ctx,
			       gcry_core_mpi_t rem, gcry_core_mpi_t dividend, ulong divisor);

void gcry_core_mpi_tdiv_q_2exp (gcry_core_context_t ctx,
				gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned int count);

/* R = DIVIDEND % DIVISOR */
void gcry_core_mpi_mod (gcry_core_context_t ctx,
			gcry_core_mpi_t r, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor);

void gcry_core_mpi_mulpowm (gcry_core_context_t ctx,
			    gcry_core_mpi_t res, gcry_core_mpi_t *basearray,
			    gcry_core_mpi_t *exparray, gcry_core_mpi_t m);

/* W = B ^ E mod M. */
void gcry_core_mpi_powm (gcry_core_context_t ctx,
			 gcry_core_mpi_t w,
			 const gcry_core_mpi_t b, const gcry_core_mpi_t e,
			 const gcry_core_mpi_t m);

/* Set G to the greatest common divisor of A and B.  
   Return true if the G is 1. */
int gcry_core_mpi_gcd (gcry_core_context_t ctx,
		       gcry_core_mpi_t g, gcry_core_mpi_t a, gcry_core_mpi_t b);

/* Set X to the multiplicative inverse of A mod M.
   Return true if the value exists. */
int gcry_core_mpi_invm (gcry_core_context_t ctx,
			gcry_core_mpi_t x, gcry_core_mpi_t a, gcry_core_mpi_t m);


/* Return the number of bits required to represent A. */
unsigned int gcry_core_mpi_get_nbits (gcry_core_context_t ctx,
				      gcry_core_mpi_t a);

/* Return true when bit number N (counting from 0) is set in A. */
int      gcry_core_mpi_test_bit (gcry_core_context_t ctx,
				 gcry_core_mpi_t a, unsigned int n);

/* Set bit number N in A. */
void     gcry_core_mpi_set_bit (gcry_core_context_t ctx,
				gcry_core_mpi_t a, unsigned int n);

/* Clear bit number N in A. */
void     gcry_core_mpi_clear_bit (gcry_core_context_t ctx,
				  gcry_core_mpi_t a, unsigned int n);

/* Set bit number N in A and clear all bits greater than N. */
void     gcry_core_mpi_set_highbit (gcry_core_context_t ctx,
				    gcry_core_mpi_t a, unsigned int n);

/* Clear bit number N in A and all bits greater than N. */
void     gcry_core_mpi_clear_highbit (gcry_core_context_t ctx,
				      gcry_core_mpi_t a, unsigned int n);

/* Shift the value of A by N bits to the right and store the result in X. */
void     gcry_core_mpi_rshift (gcry_core_context_t ctx,
			       gcry_core_mpi_t x, gcry_core_mpi_t a, unsigned int n);

/* Store NBITS of the value P points to in A and mark A as an opaque
   value.  WARNING: Never use an opaque MPI for anything thing else then 
   gcry_mpi_release, gcry_mpi_get_opaque. */
gcry_core_mpi_t gcry_core_mpi_set_opaque (gcry_core_context_t ctx,
				     gcry_core_mpi_t a, void *p, unsigned int nbits);

/* Return a pointer to an opaque value stored in A and return its size
   in NBITS.  Note that the returned pointer is still owned by A and
   that the function should never be used for an non-opaque MPI. */
void *gcry_core_mpi_get_opaque (gcry_core_context_t ctx,
				gcry_core_mpi_t a, unsigned int *nbits);

/* Set the FLAG for the big integer A.  Currently only the flag
   GCRYMPI_FLAG_SECURE is allowed to convert A into an big intger
   stored in "secure" memory. */
void gcry_core_mpi_set_flag (gcry_core_context_t ctx,
			     gcry_core_mpi_t a, enum gcry_mpi_flag flag);

/* Clear FLAG for the big integer A.  Note that this function is
   currently useless as no flags are allowed. */
void gcry_core_mpi_clear_flag (gcry_core_context_t ctx,
			       gcry_core_mpi_t a, enum gcry_mpi_flag flag);

/* Return true when the FLAG is set for A. */
int gcry_core_mpi_get_flag (gcry_core_context_t ctx,
			    gcry_core_mpi_t a, enum gcry_mpi_flag flag);

/* Count the number of zerobits at the low end of A.  */
unsigned gcry_core_mpi_trailing_zeros (gcry_core_context_t ctx, gcry_core_mpi_t a);

gcry_core_mpi_t gcry_core_mpi_alloc_set_ui (gcry_core_context_t ctx,  unsigned long u);

gcry_core_mpi_t gcry_core_mpi_alloc_like (gcry_core_context_t ctx,  gcry_core_mpi_t a);

void gcry_core_mpi_set_buffer (gcry_core_context_t ctx,
			       gcry_core_mpi_t a, const unsigned char *buffer, unsigned nbytes, int sign);

/* Set the big integer W to a random value of NBITS using a random
   generator with quality LEVEL. */
void gcry_core_mpi_randomize (gcry_core_context_t ctx,
			      gcry_core_mpi_t w,
			      unsigned int nbits, enum gcry_random_level level);

int gcry_core_mpi_divisible_ui (gcry_core_context_t ctx,
				gcry_core_mpi_t dividend, ulong divisor);



extern gcry_core_subsystem_mpi_t gcry_core_subsystem_mpi;

#endif
