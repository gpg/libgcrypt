/* interface.c - MPI interface
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

#include <gcrypt-mpi-internal.h>

gcry_core_mpi_t
gcry_core_mpi_new (gcry_core_context_t ctx, unsigned int nbits)
{
  return (*ctx->subsystems.mpi->new) (ctx, nbits);
}

gcry_core_mpi_t
gcry_core_mpi_snew (gcry_core_context_t ctx, unsigned int nbits)
{
  return (*ctx->subsystems.mpi->snew) (ctx, nbits);
}

void
gcry_core_mpi_release (gcry_core_context_t ctx, gcry_core_mpi_t a)
{
  (*ctx->subsystems.mpi->release) (ctx, a);
}

gcry_core_mpi_t
gcry_core_mpi_copy (gcry_core_context_t ctx, const gcry_core_mpi_t a)
{
  return (*ctx->subsystems.mpi->copy) (ctx, a);
}

gcry_core_mpi_t
gcry_core_mpi_set (gcry_core_context_t ctx,
		   gcry_core_mpi_t w, const gcry_core_mpi_t u)
{
  return (*ctx->subsystems.mpi->set) (ctx, w, u);
}

gcry_core_mpi_t
gcry_core_mpi_set_ui (gcry_core_context_t ctx,
		      gcry_core_mpi_t w, unsigned long u)
{
  return (*ctx->subsystems.mpi->set_ui) (ctx, w, u);
}

gcry_error_t
gcry_core_mpi_get_ui (gcry_core_context_t ctx,
		      gcry_core_mpi_t w, unsigned long *u)
{
  return (*ctx->subsystems.mpi->get_ui) (ctx, w, u);
}

void
gcry_core_mpi_swap (gcry_core_context_t ctx,
		    gcry_core_mpi_t a, gcry_core_mpi_t b)
{
  (*ctx->subsystems.mpi->swap) (ctx, a, b);
}

int
gcry_core_mpi_cmp (gcry_core_context_t ctx,
		   const gcry_core_mpi_t u, const gcry_core_mpi_t v)
{
  return (*ctx->subsystems.mpi->cmp) (ctx, u, v);
}

int
gcry_core_mpi_cmp_ui (gcry_core_context_t ctx,
		      const gcry_core_mpi_t u, unsigned long v)
{
  return (*ctx->subsystems.mpi->cmp_ui) (ctx, u, v);
}

gcry_error_t
gcry_core_mpi_scan (gcry_core_context_t ctx,
		    gcry_core_mpi_t *ret_mpi, enum gcry_mpi_format format,
		    const unsigned char *buffer, size_t buflen, 
		    size_t *nscanned)
{
  return (*ctx->subsystems.mpi->scan) (ctx, ret_mpi, format,
				      buffer, buflen, nscanned);
}

gcry_error_t
gcry_core_mpi_print (gcry_core_context_t ctx,
		     enum gcry_mpi_format format,
		     unsigned char *buffer, size_t buflen,
		     size_t *nwritten,
		     const gcry_core_mpi_t a)
{
  return (*ctx->subsystems.mpi->print) (ctx, format, buffer, buflen, nwritten, a);
}

gcry_error_t
gcry_core_mpi_aprint (gcry_core_context_t ctx,
		      enum gcry_mpi_format format,
		      unsigned char **buffer, size_t *nwritten,
		      const gcry_core_mpi_t a)
{
  return (*ctx->subsystems.mpi->aprint) (ctx, format, buffer, nwritten, a);
}

void
gcry_core_mpi_dump (gcry_core_context_t ctx, const gcry_core_mpi_t a)
{
  (*ctx->subsystems.mpi->dump) (ctx, a);
}

void
gcry_core_mpi_add (gcry_core_context_t ctx,
		   gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v)
{
  (*ctx->subsystems.mpi->add) (ctx, w, u, v);
}

void
gcry_core_mpi_add_ui (gcry_core_context_t ctx,
		      gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v)
{
  (*ctx->subsystems.mpi->add_ui) (ctx, w, u, v);
}

void
gcry_core_mpi_addm (gcry_core_context_t ctx,
		    gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m)
{
  (*ctx->subsystems.mpi->addm) (ctx, w, u, v, m);
}

void
gcry_core_mpi_sub (gcry_core_context_t ctx,
		   gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v)
{
  (*ctx->subsystems.mpi->sub) (ctx, w, u, v);
}

void
gcry_core_mpi_sub_ui (gcry_core_context_t ctx,
		      gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v )
{
  (*ctx->subsystems.mpi->sub_ui) (ctx, w, u, v);
}

void
gcry_core_mpi_subm (gcry_core_context_t ctx,
		    gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m)
{
  (*ctx->subsystems.mpi->subm) (ctx, w, u, v, m);
}

void
gcry_core_mpi_mul (gcry_core_context_t ctx,
		   gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v)
{
  (*ctx->subsystems.mpi->mul) (ctx, w, u, v);
}

void
gcry_core_mpi_mul_ui (gcry_core_context_t ctx,
		      gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long v )
{
  (*ctx->subsystems.mpi->mul_ui) (ctx, w, u, v);
}

void
gcry_core_mpi_mulm (gcry_core_context_t ctx,
		    gcry_core_mpi_t w, gcry_core_mpi_t u, gcry_core_mpi_t v, gcry_core_mpi_t m)
{
  (*ctx->subsystems.mpi->mulm) (ctx, w, u, v, m);
}

void
gcry_core_mpi_mul_2exp (gcry_core_context_t ctx,
			gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned long cnt)
{
  (*ctx->subsystems.mpi->mul_2exp) (ctx, w, u, cnt);
}

void
gcry_core_mpi_div (gcry_core_context_t ctx,
		   gcry_core_mpi_t q, gcry_core_mpi_t r,
		   gcry_core_mpi_t dividend, gcry_core_mpi_t divisor, int round)
{
  (*ctx->subsystems.mpi->div) (ctx, q, r, dividend, divisor, round);
}

void
gcry_core_mpi_fdiv_q (gcry_core_context_t ctx,
		      gcry_core_mpi_t quot, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor)
{
  (*ctx->subsystems.mpi->fdiv_q) (ctx, quot, dividend, divisor);
}

void
gcry_core_mpi_fdiv_r (gcry_core_context_t ctx,
		      gcry_core_mpi_t rem, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor)
{
  (*ctx->subsystems.mpi->fdiv_r) (ctx, rem, dividend, divisor);
}

ulong
gcry_core_mpi_fdiv_r_ui (gcry_core_context_t ctx,
			 gcry_core_mpi_t rem, gcry_core_mpi_t dividend, ulong divisor)
{
  return (*ctx->subsystems.mpi->fdiv_r_ui) (ctx, rem, dividend, divisor);
}

void
gcry_core_mpi_tdiv_q_2exp(gcry_core_context_t ctx,
			  gcry_core_mpi_t w, gcry_core_mpi_t u, unsigned int count)
{
  (*ctx->subsystems.mpi->tdiv_q_2exp) (ctx, w, u, count);
}

void
gcry_core_mpi_mod (gcry_core_context_t ctx,
		   gcry_core_mpi_t r, gcry_core_mpi_t dividend, gcry_core_mpi_t divisor)
{
  (*ctx->subsystems.mpi->mod) (ctx, r, dividend, divisor);
}

void
gcry_core_mpi_powm (gcry_core_context_t ctx,
		    gcry_core_mpi_t w,
		    const gcry_core_mpi_t b, const gcry_core_mpi_t e,
		    const gcry_core_mpi_t m)
{
  (*ctx->subsystems.mpi->powm) (ctx, w, b, e, m);
}

int
gcry_core_mpi_gcd (gcry_core_context_t ctx,
		   gcry_core_mpi_t g, gcry_core_mpi_t a, gcry_core_mpi_t b)
{
  return (*ctx->subsystems.mpi->gcd) (ctx, g, a, b);
}

int
gcry_core_mpi_invm (gcry_core_context_t ctx,
		    gcry_core_mpi_t x, gcry_core_mpi_t a, gcry_core_mpi_t m)
{
  return (*ctx->subsystems.mpi->invm) (ctx, x, a, m);
}


unsigned int
gcry_core_mpi_get_nbits (gcry_core_context_t ctx,
			 gcry_core_mpi_t a)
{
  return (*ctx->subsystems.mpi->get_nbits) (ctx, a);
}

int
gcry_core_mpi_test_bit (gcry_core_context_t ctx,
			gcry_core_mpi_t a, unsigned int n)
{
  return (*ctx->subsystems.mpi->test_bit) (ctx, a, n);
}

void
gcry_core_mpi_set_bit (gcry_core_context_t ctx,
		       gcry_core_mpi_t a, unsigned int n)
{
  (*ctx->subsystems.mpi->set_bit) (ctx, a, n);
}

void
gcry_core_mpi_set_buffer (gcry_core_context_t ctx,
			  gcry_core_mpi_t a, const byte *buffer, unsigned nbytes, int sign)
{
  (*ctx->subsystems.mpi->set_buffer) (ctx, a, buffer, nbytes, sign);
}

void
gcry_core_mpi_clear_bit (gcry_core_context_t ctx,
			 gcry_core_mpi_t a, unsigned int n)
{
  (*ctx->subsystems.mpi->clear_bit) (ctx, a, n);
}

void
gcry_core_mpi_set_highbit (gcry_core_context_t ctx,
			   gcry_core_mpi_t a, unsigned int n)
{
  (*ctx->subsystems.mpi->set_highbit) (ctx, a, n);
}

void
gcry_core_mpi_clear_highbit (gcry_core_context_t ctx,
			     gcry_core_mpi_t a, unsigned int n)
{
  (*ctx->subsystems.mpi->clear_highbit) (ctx, a, n);
}

void
gcry_core_mpi_rshift (gcry_core_context_t ctx,
		      gcry_core_mpi_t x, gcry_core_mpi_t a, unsigned int n)
{
  (*ctx->subsystems.mpi->rshift) (ctx, x, a, n);
}

gcry_core_mpi_t
gcry_core_mpi_set_opaque (gcry_core_context_t ctx,
			  gcry_core_mpi_t a, void *p, unsigned int nbits)
{
  return (*ctx->subsystems.mpi->set_opaque) (ctx, a, p, nbits);
}

void *
gcry_core_mpi_get_opaque (gcry_core_context_t ctx,
			  gcry_core_mpi_t a, unsigned int *nbits)
{
  return (*ctx->subsystems.mpi->get_opaque) (ctx, a, nbits);
}

void
gcry_core_mpi_set_flag (gcry_core_context_t ctx,
			gcry_core_mpi_t a, enum gcry_mpi_flag flag)
{
  (*ctx->subsystems.mpi->set_flag) (ctx, a, flag);
}

void
gcry_core_mpi_clear_flag (gcry_core_context_t ctx,
			  gcry_core_mpi_t a, enum gcry_mpi_flag flag)
{
  (*ctx->subsystems.mpi->clear_flag) (ctx, a, flag);
}

int
gcry_core_mpi_get_flag (gcry_core_context_t ctx,
			gcry_core_mpi_t a, enum gcry_mpi_flag flag)
{
  return (*ctx->subsystems.mpi->get_flag) (ctx, a, flag);
}

unsigned
gcry_core_mpi_trailing_zeros (gcry_core_context_t ctx, gcry_core_mpi_t a)
{
  return (*ctx->subsystems.mpi->trailing_zeros) (ctx, a);
}

gcry_core_mpi_t
gcry_core_mpi_alloc_set_ui (gcry_core_context_t ctx,  unsigned long u)
{
  return (*ctx->subsystems.mpi->alloc_set_ui) (ctx, u);
}

gcry_core_mpi_t
gcry_core_mpi_alloc_like (gcry_core_context_t ctx,  gcry_core_mpi_t a)
{
  return (*ctx->subsystems.mpi->alloc_like) (ctx, a);
}

void
gcry_core_mpi_mulpowm (gcry_core_context_t ctx,
		       gcry_core_mpi_t res, gcry_core_mpi_t *basearray,
		       gcry_core_mpi_t *exparray, gcry_core_mpi_t m)
{
  (*ctx->subsystems.mpi->mulpowm) (ctx, res, basearray, exparray, m);
}

void
gcry_core_mpi_randomize (gcry_core_context_t ctx,
			 gcry_core_mpi_t w,
			 unsigned int nbits, enum gcry_random_level level)
{
  (*ctx->subsystems.mpi->randomize) (ctx, w, nbits, level);
}

int
gcry_core_mpi_divisible_ui (gcry_core_context_t ctx,
			    gcry_core_mpi_t dividend, ulong divisor)
{
  return (*ctx->subsystems.mpi->divisible_ui) (ctx, dividend, divisor);
}  
