/* poly1305-internal.h  -  Poly1305 internals
 * Copyright (C) 2014 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G10_POLY1305_INTERNAL_H
#define G10_POLY1305_INTERNAL_H

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"


#define POLY1305_TAGLEN 16
#define POLY1305_KEYLEN 32


/* Block-size used in default implementation. */
#define POLY1305_REF_BLOCKSIZE 16

/* State size of default implementation. */
#define POLY1305_REF_STATESIZE 64

/* State alignment for default implementation. */
#define POLY1305_REF_ALIGNMENT sizeof(void *)


#undef POLY1305_SYSV_FUNC_ABI

/* POLY1305_USE_SSE2 indicates whether to compile with AMD64 SSE2 code. */
#undef POLY1305_USE_SSE2
#if defined(__x86_64__) && (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))
# define POLY1305_USE_SSE2 1
# define POLY1305_SSE2_BLOCKSIZE 32
# define POLY1305_SSE2_STATESIZE 248
# define POLY1305_SSE2_ALIGNMENT 16
# define POLY1305_SYSV_FUNC_ABI 1
#endif


/* POLY1305_USE_AVX2 indicates whether to compile with AMD64 AVX2 code. */
#undef POLY1305_USE_AVX2
#if defined(__x86_64__) && (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS)) && \
    defined(ENABLE_AVX2_SUPPORT)
# define POLY1305_USE_AVX2 1
# define POLY1305_AVX2_BLOCKSIZE 64
# define POLY1305_AVX2_STATESIZE 328
# define POLY1305_AVX2_ALIGNMENT 32
# define POLY1305_SYSV_FUNC_ABI 1
#endif


/* POLY1305_USE_NEON indicates whether to enable ARM NEON assembly code. */
#undef POLY1305_USE_NEON
#if defined(ENABLE_NEON_SUPPORT) && defined(HAVE_ARM_ARCH_V6) && \
    defined(__ARMEL__) && defined(HAVE_COMPATIBLE_GCC_ARM_PLATFORM_AS) && \
    defined(HAVE_GCC_INLINE_ASM_NEON)
# define POLY1305_USE_NEON 1
# define POLY1305_NEON_BLOCKSIZE 32
# define POLY1305_NEON_STATESIZE 128
# define POLY1305_NEON_ALIGNMENT 16
#endif


/* Largest block-size used in any implementation (optimized implementations
 * might use block-size multiple of 16). */
#ifdef POLY1305_USE_AVX2
# define POLY1305_LARGEST_BLOCKSIZE POLY1305_AVX2_BLOCKSIZE
#elif defined(POLY1305_USE_NEON)
# define POLY1305_LARGEST_BLOCKSIZE POLY1305_NEON_BLOCKSIZE
#elif defined(POLY1305_USE_SSE2)
# define POLY1305_LARGEST_BLOCKSIZE POLY1305_SSE2_BLOCKSIZE
#else
# define POLY1305_LARGEST_BLOCKSIZE POLY1305_REF_BLOCKSIZE
#endif

/* Largest state-size used in any implementation. */
#ifdef POLY1305_USE_AVX2
# define POLY1305_LARGEST_STATESIZE POLY1305_AVX2_STATESIZE
#elif defined(POLY1305_USE_NEON)
# define POLY1305_LARGEST_STATESIZE POLY1305_NEON_STATESIZE
#elif defined(POLY1305_USE_SSE2)
# define POLY1305_LARGEST_STATESIZE POLY1305_SSE2_STATESIZE
#else
# define POLY1305_LARGEST_STATESIZE POLY1305_REF_STATESIZE
#endif

/* Minimum alignment for state pointer passed to implementations. */
#ifdef POLY1305_USE_AVX2
# define POLY1305_STATE_ALIGNMENT POLY1305_AVX2_ALIGNMENT
#elif defined(POLY1305_USE_NEON)
# define POLY1305_STATE_ALIGNMENT POLY1305_NEON_ALIGNMENT
#elif defined(POLY1305_USE_SSE2)
# define POLY1305_STATE_ALIGNMENT POLY1305_SSE2_ALIGNMENT
#else
# define POLY1305_STATE_ALIGNMENT POLY1305_REF_ALIGNMENT
#endif


/* Assembly implementations use SystemV ABI, ABI conversion and additional
 * stack to store XMM6-XMM15 needed on Win64. */
#undef OPS_FUNC_ABI
#if defined(POLY1305_SYSV_FUNC_ABI) && \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS)
# define OPS_FUNC_ABI __attribute__((sysv_abi))
#else
# define OPS_FUNC_ABI
#endif


typedef struct poly1305_key_s
{
  byte b[POLY1305_KEYLEN];
} poly1305_key_t;


typedef struct poly1305_ops_s
{
  size_t block_size;
  void (*init_ext) (void *ctx, const poly1305_key_t * key) OPS_FUNC_ABI;
  unsigned int (*blocks) (void *ctx, const byte * m, size_t bytes) OPS_FUNC_ABI;
  unsigned int (*finish_ext) (void *ctx, const byte * m, size_t remaining,
			      byte mac[POLY1305_TAGLEN]) OPS_FUNC_ABI;
} poly1305_ops_t;


typedef struct poly1305_context_s
{
  byte state[POLY1305_LARGEST_STATESIZE + POLY1305_STATE_ALIGNMENT];
  byte buffer[POLY1305_LARGEST_BLOCKSIZE];
  const poly1305_ops_t *ops;
  unsigned int leftover;
} poly1305_context_t;


gcry_err_code_t _gcry_poly1305_init (poly1305_context_t * ctx, const byte * key,
				     size_t keylen);

void _gcry_poly1305_finish (poly1305_context_t * ctx,
			    byte mac[POLY1305_TAGLEN]);

void _gcry_poly1305_update (poly1305_context_t * ctx, const byte * buf,
			    size_t buflen);


#endif /* G10_POLY1305_INTERNAL_H */
