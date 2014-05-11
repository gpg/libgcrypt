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


/* Largest block-size used in any implementation (optimized implementations
 * might use block-size multiple of 16). */
#define POLY1305_LARGEST_BLOCKSIZE POLY1305_REF_BLOCKSIZE

/* Largest state-size used in any implementation. */
#define POLY1305_LARGEST_STATESIZE POLY1305_REF_STATESIZE

/* Minimum alignment for state pointer passed to implementations. */
#define POLY1305_STATE_ALIGNMENT POLY1305_REF_ALIGNMENT


typedef struct poly1305_key_s
{
  byte b[POLY1305_KEYLEN];
} poly1305_key_t;


typedef struct poly1305_ops_s
{
  size_t block_size;
  void (*init_ext) (void *ctx, const poly1305_key_t * key);
  unsigned int (*blocks) (void *ctx, const byte * m, size_t bytes);
  unsigned int (*finish_ext) (void *ctx, const byte * m, size_t remaining,
			      byte mac[POLY1305_TAGLEN]);
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
