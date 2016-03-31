/* sha1.h - SHA-1 context definition
 * Copyright (C) 1998, 2001, 2002, 2003, 2008 Free Software Foundation, Inc.
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
#ifndef GCRY_SHA1_H
#define GCRY_SHA1_H

#include "hash-common.h"

/* We need this here for direct use by random-csprng.c. */
typedef struct
{
  gcry_md_block_ctx_t bctx;
  u32          h0,h1,h2,h3,h4;
  unsigned int use_ssse3:1;
  unsigned int use_avx:1;
  unsigned int use_bmi2:1;
  unsigned int use_neon:1;
} SHA1_CONTEXT;


void _gcry_sha1_mixblock_init (SHA1_CONTEXT *hd);
unsigned int _gcry_sha1_mixblock (SHA1_CONTEXT *hd, void *blockof64byte);

#endif /*GCRY_SHA1_H*/
