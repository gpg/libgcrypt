/* const-time.h  -  Constant-time functions
 *      Copyright (C) 2023  g10 Code GmbH
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
 */

#ifndef GCRY_CONST_TIME_H
#define GCRY_CONST_TIME_H

#include "types.h"


/*
 * Return 1 if it's not same, 0 if same.
 */
static inline unsigned int
ct_not_equal_byte (unsigned char b0, unsigned char b1)
{
#ifdef POSSIBLE_CONDITIONAL_BRANCH_IN_BYTE_COMPARISON
  unsigned int diff;

  diff = b0;
  diff ^= b1;

  return (0U - diff) >> (sizeof (unsigned int)*8 - 1);
#else
  return b0 != b1;
#endif
}

/* Compare byte-arrays of length LEN, return 1 if it's not same, 0
   otherwise.  We use pointer of void *, so that it can be used with
   any structure.  */
unsigned int ct_not_memequal (const void *b1, const void *b2, size_t len);

/* Compare byte-arrays of length LEN, return 0 if it's not same, 1
   otherwise.  We use pointer of void *, so that it can be used with
   any structure.  */
unsigned int ct_memequal (const void *b1, const void *b2, size_t len);

/*
 *  Return NULL when OP_ENABLED=1
 *  otherwise, return W
 */
static inline gcry_sexp_t
sexp_null_cond (gcry_sexp_t w, unsigned long op_enable)
{
  static volatile uintptr_t vone = 1;
  size_t mask = (uintptr_t)op_enable - vone;

  return (gcry_sexp_t)(void *)((uintptr_t)w & mask);
}

/*
 * Copy LEN bytes from memory area SRC to memory area DST, when
 * OP_ENABLED=1.  When DST <= SRC, the memory areas may overlap.  When
 * DST > SRC, the memory areas must not overlap.
 */
void ct_memmov_cond (void *dst, const void *src, size_t len,
                     unsigned long op_enable);

#endif /*GCRY_CONST_TIME_H*/
