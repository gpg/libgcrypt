/* const-time.c  -  Constant-time functions
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "g10lib.h"
#include "const-time.h"

/*
 * Compare byte arrays of length LEN, return 1 if it's not same,
 * 0, otherwise.
 *
 * Originally in NetBSD as "consttime_memequal" which is:
 *
 *   Written by Matthias Drochner <drochner@NetBSD.org>.
 *   Public domain.
 *
 * Modified the function name, return type to unsigned,
 * and return value (0 <-> 1).
 */
unsigned int
ct_not_memequal (const void *b1, const void *b2, size_t len)
{
  const unsigned char *c1 = b1, *c2 = b2;
  unsigned int res = 0;

  while (len--)
    res |= *c1++ ^ *c2++;

  return ct_not_equal_byte (res, 0);
}

/*
 * Copy LEN bytes from memory area SRC to memory area DST, when
 * OP_ENABLED=1.  When DST <= SRC, the memory areas may overlap.  When
 * DST > SRC, the memory areas must not overlap.
 */
void
ct_memmov_cond (void *dst, const void *src, size_t len,
                unsigned long op_enable)
{
  size_t i;
  unsigned char mask;
  unsigned char *b_dst = dst;
  const unsigned char *b_src = src;

  mask = -(unsigned char)op_enable;
  for (i = 0; i < len; i++)
    b_dst[i] ^= mask & (b_dst[i] ^ b_src[i]);
}
