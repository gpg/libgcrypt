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

/* Originally in NetBSD.
 *
 * Written by Matthias Drochner <drochner@NetBSD.org>.
 * Public domain.
 *
 * Modified the function name and return type to unsigned.
 */
unsigned int
ct_memequal (const void *b1, const void *b2, size_t len)
{
	const unsigned char *c1 = b1, *c2 = b2;
	unsigned int res = 0;

	while (len--)
		res |= *c1++ ^ *c2++;

	/*
	 * Map 0 to 1 and [1, 256) to 0 using only constant-time
	 * arithmetic.
	 *
	 * This is not simply `!res' because although many CPUs support
	 * branchless conditional moves and many compilers will take
	 * advantage of them, certain compilers generate branches on
	 * certain CPUs for `!res'.
	 */
	return (1 & ((res - 1) >> 8));
}
