/* chacha20-riscv-zvkb.c - RISC-V Zvkb implementation of ChaCha20
 * Copyright (C) 2025-2026 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#include <config.h>

#if defined (__riscv) && \
    defined(HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS) && \
    defined(HAVE_COMPATIBLE_CC_RISCV_VECTOR_CRYPTO_INTRINSICS) && \
    defined(USE_CHACHA20)


#define ROTATE(v, c)	__riscv_vror_vx_u32m1(v, 32 - (c), vl)
#define ROTATE16(v)	ROTATE(v, 16)
#define ROTATE8(v)	ROTATE(v, 8)


#include "chacha20-riscv-rvv.h"


size_t ASM_FUNC_ATTR FUNC_ATTR_OPT_O2
_gcry_chacha20_riscv_zvkb_blocks(u32 *state, byte *dst, const byte *src,
				 size_t nblks)
{
  return chacha20_rvv_blocks(state, dst, src, nblks);
}

#endif /* HAVE_COMPATIBLE_CC_RISCV_VECTOR_CRYPTO_INTRINSICS */
