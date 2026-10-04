/* chacha20-riscv-v.c - RISC-V vector implementation of ChaCha20
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
    defined(USE_CHACHA20)


#define LOAD_GATHER_ROTATE_CONSTANTS 1

#define ROTATE16(v)	__riscv_vreinterpret_v_u16m1_u32m1( \
				__riscv_vrgather_vv_u16m1( \
					__riscv_vreinterpret_v_u32m1_u16m1(v), \
					rot16, vl * 2))
#define ROTATE8(v)	__riscv_vreinterpret_v_u8m1_u32m1( \
				__riscv_vrgather_vv_u8m1( \
					__riscv_vreinterpret_v_u32m1_u8m1(v), \
					rot8, vl * 4))
#define ROTATE(v, c)	__riscv_vadd_vv_u32m1( \
				__riscv_vsll_vx_u32m1((v), (c), vl), \
				__riscv_vsrl_vx_u32m1((v), 32 - (c), vl), vl)


#include "chacha20-riscv-rvv.h"


size_t ASM_FUNC_ATTR FUNC_ATTR_OPT_O2
_gcry_chacha20_riscv_v_blocks(u32 *state, byte *dst, const byte *src,
			      size_t nblks)
{
  return chacha20_rvv_blocks(state, dst, src, nblks);
}

unsigned int ASM_FUNC_ATTR FUNC_ATTR_OPT_O2
_gcry_chacha20_riscv_v_check_hw(void)
{
  return (__riscv_vsetvl_e8m1(16) == 16);
}

#endif /* HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS */
