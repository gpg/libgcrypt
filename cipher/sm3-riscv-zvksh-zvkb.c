/* sm3-riscv-zvksh-zvkb.c - RISC-V vector crypto implementation of SM3
 * Copyright (C) 2026 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
    defined(USE_SM3)

#include "g10lib.h"
#include "simd-common-riscv.h"
#include <riscv_vector.h>


#define ALWAYS_INLINE inline __attribute__((always_inline))
#define NO_INLINE __attribute__((noinline))
#define NO_INSTRUMENT_FUNCTION __attribute__((no_instrument_function))

#define ASM_FUNC_ATTR          NO_INSTRUMENT_FUNCTION
#define ASM_FUNC_ATTR_INLINE   ASM_FUNC_ATTR ALWAYS_INLINE
#define ASM_FUNC_ATTR_NOINLINE ASM_FUNC_ATTR NO_INLINE

#ifdef HAVE_GCC_ATTRIBUTE_OPTIMIZE
# define FUNC_ATTR_OPT_O2 __attribute__((optimize("-O2")))
#else
# define FUNC_ATTR_OPT_O2
#endif


/* m2 variant for VLEN == 128 */
#define SM3_LMUL m2
#include "sm3-riscv-zvksh-zvkb.h"

/* m1 variant for VLEN >= 256, compiled separately with zvl256b */
extern unsigned int
_gcry_sm3_transform_riscv_zvksh_zvkb_m1(u32 state[8],
					const unsigned char *input_data,
					size_t num_blks);

unsigned int
_gcry_sm3_transform_riscv_zvksh_zvkb(u32 state[8],
				     const unsigned char *input_data,
				     size_t num_blks)
{
  if (__riscv_vsetvlmax_e8m1() >= 32)
    return _gcry_sm3_transform_riscv_zvksh_zvkb_m1(state, input_data,
						   num_blks);
  else
    return sm3_transform_zvksh_zvkb_m2(state, input_data, num_blks);
}

unsigned int ASM_FUNC_ATTR FUNC_ATTR_OPT_O2
_gcry_sm3_riscv_v_check_hw(void)
{
  return (__riscv_vsetvl_e32m2(8) == 8);
}

#endif /* HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS */
