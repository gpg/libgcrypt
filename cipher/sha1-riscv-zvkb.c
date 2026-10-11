/* sha1-riscv-zvkb.c - RISC-V vector SHA-1 with Zvkb
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
    defined(USE_SHA1)

#include "g10lib.h"
#include "bithelp.h"
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


/* One block, VLEN == 128 */
#define SHA1_LMUL m1
#define SHA1_NBLK 1
#include "sha1-riscv-zvkb.h"

/* One block, VLEN >= 256 */
#define SHA1_LMUL mf2
#define SHA1_NBLK 1
#include "sha1-riscv-zvkb.h"

/* Two blocks, VLEN >= 512 */
#define SHA1_LMUL mf2
#define SHA1_NBLK 2
#include "sha1-riscv-zvkb.h"

unsigned int ASM_FUNC_ATTR
_gcry_sha1_transform_riscv_zvkb(void *state_ptr,
				const unsigned char *input_data,
				size_t num_blks)
{
  u32 *state = state_ptr;
  size_t vlenb = __riscv_vsetvlmax_e8m1();
  unsigned int burn = 0;
  unsigned int nburn;

  if (vlenb < 32)
    return sha1_transform_zvkb_m1x1(state, input_data, num_blks);

  if (vlenb < 64 || num_blks < 2)
    return sha1_transform_zvkb_mf2x1(state, input_data, num_blks);

  if (num_blks & 1)
    {
      burn = sha1_transform_zvkb_mf2x1(state, input_data, 1);
      input_data += 64;
      num_blks--;
    }

  nburn = sha1_transform_zvkb_mf2x2(state, input_data, num_blks);

  return nburn > burn ? nburn : burn;
}

unsigned int ASM_FUNC_ATTR FUNC_ATTR_OPT_O2
_gcry_sha1_riscv_v_check_hw(void)
{
  return (__riscv_vsetvl_e32m1(4) == 4);
}

#endif /* HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS */
