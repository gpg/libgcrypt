/* RISC-V vector permutation AES for Libgcrypt
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
 *
 *
 * The code is based on the public domain library libvpaes version 0.5
 * available at http://crypto.stanford.edu/vpaes/ and which carries
 * this notice:
 *
 *     libvpaes: constant-time SSSE3 AES encryption and decryption.
 *     version 0.5
 *
 *     By Mike Hamburg, Stanford University, 2009.  Public domain.
 *     I wrote essentially all of this code.  I did not write the test
 *     vectors; they are the NIST known answer tests.  I hereby release all
 *     the code and documentation here that I wrote into the public domain.
 *
 *     This is an implementation of AES following my paper,
 *       "Accelerating AES with Vector Permute Instructions"
 *       CHES 2009; http://shiftleft.org/papers/vector_aes/
 */

#include <config.h>
#include "rijndael-internal.h"

#ifdef USE_VP_RISCV

#define VP_LMUL128 m1

#include "rijndael-vp-riscv.h"

extern void _gcry_aes_vp_riscv_mf2_setup (RIJNDAEL_context *ctx,
					   rijndael_setkeyfn_t *hw_setkey,
					   cipher_bulk_ops_t *bulk_ops);
extern void _gcry_aes_vp_riscv_mf4_setup (RIJNDAEL_context *ctx,
					   rijndael_setkeyfn_t *hw_setkey,
					   cipher_bulk_ops_t *bulk_ops);
extern void _gcry_aes_vp_riscv_mf8_setup (RIJNDAEL_context *ctx,
					   rijndael_setkeyfn_t *hw_setkey,
					   cipher_bulk_ops_t *bulk_ops);

int
_gcry_aes_vp_riscv_setup_acceleration (RIJNDAEL_context *ctx,
				       rijndael_setkeyfn_t *hw_setkey,
				       cipher_bulk_ops_t *bulk_ops)
{
  size_t vlenb;

  if (__riscv_vsetvl_e8m1(16) != 16)
    return 0;

  vlenb = __riscv_vsetvlmax_e8m1 ();
  if (vlenb >= 128)
    _gcry_aes_vp_riscv_mf8_setup (ctx, hw_setkey, bulk_ops);
  else if (vlenb >= 64)
    _gcry_aes_vp_riscv_mf4_setup (ctx, hw_setkey, bulk_ops);
  else if (vlenb >= 32)
    _gcry_aes_vp_riscv_mf2_setup (ctx, hw_setkey, bulk_ops);
  else
    _gcry_aes_vp_riscv_m1_setup (ctx, hw_setkey, bulk_ops);

  return 1;
}

#endif /* USE_VP_RISCV */
