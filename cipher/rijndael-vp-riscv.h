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

#ifndef GCRY_RIJNDAEL_VP_RISCV_H
#define GCRY_RIJNDAEL_VP_RISCV_H

#include <config.h>
#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "rijndael-internal.h"
#include "cipher-internal.h"

#ifdef VP_LMUL128

/**********************************************************************
  AT&T x86 asm to intrinsics conversion macros (RISC-V)
 **********************************************************************/

/* VP_LMUL128 is LMUL that gives 128-bit register group. */

#include <riscv_vector.h>
#include "simd-common-riscv.h"

#define VP_CAT_(a, b)           a##b
#define VP_CAT(a, b)            VP_CAT_(a, b)
#define VP_CAT3_(a, b, c)       a##b##c
#define VP_CAT3(a, b, c)        VP_CAT3_(a, b, c)

#define VP_U8(fn, lmul)         VP_CAT3(__riscv_, fn, VP_CAT(_u8, lmul))

#define VP_TO_M1_m1(a)          (a)
#define VP_TO_M1_mf2(a)         __riscv_vlmul_ext_v_u8mf2_u8m1(a)
#define VP_TO_M1_mf4(a)         __riscv_vlmul_ext_v_u8mf4_u8m1(a)
#define VP_TO_M1_mf8(a)         __riscv_vlmul_ext_v_u8mf8_u8m1(a)
#define VP_FROM_M1_m1(a)        (a)
#define VP_FROM_M1_mf2(a)       __riscv_vlmul_trunc_v_u8m1_u8mf2(a)
#define VP_FROM_M1_mf4(a)       __riscv_vlmul_trunc_v_u8m1_u8mf4(a)
#define VP_FROM_M1_mf8(a)       __riscv_vlmul_trunc_v_u8m1_u8mf8(a)
#define VP_TO_M1(lmul, a)       VP_CAT(VP_TO_M1_, lmul)(a)
#define VP_FROM_M1(lmul, a)     VP_CAT(VP_FROM_M1_, lmul)(a)

/*
 * SIMD128
 */

typedef VP_CAT3(vuint8, VP_LMUL128, _t) __m128i;

#define V128(fn)                VP_U8(fn, VP_LMUL128)

#define cast_m128i_to_u32(a)    (__riscv_vreinterpret_v_u8m1_u32m1(VP_TO_M1(VP_LMUL128, a)))
#define cast_m128i_to_u64(a)    (__riscv_vreinterpret_v_u8m1_u64m1(VP_TO_M1(VP_LMUL128, a)))
#define cast_m128i_to_s64(a)    (__riscv_vreinterpret_v_u64m1_i64m1(cast_m128i_to_u64(a)))

#define cast_u32_to_m128i(a)    (VP_FROM_M1(VP_LMUL128, __riscv_vreinterpret_v_u32m1_u8m1(a)))
#define cast_u64_to_m128i(a)    (VP_FROM_M1(VP_LMUL128, __riscv_vreinterpret_v_u64m1_u8m1(a)))
#define cast_s64_to_m128i(a)    (cast_u64_to_m128i(__riscv_vreinterpret_v_i64m1_u64m1(a)))

#define pand128(a, o)           (o = V128(vand_vv)((o), (a), 16))
#define pandn128(a, o)          (o = V128(vand_vv)(V128(vnot_v)((o), 16), (a), 16))
#define pxor128(a, o)           (o = V128(vxor_vv)((o), (a), 16))
#define paddb128(a, o)          (o = V128(vadd_vv)((o), (a), 16))
#define paddd128(a, o)          (o = cast_u32_to_m128i(__riscv_vadd_vv_u32m1( \
							cast_m128i_to_u32(o), \
							cast_m128i_to_u32(a), 4)))
#define paddq128(a, o)          (o = cast_u64_to_m128i(__riscv_vadd_vv_u64m1( \
							cast_m128i_to_u64(o), \
							cast_m128i_to_u64(a), 2)))

#define psrld128(s, o)          (o = cast_u32_to_m128i(__riscv_vsrl_vx_u32m1(cast_m128i_to_u32(o), (s), 4))
#define psraq128(s, o)          (o = cast_s64_to_m128i(__riscv_vsra_vx_i64m1(cast_m128i_to_s64(o), (s), 2)))
#define psrldq128(s, o)         (o = V128(vslidedown_vx)((o), (s), 16))
#define pslldq128(s, o)         ({ __m128i __tmp = V128(vmv_v_x)(0, 16); \
				   o = V128(vslideup_vx)(__tmp, (o), (s), 16); })
#define psrl_byte_128(s, o)     (o = V128(vsrl_vx)((o), (s), 16))

#define pshufb128(m8, o)        (o = V128(vrgather_vv)((o), (m8), 16))
#define pshufd128(m32, a, o)    ({ static const __m128i_const __tmp1 = PSHUFD_MASK_TO_PSHUFB_MASK(m32); \
				   __m128i __tmp2; \
				   movdqa128(a, o); \
				   movdqa128_memld(&__tmp1, __tmp2); \
				   pshufb128(__tmp2, o); })

#define pshufd128_0x93(a, o)    pshufd128(0x93, a, o)
#define pshufd128_0xFF(a, o)    pshufd128(0xFF, a, o)
#define pshufd128_0xFE(a, o)    pshufd128(0xFE, a, o)
#define pshufd128_0x4E(a, o)    pshufd128(0x4E, a, o)

#define palignr128(s, a, o)     (o = V128(vslideup_vx)(V128(vslidedown_vx)((a), (s), 16), (o), 16 - (s), 16))

#define movdqa128(a, o)         (o = (a))

#define movdqa128_memld(a, o)   (o = V128(vle8_v)((const void *)(a), 16))

#define pand128_amemld(m, o)    pand128(V128(vle8_v)((const void *)(m), 16), (o))
#define pxor128_amemld(m, o)    pxor128(V128(vle8_v)((const void *)(m), 16), (o))
#define paddq128_amemld(m, o)   paddq128(V128(vle8_v)((const void *)(m), 16), (o))
#define paddd128_amemld(m, o)   paddd128(V128(vle8_v)((const void *)(m), 16), (o))
#define pshufb128_amemld(m, o)  pshufb128(V128(vle8_v)((const void *)(m), 16), (o))

/* Following operations may have unaligned memory input */
#define movdqu128_memld(a, o)   (o = V128(vle8_v)((const void *)(a), 16))

/* Following operations may have unaligned memory output */
#define movdqu128_memst(a, o)   (V128(vse8_v)((void *)(o), (a), 16))

#ifdef HAVE_GCC_ATTRIBUTE_OPTIMIZE
# define FUNC_ATTR_OPT __attribute__((optimize("-O2")))
#else
# define FUNC_ATTR_OPT
#endif

#define SIMD128_OPT_ATTR FUNC_ATTR_OPT

#define VP_FUNC(name) VP_CAT3(_gcry_aes_vp_riscv_, VP_LMUL128, _##name)

#define FUNC_ENCRYPT VP_FUNC(encrypt)
#define FUNC_DECRYPT VP_FUNC(decrypt)
#define FUNC_CFB_ENC VP_FUNC(cfb_enc)
#define FUNC_CFB_DEC VP_FUNC(cfb_dec)
#define FUNC_CBC_ENC VP_FUNC(cbc_enc)
#define FUNC_CBC_DEC VP_FUNC(cbc_dec)
#define FUNC_CTR_ENC VP_FUNC(ctr_enc)
#define FUNC_CTR32LE_ENC VP_FUNC(ctr32le_enc)
#define FUNC_OCB_CRYPT VP_FUNC(ocb_crypt)
#define FUNC_OCB_AUTH VP_FUNC(ocb_auth)
#define FUNC_ECB_CRYPT VP_FUNC(ecb_crypt)
#define FUNC_XTS_CRYPT VP_FUNC(xts_crypt)
#define FUNC_SETKEY VP_FUNC(do_setkey)
#define FUNC_PREPARE_DEC VP_FUNC(prepare_decryption)

#include "rijndael-vp-simd128.h"

void
VP_FUNC(setup) (RIJNDAEL_context *ctx, rijndael_setkeyfn_t *hw_setkey,
		cipher_bulk_ops_t *bulk_ops)
{
  *hw_setkey = FUNC_SETKEY;
  ctx->encrypt_fn = FUNC_ENCRYPT;
  ctx->decrypt_fn = FUNC_DECRYPT;
  ctx->prepare_decryption = FUNC_PREPARE_DEC;

  bulk_ops->cfb_enc = FUNC_CFB_ENC;
  bulk_ops->cfb_dec = FUNC_CFB_DEC;
  bulk_ops->cbc_enc = FUNC_CBC_ENC;
  bulk_ops->cbc_dec = FUNC_CBC_DEC;
  bulk_ops->ctr16be_enc = FUNC_CTR_ENC;
  bulk_ops->ctr32le_enc = FUNC_CTR32LE_ENC;
  bulk_ops->ocb_crypt = FUNC_OCB_CRYPT;
  bulk_ops->ocb_auth = FUNC_OCB_AUTH;
  bulk_ops->ecb_crypt = FUNC_ECB_CRYPT;
  bulk_ops->xts_crypt = FUNC_XTS_CRYPT;
}

#endif /* VP_LMUL128 */

#endif /* GCRY_RIJNDAEL_VP_RISCV_H */
