/* SSSE3 vector permutation AES for Libgcrypt
 * Copyright (C) 2014-2017 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* for memcmp() */

#include "types.h"  /* for byte and u32 typedefs */
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "rijndael-internal.h"
#include "./cipher-internal.h"


#ifdef USE_VP_AARCH64


#ifdef HAVE_GCC_ATTRIBUTE_OPTIMIZE
# define FUNC_ATTR_OPT __attribute__((optimize("-O2")))
#else
# define FUNC_ATTR_OPT
#endif

#define SIMD128_OPT_ATTR FUNC_ATTR_OPT

#define FUNC_ENCRYPT _gcry_aes_vp_aarch64_encrypt
#define FUNC_DECRYPT _gcry_aes_vp_aarch64_decrypt
#define FUNC_CFB_ENC _gcry_aes_vp_aarch64_cfb_enc
#define FUNC_CFB_DEC _gcry_aes_vp_aarch64_cfb_dec
#define FUNC_CBC_ENC _gcry_aes_vp_aarch64_cbc_enc
#define FUNC_CBC_DEC _gcry_aes_vp_aarch64_cbc_dec
#define FUNC_CTR_ENC _gcry_aes_vp_aarch64_ctr_enc
#define FUNC_CTR32LE_ENC _gcry_aes_vp_aarch64_ctr32le_enc
#define FUNC_OCB_CRYPT _gcry_aes_vp_aarch64_ocb_crypt
#define FUNC_OCB_AUTH _gcry_aes_vp_aarch64_ocb_auth
#define FUNC_ECB_CRYPT _gcry_aes_vp_aarch64_ecb_crypt
#define FUNC_XTS_CRYPT _gcry_aes_vp_aarch64_xts_crypt
#define FUNC_SETKEY _gcry_aes_vp_aarch64_do_setkey
#define FUNC_PREPARE_DEC _gcry_aes_vp_aarch64_prepare_decryption

#include "rijndael-vp-simd128.h"

#endif /* USE_VP_AARCH64 */
