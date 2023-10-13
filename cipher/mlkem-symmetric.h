/* mlkem-symmetric.h - functions wrapping symmetric primitives for ML-KEM
 * Copyright (C) 2023 MTG AG
 * The code was created based on the reference implementation that is part of the ML-KEM NIST submission.
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

#ifndef GCRYPT_MLKEM_SYMMETRIC_H
#define GCRYPT_MLKEM_SYMMETRIC_H

#include <config.h>
#include <stddef.h>
#include <stdint.h>
#include "mlkem-params.h"


#include "g10lib.h"


void _gcry_mlkem_shake128_absorb (
    gcry_md_hd_t h,
    const unsigned char seed[GCRY_MLKEM_SYMBYTES],
    unsigned char x,
    unsigned char y);

/*************************************************
 * Name:        mlkem_shake256_prf
 *
 * Description: Usage of SHAKE256 as a PRF, concatenates secret and public
 *input and then generates outlen bytes of SHAKE256 output
 *
 * Arguments:   - unsigned char *out: pointer to output
 *              - size_t outlen: number of requested output bytes
 *              - const unsigned char *key: pointer to the key (of length GCRY_MLKEM_SYMBYTES)
 *              - unsigned char nonce: single-byte nonce (public PRF input)
 **************************************************/
gcry_err_code_t _gcry_mlkem_shake256_prf (
    uint8_t *out,
    size_t outlen,
    const uint8_t key[GCRY_MLKEM_SYMBYTES],
    uint8_t nonce);

gcry_err_code_t _gcry_mlkem_shake128_squeezeblocks (gcry_md_hd_t h,
                                                    uint8_t *out,
                                                    size_t nblocks);

gcry_err_code_t _gcry_mlkem_prf (uint8_t *out,
                                 size_t outlen,
                                 const uint8_t key[GCRY_MLKEM_SYMBYTES],
                                 uint8_t nonce);


#endif /* GCRYPT_MLKEM_SYMMETRIC_H */
