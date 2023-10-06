/* mlkem-params.h - parameter definitions for ML-KEM
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

#ifndef GCRYPT_MLKEM_PARAMS_H
#define GCRYPT_MLKEM_PARAMS_H

#include <stdint.h>

typedef enum
{
  GCRY_MLKEM_512,
  GCRY_MLKEM_768,
  GCRY_MLKEM_1024
} gcry_mlkem_param_id;

typedef struct
{
  gcry_mlkem_param_id id;
  uint8_t k;
  uint8_t eta1;
  uint16_t polyvec_bytes;
  uint8_t poly_compressed_bytes;
  uint16_t polyvec_compressed_bytes;
  uint16_t public_key_bytes;
  uint16_t indcpa_secret_key_bytes;
  uint16_t secret_key_bytes;
  uint16_t ciphertext_bytes;

} gcry_mlkem_param_t;


#define GCRY_MLKEM_N 256
#define GCRY_MLKEM_Q 3329

#define GCRY_MLKEM_SYMBYTES 32 /* size in bytes of hashes, and seeds */
#define GCRY_MLKEM_SSBYTES 32  /* size in bytes of shared key */

#define GCRY_MLKEM_POLYBYTES 384
#define GCRY_MLKEM_POLYVECBYTES (MLKEM_K * GCRY_MLKEM_POLYBYTES)


#define GCRY_MLKEM_ETA1_MAX 3
#define GCRY_MLKEM_ETA2 2

#define GCRY_MLKEM_INDCPA_MSGBYTES (GCRY_MLKEM_SYMBYTES)
#if (GCRY_MLKEM_INDCPA_MSGBYTES != GCRY_MLKEM_N / 8)
#error "GCRY_MLKEM_INDCPA_MSGBYTES must be equal to GCRY_MLKEM_N/8 bytes!"
#endif


#define GCRY_MLKEM_COINS_SIZE (2 * GCRY_MLKEM_SYMBYTES)


#define GCRY_SHAKE128_RATE 168
#define GCRY_SHAKE256_RATE 136
#define GCRY_SHA3_256_RATE 136
#define GCRY_SHA3_512_RATE 72


#define GCRY_MLKEM_XOF_BLOCKBYTES GCRY_SHAKE128_RATE

#endif /* GCRYPT_MLKEM_PARAMS_H */
