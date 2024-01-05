/* mlkem-aux.h - Auxiliary functions for ML-KEM
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

#ifndef GCRYPT_MLKEM_AUX_H
#define GCRYPT_MLKEM_AUX_H

int16_t _gcry_mlkem_montgomery_reduce (int32_t a);

int16_t _gcry_mlkem_barrett_reduce (int16_t a);

#endif /* GCRYPT_MLKEM_AUX_H */

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

/* mlkem-common.h - general functions for ML-KEM
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

#ifndef GCRYPT_MLKEM_COMMON_H
#define GCRYPT_MLKEM_COMMON_H


gcry_err_code_t _gcry_mlkem_kem_keypair_derand (uint8_t *pk,
                                                uint8_t *sk,
                                                const gcry_mlkem_param_t *param,
                                                uint8_t *coins);


gcry_err_code_t mlkem_keypair (int algo, uint8_t *pk, uint8_t *sk);


gcry_err_code_t _gcry_mlkem_kem_enc_derand (uint8_t *ct,
                                            uint8_t *ss,
                                            const uint8_t *pk,
                                            const gcry_mlkem_param_t *param,
                                            uint8_t *coins);

gcry_err_code_t mlkem_encap (int algo, uint8_t *ct, uint8_t *ss,
                             const uint8_t *pk);

gcry_err_code_t mlkem_decap (int algo, uint8_t *ss, const uint8_t *ct,
                             const uint8_t *sk);

#endif /* GCRYPT_MLKEM_COMMON_H */

/* mlkem-ntt.h - number-theoretic transform functions for ML-KEM
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

#ifndef GCRYPT_MLKEM_NTT_H
#define GCRYPT_MLKEM_NTT_H

void _gcry_mlkem_ntt (int16_t poly[256]);

void _gcry_mlkem_invntt (int16_t poly[256]);

void _gcry_mlkem_basemul (
    int16_t r[2], const int16_t a[2], const int16_t b[2], int zeta, int sign);

#endif /* GCRYPT_MLKEM_NTT_H */

/* mlkem-poly.h - functions related to polynomials for ML-KEM
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

#ifndef GCRYPT_MLKEM_POLY_H
#define GCRYPT_MLKEM_POLY_H

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct
{
  int16_t coeffs[GCRY_MLKEM_N];
} gcry_mlkem_poly;


void _gcry_mlkem_poly_compress (unsigned char *r,
                                const gcry_mlkem_poly *a,
                                gcry_mlkem_param_t const *param);

void _gcry_mlkem_poly_decompress (gcry_mlkem_poly *r,
                                  const unsigned char *a,
                                  gcry_mlkem_param_t const *param);


void _gcry_mlkem_poly_tobytes (unsigned char r[GCRY_MLKEM_POLYBYTES],
                               const gcry_mlkem_poly *a);

void _gcry_mlkem_poly_frombytes (gcry_mlkem_poly *r,
                                 const unsigned char a[GCRY_MLKEM_POLYBYTES]);


void _gcry_mlkem_poly_frommsg (
    gcry_mlkem_poly *r, const unsigned char msg[GCRY_MLKEM_INDCPA_MSGBYTES]);

void _gcry_mlkem_poly_tomsg (unsigned char msg[GCRY_MLKEM_INDCPA_MSGBYTES],
                             const gcry_mlkem_poly *r);


void _gcry_mlkem_poly_getnoise_eta1 (
    gcry_mlkem_poly *r,
    const unsigned char seed[GCRY_MLKEM_SYMBYTES],
    unsigned char nonce,
    gcry_mlkem_param_t const *param);


void _gcry_mlkem_poly_getnoise_eta2 (
    gcry_mlkem_poly *r,
    const unsigned char seed[GCRY_MLKEM_SYMBYTES],
    unsigned char nonce);


void _gcry_mlkem_poly_ntt (gcry_mlkem_poly *r);

void _gcry_mlkem_poly_invntt_tomont (gcry_mlkem_poly *r);

void _gcry_mlkem_poly_basemul_montgomery (gcry_mlkem_poly *r,
                                          const gcry_mlkem_poly *a,
                                          const gcry_mlkem_poly *b);

void _gcry_mlkem_poly_tomont (gcry_mlkem_poly *r);


void _gcry_mlkem_poly_reduce (gcry_mlkem_poly *r);


void _gcry_mlkem_poly_add (gcry_mlkem_poly *r,
                           const gcry_mlkem_poly *a,
                           const gcry_mlkem_poly *b);

void _gcry_mlkem_poly_sub (gcry_mlkem_poly *r,
                           const gcry_mlkem_poly *a,
                           const gcry_mlkem_poly *b);

#endif /* GCRYPT_MLKEM_POLY_H */

/* mlkem-polyvec.h - functions related to vectors of polynomials for ML-KEM
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

#ifndef GCRYPT_MLKEM_POLYVEC_H
#define GCRYPT_MLKEM_POLYVEC_H

typedef struct
{
  gcry_mlkem_poly *vec;
} gcry_mlkem_polyvec;


gcry_error_t _gcry_mlkem_polymatrix_create (gcry_mlkem_polyvec **polymat,
                                            gcry_mlkem_param_t const *param);

void _gcry_mlkem_polymatrix_destroy (gcry_mlkem_polyvec **polymat,
                                     gcry_mlkem_param_t const *param);

gcry_error_t _gcry_mlkem_polyvec_create (gcry_mlkem_polyvec *polyvec,
                                         gcry_mlkem_param_t const *param);

void _gcry_mlkem_polyvec_destroy (gcry_mlkem_polyvec *polyvec);

void _gcry_mlkem_polyvec_compress (uint8_t *r,
                                   const gcry_mlkem_polyvec *a,
                                   gcry_mlkem_param_t const *param);

void _gcry_mlkem_polyvec_decompress (gcry_mlkem_polyvec *r,
                                     const uint8_t *a,
                                     gcry_mlkem_param_t const *param);

void _gcry_mlkem_polyvec_tobytes (uint8_t *r,
                                  const gcry_mlkem_polyvec *a,
                                  gcry_mlkem_param_t const *param);

void _gcry_mlkem_polyvec_frombytes (gcry_mlkem_polyvec *r,
                                    const uint8_t *a,
                                    gcry_mlkem_param_t const *param);

void _gcry_mlkem_polyvec_ntt (gcry_mlkem_polyvec *r,
                              gcry_mlkem_param_t const *param);

void _gcry_mlkem_polyvec_invntt_tomont (gcry_mlkem_polyvec *r,
                                        gcry_mlkem_param_t const *param);

gcry_err_code_t _gcry_mlkem_polyvec_basemul_acc_montgomery (
    gcry_mlkem_poly *r,
    const gcry_mlkem_polyvec *a,
    const gcry_mlkem_polyvec *b,
    gcry_mlkem_param_t const *param);

void _gcry_mlkem_polyvec_reduce (gcry_mlkem_polyvec *r,
                                 gcry_mlkem_param_t const *param);

void _gcry_mlkem_polyvec_add (gcry_mlkem_polyvec *r,
                              const gcry_mlkem_polyvec *a,
                              const gcry_mlkem_polyvec *b,
                              gcry_mlkem_param_t const *param);

#endif /* GCRYPT_MLKEM_POLYVEC_H */

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

/* mlkem-cbd.h - centered binomial distribution functions for ML-KEM
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

#ifndef GCRYPT_MLKEM_CBD_H
#define GCRYPT_MLKEM_CBD_H

/**
 * buf has length MLKEM_ETA1*GCRY_MLKEM_N/4
 */
void _gcry_mlkem_poly_cbd_eta1 (gcry_mlkem_poly *r,
                                const uint8_t *buf,
                                gcry_mlkem_param_t const *param);

void _gcry_mlkem_poly_cbd_eta2 (
    gcry_mlkem_poly *r, const uint8_t buf[GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 4]);

#endif /* GCRYPT_MLKEM_CBD_H */
