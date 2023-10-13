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

#include <stdint.h>
#include "mlkem-params.h"

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
