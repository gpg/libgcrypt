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

#include <config.h>
#include <stdint.h>
#include "mlkem-params.h"
#include "mlkem-poly.h"
#include "g10lib.h"
#include "mlkem-aux.h"

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
