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

#include <stdint.h>
#include "mlkem-params.h"


void _gcry_mlkem_ntt (int16_t poly[256]);

void _gcry_mlkem_invntt (int16_t poly[256]);

void _gcry_mlkem_basemul (
    int16_t r[2], const int16_t a[2], const int16_t b[2], int zeta, int sign);

#endif /* GCRYPT_MLKEM_NTT_H */
