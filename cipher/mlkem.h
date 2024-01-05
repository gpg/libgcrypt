/* mlkem.h - ML-KEM functions
 * Copyright (C) 2023 MTG AG
 * The code was created based on the reference implementation that is
 * part of the ML-KEM NIST submission.
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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef MLKEM_H
#define MLKEM_H

gcry_err_code_t _gcry_mlkem_keypair (int algo, uint8_t *pk, uint8_t *sk);


gcry_err_code_t _gcry_mlkem_encap (int algo, uint8_t *ct, uint8_t *ss,
                                   const uint8_t *pk);

gcry_err_code_t _gcry_mlkem_decap (int algo, uint8_t *ss, const uint8_t *ct,
                                   const uint8_t *sk);

#endif /* MLKEM_H */
