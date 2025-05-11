/* dilithium.h - the Dilithium (header)
 * Copyright (C) 2025 g10 Code GmbH
 *
 * This file was modified for use by Libgcrypt.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * You can also use this file under the same licence of original code.
 * SPDX-License-Identifier: CC0 OR Apache-2.0
 *
 */
/*
  Original code from:

  Repository: https://github.com/pq-crystals/dilithium.git
  Branch: master
  Commit: 444cdcc84eb36b66fe27b3a2529ee48f6d8150c2

  Licence:
  Public Domain (https://creativecommons.org/share-your-work/public-domain/cc0/);
  or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).

  Authors:
        Léo Ducas
        Eike Kiltz
        Tancrède Lepoint
        Vadim Lyubashevsky
        Gregor Seiler
        Peter Schwabe
        Damien Stehlé

  Dilithium Home: https://github.com/pq-crystals/dilithium.git
 */
/* Standalone use is possible either with DILITHIUM_MODE defined with
 * the value (2, 3, or 5), or not defined.  For the latter, routines
 * for three variants are available.
 */
#ifndef DILITHIUM_H
#define DILITHIUM_H

#define SEEDBYTES 32
#define RNDBYTES 32

#if defined(DILITHIUM_MODE)
# if DILITHIUM_MODE == 2
# define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + 4*320)
# define CRYPTO_SECRETKEYBYTES (2*SEEDBYTES \
                                + 64 \
                                + 4*96 \
                                + 4*96 \
                                + 4*416)
# define CRYPTO_BYTES (32 + L*576 + 80 + 4)
# elif DILITHIUM_MODE == 3
# define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + 6*320)
# define CRYPTO_SECRETKEYBYTES (2*SEEDBYTES \
                                + 64 \
                                + 5*128 \
                                + 6*128 \
                                + 6*416)
# define CRYPTO_BYTES (48 + 5*640 + 55 + 6)
# elif DILITHIUM_MODE == 5
# define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + 8*320)
# define CRYPTO_SECRETKEYBYTES (2*SEEDBYTES \
                                + 64 \
                                + 7*96 \
                                + 8*96 \
                                + 8*416)
# define CRYPTO_BYTES (64 + 7*640 + 75 + 8)
# else
# error "DILITHIUM_MODE should be either 2, 3 or 5"
# endif
#else
# define CRYPTO_PUBLICKEYBYTES_2 (SEEDBYTES + 4*320)
# define CRYPTO_SECRETKEYBYTES_2 (2*SEEDBYTES \
                                  + 64 \
                                  + 4*96 \
                                  + 4*96 \
                                  + 4*416)
# define CRYPTO_BYTES_2 (32 + L*576 + 80 + 4)

# define CRYPTO_PUBLICKEYBYTES_3 (SEEDBYTES + 6*320)
# define CRYPTO_SECRETKEYBYTES_3 (2*SEEDBYTES \
                                  + 64 \
                                  + 5*128 \
                                  + 6*128 \
                                  + 6*416)
# define CRYPTO_BYTES_3 (48 + 5*640 + 55 + 6)

# define CRYPTO_PUBLICKEYBYTES_5 (SEEDBYTES + 8*320)
# define CRYPTO_SECRETKEYBYTES_5 (2*SEEDBYTES \
                                  + 64 \
                                  + 7*96 \
                                  + 8*96 \
                                  + 8*416)
# define CRYPTO_BYTES_5 (64 + 7*640 + 75 + 8)
#endif

#endif
