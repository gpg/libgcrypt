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
#define TRBYTES 64
#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416

#if defined(DILITHIUM_MODE)
# if DILITHIUM_MODE == 2
# define K 4
# define L 4
# define CTILDEBYTES 32
# define POLYETA_PACKEDBYTES  96
# define POLYZ_PACKEDBYTES   576
# define OMEGA 80
# elif DILITHIUM_MODE == 3
# define K 6
# define L 5
# define POLYETA_PACKEDBYTES 128
# define CTILDEBYTES 48
# define POLYZ_PACKEDBYTES   640
# define OMEGA 55
# elif DILITHIUM_MODE == 5
# define K 8
# define L 7
# define CTILDEBYTES 64
# define POLYETA_PACKEDBYTES  96
# define POLYZ_PACKEDBYTES   640
# define OMEGA 75
# else
# error "DILITHIUM_MODE should be either 2, 3 or 5"
# endif
# define POLYVECH_PACKEDBYTES (OMEGA + K)
# define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES)
# define CRYPTO_SECRETKEYBYTES (2*SEEDBYTES \
                                + TRBYTES \
                                + L*POLYETA_PACKEDBYTES \
                                + K*POLYETA_PACKEDBYTES \
                                + K*POLYT0_PACKEDBYTES)
# define CRYPTO_BYTES (CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)
#else
/* TBD */
#endif

#endif
