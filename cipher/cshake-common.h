/* cshake-common.h  -  Some helpers for cSHAKE and KMAC
 * Copyright (C) 2012-2017 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
#ifndef GCRYPT_CSHAKE_COMMON_H
#define GCRYPT_CSHAKE_COMMON_H


#include <config.h>
#include "g10lib.h"
#include <stddef.h>
#include "gcrypt.h"

typedef enum
{
  left  = 1,
  right = 2
} encoded_direction_t;

size_t _gcry_cshake_bit_len_from_byte_len (size_t byte_length);


int _gcry_cshake_append_byte_to_buffer (gcry_buffer_t *buf,
                                        const unsigned char byte);

/**
 * Performs left_encode as defined in
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf.
 * Caller must ensure that sufficient capacity is left in the output buffer to
 * perform the encoding. The function appends at most one byte more (one
 * because of additional length octed) than the byte size needed to represent
 * the value of the input parameter s.
 */
size_t _gcry_cshake_left_encode (size_t s, gcry_buffer_t *output_buffer);


/**
 * Performs right_encode as defined in
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf.
 * Caller must ensure that sufficient capacity is left in the output buffer to
 * perform the encoding. The function appends at most one byte more (one
 * because of additional length octed) than the byte size needed to represent
 * the value of the input parameter s.
 */
size_t _gcry_cshake_right_encode (size_t s, gcry_buffer_t *output_buffer);



#endif
