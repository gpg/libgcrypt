/* cshake-common.c  -  Some helpers for cSHAKE and KMAC
 * Copyright (C) 2023 MTG AG
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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

#include "cshake-common.h"



/**
 * @brief Append data to a buffer
 *
 * @param buf the buffer to append data to
 * @param data data to append
 * @param len length of the data
 *
 * @return 0 on success, 1 if the buffer is overfilled
 */
int
_gcry_cshake_append_to_buffer (gcry_buffer_t *buf,
                               const unsigned char *data,
                               size_t len)
{
  if (buf->size - buf->len < len)
    {
      return 1;
    }
  memcpy (((unsigned char*) buf->data) + buf->len, data, len);
  buf->len += len;
  return 0;
}

static int
append_byte_to_buffer (gcry_buffer_t *buf, const unsigned char b)
{
  return _gcry_cshake_append_to_buffer (buf, &b, 1);
}

/**
 * Performs left_encode or right_encode as defined in
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf.
 * Caller must ensure that sufficient capacity is left in the output buffer.
 * The function appends at most one byte more (one because of additional length
 * octed) than the byte size
 * needed to represent the value of the input parameter s.
 */
static size_t
left_or_right_encode (size_t s,
                      gcry_buffer_t *output_buffer,
                      encoded_direction_t dir)
{
  int i;
  size_t bytes_appended = 0;
  // determine number of octets needed to encode s
  for (i = sizeof (s); i > 0; i--)
    {
      unsigned char t = (s >> ((i - 1) * 8) & (size_t)0xFF);
      if (t != 0)
        {
          break;
        }
    }
  if (i == 0)
    {
      i = 1;
    }
  if (dir == left)
    {
      if (append_byte_to_buffer (output_buffer, i))
        {
          /* error */
          return 0;
        }
      bytes_appended++;
    }
  // big endian encoding of s
  for (int j = i; j > 0; j--)
    {
      if (append_byte_to_buffer (output_buffer,
                                 s >> (j - 1) * 8 & ((size_t)0xFF)))
        {
          /* error */
          return 0;
        }
      bytes_appended++;
    }
  if (dir == right)
    {
      if (append_byte_to_buffer (output_buffer, (unsigned char)i))
        {
          /* error */
          return 0;
        }
      bytes_appended++;
    }
  return bytes_appended;
}

size_t
_gcry_cshake_left_encode (size_t s,
                          gcry_buffer_t *output_buffer)
{
  return left_or_right_encode (s, output_buffer, left);
}

size_t
_gcry_cshake_right_encode (size_t s,
                           gcry_buffer_t *output_buffer)
{
  size_t result = left_or_right_encode (s, output_buffer, right);
  return result;
}

/**
 * Convert byte length to bit length. Returns zero on overflow, i.e.
 * precondition that bit length fits into size_t has to be checked by the
 * caller.
 */
size_t
_gcry_cshake_bit_len_from_byte_len (size_t byte_length)
{
  size_t bit_length = 8 * byte_length;
  if (bit_length < byte_length)
    {
      return 0;
    }
  return bit_length;
}
