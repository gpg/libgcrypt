/* kem.c  - Key Encapsulation Methods
 * Copyright (C) 2023 Simon Josefsson <simon@josefsson.org>
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"

#include "sntrup761.h"
#include "mlkem-common.h"

static void
_kem_random (void *ctx, size_t length, uint8_t * dst)
{
  (void) ctx;

  _gcry_randomize (dst, length, GCRY_STRONG_RANDOM);
}

gcry_err_code_t
_gcry_kem_keypair (int algo, const void *context, void *pubkey, void *seckey)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      if (context != NULL)
        return GPG_ERR_INV_VALUE;
      sntrup761_keypair (pubkey, seckey, NULL, _kem_random);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      if (context != NULL)
        return GPG_ERR_INV_VALUE;
      mlkem_keypair (algo, pubkey, seckey);
      return GPG_ERR_NO_ERROR;
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_err_code_t
_gcry_kem_encap (int algo, const void *context,
                 const void *pubkey,
                 void *ciphertext,
                 void *shared_secret)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      if (context != NULL)
        return GPG_ERR_INV_VALUE;
      sntrup761_enc (ciphertext, shared_secret, pubkey, NULL, _kem_random);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      if (context != NULL)
        return GPG_ERR_INV_VALUE;
      return mlkem_encap (algo, ciphertext, shared_secret, pubkey);
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_err_code_t
_gcry_kem_decap (int algo, const void *context,
                 const void *seckey,
                 const void *ciphertext,
                 void *shared_secret)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      if (context != NULL)
        return GPG_ERR_INV_VALUE;
      sntrup761_dec (shared_secret, ciphertext, seckey);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      if (context != NULL)
        return GPG_ERR_INV_VALUE;
      return mlkem_decap (algo, shared_secret, ciphertext, seckey);
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}
