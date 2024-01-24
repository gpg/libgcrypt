/* kem.c  - Key Encapsulation Mechanisms
 * Copyright (C) 2023 Simon Josefsson <simon@josefsson.org>
 * Copyright (C) 2023 g10 Code GmbH
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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "sntrup761.h"
#include "kyber.h"
#include "kem-ecc.h"

static void
sntrup761_random (void *ctx, size_t length, uint8_t *dst)
{
  (void)ctx;

  _gcry_randomize (dst, length, GCRY_STRONG_RANDOM);
}

gcry_err_code_t
_gcry_kem_keypair (int algo,
                   void *pubkey, size_t pubkey_len,
                   void *seckey, size_t seckey_len)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      (void)pubkey; (void)seckey;
      if (seckey_len != GCRY_KEM_SNTRUP761_SECKEY_LEN
          || pubkey_len != GCRY_KEM_SNTRUP761_PUBKEY_LEN)
        return GPG_ERR_INV_ARG;
      sntrup761_keypair (pubkey, seckey, NULL, sntrup761_random);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      kyber_keypair (algo, pubkey, seckey);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_RAW_X25519:
    case GCRY_KEM_DHKEM25519:
    case GCRY_KEM_PGP_X25519:
    case GCRY_KEM_CMS_X25519_X963_SHA256:
    case GCRY_KEM_CMS_X25519_HKDF_SHA256:
      return _gcry_ecc_raw_keypair (GCRY_ECC_CURVE25519, pubkey, seckey);
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_err_code_t
_gcry_kem_encap (int algo,
                 const void *pubkey, size_t pubkey_len,
                 void *ciphertext, size_t ciphertext_len,
                 void *shared, size_t shared_len,
                 const void *optional, size_t optional_len)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      (void)pubkey; (void)ciphertext; (void)shared;
      if (optional != NULL || optional_len != 0)
        return GPG_ERR_INV_VALUE;
      if (pubkey_len != GCRY_KEM_SNTRUP761_PUBKEY_LEN
          || ciphertext_len != GCRY_KEM_SNTRUP761_ENCAPS_LEN
          || shared_len != GCRY_KEM_SNTRUP761_SHARED_LEN)
        return GPG_ERR_INV_VALUE;
      sntrup761_enc (ciphertext, shared, pubkey, NULL, sntrup761_random);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      if (optional != NULL)
        return GPG_ERR_INV_VALUE;
      kyber_encap (algo, ciphertext, shared, pubkey);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_RAW_X25519:
      if (optional != NULL)
        return GPG_ERR_INV_VALUE;
      return _gcry_ecc_raw_encap (GCRY_ECC_CURVE25519, pubkey, ciphertext,
                                  shared);
    case GCRY_KEM_DHKEM25519:
      if (optional != NULL)
        return GPG_ERR_INV_VALUE;
      return _gcry_ecc_dhkem_encap (algo, pubkey, ciphertext, shared);
    case GCRY_KEM_PGP_X25519:
      return _gcry_openpgp_kem_encap (algo, pubkey, ciphertext, shared,
                                      optional);
    case GCRY_KEM_CMS_X25519_X963_SHA256:
    case GCRY_KEM_CMS_X25519_HKDF_SHA256:
      return _gcry_cms_kem_encap (algo, pubkey, ciphertext, shared,
                                  optional);
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_err_code_t
_gcry_kem_decap (int algo,
                 const void *seckey, size_t seckey_len,
                 const void *ciphertext, size_t ciphertext_len,
                 void *shared, size_t shared_len,
                 const void *optional, size_t optional_len)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      (void)seckey; (void)ciphertext; (void)shared;
      if (optional != NULL || optional_len != 0)
        return GPG_ERR_INV_VALUE;
      if (seckey_len != GCRY_KEM_SNTRUP761_SECKEY_LEN
          || ciphertext_len != GCRY_KEM_SNTRUP761_ENCAPS_LEN
          || shared_len != GCRY_KEM_SNTRUP761_SHARED_LEN)
        return GPG_ERR_INV_VALUE;
      sntrup761_dec (shared, ciphertext, seckey);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      if (optional != NULL)
        return GPG_ERR_INV_VALUE;
      kyber_decap (algo, shared, ciphertext, seckey);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_RAW_X25519:
      if (optional != NULL)
        return GPG_ERR_INV_VALUE;
      return _gcry_ecc_raw_decap (GCRY_ECC_CURVE25519, seckey, ciphertext,
                                  shared);
    case GCRY_KEM_DHKEM25519:
      return _gcry_ecc_dhkem_decap (algo, seckey, ciphertext, shared,
                                    optional);
    case GCRY_KEM_PGP_X25519:
      return _gcry_openpgp_kem_decap (algo, seckey, ciphertext, shared,
                                      optional);
    case GCRY_KEM_CMS_X25519_X963_SHA256:
    case GCRY_KEM_CMS_X25519_HKDF_SHA256:
      return _gcry_cms_kem_decap (algo, seckey, ciphertext, shared,
                                  optional);
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}
