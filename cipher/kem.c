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


static gpg_err_code_t
ecc_kem_decap (int algo, const void *seckey, const void *ciphertext,
               void *shared_secret, const void *kdf_param)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[32];
  unsigned char *p;
  unsigned char labeled_ikm[7+5+7+32];
  unsigned char labeled_info[2+7+5+13+32+32];
  gcry_kdf_hd_t hd;
  unsigned long param[1] = { 32 };

  if (algo != GCRY_KEM_DHKEM_X25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for the DHKEM(X25519, HKDF-SHA256).  */

  curveid = GCRY_ECC_CURVE25519;

  /* Do ECDH.  */
  err = _gcry_ecc_mul_point (curveid, ecdh, seckey, ciphertext);
  if (err)
    return err;

  p = labeled_ikm;
  memcpy (p, "HPKE-v1", 7);
  p += 7;
  memcpy (p, "KEM\x00\x20", 5); /* suite_id */
  p += 5;
  memcpy (p, "eae_prk", 7);
  p += 7;
  memcpy (p, ecdh, 32);

  p = labeled_info;
  memcpy (p, "\x00\x20", 2);    /* length */
  p += 2;
  memcpy (p, "HPKE-v1", 7);     /* suite_id */
  p += 7;
  memcpy (p, "KEM\x00\x20", 5); /* suite_id */
  p += 5;
  memcpy (p, "shared_secret", 13);
  p += 13;
  /* kem_context */
  memcpy (p, ciphertext, 32);
  p += 32;
  memcpy (p, kdf_param, 32);
  p += 32;

  err = _gcry_kdf_open (&hd, GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param, 1,
                        labeled_ikm, sizeof (labeled_ikm),
                        NULL, 0, NULL, 0, labeled_info, sizeof (labeled_info));
  if (err)
    return err;

  err = _gcry_kdf_compute (hd, NULL);
  if (!err)
    err = _gcry_kdf_final (hd, 32, shared_secret);
  _gcry_kdf_close (hd);

  return err;
}

gcry_err_code_t
_gcry_kem_keypair (int algo, void *pubkey, void *seckey)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      sntrup761_keypair (pubkey, seckey, NULL, _kem_random);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      mlkem_keypair (algo, pubkey, seckey);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_DHKEM_X25519:
      return GPG_ERR_NOT_IMPLEMENTED; /* Not yet.  */
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_err_code_t
_gcry_kem_encap (int algo,
                 const void *pubkey,
                 void *ciphertext,
                 void *shared_secret,
                 const void *kdf_param)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      sntrup761_enc (ciphertext, shared_secret, pubkey, NULL, _kem_random);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      return mlkem_encap (algo, ciphertext, shared_secret, pubkey);
    case GCRY_KEM_DHKEM_X25519:
      return GPG_ERR_NOT_IMPLEMENTED; /* Not yet.  */
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_err_code_t
_gcry_kem_decap (int algo,
                 const void *seckey,
                 const void *ciphertext,
                 void *shared_secret,
                 const void *kdf_param)
{
  switch (algo)
    {
    case GCRY_KEM_SNTRUP761:
      sntrup761_dec (shared_secret, ciphertext, seckey);
      return GPG_ERR_NO_ERROR;
    case GCRY_KEM_MLKEM512:
    case GCRY_KEM_MLKEM768:
    case GCRY_KEM_MLKEM1024:
      return mlkem_decap (algo, shared_secret, ciphertext, seckey);
    case GCRY_KEM_DHKEM_X25519:
      return ecc_kem_decap (algo, seckey, ciphertext, shared_secret, kdf_param);
    default:
      return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}
