/* kem-ecc.c - Key Encapsulation Mechanism with ECC
 * Copyright (C) 2024 g10 Code GmbH
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
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"

static gpg_err_code_t
ecc_mul_point (int curveid, unsigned char *result,
               const unsigned char *scalar, const unsigned char *point)
{
  return _gcry_ecc_mul_point (curveid, result, scalar, point);
}


/* The generator of Curve25519.  */
static const unsigned char curve25519_G[32] = { 0x09 };
/* The generator of Curve448.  */
static const unsigned char curve448_G[56] = { 0x05 };

static gpg_err_code_t
ecc_gen_keypair (int curveid, void *pubkey, void *seckey)
{
  unsigned char *seckey_byte = seckey;
  unsigned int len = _gcry_ecc_get_algo_keylen (curveid);
  const unsigned char *G;

  if (curveid == GCRY_ECC_CURVE25519)
    G = curve25519_G;
  else
    G = curve448_G;

  _gcry_randomize (seckey, len, GCRY_STRONG_RANDOM);
  return ecc_mul_point (curveid, pubkey, seckey_byte, G);
}


static gpg_err_code_t
ecc_dhkem_kdf (const unsigned char *ecdh, const unsigned char *ciphertext,
               const unsigned char *pubkey, void *shared)
{
  gpg_err_code_t err;
  unsigned char *p;
  unsigned char labeled_ikm[7+5+7+32];
  unsigned char labeled_info[2+7+5+13+32+32];
  gcry_kdf_hd_t hd;
  unsigned long param[1] = { 32 }; /* output-len */

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
  memcpy (p, "HPKE-v1", 7);
  p += 7;
  memcpy (p, "KEM\x00\x20", 5); /* suite_id */
  p += 5;
  memcpy (p, "shared_secret", 13);
  p += 13;
  /* kem_context */
  memcpy (p, ciphertext, 32);
  p += 32;
  memcpy (p, pubkey, 32);
  p += 32;

  err = _gcry_kdf_open (&hd, GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param, 1,
                        labeled_ikm, sizeof (labeled_ikm),
                        NULL, 0, NULL, 0, labeled_info, sizeof (labeled_info));
  if (err)
    return err;

  err = _gcry_kdf_compute (hd, NULL);
  if (!err)
    err = _gcry_kdf_final (hd, 32, shared);
  _gcry_kdf_close (hd);
  return err;
}


gpg_err_code_t
ecc_dhkem_keypair (int algo, void *pubkey, void *seckey)
{
  int curveid;

  if (algo != GCRY_KEM_DHKEM25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for X25519.  */
  curveid = GCRY_ECC_CURVE25519;

  return ecc_gen_keypair (curveid, pubkey, seckey);
}

gpg_err_code_t
ecc_dhkem_encap (int algo, const void *pubkey, void *ciphertext,
                 void *shared)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[32];
  unsigned char seckey_ephemeral[32];
  void *pubkey_ephemeral = ciphertext;

  err = ecc_dhkem_keypair (algo, pubkey_ephemeral, seckey_ephemeral);
  if (err)
    return err;

  if (algo != GCRY_KEM_DHKEM25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for the DHKEM(X25519, HKDF-SHA256).  */
  curveid = GCRY_ECC_CURVE25519;

  /* Do ECDH.  */
  err = ecc_mul_point (curveid, ecdh, seckey_ephemeral, pubkey);
  if (err)
    return err;

  return ecc_dhkem_kdf (ecdh, ciphertext, pubkey, shared);
}

gpg_err_code_t
ecc_dhkem_decap (int algo, const void *seckey, const void *ciphertext,
                 void *shared, const void *optional)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[32];
  unsigned char pubkey_computed[32];
  const unsigned char *pubkey;

  if (algo != GCRY_KEM_DHKEM25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for the DHKEM(X25519, HKDF-SHA256).  */
  curveid = GCRY_ECC_CURVE25519;

  if (optional)
    pubkey = optional;
  else
    {
      err = ecc_mul_point (curveid, pubkey_computed, seckey, curve25519_G);
      if (err)
        return err;

      pubkey = pubkey_computed;
    }

  /* Do ECDH.  */
  err = ecc_mul_point (curveid, ecdh, seckey, ciphertext);
  if (err)
    return err;

  return ecc_dhkem_kdf (ecdh, ciphertext, pubkey, shared);
}


gpg_err_code_t
openpgp_kem_keypair (int algo, void *pubkey, void *seckey)
{
  int curveid;

  if (algo != GCRY_KEM_PGP_X25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for X25519.  */
  curveid = GCRY_ECC_CURVE25519;

  return ecc_gen_keypair (curveid, pubkey, seckey);
}

static gpg_err_code_t
openpgp_kem_kdf (const unsigned char *ecdh, size_t ecdh_len,
                 const unsigned char *kdf_param, void *shared)
{
  gpg_err_code_t err;
  gcry_kdf_hd_t hd;
  unsigned long param[1];
  int curve_oid_len;
  int hash_id;
  int kek_id;
  size_t z_len;
  size_t kdf_param_len;

  if (kdf_param == NULL)
    return GPG_ERR_INV_VALUE;

  curve_oid_len = kdf_param[0];
  hash_id = kdf_param[1+curve_oid_len+3];
  kek_id = kdf_param[1+curve_oid_len+4];
  kdf_param_len = 1+curve_oid_len+5+20+20;

  err = _gcry_cipher_algo_info (kek_id, GCRYCTL_GET_KEYLEN, NULL, &z_len);
  if (err)
    return err;

  param[0] = z_len;

  err = _gcry_kdf_open (&hd, GCRY_KDF_ONESTEP_KDF, hash_id, param, 1,
                        ecdh, ecdh_len,
                        NULL, 0, NULL, 0, kdf_param, kdf_param_len);
  if (err)
    return err;

  err = _gcry_kdf_compute (hd, NULL);
  if (!err)
    err = _gcry_kdf_final (hd, z_len, shared);
  _gcry_kdf_close (hd);

  return err;
}

/* In OpenPGP v4, 0x40 is prepended to the native encoding of public
   key.  Here, PUBKEY and CIPHERTEXT are native representation sans
   the prefix.  */
gpg_err_code_t
openpgp_kem_encap (int algo, const void *pubkey, void *ciphertext,
                   void *shared, const void *optional)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[32];
  const unsigned char *kdf_param = optional;
  unsigned char seckey_ephemeral[32];
  void *pubkey_ephemeral = ciphertext;

  err = openpgp_kem_keypair (algo, pubkey_ephemeral, seckey_ephemeral);
  if (err)
    return err;

  if (algo != GCRY_KEM_PGP_X25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for the OpenPGP KEM(Curve25519, One-Step KDF).  */
  curveid = GCRY_ECC_CURVE25519;

  /* Do ECDH.  */
  err = ecc_mul_point (curveid, ecdh, seckey_ephemeral, pubkey);
  if (err)
    return err;

  return openpgp_kem_kdf (ecdh, sizeof (ecdh), kdf_param, shared);
}

/* In OpenPGP v4, secret key is represented with big-endian MPI.
   Here, SECKEY is native fixed size little-endian representation.
   CIPHERTEXT is native representation sans the prefix 0x40.
  */
gpg_err_code_t
openpgp_kem_decap (int algo, const void *seckey, const void *ciphertext,
                   void *shared, const void *optional)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[32];
  const unsigned char *kdf_param = optional;

  if (algo != GCRY_KEM_PGP_X25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for the OpenPGP KEM(Curve25519, One-Step KDF).  */
  curveid = GCRY_ECC_CURVE25519;

  /* Do ECDH.  */
  err = ecc_mul_point (curveid, ecdh, seckey, ciphertext);
  if (err)
    return err;

  return openpgp_kem_kdf (ecdh, sizeof (ecdh), kdf_param, shared);
}
