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

#include "kem-ecc.h"

#define ECC_PUBKEY_LEN_MAX 133
#define ECC_SECKEY_LEN_MAX 64

static const char *
algo_to_curve (int algo)
{
  switch (algo)
    {
    case GCRY_KEM_RAW_X25519:
    case GCRY_KEM_DHKEM25519:
    case GCRY_KEM_OPENPGP_X25519:
    case GCRY_KEM_CMS_X25519_X963_SHA256:
    case GCRY_KEM_CMS_X25519_HKDF_SHA256:
      return "Curve25519";

    case GCRY_KEM_RAW_X448:
    case GCRY_KEM_DHKEM448:
      return "X448";

    case GCRY_KEM_RAW_BP256:
      return "bp256";

    case GCRY_KEM_RAW_BP384:
      return "bp384";

    case GCRY_KEM_RAW_BP512:
      return "bp512";

    default:
      return 0;
    }
}


static int
algo_to_seckey_len (int algo)
{
  switch (algo)
    {
    case GCRY_KEM_RAW_X25519:
    case GCRY_KEM_DHKEM25519:
    case GCRY_KEM_OPENPGP_X25519:
    case GCRY_KEM_CMS_X25519_X963_SHA256:
    case GCRY_KEM_CMS_X25519_HKDF_SHA256:
      return 32;

    case GCRY_KEM_RAW_X448:
    case GCRY_KEM_DHKEM448:
      return 56;

    case GCRY_KEM_RAW_BP256:
      return 32;

    case GCRY_KEM_RAW_BP384:
      return 48;

    case GCRY_KEM_RAW_BP512:
      return 64;

    default:
      return 0;
    }
}


static gpg_err_code_t
ecc_mul_point (int algo, unsigned char *result, size_t result_len,
               const unsigned char *scalar, size_t scalar_len,
               const unsigned char *point, size_t point_len)
{
  const char *curve = algo_to_curve (algo);

  return _gcry_ecc_curve_mul_point (curve, result, result_len,
                                    scalar, scalar_len, point, point_len);
}


gpg_err_code_t
_gcry_ecc_raw_keypair (int algo, void *pubkey, size_t pubkey_len,
                       void *seckey, size_t seckey_len)
{
  const char *curve = algo_to_curve (algo);

  return _gcry_ecc_curve_keypair (curve,
                                  pubkey, pubkey_len, seckey, seckey_len);
}

gpg_err_code_t
_gcry_ecc_raw_encap (int algo, const void *pubkey, size_t pubkey_len,
                     void *ciphertext, size_t ciphertext_len,
                     void *shared, size_t shared_len)
{
  gpg_err_code_t err;
  unsigned char seckey_ephemeral[ECC_SECKEY_LEN_MAX];
  void *pubkey_ephemeral = ciphertext;
  size_t seckey_len;

  if (ciphertext_len != pubkey_len)
    return GPG_ERR_INV_VALUE;

  seckey_len = algo_to_seckey_len (algo);
  err = _gcry_ecc_raw_keypair (algo, pubkey_ephemeral, pubkey_len,
                               seckey_ephemeral, seckey_len);
  if (err)
    return err;

  /* Do ECDH.  */
  return ecc_mul_point (algo, shared, shared_len, seckey_ephemeral, seckey_len,
                        pubkey, pubkey_len);
}

gpg_err_code_t
_gcry_ecc_raw_decap (int algo, const void *seckey, size_t seckey_len,
                     const void *ciphertext, size_t ciphertext_len,
                     void *shared, size_t shared_len)
{
  /* Do ECDH.  */
  return ecc_mul_point (algo, shared, shared_len, seckey, seckey_len,
                        ciphertext, ciphertext_len);
}


enum
  {
    DHKEM_X25519_HKDF_SHA256 = 0x20, /* Defined in RFC 9180.  */
    DHKEM_X448_HKDF_SHA512   = 0x21
  };

static gpg_err_code_t
ecc_dhkem_kdf (int kem_algo, size_t ecc_len,
               const unsigned char *ecdh, const unsigned char *ciphertext,
               const unsigned char *pubkey, void *shared)
{
  gpg_err_code_t err;
  unsigned char *p;
  unsigned char labeled_ikm[7+5+7+ECC_PUBKEY_LEN_MAX];
  int labeled_ikm_size;
  unsigned char labeled_info[2+7+5+13+2*ECC_PUBKEY_LEN_MAX];
  int labeled_info_size;
  gcry_kdf_hd_t hd;
  unsigned long param[1];
  int macalgo;
  int mac_len;

  if (kem_algo == DHKEM_X25519_HKDF_SHA256)
    macalgo = GCRY_MAC_HMAC_SHA256;
  else if (kem_algo == DHKEM_X448_HKDF_SHA512)
    macalgo = GCRY_MAC_HMAC_SHA512;
  else
    return GPG_ERR_UNKNOWN_ALGORITHM;

  mac_len = _gcry_mac_get_algo_maclen (macalgo);
  param[0] = mac_len;
  labeled_ikm_size = 7+5+7+ecc_len;
  labeled_info_size = 2+7+5+13+ecc_len*2;

  p = labeled_ikm;
  memcpy (p, "HPKE-v1", 7);
  p += 7;
  memcpy (p, "KEM", 3);
  p[3] = 0;
  p[4] = kem_algo;
  p += 5;
  memcpy (p, "eae_prk", 7);
  p += 7;
  memcpy (p, ecdh, ecc_len);

  p = labeled_info;
  /* length */
  p[0] = 0;
  p[1] = mac_len;
  p += 2;
  memcpy (p, "HPKE-v1", 7);
  p += 7;
  memcpy (p, "KEM", 3);
  p[3] = 0;
  p[4] = kem_algo;
  p += 5;
  memcpy (p, "shared_secret", 13);
  p += 13;
  /* kem_context */
  memcpy (p, ciphertext, ecc_len);
  p += ecc_len;
  memcpy (p, pubkey, ecc_len);
  p += ecc_len;

  err = _gcry_kdf_open (&hd, GCRY_KDF_HKDF, macalgo, param, 1,
                        labeled_ikm, labeled_ikm_size,
                        NULL, 0, NULL, 0, labeled_info, labeled_info_size);
  if (err)
    return err;

  err = _gcry_kdf_compute (hd, NULL);
  if (!err)
    err = _gcry_kdf_final (hd, mac_len, shared);
  _gcry_kdf_close (hd);
  return err;
}


gpg_err_code_t
_gcry_ecc_dhkem_encap (int algo, const void *pubkey, void *ciphertext,
                       void *shared)
{
  gpg_err_code_t err;
  unsigned char ecdh[ECC_PUBKEY_LEN_MAX];
  unsigned char seckey_ephemeral[ECC_SECKEY_LEN_MAX];
  void *pubkey_ephemeral = ciphertext;
  int curveid;
  int kem_algo;
  size_t ecc_len;

  if (algo == GCRY_KEM_DHKEM25519)
    {
      curveid = GCRY_ECC_CURVE25519;
      kem_algo = DHKEM_X25519_HKDF_SHA256;
    }
  else if (algo == GCRY_KEM_DHKEM448)
    {
      curveid = GCRY_ECC_CURVE448;
      kem_algo = DHKEM_X448_HKDF_SHA512;
    }
  else
    return GPG_ERR_UNKNOWN_ALGORITHM;

  ecc_len = _gcry_ecc_get_algo_keylen (curveid);

  err = _gcry_ecc_raw_keypair (algo, pubkey_ephemeral, ecc_len,
                               seckey_ephemeral, ecc_len);
  if (err)
    return err;

  /* Do ECDH.  */
  err = ecc_mul_point (algo, ecdh, ecc_len, seckey_ephemeral, ecc_len,
                       pubkey, ecc_len);
  if (err)
    return err;

  return ecc_dhkem_kdf (kem_algo, ecc_len, ecdh, ciphertext, pubkey, shared);
}

gpg_err_code_t
_gcry_ecc_dhkem_decap (int algo, const void *seckey, const void *ciphertext,
                       void *shared, const void *optional)
{
  gpg_err_code_t err;
  unsigned char ecdh[ECC_PUBKEY_LEN_MAX];
  unsigned char pubkey_computed[ECC_PUBKEY_LEN_MAX];
  const unsigned char *pubkey;
  int curveid;
  int kem_algo;
  size_t ecc_len;

  if (algo == GCRY_KEM_DHKEM25519)
    {
      curveid = GCRY_ECC_CURVE25519;
      kem_algo = DHKEM_X25519_HKDF_SHA256;
    }
  else if (algo == GCRY_KEM_DHKEM448)
    {
      curveid = GCRY_ECC_CURVE448;
      kem_algo = DHKEM_X448_HKDF_SHA512;
    }
  else
    return GPG_ERR_UNKNOWN_ALGORITHM;

  ecc_len = _gcry_ecc_get_algo_keylen (curveid);

  if (optional)
    pubkey = optional;
  else
    {
      err = ecc_mul_point (algo, pubkey_computed, ecc_len, seckey, ecc_len,
                           NULL, ecc_len);
      if (err)
        return err;

      pubkey = pubkey_computed;
    }

  /* Do ECDH.  */
  err = ecc_mul_point (algo, ecdh, ecc_len, seckey, ecc_len,
                       ciphertext, ecc_len);
  if (err)
    return err;

  return ecc_dhkem_kdf (kem_algo, ecc_len, ecdh, ciphertext, pubkey, shared);
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
_gcry_openpgp_kem_encap (int algo, const void *pubkey, void *ciphertext,
                         void *shared, const void *optional)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[ECC_PUBKEY_LEN_MAX];
  const unsigned char *kdf_param = optional;
  unsigned char seckey_ephemeral[ECC_SECKEY_LEN_MAX];
  void *pubkey_ephemeral = ciphertext;
  size_t ecc_len;

  if (algo != GCRY_KEM_OPENPGP_X25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for the OpenPGP KEM(Curve25519, One-Step KDF).  */
  curveid = GCRY_ECC_CURVE25519;

  ecc_len = _gcry_ecc_get_algo_keylen (curveid);
  err = _gcry_ecc_raw_keypair (algo, pubkey_ephemeral, ecc_len,
                               seckey_ephemeral, ecc_len);
  if (err)
    return err;

  /* Do ECDH.  */
  err = ecc_mul_point (algo, ecdh, ecc_len, seckey_ephemeral, ecc_len,
                       pubkey, ecc_len);
  if (err)
    return err;

  return openpgp_kem_kdf (ecdh, ecc_len, kdf_param, shared);
}

/* In OpenPGP v4, secret key is represented with big-endian MPI.
   Here, SECKEY is native fixed size little-endian representation.
   CIPHERTEXT is native representation sans the prefix 0x40.
  */
gpg_err_code_t
_gcry_openpgp_kem_decap (int algo, const void *seckey, const void *ciphertext,
                         void *shared, const void *optional)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[ECC_PUBKEY_LEN_MAX];
  const unsigned char *kdf_param = optional;
  size_t ecc_len;

  if (algo != GCRY_KEM_OPENPGP_X25519)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  /* From here, it's only for the OpenPGP KEM(Curve25519, One-Step KDF).  */
  curveid = GCRY_ECC_CURVE25519;

  ecc_len = _gcry_ecc_get_algo_keylen (curveid);

  /* Do ECDH.  */
  err = ecc_mul_point (algo, ecdh, ecc_len, seckey, ecc_len,
                       ciphertext, ecc_len);
  if (err)
    return err;

  return openpgp_kem_kdf (ecdh, ecc_len, kdf_param, shared);
}


static gpg_err_code_t
cms_kem_kdf (int kdf_id, int hash_id,
             const unsigned char *ecdh, size_t ecdh_len,
             const unsigned char *sharedinfo, void *shared)
{
  gpg_err_code_t err;
  gcry_kdf_hd_t hd;
  unsigned long param[1];
  unsigned int sharedinfolen;
  const unsigned char *supppubinfo;
  unsigned int keylen;

  /*
   *  ECC-CMS-SharedInfo ::= SEQUENCE {
   *      keyInfo         AlgorithmIdentifier,
   *      entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
   *      suppPubInfo [2] EXPLICIT OCTET STRING  }
   */
  if (!sharedinfo)
    return GPG_ERR_INV_VALUE;

  if (sharedinfo[0] != 0x30 /* Constructed | SEQUENCE */
      || sharedinfo[1] >= 0x80)
    return GPG_ERR_INV_VALUE;

  sharedinfolen = sharedinfo[1] + 2;

  /* Extract KEYLEN for keywrap from suppPubInfo.  */
  supppubinfo = sharedinfo + sharedinfolen - 8;
  if (supppubinfo[0] != 0xA2 /* CLASS_CONTEXT | Constructed | 2 */
      || supppubinfo[1] != 6
      || supppubinfo[2] != 0x04 /* OCTET STRING */
      || supppubinfo[3] != 4)
    return GPG_ERR_INV_VALUE;

  keylen = ((((supppubinfo[4] << 24) | (supppubinfo[5] << 16)
              | (supppubinfo[6] << 8) | supppubinfo[7])) + 7) / 8;

  param[0] = keylen;

  err = _gcry_kdf_open (&hd, kdf_id, hash_id, param, 1,
                        ecdh, ecdh_len,
                        NULL, 0, NULL, 0, sharedinfo, sharedinfolen);
  if (err)
    return err;

  err = _gcry_kdf_compute (hd, NULL);
  if (!err)
    err = _gcry_kdf_final (hd, keylen, shared);
  _gcry_kdf_close (hd);

  return err;
}

gpg_err_code_t
_gcry_cms_kem_encap (int algo, const void *pubkey, void *ciphertext,
                     void *shared, const void *optional)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[ECC_PUBKEY_LEN_MAX];
  const unsigned char *sharedinfo = optional;
  unsigned char seckey_ephemeral[ECC_SECKEY_LEN_MAX];
  void *pubkey_ephemeral = ciphertext;
  int kdf_method;
  size_t ecc_len;

  if (algo == GCRY_KEM_CMS_X25519_X963_SHA256)
    kdf_method = GCRY_KDF_X963_KDF;
  else if (algo == GCRY_KEM_CMS_X25519_HKDF_SHA256)
    kdf_method = GCRY_KDF_HKDF;
  else
    return GPG_ERR_UNKNOWN_ALGORITHM;

  curveid = GCRY_ECC_CURVE25519;
  ecc_len = _gcry_ecc_get_algo_keylen (curveid);

  err = _gcry_ecc_raw_keypair (algo, pubkey_ephemeral, ecc_len,
                               seckey_ephemeral, ecc_len);
  if (err)
    return err;

  /* Do ECDH.  */
  err = ecc_mul_point (algo, ecdh, ecc_len, seckey_ephemeral, ecc_len,
                       pubkey, ecc_len);
  if (err)
    return err;

  return cms_kem_kdf (kdf_method, GCRY_MD_SHA256, ecdh, ecc_len,
                      sharedinfo, shared);
}

gpg_err_code_t
_gcry_cms_kem_decap (int algo, const void *seckey, const void *ciphertext,
                     void *shared, const void *optional)
{
  gpg_err_code_t err;
  int curveid;
  unsigned char ecdh[ECC_PUBKEY_LEN_MAX];
  const unsigned char *sharedinfo = optional;
  int kdf_method;
  size_t ecc_len;

  if (algo == GCRY_KEM_CMS_X25519_X963_SHA256)
    kdf_method = GCRY_KDF_X963_KDF;
  else if (algo == GCRY_KEM_CMS_X25519_HKDF_SHA256)
    kdf_method = GCRY_KDF_HKDF;
  else
    return GPG_ERR_UNKNOWN_ALGORITHM;

  curveid = GCRY_ECC_CURVE25519;
  ecc_len = _gcry_ecc_get_algo_keylen (curveid);

  /* Do ECDH.  */
  err = ecc_mul_point (algo, ecdh, ecc_len, seckey, ecc_len,
                       ciphertext, ecc_len);
  if (err)
    return err;

  return cms_kem_kdf (kdf_method, GCRY_MD_SHA256, ecdh, ecc_len,
                      sharedinfo, shared);
}
