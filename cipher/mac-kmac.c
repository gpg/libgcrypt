/* mac-kmac.c  -  KMAC glue for MAC API
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "./mac-internal.h"
#include "gcrypt.h"

#include <stddef.h>
#include "cshake-common.h"
#include "bufhelp.h"
#include "keccak.h"

static void
write_encoded_key (gcry_mac_hd_t h, const unsigned char *key, size_t keylen)
{

  size_t written_bytes = 0;
  size_t bit_len;
  gcry_buffer_t buf1;
  unsigned char array[20];
  unsigned rate_in_bytes = h->u.kmac.cshake_rate_in_bytes;
  size_t rem;

  /* catch overly large size of key early that would cause problem in
   * subseuqently invoked conversion routines */
  buf1.size = sizeof (array);
  buf1.data = array;
  buf1.len  = 0;
  /* bytepad(encode_string(key), <keccak_rate>) */
  /* inside bytepad: leading encoding of w */
  _gcry_cshake_left_encode (h->u.kmac.cshake_rate_in_bytes, &buf1);

  /* encode_string(key) */
  bit_len = _gcry_cshake_bit_len_from_byte_len (keylen);
  _gcry_cshake_left_encode (bit_len, &buf1);
  _gcry_md_write (h->u.kmac.md_ctx, buf1.data, buf1.len);
  written_bytes += buf1.len;
  _gcry_md_write (h->u.kmac.md_ctx, key, keylen);
  written_bytes += keylen;


  /* complete bytebad operation by applying padding */
  rem = written_bytes % rate_in_bytes;
  if (rem != 0)
    {
      rem = rate_in_bytes - rem;
      memset (array, 0, sizeof (array));
    }

  while (rem > 0)
    {
      unsigned to_use = rem > sizeof (array) ? sizeof (array) : rem;
      _gcry_md_write (h->u.kmac.md_ctx, array, to_use);
      rem -= to_use;
    }
  return;
}

static gpg_err_code_t
kmac_finalize (gcry_mac_hd_t h)
{

  size_t bit_len;
  unsigned char array[20];

  gcry_buffer_t buf1;
  buf1.size = sizeof (array);
  buf1.data = array;
  buf1.len  = 0;
  bit_len   = _gcry_cshake_bit_len_from_byte_len (h->u.kmac.output_byte_len);
  _gcry_cshake_right_encode (bit_len, &buf1);
  _gcry_md_write (h->u.kmac.md_ctx, buf1.data, buf1.len);
  h->u.kmac.finalized = 1;
  return GPG_ERR_NO_ERROR;
}

static gcry_err_code_t
kmac_open (gcry_mac_hd_t h)
{
  gcry_err_code_t err;
  gcry_md_hd_t hd;
  int secure = (h->magic == CTX_MAC_MAGIC_SECURE);
  unsigned int flags;
  int md_algo;
  unsigned rate_in_bytes, output_byte_len;
  switch (h->spec->algo)
    {
    case GCRY_MAC_KMAC128_128:
      md_algo         = GCRY_MD_CSHAKE128;
      rate_in_bytes   = 168;
      output_byte_len = 256 / 8;
      break;
    case GCRY_MAC_KMAC256_256:
      md_algo         = GCRY_MD_CSHAKE256;
      rate_in_bytes   = 136;
      output_byte_len = 512 / 8;
      break;
    default:
      return GPG_ERR_INV_ARG;
    }
  h->u.kmac.buffered_key         = NULL;
  h->u.kmac.md_algo              = md_algo;
  h->u.kmac.s_set                = 0;
  h->u.kmac.key_set              = 0;
  h->u.kmac.output_byte_len      = output_byte_len;
  h->u.kmac.finalized            = 0;
  h->u.kmac.cshake_rate_in_bytes = rate_in_bytes;
  h->u.kmac.computed_mac         = NULL;
  h->u.kmac.have_computed_mac    = 0;
  flags                          = (secure ? GCRY_MD_FLAG_SECURE : 0);

  err = _gcry_md_open (&hd, md_algo, flags);
  if (err)
    {
      return err;
    }
  h->u.kmac.md_ctx = hd;

  err = _gcry_md_ctl (hd, GCRYCTL_CSHAKE_N, (unsigned char *)"KMAC", 4);
  if (err)
    {
      return err;
    }
  h->u.kmac.computed_mac = secure ? xtrymalloc_secure (output_byte_len)
                                  : xtrymalloc (output_byte_len);
  if (!h->u.kmac.computed_mac)
    {
      return gpg_err_code_from_syserror ();
    }

  return GPG_ERR_NO_ERROR;
}


static void
kmac_close (gcry_mac_hd_t h)
{
  _gcry_md_close (h->u.kmac.md_ctx);
  h->u.kmac.md_ctx = NULL;
  xfree (h->u.kmac.computed_mac);
  xfree (h->u.kmac.buffered_key);
}

static gcry_err_code_t
kmac_setkey (gcry_mac_hd_t h, const unsigned char *key, size_t keylen)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  /* catch overly large size of key early that would cause problem in
   * subseuqently invoked conversion routines */
  if (DOES_MULT_OVERFL_SIZE_T (8, keylen) || keylen > 0xFFFFFFFF)
    {
      return GPG_ERR_TOO_LARGE;
    }
  /* if IV=S was set already, then encode and write key to cSHAKE, else
   * store it. */
  if (!h->u.kmac.s_set)
    {
      h->u.kmac.buffered_key = xtrymalloc_secure (keylen);
      if (!h->u.kmac.buffered_key)
        {
          return GPG_ERR_ENOMEM;
        }
      memcpy (h->u.kmac.buffered_key, key, keylen);
      h->u.kmac.buffered_key_len = keylen;
    }
  else
    {
      write_encoded_key (h, key, keylen);
    }
  h->u.kmac.key_set = 1;
  return err;
}

gcry_err_code_t
kmac_setiv (gcry_mac_hd_t h, const unsigned char *iv, size_t ivlen)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  /* catch overly large size of IV early that would cause problem in
   * subseuqently invoked conversion routines */
  if (DOES_MULT_OVERFL_SIZE_T (8, ivlen) || ivlen > 0xFFFFFFFF)
    {
      return GPG_ERR_TOO_LARGE;
    }
  if (h->u.kmac.s_set)
    {
      return GPG_ERR_INV_STATE;
    }
  err = _gcry_md_ctl (
      h->u.kmac.md_ctx, GCRYCTL_CSHAKE_S, (unsigned char *)iv, ivlen);
  if (err)
    {
      return err;
    }
  h->u.kmac.s_set = 1;
  /* if key is stored in context already, then write it after having set
   * S in cshake and free the buffer */
  if (h->u.kmac.buffered_key != NULL)
    {
      write_encoded_key (
          h, h->u.kmac.buffered_key, h->u.kmac.buffered_key_len);
      xfree (h->u.kmac.buffered_key);
      h->u.kmac.buffered_key     = NULL;
      h->u.kmac.buffered_key_len = 0;
    }
  return GPG_ERR_NO_ERROR;
}


static gcry_err_code_t
kmac_reset (gcry_mac_hd_t h)
{
  /* clear all fields and state */
  kmac_close (h);
  return kmac_open (h);
}


static gcry_err_code_t
kmac_write (gcry_mac_hd_t h, const unsigned char *buf, size_t buflen)
{
  gpg_err_code_t err = 0;

  /* If IV (=S in KMAC) was not set, it is implicitly empty */
  if (!h->u.kmac.s_set)
    {
      err = kmac_setiv (h, NULL, 0);
      if (err)
        {
          return err;
        }
    }
  if (!h->u.kmac.key_set || h->u.kmac.finalized)
    {
      return GPG_ERR_INV_STATE;
    }
  _gcry_md_write (h->u.kmac.md_ctx, buf, buflen);
  return GPG_ERR_NO_ERROR;
}


static gcry_err_code_t
kmac_read (gcry_mac_hd_t h, unsigned char *outbuf, size_t *outlen_ptr)
{

  if (outlen_ptr && *outlen_ptr > h->u.kmac.output_byte_len)
    {
      *outlen_ptr = h->u.kmac.output_byte_len;
    }
  /* Both read and verify may be called in any order. Thus the KMAC context
   * holds the computed MAC in a buffer. */
  if (!h->u.kmac.have_computed_mac)
    {
      gpg_err_code_t err = GPG_ERR_NO_ERROR;
      err                = kmac_finalize (h);
      if (err)
        {
          return err;
        }

      err = _gcry_md_extract (h->u.kmac.md_ctx,
                              h->u.kmac.md_algo,
                              h->u.kmac.computed_mac,
                              h->u.kmac.output_byte_len);
      if (err)
        {
          return err;
        }
      h->u.kmac.have_computed_mac = 1;
    }
  if (outlen_ptr)
    {
      memcpy (outbuf, h->u.kmac.computed_mac, *outlen_ptr);
    }
  return GPG_ERR_NO_ERROR;
}


static gcry_err_code_t
kmac_verify (gcry_mac_hd_t h, const unsigned char *buf, size_t buflen)
{
  /* This function verifies full MACs only. If a too short MAC is provided by
   * the caller, the verification fails. Note that for instance HMAC in
   * libgcrypt behaves differently: if there a MAC is provided to the verify
   * function that is shorter than the regular MAC length, the verification
   * succeeds if that shorter MAC is a matching the start of the regular MAC.
   * This behaviour incurs the risk that an implementation issues the
   * verification of a one-byte-length attacker controlled MAC that then
   * verifies correctly with probability 1/256 (the case of zero-length MACs is
   * caught by the higher-level generic MAC API).
   */
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  size_t outlen      = h->u.kmac.output_byte_len;
  if (buflen != outlen)
    {
      return GPG_ERR_INV_LENGTH;
    }
  err = kmac_read (h, NULL, NULL);
  if (err)
    {
      return err;
    }
  return buf_eq_const (buf, h->u.kmac.computed_mac, outlen) ? 0
                                                            : GPG_ERR_CHECKSUM;
}
static unsigned int
kmac_get_maclen (int algo)
{
  switch (algo)
    {
    case GCRY_MAC_KMAC128_128:
      return 256 / 8;
    case GCRY_MAC_KMAC256_256:
      return 512 / 8;
    default:
      return 0;
    }
}


static unsigned int
kmac_get_keylen (int algo)
{
  /* The key length for KMAC is arbitrary. Here, we return values
   * corresponding to the security level. */
  switch (algo)
    {
    case GCRY_MAC_KMAC128_128:
      return 128 / 8;
    case GCRY_MAC_KMAC256_256:
      return 256 / 8;
    default:
      /* return the minimum reasonable value */
      return 128;
    }
}

static const gcry_mac_spec_ops_t kmac_ops = {
    kmac_open,
    kmac_close,
    kmac_setkey,
    kmac_setiv,
    kmac_reset,
    kmac_write,
    kmac_read,
    kmac_verify,
    kmac_get_maclen,
    kmac_get_keylen,
    NULL,
    NULL /* no kmac_selftest */
};

const gcry_mac_spec_t _gcry_mac_type_spec_kmac128_128
    = {GCRY_MAC_KMAC128_128, {0, 0}, "KMAC128(128)", &kmac_ops};

const gcry_mac_spec_t _gcry_mac_type_spec_kmac256_256
    = {GCRY_MAC_KMAC256_256, {0, 0}, "KMAC256(256)", &kmac_ops};
