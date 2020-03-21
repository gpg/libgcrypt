/* mac-hmac.c  -  HMAC glue for MAC API
 * Copyright (C) 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
#include "bufhelp.h"


static int
map_mac_algo_to_md (int mac_algo)
{
  switch (mac_algo)
    {
    default:
      return GCRY_MD_NONE;
    case GCRY_MAC_HMAC_MD2:
      return GCRY_MD_MD2;
    case GCRY_MAC_HMAC_MD4:
      return GCRY_MD_MD4;
    case GCRY_MAC_HMAC_MD5:
      return GCRY_MD_MD5;
    case GCRY_MAC_HMAC_SHA1:
      return GCRY_MD_SHA1;
    case GCRY_MAC_HMAC_SHA224:
      return GCRY_MD_SHA224;
    case GCRY_MAC_HMAC_SHA256:
      return GCRY_MD_SHA256;
    case GCRY_MAC_HMAC_SHA384:
      return GCRY_MD_SHA384;
    case GCRY_MAC_HMAC_SHA512:
      return GCRY_MD_SHA512;
    case GCRY_MAC_HMAC_SHA512_256:
      return GCRY_MD_SHA512_256;
    case GCRY_MAC_HMAC_SHA512_224:
      return GCRY_MD_SHA512_224;
    case GCRY_MAC_HMAC_SHA3_224:
      return GCRY_MD_SHA3_224;
    case GCRY_MAC_HMAC_SHA3_256:
      return GCRY_MD_SHA3_256;
    case GCRY_MAC_HMAC_SHA3_384:
      return GCRY_MD_SHA3_384;
    case GCRY_MAC_HMAC_SHA3_512:
      return GCRY_MD_SHA3_512;
    case GCRY_MAC_HMAC_RMD160:
      return GCRY_MD_RMD160;
    case GCRY_MAC_HMAC_TIGER1:
      return GCRY_MD_TIGER1;
    case GCRY_MAC_HMAC_WHIRLPOOL:
      return GCRY_MD_WHIRLPOOL;
    case GCRY_MAC_HMAC_GOSTR3411_94:
      return GCRY_MD_GOSTR3411_94;
    case GCRY_MAC_HMAC_GOSTR3411_CP:
      return GCRY_MD_GOSTR3411_CP;
    case GCRY_MAC_HMAC_STRIBOG256:
      return GCRY_MD_STRIBOG256;
    case GCRY_MAC_HMAC_STRIBOG512:
      return GCRY_MD_STRIBOG512;
    case GCRY_MAC_HMAC_BLAKE2B_512:
      return GCRY_MD_BLAKE2B_512;
    case GCRY_MAC_HMAC_BLAKE2B_384:
      return GCRY_MD_BLAKE2B_384;
    case GCRY_MAC_HMAC_BLAKE2B_256:
      return GCRY_MD_BLAKE2B_256;
    case GCRY_MAC_HMAC_BLAKE2B_160:
      return GCRY_MD_BLAKE2B_160;
    case GCRY_MAC_HMAC_BLAKE2S_256:
      return GCRY_MD_BLAKE2S_256;
    case GCRY_MAC_HMAC_BLAKE2S_224:
      return GCRY_MD_BLAKE2S_224;
    case GCRY_MAC_HMAC_BLAKE2S_160:
      return GCRY_MD_BLAKE2S_160;
    case GCRY_MAC_HMAC_BLAKE2S_128:
      return GCRY_MD_BLAKE2S_128;
    case GCRY_MAC_HMAC_SM3:
      return GCRY_MD_SM3;
    }
}


static gcry_err_code_t
hmac_open (gcry_mac_hd_t h)
{
  gcry_err_code_t err;
  gcry_md_hd_t hd;
  int secure = (h->magic == CTX_MAGIC_SECURE);
  unsigned int flags;
  int md_algo;

  md_algo = map_mac_algo_to_md (h->spec->algo);

  flags = GCRY_MD_FLAG_HMAC;
  flags |= (secure ? GCRY_MD_FLAG_SECURE : 0);

  err = _gcry_md_open (&hd, md_algo, flags);
  if (err)
    return err;

  h->u.hmac.md_algo = md_algo;
  h->u.hmac.md_ctx = hd;
  return 0;
}


static void
hmac_close (gcry_mac_hd_t h)
{
  _gcry_md_close (h->u.hmac.md_ctx);
  h->u.hmac.md_ctx = NULL;
}


static gcry_err_code_t
hmac_setkey (gcry_mac_hd_t h, const unsigned char *key, size_t keylen)
{
  return _gcry_md_setkey (h->u.hmac.md_ctx, key, keylen);
}


static gcry_err_code_t
hmac_reset (gcry_mac_hd_t h)
{
  _gcry_md_reset (h->u.hmac.md_ctx);
  return 0;
}


static gcry_err_code_t
hmac_write (gcry_mac_hd_t h, const unsigned char *buf, size_t buflen)
{
  _gcry_md_write (h->u.hmac.md_ctx, buf, buflen);
  return 0;
}


static gcry_err_code_t
hmac_read (gcry_mac_hd_t h, unsigned char *outbuf, size_t * outlen)
{
  unsigned int dlen;
  const unsigned char *digest;

  dlen = _gcry_md_get_algo_dlen (h->u.hmac.md_algo);
  digest = _gcry_md_read (h->u.hmac.md_ctx, h->u.hmac.md_algo);

  if (*outlen <= dlen)
    buf_cpy (outbuf, digest, *outlen);
  else
    {
      buf_cpy (outbuf, digest, dlen);
      *outlen = dlen;
    }

  return 0;
}


static gcry_err_code_t
hmac_verify (gcry_mac_hd_t h, const unsigned char *buf, size_t buflen)
{
  unsigned int dlen;
  const unsigned char *digest;

  dlen = _gcry_md_get_algo_dlen (h->u.hmac.md_algo);
  digest = _gcry_md_read (h->u.hmac.md_ctx, h->u.hmac.md_algo);

  if (buflen > dlen)
    return GPG_ERR_INV_LENGTH;

  return buf_eq_const (buf, digest, buflen) ? 0 : GPG_ERR_CHECKSUM;
}


static unsigned int
hmac_get_maclen (int algo)
{
  return _gcry_md_get_algo_dlen (map_mac_algo_to_md (algo));
}


static unsigned int
hmac_get_keylen (int algo)
{
  /* Return blocksize for default key length. */
  switch (algo)
    {
    case GCRY_MD_SHA3_224:
      return 1152 / 8;
    case GCRY_MD_SHA3_256:
      return 1088 / 8;
    case GCRY_MD_SHA3_384:
      return 832 / 8;
    case GCRY_MD_SHA3_512:
      return 576 / 8;
    case GCRY_MAC_HMAC_SHA384:
    case GCRY_MAC_HMAC_SHA512:
      return 128;
    case GCRY_MAC_HMAC_GOSTR3411_94:
      return 32;
    default:
      return 64;
    }
}


static const gcry_mac_spec_ops_t hmac_ops = {
  hmac_open,
  hmac_close,
  hmac_setkey,
  NULL,
  hmac_reset,
  hmac_write,
  hmac_read,
  hmac_verify,
  hmac_get_maclen,
  hmac_get_keylen,
  NULL
};


#if USE_SHA1
gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha1 = {
  GCRY_MAC_HMAC_SHA1, {0, 1}, "HMAC_SHA1",
  &hmac_ops
};
#endif
#if USE_SHA256
gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha256 = {
  GCRY_MAC_HMAC_SHA256, {0, 1}, "HMAC_SHA256",
  &hmac_ops
};

gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha224 = {
  GCRY_MAC_HMAC_SHA224, {0, 1}, "HMAC_SHA224",
  &hmac_ops
};
#endif
#if USE_SHA512
gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha512 = {
  GCRY_MAC_HMAC_SHA512, {0, 1}, "HMAC_SHA512",
  &hmac_ops
};

gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha384 = {
  GCRY_MAC_HMAC_SHA384, {0, 1}, "HMAC_SHA384",
  &hmac_ops
};

gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha512_256 = {
  GCRY_MAC_HMAC_SHA512_256, {0, 1}, "HMAC_SHA512_256",
  &hmac_ops
};

gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha512_224 = {
  GCRY_MAC_HMAC_SHA512_224, {0, 1}, "HMAC_SHA512_224",
  &hmac_ops
};

#endif
#if USE_SHA3
gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha3_224 = {
  GCRY_MAC_HMAC_SHA3_224, {0, 1}, "HMAC_SHA3_224",
  &hmac_ops
};

gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha3_256 = {
  GCRY_MAC_HMAC_SHA3_256, {0, 1}, "HMAC_SHA3_256",
  &hmac_ops
};

gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha3_384 = {
  GCRY_MAC_HMAC_SHA3_384, {0, 1}, "HMAC_SHA3_384",
  &hmac_ops
};

gcry_mac_spec_t _gcry_mac_type_spec_hmac_sha3_512 = {
  GCRY_MAC_HMAC_SHA3_512, {0, 1}, "HMAC_SHA3_512",
  &hmac_ops
};
#endif
#ifdef USE_GOST_R_3411_94
gcry_mac_spec_t _gcry_mac_type_spec_hmac_gost3411_94 = {
  GCRY_MAC_HMAC_GOSTR3411_94, {0, 0}, "HMAC_GOSTR3411_94",
  &hmac_ops
};
gcry_mac_spec_t _gcry_mac_type_spec_hmac_gost3411_cp = {
  GCRY_MAC_HMAC_GOSTR3411_CP, {0, 0}, "HMAC_GOSTR3411_CP",
  &hmac_ops
};
#endif
#ifdef USE_GOST_R_3411_12
gcry_mac_spec_t _gcry_mac_type_spec_hmac_stribog256 = {
  GCRY_MAC_HMAC_STRIBOG256, {0, 0}, "HMAC_STRIBOG256",
  &hmac_ops
};

gcry_mac_spec_t _gcry_mac_type_spec_hmac_stribog512 = {
  GCRY_MAC_HMAC_STRIBOG512, {0, 0}, "HMAC_STRIBOG512",
  &hmac_ops
};
#endif
#if USE_WHIRLPOOL
gcry_mac_spec_t _gcry_mac_type_spec_hmac_whirlpool = {
  GCRY_MAC_HMAC_WHIRLPOOL, {0, 0}, "HMAC_WHIRLPOOL",
  &hmac_ops
};
#endif
#if USE_RMD160
gcry_mac_spec_t _gcry_mac_type_spec_hmac_rmd160 = {
  GCRY_MAC_HMAC_RMD160, {0, 0}, "HMAC_RIPEMD160",
  &hmac_ops
};
#endif
#if USE_TIGER
gcry_mac_spec_t _gcry_mac_type_spec_hmac_tiger1 = {
  GCRY_MAC_HMAC_TIGER1, {0, 0}, "HMAC_TIGER",
  &hmac_ops
};
#endif
#if USE_MD5
gcry_mac_spec_t _gcry_mac_type_spec_hmac_md5 = {
  GCRY_MAC_HMAC_MD5, {0, 0}, "HMAC_MD5",
  &hmac_ops
};
#endif
#if USE_MD4
gcry_mac_spec_t _gcry_mac_type_spec_hmac_md4 = {
  GCRY_MAC_HMAC_MD4, {0, 0}, "HMAC_MD4",
  &hmac_ops
};
#endif
#if USE_MD2
gcry_mac_spec_t _gcry_mac_type_spec_hmac_md2 = {
  GCRY_MAC_HMAC_MD2, {0, 0}, "HMAC_MD2",
  &hmac_ops
};
#endif
#if USE_BLAKE2
gcry_mac_spec_t _gcry_mac_type_spec_hmac_blake2b_512 = {
  GCRY_MAC_HMAC_BLAKE2B_512, {0, 0}, "HMAC_BLAKE2B_512",
  &hmac_ops
};
gcry_mac_spec_t _gcry_mac_type_spec_hmac_blake2b_384 = {
  GCRY_MAC_HMAC_BLAKE2B_384, {0, 0}, "HMAC_BLAKE2B_384",
  &hmac_ops
};
gcry_mac_spec_t _gcry_mac_type_spec_hmac_blake2b_256 = {
  GCRY_MAC_HMAC_BLAKE2B_256, {0, 0}, "HMAC_BLAKE2B_256",
  &hmac_ops
};
gcry_mac_spec_t _gcry_mac_type_spec_hmac_blake2b_160 = {
  GCRY_MAC_HMAC_BLAKE2B_160, {0, 0}, "HMAC_BLAKE2B_160",
  &hmac_ops
};
gcry_mac_spec_t _gcry_mac_type_spec_hmac_blake2s_256 = {
  GCRY_MAC_HMAC_BLAKE2S_256, {0, 0}, "HMAC_BLAKE2S_256",
  &hmac_ops
};
gcry_mac_spec_t _gcry_mac_type_spec_hmac_blake2s_224 = {
  GCRY_MAC_HMAC_BLAKE2S_224, {0, 0}, "HMAC_BLAKE2S_224",
  &hmac_ops
};
gcry_mac_spec_t _gcry_mac_type_spec_hmac_blake2s_160 = {
  GCRY_MAC_HMAC_BLAKE2S_160, {0, 0}, "HMAC_BLAKE2S_160",
  &hmac_ops
};
gcry_mac_spec_t _gcry_mac_type_spec_hmac_blake2s_128 = {
  GCRY_MAC_HMAC_BLAKE2S_128, {0, 0}, "HMAC_BLAKE2S_128",
  &hmac_ops
};
#endif
#if USE_SM3
gcry_mac_spec_t _gcry_mac_type_spec_hmac_sm3 = {
  GCRY_MAC_HMAC_SM3, {0, 0}, "HMAC_SM3",
  &hmac_ops
};
#endif
