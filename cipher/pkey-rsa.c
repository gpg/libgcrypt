/* pkey-rsa.c  -        PKEY API implementation for RSA PSS/15/931
 * Copyright (C) 2021 g10 Code GmbH
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "g10lib.h"
#include "gcrypt-int.h"
#include "pkey-internal.h"

gcry_error_t
_gcry_pkey_rsapss_sign (gcry_pkey_hd_t h,
                        int num_in, const unsigned char *const in[],
                        const size_t in_len[],
                        int num_out, unsigned char *out[], size_t out_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_sk = NULL;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;
  const char *md_name;
  gcry_sexp_t s_tmp, s_tmp2;

  if (num_in != 2)
    return gpg_error (GPG_ERR_INV_ARG);

  if (num_out != 1)
    return gpg_error (GPG_ERR_INV_ARG);

  switch (h->rsa.md_algo)
    {
    case GCRY_MD_SHA224:
      md_name = "sha224";
      break;
    case GCRY_MD_SHA256:
      md_name = "sha256";
      break;
    case GCRY_MD_SHA384:
      md_name = "sha384";
      break;
    case GCRY_MD_SHA512:
      md_name = "sha512";
      break;
    default:
      return gpg_error (GPG_ERR_INV_ARG);
    }

  err = sexp_build (&s_sk, NULL,
                    "(private-key (rsa (n %b)(e %b)(d %b)))",
                    (int)h->rsa.n_len, h->rsa.n,
                    (int)h->rsa.e_len, h->rsa.e,
                    (int)h->rsa.d_len, h->rsa.d);
  if (err)
    return err;

  err = sexp_build (&s_msg, NULL,
                    "(data"
                    " (flags pss)"
                    " (hash-algo %s)"
                    " (value %b)"
                    " (salt-length %d)"
                    " (random-override %b))",
                    md_name,
                    (int)in_len[0], in[0],
                    (int)in_len[1],
                    (int)in_len[1], in[1]);
  if (err)
    {
      sexp_release (s_sk);
      return err;
    }

  err = _gcry_pk_sign (&s_sig, s_msg, s_sk);
  sexp_release (s_sk);
  sexp_release (s_msg);
  if (err)
    return err;

  out[0] = NULL;
  s_tmp2 = NULL;
  s_tmp = sexp_find_token (s_sig, "sig-val", 0);
  if (s_tmp)
    {
      s_tmp2 = s_tmp;
      s_tmp = sexp_find_token (s_tmp2, "rsa", 0);
      if (s_tmp)
        {
          sexp_release (s_tmp2);
          s_tmp2 = s_tmp;
          s_tmp = sexp_find_token (s_tmp2, "s", 0);
          if (s_tmp)
            {
              out[0] = sexp_nth_buffer (s_tmp, 1, &out_len[0]);
              sexp_release (s_tmp);
            }
        }
    }
  sexp_release (s_tmp2);

  if (out[0] == NULL)
    err = gpg_error (GPG_ERR_BAD_SIGNATURE);

  sexp_release (s_sig);

  return err;
}

gcry_error_t
_gcry_pkey_rsapss_verify (gcry_pkey_hd_t h,
                          int num_in, const unsigned char *const in[],
                          const size_t in_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_pk = NULL;
  const char *md_name;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;

  if (num_in != 3)
    return gpg_error (GPG_ERR_INV_ARG);

  switch (h->rsa.md_algo)
    {
    case GCRY_MD_SHA224:
      md_name = "sha224";
      break;
    case GCRY_MD_SHA256:
      md_name = "sha256";
      break;
    case GCRY_MD_SHA384:
      md_name = "sha384";
      break;
    case GCRY_MD_SHA512:
      md_name = "sha512";
      break;
    default:
      return gpg_error (GPG_ERR_INV_ARG);
    }

  err = sexp_build (&s_pk, NULL,
                    "(public-key (rsa (n %b)(e %b)))",
                    (int)h->rsa.n_len, h->rsa.n,
                    (int)h->rsa.e_len, h->rsa.e);
  if (err)
    return err;

  err = sexp_build (&s_msg, NULL,
                    "(data"
                    " (flags pss)"
                    " (hash-algo %s)"
                    " (value %b)"
                    " (salt-length %d)"
                    " (random-override %b))",
                    md_name,
                    (int)in_len[0], in[0],
                    (int)in_len[1],
                    (int)in_len[1], in[1]);
  if (err)
    {
      sexp_release (s_pk);
      return err;
    }

  err = sexp_build (&s_sig, NULL,
                    "(sig-val(rsa(s %b)))",
                    (int)in_len[2], in[2]);
  if (err)
    {
      sexp_release (s_msg);
      sexp_release (s_pk);
      return err;
    }

  err = _gcry_pk_verify (s_sig, s_msg, s_pk);

  sexp_release (s_sig);
  sexp_release (s_msg);
  sexp_release (s_pk);

  return err;
}


gcry_error_t
_gcry_pkey_rsa15_sign (gcry_pkey_hd_t h,
                       int num_in, const unsigned char *const in[],
                       const size_t in_len[],
                       int num_out, unsigned char *out[], size_t out_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_sk = NULL;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;
  const char *md_name;
  gcry_sexp_t s_tmp, s_tmp2;

  if (num_in != 1)
    return gpg_error (GPG_ERR_INV_ARG);

  if (num_out != 1)
    return gpg_error (GPG_ERR_INV_ARG);

  switch (h->rsa.md_algo)
    {
    case GCRY_MD_SHA224:
      md_name = "sha224";
      break;
    case GCRY_MD_SHA256:
      md_name = "sha256";
      break;
    case GCRY_MD_SHA384:
      md_name = "sha384";
      break;
    case GCRY_MD_SHA512:
      md_name = "sha512";
      break;
    default:
      return gpg_error (GPG_ERR_INV_ARG);
    }

  err = sexp_build (&s_sk, NULL,
                    "(private-key (rsa (n %b)(e %b)(d %b)))",
                    (int)h->rsa.n_len, h->rsa.n,
                    (int)h->rsa.e_len, h->rsa.e,
                    (int)h->rsa.d_len, h->rsa.d);
  if (err)
    return err;

  err = sexp_build (&s_msg, NULL,
                    "(data"
                    " (flags pkcs1 prehash)"
                    " (hash-algo %s)"
                    " (value %b))",
                    md_name,
                    (int)in_len[0], in[0]);
  if (err)
    {
      sexp_release (s_sk);
      return err;
    }

  err = _gcry_pk_sign (&s_sig, s_msg, s_sk);
  sexp_release (s_sk);
  sexp_release (s_msg);
  if (err)
    return err;

  out[0] = NULL;
  s_tmp2 = NULL;
  s_tmp = sexp_find_token (s_sig, "sig-val", 0);
  if (s_tmp)
    {
      s_tmp2 = s_tmp;
      s_tmp = sexp_find_token (s_tmp2, "rsa", 0);
      if (s_tmp)
        {
          sexp_release (s_tmp2);
          s_tmp2 = s_tmp;
          s_tmp = sexp_find_token (s_tmp2, "s", 0);
          if (s_tmp)
            {
              out[0] = sexp_nth_buffer (s_tmp, 1, &out_len[0]);
              sexp_release (s_tmp);
            }
        }
    }
  sexp_release (s_tmp2);

  if (out[0] == NULL)
    err = gpg_error (GPG_ERR_BAD_SIGNATURE);

  sexp_release (s_sig);

  return err;
}

gcry_error_t
_gcry_pkey_rsa15_verify (gcry_pkey_hd_t h,
                         int num_in, const unsigned char *const in[],
                         const size_t in_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_pk = NULL;
  const char *md_name;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;

  if (num_in != 2)
    return gpg_error (GPG_ERR_INV_ARG);

  switch (h->rsa.md_algo)
    {
    case GCRY_MD_SHA224:
      md_name = "sha224";
      break;
    case GCRY_MD_SHA256:
      md_name = "sha256";
      break;
    case GCRY_MD_SHA384:
      md_name = "sha384";
      break;
    case GCRY_MD_SHA512:
      md_name = "sha512";
      break;
    default:
      return gpg_error (GPG_ERR_INV_ARG);
    }

  err = sexp_build (&s_pk, NULL,
                    "(public-key (rsa (n %b)(e %b)))",
                    (int)h->rsa.n_len, h->rsa.n,
                    (int)h->rsa.e_len, h->rsa.e);
  if (err)
    return err;

  err = sexp_build (&s_msg, NULL,
                    "(data"
                    " (flags pkcs1 prehash)"
                    " (hash-algo %s)"
                    " (value %b))",
                    md_name,
                    (int)in_len[0], in[0]);
  if (err)
    {
      sexp_release (s_pk);
      return err;
    }

  err = sexp_build (&s_sig, NULL,
                    "(sig-val(rsa(s %b)))",
                    (int)in_len[1], in[1]);
  if (err)
    {
      sexp_release (s_msg);
      sexp_release (s_pk);
      return err;
    }

  err = _gcry_pk_verify (s_sig, s_msg, s_pk);

  sexp_release (s_sig);
  sexp_release (s_msg);
  sexp_release (s_pk);

  return err;
}



static void
x931_encode_sig (gcry_pkey_hd_t h, unsigned char md_number,
                 unsigned char *frame,
                 const unsigned char *input, size_t input_len)
{
  size_t hashlen;
  size_t len_ps;

  hashlen = _gcry_md_get_algo_dlen (h->rsa.md_algo);

  len_ps = h->rsa.n_len - hashlen - 4;
  frame[0] = 0x6b;
  memset (frame+1, 0xbb, len_ps);
  frame[1+len_ps] = 0xba;
  _gcry_md_hash_buffer (h->rsa.md_algo, &frame[len_ps+2], input, input_len);
  frame[h->rsa.n_len - 2] = md_number;
  frame[h->rsa.n_len - 1] = 0xcc;
}

static int
bn_sub (unsigned char *res,
        const unsigned char *a, const unsigned char *b, size_t n)
{
  int i;
  unsigned char borrow = 0;

  for (i = 0; i < (int)n; i++)
    {
      res[n-i-1] = a[n-i-1] - b[n-i-1] - borrow;
      if ((int)a[n-i-1] < (int)b[n-i-1] + borrow)
        borrow = 1;
      else
        borrow = 0;
    }

  return borrow;
}

static int
bn_cmp (const unsigned char *a, const unsigned char *b, size_t n)
{
  int i;
  unsigned char borrow = 0;

  for (i = 0; i < (int)n; i++)
    {
      if ((int)a[n-i-1] < (int)b[n-i-1] + borrow)
        borrow = 1;
      else
        borrow = 0;
    }

  return borrow;
}

gcry_error_t
_gcry_pkey_rsa931_sign (gcry_pkey_hd_t h,
                        int num_in, const unsigned char *const in[],
                        const size_t in_len[],
                        int num_out, unsigned char *out[], size_t out_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_sk = NULL;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;
  gcry_sexp_t s_tmp, s_tmp2;
  unsigned char md_number;
  unsigned char *frame;

  if (num_in != 1)
    return gpg_error (GPG_ERR_INV_ARG);

  if (num_out != 1)
    return gpg_error (GPG_ERR_INV_ARG);

  switch (h->rsa.md_algo)
    {
    case GCRY_MD_SHA224:
      md_number = 0x38;
      break;
    case GCRY_MD_SHA256:
      md_number = 0x34;
      break;
    case GCRY_MD_SHA384:
      md_number = 0x36;
      break;
    case GCRY_MD_SHA512:
      md_number = 0x35;
      break;
    default:
      return gpg_error (GPG_ERR_INV_ARG);
    }

  if (!(frame = xtrymalloc (h->rsa.n_len)))
    return gpg_error_from_syserror ();

  x931_encode_sig (h, md_number, frame, in[0], in_len[0]);

  err = sexp_build (&s_sk, NULL,
                    "(private-key (rsa (n %b)(e %b)(d %b)))",
                    (int)h->rsa.n_len, h->rsa.n,
                    (int)h->rsa.e_len, h->rsa.e,
                    (int)h->rsa.d_len, h->rsa.d);
  if (err)
    {
      xfree (frame);
      return err;
    }

  err = sexp_build (&s_msg, NULL,
                    "(data"
                    " (flags raw fixedlen)"
                    " (value %b))",
                    (int)h->rsa.n_len, frame);
  if (err)
    {
      xfree (frame);
      sexp_release (s_sk);
      return err;
    }

  err = _gcry_pk_sign (&s_sig, s_msg, s_sk);
  sexp_release (s_sk);
  sexp_release (s_msg);
  if (err)
    {
      xfree (frame);
      return err;
    }

  out[0] = NULL;
  s_tmp2 = NULL;
  s_tmp = sexp_find_token (s_sig, "sig-val", 0);
  if (s_tmp)
    {
      s_tmp2 = s_tmp;
      s_tmp = sexp_find_token (s_tmp2, "rsa", 0);
      if (s_tmp)
        {
          sexp_release (s_tmp2);
          s_tmp2 = s_tmp;
          s_tmp = sexp_find_token (s_tmp2, "s", 0);
          if (s_tmp)
            {
              out[0] = sexp_nth_buffer (s_tmp, 1, &out_len[0]);
              sexp_release (s_tmp);
            }
        }
    }
  sexp_release (s_tmp2);

  if (out[0] == NULL)
    err = gpg_error (GPG_ERR_BAD_SIGNATURE);
  else
    {
      /* X9.31 signature scheme is tricky;  It selects minimum one.  */
      if (!bn_sub (frame, h->rsa.n, out[0], h->rsa.n_len)
          && bn_cmp (frame, out[0], h->rsa.n_len))
        memcpy (out[0], frame, h->rsa.n_len);
    }

  sexp_release (s_sig);
  xfree (frame);

  return err;
}

gcry_error_t
_gcry_pkey_rsa931_verify (gcry_pkey_hd_t h,
                          int num_in, const unsigned char *const in[],
                          const size_t in_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_pk = NULL;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;
  unsigned char md_number;
  unsigned char *frame;

  if (num_in != 2)
    return gpg_error (GPG_ERR_INV_ARG);

  switch (h->rsa.md_algo)
    {
    case GCRY_MD_SHA224:
      md_number = 0x38;
      break;
    case GCRY_MD_SHA256:
      md_number = 0x34;
      break;
    case GCRY_MD_SHA384:
      md_number = 0x36;
      break;
    case GCRY_MD_SHA512:
      md_number = 0x35;
      break;
    default:
      return gpg_error (GPG_ERR_INV_ARG);
    }

  if (!(frame = xtrymalloc (h->rsa.n_len)))
    return gpg_error_from_syserror ();

  x931_encode_sig (h, md_number, frame, in[0], in_len[0]);

  err = sexp_build (&s_pk, NULL,
                    "(public-key (rsa (n %b)(e %b)))",
                    (int)h->rsa.n_len, h->rsa.n,
                    (int)h->rsa.e_len, h->rsa.e);
  if (err)
    {
      xfree (frame);
      return err;
    }

  err = sexp_build (&s_msg, NULL,
                    "(data"
                    " (flags raw fixedlen)"
                    " (value %b))",
                    (int)h->rsa.n_len, frame);
  xfree (frame);
  if (err)
    {
      sexp_release (s_pk);
      return err;
    }

  err = sexp_build (&s_sig, NULL,
                    "(sig-val(rsa(s %b)))",
                    (int)in_len[1], in[1]);
  if (err)
    {
      sexp_release (s_msg);
      sexp_release (s_pk);
      return err;
    }

  /* We check two possible signature;
   * This allows invalid signature (by another value).
   * We should support X9.31 signature scheme in lower level.
   */

  err = _gcry_pk_verify (s_sig, s_msg, s_pk);

  if (err)
    {
      unsigned char *alt;

      /* Try another.  */
      sexp_release (s_sig);

      if (!(alt = xtrymalloc (h->rsa.n_len)))
        {
          sexp_release (s_msg);
          sexp_release (s_pk);
          return gpg_error_from_syserror ();
        }

      bn_sub (alt, h->rsa.n, in[1], h->rsa.n_len);
      err = sexp_build (&s_sig, NULL,
                        "(sig-val(rsa(s %b)))",
                        (int)in_len[1], alt);
      if (err)
        {
          sexp_release (s_msg);
          sexp_release (s_pk);
          return err;
        }

      err = _gcry_pk_verify (s_sig, s_msg, s_pk);
    }

  sexp_release (s_sig);
  sexp_release (s_msg);
  sexp_release (s_pk);

  return err;
}
