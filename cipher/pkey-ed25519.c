/* pkey-ed25519.c  -	PKEY API implementation for Ed25519
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
_gcry_pkey_ed25519_sign (gcry_pkey_hd_t h,
                         int num_in, const unsigned char *const in[],
                         const size_t in_len[],
                         int num_out, unsigned char *out[], size_t out_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_sk = NULL;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;

  gcry_sexp_t s_tmp, s_tmp2;

  if ((h->flags & GCRY_PKEY_FLAG_CONTEXT))
    {
      if (num_in != 2 || (h->flags & GCRY_PKEY_FLAG_PREHASH))
        return gpg_error (GPG_ERR_INV_ARG);
    }
  else
    {
      if (num_in != 1)
        return gpg_error (GPG_ERR_INV_ARG);
    }

  if (num_out != 2)
    return gpg_error (GPG_ERR_INV_ARG);

  if (h->pk)
    err = sexp_build (&s_sk, NULL,
                      "(private-key"
                      " (ecc"
                      "  (curve \"Ed25519\")"
                      "  (flags eddsa)"
                      "  (q %b)"
                      "  (d %b)))",
                      (int)h->pk_len, h->pk,
                      (int)h->sk_len, h->sk);
  else
    err = sexp_build (&s_sk, NULL,
                      "(private-key"
                      " (ecc"
                      "  (curve \"Ed25519\")"
                      "  (flags eddsa)"
                      "  (d %b)))",
                      (int)h->sk_len, h->sk);
  if (err)
    return err;

  if ((h->flags & GCRY_PKEY_FLAG_CONTEXT))
    err = sexp_build (&s_msg, NULL,
                      "(data"
                      " (flags eddsa)"
                      " (hash-algo sha512)"
                      " (value %b)"
                      " (label %b))",
                      (int)in_len[0], in[0],
                      (int)in_len[1], in[1]);
  else if ((h->flags & GCRY_PKEY_FLAG_PREHASH))
    err = sexp_build (&s_msg, NULL,
                      "(data"
                      " (flags eddsa prehash)"
                      " (hash-algo sha512)"
                      " (value %b))", (int)in_len[0], in[0]);
  else
    err = sexp_build (&s_msg, NULL,
                      "(data"
                      " (flags eddsa)"
                      " (hash-algo sha512)"
                      " (value %b))", (int)in_len[0], in[0]);
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

  out[0] = out[1] = NULL;
  s_tmp2 = NULL;
  s_tmp = sexp_find_token (s_sig, "sig-val", 0);
  if (s_tmp)
    {
      s_tmp2 = s_tmp;
      s_tmp = sexp_find_token (s_tmp2, "eddsa", 0);
      if (s_tmp)
        {
          sexp_release (s_tmp2);
          s_tmp2 = s_tmp;
          s_tmp = sexp_find_token (s_tmp2, "r", 0);
          if (s_tmp)
            {
              out[0] = sexp_nth_buffer (s_tmp, 1, &out_len[0]);
              sexp_release (s_tmp);
            }
          s_tmp = sexp_find_token (s_tmp2, "s", 0);
          if (s_tmp)
            {
              out[1] = sexp_nth_buffer (s_tmp, 1, &out_len[1]);
              sexp_release (s_tmp);
            }
        }
    }
  sexp_release (s_tmp2);

  if (out[0] == NULL || out[1] == NULL)
    err = gpg_error (GPG_ERR_BAD_SIGNATURE);

  sexp_release (s_sig);

  return err;
}

gcry_error_t
_gcry_pkey_ed25519_verify (gcry_pkey_hd_t h,
                           int num_in, const unsigned char *const in[],
                           const size_t in_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_pk = NULL;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;

  if ((h->flags & GCRY_PKEY_FLAG_CONTEXT))
    {
      if (num_in != 4 || (h->flags & GCRY_PKEY_FLAG_PREHASH))
        return gpg_error (GPG_ERR_INV_ARG);
    }
  else
    {
      if (num_in != 3)
        return gpg_error (GPG_ERR_INV_ARG);
    }

  err = sexp_build (&s_pk, NULL,
                    "(public-key"
                    " (ecc"
                    "  (curve \"Ed25519\")"
                    "  (flags eddsa)"
                    "  (q %b)))",
                    (int)h->pk_len, h->pk);
  if (err)
    return err;

  if (h->flags & GCRY_PKEY_FLAG_CONTEXT)
    err = sexp_build (&s_msg, NULL,
                      "(data"
                      " (flags eddsa)"
                      " (hash-algo sha512)"
                      " (value %b)"
                      " (label %b))",
                      (int)in_len[0], in[0],
                      (int)in_len[3], in[3]);
  else if ((h->flags & GCRY_PKEY_FLAG_PREHASH))
    err = sexp_build (&s_msg, NULL,
                      "(data"
                      " (flags eddsa prehash)"
                      " (hash-algo sha512)"
                      " (value %b))", (int)in_len[0], in[0]);
  else
    err = sexp_build (&s_msg, NULL,
                      "(data"
                      " (flags eddsa)"
                      " (hash-algo sha512)"
                      " (value %b))", (int)in_len[0], in[0]);
  if (err)
    {
      sexp_release (s_pk);
      return err;
    }

  err = sexp_build (&s_sig, NULL,
                    "(sig-val(eddsa(r %b)(s %b)))",
                    (int)in_len[1], in[1],
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
