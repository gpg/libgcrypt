/* pkey-ecc-nist.c  -	PKEY API implementation for NIST Curves
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

static const char *
get_curve_name (int curve)
{
  switch (curve)
    {
    case GCRY_PKEY_CURVE_NIST_P224:
      return "nistp224";
    case GCRY_PKEY_CURVE_NIST_P256:
      return "nistp256";
    case GCRY_PKEY_CURVE_NIST_P384:
      return "nistp384";
    case GCRY_PKEY_CURVE_NIST_P521:
      return "nistp521";
    default:
      return "unknown";
    }
}

gcry_error_t
_gcry_pkey_nist_sign (gcry_pkey_hd_t h,
		      int num_in, const unsigned char *const in[],
		      const size_t in_len[],
		      int num_out, unsigned char *out[], size_t out_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_sk = NULL;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;
  gcry_sexp_t s_tmp, s_tmp2;
  const char *curve;
  const char *md_name;

  if (num_in != 2)  /* For now, k should be specified by the caller.  */
    return gpg_error (GPG_ERR_INV_ARG);

  if (num_out != 2)
    return gpg_error (GPG_ERR_INV_ARG);

  curve = get_curve_name (h->ecc.curve);
  if (h->ecc.pk)
    err = sexp_build (&s_sk, NULL,
                      "(private-key"
                      " (ecc"
                      "  (curve %s)"
                      "  (q %b)"
                      "  (d %b)))", curve,
                      (int)h->ecc.pk_len, h->ecc.pk,
                      (int)h->ecc.sk_len, h->ecc.sk);
  else
    err = sexp_build (&s_sk, NULL,
                      "(private-key"
                      " (ecc"
                      "  (curve %s)"
                      "  (d %b)))", curve,
                      (int)h->ecc.sk_len, h->ecc.sk);
  if (err)
    return err;

  md_name = _gcry_md_algo_name (h->ecc.md_algo);

  if ((h->flags & GCRY_PKEY_FLAG_PREHASH))
    err = sexp_build (&s_msg, NULL,
                      "(data"
                      " (flags raw prehash)"
                      " (label %b)"
                      " (hash-algo %s)"
                      " (value %b))",
		      (int)in_len[1], in[1],
		      md_name, (int)in_len[0], in[0]);
  else
    err = sexp_build (&s_msg, NULL,
                      "(data "
		      " (label %b)"
		      " (value %b))", (int)in_len[1], in[1],
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

  out[0] = out[1] = NULL;
  s_tmp2 = NULL;
  s_tmp = sexp_find_token (s_sig, "sig-val", 0);
  if (s_tmp)
    {
      s_tmp2 = s_tmp;
      s_tmp = sexp_find_token (s_tmp2, "ecdsa", 0);
      if (s_tmp)
        {
          sexp_release (s_tmp2);
          s_tmp2 = s_tmp;
          s_tmp = sexp_find_token (s_tmp2, "r", 0);
          if (s_tmp)
            {
              const char *p;
              size_t n;

              out_len[0] = h->ecc.sk_len;
              out[0] = xtrymalloc (h->ecc.sk_len);
              if (!out[0])
                {
                  err = gpg_error_from_syserror ();
                  sexp_release (s_tmp);
                  sexp_release (s_tmp2);
                  return err;
                }

              p = sexp_nth_data (s_tmp, 1, &n);
              if (n == h->ecc.sk_len)
                memcpy (out[0], p, h->ecc.sk_len);
              else
                {
                  memset (out[0], 0, h->ecc.sk_len - n);
                  memcpy (out[0] + h->ecc.sk_len - n, p, n);
                }
              sexp_release (s_tmp);
            }
          s_tmp = sexp_find_token (s_tmp2, "s", 0);
          if (s_tmp)
            {
              const char *p;
              size_t n;

              out_len[1] = h->ecc.sk_len;
              out[1] = xtrymalloc (h->ecc.sk_len);
              if (!out[1])
                {
                  err = gpg_error_from_syserror ();
                  sexp_release (s_tmp);
                  sexp_release (s_tmp2);
                  return err;
                }

              p = sexp_nth_data (s_tmp, 1, &n);
              if (n == h->ecc.sk_len)
                memcpy (out[1], p, h->ecc.sk_len);
              else
                {
                  memset (out[1], 0, h->ecc.sk_len - n);
                  memcpy (out[1] + h->ecc.sk_len - n, p, n);
                }
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
_gcry_pkey_nist_verify (gcry_pkey_hd_t h,
			int num_in, const unsigned char *const in[],
			const size_t in_len[])
{
  gcry_error_t err = 0;
  gcry_sexp_t s_pk = NULL;
  gcry_sexp_t s_msg= NULL;
  gcry_sexp_t s_sig= NULL;
  const char *curve;
  const char *md_name;

  if (num_in != 4)  /* For now, k should be specified by the caller.  */
    return gpg_error (GPG_ERR_INV_ARG);

  curve = get_curve_name (h->ecc.curve);
  err = sexp_build (&s_pk, NULL,
		    "(public-key"
		    " (ecc"
		    "  (curve %s)"
		    "  (q %b)))", curve,
		    (int)h->ecc.pk_len, h->ecc.pk);
  if (err)
    return err;

  md_name = _gcry_md_algo_name (h->ecc.md_algo);

  if ((h->flags & GCRY_PKEY_FLAG_PREHASH))
    err = sexp_build (&s_msg, NULL,
                      "(data"
                      " (flags raw prehash)"
                      " (label %b)"
                      " (hash-algo %s)"
                      " (value %b))",
		      (int)in_len[1], in[1],
		      md_name, (int)in_len[0], in[0]);
  else
    err = sexp_build (&s_msg, NULL,
                      "(data "
		      " (label %b)"
		      " (value %b))", (int)in_len[1], in[1],
		      (int)in_len[0], in[0]);
  if (err)
    {
      sexp_release (s_pk);
      return err;
    }

  err = sexp_build (&s_sig, NULL,
                    "(sig-val(ecdsa(r %b)(s %b)))",
                    (int)in_len[2], in[2],
                    (int)in_len[3], in[3]);
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
