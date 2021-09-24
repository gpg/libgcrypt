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
#include "mpi.h"
#include "mpi-internal.h"
#include "ec-context.h"
#include "gcrypt-int.h"
#include "cipher.h"
#include "context.h"
#include "pubkey-internal.h"
#include "ecc-common.h"
#include "pkey-internal.h"

static const char *
get_curve_name (int curve)
{
  switch (curve)
    {
    case GCRY_PKEY_CURVE_NIST_P192:
      return "nistp192";
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


gcry_error_t
_gcry_pkey_nist_ecdh (gcry_pkey_hd_t h,
		      int num_in, const unsigned char *const in[],
		      const size_t in_len[],
		      int num_out, unsigned char *out[], size_t out_len[])
{
  gpg_err_code_t errc;
  gcry_error_t err = 0;
  const char *curve;
  int flags = 0;
  unsigned int nbits;
  elliptic_curve_t E;
  mpi_ec_t ec;
  mpi_point_struct kG;
  mpi_point_struct R;
  gcry_mpi_t x, y;
  size_t n;

  if (num_in != 2)
    return gpg_error (GPG_ERR_INV_ARG);

  if (num_out != 1 && num_out != 2)
    return gpg_error (GPG_ERR_INV_ARG);

  curve = get_curve_name (h->ecc.curve);

  memset (&E, 0, sizeof E);
  errc = _gcry_ecc_fill_in_curve (0, curve, &E, &nbits);
  if (errc)
    return gpg_error (errc);

  ec = _gcry_mpi_ec_p_internal_new (E.model, E.dialect, flags, E.p, E.a, E.b);
  if (!ec)
    {
      _gcry_ecc_curve_free (&E);
      return gpg_error (GPG_ERR_INV_CURVE);
    }

  ec->G = mpi_point_snatch_set (NULL, E.G.x, E.G.y, E.G.z);
  E.G.x = NULL;
  E.G.y = NULL;
  E.G.z = NULL;
  ec->n = E.n;
  E.n = NULL;
  ec->h = E.h;
  ec->name = E.name;
  ec->Q = _gcry_mpi_point_new (nbits);
  _gcry_mpi_scan (&ec->d, GCRYMPI_FMT_USG, h->ecc.sk, h->ecc.sk_len, NULL);
  _gcry_ecc_curve_free (&E);

  if (h->ecc.pk)
    {
      size_t n = h->ecc.pk_len;

      if (n < 1 || h->ecc.pk[0] != 0x04 || ((n - 1) % 2))
	{
	  _gcry_mpi_ec_free (ec);
	  return gpg_error (GPG_ERR_INV_OBJ);
	}

      n = (n - 1)/2;
      mpi_free (ec->Q->x);
      ec->Q->x = NULL;
      mpi_free (ec->Q->y);
      ec->Q->y = NULL;
      _gcry_mpi_scan (&ec->Q->x, GCRYMPI_FMT_USG, h->ecc.pk+1, n, NULL);
      _gcry_mpi_scan (&ec->Q->y, GCRYMPI_FMT_USG, h->ecc.pk+1+n, n, NULL);
      mpi_set_ui (ec->Q->z, 1);
    }
  else
    {
      /* FIXME: compute ec->Q by [ec->d] ec->G.  */
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }

  if (err)
    {
      _gcry_mpi_ec_free (ec);
      return err;
    }

  _gcry_mpi_scan (&kG.x, GCRYMPI_FMT_USG, in[0], in_len[0], NULL);
  _gcry_mpi_scan (&kG.y, GCRYMPI_FMT_USG, in[1], in_len[1], NULL);
  kG.z = mpi_new (0);
  mpi_set_ui (kG.z, 1);

  if (DBG_CIPHER)
    log_printpnt ("ecdh    kG", &kG, NULL);

  if (!_gcry_mpi_ec_curve_point (&kG, ec))
    {
      point_free (&kG);
      _gcry_mpi_ec_free (ec);
      return gpg_error (GPG_ERR_INV_DATA);
    }

  point_init (&R);

  /* R = dkG */
  _gcry_mpi_ec_mul_point (&R, ec->d, &kG, ec);

  point_free (&kG);

  x = mpi_new (0);
  y = mpi_new (0);
  if (_gcry_mpi_ec_get_affine (x, y, &R, ec))
    {
      mpi_free (x);
      mpi_free (y);
      point_free (&R);
      _gcry_mpi_ec_free (ec);
      return gpg_error (GPG_ERR_INV_DATA);
    }

  point_free (&R);
  _gcry_mpi_ec_free (ec);

  out[0] = xmalloc (h->ecc.sk_len);
  errc = _gcry_mpi_print (GCRYMPI_FMT_USG, out[0], h->ecc.sk_len, &n, x);
  if (n < h->ecc.sk_len)
    {
      memmove (out[0] + h->ecc.sk_len - n, out[0], n);
      memset (out[0], 0, h->ecc.sk_len - n);
    }
  out_len[0] = h->ecc.sk_len;

  mpi_free (x);

  if (num_out == 2)
    {
      out[1] = xmalloc (h->ecc.sk_len);
      errc = _gcry_mpi_print (GCRYMPI_FMT_USG, out[1], h->ecc.sk_len, &n, y);
      if (n < h->ecc.sk_len)
	{
	  memmove (out[1] + h->ecc.sk_len - n, out[1], n);
	  memset (out[1], 0, h->ecc.sk_len - n);
	}
      out_len[1] = h->ecc.sk_len;
    }

  mpi_free (y);

  return 0;
}
