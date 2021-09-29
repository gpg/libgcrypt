/* pkey.c  -    Pubric key cryptography API
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
_gcry_pkey_vopen (gcry_pkey_hd_t *h_p, int algo, unsigned int flags,
                  va_list arg_ptr)
{
  gcry_error_t err = 0;
  gcry_pkey_hd_t h;

  if (algo == GCRY_PKEY_ECC || algo == GCRY_PKEY_RSA || algo == GCRY_PKEY_DSA)
    ;
  else if (algo == GCRY_PKEY_ELG)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else
    err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
  if (err)
    return err;

  if (!(h = xtrycalloc (1, sizeof (struct gcry_pkey_handle))))
    return gpg_error_from_syserror ();

  h->algo = algo;
  h->flags = flags;

  if (algo == GCRY_PKEY_ECC)
    {
      int curve;
      unsigned char *pk;
      unsigned char *sk;

      curve = va_arg (arg_ptr, int);
      if (curve == GCRY_PKEY_CURVE_ED25519 || curve == GCRY_PKEY_CURVE_ED448)
        h->ecc.md_algo = 0;
      else if (curve == GCRY_PKEY_CURVE_NIST_P192
	       || curve == GCRY_PKEY_CURVE_NIST_P224
	       || curve == GCRY_PKEY_CURVE_NIST_P256
	       || curve == GCRY_PKEY_CURVE_NIST_P384
	       || curve == GCRY_PKEY_CURVE_NIST_P521)
	h->ecc.md_algo = va_arg (arg_ptr, int);
      else
        err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      if (err)
        {
          xfree (h);
          return err;
        }

      h->ecc.curve = curve;

      if (h->ecc.md_algo)
	{	/* NIST curves */
	  unsigned char *x, *y;
	  size_t x_len, y_len;

	  x = va_arg (arg_ptr, unsigned char *);
	  x_len = va_arg (arg_ptr, size_t);
	  y = va_arg (arg_ptr, unsigned char *);
	  y_len = va_arg (arg_ptr, size_t);

	  if (x && y)
	    {
	      h->ecc.pk_len = 1 + x_len + y_len;
	      h->ecc.pk = xtrymalloc (h->ecc.pk_len);
	      if (!h->ecc.pk)
		{
		  err = gpg_error_from_syserror ();
		  xfree (h);
		  return err;
		}

	      h->ecc.pk[0] = 0x04;
	      memcpy (h->ecc.pk+1, x, x_len);
	      memcpy (h->ecc.pk+1+x_len, y, y_len);
	    }
	  else
	    h->ecc.pk = NULL;
	}
      else
	{	/* Modern curves */
	  pk = va_arg (arg_ptr, unsigned char *);
	  h->ecc.pk_len = va_arg (arg_ptr, size_t);

	  if (pk)
	    {
	      h->ecc.pk = xtrymalloc (h->ecc.pk_len);
	      if (!h->ecc.pk)
		{
		  err = gpg_error_from_syserror ();
		  xfree (h);
		  return err;
		}
	      memcpy (h->ecc.pk, pk, h->ecc.pk_len);
	    }
	  else
	    h->ecc.pk = NULL;
	}

      if (!(flags & GCRY_PKEY_FLAG_SECRET))
        {
          h->ecc.sk = sk = NULL;
          h->ecc.sk_len = 0;
        }
      else
        {
          sk = va_arg (arg_ptr, unsigned char *);
          h->ecc.sk_len = va_arg (arg_ptr, size_t);
        }

      if (sk)
        {
          h->ecc.sk = xtrymalloc_secure (h->ecc.sk_len);
          if (!h->ecc.sk)
            {
              err = gpg_error_from_syserror ();
              xfree (h->ecc.pk);
              xfree (h);
              return err;
            }
          memcpy (h->ecc.sk, sk, h->ecc.sk_len);
        }
    }
  else if (algo == GCRY_PKEY_RSA)
    {
      int scheme;
      int md_algo;
      unsigned char *n;
      unsigned char *e;
      unsigned char *d;

      scheme = va_arg (arg_ptr, int);
      if (scheme == GCRY_PKEY_RSA_PSS)
        ;
      else if (scheme == GCRY_PKEY_RSA_15)
        ;
      else if (scheme == GCRY_PKEY_RSA_931)
        ;
      else
        err = gpg_error (GPG_ERR_INV_ARG);
      if (err)
        {
          xfree (h);
          return err;
        }

      h->rsa.scheme = scheme;

      md_algo = va_arg (arg_ptr, int);
      h->rsa.md_algo = md_algo;

      n = va_arg (arg_ptr, unsigned char *);
      h->rsa.n_len = va_arg (arg_ptr, size_t);
      e = va_arg (arg_ptr, unsigned char *);
      h->rsa.e_len = va_arg (arg_ptr, size_t);

      if (!(flags & GCRY_PKEY_FLAG_SECRET))
        {
          h->rsa.d = d = NULL;
          h->rsa.d_len = 0;
        }
      else
        {
          d = va_arg (arg_ptr, unsigned char *);
          h->rsa.d_len = va_arg (arg_ptr, size_t);
        }

      if (err)
        {
          xfree (h);
          return err;
        }

      if (n)
        {
          h->rsa.n = xtrymalloc (h->rsa.n_len);
          if (!h->rsa.n)
            {
              err = gpg_error_from_syserror ();
              xfree (h);
              return err;
            }
          memcpy (h->rsa.n, n, h->rsa.n_len);
        }
      else
        h->rsa.n = NULL;

      if (e)
        {
          h->rsa.e = xtrymalloc (h->rsa.e_len);
          if (!h->rsa.e)
            {
              err = gpg_error_from_syserror ();
              xfree (h);
              return err;
            }
          memcpy (h->rsa.e, e, h->rsa.e_len);
        }
      else
        h->rsa.e = NULL;

      if (d)
        {
          h->rsa.d = xtrymalloc (h->rsa.d_len);
          if (!h->rsa.d)
            {
              err = gpg_error_from_syserror ();
              xfree (h);
              return err;
            }
          memcpy (h->rsa.d, d, h->rsa.d_len);
        }
    }
  else if (algo == GCRY_PKEY_DSA)
    {
      int md_algo;
      unsigned char *p;
      unsigned char *q;
      unsigned char *g;
      unsigned char *x;
      unsigned char *y;

      md_algo = va_arg (arg_ptr, int);
      h->dsa.md_algo = md_algo;

      p = va_arg (arg_ptr, unsigned char *);
      h->dsa.p_len = va_arg (arg_ptr, size_t);
      q = va_arg (arg_ptr, unsigned char *);
      h->dsa.q_len = va_arg (arg_ptr, size_t);
      g = va_arg (arg_ptr, unsigned char *);
      h->dsa.g_len = va_arg (arg_ptr, size_t);

      y = va_arg (arg_ptr, unsigned char *);
      h->dsa.y_len = va_arg (arg_ptr, size_t);
      if (!(flags & GCRY_PKEY_FLAG_SECRET))
        {
          h->dsa.x = x = NULL;
          h->dsa.x_len = 0;
        }
      else
        {
          x = va_arg (arg_ptr, unsigned char *);
          h->dsa.x_len = va_arg (arg_ptr, size_t);
        }

      if (err)
        {
          xfree (h);
          return err;
        }

      if (p)
        {
          h->dsa.p = xtrymalloc (h->dsa.p_len);
          if (!h->dsa.p)
            {
              err = gpg_error_from_syserror ();
              xfree (h);
              return err;
            }
          memcpy (h->dsa.p, p, h->dsa.p_len);
        }
      else
        h->dsa.p = NULL;

      if (q)
        {
          h->dsa.q = xtrymalloc (h->dsa.q_len);
          if (!h->dsa.q)
            {
              err = gpg_error_from_syserror ();
              xfree (h);
              return err;
            }
          memcpy (h->dsa.q, q, h->dsa.q_len);
        }
      else
        h->dsa.q = NULL;

      if (g)
        {
          h->dsa.g = xtrymalloc (h->dsa.g_len);
          if (!h->dsa.g)
            {
              err = gpg_error_from_syserror ();
              xfree (h);
              return err;
            }
          memcpy (h->dsa.g, g, h->dsa.g_len);
        }
      else
        h->dsa.g = NULL;

      if (y)
        {
          h->dsa.y = xtrymalloc (h->dsa.y_len);
          if (!h->dsa.y)
            {
              err = gpg_error_from_syserror ();
              xfree (h);
              return err;
            }
          memcpy (h->dsa.y, y, h->dsa.y_len);
        }
      else
        h->dsa.y = NULL;

      if (x)
        {
          h->dsa.x = xtrymalloc (h->dsa.x_len);
          if (!h->dsa.x)
            {
              err = gpg_error_from_syserror ();
              xfree (h);
              return err;
            }
          memcpy (h->dsa.x, x, h->dsa.x_len);
        }
    }

  *h_p = h;

  return err;
}

gcry_error_t
_gcry_pkey_ctl (gcry_pkey_hd_t h, int cmd, void *buffer, size_t buflen)
{
  gcry_error_t err = 0;

  (void)h;  (void)cmd;  (void)buffer;  (void)buflen;
  /* FIXME: Not yet implemented anything.  */
  return err;
}

/* For now, it uses SEXP implementation, because the purpose is
   to test the API (but not the implementation).
   Will be rewritten soon.

  Currently, it's like:

  [ gcry_pkey_op API (with binary data) ]
          |
  [ gcry_pk_ API (with SEXP) ]
          |
  [ lower level public key implementations (with SEXP) ]

  It will be like:

  [ gcry_pk_ API with SEXP ]    [ gcry_pkey_op API with binary data ]
          |                                    |
        [ lower level public key implementations ]

  That is, lower level public key implementations won't have any
  (direct) handling of SEXP.

  */
gcry_error_t
_gcry_pkey_op (gcry_pkey_hd_t h, int cmd,
               int num_in, const unsigned char *const in[],
               const size_t in_len[],
               int num_out, unsigned char *out[], size_t out_len[])
{
  gcry_error_t err = 0;

  if (h->algo == GCRY_PKEY_ECC)
    {
      if (h->ecc.curve == GCRY_PKEY_CURVE_ED25519)
        {
          if (cmd == GCRY_PKEY_OP_SIGN)
            err = _gcry_pkey_ed25519_sign (h, num_in, in, in_len,
                                           num_out, out, out_len);
          else if (cmd == GCRY_PKEY_OP_VERIFY)
            err = _gcry_pkey_ed25519_verify (h, num_in, in, in_len);
          else
            err = gpg_error (GPG_ERR_INV_OP);
        }
      else if (h->ecc.curve == GCRY_PKEY_CURVE_ED448)
        {
          if (cmd == GCRY_PKEY_OP_SIGN)
            err = _gcry_pkey_ed448_sign (h, num_in, in, in_len,
                                         num_out, out, out_len);
          else if (cmd == GCRY_PKEY_OP_VERIFY)
            err = _gcry_pkey_ed448_verify (h, num_in, in, in_len);
          else
            err = gpg_error (GPG_ERR_INV_OP);
        }
      else if (h->ecc.curve == GCRY_PKEY_CURVE_NIST_P192
	       || h->ecc.curve == GCRY_PKEY_CURVE_NIST_P224
	       || h->ecc.curve == GCRY_PKEY_CURVE_NIST_P256
	       || h->ecc.curve == GCRY_PKEY_CURVE_NIST_P384
	       || h->ecc.curve == GCRY_PKEY_CURVE_NIST_P521)
        {
          if (cmd == GCRY_PKEY_OP_SIGN)
            err = _gcry_pkey_nist_sign (h, num_in, in, in_len,
					num_out, out, out_len);
          else if (cmd == GCRY_PKEY_OP_VERIFY)
            err = _gcry_pkey_nist_verify (h, num_in, in, in_len);
          else if (cmd == GCRY_PKEY_OP_ECDH)
            err = _gcry_pkey_nist_ecdh (h, num_in, in, in_len,
					num_out, out, out_len);
          else
            err = gpg_error (GPG_ERR_INV_OP);
        }
      else
        err = gpg_error (GPG_ERR_INV_OP);
    }
  else if (h->algo == GCRY_PKEY_RSA)
    {
      if (cmd == GCRY_PKEY_OP_DECRYPT)
	{
	  /* FIXME: For now, only support raw encoding.  */
	  err = _gcry_pkey_rsa_dec (h, num_in, in, in_len,
				    num_out, out, out_len);
	}
      else
	{
	  if (h->rsa.scheme == GCRY_PKEY_RSA_PSS)
	    {
	      if (cmd == GCRY_PKEY_OP_SIGN)
		err = _gcry_pkey_rsapss_sign (h, num_in, in, in_len,
					      num_out, out, out_len);
	      else if (cmd == GCRY_PKEY_OP_VERIFY)
		err = _gcry_pkey_rsapss_verify (h, num_in, in, in_len);
	      else
		err = gpg_error (GPG_ERR_INV_OP);
	    }
	  else if (h->rsa.scheme == GCRY_PKEY_RSA_15)
	    {
	      if (cmd == GCRY_PKEY_OP_SIGN)
		err = _gcry_pkey_rsa15_sign (h, num_in, in, in_len,
					     num_out, out, out_len);
	      else if (cmd == GCRY_PKEY_OP_VERIFY)
		err = _gcry_pkey_rsa15_verify (h, num_in, in, in_len);
	      else
		err = gpg_error (GPG_ERR_INV_OP);
	    }
	  else if (h->rsa.scheme == GCRY_PKEY_RSA_931)
	    {
	      if (cmd == GCRY_PKEY_OP_SIGN)
		err = _gcry_pkey_rsa931_sign (h, num_in, in, in_len,
					      num_out, out, out_len);
	      else if (cmd == GCRY_PKEY_OP_VERIFY)
		err = _gcry_pkey_rsa931_verify (h, num_in, in, in_len);
	      else
		err = gpg_error (GPG_ERR_INV_OP);
	    }
	  else
	    err = gpg_error (GPG_ERR_INV_OP);
	}
    }
  else if (h->algo == GCRY_PKEY_DSA)
    {
      if (cmd == GCRY_PKEY_OP_SIGN)
        err = _gcry_pkey_dsa_sign (h, num_in, in, in_len,
                                   num_out, out, out_len);
      else if (cmd == GCRY_PKEY_OP_VERIFY)
        err = _gcry_pkey_dsa_verify (h, num_in, in, in_len);
      else
        err = gpg_error (GPG_ERR_INV_OP);
    }
  else
    err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  return err;
}

void
_gcry_pkey_close (gcry_pkey_hd_t h)
{
  if (h)
    {
      if (h->algo == GCRY_PKEY_ECC)
        {
          xfree (h->ecc.pk);
          xfree (h->ecc.sk);
        }
      else if (h->algo == GCRY_PKEY_RSA)
        {
          xfree (h->rsa.n);
          xfree (h->rsa.e);
          xfree (h->rsa.d);
        }
      else if (h->algo == GCRY_PKEY_DSA)
        {
          xfree (h->dsa.p);
          xfree (h->dsa.q);
          xfree (h->dsa.g);
          xfree (h->dsa.x);
          xfree (h->dsa.y);
        }

      xfree (h);
    }
}
