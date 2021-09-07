/* pkey.c  -	pubric key cryptography API
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
  int curve;
  unsigned char *pk;
  unsigned char *sk;

  if (algo == GCRY_PKEY_ECC)
    ;
  else if (algo == GCRY_PKEY_RSA)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else if (algo == GCRY_PKEY_DSA)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else if (algo == GCRY_PKEY_ELG)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else
    err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
  if (err)
    return err;

  if (!(h = xtrycalloc (1, sizeof (struct gcry_pkey_handle))))
    return gpg_err_code_from_syserror ();

  h->algo = algo;
  h->flags = flags;

  /* For now, it's GCRY_PKEY_ECC only.  */
  curve = va_arg (arg_ptr, int);
  if (curve == GCRY_PKEY_CURVE_ED25519)
    ;
  else if (curve == GCRY_PKEY_CURVE_ED448)
    ;
  else
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  if (err)
    {
      xfree (h);
      return err;
    }

  h->curve = curve;

  *h_p = h;

  if (!(flags & GCRY_PKEY_FLAG_SECRET))
    {
      pk = va_arg (arg_ptr, unsigned char *);
      h->pk_len = va_arg (arg_ptr, size_t);
      h->sk = sk = NULL;
      h->sk_len = 0;
    }
  else
    {
      pk = va_arg (arg_ptr, unsigned char *);
      h->pk_len = va_arg (arg_ptr, size_t);
      sk = va_arg (arg_ptr, unsigned char *);
      h->sk_len = va_arg (arg_ptr, size_t);
    }

  if (err)
    {
      xfree (h);
      return err;
    }

  if (pk)
    {
      h->pk = xtrymalloc (h->pk_len);
      if (!h->pk)
        {
          err = gpg_err_code_from_syserror ();
          xfree (h);
          return err;
        }
      memcpy (h->pk, pk, h->pk_len);
    }
  else
    h->pk = NULL;

  if (sk)
    {
      h->sk = xtrymalloc_secure (h->sk_len);
      if (!h->sk)
        {
          err = gpg_err_code_from_syserror ();
          xfree (h->pk);
          xfree (h);
          return err;
        }
      memcpy (h->sk, sk, h->sk_len);
    }

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

  /* Just for Ed25519 and Ed448 for now.  Will support more...  */
  if (h->algo == GCRY_PKEY_ECC)
    {
      if (h->curve == GCRY_PKEY_CURVE_ED25519)
        {
          if (cmd == GCRY_PKEY_OP_SIGN)
            err = _gcry_pkey_ed25519_sign (h, num_in, in, in_len,
                                           num_out, out, out_len);
          else if (cmd == GCRY_PKEY_OP_VERIFY)
            err = _gcry_pkey_ed25519_verify (h, num_in, in, in_len);
          else
            err = gpg_error (GPG_ERR_INV_OP);
        }
      else if (h->curve == GCRY_PKEY_CURVE_ED448)
        {
          if (cmd == GCRY_PKEY_OP_SIGN)
            err = _gcry_pkey_ed448_sign (h, num_in, in, in_len,
                                         num_out, out, out_len);
          else if (cmd == GCRY_PKEY_OP_VERIFY)
            err = _gcry_pkey_ed448_verify (h, num_in, in, in_len);
          else
            err = gpg_error (GPG_ERR_INV_OP);
        }
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
      xfree (h->sk);
      xfree (h->pk);
      xfree (h);
    }
}
