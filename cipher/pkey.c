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

struct gcry_pkey_handle {
  int algo;
  unsigned int flags;

  /* FIXME: Use of union would be better, here.  */

  int curve;

  unsigned char *pk;
  size_t pk_len;

  unsigned char *sk;
  size_t sk_len;
};

gcry_error_t
_gcry_pkey_vopen (gcry_pkey_hd_t *h_p, int algo, unsigned int flags,
                  va_list arg_ptr)
{
  gcry_error_t err = 0;
  gcry_pkey_hd_t h;
  int curve;
  unsigned char *pk;
  size_t pk_len;
  unsigned char *sk;
  size_t sk_len;

  if (algo == GCRY_PKEY_RSA)
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

  /* For now, it's GCRY_PKEY_ECC.  */
  curve = va_arg (arg_ptr, int);
  if (curve != GCRY_PKEY_CURVE_ED25519)
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
      pk_len = va_arg (arg_ptr, size_t);
      h->sk = sk = NULL;
      h->sk_len = sk_len = 0;
    }
  else
    {
      pk = va_arg (arg_ptr, unsigned char *);
      pk_len = va_arg (arg_ptr, size_t);
      sk = va_arg (arg_ptr, unsigned char *);
      sk_len = va_arg (arg_ptr, size_t);
      /* FIXME: PK is required for now.  */
      if (!pk)
        err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }

  if (err)
    {
      xfree (h);
      return err;
    }

  h->pk = xtrymalloc (pk_len);
  if (h->pk)
    {
      err = gpg_err_code_from_syserror ();
      xfree (h);
      return err;
    }
  memcpy (h->pk, pk, pk_len);

  if (sk)
    {
      h->sk = xtrymalloc_secure (pk_len);
      if (h->sk)
        {
          err = gpg_err_code_from_syserror ();
          xfree (h->pk);
          xfree (h);
          return err;
        }
      memcpy (h->sk, sk, sk_len);
    }

  return err;
}

gcry_error_t
_gcry_pkey_ctl (gcry_pkey_hd_t h, int cmd, void *buffer, size_t buflen)
{
  gcry_error_t err = 0;

  (void)h;   (void)buffer;  (void)buflen;
  /* FIXME: Not yet implemented anything.  */
  return err;
}

gcry_error_t
_gcry_pkey_op (gcry_pkey_hd_t h, int cmd,
               int num_in, const unsigned char *const in[],
               const size_t in_len[],
               int num_out, unsigned char *out[], size_t out_len[])
{
  gcry_error_t err = 0;

  return err;
}

void
_gcry_pkey_close (gcry_pkey_hd_t h)
{
  xfree (h->sk);
  xfree (h->pk);
  xfree (h);
}
