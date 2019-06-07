/* ecc-ecdh.c  -  Elliptic Curve Diffie-Hellman key agreement
 * Copyright (C) 2019 g10 Code GmbH
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
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
#include <errno.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "context.h"
#include "ec-context.h"
#include "ecc-common.h"

#define ECC_CURVE25519_BITS 256

static mpi_ec_t
prepare_ec (const char *curve_name, elliptic_curve_t *E)
{
  mpi_ec_t ec;

  memset (E, 0, sizeof *E);
  if (_gcry_ecc_fill_in_curve (0, curve_name, E, NULL))
    return NULL;

  ec = _gcry_mpi_ec_p_internal_new (E->model, E->dialect,
                                    PUBKEY_FLAG_DJB_TWEAK, E->p, E->a, E->b);
  return ec;
}


gpg_error_t
_gcry_ecc_mul_point (int algo, unsigned char **r_result,
                     const unsigned char *scalar, const unsigned char *point)
{
  if (algo != GCRY_ECC_CURVE25519)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else
    {
      gpg_err_code_t err;
      elliptic_curve_t E;
      unsigned char buffer[ECC_CURVE25519_BITS/8];
      gcry_mpi_t mpi_k = mpi_new (ECC_CURVE25519_BITS);
      mpi_ec_t ec = prepare_ec ("Curve25519", &E);
      gcry_mpi_t mpi_u = mpi_new (ECC_CURVE25519_BITS);
      mpi_point_t P = mpi_point_new (ECC_CURVE25519_BITS);
      mpi_point_t Q = mpi_point_new (ECC_CURVE25519_BITS);
      gcry_mpi_t x = mpi_new (ECC_CURVE25519_BITS);
      unsigned int len;
      int i;

      memcpy (buffer, scalar, ECC_CURVE25519_BITS/8);
      reverse_buffer (buffer, ECC_CURVE25519_BITS/8);
      _gcry_mpi_set_buffer (mpi_k, buffer, ECC_CURVE25519_BITS/8, 0);

      for (i = 0; i < mpi_get_nbits (E.h) - 1; i++)
        mpi_clear_bit (mpi_k, i);
      mpi_set_highbit (mpi_k, mpi_get_nbits (E.p) - 1);

      _gcry_mpi_set_buffer (mpi_u, point, ECC_CURVE25519_BITS/8, 0);

      err = _gcry_ecc_mont_decodepoint (mpi_u, ec, P);
      _gcry_mpi_release (mpi_u);
      if (err)
        goto leave;

      _gcry_mpi_ec_mul_point (Q, mpi_k, P, ec);
      _gcry_mpi_ec_get_affine (x, NULL, Q, ec);

      *r_result = _gcry_mpi_get_buffer (x, ECC_CURVE25519_BITS/8, &len, NULL);
      if (!*r_result)
        err = gpg_error_from_syserror ();

    leave:
      _gcry_mpi_release (x);
      _gcry_mpi_point_release (Q);
      _gcry_mpi_point_release (P);
      _gcry_mpi_release (mpi_k);
      return err;
    }
}
