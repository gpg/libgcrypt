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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
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

gpg_error_t
_gcry_ecc_mul_point (int algo, unsigned char *result,
		     const unsigned char *scalar, const unsigned char *point)
{
  if (algo != GCRY_ECC_CURVE25519)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}
