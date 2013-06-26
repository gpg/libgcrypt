/* gcrypt-int.h - Internal version of gcrypt.h
 * Copyright (C) 2013 g10 Code GmbH
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

#ifndef GCRY_GCRYPT_INT_H
#define GCRY_GCRYPT_INT_H

#ifdef _GCRYPT_H
#error  gcrypt.h already included
#endif

#include "gcrypt.h"

/* These error codes are used but not defined in the required
   libgpg-error 1.11.  Define them here. */
#ifndef GPG_ERR_NO_CRYPT_CTX
# define GPG_ERR_NO_CRYPT_CTX	    191
# define GPG_ERR_WRONG_CRYPT_CTX    192
# define GPG_ERR_BAD_CRYPT_CTX	    193
# define GPG_ERR_CRYPT_CTX_CONFLICT 194
# define GPG_ERR_BROKEN_PUBKEY      195
# define GPG_ERR_BROKEN_SECKEY      196
#endif

#endif /*GCRY_GCRYPT_INT_H*/
