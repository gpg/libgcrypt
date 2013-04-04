/* scrypt.h - Scrypt password-based key derivation function.
 *
 * This file is part of Libgcrypt.
 */

/* Adapted from the nettle, low-level cryptographics library for
 * libgcrypt by Christian Grothoff; original license:
 *
 * Copyright (C) 2012 Simon Josefsson
 *
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#ifndef SCRYPT_H_INCLUDED
#define SCRYPT_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include "g10lib.h"
#include "cipher.h"


/* Transform a passphrase into a suitable key of length KEYSIZE and
   store this key in the caller provided buffer KEYBUFFER.  The caller
   must provide PRFALGO which indicates the pseudorandom function to
   use: This shall be the algorithms id of a hash algorithm; it is
   used in HMAC mode.  SALT is a salt of length SALTLEN and ITERATIONS
   gives the number of iterations; implemented in 'kdf.c', used by
   scrypt.c */
gpg_err_code_t
pkdf2 (const void *passphrase, size_t passphraselen,
       int hashalgo,
       const void *salt, size_t saltlen,
       unsigned long iterations,
       size_t keysize, void *keybuffer);


gcry_err_code_t
scrypt (const uint8_t * passwd, size_t passwdlen,
	int subalgo,
	const uint8_t * salt, size_t saltlen,
	unsigned long iterations,
	size_t dkLen, uint8_t * DK);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_H_INCLUDED */
