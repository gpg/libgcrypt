/* pkapi.c  -  public key function interface
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "g10lib.h"






int
gcry_pk_encrypt( GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP pkey )
{
	/* ... */
    return 0;
}

int
gcry_pk_decrypt( GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP skey )
{
	/* ... */
    return 0;
}

int
gcry_pk_sign( GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP skey )
{
    GCRY_SEXP s;
    /* get the secret key */
    s = gcry_sexp_find_token( skey, "private-key", 0 );
    if( !s )
	return -1; /* no private key */
	/* ... */
    return 0;
}

int
gcry_pk_verify( GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP pkey )
{
	/* ... */
    return 0;
}

