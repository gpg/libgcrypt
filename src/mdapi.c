/* mdapi.c  -  message digest function interface
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

#define GCRYPT_NO_MPI_MACROS 1
#include "g10lib.h"
#include "cipher.h"
#include "memory.h"


GCRY_MD_HD
gcry_md_open( GCRY_MD_HD *ret_hd, int algo, unsigned int flags )
{
    /* fixme: check that algo is available and that only valid
     * flag values are used */
    hd = md_open( algo, (flags & GCRY_MD_FLAG_SECURE) );
    return hd;
}

void
gcry_md_close( GCRY_MD_HD hd )
{
    md_close( hd );
}

int
gcry_md_enable( GCRY_MD_HD hd, int algo )
{
    /* fixme: check that algo is available */
    md_enable( hd, algo );
    return 0;
}

GCRY_MD_HD
gcry_md_copy( GCRY_MD_HD hd )
{
    return md_copy( hd );
}

int
gcry_md_ctl( GCRY_MD_HD hd, int cmd, byte *buffer, size_t buflen)
{
    if( cmd == GCRYCTL_FINALIZE )
	md_final( hd );
    else
	return GCRYERR_INV_OP;
    return 0;
}

void
gcry_md_write( GCRY_MD_HD hd, const byte *inbuf, size_t inlen)
{
    md_write( hd, (byte*)inbuf, inlen );
}

/****************
 * Read out the complete digest, this function implictly finalizes
 * the hash.
 */
byte *
gcry_md_read( GCRY_MD_HD hd, int algo )
{
    gcry_md_ctl( hd, GCRYCTL_FINALIZE, NULL, 0 );
    return md_read( hd, algo);
}

int
gcry_md_get_algo( GCRY_MD_HD hd )
{
    return md_get_algo( hd ); /* fixme: we need error handling */
}

/****************
 * Return the length of the digest in bytes.
 * This function will return 0 in case of errors.
 */
unsigned int
gcry_md_get_algo_dlen( int algo )
{
    /* we do some very quick checks here */
    switch( algo )
    {
      case GCRY_MD_MD5: return 16;
      case GCRY_MD_SHA1:
      case GCRY_MD_RMD160: return 20;
      default:
	/* fixme: pass it to a lookup function */
	set_lasterr( GCRYERR_INV_ALGO );
	return -1;
    }
}


/****************
 * Read out an intermediate digest.
 */
int
gcry_md_get( GCRY_MD_HD hd, int algo, byte *buffer, int buflen )
{
    return GCRYERR_INTERNAL;
}



