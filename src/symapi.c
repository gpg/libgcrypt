/* symapi.c  -	symmetric cipher function interface
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

/* fixme: merge this function with ../cipher/cipher.c */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "g10lib.h"
#define G10_MPI_H  /* fake mpi.h header */
#include "cipher.h"


#define CONTEXT_MAGIC 0x12569afe

struct gcry_cipher_context {
    u32 magic;
    int mode;
    unsigned flags;
    CIPHER_HANDLE hd;
};


GCRY_CIPHER_HD
gcry_cipher_open( int algo, int mode, unsigned flags )
{
    GCRY_CIPHER_HD h;

    /* check whether the algo is available */
    if( check_cipher_algo( algo ) ) {
	set_lasterr( GCRYERR_INV_ALGO );
	return NULL;
    }
    /* check flags */
    if( (flags & ~(GCRY_CIPHER_SECURE|GCRY_CIPHER_ENABLE_SYNC)) ) {
	set_lasterr( GCRYERR_INV_ARG );
	return NULL;
    }

    /* map mode to internal mode */
    switch( mode ) {
      case GCRY_CIPHER_MODE_NONE: mode = CIPHER_MODE_DUMMY; break;
      case GCRY_CIPHER_MODE_ECB: mode = CIPHER_MODE_ECB; break;
      case GCRY_CIPHER_MODE_CFB:
	mode = (flags & GCRY_CIPHER_ENABLE_SYNC) ? CIPHER_MODE_PHILS_CFB
						 : CIPHER_MODE_CFB;
	break;
      default:
	set_lasterr( GCRYERR_INV_ALGO );
	return NULL;
    }

    /* allocate the handle */
    h = m_lib_alloc_clear( sizeof *h );
    if( !h ) {
	set_lasterr( GCRYERR_NOMEM );
	return NULL;
    }
    h->magic = CONTEXT_MAGIC;
    h->mode = mode;
    h->hd = cipher_open( algo, mode, (flags & GCRY_CIPHER_SECURE) );
    if( !h ) {
	m_lib_free( h );
	set_lasterr( GCRYERR_INTERNAL );
	return NULL;
    }

    return h;
}


void
gcry_cipher_close( GCRY_CIPHER_HD h )
{
    if( !h )
	return;
    if( h->magic != CONTEXT_MAGIC )  {
	fatal_invalid_arg("gcry_cipher_close: already closed/invalid handle");
	return;
    }
    cipher_close( h->hd );
    h->magic = 0;
    m_lib_free(h);
}

int gcry_cipher_ctl( GCRY_CIPHER_HD h, int cmd, byte *buffer, size_t buflen)
{
    switch( cmd ) {
      case GCRYCTL_SET_KEY:
	cipher_setkey( h->hd, buffer, buflen );
	break;
      case GCRYCTL_SET_IV:
	cipher_setiv( h->hd, buffer );
	break;
      case GCRYCTL_CFB_SYNC:
	cipher_sync( h->hd );
      default:
	return set_lasterr( GCRYERR_INV_OP );
    }
    return 0;
}


int
gcry_cipher_encrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				       byte  *in, size_t inlen )
{
    if( outsize < inlen )
	return set_lasterr( GCRYERR_TOO_SHORT );
    cipher_encrypt( h->hd, out, in, inlen );
    return 0;
}

int
gcry_cipher_decrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				       byte  *in, size_t inlen )
{
    if( outsize < inlen )
	return set_lasterr( GCRYERR_TOO_SHORT );
    cipher_decrypt( h->hd, out, in, inlen );
    return 0;
}

