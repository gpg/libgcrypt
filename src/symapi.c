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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "g10lib.h"
#include "cipher.h"


#define CONTEXT_MAGIC = 0x12569afe;

struct gcry_cipher_context {
    u32 magic;
    unsigned flags;
    CIPHER_HD *hd;
};


GCRY_CIPHER_HD
gcry_cipher_open( int algo, int mode, unsigned flags )
{
    GCRY_CIPHER_HD hd;

    hd = m_lib_alloc_clear( sizeof *hd );
    if( !hd ) {
	set_lasterr( GCRYERR_NOMEM );
	return NULL;
    }

    /* check whether the algo is available */

    /* setup a context */

    /* return the handle */
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

int  gcry_cipher_ctl( GCRY_CIPHER_HD h, int cmd, byte *buffer, size_t buflen)
{
}

