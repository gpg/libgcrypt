/* global.c  -	global control functions
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

static int last_ec; /* fixme: make thread safe */


int
gcry_control( enum gcry_ctl_cmds cmd, ... )
{
    switch( cmd ) {
     #if 0
      case GCRYCTL_NO_MEM_IS_FATAL:
	break;
      case GCRYCTL_SET_FATAL_FNC:
	break;
     #endif
      case GCRYCTL_DUMP_RANDOM_STATS:
	random_dump_stats();
	break;

      case GCRYCTL_DUMP_SECMEM_STATS:
	secmem_dump_stats();
	break;

      default:
	return GCRYERR_INV_OP;
    }
    return 0;
}

int
gcry_errno()
{
    return last_ec;
}

const char*
gcry_strerror( int ec )
{
    const char *s;
    static char buf[20];

    if( ec == -1 )
	ec = gcry_errno();
  #define X(n,a) case GCRYERR_##n : s = a; break;
    switch( ec ) {
      X(SUCCESS,	N_("no error"))
      X(GENERAL,	N_("general error"))
      X(INV_OP, 	N_("invalid operation code or ctl command"))
      X(NOMEM,		N_("out of core"))
      X(INV_ARG,	N_("invalid argument"))
      X(INTERNAL,	N_("internal error"))
      X(EOF,		N_("EOF"))
      X(TOO_SHORT,	N_("provided buffer too short"))
      X(TOO_LARGE,	N_("object is too large"))
      X(INV_OBJ,	N_("an object is not valid"))
      X(WEAK_KEY,	N_("weak encryption key"))
      X(INV_PK_ALGO,	N_("invalid public key algorithm"))
      X(INV_CIPHER_ALGO,N_("invalid cipher algorithm"))
      X(INV_MD_ALGO,	N_("invalid hash algorithm"))
      X(WRONG_PK_ALGO,	N_("unusable public key algorithm"))
      default:
	sprintf( buf, "ec=%d", ec );
	s = buf;
    }
  #undef X
    return s;
}


int
set_lasterr( int ec )
{
    if( ec )
	last_ec = ec == -1 ? GCRYERR_EOF : ec;
    return ec;
}

void
g10_free( void *p )
{
    if( p )
	m_free(p);
}

void *
g10_malloc( size_t n )
{
    return m_alloc( n );
}

void *
g10_malloc_secure( size_t n )
{
    return m_alloc_secure( n );
}

void *
g10_calloc( size_t n, size_t m )
{
    void *p = g10_malloc( n*m );
    if( p )
	memset( p, 0, n*m );
    return p;
}

void *
g10_calloc_secure( size_t n, size_t m )
{
    void *p = g10_malloc_secure( n*m );
    if( p )
	memset( p, 0, n*m );
    return p;
}


void *
g10_xmalloc( size_t n )
{
    void *p = g10_malloc( n );
    if( !n ) {
	fprintf(stderr,"OUT OF CORE\n");
	exit(4);
    }
    return p;
}

void *
g10_xmalloc_secure( size_t n )
{
    void *p = g10_malloc_secure( n );
    if( !n ) {
	fprintf(stderr,"OUT OF CORE in secure memory\n");
	exit(4);
    }
    return p;
}

void *
g10_xcalloc( size_t n, size_t m )
{
    void *p = g10_calloc( n, m );
    if( !n ) {
	fprintf(stderr,"OUT OF CORE\n");
	exit(4);
    }
    return p;
}

void *
g10_xcalloc_secure( size_t n, size_t m )
{
    void *p = g10_calloc_secure( n, m );
    if( !n ) {
	fprintf(stderr,"OUT OF CORE in secure memory\n");
	exit(4);
    }
    return p;
}

