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
#include "memory.h" /* for the m_* functions */

static int last_ec; /* fixme: make thread safe */

static void *(*alloc_func)(size_t n) = NULL;
static void *(*alloc_secure_func)(size_t n) = NULL;
static int   (*is_secure_func)(const void*) = NULL;
static void *(*realloc_func)(void *p, size_t n) = NULL;
static void (*free_func)(void*) = NULL;
static int (*outofcore_handler)( void*, size_t, unsigned int ) = NULL;
static void *outofcore_handler_value = NULL;

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
      X(NO_MEM, 	N_("out of core"))
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



/****************
 * NOTE: All 5 functions should be set.
 */
void
gcry_set_allocation_handler( void *(*new_alloc_func)(size_t n),
			     void *(*new_alloc_secure_func)(size_t n),
			     int (*new_is_secure_func)(const void*),
			     void *(*new_realloc_func)(void *p, size_t n),
			     void (*new_free_func)(void*) )
{
    alloc_func	      = new_alloc_func;
    alloc_secure_func = new_alloc_secure_func;
    is_secure_func    = new_is_secure_func;
    realloc_func      = new_realloc_func;
    free_func	      = new_free_func;
}



/****************
 * Set an optional handler which is called in case the xmalloc functions
 * ran out of memory.  This handler may do one of these things:
 *   o free some memory and return true, so that the xmalloc function
 *     tries again.
 *   o Do whatever tit like and return false, so that the xmalloc functions
 *     use the default fatal error handler.
 *   o Terminate the program and don't return.
 *
 * The handler function is called with 3 argiments:  The opaque value set with
 * this function, the requested memory size, and a flag with these bits
 * currently defined:
 *	bit 0 set = secure memory has been requested.
 */
void
gcry_set_outofcore_handler( int (*f)( void*, size_t, unsigned int ),
							void *value )
{
    outofcore_handler = f;
    outofcore_handler_value = value;
}



void *
g10_malloc( size_t n )
{
    if( alloc_func )
	return alloc_func( n ) ;
    return g10_private_malloc( n );
}

void *
g10_malloc_secure( size_t n )
{
    if( alloc_secure_func )
	return alloc_secure_func( n ) ;
    return g10_private_malloc_secure( n );
}

int
g10_is_secure( const void *a )
{
    if( is_secure_func )
	return is_secure_func( a ) ;
    return g10_private_is_secure( a );
}

void *
g10_realloc( void *a, size_t n )
{
    if( realloc_func )
	return realloc_func( a, n ) ;
    return g10_private_realloc( a, n );
}

void
g10_free( void *p )
{
    if( !p )
	return;

    if( free_func )
	free_func( p );
    else
	g10_private_free( p );
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
    void *p;

    while ( !(p = g10_malloc( n )) ) {
	if( !outofcore_handler
	    || !outofcore_handler( outofcore_handler_value, n, 0 ) ) {
	    g10_fatal_error(GCRYERR_NO_MEM, NULL );
	}
    }
    return p;
}

void *
g10_xrealloc( void *a, size_t n )
{
    void *p;

    while ( !(p = g10_realloc( a, n )) ) {
	if( !outofcore_handler
	    || !outofcore_handler( outofcore_handler_value, n, 2 ) ) {
	    g10_fatal_error(GCRYERR_NO_MEM, NULL );
	}
    }
    return p;
}

void *
g10_xmalloc_secure( size_t n )
{
    void *p;

    while ( !(p = g10_malloc_secure( n )) ) {
	if( !outofcore_handler
	    || !outofcore_handler( outofcore_handler_value, n, 1 ) ) {
	    g10_fatal_error(GCRYERR_NO_MEM,
			     _("out of core in secure memory"));
	}
    }
    return p;
}

void *
g10_xcalloc( size_t n, size_t m )
{
    void *p = g10_xmalloc( n*m );
    memset( p, 0, n*m );
    return p;
}

void *
g10_xcalloc_secure( size_t n, size_t m )
{
    void *p = g10_xmalloc_secure( n* m );
    memset( p, 0, n*m );
    return p;
}

