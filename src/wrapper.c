/* wrapper.c  -  wrapper around the internal functions
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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
#include <stdlib.h>

#include "g10lib.h"


void *gcry_malloc( size_t n )		 { return g10_malloc( n ); }
void *gcry_calloc( size_t n, size_t m )  { return g10_calloc( n, m ); }
void *gcry_malloc_secure( size_t n )	 { return g10_malloc_secure( n );}
void *gcry_calloc_secure( size_t n, size_t m )
					 { return g10_calloc_secure( n, m ); }
void *gcry_realloc( void *a, size_t n )  { return g10_realloc( a, n ); }
void *gcry_xmalloc( size_t n )		 { return g10_xmalloc(	n ); }
void *gcry_xcalloc( size_t n, size_t m ) { return g10_xcalloc( n,  m ); }
void *gcry_xmalloc_secure( size_t n )	 { return g10_xmalloc_secure( n ); }
void *gcry_xcalloc_secure( size_t n, size_t m )
					 { return g10_xcalloc_secure( n, m ); }
void *gcry_xrealloc( void *a, size_t n ) { return g10_xrealloc( a, n ); }
char *gcry_xstrdup( const char * a)	 { return g10_xstrdup( a); }
void  gcry_free( void *p )		 { g10_free( p ); }
int   gcry_is_secure( const void *p )	 { g10_is_secure( p ); }

