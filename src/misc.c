/* misc.c  -  symmetric cipher function interface
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
#include <unistd.h>

#include "g10lib.h"

static void (*fatal_error_handler)(void*,int, const char*) = NULL;
static void *fatal_error_handler_value = 0;

static const char *(*user_gettext_handler)( const char * ) = NULL;

void
gcry_set_gettext_handler( const char *(*f)(const char*) )
{
    user_gettext_handler = f;
}


const char *
g10_gettext( const char *key )
{
    if( user_gettext_handler )
	return user_gettext_handler( key );
    /* FIXME: switch the domain to gnupg and restore later */
    return key;
}

void
gcry_set_fatalerror_handler( void (*fnc)(void*,int, const char*), void *value)
{
    fatal_error_handler_value = value;
    fatal_error_handler = fnc;
}

static void
write2stderr( const char *s )
{
    write( 2, s, strlen(s) );
}

/****************
 * This function is called for fatal errors.  A caller might want to
 * set his own handler becuase this function simply calls abort().
 */
void
g10_fatal_error(int rc, const char *text )
{
    if( !text ) /* get a default text */
	text = gcry_strerror(rc);

    if( fatal_error_handler )
	fatal_error_handler( fatal_error_handler_value, rc, text );

    write2stderr("\nFatal error: ");
    write2stderr(text);
    write2stderr("\n");
    abort();
}

