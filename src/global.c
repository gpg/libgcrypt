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
  #if 0
    switch( cmd ) {
      case GCRYCTL_NO_MEM_IS_FATAL:
	break;
      case GCRYCTL_SET_FATAL_FNC:
	break;
    }
  #endif
    return GCRYERR_INV_OP;
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
    switch( ec ) {
      default:
	sprintf( buf, "ec=%d", ec );
	s = buf;
    }
    return s;
}


int
set_lasterr( int ec )
{
    if( ec )
	last_ec = ec == -1 ? GCRYERR_EOF : ec;
    return ec;
}


