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

#include "g10lib.h"


GCRY_MD_HD
gcry_md_open( int algo, unsigned flags )
{
}

void
gcry_md_close( GCRY_MD_HD hd )
{
}

void
gcry_md_enable( GCRY_MD_HD hd, int algo )
{
}

GCRY_MD_HD
gcry_md_copy( GCRY_MD_HD hd )
{
}

int
gcry_md_ctl( GCRY_MD_HD hd, int cmd, byte *buffer, size_t buflen)
{
}

void
gcry_md_write( GCRY_MD_HD hd, byte *inbuf, size_t inlen)
{
}

byte *
gcry_md_read( GCRY_MD_HD hd, int algo )
{
}


int
gcry_md_get( GCRY_MD_HD hd, int algo, byte *buffer, int buflen )
{
}



