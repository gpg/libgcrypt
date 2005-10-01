/* misc.c - Misc helper functions.
   Copyright (C) 2005 g10 Code GmbH

   This file is part of Libgcrypt.
 
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
 
   Libgcrypt is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU Lesser General Public
   License along with Libgcrypt; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <gcrypt-common-internal.h>

/* FIXME: copyright line and function name.  */

void
_gcry_burn_stack (int bytes)
{
    char buf[64];
    
    wipememory (buf, sizeof buf);
    bytes -= sizeof buf;
    if (bytes > 0)
        _gcry_burn_stack (bytes);
}
