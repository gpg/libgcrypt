/* cast5.h
 *	Copyright (C) 1998, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_CAST5_H
#define G10_CAST5_H

#include "types.h"

const char *
_gcry_cast5_get_info( int algo, size_t *keylen,
		   size_t *blocksize, size_t *contextsize,
		   int	(**setkeyf)( void *c, byte *key, unsigned keylen ),
		   void (**encryptf)( void *c, byte *outbuf, byte *inbuf ),
		   void (**decryptf)( void *c, byte *outbuf, byte *inbuf )
		 );

#endif /*G10_CAST5_H*/
