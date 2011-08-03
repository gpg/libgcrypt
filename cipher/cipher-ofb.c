/* cipher-ofb.c  - Generic OFB mode implementation
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003
 *               2005, 2007, 2008, 2009, 2011 Free Software Foundation, Inc.
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "ath.h"
#include "./cipher-internal.h"


gcry_err_code_t
_gcry_cipher_ofb_encrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, unsigned int outbuflen,
                          const unsigned char *inbuf, unsigned int inbuflen)
{
  unsigned char *ivp;
  size_t blocksize = c->cipher->blocksize;

  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if ( inbuflen <= c->unused )
    {
      /* Short enough to be encoded by the remaining XOR mask. */
      /* XOR the input with the IV */
      for (ivp=c->u_iv.iv+c->cipher->blocksize - c->unused;
           inbuflen;
           inbuflen--, c->unused-- )
        *outbuf++ = (*ivp++ ^ *inbuf++);
      return 0;
    }

  if( c->unused )
    {
      inbuflen -= c->unused;
      for(ivp=c->u_iv.iv+blocksize - c->unused; c->unused; c->unused-- )
        *outbuf++ = (*ivp++ ^ *inbuf++);
    }

  /* Now we can process complete blocks. */
  while ( inbuflen >= blocksize )
    {
      int i;
      /* Encrypt the IV (and save the current one). */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );

      for (ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
        *outbuf++ = (*ivp++ ^ *inbuf++);
      inbuflen -= blocksize;
    }
  if ( inbuflen )
    { /* process the remaining bytes */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      c->unused = blocksize;
      c->unused -= inbuflen;
      for(ivp=c->u_iv.iv; inbuflen; inbuflen-- )
        *outbuf++ = (*ivp++ ^ *inbuf++);
    }
  return 0;
}


gcry_err_code_t
_gcry_cipher_ofb_decrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, unsigned int outbuflen,
                          const unsigned char *inbuf, unsigned int inbuflen)
{
  unsigned char *ivp;
  size_t blocksize = c->cipher->blocksize;

  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if( inbuflen <= c->unused )
    {
      /* Short enough to be encoded by the remaining XOR mask. */
      for (ivp=c->u_iv.iv+blocksize - c->unused; inbuflen; inbuflen--,c->unused--)
        *outbuf++ = *ivp++ ^ *inbuf++;
      return 0;
    }

  if ( c->unused )
    {
      inbuflen -= c->unused;
      for (ivp=c->u_iv.iv+blocksize - c->unused; c->unused; c->unused-- )
        *outbuf++ = *ivp++ ^ *inbuf++;
    }

  /* Now we can process complete blocks. */
  while ( inbuflen >= blocksize )
    {
      int i;
      /* Encrypt the IV (and save the current one). */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      for (ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
        *outbuf++ = *ivp++ ^ *inbuf++;
      inbuflen -= blocksize;
    }
  if ( inbuflen )
    { /* Process the remaining bytes. */
      /* Encrypt the IV (and save the current one). */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      c->unused = blocksize;
      c->unused -= inbuflen;
      for (ivp=c->u_iv.iv; inbuflen; inbuflen-- )
        *outbuf++ = *ivp++ ^ *inbuf++;
    }
  return 0;
}
