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

/* fixme: merge this function with ../cipher/cipher.c */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "g10lib.h"
#define G10_MPI_H  /* fake mpi.h header */
#include "cipher.h"

/* FIXME: We should really have the m_lib functions to allow
 *	  overriding of the default malloc functions
 * For now use this kludge: */
#define m_lib_alloc	   m_alloc
#define m_lib_alloc_clear  m_alloc_clear
#define m_lib_free	   m_free


#define CONTEXT_MAGIC 0x12569afe

struct gcry_cipher_context {
    u32 magic;
    int mode;
    unsigned flags;
    CIPHER_HANDLE hd;
};


GCRY_CIPHER_HD
gcry_cipher_open( int algo, int mode, unsigned flags )
{
    GCRY_CIPHER_HD h;

    /* check whether the algo is available */
    if( check_cipher_algo( algo ) ) {
	set_lasterr( GCRYERR_INV_ALGO );
	return NULL;
    }

    /* check flags */
    if( (flags & ~(GCRY_CIPHER_SECURE|GCRY_CIPHER_ENABLE_SYNC)) ) {
	set_lasterr( GCRYERR_INV_ARG );
	return NULL;
    }

    /* map mode to internal mode */
    switch( mode ) {
      case GCRY_CIPHER_MODE_NONE:
	mode = CIPHER_MODE_DUMMY;
	break;
      case GCRY_CIPHER_MODE_ECB:
	mode = CIPHER_MODE_ECB;
	break;
      case GCRY_CIPHER_MODE_CFB:
	mode = (flags & GCRY_CIPHER_ENABLE_SYNC) ? CIPHER_MODE_PHILS_CFB
						 : CIPHER_MODE_CFB;
	break;
      case GCRY_CIPHER_MODE_CBC: mode = CIPHER_MODE_CBC;
	break;
      default:
	set_lasterr( GCRYERR_INV_ALGO );
	return NULL;
    }

 /*    FIXME: issue a warning when CIPHER_MODE_NONE is used */

    /* allocate the handle */
    h = m_lib_alloc_clear( sizeof *h );
    if( !h ) {
	set_lasterr( GCRYERR_NOMEM );
	return NULL;
    }
    h->magic = CONTEXT_MAGIC;
    h->mode = mode;
    h->hd = cipher_open( algo, mode, (flags & GCRY_CIPHER_SECURE) );
    if( !h ) {
	m_lib_free( h );
	set_lasterr( GCRYERR_INTERNAL );
	return NULL;
    }

    return h;
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

int gcry_cipher_ctl( GCRY_CIPHER_HD h, int cmd, byte *buffer, size_t buflen)
{
    switch( cmd ) {
      case GCRYCTL_SET_KEY:
	cipher_setkey( h->hd, buffer, buflen );
	break;
      case GCRYCTL_SET_IV:
	cipher_setiv( h->hd, buffer, buflen );
	break;
      case GCRYCTL_CFB_SYNC:
	cipher_sync( h->hd );
      default:
	return set_lasterr( GCRYERR_INV_OP );
    }
    return 0;
}


/****************
 * Return information about the cipher handle.
 * -1 is returned on error and gcry_errno() may be used to get more information
 * about the error.
 */
int
gcry_cipher_info( GCRY_CIPHER_HD h, int cmd, byte *buffer, size_t *nbytes)
{
    switch( cmd ) {
      default:
	set_lasterr( GCRYERR_INV_OP );
	return -1;
    }
    return 0;
}

/****************
 * Return information about the given cipher algorithm
 * WHAT select the kind of information returned:
 *  GCRYCTL_GET_KEYLEN:
 *	Return the length of the key, if the algorithm
 *	supports multiple key length, the maximum supported value
 *	is returnd.  The length is return as number of octets.
 *	buffer and nbytes must be zero.
 *  GCRYCTL_GET_BLKLEN:
 *	Return the blocklength of the algorithm counted in octets.
 *	buffer and nbytes must be zero.
 *  GCRYCTL_TEST_ALGO:
 *	Returns 0 when the specified algorithm is available for use.
 *	buffer and nbytes must be zero.
 *
 * On error the value -1 is returned and the error reason may be
 * retrieved by gcry_errno().
 * Note:  Because this function is in most caes used to return an
 * integer value, we can make it easier for the caller to just look at
 * the return value.  The caller will in all cases consult the value
 * and thereby detecting whether a error occured or not (i.e. while checking
 * the block size)
 */
int
gcry_cipher_algo_info( int algo, int what, void *buffer, size_t *nbytes)
{
    switch( what ) {
      case GCRYCTL_GET_KEYLEN:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_ARG );
	    return -1;
	}
	BUG(); /* FIXME: implement this */
	break;

      case GCRYCTL_GET_BLKLEN:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_ARG );
	    return -1;
	}
	ui = cipher_get_blocksize( algo );
	if( ui > 0 && ui < 10000 )
	    return (int)ui;
	/* the only reason is an invalid algo or a strange blocksize */
	set_lasterr( GCRYERR_INV_ALGO );
	return -1;

      case GCRYCTL_TEST_ALGO:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_ARG );
	    return -1;
	}
	if( check_cipher_algo( algo ) ) {
	    set_lasterr( GCRYERR_INV_ALGO );
	    return -1;
	}
	return 0;


      default:
	set_lasterr( GCRYERR_INV_OP );
	return -1;
    }
    return 0;
}


/****************
 * This function simply returns the name of the algorithm or soem constant
 * string when there is no algo.  It will never return NULL.
 */
const char *
gcry_cipher_algo_name( int algo )
{
    return cipher_algo_to_string( algo );
}


/****************
 * Encrypt IN and write it to OUT.  If IN is NULL, in-place encryption has
 * been requested,
 */
int
gcry_cipher_encrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				       const byte  *in, size_t inlen )
{
    if( !in ) {
	/* caller requested in-place encryption */
	/* actullay cipher_encrypt() does not need to know about it, but
	 * we may chnage this to get better performace */
	cipher_encrypt( h->hd, out, out, outsize );
    }
    else {
	if( outsize < inlen )
	    return set_lasterr( GCRYERR_TOO_SHORT );
	/* fixme: check that the inlength is a multipe of the blocksize
	 * if a blockoriented mode is used, or modify cipher_encrypt to
	 * return an error in this case */
	cipher_encrypt( h->hd, out, in, inlen );
    }
    return 0;
}

int
gcry_cipher_decrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				 const byte  *in, size_t inlen )
{
    if( !in ) {
	/* caller requested in-place encryption */
	/* actullay cipher_encrypt() does not need to know about it, but
	 * we may chnage this to get better performace */
	cipher_decrypt( h->hd, out, out, outsize );
    }
    else {
	if( outsize < inlen )
	    return set_lasterr( GCRYERR_TOO_SHORT );
	/* fixme: check that the inlength is a multipe of the blocksize
	 * if a blockoriented mode is used, or modify cipher_encrypt to
	 * return an error in this case */
	cipher_decrypt( h->hd, out, in, inlen );
    }
    return 0;
}

