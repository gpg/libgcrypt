/* cipher.h
 *	Copyright (C) 1998, 2002 Free Software Foundation, Inc.
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
#ifndef G10_CIPHER_H
#define G10_CIPHER_H


#define DBG_CIPHER _gcry_get_debug_flag( 1 )

#include "../cipher/random.h"


#define CIPHER_ALGO_NONE	 0
#define CIPHER_ALGO_IDEA	 1
#define CIPHER_ALGO_3DES	 2
#define CIPHER_ALGO_CAST5	 3
#define CIPHER_ALGO_BLOWFISH	 4  /* blowfish 128 bit key */
#define CIPHER_ALGO_SAFER_SK128  5
#define CIPHER_ALGO_DES_SK	 6
#define CIPHER_ALGO_TWOFISH	10  /* twofish 256 bit */
#define CIPHER_ALGO_SKIPJACK   101  /* experimental: skipjack */
#define CIPHER_ALGO_TWOFISH_OLD 102 /* experimental: twofish 128 bit */
#define CIPHER_ALGO_DUMMY      110  /* no encryption at all */

#define PUBKEY_ALGO_RSA        1
#define PUBKEY_ALGO_RSA_E      2     /* RSA encrypt only */
#define PUBKEY_ALGO_RSA_S      3     /* RSA sign only */
#define PUBKEY_ALGO_ELGAMAL_E 16     /* encrypt only ElGamal (but not for v3)*/
#define PUBKEY_ALGO_DSA       17
#define PUBKEY_ALGO_ELGAMAL   20     /* sign and encrypt elgamal */

#if 0
#define PUBKEY_USAGE_SIG     1	    /* key is good for signatures */
#define PUBKEY_USAGE_ENC     2	    /* key is good for encryption */
#endif

#define DIGEST_ALGO_MD5       1
#define DIGEST_ALGO_SHA1      2
#define DIGEST_ALGO_RMD160    3
#define DIGEST_ALGO_TIGER     6

#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
		       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL || (a)==PUBKEY_ALGO_ELGAMAL_E)


/*-- rmd160.c --*/
void _gcry_rmd160_hash_buffer( char *outbuf, const char *buffer, size_t length );


/*-- smallprime.c --*/
extern ushort small_prime_numbers[];

/*-- dsa.c --*/
void _gcry_register_pk_dsa_progress (void (*cb)(void *,const char *,
                                                int,int,int),
                                     void *cb_data );
/*-- elgamal.c --*/
void _gcry_register_pk_elg_progress (void (*cb)(void *,const char *,
                                                int,int,int),
                                     void *cb_data );
/*-- primegen.c --*/
void _gcry_register_primegen_progress (void (*cb)(void *,const char *,
                                                int,int,int),
                                       void *cb_data );



#endif /*G10_CIPHER_H*/

