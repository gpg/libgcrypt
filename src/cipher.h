/* cipher.h
 *	Copyright (C) 1998, 2002, 2003 Free Software Foundation, Inc.
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

#include <gcrypt.h>

#define DBG_CIPHER _gcry_get_debug_flag( 1 )

#include "../cipher/random.h"

#define PUBKEY_FLAG_NO_BLINDING 1 << 0

/*-- rmd160.c --*/
void _gcry_rmd160_hash_buffer (char *outbuf, const char *buffer, size_t length);

/*-- smallprime.c --*/
extern ushort small_prime_numbers[];

/*-- dsa.c --*/
void _gcry_register_pk_dsa_progress (gcry_handler_progress_t cbc, void *cb_data);
/*-- elgamal.c --*/
void _gcry_register_pk_elg_progress (gcry_handler_progress_t cb, void *cb_data);
/*-- primegen.c --*/
void _gcry_register_primegen_progress (gcry_handler_progress_t cb, void *cb_data);

typedef gpg_err_code_t (*gcry_pk_generate_t) (int algo,
					      unsigned int nbits,
					      unsigned long use_e,
					      gcry_mpi_t *skey,
					      gcry_mpi_t **retfactors);
typedef gpg_err_code_t (*gcry_pk_check_secret_key_t) (int algo, gcry_mpi_t *skey);
typedef gpg_err_code_t (*gcry_pk_encrypt_t) (int algo,
					     gcry_mpi_t *resarr,
					     gcry_mpi_t data,
					     gcry_mpi_t *pkey,
					     int flags);
typedef gpg_err_code_t (*gcry_pk_decrypt_t) (int algo,
					     gcry_mpi_t *result,
					     gcry_mpi_t *data,
					     gcry_mpi_t *skey,
					     int flags);
typedef gpg_err_code_t (*gcry_pk_sign_t) (int algo,
					  gcry_mpi_t *resarr,
					  gcry_mpi_t data,
					  gcry_mpi_t *skey);
typedef gpg_err_code_t (*gcry_pk_verify_t) (int algo,
					    gcry_mpi_t hash,
					    gcry_mpi_t *data,
					    gcry_mpi_t *pkey,
					    int (*cmp)(void *, gcry_mpi_t),
					    void *opaquev);
typedef unsigned (*gcry_pk_get_nbits_t) (int algo, gcry_mpi_t *pkey);

typedef struct gcry_pubkey_spec
{
  const char *name;
  char **sexp_names;
  int id;
  const char *elements_pkey;
  const char *elements_skey;
  const char *elements_enc;
  const char *elements_sig;
  const char *elements_grip;
  int use;
  gcry_pk_generate_t generate;
  gcry_pk_check_secret_key_t check_secret_key;
  gcry_pk_encrypt_t encrypt;
  gcry_pk_decrypt_t decrypt;
  gcry_pk_sign_t sign;
  gcry_pk_verify_t verify;
  gcry_pk_get_nbits_t get_nbits;
} gcry_pubkey_spec_t;

typedef void (*gcry_md_init_t) (void *c);
typedef void (*gcry_md_write_t) (void *c, unsigned char *buf, size_t nbytes);
typedef void (*gcry_md_final_t) (void *c);
typedef unsigned char *(*gcry_md_read_t) (void *c);

typedef struct gcry_digest_spec
{
  const char *name;
  int id;
  unsigned char *asnoid;
  int asnlen;
  int mdlen;
  gcry_md_init_t init;
  gcry_md_write_t write;
  gcry_md_final_t final;
  gcry_md_read_t read;
  size_t contextsize; /* allocate this amount of context */
} gcry_digest_spec_t;

typedef gpg_err_code_t (*gcry_cipher_setkey_t) (void *c,
						const unsigned char *key,
						unsigned keylen);
typedef void (*gcry_cipher_encrypt_t) (void *c,
				       unsigned char *outbuf,
				       const unsigned char *inbuf);
typedef void (*gcry_cipher_decrypt_t) (void *c,
				       unsigned char *outbuf,
				       const unsigned char *inbuf);
typedef void (*gcry_cipher_stencrypt_t) (void *c,
					 unsigned char *outbuf,
					 const unsigned char *inbuf,
					 unsigned int n);
typedef void (*gcry_cipher_stdecrypt_t) (void *c,
					 unsigned char *outbuf,
					 const unsigned char *inbuf,
					 unsigned int n);

typedef struct gcry_cipher_spec
{
  const char *name;
  int id;
  size_t blocksize;
  size_t keylen;
  size_t contextsize;
  gcry_cipher_setkey_t setkey;
  gcry_cipher_encrypt_t encrypt;
  gcry_cipher_decrypt_t decrypt;
  gcry_cipher_stencrypt_t stencrypt;
  gcry_cipher_stdecrypt_t stdecrypt;
} gcry_cipher_spec_t;

/* Declarations for the cipher specifications.  */
extern gcry_cipher_spec_t cipher_spec_blowfish;
extern gcry_cipher_spec_t cipher_spec_des;
extern gcry_cipher_spec_t cipher_spec_tripledes;
extern gcry_cipher_spec_t cipher_spec_arcfour;
extern gcry_cipher_spec_t cipher_spec_cast5;
extern gcry_cipher_spec_t cipher_spec_aes;
extern gcry_cipher_spec_t cipher_spec_aes192;
extern gcry_cipher_spec_t cipher_spec_aes256;
extern gcry_cipher_spec_t cipher_spec_twofish;
extern gcry_cipher_spec_t cipher_spec_twofish128;
extern gcry_cipher_spec_t cipher_spec_serpent128;
extern gcry_cipher_spec_t cipher_spec_serpent192;
extern gcry_cipher_spec_t cipher_spec_serpent256;

/* Declarations for the digest specifications.  */
extern gcry_digest_spec_t digest_spec_crc32;
extern gcry_digest_spec_t digest_spec_crc32_rfc1510;
extern gcry_digest_spec_t digest_spec_crc24_rfc2440;
extern gcry_digest_spec_t digest_spec_md4;
extern gcry_digest_spec_t digest_spec_md5;
extern gcry_digest_spec_t digest_spec_rmd160;
extern gcry_digest_spec_t digest_spec_sha1;
extern gcry_digest_spec_t digest_spec_sha256;
extern gcry_digest_spec_t digest_spec_sha512;
extern gcry_digest_spec_t digest_spec_sha384;
extern gcry_digest_spec_t digest_spec_tiger;

/* Declarations for the pubkey cipher specifications.  */
extern gcry_pubkey_spec_t pubkey_spec_rsa;
extern gcry_pubkey_spec_t pubkey_spec_elg;
extern gcry_pubkey_spec_t pubkey_spec_dsa;

#endif /*G10_CIPHER_H*/
