/* gcrypt-module.h - GNU cryptographic library interface
 * Copyright (C) 2003 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
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

/* This file contains the necessary declarations/definitions for
   working with Libgcrypt modules.  */

#ifndef _GCRYPT_MODULE_H
#define _GCRYPT_MODULE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens's auto-indent happy */
}
#endif
#endif

#include <stddef.h>

/* This type represents a `module'.  */
typedef struct gcry_module *gcry_module_t;

/* Check that the library fulfills the version requirement.  */

/* Type for the cipher_setkey function.  */
typedef gcry_err_code_t (*gcry_cipher_setkey_t) (void *c,
						 const unsigned char *key,
						 unsigned keylen);

/* Type for the cipher_encrypt function.  */
typedef void (*gcry_cipher_encrypt_t) (void *c,
				       unsigned char *outbuf,
				       const unsigned char *inbuf);

/* Type for the cipher_decrypt function.  */
typedef void (*gcry_cipher_decrypt_t) (void *c,
				       unsigned char *outbuf,
				       const unsigned char *inbuf);

/* Type for the cipher_stencrypt function.  */
typedef void (*gcry_cipher_stencrypt_t) (void *c,
					 unsigned char *outbuf,
					 const unsigned char *inbuf,
					 unsigned int n);

/* Type for the cipher_stdecrypt function.  */
typedef void (*gcry_cipher_stdecrypt_t) (void *c,
					 unsigned char *outbuf,
					 const unsigned char *inbuf,
					 unsigned int n);

typedef struct gcry_cipher_oid_spec
{
  const char *oid;
  int mode;
} gcry_cipher_oid_spec_t;

/* Module specification structure for ciphers.  */
typedef struct gcry_cipher_spec
{
  const char *name;
  const char **aliases;
  gcry_cipher_oid_spec_t *oids;
  size_t blocksize;
  size_t keylen;
  size_t contextsize;
  gcry_cipher_setkey_t setkey;
  gcry_cipher_encrypt_t encrypt;
  gcry_cipher_decrypt_t decrypt;
  gcry_cipher_stencrypt_t stencrypt;
  gcry_cipher_stdecrypt_t stdecrypt;
} gcry_cipher_spec_t;

/* Register a new cipher module whose specification can be found in
   CIPHER.  On success, a new algorithm ID is stored in ALGORITHM_ID
   and a pointer representhing this module is stored in MODULE.  */
gcry_error_t gcry_cipher_register (gcry_cipher_spec_t *cipher,
				   unsigned int *algorithm_id,
				   gcry_module_t *module);

/* Unregister the cipher identified by MODULE, which must have been
   registered with gcry_cipher_register.  */
void gcry_cipher_unregister (gcry_module_t module);

/* ********************** */

#define _GCRY_AC_SPEC(identifier) \
  static gcry_ac_struct_spec_t spec_##identifier[]

#define GCRY_AC_SPEC_KEY_PUBLIC     _GCRY_AC_SPEC (key_public)
#define GCRY_AC_SPEC_KEY_SECRET     _GCRY_AC_SPEC (key_secret)
#define GCRY_AC_SPEC_DATA_ENCRYPTED _GCRY_AC_SPEC (data_encrypted)
#define GCRY_AC_SPEC_DATA_SIGNED    _GCRY_AC_SPEC (data_signed)

#define _GCRY_AC_ELEM(elem, type) { #elem, offsetof (type, elem) }

#define GCRY_AC_ELEM_KEY_PUBLIC(elem)     _GCRY_AC_ELEM (elem, key_public_t)
#define GCRY_AC_ELEM_KEY_SECRET(elem)     _GCRY_AC_ELEM (elem, key_secret_t)
#define GCRY_AC_ELEM_DATA_ENCRYPTED(elem) _GCRY_AC_ELEM (elem, data_encrypted_t)
#define GCRY_AC_ELEM_DATA_SIGNED(elem)    _GCRY_AC_ELEM (elem, data_signed_t)

typedef struct gcry_ac_struct_spec
{
  const char *name;
  size_t offset;
} gcry_ac_struct_spec_t;

/* Type for the pk_generate function.  */
typedef gcry_err_code_t (*gcry_ac_generate_t) (unsigned int nbits,
					       void *generate_spec,
					       void *key_secret,
					       void *key_public,
					       gcry_mpi_t **misc_data);

/* Type for the pk_check_secret_key function.  */
typedef gcry_err_code_t (*gcry_ac_key_secret_check_t) (void *key_secret);

/* Type for the pk_encrypt function.  */
typedef gcry_err_code_t (*gcry_ac_encrypt_t) (gcry_mpi_t data,
					      void *key_public,
					      void *data_encrypted,
					      unsigned int flags);

/* Type for the pk_decrypt function.  */
typedef gcry_err_code_t (*gcry_ac_decrypt_t) (void *data_encrypted,
					      void *key_secret,
					      gcry_mpi_t *data_decrypted,
					      unsigned int flags);

/* Type for the pk_sign function.  */
typedef gcry_err_code_t (*gcry_ac_sign_t) (gcry_mpi_t data,
					   void *key_secret,
					   void *data_signed);

/* Type for the pk_verify function.  */
typedef gcry_err_code_t (*gcry_ac_verify_t) (gcry_mpi_t data,
					     void *key_public,
					     void *data_signed);

/* Type for the pk_get_nbits function.  */
typedef gcry_err_code_t (*gcry_ac_get_nbits_t) (void *key_public,
						void *key_secret,
						unsigned int *key_nbits);

/* Type for the pk_get_grip function.  */
typedef gcry_err_code_t (*gcry_ac_get_grip_t) (void *key_public,
					       unsigned char *key_grip);

/* Module specification structure for message digests.  */
typedef struct gcry_ac_spec
{
  const char *name;
  char **aliases;
  size_t size_key_public;
  size_t size_key_secret;
  size_t size_data_encrypted;
  size_t size_data_signed;
  unsigned int elems_key_public;
  unsigned int elems_key_secret;
  unsigned int elems_data_encrypted;
  unsigned int elems_data_signed;
  gcry_ac_struct_spec_t *spec_key_public;
  gcry_ac_struct_spec_t *spec_key_secret;
  gcry_ac_struct_spec_t *spec_data_encrypted;
  gcry_ac_struct_spec_t *spec_data_signed;
  gcry_ac_generate_t generate;
  gcry_ac_key_secret_check_t key_secret_check;
  gcry_ac_encrypt_t encrypt;
  gcry_ac_decrypt_t decrypt;
  gcry_ac_sign_t sign;
  gcry_ac_verify_t verify;
  gcry_ac_get_nbits_t get_nbits;
  gcry_ac_get_grip_t get_grip;
} gcry_ac_spec_t;

/* Register a new algorithm module whose specification can be found in
   ALGORITHM.  On success, a new algorithm ID is stored in
   ALGORITHM_ID and a pointer representhing this module is stored in
   MODULE.  */
gcry_error_t gcry_ac_register (gcry_ac_spec_t *algorithm,
			       unsigned int *algorithm_id,
			       gcry_module_t *module);

/* Unregister the algorithm identified by MODULE, which must have been
   registered with gcry_ac_register.  */
void gcry_ac_unregister (gcry_module_t module);

/* ********************** */

/* Type for the md_init function.  */
typedef void (*gcry_md_init_t) (void *c);

/* Type for the md_write function.  */
typedef void (*gcry_md_write_t) (void *c, unsigned char *buf, size_t nbytes);

/* Type for the md_final function.  */
typedef void (*gcry_md_final_t) (void *c);

/* Type for the md_read function.  */
typedef unsigned char *(*gcry_md_read_t) (void *c);

typedef struct gcry_md_oid_spec
{
  const char *oidstring;
} gcry_md_oid_spec_t;

/* Module specification structure for message digests.  */
typedef struct gcry_md_spec
{
  const char *name;
  unsigned char *asnoid;
  int asnlen;
  gcry_md_oid_spec_t *oids;
  int mdlen;
  gcry_md_init_t init;
  gcry_md_write_t write;
  gcry_md_final_t final;
  gcry_md_read_t read;
  size_t contextsize; /* allocate this amount of context */
} gcry_md_spec_t;

/* Register a new digest module whose specification can be found in
   DIGEST.  On success, a new algorithm ID is stored in ALGORITHM_ID
   and a pointer representhing this module is stored in MODULE.  */
gcry_error_t gcry_md_register (gcry_md_spec_t *digest,
			       unsigned int *algorithm_id,
			       gcry_module_t *module);

/* Unregister the digest identified by ID, which must have been
   registered with gcry_digest_register.  */
void gcry_md_unregister (gcry_module_t module);

#if 0 /* keep Emacsens's auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif
#endif
