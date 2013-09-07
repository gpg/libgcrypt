/* cipher-proto.h - Internal declarations
 *	Copyright (C) 2008, 2011 Free Software Foundation, Inc.
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

/* This file has been factored out from cipher.h so that it can be
   used standalone in visibility.c . */

#ifndef G10_CIPHER_PROTO_H
#define G10_CIPHER_PROTO_H


enum pk_encoding;


/* Definition of a function used to report selftest failures.
   DOMAIN is a string describing the function block:
          "cipher", "digest", "pubkey or "random",
   ALGO   is the algorithm under test,
   WHAT   is a string describing what has been tested,
   DESC   is a string describing the error. */
typedef void (*selftest_report_func_t)(const char *domain,
                                       int algo,
                                       const char *what,
                                       const char *errdesc);

/* Definition of the selftest functions.  */
typedef gpg_err_code_t (*selftest_func_t)
     (int algo, int extended, selftest_report_func_t report);


/*
 *
 * Public key related definitions.
 *
 */

/* Type for the pk_generate function.  */
typedef gcry_err_code_t (*gcry_pk_generate_t) (int algo,
                                               unsigned int nbits,
                                               unsigned long evalue,
                                               gcry_sexp_t genparms,
                                               gcry_sexp_t *r_skey);

/* Type for the pk_check_secret_key function.  */
typedef gcry_err_code_t (*gcry_pk_check_secret_key_t) (int algo,
						       gcry_mpi_t *skey);

/* Type for the pk_encrypt function.  */
typedef gcry_err_code_t (*gcry_pk_encrypt_t) (int algo,
					      gcry_sexp_t *r_result,
					      gcry_mpi_t data,
					      gcry_mpi_t *pkey,
					      int flags);

/* Type for the pk_decrypt function.  */
typedef gcry_err_code_t (*gcry_pk_decrypt_t) (int algo,
					      gcry_sexp_t *r_result,
					      gcry_mpi_t *data,
					      gcry_mpi_t *skey,
					      int flags,
                                              enum pk_encoding encoding,
                                              int hash_algo,
                                              unsigned char *label,
                                              size_t labellen);

/* Type for the pk_sign function.  */
typedef gcry_err_code_t (*gcry_pk_sign_t) (int algo,
					   gcry_sexp_t *r_result,
					   gcry_mpi_t data,
					   gcry_mpi_t *skey,
                                           int flags,
                                           int hashalgo);

/* Type for the pk_verify function.  */
typedef gcry_err_code_t (*gcry_pk_verify_t) (int algo,
					     gcry_mpi_t hash,
					     gcry_mpi_t *data,
					     gcry_mpi_t *pkey,
					     int (*cmp) (void *, gcry_mpi_t),
					     void *opaquev,
                                             int flags,
                                             int hashalgo);

/* Type for the pk_get_nbits function.  */
typedef unsigned (*gcry_pk_get_nbits_t) (int algo,
                                         gcry_mpi_t *pkey);


/* The type used to compute the keygrip.  */
typedef gpg_err_code_t (*pk_comp_keygrip_t) (gcry_md_hd_t md,
                                             gcry_sexp_t keyparm);

/* The type used to query ECC curve parameters.  */
typedef gcry_err_code_t (*pk_get_param_t) (const char *name,
                                           gcry_mpi_t *pkey);

/* The type used to query an ECC curve name.  */
typedef const char *(*pk_get_curve_t)(gcry_mpi_t *pkey, int iterator,
                                      unsigned int *r_nbits);

/* The type used to query ECC curve parameters by name.  */
typedef gcry_sexp_t (*pk_get_curve_param_t)(const char *name);


/* Module specification structure for public key algoritms.  */
typedef struct gcry_pk_spec
{
  int algo;
  struct {
    unsigned int disabled:1;
    unsigned int fips:1;
  } flags;
  int use;
  const char *name;
  const char **aliases;
  const char *elements_pkey;
  const char *elements_skey;
  const char *elements_enc;
  const char *elements_sig;
  const char *elements_grip;
  gcry_pk_generate_t generate;
  gcry_pk_check_secret_key_t check_secret_key;
  gcry_pk_encrypt_t encrypt;
  gcry_pk_decrypt_t decrypt;
  gcry_pk_sign_t sign;
  gcry_pk_verify_t verify;
  gcry_pk_get_nbits_t get_nbits;
  selftest_func_t selftest;
  pk_comp_keygrip_t comp_keygrip;
  pk_get_param_t get_param;
  pk_get_curve_t get_curve;
  pk_get_curve_param_t get_curve_param;
} gcry_pk_spec_t;



/* The type used to convey additional information to a cipher.  */
typedef gpg_err_code_t (*cipher_set_extra_info_t)
     (void *c, int what, const void *buffer, size_t buflen);

/* The type used to set an IV directly in the algorithm module.  */
typedef void (*cipher_setiv_func_t)(void *c,
                                    const byte *iv, unsigned int ivlen);

/* Extra module specification structures.  These are used for internal
   modules which provide more functions than available through the
   public algorithm register APIs.  */
typedef struct cipher_extra_spec
{
  selftest_func_t selftest;
  cipher_set_extra_info_t set_extra_info;
  cipher_setiv_func_t setiv;
} cipher_extra_spec_t;

typedef struct md_extra_spec
{
  selftest_func_t selftest;
} md_extra_spec_t;



/* The private register functions. */
gcry_error_t _gcry_cipher_register (gcry_cipher_spec_t *cipher,
                                    cipher_extra_spec_t *extraspec,
                                    int *algorithm_id,
                                    gcry_module_t *module);
gcry_error_t _gcry_md_register (gcry_md_spec_t *cipher,
                                md_extra_spec_t *extraspec,
                                unsigned int *algorithm_id,
                                gcry_module_t *module);

/* The selftest functions.  */
gcry_error_t _gcry_cipher_selftest (int algo, int extended,
                                    selftest_report_func_t report);
gcry_error_t _gcry_md_selftest (int algo, int extended,
                                selftest_report_func_t report);
gcry_error_t _gcry_pk_selftest (int algo, int extended,
                                selftest_report_func_t report);
gcry_error_t _gcry_hmac_selftest (int algo, int extended,
                                  selftest_report_func_t report);

gcry_error_t _gcry_random_selftest (selftest_report_func_t report);


/*-- pubkey.c --*/
gcry_err_code_t _gcry_pubkey_get_sexp (gcry_sexp_t *r_sexp,
                                       int reserved, gcry_ctx_t ctx);


#endif /*G10_CIPHER_PROTO_H*/
