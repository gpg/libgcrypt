/* g10lib.h -  internal defintions for libgcrypt
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.
 *
 * This header is to be used inside of libgcrypt in place of gcrypt.h.
 * This way we can better distinguish between internal and external
 * usage of gcrypt.h
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

#ifndef G10LIB_H
#define G10LIB_H 1

#ifdef _GCRYPT_H
#error  gcrypt.h already included
#endif

#ifndef _GCRYPT_IN_LIBGCRYPT 
#error something is wrong with config.h
#endif

#include <gcrypt.h>
#include "types.h"

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
#define JNLIB_GCC_M_FUNCTION 1
#define JNLIB_GCC_A_NR 	     __attribute__ ((noreturn))
#define JNLIB_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
#define JNLIB_GCC_A_NR_PRINTF( f, a ) \
			    __attribute__ ((noreturn, format (printf,f,a)))
#define GCC_ATTR_NORETURN  __attribute__ ((__noreturn__))
#else
#define JNLIB_GCC_A_NR
#define JNLIB_GCC_A_PRINTF( f, a )
#define JNLIB_GCC_A_NR_PRINTF( f, a )
#define GCC_ATTR_NORETURN 
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96 )
#define GCC_ATTR_PURE  __attribute__ ((__pure__))
#else
#define GCC_ATTR_PURE
#endif

/* (The malloc attribute might be defined prior to 3.2 - I am just not sure) */
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 2 )
#define GCC_ATTR_MALLOC    __attribute__ ((__malloc__))
#else
#define GCC_ATTR_MALLOC
#endif

#ifdef G10_I18N_H
#error i18n should not be included here
#endif

#define _(a)  _gcry_gettext(a)
#define N_(a) (a)

void  _gcry_check_heap( const void *a );

int _gcry_get_debug_flag( unsigned int mask );


/*-- gcrypt/misc.c --*/

#ifdef JNLIB_GCC_M_FUNCTION
void _gcry_bug (const char *file, int line,
                const char *func) GCC_ATTR_NORETURN;
#else
void _gcry_bug (const char *file, int line);
#endif

const char *_gcry_gettext (const char *key);
void _gcry_fatal_error(int rc, const char *text ) JNLIB_GCC_A_NR;
void _gcry_log( int level, const char *fmt, ... ) JNLIB_GCC_A_PRINTF(2,3);
void _gcry_log_bug( const char *fmt, ... )   JNLIB_GCC_A_NR_PRINTF(1,2);
void _gcry_log_fatal( const char *fmt, ... ) JNLIB_GCC_A_NR_PRINTF(1,2);
void _gcry_log_error( const char *fmt, ... ) JNLIB_GCC_A_PRINTF(1,2);
void _gcry_log_info( const char *fmt, ... )  JNLIB_GCC_A_PRINTF(1,2);
void _gcry_log_debug( const char *fmt, ... ) JNLIB_GCC_A_PRINTF(1,2);
void _gcry_log_printf ( const char *fmt, ... ) JNLIB_GCC_A_PRINTF(1,2);

void _gcry_set_log_verbosity( int level );
int _gcry_log_verbosity( int level );

#ifdef JNLIB_GCC_M_FUNCTION
#define BUG() _gcry_bug( __FILE__ , __LINE__, __FUNCTION__ )
#else
#define BUG() _gcry_bug( __FILE__ , __LINE__ )
#endif

#define log_hexdump _gcry_log_hexdump
#define log_bug     _gcry_log_bug
#define log_fatal   _gcry_log_fatal
#define log_error   _gcry_log_error
#define log_info    _gcry_log_info
#define log_debug   _gcry_log_debug
#define log_printf  _gcry_log_printf




/*-- cipher/pubkey.c --*/

#ifndef mpi_powm
#define mpi_powm(w,b,e,m)   gcry_mpi_powm( (w), (b), (e), (m) )
#endif

/*-- primegen.c --*/
gcry_mpi_t _gcry_generate_secret_prime (unsigned int nbits,
                                 int (*extra_check)(void*, gcry_mpi_t),
                                 void *extra_check_arg);
gcry_mpi_t _gcry_generate_public_prime (unsigned int nbits,
                                 int (*extra_check)(void*, gcry_mpi_t),
                                 void *extra_check_arg);
gcry_mpi_t _gcry_generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
					   gcry_mpi_t g, gcry_mpi_t **factors );


/* replacements of missing functions (missing-string.c)*/
#ifndef HAVE_STPCPY
char *stpcpy (char *a, const char *b);
#endif
#ifndef HAVE_STRCASECMP
int strcasecmp (const char *a, const char *b) GCC_ATTR_PURE;
#endif

/* macros used to rename missing functions */
#ifndef HAVE_STRTOUL
#define strtoul(a,b,c)  ((unsigned long)strtol((a),(b),(c)))
#endif
#ifndef HAVE_MEMMOVE
#define memmove(d, s, n) bcopy((s), (d), (n))
#endif
#ifndef HAVE_STRICMP
#define stricmp(a,b)	 strcasecmp( (a), (b) )
#endif
#ifndef HAVE_ATEXIT
#define atexit(a)    (on_exit((a),0))
#endif
#ifndef HAVE_RAISE
#define raise(a) kill(getpid(), (a))
#endif


/* some handy macros */
#ifndef STR
#define STR(v) #v
#endif
#define STR2(v) STR(v)
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

/* Stack burning.  */

void _gcry_burn_stack (int bytes);

/* Digit predicates.  */

#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define octdigitp(p) (*(p) >= '0' && *(p) <= '7')
#define alphap(a)    (   (*(a) >= 'A' && *(a) <= 'Z')  \
                      || (*(a) >= 'a' && *(a) <= 'z'))
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))

/* Management for ciphers/digests/pubkey-ciphers.  */

/* Structure for each registered `module'.  */
struct gcry_module
{
  struct gcry_module *next;     /* List pointers.      */
  struct gcry_module **prevp;
  void *spec;			/* The acctual specs.  */
  int flags;			/* Associated flags.   */
  int counter;			/* Use counter.        */
  unsigned int mod_id;		/* ID of this module.  */
};

/* Flags for the `flags' member of gcry_module_t.  */
#define FLAG_MODULE_DISABLED 1 << 0

gcry_err_code_t _gcry_module_add (gcry_module_t *entries,
				 unsigned int id,
				 void *spec,
				 gcry_module_t *module);

typedef int (*gcry_module_lookup_t) (void *spec, void *data);

/* Lookup a module specification by it's ID.  After a successfull
   lookup, the module has it's resource counter incremented.  */
gcry_module_t _gcry_module_lookup_id (gcry_module_t entries,
				       unsigned int id);

/* Internal function.  Lookup a module specification.  */
gcry_module_t _gcry_module_lookup (gcry_module_t entries, void *data,
				    gcry_module_lookup_t func);

/* Release a module.  In case the use-counter reaches zero, destroy
   the module.  */
void _gcry_module_release (gcry_module_t entry);

/* Add a reference to a module.  */
void _gcry_module_use (gcry_module_t module);

/* Return a list of module IDs.  */
gcry_err_code_t _gcry_module_list (gcry_module_t modules,
				   int **list, int *list_length);

gcry_err_code_t _gcry_cipher_init (void);
gcry_err_code_t _gcry_md_init (void);
gcry_err_code_t _gcry_ac_init (void);

/* Creates a new, empty data set and stores it in DATA.  */
gcry_err_code_t _gcry_ac_data_new (gcry_ac_data_t *data);

/* Destroys the data set DATA.  */
void _gcry_ac_data_destroy (gcry_ac_data_t data);

/* Create a copy of the data set DATA and store it in DATA_CP.  */
gcry_err_code_t _gcry_ac_data_copy (gcry_ac_data_t *data_cp, gcry_ac_data_t data);

/* Returns the number of named MPI values inside of the data set
   DATA.  */
unsigned int _gcry_ac_data_length (gcry_ac_data_t data);

/* Adds the value MPI to the data set DATA with the label NAME.  If
   there is already a value with that label, it is replaced, otherwise
   a new value is added. */
gcry_err_code_t _gcry_ac_data_set (gcry_ac_data_t data, unsigned int flags,
				   const char *name, gcry_mpi_t mpi);

/* Stores the value labelled with NAME found in the data set DATA in
   MPI.  The returned MPI value will be released in case
   gcry_ac_data_set is used to associate the label NAME with a
   different MPI value.  */
gcry_err_code_t _gcry_ac_data_get_name (gcry_ac_data_t data, unsigned int flags,
					const char *name, gcry_mpi_t *mpi);

/* Stores in NAME and MPI the named MPI value contained in the data
   set DATA with the index INDEX.  NAME or MPI may be NULL.  The
   returned MPI value will be released in case gcry_ac_data_set is
   used to associate the label NAME with a different MPI value.  */
gcry_err_code_t _gcry_ac_data_get_index (gcry_ac_data_t data, unsigned int flags,
					 unsigned int index,  const char **name, gcry_mpi_t *mpi);

/* Destroys any values contained in the data set DATA.  */
void _gcry_ac_data_clear (gcry_ac_data_t data);

/* Creates a new handle for the algorithm ALGORITHM and store it in
   HANDLE.  FLAGS is not used yet.  */
gcry_err_code_t _gcry_ac_open (gcry_ac_handle_t *handle, gcry_ac_id_t algorithm,
			       unsigned int flags);

/* Destroys the handle HANDLE.  */
void _gcry_ac_close (gcry_ac_handle_t handle);

/* Creates a new key of type TYPE, consisting of the MPI values
   contained in the data set DATA and stores it in KEY.  */
gcry_err_code_t _gcry_ac_key_init (gcry_ac_key_t *key, gcry_ac_handle_t handle,
				   gcry_ac_key_type_t type, gcry_ac_data_t data);

/* Generates a new key pair via the handle HANDLE of NBITS bits and
   stores it in KEY_PAIR.  In case non-standard settings are wanted, a
   pointer to a structure of type gcry_ac_key_spec_<algorithm>_t,
   matching the selected algorithm, can be given as KEY_SPEC.  */
gcry_err_code_t _gcry_ac_key_pair_generate (gcry_ac_handle_t handle, unsigned int nbits,
					    void *key_spec, gcry_ac_key_pair_t *key_pair,
					    gcry_mpi_t **misc_data);

/* Returns the key of type WHICH out of the key pair KEY_PAIR.  */
gcry_ac_key_t _gcry_ac_key_pair_extract (gcry_ac_key_pair_t key_pair, gcry_ac_key_type_t witch);

/* Destroys the key KEY.  */
void _gcry_ac_key_destroy (gcry_ac_key_t key);

/* Destroys the key pair KEY_PAIR.  */
void _gcry_ac_key_pair_destroy (gcry_ac_key_pair_t key_pair);

/* Returns the data set contained in the key KEY.  */
gcry_ac_data_t _gcry_ac_key_data_get (gcry_ac_key_t key);

/* Verifies that the key KEY is sane.  */
gcry_err_code_t _gcry_ac_key_test (gcry_ac_handle_t handle, gcry_ac_key_t key);

/* Stores the number of bits of the key KEY in NBITS.  */
gcry_err_code_t _gcry_ac_key_get_nbits (gcry_ac_handle_t handle, gcry_ac_key_t key,
					unsigned int *nbits);

/* Writes the 20 byte long key grip of the key KEY to KEY_GRIP.  */
gcry_err_code_t _gcry_ac_key_get_grip (gcry_ac_handle_t handle, gcry_ac_key_t key,
				       unsigned char *key_grip);

/* Encrypts the plain text MPI value DATA_PLAIN with the public key
   KEY under the control of the flags FLAGS and stores the resulting
   data set into DATA_ENCRYPTED.  */
gcry_err_code_t _gcry_ac_data_encrypt (gcry_ac_handle_t handle, unsigned int flags,
				       gcry_ac_key_t key, gcry_mpi_t data_plain,
				       gcry_ac_data_t *data_encrypted);

/* Decrypts the encrypted data contained in the data set
   DATA_ENCRYPTED with the secret key KEY under the control of the
   flags FLAGS and stores the resulting plain text MPI value in
   DATA_PLAIN.  */
gcry_err_code_t _gcry_ac_data_decrypt (gcry_ac_handle_t handle, unsigned int flags,
				       gcry_ac_key_t key, gcry_mpi_t *data_decrypted,
				       gcry_ac_data_t data_encrypted);

/* Signs the data contained in DATA with the secret key KEY and stores
   the resulting signature data set in DATA_SIGNATURE.  */
gcry_err_code_t _gcry_ac_data_sign (gcry_ac_handle_t handle, gcry_ac_key_t key,
				    gcry_mpi_t data, gcry_ac_data_t *data_signed);

/* Verifies that the signature contained in the data set
   DATA_SIGNATURE is indeed the result of signing the data contained
   in DATA with the secret key belonging to the public key KEY.  */
gcry_err_code_t _gcry_ac_data_verify (gcry_ac_handle_t handle, gcry_ac_key_t key,
				      gcry_mpi_t data, gcry_ac_data_t data_signed);

/* Stores the textual representation of the algorithm whose id is
   given in ALGORITHM in NAME.  */
gcry_err_code_t _gcry_ac_id_to_name (gcry_ac_id_t algorithm_id, const char **algorithm_name);

/* Stores the numeric ID of the algorithm whose textual representation
   is contained in NAME in ALGORITHM.  */
gcry_err_code_t _gcry_ac_name_to_id (const char *name, gcry_ac_id_t *algorithm_id);

/* Get a list consisting of the IDs of the loaded algorithm modules.
   If LIST is zero, write the number of loaded pubkey modules to
   LIST_LENGTH and return.  If LIST is non-zero, the first
   *LIST_LENGTH algorithm IDs are stored in LIST, which must be of
   according size.  In case there are less pubkey modules than
   *LIST_LENGTH, *LIST_LENGTH is updated to the correct number.  */
gcry_error_t _gcry_ac_list (int **list, int *list_length);

/* Encode a message according to the encoding method METHOD.  OPTIONS
   must be a pointer to a method-specific structure
   (gcry_ac_em*_t).  */
gcry_err_code_t gcry_ac_data_encode (gcry_ac_em_t method, unsigned int flags, void *options,
				     unsigned char *m, size_t m_n,
				     unsigned char **em, size_t *em_n);

/* Dencode a message according to the encoding method METHOD.  OPTIONS
   must be a pointer to a method-specific structure
   (gcry_ac_em*_t).  */
gcry_err_code_t _gcry_ac_data_decode (gcry_ac_em_t method, unsigned int flags, void *options,
				      unsigned char *em, size_t em_n,
				      unsigned char **m, size_t *m_n);

/* Convert an MPI into an octet string.  */
void _gcry_ac_mpi_to_os (gcry_mpi_t mpi, unsigned char *os, size_t os_n);

/* Convert an MPI into an newly allocated octet string.  */
gcry_err_code_t _gcry_ac_mpi_to_os_alloc (gcry_mpi_t mpi, unsigned char **os, size_t *os_n);

/* Convert an octet string into an MPI.  */
void _gcry_ac_os_to_mpi (gcry_mpi_t mpi, unsigned char *os, size_t os_n);

/* Encrypts the plain text message contained in M, which is of size
   M_N, with the public key KEY_PUBLIC according to the Encryption
   Scheme SCHEME_ID.  HANDLE is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The encrypted message will be stored in C and C_N.  */
gcry_err_code_t
_gcry_ac_data_encrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			      unsigned int flags, void *opts, gcry_ac_key_t key_public,
			      unsigned char *m, size_t m_n, unsigned char **c, size_t *c_n);

/* Decryptes the cipher message contained in C, which is of size C_N,
   with the secret key KEY_SECRET according to the Encryption Scheme
   SCHEME_ID.  Handle is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The decrypted message will be stored in M and M_N.  */
gcry_err_code_t _gcry_ac_data_decrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
					      unsigned int flags, void *opts,
					      gcry_ac_key_t key_secret,
					      unsigned char *c, size_t c_n,
					      unsigned char **m, size_t *m_n);

/* Signs the message contained in M, which is of size M_N, with the
   secret key KEY_SECRET according to the Signature Scheme SCHEME_ID.
   Handle is used for accessing the low-level cryptographic
   primitives.  If OPTS is not NULL, it has to be an anonymous
   structure specific to the chosen scheme (gcry_ac_ssa_*_t).  The
   signed message will be stored in S and S_N.  */
gcry_err_code_t _gcry_ac_data_sign_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
					   unsigned int flags, void *opts,
					   gcry_ac_key_t key_secret,
					   unsigned char *m, size_t m_n,
					   unsigned char **s, size_t *s_n);

/* Verifies that the signature contained in S, which is of length S_N,
   is indeed the result of signing the message contained in M, which
   is of size M_N, with the secret key belonging to the public key
   KEY_PUBLIC.  If OPTS is not NULL, it has to be an anonymous
   structure (gcry_ac_ssa_*_t) specific to the Signature Scheme, whose
   ID is contained in SCHEME_ID.  */
gcry_err_code_t _gcry_ac_data_verify_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
					     unsigned int flags, void *opts,
					     gcry_ac_key_t key_public,
					     unsigned char *m, size_t m_n,
					     unsigned char *s, size_t s_n);

/* Mark the algorithm identitified by HANDLE as `enabled' (this is the
   default).  */
gcry_error_t _gcry_ac_algorithm_enable (gcry_ac_handle_t handle);

/* Mark the algorithm identitified by HANDLE as `disabled'.  */
gcry_error_t _gcry_ac_algorithm_disable (gcry_ac_handle_t handle);

/* Return the amount of `elements' for certain cryptographic objects
   like keys (secret, public) and data (encrypted, signed).  */
void _gcry_ac_elements_amount_get (gcry_ac_handle_t handle,
				   unsigned int *elements_key_secret,
				   unsigned int *elements_key_public,
				   unsigned int *elements_encryption,
				   unsigned int *elements_signature);

/* Internal function used by pubkey.c.  Extract certain information
   from a given handle.  */
void _gcry_ac_info_get (gcry_ac_handle_t handle,
			gcry_ac_id_t *algorithm_id, unsigned int *algorithm_use_flags);

/* Convert the MPIs contained in the data set into an arg list
   suitable for passing to gcry_sexp_build_array().  */
gcry_err_code_t _gcry_ac_arg_list_from_data (gcry_ac_data_t data, void ***arg_list);

void _gcry_ac_progress_register (gcry_handler_progress_t cb,
				 void *cb_data);

void _gcry_ac_progress (const char *identifier, int c);

#define GCRY_AC_KEY_GRIP_FLAG_SEXP (1 << 0)

gcry_err_code_t _gcry_ac_key_get_grip_std (unsigned char *key_grip,
					   unsigned int flags, ...);


gcry_err_code_t _gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags);


void _gcry_md_info_get (gcry_md_hd_t handle,
			unsigned char **md_asn, size_t *md_asn_n, size_t *dlen);

#endif /* G10LIB_H */
