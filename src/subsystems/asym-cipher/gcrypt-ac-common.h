#ifndef _GCRYPT_AC_COMMON_H
#define _GCRYPT_AC_COMMON_H

#include <gcrypt-mpi-common.h>
#include <gcrypt-md-common.h>
#include <gcrypt-sexp-common.h>

/* This type represents a `handle' that is needed by functions
   performing cryptographic operations.  */
struct gcry_core_ac_handle;
typedef struct gcry_core_ac_handle *gcry_core_ac_handle_t;

typedef gcry_core_ac_handle_t gcry_core_ac_hd_t;

/* Type for the `generate' function.  */
typedef gcry_error_t (*gcry_core_ac_generate_t) (gcry_core_context_t ctx,
						 unsigned int flags,
						 unsigned int nbits,
						 void *spec,
						 gcry_core_mpi_t *skey,
						 gcry_core_mpi_t **retfactors);

/* Type for the `check_secret_key' function.  */
typedef gcry_error_t (*gcry_core_ac_check_secret_key_t) (gcry_core_context_t ctx,
							 unsigned int flags,
							 gcry_core_mpi_t *skey);

/* Type for the `encrypt' function.  */
typedef gcry_error_t (*gcry_core_ac_encrypt_t) (gcry_core_context_t ctx,
						unsigned int flags,
						gcry_core_mpi_t *resarr,
						gcry_core_mpi_t data,
						gcry_core_mpi_t *pkey);

/* Type for the `decrypt' function.  */
typedef gcry_error_t (*gcry_core_ac_decrypt_t) (gcry_core_context_t ctx,
						unsigned int flags,
						gcry_core_mpi_t *result,
						gcry_core_mpi_t *data,
						gcry_core_mpi_t *skey);

/* Type for the `sign' function.  */
typedef gcry_error_t (*gcry_core_ac_sign_t) (gcry_core_context_t ctx,
					     unsigned int flags,
					     gcry_core_mpi_t *resarr,
					     gcry_core_mpi_t data,
					     gcry_core_mpi_t *skey);

/* Type for the `verify' function.  */
typedef gcry_error_t (*gcry_core_ac_verify_t) (gcry_core_context_t ctx,
					       unsigned int flags,
					       gcry_core_mpi_t hash,
					       gcry_core_mpi_t *data,
					       gcry_core_mpi_t *pkey,
					       int (*cmp) (void *, gcry_core_mpi_t),
					       void *opaquev);

/* Type for the `get_nbits' function.  */
typedef unsigned (*gcry_core_ac_get_nbits_t) (gcry_core_context_t ctx,
					      unsigned int flags,
					      gcry_core_mpi_t *pkey);

/* Type for the `key_grip' function.  */
typedef gcry_error_t (*gcry_core_ac_keygrip_t) (gcry_core_context_t ctx,
						unsigned int flags,
						gcry_core_mpi_t *pkey,
						unsigned char *grip);

/* Module specification structure for message digests.  */
typedef struct gcry_core_ac_spec
{
  const char *name;
  char **aliases;
  const char *elements_pkey;
  const char *elements_skey;
  const char *elements_enc;
  const char *elements_sig;
  const char *elements_grip;
  int use;
  size_t keygrip_size;
  gcry_core_ac_generate_t generate;
  gcry_core_ac_check_secret_key_t check_secret_key;
  gcry_core_ac_encrypt_t encrypt;
  gcry_core_ac_decrypt_t decrypt;
  gcry_core_ac_sign_t sign;
  gcry_core_ac_verify_t verify;
  gcry_core_ac_get_nbits_t get_nbits;
  gcry_core_ac_keygrip_t keygrip;
} *gcry_core_ac_spec_t;



/* Extended open mechanism.  */

typedef enum
  {
    GCRY_CORE_AC_CB_GENERATE,
    GCRY_CORE_AC_CB_CHECK,
    GCRY_CORE_AC_CB_NBITS,
    GCRY_CORE_AC_CB_GRIP,
    GCRY_CORE_AC_CB_ENCRYPT,
    GCRY_CORE_AC_CB_DECRYPT,
    GCRY_CORE_AC_CB_SIGN,
    GCRY_CORE_AC_CB_VERIFY
  }
gcry_core_ac_cb_type_t;

typedef struct gcry_core_ac_cb_generate
{
  unsigned int nbits;
  void *spec;
  gcry_core_mpi_t *skey;
  gcry_core_mpi_t **retfactors;
} gcry_core_ac_cb_generate_t;

typedef struct gcry_core_ac_cb_check
{
  gcry_core_mpi_t *skey;
} gcry_core_ac_cb_check_t;

typedef struct gcry_core_ac_cb_nbits
{
  gcry_core_mpi_t *key;
  unsigned int *n;
} gcry_core_ac_cb_nbits_t;

typedef struct gcry_core_ac_cb_grip
{
  gcry_core_mpi_t *key;
  unsigned char *grip;
  const char *elems;
} gcry_core_ac_cb_grip_t;

typedef struct gcry_core_ac_cb_encrypt
{
  gcry_core_mpi_t *resarr;
  gcry_core_mpi_t data;
  gcry_core_mpi_t *pkey;
  unsigned int flags;
} gcry_core_ac_cb_encrypt_t;

typedef struct gcry_core_ac_cb_decrypt
{
  gcry_core_mpi_t *result;
  gcry_core_mpi_t *data;
  gcry_core_mpi_t *skey;
  unsigned int flags;
} gcry_core_ac_cb_decrypt_t;

typedef struct gcry_core_ac_cb_sign
{
  gcry_core_mpi_t *resarr;
  gcry_core_mpi_t data;
  gcry_core_mpi_t *skey;
  unsigned int flags;
} gcry_core_ac_cb_sign_t;

typedef struct gcry_core_ac_cb_verify
{
  gcry_core_mpi_t hash;
  gcry_core_mpi_t *data;
  gcry_core_mpi_t *pkey;
  unsigned int flags;
} gcry_core_ac_cb_verify_t;

typedef gcry_error_t (*gcry_core_ac_cb_t) (gcry_core_context_t ctx,
					   void *opaque,
					   gcry_core_ac_cb_type_t type,
					   void *args);



/* Key types.  */
typedef enum gcry_core_ac_key_type
  {
    GCRY_CORE_AC_KEY_SECRET,
    GCRY_CORE_AC_KEY_PUBLIC
  }
gcry_core_ac_key_type_t;

/* Encoding methods.  */
typedef enum gcry_core_ac_em
  {
    GCRY_CORE_AC_EME_PKCS_V1_5,
    GCRY_CORE_AC_EMSA_PKCS_V1_5,
  }
gcry_core_ac_em_t;

/* Encryption and Signature schemes.  */
typedef enum gcry_core_ac_scheme
  {
    GCRY_CORE_AC_ES_PKCS_V1_5,
    GCRY_CORE_AC_SSA_PKCS_V1_5,
  }
gcry_core_ac_scheme_t;

/* AC data.  */
#define GCRY_CORE_AC_FLAG_NO_BLINDING (1 << 2)

/* This type represents a `data set'.  */
typedef struct gcry_core_ac_data *gcry_core_ac_data_t;

/* This type represents a single `key', either a secret one or a
   public one.  */
typedef struct gcry_core_ac_key *gcry_core_ac_key_t;

/* This type represents a `key pair' containing a secret and a public
   key.  */
typedef struct gcry_core_ac_key_pair *gcry_core_ac_key_pair_t;

typedef gpg_error_t (*gcry_core_ac_data_read_cb_t) (gcry_core_context_t ctx,
						    void *opaque,
						    unsigned char *buffer,
						    size_t *buffer_n);

typedef gpg_error_t (*gcry_core_ac_data_write_cb_t) (gcry_core_context_t ctx,
						     void *opaque,
						     unsigned char *buffer,
						     size_t buffer_n);

typedef enum
  {
    GCRY_CORE_AC_IO_READABLE,
    GCRY_CORE_AC_IO_WRITABLE
  }
gcry_core_ac_io_mode_t;

typedef enum
  {
    GCRY_CORE_AC_IO_STRING,
    GCRY_CORE_AC_IO_CALLBACK
  }
gcry_core_ac_io_type_t;

typedef struct gcry_core_ac_io
{
  /* This is an INTERNAL structure, do NOT use manually.  */
  gcry_core_ac_io_mode_t mode;
  gcry_core_ac_io_type_t type;
  union
  {
    union
    {
      struct
      {
	gcry_core_ac_data_read_cb_t cb;
	void *opaque;
      } callback;
      struct
      {
	unsigned char *data;
	size_t data_n;
      } string;
      void *opaque;
    } readable;
    union
    {
      struct
      {
	gcry_core_ac_data_write_cb_t cb;
	void *opaque;
      } callback;
      struct
      {
	unsigned char **data;
	size_t *data_n;
      } string;
      void *opaque;
    } writable;
  };
}
gcry_core_ac_io_t;

/* Structure used for passing data to the implementation of the
   `EME-PKCS-V1_5' encoding method.  */
typedef struct gcry_core_ac_eme_pkcs_v1_5
{
  gcry_core_ac_key_t key;
  gcry_core_ac_handle_t handle;
} gcry_core_ac_eme_pkcs_v1_5_t;

typedef enum gcry_md_algos gcry_md_algo_t;

/* Structure used for passing data to the implementation of the
   `EMSA-PKCS-V1_5' encoding method.  */
typedef struct gcry_core_ac_emsa_pkcs_v1_5
{
  gcry_core_md_spec_t md;
  size_t em_n;
} gcry_core_ac_emsa_pkcs_v1_5_t;

/* Structure used for passing data to the implementation of the
   `SSA-PKCS-V1_5' signature scheme.  */
typedef struct gcry_core_ac_ssa_pkcs_v1_5
{
  gcry_core_md_spec_t md;
} gcry_core_ac_ssa_pkcs_v1_5_t;





gcry_error_t gcry_core_ac_data_new (gcry_core_context_t ctx,
				    unsigned int flags,
				    gcry_core_ac_data_t *data);

void gcry_core_ac_data_destroy (gcry_core_context_t ctx,
				    unsigned int flags,
				gcry_core_ac_data_t data);

gcry_error_t gcry_core_ac_data_copy (gcry_core_context_t ctx,
				    unsigned int flags,
				     gcry_core_ac_data_t *data_cp,
				     gcry_core_ac_data_t data);

unsigned int gcry_core_ac_data_length (gcry_core_context_t ctx,
				    unsigned int flags,
				       gcry_core_ac_data_t data);

void gcry_core_ac_data_clear (gcry_core_context_t ctx,
				    unsigned int flags,
			      gcry_core_ac_data_t data);

gcry_error_t gcry_core_ac_data_set (gcry_core_context_t ctx,
				    unsigned int flags,
				    gcry_core_ac_data_t data,
				    const char *name,
				    gcry_core_mpi_t mpi);

gcry_error_t gcry_core_ac_data_get (gcry_core_context_t ctx,
				    unsigned int flags,
				    gcry_core_ac_data_t data,
				    const char *name,
				    gcry_core_mpi_t *mpi);

gcry_error_t gcry_core_ac_data_get_idx (gcry_core_context_t ctx,
					unsigned int flags,
					gcry_core_ac_data_t data,
					unsigned int idx,
					char **name,
					gcry_core_mpi_t *mpi);

gcry_error_t gcry_core_ac_data_to_sexp (gcry_core_context_t ctx,
				    unsigned int flags,
					gcry_core_ac_data_t data,
					gcry_core_sexp_t *sexp,
					const char **identifiers);

gcry_error_t gcry_core_ac_data_from_sexp (gcry_core_context_t ctx,
				    unsigned int flags,
					  gcry_core_ac_data_t *data,
					  gcry_core_sexp_t sexp,
					  const char **identifiers);

void gcry_core_ac_io_init (gcry_core_context_t ctx,
				    unsigned int flags,
			   gcry_core_ac_io_t *ac_io,
			   gcry_core_ac_io_mode_t mode,
			   gcry_core_ac_io_type_t type, ...);

void gcry_core_ac_io_init_va (gcry_core_context_t ctx,
				    unsigned int flags,
			      gcry_core_ac_io_t *ac_io,
			      gcry_core_ac_io_mode_t mode,
			      gcry_core_ac_io_type_t type,
			      va_list ap);

gcry_error_t gcry_core_ac_open (gcry_core_context_t ctx,
				unsigned int flags,
				gcry_core_ac_handle_t *handle,
				gcry_core_ac_spec_t spec);

void gcry_core_ac_set_cb (gcry_core_context_t ctx,
			  gcry_core_ac_handle_t handle,
				unsigned int flags,
			  gcry_core_ac_cb_t cb,
			  void *opaque);

void gcry_core_ac_close (gcry_core_context_t ctx,
			 gcry_core_ac_handle_t handle,
			 unsigned int flags);

gcry_error_t gcry_core_ac_key_init (gcry_core_context_t ctx,
				unsigned int flags,
				    gcry_core_ac_key_t *key,
				    gcry_core_ac_key_type_t type,
				    gcry_core_ac_data_t data);

gcry_error_t gcry_core_ac_key_pair_generate (gcry_core_context_t ctx,
					     gcry_core_ac_handle_t handle,
					     unsigned int flags,
					     unsigned int nbits, void *spec,
					     gcry_core_ac_key_pair_t *key_pair,
					     gcry_core_mpi_t **misc_data);

gcry_core_ac_key_t gcry_core_ac_key_pair_extract (gcry_core_context_t ctx,
				unsigned int flags,
						  gcry_core_ac_key_pair_t pair,
						  gcry_core_ac_key_type_t type);

gcry_core_ac_data_t gcry_core_ac_key_data_get (gcry_core_context_t ctx,
				unsigned int flags,
					       gcry_core_ac_key_t key);

gcry_error_t gcry_core_ac_key_test (gcry_core_context_t ctx,
				    gcry_core_ac_handle_t handle,
				    unsigned int flags,
				    gcry_core_ac_key_t key);

gcry_error_t gcry_core_ac_key_get_nbits (gcry_core_context_t ctx,
					 gcry_core_ac_handle_t handle,
				unsigned int flags,
					 gcry_core_ac_key_t key,
					 unsigned int *nbits);

gcry_error_t gcry_core_ac_key_get_grip (gcry_core_context_t ctx,
					gcry_core_ac_handle_t handle,
				unsigned int flags,
					gcry_core_ac_key_t key,
					unsigned char *key_grip,
					size_t *key_grip_n);

void gcry_core_ac_key_destroy (gcry_core_context_t ctx,
				unsigned int flags,
			       gcry_core_ac_key_t key);

void gcry_core_ac_key_pair_destroy (gcry_core_context_t ctx,
				unsigned int flags,
				    gcry_core_ac_key_pair_t pair);

gcry_error_t gcry_core_ac_data_encode (gcry_core_context_t ctx,
				       gcry_core_ac_em_t method,
				unsigned int flags,
				       void *options,
				       gcry_core_ac_io_t *io_read,
				       gcry_core_ac_io_t *io_write);

gcry_error_t gcry_core_ac_data_decode (gcry_core_context_t ctx,
				       gcry_core_ac_em_t method,
				       unsigned int flags,
				       void *options,
				       gcry_core_ac_io_t *io_read,
				       gcry_core_ac_io_t *io_write);

void gcry_core_ac_mpi_to_os (gcry_core_context_t ctx,
				       unsigned int flags,
			     gcry_core_mpi_t mpi,
			     unsigned char *os,
			     size_t os_n);

gcry_error_t gcry_core_ac_mpi_to_os_alloc (gcry_core_context_t ctx,
				       unsigned int flags,
					   gcry_core_mpi_t mpi,
					   unsigned char **os,
					   size_t *os_n);

void gcry_core_ac_os_to_mpi (gcry_core_context_t ctx,
				       unsigned int flags,
			     gcry_core_mpi_t mpi,
			     unsigned char *os,
			     size_t os_n);

gcry_error_t gcry_core_ac_data_encrypt (gcry_core_context_t ctx,
					gcry_core_ac_handle_t handle,
					unsigned int flags,
					gcry_core_ac_key_t key,
					gcry_core_mpi_t data_plain,
					gcry_core_ac_data_t *data_encrypted);

gcry_error_t gcry_core_ac_data_decrypt (gcry_core_context_t ctx,
					gcry_core_ac_handle_t handle,
					unsigned int flags,
					gcry_core_ac_key_t key,
					gcry_core_mpi_t *data_plain,
					gcry_core_ac_data_t data_encrypted);

gcry_error_t gcry_core_ac_data_sign (gcry_core_context_t ctx,
				     gcry_core_ac_handle_t handle,
				       unsigned int flags,
				     gcry_core_ac_key_t key,
				     gcry_core_mpi_t data,
				     gcry_core_ac_data_t *data_signature);

gcry_error_t gcry_core_ac_data_verify (gcry_core_context_t ctx,
				       gcry_core_ac_handle_t handle,
				       unsigned int flags,
				       gcry_core_ac_key_t key,
				       gcry_core_mpi_t data,
				       gcry_core_ac_data_t data_signature);
/* FIXME: should we use a boolean type here? */

gcry_error_t gcry_core_ac_data_encrypt_scheme (gcry_core_context_t ctx,
					       gcry_core_ac_handle_t handle,
					       gcry_core_ac_scheme_t scheme,
					       unsigned int flags,
					       void *opts,
					       gcry_core_ac_key_t key,
					       gcry_core_ac_io_t *io_message,
					       gcry_core_ac_io_t *io_cipher);

gcry_error_t gcry_core_ac_data_decrypt_scheme (gcry_core_context_t ctx,
					       gcry_core_ac_handle_t handle,
					       gcry_core_ac_scheme_t scheme,
					       unsigned int flags,
					       void *opts,
					       gcry_core_ac_key_t key,
					       gcry_core_ac_io_t *io_cipher,
					       gcry_core_ac_io_t *io_message);

gcry_error_t gcry_core_ac_data_sign_scheme (gcry_core_context_t ctx,
					    gcry_core_ac_handle_t handle,
					    gcry_core_ac_scheme_t scheme,
					    unsigned int flags,
					    void *opts,
					    gcry_core_ac_key_t key,
					    gcry_core_ac_io_t *io_message,
					    gcry_core_ac_io_t *io_signature);

gcry_error_t gcry_core_ac_data_verify_scheme (gcry_core_context_t ctx,
					      gcry_core_ac_handle_t handle,
					      gcry_core_ac_scheme_t scheme,
					      unsigned int flags,
					      void *opts,
					      gcry_core_ac_key_t key,
					      gcry_core_ac_io_t *io_message,
					      gcry_core_ac_io_t *io_signature);



typedef gcry_error_t (*gcry_subsystem_ac_prepare_t) (gcry_core_context_t ctx,
						     void **ptr);
typedef gcry_error_t (*gcry_subsystem_ac_data_new_t) (gcry_core_context_t ctx,
				       unsigned int flags,
						      gcry_core_ac_data_t *data);
typedef void (*gcry_subsystem_ac_data_destroy_t) (gcry_core_context_t ctx,
				       unsigned int flags,
						  gcry_core_ac_data_t data);
typedef gcry_error_t (*gcry_subsystem_ac_data_copy_t) (gcry_core_context_t ctx,
				       unsigned int flags,
						       gcry_core_ac_data_t *data_cp,
						       gcry_core_ac_data_t data);
typedef unsigned int (*gcry_subsystem_ac_data_length_t) (gcry_core_context_t ctx,
				       unsigned int flags,
							 gcry_core_ac_data_t data);
typedef void (*gcry_subsystem_ac_data_clear_t) (gcry_core_context_t ctx,
				       unsigned int flags,
						gcry_core_ac_data_t data);
typedef gcry_error_t (*gcry_subsystem_ac_data_set_t) (gcry_core_context_t ctx,
				       unsigned int flags,
						      gcry_core_ac_data_t data,
						      const char *name,
						      gcry_core_mpi_t mpi);
typedef gcry_error_t (*gcry_subsystem_ac_data_get_t) (gcry_core_context_t ctx,
						      unsigned int flags,
						      gcry_core_ac_data_t data,
						      const char *name,
						      gcry_core_mpi_t *mpi);
typedef gcry_error_t (*gcry_subsystem_ac_data_get_idx_t) (gcry_core_context_t ctx,
							  unsigned int flags,
							  gcry_core_ac_data_t data,
							  unsigned int idx,
							  char **name,
							  gcry_core_mpi_t *mpi);
typedef gcry_error_t (*gcry_subsystem_ac_data_to_sexp_t) (gcry_core_context_t ctx,
				       unsigned int flags,
							  gcry_core_ac_data_t data,
							  gcry_core_sexp_t *sexp,
							  const char **identifiers);
typedef gcry_error_t (*gcry_subsystem_ac_data_from_sexp_t) (gcry_core_context_t ctx,
				       unsigned int flags,
							    gcry_core_ac_data_t *data,
							    gcry_core_sexp_t sexp,
							    const char **identifiers);
typedef void (*gcry_subsystem_ac_io_init_va_t) (gcry_core_context_t ctx,
				       unsigned int flags,
						gcry_core_ac_io_t *ac_io,
						gcry_core_ac_io_mode_t mode,
						gcry_core_ac_io_type_t type,
						va_list ap);
typedef gcry_error_t (*gcry_subsystem_ac_open_t) (gcry_core_context_t ctx,
				       unsigned int flags,
						  gcry_core_ac_handle_t *handle,
						  gcry_core_ac_spec_t spec);
typedef void (*gcry_subsystem_ac_set_cb_t) (gcry_core_context_t ctx,
					    gcry_core_ac_handle_t handle,
				       unsigned int flags,
					    gcry_core_ac_cb_t cb,
					    void *opaque);
typedef void (*gcry_subsystem_ac_close_t) (gcry_core_context_t ctx,
					   gcry_core_ac_handle_t handle,
					   unsigned int flags);
typedef gcry_error_t (*gcry_subsystem_ac_key_init_t) (gcry_core_context_t ctx,
				       unsigned int flags,
						      gcry_core_ac_key_t *key,
						      gcry_core_ac_key_type_t type,
						      gcry_core_ac_data_t data);
typedef gcry_error_t (*gcry_subsystem_ac_key_pair_generate_t) (gcry_core_context_t ctx,
							       gcry_core_ac_handle_t handle,
				       unsigned int flags,
							       unsigned int nbits, void *spec,
							       gcry_core_ac_key_pair_t *key_pair,
							       gcry_core_mpi_t **misc_data);
typedef gcry_core_ac_key_t (*gcry_subsystem_ac_key_pair_extract_t) (gcry_core_context_t ctx,
				       unsigned int flags,
								    gcry_core_ac_key_pair_t pair,
								    gcry_core_ac_key_type_t type);
typedef gcry_core_ac_data_t (*gcry_subsystem_ac_key_data_get_t) (gcry_core_context_t ctx,
				       unsigned int flags,
								 gcry_core_ac_key_t key);
typedef gcry_error_t (*gcry_subsystem_ac_key_test_t) (gcry_core_context_t ctx,
						      gcry_core_ac_handle_t handle,
				unsigned int flags,
						      gcry_core_ac_key_t key);
typedef gcry_error_t (*gcry_subsystem_ac_key_get_nbits_t) (gcry_core_context_t ctx,
							   gcry_core_ac_handle_t handle,
				unsigned int flags,
							   gcry_core_ac_key_t key,
							   unsigned int *nbits);
typedef gcry_error_t (*gcry_subsystem_ac_key_get_grip_t) (gcry_core_context_t ctx,
							  gcry_core_ac_handle_t handle,
				unsigned int flags,
							  gcry_core_ac_key_t key,
							  unsigned char *key_grip,
							  size_t *key_grip_n);
typedef void (*gcry_subsystem_ac_key_destroy_t) (gcry_core_context_t ctx,
				unsigned int flags,
						 gcry_core_ac_key_t key);
typedef void (*gcry_subsystem_ac_key_pair_destroy_t) (gcry_core_context_t ctx,
				unsigned int flags,
						      gcry_core_ac_key_pair_t pair);
typedef gcry_error_t (*gcry_subsystem_ac_data_encode_t) (gcry_core_context_t ctx,
							 gcry_core_ac_em_t method,
							 unsigned int flags,
							 void *options,
							 gcry_core_ac_io_t *io_read,
							 gcry_core_ac_io_t *io_write);
typedef gcry_error_t (*gcry_subsystem_ac_data_decode_t) (gcry_core_context_t ctx,
							 gcry_core_ac_em_t method,
							 unsigned int flags,
							 void *options,
							 gcry_core_ac_io_t *io_read,
							 gcry_core_ac_io_t *io_write);
typedef void (*gcry_subsystem_ac_mpi_to_os_t) (gcry_core_context_t ctx,
				unsigned int flags,
					       gcry_core_mpi_t mpi,
					       unsigned char *os,
					       size_t os_n);
typedef gcry_error_t (*gcry_subsystem_ac_mpi_to_os_alloc_t) (gcry_core_context_t ctx,
				unsigned int flags,
							     gcry_core_mpi_t mpi,
							     unsigned char **os,
							     size_t *os_n);
typedef void (*gcry_subsystem_ac_os_to_mpi_t) (gcry_core_context_t ctx,
				unsigned int flags,
					       gcry_core_mpi_t mpi,
					       unsigned char *os,
					       size_t os_n);
typedef gcry_error_t (*gcry_subsystem_ac_data_encrypt_t) (gcry_core_context_t ctx,
							  gcry_core_ac_handle_t handle,
							  unsigned int flags,
							  gcry_core_ac_key_t key,
							  gcry_core_mpi_t data_plain,
							  gcry_core_ac_data_t *data_encrypted);
typedef gcry_error_t (*gcry_subsystem_ac_data_decrypt_t) (gcry_core_context_t ctx,
							  gcry_core_ac_handle_t handle,
							  unsigned int flags,
							  gcry_core_ac_key_t key,
							  gcry_core_mpi_t *data_plain,
							  gcry_core_ac_data_t data_encrypted);
typedef gcry_error_t (*gcry_subsystem_ac_data_sign_t) (gcry_core_context_t ctx,
						       gcry_core_ac_handle_t handle,
				unsigned int flags,
						       gcry_core_ac_key_t key,
						       gcry_core_mpi_t data,
						       gcry_core_ac_data_t *data_signature);
typedef gcry_error_t (*gcry_subsystem_ac_data_verify_t) (gcry_core_context_t ctx,
							 gcry_core_ac_handle_t handle,
							 unsigned int flags,
							 gcry_core_ac_key_t key,
							 gcry_core_mpi_t data,
							 gcry_core_ac_data_t data_signature);
typedef gcry_error_t (*gcry_subsystem_ac_data_encrypt_scheme_t) (gcry_core_context_t ctx,
								 gcry_core_ac_handle_t handle,
								 gcry_core_ac_scheme_t scheme,
								 unsigned int flags,
								 void *opts,
								 gcry_core_ac_key_t key,
								 gcry_core_ac_io_t *io_message,
								 gcry_core_ac_io_t *io_cipher);
typedef gcry_error_t (*gcry_subsystem_ac_data_decrypt_scheme_t) (gcry_core_context_t ctx,
								 gcry_core_ac_handle_t handle,
								 gcry_core_ac_scheme_t scheme,
								 unsigned int flags,
								 void *opts,
								 gcry_core_ac_key_t key,
								 gcry_core_ac_io_t *io_cipher,
								 gcry_core_ac_io_t *io_message);
typedef gcry_error_t (*gcry_subsystem_ac_data_sign_scheme_t) (gcry_core_context_t ctx,
							      gcry_core_ac_handle_t handle,
							      gcry_core_ac_scheme_t scheme,
							      unsigned int flags,
							      void *opts,
							      gcry_core_ac_key_t key,
							      gcry_core_ac_io_t *io_message,
							      gcry_core_ac_io_t *io_signature);
typedef gcry_error_t (*gcry_subsystem_ac_data_verify_scheme_t) (gcry_core_context_t ctx,
								gcry_core_ac_handle_t handle,
								gcry_core_ac_scheme_t scheme,
								unsigned int flags,
								void *opts,
								gcry_core_ac_key_t key,
								gcry_core_ac_io_t *io_message,
								gcry_core_ac_io_t *io_signature);

typedef struct gcry_core_subsystem_ac
{
  gcry_subsystem_ac_prepare_t prepare;
  gcry_subsystem_ac_data_new_t data_new;
  gcry_subsystem_ac_data_destroy_t data_destroy;
  gcry_subsystem_ac_data_copy_t data_copy;
  gcry_subsystem_ac_data_length_t data_length;
  gcry_subsystem_ac_data_clear_t data_clear;
  gcry_subsystem_ac_data_set_t data_set;
  gcry_subsystem_ac_data_get_t data_get;
  gcry_subsystem_ac_data_get_idx_t data_get_idx;
  gcry_subsystem_ac_data_to_sexp_t data_to_sexp;
  gcry_subsystem_ac_data_from_sexp_t data_from_sexp;
  gcry_subsystem_ac_io_init_va_t io_init_va;
  gcry_subsystem_ac_open_t open;
  gcry_subsystem_ac_set_cb_t set_cb;
  gcry_subsystem_ac_close_t close;
  gcry_subsystem_ac_key_init_t key_init;
  gcry_subsystem_ac_key_pair_generate_t key_pair_generate;
  gcry_subsystem_ac_key_pair_extract_t key_pair_extract;
  gcry_subsystem_ac_key_data_get_t key_data_get;
  gcry_subsystem_ac_key_test_t key_test;
  gcry_subsystem_ac_key_get_nbits_t key_get_nbits;
  gcry_subsystem_ac_key_get_grip_t key_get_grip;
  gcry_subsystem_ac_key_destroy_t key_destroy;
  gcry_subsystem_ac_key_pair_destroy_t key_pair_destroy;
  gcry_subsystem_ac_data_encode_t data_encode;
  gcry_subsystem_ac_data_decode_t data_decode;
  gcry_subsystem_ac_mpi_to_os_t mpi_to_os;
  gcry_subsystem_ac_mpi_to_os_alloc_t mpi_to_os_alloc;
  gcry_subsystem_ac_os_to_mpi_t os_to_mpi;
  gcry_subsystem_ac_data_encrypt_t data_encrypt;
  gcry_subsystem_ac_data_decrypt_t data_decrypt;
  gcry_subsystem_ac_data_sign_t data_sign;
  gcry_subsystem_ac_data_verify_t data_verify;
  gcry_subsystem_ac_data_encrypt_scheme_t data_encrypt_scheme;
  gcry_subsystem_ac_data_decrypt_scheme_t data_decrypt_scheme;
  gcry_subsystem_ac_data_sign_scheme_t data_sign_scheme;
  gcry_subsystem_ac_data_verify_scheme_t data_verify_scheme;
} *gcry_core_subsystem_ac_t;

extern gcry_core_subsystem_ac_t gcry_core_subsystem_ac;
void gcry_core_set_subsystem_ac (gcry_core_context_t ctx, gcry_core_subsystem_ac_t ac);

#endif
