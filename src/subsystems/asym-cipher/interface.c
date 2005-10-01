#include <gcrypt-ac-internal.h>

gcry_error_t
gcry_core_ac_data_new (gcry_core_context_t ctx,
		       unsigned int flags,
		       gcry_core_ac_data_t *data)
{
  return (*ctx->subsystems.ac->data_new) (ctx, flags, data);
}

void
gcry_core_ac_data_destroy (gcry_core_context_t ctx,
			   unsigned int flags,
			   gcry_core_ac_data_t data)
{
  (*ctx->subsystems.ac->data_destroy) (ctx, flags, data);
}


gcry_error_t
gcry_core_ac_data_copy (gcry_core_context_t ctx,
			   unsigned int flags,
			gcry_core_ac_data_t *data_cp, gcry_core_ac_data_t data)
{
  return (*ctx->subsystems.ac->data_copy) (ctx, flags, data_cp, data);
}

unsigned int
gcry_core_ac_data_length (gcry_core_context_t ctx,
			   unsigned int flags,
			  gcry_core_ac_data_t data)
{
  return (*ctx->subsystems.ac->data_length) (ctx, flags, data);
}

gcry_error_t
gcry_core_ac_data_set (gcry_core_context_t ctx,
			   unsigned int flags,
		       gcry_core_ac_data_t data,
		       const char *name, gcry_core_mpi_t mpi)
{
  return (*ctx->subsystems.ac->data_set) (ctx, flags, data, name, mpi);
}

gcry_error_t
gcry_core_ac_data_get (gcry_core_context_t ctx,
		       unsigned int flags,
		       gcry_core_ac_data_t data,
		       const char *name, gcry_core_mpi_t *mpi)
{
  return (*ctx->subsystems.ac->data_get) (ctx, flags, data, name, mpi);
}

gcry_error_t
gcry_core_ac_data_get_idx (gcry_core_context_t ctx,
			   unsigned int flags,
			   gcry_core_ac_data_t data,
			   unsigned int idx,
			   char **name,
			   gcry_core_mpi_t *mpi)
{
  return (*ctx->subsystems.ac->data_get_idx) (ctx, flags, data, idx, name, mpi);
}

gcry_error_t
gcry_core_ac_data_to_sexp (gcry_core_context_t ctx,
			   unsigned int flags,
			   gcry_core_ac_data_t data, gcry_core_sexp_t *sexp,
			   const char **identifiers)
{
  return (*ctx->subsystems.ac->data_to_sexp) (ctx, flags, data, sexp, identifiers);
}

gcry_error_t
gcry_core_ac_data_from_sexp (gcry_core_context_t ctx,
			   unsigned int flags,
			     gcry_core_ac_data_t *data_set, gcry_core_sexp_t sexp,
			     const char **identifiers)
{
  return (*ctx->subsystems.ac->data_from_sexp) (ctx, flags, data_set, sexp, identifiers);
}

void
gcry_core_ac_data_clear (gcry_core_context_t ctx,
			   unsigned int flags,
			 gcry_core_ac_data_t data)
{
  (*ctx->subsystems.ac->data_clear) (ctx, flags, data);
}

void
gcry_core_ac_io_init (gcry_core_context_t ctx,
			   unsigned int flags,
		      gcry_core_ac_io_t *ac_io,
		      gcry_core_ac_io_mode_t mode,
		      gcry_core_ac_io_type_t type,
		      ...)
{
  va_list ap;

  va_start (ap, type);
  (*ctx->subsystems.ac->io_init_va) (ctx, flags, ac_io, mode, type, ap);
  va_end (ap);
}

void
gcry_core_ac_io_init_va (gcry_core_context_t ctx,
			   unsigned int flags,
			 gcry_core_ac_io_t *ac_io,
			 gcry_core_ac_io_mode_t mode,
			 gcry_core_ac_io_type_t type,
			 va_list ap)
{
  (*ctx->subsystems.ac->io_init_va) (ctx, flags, ac_io, mode, type, ap);
}

gcry_error_t
gcry_core_ac_open (gcry_core_context_t ctx,
			   unsigned int flags,
		   gcry_core_ac_handle_t *handle,
		   gcry_core_ac_spec_t spec)
{
  return (*ctx->subsystems.ac->open) (ctx, flags, handle, spec);
}

void
gcry_core_ac_set_cb (gcry_core_context_t ctx,
		     gcry_core_ac_handle_t handle,
		     unsigned int flags,
		     gcry_core_ac_cb_t cb,
		     void *opaque)
{
  return (*ctx->subsystems.ac->set_cb) (ctx, handle, flags, cb, opaque);
}

void
gcry_core_ac_close (gcry_core_context_t ctx,
		    gcry_core_ac_handle_t handle,
		     unsigned int flags)
{
  (*ctx->subsystems.ac->close) (ctx, handle, flags);
}

gcry_error_t
gcry_core_ac_key_init (gcry_core_context_t ctx,
		     unsigned int flags,
		       gcry_core_ac_key_t *key,
		       gcry_core_ac_key_type_t type,
		       gcry_core_ac_data_t data)
{
  return (*ctx->subsystems.ac->key_init) (ctx, flags, key, type, data);
}

gcry_error_t
gcry_core_ac_key_pair_generate (gcry_core_context_t ctx,
				gcry_core_ac_handle_t handle,
		     unsigned int flags,
				unsigned int nbits,
				void *spec,
				gcry_core_ac_key_pair_t *pair,
				gcry_core_mpi_t **misc_data)
{
  return (*ctx->subsystems.ac->key_pair_generate) (ctx, handle,
						   flags,
						   nbits, spec, pair, misc_data);
}

gcry_core_ac_key_t
gcry_core_ac_key_pair_extract (gcry_core_context_t ctx,
		     unsigned int flags,
			       gcry_core_ac_key_pair_t pair,
			       gcry_core_ac_key_type_t type)
{
  return (*ctx->subsystems.ac->key_pair_extract) (ctx, flags, pair, type);
}

void
gcry_core_ac_key_destroy (gcry_core_context_t ctx,
		     unsigned int flags,
			  gcry_core_ac_key_t key)
{
  (*ctx->subsystems.ac->key_destroy) (ctx, flags, key);
}

void
gcry_core_ac_key_pair_destroy (gcry_core_context_t ctx,
		     unsigned int flags,
			       gcry_core_ac_key_pair_t pair)
{
  (*ctx->subsystems.ac->key_pair_destroy) (ctx, flags, pair);
}

gcry_core_ac_data_t
gcry_core_ac_key_data_get (gcry_core_context_t ctx,
		     unsigned int flags,
			   gcry_core_ac_key_t key)
{
  return (*ctx->subsystems.ac->key_data_get) (ctx, flags, key);
}

gcry_error_t
gcry_core_ac_key_test (gcry_core_context_t ctx,
		       gcry_core_ac_handle_t handle,
		     unsigned int flags,
		       gcry_core_ac_key_t key)
{
  return (*ctx->subsystems.ac->key_test) (ctx, handle, flags, key);
}

gcry_error_t
gcry_core_ac_key_get_nbits (gcry_core_context_t ctx,
			    gcry_core_ac_handle_t handle,
		     unsigned int flags,
			    gcry_core_ac_key_t key,
			    unsigned int *nbits)
{
  return (*ctx->subsystems.ac->key_get_nbits) (ctx, handle, flags, key, nbits);
}

gcry_error_t
gcry_core_ac_key_get_grip (gcry_core_context_t ctx,
			   gcry_core_ac_handle_t handle,
		     unsigned int flags,
			   gcry_core_ac_key_t key,
			   unsigned char *key_grip,
			   size_t *key_grip_n)
{
  return (*ctx->subsystems.ac->key_get_grip) (ctx,
					     handle, flags,
					      key, key_grip, key_grip_n);
}

gcry_error_t
gcry_core_ac_data_encrypt (gcry_core_context_t ctx,
			   gcry_core_ac_handle_t handle,
			   unsigned int flags,
			   gcry_core_ac_key_t key,
			   gcry_core_mpi_t data_plain,
			   gcry_core_ac_data_t *data_encrypted)
{
  return (*ctx->subsystems.ac->data_encrypt) (ctx, handle, flags, key, data_plain, data_encrypted);
}

gcry_error_t
gcry_core_ac_data_decrypt (gcry_core_context_t ctx,
			   gcry_core_ac_handle_t handle,
			   unsigned int flags,
			   gcry_core_ac_key_t key,
			   gcry_core_mpi_t *data_plain,
			   gcry_core_ac_data_t data_encrypted)
{
  return (*ctx->subsystems.ac->data_decrypt) (ctx, handle, flags, key, data_plain, data_encrypted);
}

/* Signs the data contained in DATA with the secret key KE) ( and stores
   the resulting signature data set in DATA_SIGNATURE.  */
gcry_error_t
gcry_core_ac_data_sign (gcry_core_context_t ctx,
			gcry_core_ac_handle_t handle,
		     unsigned int flags,
			gcry_core_ac_key_t key,
			gcry_core_mpi_t data,
			gcry_core_ac_data_t *data_signature)
{
  return (*ctx->subsystems.ac->data_sign) (ctx, handle, flags, key, data, data_signature);
}

gcry_error_t
gcry_core_ac_data_verify (gcry_core_context_t ctx,
			  gcry_core_ac_handle_t handle,
		     unsigned int flags,
			  gcry_core_ac_key_t key,
			  gcry_core_mpi_t data,
			  gcry_core_ac_data_t data_signature)
{
  return (*ctx->subsystems.ac->data_verify) (ctx, handle, flags, key, data, data_signature);
}

void
gcry_core_ac_mpi_to_os (gcry_core_context_t ctx,
		     unsigned int flags,
			gcry_core_mpi_t mpi,
			unsigned char *os, size_t os_n)
{
  (*ctx->subsystems.ac->mpi_to_os) (ctx, flags, mpi, os, os_n);
}

gcry_error_t
gcry_core_ac_mpi_to_os_alloc (gcry_core_context_t ctx,
		     unsigned int flags,
			      gcry_core_mpi_t mpi,
			      unsigned char **os, size_t *os_n)
{
  return (*ctx->subsystems.ac->mpi_to_os_alloc) (ctx, flags, mpi, os, os_n);
}

void
gcry_core_ac_os_to_mpi (gcry_core_context_t ctx,
		     unsigned int flags,
			gcry_core_mpi_t mpi,
			unsigned char *os, size_t os_n)
{
  (*ctx->subsystems.ac->os_to_mpi) (ctx, flags, mpi, os, os_n);
}

gcry_error_t
gcry_core_ac_data_encode (gcry_core_context_t ctx,
			  gcry_core_ac_em_t method,
			  unsigned int flags,
			  void *options,
			  gcry_core_ac_io_t *ac_io_read,
			  gcry_core_ac_io_t *ac_io_write)
{
  return (*ctx->subsystems.ac->data_encode) (ctx, method, flags, options,
					     ac_io_read, ac_io_write);
}
			   
gcry_error_t
gcry_core_ac_data_decode (gcry_core_context_t ctx,
			  gcry_core_ac_em_t method,
			  unsigned int flags,
			  void *options,
			  gcry_core_ac_io_t *ac_io_read,
			  gcry_core_ac_io_t *ac_io_write)
{
  return (*ctx->subsystems.ac->data_decode) (ctx, method, flags, options,
					     ac_io_read, ac_io_write);
}


gcry_error_t
gcry_core_ac_data_encrypt_scheme (gcry_core_context_t ctx,
				  gcry_core_ac_handle_t handle,
				  gcry_core_ac_scheme_t scheme_id,
				  unsigned int flags,
				  void *opts,
				  gcry_core_ac_key_t key,
				  gcry_core_ac_io_t *io_message,
				  gcry_core_ac_io_t *io_cipher)
{
  return (*ctx->subsystems.ac->data_encrypt_scheme) (ctx, handle, scheme_id, flags, opts, key, io_message, io_cipher);
}

gcry_error_t
gcry_core_ac_data_decrypt_scheme (gcry_core_context_t ctx,
				  gcry_core_ac_handle_t handle,
				  gcry_core_ac_scheme_t scheme_id,
				  unsigned int flags,
				  void *opts,
				  gcry_core_ac_key_t key,
				  gcry_core_ac_io_t *io_cipher,
				  gcry_core_ac_io_t *io_message)
{
  return (*ctx->subsystems.ac->data_decrypt_scheme) (ctx, handle, scheme_id, flags, opts, key, io_cipher, io_message);
}

gcry_error_t
gcry_core_ac_data_sign_scheme (gcry_core_context_t ctx,
			       gcry_core_ac_handle_t handle,
			       gcry_core_ac_scheme_t scheme_id,
			       unsigned int flags,
			       void *opts,
			       gcry_core_ac_key_t key,
			       gcry_core_ac_io_t *io_message,
			       gcry_core_ac_io_t *io_signature)
{
  return (*ctx->subsystems.ac->data_sign_scheme) (ctx, handle, scheme_id, flags, opts, key, io_message, io_signature);
}

gcry_error_t
gcry_core_ac_data_verify_scheme (gcry_core_context_t ctx,
				 gcry_core_ac_handle_t handle,
				 gcry_core_ac_scheme_t scheme_id,
				 unsigned int flags,
				 void *opts,
				 gcry_core_ac_key_t key,
				 gcry_core_ac_io_t *io_message,
				 gcry_core_ac_io_t *io_signature)
{
  return (*ctx->subsystems.ac->data_verify_scheme) (ctx, handle, scheme_id, flags, opts, key, io_message, io_signature);
}
