#include <gcrypt-md-internal.h>

gcry_error_t
gcry_core_md_open (gcry_core_context_t ctx, gcry_core_md_hd_t *h,
		   gcry_core_md_spec_t algo, unsigned int flags)
{
  return (*ctx->subsystems.md->open) (ctx, h, algo, flags);
}

void
gcry_core_md_set_cb (gcry_core_context_t ctx,
		     gcry_core_md_hd_t handle,
		     gcry_core_md_spec_t algo,
		     gcry_core_md_cb_t cb,
		     void *opaque)
{
  return (*ctx->subsystems.md->set_cb) (ctx, handle, algo, cb, opaque);
}

void
gcry_core_md_close (gcry_core_context_t ctx, gcry_core_md_hd_t hd)
{
  (*ctx->subsystems.md->close) (ctx, hd);
}

gcry_error_t
gcry_core_md_enable (gcry_core_context_t ctx,
		     gcry_core_md_hd_t hd, gcry_core_md_spec_t algo)
{
  return (*ctx->subsystems.md->enable) (ctx, hd, algo);
}

gcry_error_t
gcry_core_md_copy (gcry_core_context_t ctx,
		   gcry_core_md_hd_t *bhd, gcry_core_md_hd_t ahd)
{
  return (*ctx->subsystems.md->copy) (ctx, bhd, ahd);
}

void
gcry_core_md_reset (gcry_core_context_t ctx, gcry_core_md_hd_t hd)
{
  (*ctx->subsystems.md->reset) (ctx, hd);
}

void
gcry_core_md_write (gcry_core_context_t ctx,
		    gcry_core_md_hd_t hd, const void *buffer, size_t length)
{
  (*ctx->subsystems.md->write) (ctx, hd, buffer, length);
}

unsigned char *
gcry_core_md_read (gcry_core_context_t ctx,
		   gcry_core_md_hd_t hd, gcry_core_md_spec_t algo)
{
  return (*ctx->subsystems.md->read) (ctx, hd, algo);
}

gcry_error_t
gcry_core_md_hash_buffer (gcry_core_context_t ctx,
			  gcry_core_md_spec_t algo, void *digest,
			  const void *buffer, size_t length)
{
  return (*ctx->subsystems.md->hash_buffer) (ctx, algo, digest, buffer, length);
}

gcry_core_md_spec_t
gcry_core_md_get_algo (gcry_core_context_t ctx,
		       gcry_core_md_hd_t hd, unsigned int nth)
{
  return (*ctx->subsystems.md->get_algo) (ctx, hd, nth);
}

int
gcry_core_md_is_enabled (gcry_core_context_t ctx,
			 gcry_core_md_hd_t a, gcry_core_md_spec_t algo)
{
  return (*ctx->subsystems.md->is_enabled) (ctx, a, algo);
}

int
gcry_core_md_is_secure (gcry_core_context_t ctx, gcry_core_md_hd_t handle)
{
  return (*ctx->subsystems.md->is_secure) (ctx, handle);
}

gcry_error_t
gcry_core_md_setkey (gcry_core_context_t ctx,
		     gcry_core_md_hd_t hd, const void *key, size_t keylen)
{
  return (*ctx->subsystems.md->setkey) (ctx, hd, key, keylen);
}

gcry_error_t
gcry_core_md_final (gcry_core_context_t ctx, gcry_core_md_hd_t handle)
{
  return (*ctx->subsystems.md->final) (ctx, handle);
}

void
gcry_core_md_debug_start (gcry_core_context_t ctx,
			  gcry_core_md_hd_t handle, const char *suffix)
{
  (*ctx->subsystems.md->debug_start) (ctx, handle, suffix);
}

void
gcry_core_md_debug_stop (gcry_core_context_t ctx,
			 gcry_core_md_hd_t handle)
{
  (*ctx->subsystems.md->debug_stop) (ctx, handle);
}
