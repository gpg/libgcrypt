#include <gcrypt-cipher-internal.h>
#include <assert.h>

gcry_error_t
gcry_core_cipher_open (gcry_core_context_t ctx,
		       gcry_core_cipher_hd_t *handle,
		       gcry_core_cipher_spec_t algo,
		       int mode, unsigned int flags)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->open);
  return (*ctx->subsystems.cipher->open) (ctx, handle, algo, mode, flags);
}

void
gcry_core_cipher_set_cb (gcry_core_context_t ctx,
			 gcry_core_cipher_hd_t handle,
			 gcry_core_cipher_cb_t cb,
			 void *opaque)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->set_cb);
  return (*ctx->subsystems.cipher->set_cb) (ctx, handle, cb, opaque);
}

void
gcry_core_cipher_close (gcry_core_context_t ctx, gcry_core_cipher_hd_t h)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->close);
  (*ctx->subsystems.cipher->close) (ctx, h);
}

gcry_error_t
gcry_core_cipher_setkey (gcry_core_context_t ctx,
			 gcry_core_cipher_hd_t handle,
			 const char *key,
			 size_t length)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->setkey);
  return (*ctx->subsystems.cipher->setkey) (ctx, handle, key, length);
}

gcry_error_t
gcry_core_cipher_setiv (gcry_core_context_t ctx,
			gcry_core_cipher_hd_t handle,
			const char *iv,
			size_t length)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->setiv);
  return (*ctx->subsystems.cipher->setiv) (ctx, handle, iv, length);
}

gcry_error_t
gcry_core_cipher_reset (gcry_core_context_t ctx,
			gcry_core_cipher_hd_t handle)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->reset);
  return (*ctx->subsystems.cipher->reset) (ctx, handle);
}

gcry_error_t
gcry_core_cipher_sync (gcry_core_context_t ctx,
		       gcry_core_cipher_hd_t handle)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->sync);
  return (*ctx->subsystems.cipher->sync) (ctx, handle);
}

gcry_error_t
gcry_core_cipher_cts (gcry_core_context_t ctx,
		      gcry_core_cipher_hd_t handle,
		      unsigned int onoff)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->cts);
  return (*ctx->subsystems.cipher->cts) (ctx, handle, onoff);
}

gcry_error_t
gcry_core_cipher_setctr (gcry_core_context_t ctx,
			 gcry_core_cipher_hd_t handle,
			 const char *k,
			 size_t l)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->setctr);
  return (*ctx->subsystems.cipher->setctr) (ctx, handle, k, l);
}

gcry_error_t
gcry_core_cipher_set_cbc_mac (gcry_core_context_t ctx,
			      gcry_core_cipher_hd_t handle,
			      unsigned int onoff)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->set_cbc_mac);
  return (*ctx->subsystems.cipher->set_cbc_mac) (ctx, handle, onoff);
}

gcry_error_t
gcry_core_cipher_encrypt (gcry_core_context_t ctx,
			  gcry_core_cipher_hd_t h,
			  unsigned char *out, size_t outsize,
			  const unsigned char *in, size_t inlen)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->encrypt);
  return (*ctx->subsystems.cipher->encrypt) (ctx, h, out, outsize, in, inlen);
}

gcry_error_t
gcry_core_cipher_decrypt (gcry_core_context_t ctx,
			  gcry_core_cipher_hd_t h,
			  unsigned char *out, size_t outsize,
			  const unsigned char *in, size_t inlen)
{
  assert (ctx->subsystems.cipher && ctx->subsystems.cipher->decrypt);
  return (*ctx->subsystems.cipher->decrypt) (ctx, h, out, outsize, in, inlen);
}
