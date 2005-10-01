#include <gcrypt-random-internal.h>
#include <assert.h>

gcry_error_t
gcry_core_random_prepare (gcry_core_context_t ctx, void **ptr)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->prepare);
  return (*ctx->subsystems.random->prepare) (ctx, ptr);
}

void
gcry_core_random_finish (gcry_core_context_t ctx, void *ptr)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->finish);
  (*ctx->subsystems.random->finish) (ctx, ptr);
}

void
gcry_core_random_dump_stats (gcry_core_context_t ctx)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->dump_stats);
  (*ctx->subsystems.random->dump_stats) (ctx);
}

gcry_error_t
gcry_core_random_add_bytes (gcry_core_context_t ctx,
			    const void *buf, size_t buflen, int quality)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->add_bytes);
  return (*ctx->subsystems.random->add_bytes) (ctx, buf, buflen, quality);
}

void *
gcry_core_random_bytes (gcry_core_context_t ctx,
			size_t nbytes, enum gcry_random_level level)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->bytes);
  return (*ctx->subsystems.random->bytes) (ctx, nbytes, level);
}

void *
gcry_core_random_bytes_secure (gcry_core_context_t ctx,
			       size_t nbytes, enum gcry_random_level level)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->bytes_secure);
  return (*ctx->subsystems.random->bytes_secure) (ctx, nbytes, level);
}

void
gcry_core_random_randomize (gcry_core_context_t ctx,
			    byte *buffer, size_t length, enum gcry_random_level level)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->randomize);
  (*ctx->subsystems.random->randomize) (ctx, buffer, length, level);
}

void
gcry_core_random_seed_file_set (gcry_core_context_t ctx, const char *filename)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->seed_file_set);
  (*ctx->subsystems.random->seed_file_set) (ctx, filename);
}

void
gcry_core_random_seed_file_update (gcry_core_context_t ctx)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->seed_file_update);
  (*ctx->subsystems.random->seed_file_update) (ctx);
}

void
gcry_core_random_fast_poll (gcry_core_context_t ctx)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->fast_poll);
  (*ctx->subsystems.random->fast_poll) (ctx);
}

void
gcry_core_random_create_nonce (gcry_core_context_t ctx,
			       unsigned char *buffer, size_t length)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->create_nonce);
  (*ctx->subsystems.random->create_nonce) (ctx, buffer, length);
}

void
gcry_core_random_initialize (gcry_core_context_t ctx, int full)
{
  assert (ctx->subsystems.random && ctx->subsystems.random->initialize);
  (*ctx->subsystems.random->initialize) (ctx, full);
}

/* EOF. */
