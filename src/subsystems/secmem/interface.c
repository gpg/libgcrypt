#include <gcrypt-secmem-internal.h>
#include <assert.h>

gcry_error_t
gcry_core_secmem_prepare (gcry_core_context_t ctx, void **ptr)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->prepare);
  return (*ctx->subsystems.secmem->prepare) (ctx, ptr);
}

void
gcry_core_secmem_finish (gcry_core_context_t ctx, void *ptr)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->finish);
  (*ctx->subsystems.secmem->finish) (ctx, ptr);
}

void
gcry_core_secmem_set_flags (gcry_core_context_t ctx, unsigned flags)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->set_flags);
  (*ctx->subsystems.secmem->set_flags) (ctx, flags);
}

unsigned
gcry_core_secmem_get_flags (gcry_core_context_t ctx)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->get_flags);
  return (*ctx->subsystems.secmem->get_flags) (ctx);
}

void
gcry_core_secmem_init (gcry_core_context_t ctx, size_t n)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->init);
  (*ctx->subsystems.secmem->init) (ctx, n);
}

void *
gcry_core_secmem_malloc (gcry_core_context_t ctx, size_t size)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->malloc);
  return (*ctx->subsystems.secmem->malloc) (ctx, size);
}

void
gcry_core_secmem_free (gcry_core_context_t ctx, void *a)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->free);
  (*ctx->subsystems.secmem->free) (ctx, a);
}

void *
gcry_core_secmem_realloc (gcry_core_context_t ctx, void *p, size_t newsize)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->realloc);
  return (*ctx->subsystems.secmem->realloc) (ctx, p, newsize);
}

int
gcry_core_secmem_is_secure (gcry_core_context_t ctx, const void *p)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->is_secure);
  return (*ctx->subsystems.secmem->is_secure) (ctx, p);
}

void
gcry_core_secmem_term (gcry_core_context_t ctx)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->term);
  (*ctx->subsystems.secmem->term) (ctx);
}

void
gcry_core_secmem_dump_stats (gcry_core_context_t ctx)
{
  assert (ctx->subsystems.secmem && ctx->subsystems.secmem->dump_stats);
  (*ctx->subsystems.secmem->dump_stats) (ctx);
}
