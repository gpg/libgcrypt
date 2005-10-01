/* secmem dummy subsystem.  */

#include <gcrypt-internal.h>
#include <assert.h>

static gcry_core_handler_alloc_t alloc_func;
static gcry_handler_secure_check_t check_func;
static gcry_core_handler_realloc_t realloc_func;
static gcry_core_handler_free_t free_func;



void
secmem_dummy_set_callbacks (gcry_core_context_t ctx,
			    gcry_core_handler_alloc_t mem_alloc_func,
			    gcry_handler_secure_check_t mem_check_func,
			    gcry_core_handler_realloc_t mem_realloc_func,
			    gcry_core_handler_free_t mem_free_func)
{
  alloc_func = mem_alloc_func;
  check_func = mem_check_func;
  realloc_func = mem_realloc_func;
  free_func = mem_free_func;
}



static void
secmem_dummy_set_flags (gcry_core_context_t ctx,
			unsigned int flags)
{
}

static unsigned
secmem_dummy_get_flags (gcry_core_context_t ctx)
{
  return 0;
}

static gcry_error_t
secmem_dummy_prepare (gcry_core_context_t ctx, void **ptr)
{
  *ptr = NULL;
  return 0;
}

static void
secmem_dummy_finish (gcry_core_context_t ctx,
		     void *ptr)
{
  assert (ptr == NULL);
}

static void
secmem_dummy_init (gcry_core_context_t ctx, size_t n)
{
}

static void *
secmem_dummy_malloc (gcry_core_context_t ctx, size_t size)
{
  return (*alloc_func) (size);
}

static void
secmem_dummy_free (gcry_core_context_t ctx, void *a)
{
  (*free_func) (a);
}

static void *
secmem_dummy_realloc (gcry_core_context_t ctx,
		      void *p, size_t newsize)
{
  return (*realloc_func) (p, newsize);
}

static int
secmem_dummy_is_secure (gcry_core_context_t ctx,
			const void *p)
{
  return (*check_func) (p);
}

static void
secmem_dummy_term (gcry_core_context_t ctx)
{
}

static void
secmem_dummy_dump_stats (gcry_core_context_t ctx)
{
}



static struct gcry_core_subsystem_secmem secmem_dummy_struct =
  {
    secmem_dummy_set_flags,
    secmem_dummy_get_flags,
    secmem_dummy_prepare,
    secmem_dummy_finish,
    secmem_dummy_init,
    secmem_dummy_malloc,
    secmem_dummy_free,
    secmem_dummy_realloc,
    secmem_dummy_is_secure,
    secmem_dummy_term,
    secmem_dummy_dump_stats
  };

gcry_core_subsystem_secmem_t secmem_dummy = &secmem_dummy_struct;
