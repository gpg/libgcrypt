#ifndef _GCRYPT_SECMEM_COMMON_H
#define _GCRYPT_SECMEM_COMMON_H

/* SECMEM subsystem.  */

typedef void (*gcry_subsystem_secmem_set_flags_t) (gcry_core_context_t ctx,
						   unsigned int flags);
typedef unsigned (*gcry_subsystem_secmem_get_flags_t) (gcry_core_context_t ctx);
typedef gcry_error_t (*gcry_subsystem_secmem_prepare_t) (gcry_core_context_t ctx, void **ptr);
typedef void (*gcry_subsystem_secmem_finish_t) (gcry_core_context_t ctx,
						void *ptr);
typedef void (*gcry_subsystem_secmem_init_t) (gcry_core_context_t ctx, size_t n);
typedef void *(*gcry_subsystem_secmem_malloc_t) (gcry_core_context_t ctx, size_t size);
typedef void (*gcry_subsystem_secmem_free_t) (gcry_core_context_t ctx, void *a);
typedef void *(*gcry_subsystem_secmem_realloc_t) (gcry_core_context_t ctx,
						  void *p, size_t newsize);
typedef int (*gcry_subsystem_secmem_is_secure_t) (gcry_core_context_t ctx,
						  const void *p);
typedef void (*gcry_subsystem_secmem_term_t) (gcry_core_context_t ctx);
typedef void (*gcry_subsystem_secmem_dump_stats_t) (gcry_core_context_t ctx);

/* FIXME: right place for these functions? hmm, should they be
   exported? -moritz  */

void gcry_core_secmem_set_flags (gcry_core_context_t ctx, unsigned flags);

unsigned gcry_core_secmem_get_flags (gcry_core_context_t ctx);

void gcry_core_secmem_init (gcry_core_context_t ctx, size_t n);

void *gcry_core_secmem_malloc (gcry_core_context_t ctx, size_t size);

void gcry_core_secmem_free (gcry_core_context_t ctx, void *a);

void *gcry_core_secmem_realloc (gcry_core_context_t ctx, void *p, size_t newsize);

int gcry_core_secmem_is_secure (gcry_core_context_t ctx, const void *p);

void gcry_core_secmem_term (gcry_core_context_t ctx);

void gcry_core_secmem_dump_stats (gcry_core_context_t ctx);



typedef struct gcry_core_subsystem_secmem
{
  gcry_subsystem_secmem_set_flags_t set_flags;
  gcry_subsystem_secmem_get_flags_t get_flags;
  gcry_subsystem_secmem_prepare_t prepare;
  gcry_subsystem_secmem_finish_t finish;
  gcry_subsystem_secmem_init_t init;
  gcry_subsystem_secmem_malloc_t malloc;
  gcry_subsystem_secmem_free_t free;
  gcry_subsystem_secmem_realloc_t realloc;
  gcry_subsystem_secmem_is_secure_t is_secure;
  gcry_subsystem_secmem_term_t term;
  gcry_subsystem_secmem_dump_stats_t dump_stats;
} *gcry_core_subsystem_secmem_t;

extern gcry_core_subsystem_secmem_t gcry_core_subsystem_secmem;

void gcry_core_set_subsystem_secmem (gcry_core_context_t ctx, gcry_core_subsystem_secmem_t secmem);

gcry_error_t gcry_core_secmem_prepare (gcry_core_context_t ctx,
				       void **ptr);

void gcry_core_secmem_finish (gcry_core_context_t ctx, void *ptr);

#endif
