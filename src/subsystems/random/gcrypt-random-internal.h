#ifndef _GCRYPT_RANDOM_INTERNAL_H
#define _GCRYPT_RANDOM_INTERNAL_H

#include <gcrypt-common-internal.h>
#include <gcrypt-random-common.h>

typedef void (*gcry_core_random_add_t) (gcry_core_context_t ctx,
					const void *, size_t, int);
typedef int (*gcry_core_random_source_gather_t) (gcry_core_context_t ctx,
						 gcry_core_random_add_t add,
						 int requester,
						 size_t length, int level);

typedef void (*gcry_core_random_source_gather_fast_t) (gcry_core_context_t ctx,
						       gcry_core_random_add_t add,
						       int requester);
						
typedef int (*gcry_core_random_source_check_t) (gcry_core_context_t ctx);

typedef struct gcry_core_random_source
{
  /* Maybe a special init function?  */
  gcry_core_random_source_check_t check;
  gcry_core_random_source_gather_t gather;
  gcry_core_random_source_gather_fast_t gather_fast;
} *gcry_core_random_source_t;

extern gcry_core_random_source_t gcry_core_random_source_dev;
extern gcry_core_random_source_t gcry_core_random_source_egd;
extern gcry_core_random_source_t gcry_core_random_source_unix;

#endif
