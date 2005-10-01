#ifndef SECMEM_H
#define SECMEM_H

#include <gcrypt-internal.h>

void secmem_dummy_set_callbacks (gcry_core_context_t ctx,
				 gcry_core_handler_alloc_t mem_alloc_func,
				 gcry_handler_secure_check_t mem_check_func,
				 gcry_core_handler_realloc_t mem_realloc_func,
				 gcry_core_handler_free_t mem_free_func);

extern gcry_core_subsystem_secmem_t secmem_dummy;

#endif
