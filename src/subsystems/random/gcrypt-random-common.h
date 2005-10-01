#ifndef _GCRYPT_RANDOM_COMMON_H
#define _GCRYPT_RANDOM_COMMON_H

/* The possible values for the random quality.  The rule of thumb is
   to use STRONG for session keys and VERY_STRONG for key material.
   WEAK is currently an alias for STRONG and should not be used
   anymore - use gcry_create_nonce instead. */
typedef enum gcry_random_level
  {
    GCRY_WEAK_RANDOM = 0,
    GCRY_STRONG_RANDOM = 1,
    GCRY_VERY_STRONG_RANDOM = 2
  }
gcry_random_level_t;

/* random handler.  */

typedef gcry_error_t (*gcry_handler_rand_source_get_t) (gcry_core_context_t ctx,
							void *opaque,
							gcry_random_level_t level,
							unsigned char *buffer,
							size_t buffer_n);

typedef gcry_error_t (*gcry_handler_rand_source_get_fast_t) (gcry_core_context_t ctx,
							     void *opaque,
							     unsigned char *buffer,
							     size_t buffer_n);

/* FIXME, correct place here??  */
typedef void (*gcry_random_add_randomness_t) (gcry_core_context_t ctx,
					      const void *b, size_t n, int FIXME);

typedef int (*gcry_random_gather_random_t) (gcry_core_context_t ctx,
					    gcry_random_add_randomness_t add_randomness,
					    int FIXME, size_t a, int b);

typedef void (*gcry_random_fast_random_poll_t) (gcry_core_context_t ctx,
						gcry_random_add_randomness_t add_randomness,
						int FIXME);

typedef void (*gcry_random_progress_cb_t) (void *, const char *, int, int, int);



//typedef void (*gcry_subsystem_random_register_progress_t) (g
typedef gcry_error_t (*gcry_subsystem_random_prepare_t) (gcry_core_context_t ctx,
							 void **ptr);
typedef void (*gcry_subsystem_random_finish_t) (gcry_core_context_t ctx,
						void *ptr);
typedef void (*gcry_subsystem_random_dump_stats_t) (gcry_core_context_t ctx);

typedef gcry_error_t (*gcry_subsystem_random_add_bytes_t) (gcry_core_context_t ctx,
							   const void *buf,
							   size_t buflen,
							   int quality);

typedef void *(*gcry_subsystem_random_bytes_t) (gcry_core_context_t ctx,
						size_t nbytes,
						enum gcry_random_level level);

typedef void *(*gcry_subsystem_random_bytes_secure_t) (gcry_core_context_t ctx,
						       size_t nbytes,
						       enum gcry_random_level level);

typedef void (*gcry_subsystem_random_randomize_t) (gcry_core_context_t ctx,
						   unsigned char *buffer,
						   size_t length,
						   enum gcry_random_level level);

typedef void (*gcry_subsystem_random_seed_file_set_t) (gcry_core_context_t ctx,
						       const char *filename);
typedef void (*gcry_subsystem_random_seed_file_update_t) (gcry_core_context_t ctx);

typedef void (*gcry_subsystem_random_fast_poll_t) (gcry_core_context_t ctx);

typedef void (*gcry_subsystem_random_create_nonce_t) (gcry_core_context_t ctx,
						      unsigned char *buffer,
						      size_t length);
typedef void (*gcry_subsystem_random_initialize_t) (gcry_core_context_t ctx,
						    int full);


void gcry_core_random_dump_stats (gcry_core_context_t ctx);

gcry_error_t gcry_core_random_add_bytes (gcry_core_context_t ctx,
					 const void *buf, size_t buflen, int quality);

void *gcry_core_random_bytes (gcry_core_context_t ctx,
			      size_t nbytes, enum gcry_random_level level);

void *gcry_core_random_bytes_secure (gcry_core_context_t ctx,
				     size_t nbytes, enum gcry_random_level level);

void gcry_core_random_randomize (gcry_core_context_t ctx,
				 unsigned char *buffer, size_t length, enum gcry_random_level level);

void gcry_core_random_seed_file_set (gcry_core_context_t ctx, const char *filename);

void gcry_core_random_seed_file_update (gcry_core_context_t ctx);

void gcry_core_random_fast_poll (gcry_core_context_t ctx);

void gcry_core_random_create_nonce (gcry_core_context_t ctx,
				    unsigned char *buffer, size_t length);



typedef struct gcry_core_subsystem_random
{
  gcry_subsystem_random_prepare_t prepare;
  gcry_subsystem_random_finish_t finish;
  gcry_subsystem_random_dump_stats_t dump_stats;
  gcry_subsystem_random_add_bytes_t add_bytes;
  gcry_subsystem_random_bytes_t bytes;
  gcry_subsystem_random_bytes_secure_t bytes_secure;
  gcry_subsystem_random_randomize_t randomize;
  gcry_subsystem_random_seed_file_set_t seed_file_set;
  gcry_subsystem_random_seed_file_update_t seed_file_update;
  gcry_subsystem_random_fast_poll_t fast_poll;
  gcry_subsystem_random_create_nonce_t create_nonce;
  gcry_subsystem_random_initialize_t initialize;
  void *opaque;
  unsigned int flags;
} *gcry_core_subsystem_random_t;

extern gcry_core_subsystem_random_t gcry_core_subsystem_random;

void gcry_core_set_subsystem_random (gcry_core_context_t ctx,
				     gcry_core_subsystem_random_t subsystem_random);

void gcry_core_set_random_seed_file (gcry_core_context_t ctx, const char *filename);



gcry_error_t gcry_core_random_prepare (gcry_core_context_t ctx,
				       void **ptr);

void gcry_core_random_finish (gcry_core_context_t ctx, void *ptr);

void gcry_core_random_initialize (gcry_core_context_t ctx, int full);

#endif
