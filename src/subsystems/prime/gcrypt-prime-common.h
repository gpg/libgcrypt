#ifndef _GCRYPT_PRIME_COMMON_H
#define _GCRYPT_PRIME_COMMON_H

/* Mode values passed to a gcry_prime_check_func_t. */
#define GCRY_PRIME_CHECK_AT_FINISH      0
#define GCRY_PRIME_CHECK_AT_GOT_PRIME   1
#define GCRY_PRIME_CHECK_AT_MAYBE_PRIME 2

/* The function should return 1 if the operation shall continue, 0 to
   reject the prime candidate. */
typedef int (*gcry_prime_check_func_t) (void *arg, int mode,
                                        gcry_core_mpi_t candidate);

/* Flags for gcry_prime_generate():  */

/* Allocate prime numbers and factors in secure memory.  */
#define GCRY_PRIME_FLAG_SECRET         (1 << 0)

/* Make sure that at least one prime factor is of size
   `FACTOR_BITS'.  */
#define GCRY_PRIME_FLAG_SPECIAL_FACTOR (1 << 1)



typedef gcry_core_mpi_t (*gcry_subsystem_prime_generate_secret_t) (gcry_core_context_t ctx,
							      unsigned int nbits,
							      int (*extra_check)
							      (gcry_core_context_t,
							       void *, gcry_core_mpi_t),
							      void *extra_check_arg);
typedef gcry_core_mpi_t (*gcry_subsystem_prime_generate_public_t) (gcry_core_context_t ctx,
							      unsigned int nbits,
							      int (*extra_check)
							      (gcry_core_context_t,
							       void *, gcry_core_mpi_t),
							      void *extra_check_arg);

typedef gcry_core_mpi_t (*gcry_subsystem_prime_generate_elg_t) (gcry_core_context_t ctx,
							   int mode,
							   unsigned pbits,
							   unsigned qbits,
							   gcry_core_mpi_t g,
							   gcry_core_mpi_t **ret_factors);

typedef gcry_error_t (*gcry_subsystem_prime_generate_t) (gcry_core_context_t ctx,
							 gcry_core_mpi_t *prime,
							 unsigned int prime_bits,
							 unsigned int factor_bits,
							 gcry_core_mpi_t **factors,
							 gcry_prime_check_func_t cb_func,
							 void *cb_arg,
							 gcry_random_level_t random_level,
							 unsigned int flags);

typedef gcry_error_t (*gcry_subsystem_prime_check_t) (gcry_core_context_t ctx,
						      gcry_core_mpi_t x,
						      unsigned int flags);

typedef gcry_error_t (*gcry_subsystem_prime_group_generator_t) (gcry_core_context_t ctx,
								gcry_core_mpi_t *r_g,
								gcry_core_mpi_t prime,
								gcry_core_mpi_t *factors,
								gcry_core_mpi_t start_g);



gcry_core_mpi_t gcry_core_prime_generate_secret (gcry_core_context_t ctx, unsigned int nbits,
					    int (*extra_check) (gcry_core_context_t,
								void *, gcry_core_mpi_t),
					    void *extra_check_arg);

gcry_core_mpi_t gcry_core_prime_generate_public (gcry_core_context_t ctx,
					    unsigned int nbits,
					    int (*extra_check) (gcry_core_context_t,
								void *, gcry_core_mpi_t),
					    void *extra_check_arg);
gcry_core_mpi_t gcry_core_prime_generate_elg (gcry_core_context_t ctx,
					 int mode, unsigned pbits, unsigned qbits,
					 gcry_core_mpi_t g, gcry_core_mpi_t ** ret_factors);

gcry_error_t gcry_core_prime_generate (gcry_core_context_t ctx,
				       gcry_core_mpi_t * prime, unsigned int prime_bits,
				       unsigned int factor_bits, gcry_core_mpi_t ** factors,
				       gcry_prime_check_func_t cb_func, void *cb_arg,
				       gcry_random_level_t random_level, unsigned int flags);

gcry_error_t gcry_core_prime_check (gcry_core_context_t ctx, gcry_core_mpi_t x, unsigned int flags);

gcry_error_t gcry_core_prime_group_generator (gcry_core_context_t ctx,
					      gcry_core_mpi_t * r_g,
					      gcry_core_mpi_t prime, gcry_core_mpi_t * factors,
					      gcry_core_mpi_t start_g);

void gcry_core_prime_release_factors (gcry_core_context_t ctx, gcry_core_mpi_t *factors);



typedef struct gcry_core_subsystem_prime
{
  gcry_subsystem_prime_generate_secret_t generate_secret;
  gcry_subsystem_prime_generate_public_t generate_public;
  gcry_subsystem_prime_generate_elg_t generate_elg;
  gcry_subsystem_prime_generate_t generate;
  gcry_subsystem_prime_check_t check;
  gcry_subsystem_prime_group_generator_t group_generator;
} *gcry_core_subsystem_prime_t;


extern gcry_core_subsystem_prime_t gcry_core_subsystem_prime;

void gcry_core_context_set_prime (gcry_core_context_t ctx, gcry_core_subsystem_prime_t prime);

#endif
