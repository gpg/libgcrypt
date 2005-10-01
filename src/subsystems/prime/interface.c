#include <gcrypt-prime-internal.h>

#include <gcrypt-mpi-internal.h>

gcry_core_mpi_t
gcry_core_prime_generate_secret (gcry_core_context_t ctx, unsigned int nbits,
				 int (*extra_check) (gcry_core_context_t,
						     void *, gcry_core_mpi_t),
				 void *extra_check_arg)
{
  return (*ctx->subsystems.prime->generate_secret) (ctx,
					nbits, extra_check, extra_check_arg);
}

gcry_core_mpi_t
gcry_core_prime_generate_public (gcry_core_context_t ctx,
				 unsigned int nbits,
				 int (*extra_check) (gcry_core_context_t,
						     void *, gcry_core_mpi_t),
				 void *extra_check_arg)
{
  return (*ctx->subsystems.prime->generate_public) (ctx,
					nbits, extra_check, extra_check_arg);
}

gcry_core_mpi_t
gcry_core_prime_generate_elg (gcry_core_context_t ctx,
			      int mode, unsigned pbits, unsigned qbits,
			      gcry_core_mpi_t g, gcry_core_mpi_t ** ret_factors)
{
  return (*ctx->subsystems.prime->generate_elg) (ctx, mode, pbits, qbits, g, ret_factors);
}

gcry_error_t
gcry_core_prime_generate (gcry_core_context_t ctx,
			  gcry_core_mpi_t * prime, unsigned int prime_bits,
			  unsigned int factor_bits, gcry_core_mpi_t ** factors,
			  gcry_prime_check_func_t cb_func, void *cb_arg,
			  gcry_random_level_t random_level, unsigned int flags)
{
  return (*ctx->subsystems.prime->generate) (ctx, prime, prime_bits, factor_bits, factors,
				 cb_func, cb_arg, random_level, flags);
}

gcry_error_t
gcry_core_prime_check (gcry_core_context_t ctx, gcry_core_mpi_t x, unsigned int flags)
{
  return (*ctx->subsystems.prime->check) (ctx, x, flags);
}


gcry_error_t
gcry_core_prime_group_generator (gcry_core_context_t ctx,
				 gcry_core_mpi_t * r_g,
				 gcry_core_mpi_t prime, gcry_core_mpi_t * factors,
				 gcry_core_mpi_t start_g)
{
  return (*ctx->subsystems.prime->group_generator) (ctx, r_g, prime, factors, start_g);
}

/* Convenience function to release the factors array. */
void
gcry_core_prime_release_factors (gcry_core_context_t ctx, gcry_core_mpi_t *factors)
{
  if (factors)
    {
      int i;
      
      for (i=0; factors[i]; i++)
        gcry_core_mpi_release (ctx, factors[i]);
      gcry_core_free (ctx, factors);
    }
}
