#include <compat/gcrypt-internal.h>

#include <gcrypt-prime-internal.h>

gcry_error_t
gcry_prime_generate (gcry_mpi_t *prime,
		     unsigned int prime_bits,
		     unsigned int factor_bits,
		     gcry_mpi_t **factors,
		     gcry_prime_check_func_t cb_func,
		     void *cb_arg,
		     gcry_random_level_t random_level,
		     unsigned int flags)
{
  _gcry_init ();
  return gcry_core_prime_generate (context, prime, prime_bits, factor_bits,
				   factors, cb_func, cb_arg, random_level,
				   flags);
}

gcry_error_t
gcry_prime_group_generator (gcry_mpi_t *r_g,
			    gcry_mpi_t prime, gcry_mpi_t *factors,
			    gcry_mpi_t start_g)
{
  _gcry_init ();
  return gcry_core_prime_group_generator (context,
					  r_g, prime, factors, start_g);
}

void
gcry_prime_release_factors (gcry_mpi_t *factors)
{
  _gcry_init ();
  gcry_core_prime_release_factors (context, factors);
}


gcry_error_t
gcry_prime_check (gcry_mpi_t x, unsigned int flags)
{
  _gcry_init ();
  return gcry_core_prime_check (context, x, flags);
}
