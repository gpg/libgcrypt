#include <gcrypt-internal.h>

#include <gcrypt-mpi-internal.h>

gcry_mpi_t
gcry_mpi_new (unsigned int nbits)
{
  _gcry_init ();
  return gcry_core_mpi_new (context, nbits);
}

gcry_mpi_t
gcry_mpi_snew (unsigned int nbits)
{
  _gcry_init ();
  return gcry_core_mpi_snew (context, nbits);
}

void
gcry_mpi_release (gcry_mpi_t a)
{
  _gcry_init ();
  return gcry_core_mpi_release (context, a);
}

gcry_mpi_t
gcry_mpi_copy (const gcry_mpi_t a)
{
  _gcry_init ();
  return gcry_core_mpi_copy (context, a);
}

gcry_mpi_t
gcry_mpi_set (gcry_mpi_t w, const gcry_mpi_t u)
{
  _gcry_init ();
  return gcry_core_mpi_set (context, w, u);
}

gcry_mpi_t
gcry_mpi_set_ui (gcry_mpi_t w, unsigned long u)
{
  _gcry_init ();
  return gcry_core_mpi_set_ui (context, w, u);
}

void
gcry_mpi_swap (gcry_mpi_t a, gcry_mpi_t b)
{
  _gcry_init ();
  gcry_core_mpi_swap (context, a, b);
}

int
gcry_mpi_cmp (const gcry_mpi_t u, const gcry_mpi_t v)
{
  _gcry_init ();
  return gcry_core_mpi_cmp (context, u, v);
}

int
gcry_mpi_cmp_ui (const gcry_mpi_t u, unsigned long v)
{
  _gcry_init ();
  return gcry_core_mpi_cmp_ui (context, u, v);
}

gcry_error_t
gcry_mpi_scan (gcry_mpi_t *ret_mpi, enum gcry_mpi_format format,
	       const unsigned char *buffer, size_t buflen, 
	       size_t *nscanned)
{
  _gcry_init ();
  return gcry_core_mpi_scan (context,
			     ret_mpi, format, buffer, buflen, nscanned);
}

gcry_error_t
gcry_mpi_print (enum gcry_mpi_format format,
		unsigned char *buffer, size_t buflen,
		size_t *nwritten,
		const gcry_mpi_t a)
{
  _gcry_init ();
  return gcry_core_mpi_print (context,
			      format, buffer, buflen, nwritten, a);
}

gcry_error_t
gcry_mpi_aprint (enum gcry_mpi_format format,
		 unsigned char **buffer, size_t *nwritten,
		 const gcry_mpi_t a)
{
  _gcry_init ();
  return gcry_core_mpi_aprint (context,
			       format, buffer, nwritten, a);
}

void
gcry_mpi_dump (const gcry_mpi_t a)
{
  _gcry_init ();
  gcry_core_mpi_dump (context, a);
}

void
gcry_mpi_add (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v)
{
  _gcry_init ();
  gcry_core_mpi_add (context, w, u, v);
}

void
gcry_mpi_add_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v)
{
  _gcry_init ();
  gcry_core_mpi_add_ui (context, w, u, v);
}

void
gcry_mpi_addm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m)
{
  _gcry_init ();
  gcry_core_mpi_addm (context, w, u, v, m);
}

void
gcry_mpi_sub (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v)
{
  _gcry_init ();
  gcry_core_mpi_sub (context, w, u, v);
}

void
gcry_mpi_sub_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v )
{
  _gcry_init ();
  gcry_core_mpi_sub_ui (context, w, u, v);
}

void
gcry_mpi_subm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m)
{
  _gcry_init ();
  gcry_core_mpi_subm (context, w, u, v, m);
}

void
gcry_mpi_mul (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v)
{
  _gcry_init ();
  gcry_core_mpi_mul (context, w, u, v);
}

void
gcry_mpi_mul_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v )
{
  _gcry_init ();
  gcry_core_mpi_mul_ui (context, w, u, v);
}

void
gcry_mpi_mulm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m)
{
  _gcry_init ();
  gcry_core_mpi_mulm (context, w, u, v, m);
}

void
gcry_mpi_mul_2exp (gcry_mpi_t w, gcry_mpi_t u, unsigned long cnt)
{
  _gcry_init ();
  gcry_core_mpi_mul_2exp (context, w, u, cnt);
}

void
gcry_mpi_div (gcry_mpi_t q, gcry_mpi_t r,
	      gcry_mpi_t dividend, gcry_mpi_t divisor, int round)
{
  _gcry_init ();
  gcry_core_mpi_div (context, q, r, dividend, divisor, round);
}

void
gcry_mpi_mod (gcry_mpi_t r, gcry_mpi_t dividend, gcry_mpi_t divisor)
{
  _gcry_init ();
  gcry_core_mpi_mod (context, r, dividend, divisor);
}

void
gcry_mpi_powm (gcry_mpi_t w,
	       const gcry_mpi_t b, const gcry_mpi_t e,
	       const gcry_mpi_t m)
{
  _gcry_init ();
  gcry_core_mpi_powm (context, w, b, e, m);
}

int
gcry_mpi_gcd (gcry_mpi_t g, gcry_mpi_t a, gcry_mpi_t b)
{
  _gcry_init ();
  return gcry_core_mpi_gcd (context, g, a, b);
}

int
gcry_mpi_invm (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t m)
{
  _gcry_init ();
  return gcry_core_mpi_invm (context, x, a, m);
}

unsigned int
gcry_mpi_get_nbits (gcry_mpi_t a)
{
  _gcry_init ();
  return gcry_core_mpi_get_nbits (context, a);
}

int
gcry_mpi_test_bit (gcry_mpi_t a, unsigned int n)
{
  _gcry_init ();
  return gcry_core_mpi_test_bit (context, a, n);
}

void
gcry_mpi_set_bit (gcry_mpi_t a, unsigned int n)
{
  _gcry_init ();
  gcry_core_mpi_set_bit (context, a, n);
}

void
gcry_mpi_clear_bit (gcry_mpi_t a, unsigned int n)
{
  _gcry_init ();
  gcry_core_mpi_clear_bit (context, a, n);
}

void
gcry_mpi_set_highbit (gcry_mpi_t a, unsigned int n)
{
  _gcry_init ();
  gcry_core_mpi_set_highbit (context, a, n);
}

void
gcry_mpi_clear_highbit (gcry_mpi_t a, unsigned int n)
{
  _gcry_init ();
  gcry_core_mpi_clear_highbit (context, a, n);
}

void
gcry_mpi_rshift (gcry_mpi_t x, gcry_mpi_t a, unsigned int n)
{
  _gcry_init ();
  gcry_core_mpi_rshift (context, x, a, n);
}

gcry_mpi_t
gcry_mpi_set_opaque (gcry_mpi_t a, void *p, unsigned int nbits)
{
  _gcry_init ();
  return gcry_core_mpi_set_opaque (context, a, p, nbits);
}

void *
gcry_mpi_get_opaque (gcry_mpi_t a, unsigned int *nbits)
{
  _gcry_init ();
  return gcry_core_mpi_get_opaque (context, a, nbits);
}

void
gcry_mpi_set_flag (gcry_mpi_t a, enum gcry_mpi_flag flag)
{
  _gcry_init ();
  gcry_core_mpi_set_flag (context, a, flag);
}

void
gcry_mpi_clear_flag (gcry_mpi_t a, enum gcry_mpi_flag flag)
{
  _gcry_init ();
  gcry_core_mpi_clear_flag (context, a, flag);
}

int
gcry_mpi_get_flag (gcry_mpi_t a, enum gcry_mpi_flag flag)
{
  _gcry_init ();
  return gcry_core_mpi_get_flag (context, a, flag);
}

/* MPI-RAND.  */

void
gcry_mpi_randomize (gcry_mpi_t w,
		    unsigned int nbits, enum gcry_random_level level)
{
  _gcry_init ();
  gcry_core_mpi_randomize (context, w, nbits, level);
}
