/* primegen.c - prime number generator
 * Copyright (C) 1998, 2000, 2001, 2002, 2003
 *               2004, 2005 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * ***********************************************************************
 * The algorithm used to generate practically save primes is due to
 * Lim and Lee as described in the CRYPTO '97 proceedings (ISBN3540633847)
 * page 260.
 */

#include <gcrypt-prime-internal.h>
#include <gcrypt-mpi-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

static gcry_core_mpi_t gen_prime (gcry_core_context_t ctx,
			     unsigned int nbits, int secret, int randomlevel,
			     int (*extra_check) (gcry_core_context_t, void *, gcry_core_mpi_t),
			     void *extra_check_arg);
static int check_prime (gcry_core_context_t ctx,
			gcry_core_mpi_t prime, gcry_core_mpi_t val_2,
			int rm_rounds, gcry_prime_check_func_t cb_func,
			void *cb_arg);
static int is_prime (gcry_core_context_t ctx, gcry_core_mpi_t n, int steps, int *count);
static void m_out_of_n (gcry_core_context_t ctx, char *array, int m, int n);

/* Note: 2 is not included because it can be tested more easily by
   looking at bit 0. The last entry in this list is marked by a zero */
static ushort small_prime_numbers[] = {
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
  47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
  103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
  211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
  269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
  389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
  449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
  587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
  643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
  773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
  853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
  991, 997, 1009, 1013, 1019, 1021, 1031, 1033,
  1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
  1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
  1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
  1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
  1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307,
  1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
  1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
  1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
  1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
  1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
  1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
  1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
  1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
  1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871,
  1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931,
  1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
  1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
  2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
  2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
  2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243,
  2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297,
  2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
  2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
  2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
  2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
  2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633,
  2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
  2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
  2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791,
  2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851,
  2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
  2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
  3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
  3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
  3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209,
  3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271,
  3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
  3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
  3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467,
  3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
  3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
  3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
  3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
  3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779,
  3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851,
  3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
  3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
  4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
  4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
  4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177,
  4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243,
  4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
  4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391,
  4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457,
  4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
  4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597,
  4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
  4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
  4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799,
  4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889,
  4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
  4957, 4967, 4969, 4973, 4987, 4993, 4999,
  0
};
static int no_of_small_prime_numbers = DIM (small_prime_numbers) - 1;

#define progress(ctx, c) _gcry_core_progress (ctx, "primegen", c, 0, 0)


/****************
 * Generate a prime number (stored in secure memory)
 */
gcry_core_mpi_t
_gcry_generate_secret_prime (gcry_core_context_t ctx, unsigned int nbits,
			     int (*extra_check) (gcry_core_context_t,
						 void *, gcry_core_mpi_t),
			     void *extra_check_arg)
{
  gcry_core_mpi_t prime;

  prime = gen_prime (ctx, nbits, 1, 2, extra_check, extra_check_arg);
  progress (ctx, '\n');
  return prime;
}

gcry_core_mpi_t
_gcry_generate_public_prime (gcry_core_context_t ctx,
			     unsigned int nbits,
			     int (*extra_check) (gcry_core_context_t,
						 void *, gcry_core_mpi_t),
			     void *extra_check_arg)
{
  gcry_core_mpi_t prime;

  prime = gen_prime (ctx, nbits, 0, 2, extra_check, extra_check_arg);
  progress (ctx, '\n');
  return prime;
}


/****************
 * We do not need to use the strongest RNG because we gain no extra
 * security from it - The prime number is public and we could also
 * offer the factors for those who are willing to check that it is
 * indeed a strong prime.  With ALL_FACTORS set to true all afcors of
 * prime-1 are returned in FACTORS.
 *
 * mode 0: Standard
 *	1: Make sure that at least one factor is of size qbits.
 */
static gcry_error_t
prime_generate_internal (gcry_core_context_t ctx,
			 int mode,
			 gcry_core_mpi_t * prime_generated, unsigned int pbits,
			 unsigned int qbits, gcry_core_mpi_t g,
			 gcry_core_mpi_t ** ret_factors,
			 gcry_random_level_t randomlevel, unsigned int flags,
			 int all_factors,
			 gcry_prime_check_func_t cb_func, void *cb_arg)
{
  gcry_error_t err = 0;
  gcry_core_mpi_t *factors_new = NULL;	/* Factors to return to the
					   caller.  */
  gcry_core_mpi_t *factors = NULL;	/* Current factors.  */
  gcry_core_mpi_t *pool = NULL;	/* Pool of primes.  */
  unsigned char *perms = NULL;	/* Permutations of POOL.  */
  gcry_core_mpi_t q_factor = NULL;	/* Used if QBITS is non-zero.  */
  unsigned int fbits = 0;	/* Length of prime factors.  */
  unsigned int n = 0;		/* Number of factors.  */
  unsigned int m = 0;		/* Number of primes in pool.  */
  gcry_core_mpi_t q = NULL;		/* First prime factor.  */
  gcry_core_mpi_t prime = NULL;	/* Prime candidate.  */
  unsigned int nprime = 0;	/* Bits of PRIME.  */
  unsigned int req_qbits;	/* The original QBITS value.  */
  gcry_core_mpi_t val_2;		/* For check_prime().  */
  unsigned int is_secret = (flags & GCRY_PRIME_FLAG_SECRET);
  unsigned int count1 = 0, count2 = 0;
  unsigned int i = 0, j = 0;

  if (pbits < 48)
    return gcry_core_error (GPG_ERR_INV_ARG);

  /* If QBITS is not given, assume a reasonable value. */
  if (!qbits)
    qbits = pbits / 3;

  req_qbits = qbits;

  /* Find number of needed prime factors.  */
  for (n = 1; (pbits - qbits - 1) / n >= qbits; n++)
    ;
  n--;

  val_2 = gcry_core_mpi_alloc_set_ui (ctx, 2);

  if ((!n) || ((mode == 1) && (n < 2)))
    {
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if (mode == 1)
    {
      n--;
      fbits = (pbits - 2 * req_qbits - 1) / n;
      qbits = pbits - req_qbits - n * fbits;
    }
  else
    {
      fbits = (pbits - req_qbits - 1) / n;
      qbits = pbits - n * fbits;
    }

  if (GCRY_CORE_DEBUGGING_PRIME (ctx))
    log_debug (ctx,
	       "gen prime: pbits=%u qbits=%u fbits=%u/%u n=%d\n",
	       pbits, req_qbits, qbits, fbits, n);

  prime = gcry_core_mpi_new (ctx, pbits);

  /* Generate first prime factor.  */
  q = gen_prime (ctx, qbits, is_secret, randomlevel, NULL, NULL);

  if (mode == 1)
    q_factor = gen_prime (ctx, req_qbits, is_secret, randomlevel, NULL, NULL);

  /* Allocate an array to hold the factors + 2 for later usage.  */
  factors = gcry_core_calloc (ctx, n + 2, sizeof (*factors));
  if (!factors)
    {
      err = gpg_error_from_errno (errno);
      goto leave;
    }

  /* Make a pool of 3n+5 primes (this is an arbitrary value).  */
  m = n * 3 + 5;
  if (mode == 1)		/* Need some more (for e.g. DSA).  */
    m += 5;
  if (m < 25)
    m = 25;
  pool = gcry_core_calloc (ctx, m, sizeof (*pool));
  if (!pool)
    {
      err = gpg_error_from_errno (errno);
      goto leave;
    }

  /* Permutate over the pool of primes.  */
  do
    {
    next_try:
      if (!perms)
	{
	  /* Allocate new primes.  */
	  for (i = 0; i < m; i++)
	    {
	      gcry_core_mpi_release (ctx, pool[i]);
	      pool[i] = NULL;
	    }

	  /* Init m_out_of_n().  */
	  perms = gcry_core_calloc (ctx, 1, m);
	  if (!perms)
	    {
	      err = gpg_error_from_errno (errno);
	      goto leave;
	    }
	  for (i = 0; i < n; i++)
	    {
	      perms[i] = 1;
	      pool[i] = gen_prime (ctx, fbits, is_secret,
				   randomlevel, NULL, NULL);
	      factors[i] = pool[i];
	    }
	}
      else
	{
	  m_out_of_n (ctx, perms, n, m);
	  for (i = j = 0; (i < m) && (j < n); i++)
	    if (perms[i])
	      {
		if (!pool[i])
		  pool[i] = gen_prime (ctx, fbits, 0, 1, NULL, NULL);
		factors[j++] = pool[i];
	      }
	  if (i == n)
	    {
	      gcry_core_free (ctx, perms);
	      perms = NULL;
	      progress (ctx, '!');
	      goto next_try;	/* Allocate new primes.  */
	    }
	}

      /* Generate next prime candidate:
         p = 2 * q [ * q_factor] * factor_0 * factor_1 * ... * factor_n + 1. 
       */
      gcry_core_mpi_set (ctx, prime, q);
      gcry_core_mpi_mul_ui (ctx, prime, prime, 2);
      if (mode == 1)
	gcry_core_mpi_mul (ctx, prime, prime, q_factor);
      for (i = 0; i < n; i++)
	gcry_core_mpi_mul (ctx, prime, prime, factors[i]);
      gcry_core_mpi_add_ui (ctx, prime, prime, 1);
      nprime = gcry_core_mpi_get_nbits (ctx, prime);

      if (nprime < pbits)
	{
	  if (++count1 > 20)
	    {
	      count1 = 0;
	      qbits++;
	      progress (ctx, '>');
	      gcry_core_mpi_release (ctx, q);
	      q = gen_prime (ctx, qbits, 0, 0, NULL, NULL);
	      goto next_try;
	    }
	}
      else
	count1 = 0;

      if (nprime > pbits)
	{
	  if (++count2 > 20)
	    {
	      count2 = 0;
	      qbits--;
	      progress (ctx, '<');
	      gcry_core_mpi_release (ctx, q);
	      q = gen_prime (ctx, qbits, 0, 0, NULL, NULL);
	      goto next_try;
	    }
	}
      else
	count2 = 0;
    }
  while (! ((nprime == pbits)
	    && check_prime (ctx, prime, val_2, 5, cb_func, cb_arg)));

  if (GCRY_CORE_DEBUGGING_PRIME (ctx))
    {
      progress (ctx, '\n');
      _gcry_log_mpidump (ctx, "prime    : ", prime);
      _gcry_log_mpidump (ctx, "factor  q: ", q);
      if (mode == 1)
	_gcry_log_mpidump (ctx, "factor q0: ", q_factor);
      for (i = 0; i < n; i++)
	_gcry_log_mpidump (ctx, "factor pi: ", factors[i]);
      log_debug (ctx, "bit sizes: prime=%u, q=%u",
		 gcry_core_mpi_get_nbits (ctx, prime),
		 gcry_core_mpi_get_nbits (ctx, q));
      if (mode == 1)
	log_debug (ctx, ", q0=%u", gcry_core_mpi_get_nbits (ctx, q_factor));
      for (i = 0; i < n; i++)
	log_debug (ctx, ", p%d=%u", i,
		   gcry_core_mpi_get_nbits (ctx, factors[i]));
      progress (ctx, '\n');
    }

  if (ret_factors)
    {
      /* Caller wants the factors.  */
      factors_new = gcry_core_calloc (ctx, n + 4, sizeof (*factors_new));
      if (!factors_new)
	{
	  err = gpg_error_from_errno (errno);
	  goto leave;
	}

      if (all_factors)
	{
	  i = 0;
	  factors_new[i++] = gcry_core_mpi_set_ui (ctx, NULL, 2);
	  factors_new[i++] = gcry_core_mpi_copy (ctx, q);
	  if (mode == 1)
	    factors_new[i++] = gcry_core_mpi_copy (ctx, q_factor);
	  for (j = 0; j < n; j++)
	    factors_new[i++] = gcry_core_mpi_copy (ctx, factors[j]);
	}
      else
	{
	  i = 0;
	  if (mode == 1)
	    {
	      factors_new[i++] = gcry_core_mpi_copy (ctx, q_factor);
	      for (; i <= n; i++)
		factors_new[i] = gcry_core_mpi_copy (ctx, factors[i]);
	    }
	  else
	    for (; i < n; i++)
	      factors_new[i] = gcry_core_mpi_copy (ctx, factors[i]);
	}
    }

  if (g)
    {
      /* Create a generator (start with 3).  */
      gcry_core_mpi_t tmp =
	gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, prime));
      gcry_core_mpi_t b =
	gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, prime));
      gcry_core_mpi_t pmin1 =
	gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, prime));

      if (mode == 1)
	err = gcry_core_error (GPG_ERR_NOT_IMPLEMENTED);
      else
	{
	  factors[n] = q;
	  factors[n + 1] = gcry_core_mpi_alloc_set_ui (ctx, 2);
	  gcry_core_mpi_sub_ui (ctx, pmin1, prime, 1);
	  gcry_core_mpi_set_ui (ctx, g, 2);
	  do
	    {
	      gcry_core_mpi_add_ui (ctx, g, g, 1);
	      if (GCRY_CORE_DEBUGGING_PRIME (ctx))
		{
		  log_debug (ctx, "checking g:");
		  gcry_core_mpi_dump (ctx, g);
		  log_printf (ctx, "\n");
		}
	      else
		progress (ctx, '^');
	      for (i = 0; i < n + 2; i++)
		{
		  gcry_core_mpi_fdiv_q (ctx, tmp, pmin1, factors[i]);
		  /* No mpi_pow(), but it is okay to use this with mod
		     prime.  */
		  gcry_core_mpi_powm (ctx, b, g, tmp, prime);
		  if (!gcry_core_mpi_cmp_ui (ctx, b, 1))
		    break;
		}
	      if (GCRY_CORE_DEBUGGING_PRIME (ctx))
		progress (ctx, '\n');
	    }
	  while (i < n + 2);

	  gcry_core_mpi_release (ctx, factors[n + 1]);
	  gcry_core_mpi_release (ctx, tmp);
	  gcry_core_mpi_release (ctx, b);
	  gcry_core_mpi_release (ctx, pmin1);
	}
    }

  if (!GCRY_CORE_DEBUGGING_PRIME (ctx))
    progress (ctx, '\n');


leave:
  if (pool)
    {
      for (i = 0; i < m; i++)
	gcry_core_mpi_release (ctx, pool[i]);
      gcry_core_free (ctx, pool);
    }
  if (factors)
    gcry_core_free (ctx, factors);	/* Factors are shallow copies.  */
  if (perms)
    gcry_core_free (ctx, perms);

  gcry_core_mpi_release (ctx, val_2);
  gcry_core_mpi_release (ctx, q);
  gcry_core_mpi_release (ctx, q_factor);

  if (!err)
    {
      *prime_generated = prime;
      if (ret_factors)
	*ret_factors = factors_new;
    }
  else
    {
      if (factors_new)
	{
	  for (i = 0; factors_new[i]; i++)
	    gcry_core_mpi_release (ctx, factors_new[i]);
	  gcry_core_free (ctx, factors_new);
	}
      gcry_core_mpi_release (ctx, prime);
    }

  return err;
}

gcry_core_mpi_t
_gcry_generate_elg_prime (gcry_core_context_t ctx,
			  int mode, unsigned pbits, unsigned qbits,
			  gcry_core_mpi_t g, gcry_core_mpi_t ** ret_factors)
{
  gcry_error_t err = 0;
  gcry_core_mpi_t prime = NULL;

  err = prime_generate_internal (ctx, mode, &prime, pbits, qbits, g,
				 ret_factors, GCRY_WEAK_RANDOM, 0, 0,
				 NULL, NULL);

  return prime;
}

static gcry_core_mpi_t
gen_prime (gcry_core_context_t ctx, unsigned int nbits, int secret,
	   int randomlevel, int (*extra_check) (gcry_core_context_t,
						void *, gcry_core_mpi_t),
	   void *extra_check_arg)
{
  gcry_core_mpi_t prime, ptest, pminus1, val_2, val_3, result;
  int i;
  unsigned x, step;
  unsigned count1, count2;
  int *mods;

  /*   if (  GCRY_CORE_DEBUGGING_PRIME (ctx) ) */
  /*     log_debug ("generate a prime of %u bits ", nbits ); */

  if (nbits < 16)
    log_fatal (ctx, "can't generate a prime with less than %d bits\n", 16);

  mods = gcry_core_xmalloc (ctx, no_of_small_prime_numbers * sizeof *mods);
  /* Make nbits fit into gcry_core_mpi_t implementation. */
  val_2 = gcry_core_mpi_alloc_set_ui (ctx, 2);
  val_3 = gcry_core_mpi_alloc_set_ui (ctx, 3);
  prime =
    secret ? gcry_core_mpi_snew (ctx, nbits) : gcry_core_mpi_new (ctx, nbits);
  result = gcry_core_mpi_alloc_like (ctx, prime);
  pminus1 = gcry_core_mpi_alloc_like (ctx, prime);
  ptest = gcry_core_mpi_alloc_like (ctx, prime);
  count1 = count2 = 0;
  for (;;)
    {				/* try forvever */
      int dotcount = 0;

      /* generate a random number */
      gcry_core_mpi_randomize (ctx, prime, nbits, randomlevel);

      /* Set high order bit to 1, set low order bit to 1.  If we are
         generating a secret prime we are most probably doing that
         for RSA, to make sure that the modulus does have the
         requested key size we set the 2 high order bits. */
      gcry_core_mpi_set_highbit (ctx, prime, nbits - 1);
      if (secret)
	gcry_core_mpi_set_bit (ctx, prime, nbits - 2);
      gcry_core_mpi_set_bit (ctx, prime, 0);

      /* Calculate all remainders. */
      for (i = 0; (x = small_prime_numbers[i]); i++)
	mods[i] = gcry_core_mpi_fdiv_r_ui (ctx, NULL, prime, x);

      /* Now try some primes starting with prime. */
      for (step = 0; step < 20000; step += 2)
	{
	  /* Check against all the small primes we have in mods. */
	  count1++;
	  for (i = 0; (x = small_prime_numbers[i]); i++)
	    {
	      while (mods[i] + step >= x)
		mods[i] -= x;
	      if (!(mods[i] + step))
		break;
	    }
	  if (x)
	    continue;		/* Found a multiple of an already known prime. */

	  gcry_core_mpi_add_ui (ctx, ptest, prime, step);

	  /* Do a fast Fermat test now. */
	  count2++;
	  gcry_core_mpi_sub_ui (ctx, pminus1, ptest, 1);
	  gcry_core_mpi_powm (ctx, result, val_2, pminus1, ptest);
	  if (!gcry_core_mpi_cmp_ui (ctx, result, 1))
	    {
	      /* Not composite, perform stronger tests */
	      if (is_prime (ctx, ptest, 5, &count2))
		{
		  if (!gcry_core_mpi_test_bit
		      (ctx, ptest, nbits - 1 - secret))
		    {
		      progress (ctx, '\n');
		      log_debug (ctx, "overflow in prime generation\n");
		      break;	/* Stop loop, continue with a new prime. */
		    }

		  if (extra_check && extra_check (ctx, extra_check_arg, ptest))
		    {
		      /* The extra check told us that this prime is
		         not of the caller's taste. */
		      progress (ctx, '/');
		    }
		  else
		    {
		      /* Got it. */
		      gcry_core_mpi_release (ctx, val_2);
		      gcry_core_mpi_release (ctx, val_3);
		      gcry_core_mpi_release (ctx, result);
		      gcry_core_mpi_release (ctx, pminus1);
		      gcry_core_mpi_release (ctx, prime);
		      gcry_core_free (ctx, mods);
		      return ptest;
		    }
		}
	    }
	  if (++dotcount == 10)
	    {
	      progress (ctx, '.');
	      dotcount = 0;
	    }
	}
      progress (ctx, ':');	/* restart with a new random value */
    }
}

/****************
 * Returns: true if this may be a prime
 * RM_ROUNDS gives the number of Rabin-Miller tests to run.
 */
static int
check_prime (gcry_core_context_t ctx,
	     gcry_core_mpi_t prime, gcry_core_mpi_t val_2,
	     int rm_rounds, gcry_prime_check_func_t cb_func, void *cb_arg)
{
  int count = 0;

#if 0
  /* FIXME, this code is flawed, needs to be looked at; doesn't work
     for small primes.  */
  int i;
  unsigned int x;
#endif

  /* Check against small primes. */
#if 0
  for (i = 0; (x = small_prime_numbers[i]); i++)
    {
      if (mpi_divisible_ui (ctx, prime, x))
	return 0;
    }
#endif

  /* A quick Fermat test. */
  {
    gcry_core_mpi_t result = gcry_core_mpi_alloc_like (ctx, prime);
    gcry_core_mpi_t pminus1 = gcry_core_mpi_alloc_like (ctx, prime);
    gcry_core_mpi_sub_ui (ctx, pminus1, prime, 1);
    gcry_core_mpi_powm (ctx, result, val_2, pminus1, prime);
    gcry_core_mpi_release (ctx, pminus1);
    if (gcry_core_mpi_cmp_ui (ctx, result, 1))
      {
	/* Is composite. */
	gcry_core_mpi_release (ctx, result);
	progress (ctx, '.');
	return 0;
      }
    gcry_core_mpi_release (ctx, result);
  }

  if (!cb_func || cb_func (cb_arg, GCRY_PRIME_CHECK_AT_MAYBE_PRIME, prime))
    {
      /* Perform stronger tests. */
      if (is_prime (ctx, prime, rm_rounds, &count))
	{
	  if (!cb_func
	      || cb_func (cb_arg, GCRY_PRIME_CHECK_AT_GOT_PRIME, prime))
	    return 1;		/* Probably a prime. */
	}
    }
  progress (ctx, '.');
  return 0;
}


/*
 * Return true if n is probably a prime
 */
static int
is_prime (gcry_core_context_t ctx, gcry_core_mpi_t n, int steps, int *count)
{
  gcry_core_mpi_t x = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, n));
  gcry_core_mpi_t y = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, n));
  gcry_core_mpi_t z = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, n));
  gcry_core_mpi_t nminus1 = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, n));
  gcry_core_mpi_t a2 = gcry_core_mpi_alloc_set_ui (ctx, 2);
  gcry_core_mpi_t q;
  unsigned i, j, k;
  int rc = 0;
  unsigned nbits = gcry_core_mpi_get_nbits (ctx, n);

  if (steps < 5) /* Make sure that we do at least 5 rounds. */
    steps = 5; 

  gcry_core_mpi_sub_ui (ctx, nminus1, n, 1);

  /* Find q and k, so that n = 1 + 2^k * q . */
  q = gcry_core_mpi_copy (ctx, nminus1);

  /* FIXME: moritz, trailing_zeros.  */
  k = gcry_core_mpi_trailing_zeros (ctx, q);
  gcry_core_mpi_tdiv_q_2exp (ctx, q, q, k);

  for (i = 0; i < steps; i++)
    {
      ++*count;
      if (!i)
	{
	  gcry_core_mpi_set_ui (ctx, x, 2);
	}
      else
	{
	  gcry_core_mpi_randomize (ctx, x, nbits, GCRY_WEAK_RANDOM);

	  /* Make sure that the number is smaller than the prime and
	     keep the randomness of the high bit. */
	  if (gcry_core_mpi_test_bit (ctx, x, nbits - 2))
	    {
	      gcry_core_mpi_set_highbit (ctx, x, nbits - 2);	/* Clear all higher bits. */
	    }
	  else
	    {
	      gcry_core_mpi_set_highbit (ctx, x, nbits - 2);
	      gcry_core_mpi_clear_bit (ctx, x, nbits - 2);
	    }
	  assert (gcry_core_mpi_cmp (ctx, x, nminus1) < 0
		  && gcry_core_mpi_cmp_ui (ctx, x, 1) > 0);
	}
      gcry_core_mpi_powm (ctx, y, x, q, n);
      if (gcry_core_mpi_cmp_ui (ctx, y, 1) && gcry_core_mpi_cmp (ctx, y, nminus1))
	{
	  for (j = 1; j < k && gcry_core_mpi_cmp (ctx, y, nminus1); j++)
	    {
	      gcry_core_mpi_powm (ctx, y, y, a2, n);
	      if (!gcry_core_mpi_cmp_ui (ctx, y, 1))
		goto leave;	/* Not a prime. */
	    }
	  if (gcry_core_mpi_cmp (ctx, y, nminus1))
	    goto leave;		/* Not a prime. */
	}
      progress (ctx, '+');
    }
  rc = 1;			/* May be a prime. */

leave:
  gcry_core_mpi_release (ctx, x);
  gcry_core_mpi_release (ctx, y);
  gcry_core_mpi_release (ctx, z);
  gcry_core_mpi_release (ctx, nminus1);
  gcry_core_mpi_release (ctx, q);
  gcry_core_mpi_release (ctx, a2);

  return rc;
}


static void
m_out_of_n (gcry_core_context_t ctx, char *array, int m, int n)
{
  int i = 0, i1 = 0, j = 0, jp = 0, j1 = 0, k1 = 0, k2 = 0;

  if (!m || m >= n)
    return;

  if (m == 1)
    {
      /* Special case. */
      for (i = 0; i < n; i++)
	{
	  if (array[i])
	    {
	      array[i++] = 0;
	      if (i >= n)
		i = 0;
	      array[i] = 1;
	      return;
	    }
	}
      BUG (ctx);
    }

  for (j = 1; j < n; j++)
    {
      if (array[n - 1] == array[n - j - 1])
	continue;
      j1 = j;
      break;
    }

  if ((m & 1))
    {
      /* M is odd. */
      if (array[n - 1])
	{
	  if (j1 & 1)
	    {
	      k1 = n - j1;
	      k2 = k1 + 2;
	      if (k2 > n)
		k2 = n;
	      goto leave;
	    }
	  goto scan;
	}
      k2 = n - j1 - 1;
      if (k2 == 0)
	{
	  k1 = i;
	  k2 = n - j1;
	}
      else if (array[k2] && array[k2 - 1])
	k1 = n;
      else
	k1 = k2 + 1;
    }
  else
    {
      /* M is even. */
      if (!array[n - 1])
	{
	  k1 = n - j1;
	  k2 = k1 + 1;
	  goto leave;
	}

      if (!(j1 & 1))
	{
	  k1 = n - j1;
	  k2 = k1 + 2;
	  if (k2 > n)
	    k2 = n;
	  goto leave;
	}
    scan:
      jp = n - j1 - 1;
      for (i = 1; i <= jp; i++)
	{
	  i1 = jp + 2 - i;
	  if (array[i1 - 1])
	    {
	      if (array[i1 - 2])
		{
		  k1 = i1 - 1;
		  k2 = n - j1;
		}
	      else
		{
		  k1 = i1 - 1;
		  k2 = n + 1 - j1;
		}
	      goto leave;
	    }
	}
      k1 = 1;
      k2 = n + 1 - m;
    }
leave:
  array[k1 - 1] = !array[k1 - 1];
  array[k2 - 1] = !array[k2 - 1];
}


/* Generate a new prime number of PRIME_BITS bits and store it in
   PRIME.  If FACTOR_BITS is non-zero, one of the prime factors of
   (prime - 1) / 2 must be FACTOR_BITS bits long.  If FACTORS is
   non-zero, allocate a new, NULL-terminated array holding the prime
   factors and store it in FACTORS.  FLAGS might be used to influence
   the prime number generation process.  */
gcry_error_t
_gcry_prime_generate (gcry_core_context_t ctx,
		      gcry_core_mpi_t * prime, unsigned int prime_bits,
		      unsigned int factor_bits, gcry_core_mpi_t ** factors,
		      gcry_prime_check_func_t cb_func, void *cb_arg,
		      gcry_random_level_t random_level, unsigned int flags)
{
  gcry_error_t err = 0;
  gcry_core_mpi_t *factors_generated = NULL;
  gcry_core_mpi_t prime_generated = NULL;
  unsigned int mode = 0;

  if (!prime)
    return gcry_core_error (GPG_ERR_INV_ARG);
  *prime = NULL;

  if (flags & GCRY_PRIME_FLAG_SPECIAL_FACTOR)
    mode = 1;

  /* Generate.  */
  err = prime_generate_internal (ctx,
				 mode, &prime_generated, prime_bits,
				 factor_bits, NULL,
				 factors ? &factors_generated : NULL,
				 random_level, flags, 1, cb_func, cb_arg);

  if (!err)
    if (cb_func)
      {
	/* Additional check. */
	if (!cb_func (cb_arg, GCRY_PRIME_CHECK_AT_FINISH, prime_generated))
	  {
	    /* Failed, deallocate resources.  */
	    unsigned int i;

	    gcry_core_mpi_release (ctx, prime_generated);
	    if (factors)
	      {
		for (i = 0; factors_generated[i]; i++)
		  gcry_core_mpi_release (ctx, factors_generated[i]);
		gcry_core_free (ctx, factors_generated);
	      }
	    err = gcry_core_error (GPG_ERR_GENERAL);
	  }
      }

  if (!err)
    {
      if (factors)
	*factors = factors_generated;
      *prime = prime_generated;
    }

  return err;
}

/* Check wether the number X is prime.  */
gcry_error_t
_gcry_prime_check (gcry_core_context_t ctx, gcry_core_mpi_t x, unsigned int flags)
{
  gcry_error_t err = 0;
  gcry_core_mpi_t val_2 = gcry_core_mpi_alloc_set_ui (ctx, 2);	/* Used by the Fermat test. */

  /* We use 64 rounds because the prime we are going to test is not
     guaranteed to be a random one. */
  if (! check_prime (ctx, x, val_2, 64, NULL, NULL))
    err = gcry_core_error (GPG_ERR_NO_PRIME);

  gcry_core_mpi_release (ctx, val_2);

  return err;
}

/* Find a generator for PRIME where the factorization of (prime-1) is
   in the NULL terminated array FACTORS. Return the generator as a
   newly allocated MPI in R_G.  If START_G is not NULL, use this as s
   atart for the search. Returns 0 on success.*/
gcry_error_t
_gcry_prime_group_generator (gcry_core_context_t ctx,
			     gcry_core_mpi_t * r_g,
			     gcry_core_mpi_t prime, gcry_core_mpi_t * factors,
			     gcry_core_mpi_t start_g)
{
  gcry_core_mpi_t tmp = gcry_core_mpi_new (ctx, 0);
  gcry_core_mpi_t b = gcry_core_mpi_new (ctx, 0);
  gcry_core_mpi_t pmin1 = gcry_core_mpi_new (ctx, 0);
  gcry_core_mpi_t g =
    start_g ? gcry_core_mpi_copy (ctx, start_g) : gcry_core_mpi_set_ui (ctx, NULL, 3);
  int first = 1;
  int i, n;

  if (!factors || !r_g || !prime)
    return gpg_error (GPG_ERR_INV_ARG);
  *r_g = NULL;

  for (n = 0; factors[n]; n++)
    ;
  if (n < 2)
    return gpg_error (GPG_ERR_INV_ARG);

  /* Extra sanity check - usually disabled. */
  /*   gcry_core_mpi_set (tmp, factors[0]); */
  /*   for(i = 1; i < n; i++) */
  /*     gcry_core_mpi_mul (tmp, tmp, factors[i]); */
  /*   gcry_core_mpi_add_ui (tmp, tmp, 1); */
  /*   if (mpi_cmp (prime, tmp)) */
  /*     return gpg_error (GPG_ERR_INV_ARG); */

  gcry_core_mpi_sub_ui (ctx, pmin1, prime, 1);
  do
    {
      if (first)
	first = 0;
      else
	gcry_core_mpi_add_ui (ctx, g, g, 1);

      if (GCRY_CORE_DEBUGGING_PRIME (ctx))
	{
	  log_debug (ctx, "checking g:");
	  gcry_core_mpi_dump (ctx, g);
	  log_debug (ctx, "\n");
	}
      else
	progress (ctx, '^');

      for (i = 0; i < n; i++)
	{
	  gcry_core_mpi_fdiv_q (ctx, tmp, pmin1, factors[i]);
	  gcry_core_mpi_powm (ctx, b, g, tmp, prime);
	  if (!gcry_core_mpi_cmp_ui (ctx, b, 1))
	    break;
	}
      if (GCRY_CORE_DEBUGGING_PRIME (ctx))
	progress (ctx, '\n');
    }
  while (i < n);

  gcry_core_mpi_release (ctx, tmp);
  gcry_core_mpi_release (ctx, b);
  gcry_core_mpi_release (ctx, pmin1);
  *r_g = g;

  return 0;
}



struct gcry_core_subsystem_prime _gcry_subsystem_prime =
  {
    _gcry_generate_secret_prime,
    _gcry_generate_public_prime,
    _gcry_generate_elg_prime,
    _gcry_prime_generate,
    _gcry_prime_check,
    _gcry_prime_group_generator
  };

gcry_core_subsystem_prime_t gcry_core_subsystem_prime = &_gcry_subsystem_prime;
