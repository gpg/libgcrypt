/* rsa.c  -  RSA function
 *	Copyright (C) 1997, 1998, 1999 by Werner Koch (dd9jn)
 *	Copyright (C) 2000, 2001, 2002, 2003, 2005 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
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
 */

/* This code uses an algorithm protected by U.S. Patent #4,405,829
   which expired on September 20, 2000.  The patent holder placed that
   patent into the public domain on Sep 6th, 2000.
*/

#include <gcrypt-ac-internal.h>

#include <gcrypt-mpi-internal.h>
#include <gcrypt-prime-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sha1.h>

#include "rsa.h"

typedef struct
{
  gcry_core_mpi_t n;			/* modulus */
  gcry_core_mpi_t e;			/* exponent */
} RSA_public_key;


typedef struct
{
  gcry_core_mpi_t n;			/* public modulus */
  gcry_core_mpi_t e;			/* public exponent */
  gcry_core_mpi_t d;			/* exponent */
  gcry_core_mpi_t p;			/* prime  p. */
  gcry_core_mpi_t q;			/* prime  q. */
  gcry_core_mpi_t u;			/* inverse of p mod q. */
} RSA_secret_key;


static void test_keys (gcry_core_context_t ctx, RSA_secret_key *sk, unsigned nbits);
static void generate (gcry_core_context_t ctx, RSA_secret_key * sk,
		      unsigned int nbits,
		      gcry_core_ac_key_spec_rsa_t *spec);
static int check_secret_key (gcry_core_context_t ctx, RSA_secret_key * sk);
static void public (gcry_core_context_t ctx,
		    gcry_core_mpi_t output, gcry_core_mpi_t input,
		    RSA_public_key * skey);
static void secret (gcry_core_context_t ctx,
		    gcry_core_mpi_t output, gcry_core_mpi_t input,
		    RSA_secret_key * skey);


static void
test_keys (gcry_core_context_t ctx, RSA_secret_key * sk, unsigned nbits)
{
  RSA_public_key pk;
  gcry_core_mpi_t test = gcry_core_mpi_new (ctx, nbits);
  gcry_core_mpi_t out1 = gcry_core_mpi_new (ctx, nbits);
  gcry_core_mpi_t out2 = gcry_core_mpi_new (ctx, nbits);

  pk.n = sk->n;
  pk.e = sk->e;
  gcry_core_mpi_randomize (ctx, test, nbits, GCRY_WEAK_RANDOM);

  public (ctx, out1, test, &pk);
  secret (ctx, out2, out1, sk);
  if (gcry_core_mpi_cmp (ctx, test, out2))
    log_fatal (ctx, "RSA operation: public, secret failed\n");
  secret (ctx, out1, test, sk);
  public (ctx, out2, out1, &pk);
  if (gcry_core_mpi_cmp (ctx, test, out2))
    log_fatal (ctx, "RSA operation: secret, public failed\n");
  gcry_core_mpi_release (ctx, test);
  gcry_core_mpi_release (ctx, out1);
  gcry_core_mpi_release (ctx, out2);
}


/* Callback used by the prime generation to test whether the exponent
   is suitable. Returns 0 if the test has been passed. */
static int
check_exponent (gcry_core_context_t ctx, void *arg, gcry_core_mpi_t a)
{
  gcry_core_mpi_t e = arg;
  gcry_core_mpi_t tmp;
  int result;

  gcry_core_mpi_sub_ui (ctx, a, a, 1);
  tmp = gcry_core_mpi_alloc_like (ctx, a);
  result = !gcry_core_mpi_gcd (ctx, tmp, e, a);	/* GCD is not 1. */
  gcry_core_mpi_release (ctx, tmp);
  gcry_core_mpi_add_ui (ctx, a, a, 1);

  return result;
}

/****************
 * Generate a key pair with a key of size NBITS.  
 * USE_E = 0 let Libcgrypt decide what exponent to use.
 *       = 1 request the use of a "secure" exponent; this is required by some 
 *           specification to be 65537.
 *       > 2 Try starting at this value until a working exponent is found.
 * Returns: 2 structures filled with all needed values
 */
static void
generate (gcry_core_context_t ctx,
	  RSA_secret_key *sk, unsigned int nbits,
	  gcry_core_ac_key_spec_rsa_t *spec)
{
  gcry_core_mpi_t p, q;		/* the two primes */
  gcry_core_mpi_t d;			/* the private key */
  gcry_core_mpi_t u;
  gcry_core_mpi_t t1, t2;
  gcry_core_mpi_t n;			/* the public key */
  gcry_core_mpi_t e;			/* the exponent */
  gcry_core_mpi_t phi;		/* helper: (p-1)(q-1) */
  gcry_core_mpi_t g;
  gcry_core_mpi_t f;
  unsigned long int use_e;

  if (spec)
    {
      use_e = spec->e;

      if (use_e == 0)
	use_e = 65537;		/* Use the value used by old versions.  */
      else if (use_e == 1)
	use_e = 65537;		/* Alias for a secure value as
				   demanded by Spinx. */
    }
  else
    use_e = 0;

  /* make sure that nbits is even so that we generate p, q of equal size */
  if ((nbits & 1))
    nbits++;

  /* Public exponent:
     In general we use 41 as this is quite fast and more secure than the
     commonly used 17.  Benchmarking the RSA verify function
     with a 1024 bit key yields (2001-11-08): 
     e=17    0.54 ms
     e=41    0.75 ms
     e=257   0.95 ms
     e=65537 1.80 ms
   */
  /* FIXME, moritz, is this correct?  */
  e = gcry_core_mpi_new (ctx, 32 + BITS_PER_MPI_LIMB - 1);
  if (!use_e)
    /* This is a reasonable secure and fast value */
    gcry_core_mpi_set_ui (ctx, e, 41);
  else
    {
      use_e |= 1;		/* make sure this is odd */
      gcry_core_mpi_set_ui (ctx, e, use_e);
    }

  n = gcry_core_mpi_new (ctx, nbits);

  p = q = NULL;
  do
    {
      /* select two (very secret) primes */
      if (p)
	gcry_core_mpi_release (ctx, p);
      if (q)
	gcry_core_mpi_release (ctx, q);
      if (use_e)
	{			/* Do an extra test to ensure that the given exponent is
				   suitable. */
	  p = gcry_core_prime_generate_secret (ctx, nbits / 2, check_exponent, e);
	  q = gcry_core_prime_generate_secret (ctx, nbits / 2, check_exponent, e);
	}
      else
	{			/* We check the exponent later. */
	  p = gcry_core_prime_generate_secret (ctx, nbits / 2, NULL, NULL);
	  q = gcry_core_prime_generate_secret (ctx, nbits / 2, NULL, NULL);
	}
      if (gcry_core_mpi_cmp (ctx, p, q) > 0)	/* p shall be smaller than q (for calc of u) */
	gcry_core_mpi_swap (ctx, p, q);
      /* calculate the modulus */
      gcry_core_mpi_mul (ctx, n, p, q);
    }
  while (gcry_core_mpi_get_nbits (ctx, n) != nbits);

  /* calculate Euler totient: phi = (p-1)(q-1) */
  /* FIXME, moritz, allocation correct?  */
  t1 = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, p));
  t2 = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, p));
  phi = gcry_core_mpi_snew (ctx, nbits);
  g = gcry_core_mpi_snew (ctx, nbits);
  f = gcry_core_mpi_snew (ctx, nbits);
  gcry_core_mpi_sub_ui (ctx, t1, p, 1);
  gcry_core_mpi_sub_ui (ctx, t2, q, 1);
  gcry_core_mpi_mul (ctx, phi, t1, t2);
  gcry_core_mpi_gcd (ctx, g, t1, t2);
  gcry_core_mpi_fdiv_q (ctx, f, phi, g);

  while (!gcry_core_mpi_gcd (ctx, t1, e, phi))	/* (while gcd is not 1) */
    {
      if (use_e)
	/* The prime generator already made sure that we never can get
	   to here. */
	BUG (ctx);
      gcry_core_mpi_add_ui (ctx, e, e, 2);
    }

  /* calculate the secret key d = e^1 mod phi */
  d = gcry_core_mpi_snew (ctx, nbits);
  gcry_core_mpi_invm (ctx, d, e, f);
  /* calculate the inverse of p and q (used for chinese remainder theorem) */
  u = gcry_core_mpi_snew (ctx, nbits);
  gcry_core_mpi_invm (ctx, u, p, q);

  if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
    {
      _gcry_log_mpidump (ctx, "  p= ", p);
      _gcry_log_mpidump (ctx, "  q= ", q);
      _gcry_log_mpidump (ctx, "phi= ", phi);
      _gcry_log_mpidump (ctx, "  g= ", g);
      _gcry_log_mpidump (ctx, "  f= ", f);
      _gcry_log_mpidump (ctx, "  n= ", n);
      _gcry_log_mpidump (ctx, "  e= ", e);
      _gcry_log_mpidump (ctx, "  d= ", d);
      _gcry_log_mpidump (ctx, "  u= ", u);
    }

  gcry_core_mpi_release (ctx, t1);
  gcry_core_mpi_release (ctx, t2);
  gcry_core_mpi_release (ctx, phi);
  gcry_core_mpi_release (ctx, f);
  gcry_core_mpi_release (ctx, g);

  sk->n = n;
  sk->e = e;
  sk->p = p;
  sk->q = q;
  sk->d = d;
  sk->u = u;

  /* now we can test our keys (this should never fail!) */
  test_keys (ctx, sk, nbits - 64);
}


/****************
 * Test wether the secret key is valid.
 * Returns: true if this is a valid key.
 */
static int
check_secret_key (gcry_core_context_t ctx, RSA_secret_key * sk)
{
  gcry_core_mpi_t temp;
  int rc;

  temp = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, sk->p) * 2);

  gcry_core_mpi_mul (ctx, temp, sk->p, sk->q);
  rc = gcry_core_mpi_cmp (ctx, temp, sk->n);
  gcry_core_mpi_release (ctx, temp);
  return !rc;
}



/****************
 * Public key operation. Encrypt INPUT with PKEY and put result into OUTPUT.
 *
 *	c = m^e mod n
 *
 * Where c is OUTPUT, m is INPUT and e,n are elements of PKEY.
 */
static void
public (gcry_core_context_t ctx,
	gcry_core_mpi_t output, gcry_core_mpi_t input, RSA_public_key * pkey)
{
  if (output == input)		/* powm doesn't like output and input the same */
    {
      gcry_core_mpi_t x;

      x = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, input) * 2);
      gcry_core_mpi_powm (ctx, x, input, pkey->e, pkey->n);
      gcry_core_mpi_set (ctx, output, x);
      gcry_core_mpi_release (ctx, x);
    }
  else
    gcry_core_mpi_powm (ctx, output, input, pkey->e, pkey->n);
}

/****************
 * Secret key operation. Encrypt INPUT with SKEY and put result into OUTPUT.
 *
 *	m = c^d mod n
 *
 * Or faster:
 *
 *      m1 = c ^ (d mod (p-1)) mod p 
 *      m2 = c ^ (d mod (q-1)) mod q 
 *      h = u * (m2 - m1) mod q 
 *      m = m1 + h * p
 *
 * Where m is OUTPUT, c is INPUT and d,n,p,q,u are elements of SKEY.
 */
static void
secret (gcry_core_context_t ctx,
	gcry_core_mpi_t output, gcry_core_mpi_t input, RSA_secret_key * skey)
{
  if (!skey->p && !skey->q && !skey->u)
    {
      gcry_core_mpi_powm (ctx, output, input, skey->d, skey->n);
    }
  else
    {
      gcry_core_mpi_t m1;
      gcry_core_mpi_t m2;
      gcry_core_mpi_t h;

      m1 = gcry_core_mpi_snew (ctx,
			       (gcry_core_mpi_get_nbits (ctx, skey->n)
				+ BITS_PER_MPI_LIMB));
      m2 = gcry_core_mpi_snew (ctx,
			       (gcry_core_mpi_get_nbits (ctx, skey->n)
				+ BITS_PER_MPI_LIMB));
      h = gcry_core_mpi_snew (ctx,
			      (gcry_core_mpi_get_nbits (ctx, skey->n)
			       + BITS_PER_MPI_LIMB));

      /* m1 = c ^ (d mod (p-1)) mod p */
      gcry_core_mpi_sub_ui (ctx, h, skey->p, 1);
      gcry_core_mpi_fdiv_r (ctx, h, skey->d, h);
      gcry_core_mpi_powm (ctx, m1, input, h, skey->p);
      /* m2 = c ^ (d mod (q-1)) mod q */
      gcry_core_mpi_sub_ui (ctx, h, skey->q, 1);
      gcry_core_mpi_fdiv_r (ctx, h, skey->d, h);
      gcry_core_mpi_powm (ctx, m2, input, h, skey->q);
      /* h = u * ( m2 - m1 ) mod q */
      gcry_core_mpi_sub (ctx, h, m2, m1);
      if (gcry_core_mpi_cmp_ui (ctx, h, 0) < 0)
	gcry_core_mpi_add (ctx, h, h, skey->q);
      gcry_core_mpi_mulm (ctx, h, skey->u, h, skey->q);
      /* m = m2 + h * p */
      gcry_core_mpi_mul (ctx, h, h, skey->p);
      gcry_core_mpi_add (ctx, output, m1, h);

      gcry_core_mpi_release (ctx, h);
      gcry_core_mpi_release (ctx, m1);
      gcry_core_mpi_release (ctx, m2);
    }
}



/* Perform RSA blinding.  */
static gcry_core_mpi_t
rsa_blind (gcry_core_context_t ctx,
	   gcry_core_mpi_t x, gcry_core_mpi_t r, gcry_core_mpi_t e, gcry_core_mpi_t n)
{
  /* A helper.  */
  gcry_core_mpi_t a;

  /* Result.  */
  gcry_core_mpi_t y;

  a = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, n));
  y = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, n));

  /* Now we calculate: y = (x * r^e) mod n, where r is the random
     number, e is the public exponent, x is the non-blinded data and n
     is the RSA modulus.  */
  gcry_core_mpi_powm (ctx, a, r, e, n);
  gcry_core_mpi_mulm (ctx, y, a, x, n);

  gcry_core_mpi_release (ctx, a);

  return y;
}

/* Undo RSA blinding.  */
static gcry_core_mpi_t
rsa_unblind (gcry_core_context_t ctx,
	     gcry_core_mpi_t x, gcry_core_mpi_t ri, gcry_core_mpi_t n)
{
  gcry_core_mpi_t y;

  y = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, n));

  /* Here we calculate: y = (x * r^-1) mod n, where x is the blinded
     decrypted data, ri is the modular multiplicative inverse of r and
     n is the RSA modulus.  */

  gcry_core_mpi_mulm (ctx, y, ri, x, n);

  return y;
}

/*********************************************
 **************  interface  ******************
 *********************************************/

gcry_err_code_t
_gcry_rsa_generate (gcry_core_context_t ctx, unsigned int flags,
		    unsigned int nbits, void *spec,
		    gcry_core_mpi_t *skey, gcry_core_mpi_t **retfactors)
{
  RSA_secret_key sk;

  generate (ctx, &sk, nbits, spec);
  skey[0] = sk.n;
  skey[1] = sk.e;
  skey[2] = sk.d;
  skey[3] = sk.p;
  skey[4] = sk.q;
  skey[5] = sk.u;

  /* make an empty list of factors */
  *retfactors = gcry_core_xcalloc (ctx, 1, sizeof **retfactors);

  return 0;
}


gcry_err_code_t
_gcry_rsa_check_secret_key (gcry_core_context_t ctx,
			    unsigned int flags,
			    gcry_core_mpi_t *skey)
{
  gcry_err_code_t err;
  RSA_secret_key sk;

  sk.n = skey[0];
  sk.e = skey[1];
  sk.d = skey[2];
  sk.p = skey[3];
  sk.q = skey[4];
  sk.u = skey[5];

  if (!check_secret_key (ctx, &sk))
    err = GPG_ERR_PUBKEY_ALGO;
  else
    err = 0;

  return err;
}


gcry_err_code_t
_gcry_rsa_encrypt (gcry_core_context_t ctx,
			    unsigned int flags,
		   gcry_core_mpi_t *resarr, gcry_core_mpi_t data,
		   gcry_core_mpi_t * pkey)
{
  RSA_public_key pk;

  pk.n = pkey[0];
  pk.e = pkey[1];
  resarr[0] = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, pk.n));
  public (ctx, resarr[0], data, &pk);

  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
_gcry_rsa_decrypt (gcry_core_context_t ctx,
			    unsigned int flags,
		   gcry_core_mpi_t *result, gcry_core_mpi_t *data,
		   gcry_core_mpi_t *skey)
{
  RSA_secret_key sk;
  gcry_core_mpi_t r = MPI_NULL;	/* Random number needed for blinding.  */
  gcry_core_mpi_t ri = MPI_NULL;	/* Modular multiplicative inverse of
				   r.  */
  gcry_core_mpi_t x = MPI_NULL;	/* Data to decrypt.  */
  gcry_core_mpi_t y;			/* Result.  */

  /* Extract private key.  */
  sk.n = skey[0];
  sk.e = skey[1];
  sk.d = skey[2];
  sk.p = skey[3];
  sk.q = skey[4];
  sk.u = skey[5];

  y = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, sk.n));

  if (!(flags & GCRY_CORE_AC_FLAG_NO_BLINDING))
    {
      /* Initialize blinding.  */

      /* First, we need a random number r between 0 and n - 1, which
         is relatively prime to n (i.e. it is neither p nor q).  */
      r = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, sk.n));
      ri = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, sk.n));

      gcry_core_mpi_randomize (ctx, r, gcry_core_mpi_get_nbits (ctx, sk.n),
			       GCRY_STRONG_RANDOM);
      gcry_core_mpi_mod (ctx, r, r, sk.n);

      /* Actually it should be okay to skip the check for equality
         with either p or q here.  */

      /* Calculate inverse of r.  */
      if (!gcry_core_mpi_invm (ctx, ri, r, sk.n))
	BUG (ctx);
    }

  if (!(flags & GCRY_CORE_AC_FLAG_NO_BLINDING))
    x = rsa_blind (ctx, data[0], r, sk.e, sk.n);
  else
    x = data[0];

  /* Do the encryption.  */
  secret (ctx, y, x, &sk);

  if (!(flags & GCRY_CORE_AC_FLAG_NO_BLINDING))
    {
      /* Undo blinding.  */
      gcry_core_mpi_t a = gcry_core_mpi_copy (ctx, y);

      gcry_core_mpi_release (ctx, y);
      y = rsa_unblind (ctx, a, ri, sk.n);

      gcry_core_mpi_release (ctx, a);
    }

  if (!(flags & GCRY_CORE_AC_FLAG_NO_BLINDING))
    {
      /* Deallocate resources needed for blinding.  */
      gcry_core_mpi_release (ctx, x);
      gcry_core_mpi_release (ctx, r);
      gcry_core_mpi_release (ctx, ri);
    }

  /* Copy out result.  */
  *result = y;

  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
_gcry_rsa_sign (gcry_core_context_t ctx,
			    unsigned int flags,
		gcry_core_mpi_t *resarr, gcry_core_mpi_t data,
		gcry_core_mpi_t *skey)
{
  RSA_secret_key sk;

  sk.n = skey[0];
  sk.e = skey[1];
  sk.d = skey[2];
  sk.p = skey[3];
  sk.q = skey[4];
  sk.u = skey[5];
  resarr[0] = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, sk.n));
  secret (ctx, resarr[0], data, &sk);

  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
_gcry_rsa_verify (gcry_core_context_t ctx,
			    unsigned int flags,
		  gcry_core_mpi_t hash,
		  gcry_core_mpi_t *data,
		  gcry_core_mpi_t *pkey,
		  int (*cmp) (void *opaque, gcry_core_mpi_t tmp), /* FIXME? */
		  void *opaquev)
{
  RSA_public_key pk;
  gcry_core_mpi_t result;
  gcry_err_code_t rc;

  pk.n = pkey[0];
  pk.e = pkey[1];
  result = gcry_core_mpi_new (ctx, 160);
  public (ctx, result, data[0], &pk);
  /*rc = (*cmp)( opaquev, result ); */
  if (gcry_core_mpi_cmp (ctx, result, hash))
    rc = GPG_ERR_BAD_SIGNATURE;
  else
    rc = GPG_ERR_NO_ERROR;

  gcry_core_mpi_release (ctx, result);

  return rc;
}


unsigned int
_gcry_rsa_get_nbits (gcry_core_context_t ctx,
			    unsigned int flags,
		     gcry_core_mpi_t *pkey)
{
  return gcry_core_mpi_get_nbits (ctx, pkey[0]);
}

gcry_error_t
_gcry_rsa_keygrip (gcry_core_context_t ctx,
			    unsigned int flags,
		   gcry_core_mpi_t *pkey,
		   unsigned char *grip)
{
  gcry_core_md_hd_t md;
  unsigned char *buffer;
  size_t buffer_n;
  unsigned char *hash;
  gcry_error_t err;

  buffer = NULL;
  buffer_n = 0;
  md = NULL;
  
  err = gcry_core_md_open (ctx, &md, gcry_core_digest_sha1, 0);
  if (err)
    goto out;

  err = gcry_core_mpi_aprint (ctx, GCRYMPI_FMT_STD,
			      &buffer, &buffer_n, pkey[0]);
  if (err)
    goto out;

  gcry_core_md_write (ctx, md, buffer, buffer_n);

  hash = gcry_core_md_read (ctx, md, NULL);
  assert (hash);		/* FIXME?  */

  memcpy (grip, hash, 20);	/* FIXME, constant.  */

 out:

  gcry_core_md_close (ctx, md);
  gcry_core_free (ctx, buffer);

  return err;
}



static char *rsa_names[] = {
  "rsa",
  "openpgp-rsa",
  "oid.1.2.840.113549.1.1.1",
  NULL,
};



static struct gcry_core_ac_spec gcry_core_ac_rsa_struct = {
  "RSA", rsa_names,
  "ne", "nedpqu", "a", "s", "n",
  GCRY_AC_KEY_USAGE_SIGN | GCRY_AC_KEY_USAGE_ENCR,
  20,
  _gcry_rsa_generate,
  _gcry_rsa_check_secret_key,
  _gcry_rsa_encrypt,
  _gcry_rsa_decrypt,
  _gcry_rsa_sign,
  _gcry_rsa_verify,
  _gcry_rsa_get_nbits,
  _gcry_rsa_keygrip
};

gcry_core_ac_spec_t gcry_core_ac_rsa = &gcry_core_ac_rsa_struct;
