/* rsa.c - RSA cryptography algorithm.
   Copyright (C) 1997, 1998, 1999 by Werner Koch (dd9jn)
   Copyright (C) 2000, 2001, 2002, 2003 Free Software Foundation, Inc.

   This file is part of Libgcrypt.
   
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA.  */

/* This code uses an algorithm protected by U.S. Patent #4,405,829
   which expired on September 20, 2000.  The patent holder placed that
   patent into the public domain on Sep 6th, 2000.  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"



#define GCRY_AC_ALGORITHM rsa
#define GCRY_AC_ALIASES "RSA", "openpgp-rsa", "oid.1.2.840.113549.1.1.1"



typedef struct key_public
{
  gcry_mpi_t n;	    /* modulus */
  gcry_mpi_t e;	    /* exponent */
} key_public_t;

typedef struct key_secret
{
  gcry_mpi_t n;	    /* public modulus */
  gcry_mpi_t e;	    /* public exponent */
  gcry_mpi_t d;	    /* exponent */
  gcry_mpi_t p;	    /* prime  p. */
  gcry_mpi_t q;	    /* prime  q. */
  gcry_mpi_t u;	    /* inverse of p mod q. */
} key_secret_t;

typedef struct data_encrypted
{
  gcry_mpi_t a;			/* Encrypted data.  */
} data_encrypted_t;

typedef struct data_signed
{
  gcry_mpi_t s;			/* Signed data.  */
} data_signed_t;



GCRY_AC_SPEC_KEY_PUBLIC =
  {
    GCRY_AC_ELEM_KEY_PUBLIC (n), GCRY_AC_ELEM_KEY_PUBLIC (e)
  };
GCRY_AC_SPEC_KEY_SECRET =
  {
    GCRY_AC_ELEM_KEY_SECRET (n), GCRY_AC_ELEM_KEY_SECRET (e),
    GCRY_AC_ELEM_KEY_SECRET (d), GCRY_AC_ELEM_KEY_SECRET (p),
    GCRY_AC_ELEM_KEY_SECRET (q), GCRY_AC_ELEM_KEY_SECRET (u)
  };
GCRY_AC_SPEC_DATA_ENCRYPTED =
  {
    GCRY_AC_ELEM_DATA_ENCRYPTED (a)
  };
GCRY_AC_SPEC_DATA_SIGNED =
  {
    GCRY_AC_ELEM_DATA_SIGNED (s)
  };



/* RSA public key operation.  Encrypt INPUT with the public key KEY
   and put the result into OUTPUT. 

     c = m^e mod n

   Where c is OUTPUT, m is INPUT and e, n are elements of KEY.  */
static void
public (gcry_mpi_t output, gcry_mpi_t input, key_public_t *key)
{
  if (output == input)
    {
      /* powm doesn't like output and input being the same.  */
      gcry_mpi_t x = mpi_alloc (mpi_get_nlimbs (input) * 2);
      mpi_powm (x, input, key->e, key->n);
      mpi_set (output, x);
      mpi_free (x);
    }
  else
    mpi_powm (output, input, key->e, key->n);
}

/* RSA secret key operation.  Decrypt INPUT with the secret key KEY
   and put the result into OUTPUT.

     m = c^d mod n

   Or faster:

     m1 = c ^ (d mod (p - 1)) mod p 
     m2 = c ^ (d mod (q - 1)) mod q 
     h = u * (m2 - m1) mod q 
     m = m1 + h * p

 FIXME!
     
 Where m is OUTPUT, c is INPUT and d,n,p,q,u are elements of SKEY.  */
static void
secret (gcry_mpi_t output, gcry_mpi_t input, key_secret_t *key)
{
#if 0
  /* Simple version.  */
  mpi_powm (output, input, skey->d, skey->n);
#else
  /* Optimized version.  */
  gcry_mpi_t m1 = mpi_alloc_secure (mpi_get_nlimbs (key->n) + 1);
  gcry_mpi_t m2 = mpi_alloc_secure (mpi_get_nlimbs (key->n) + 1);
  gcry_mpi_t h = mpi_alloc_secure (mpi_get_nlimbs (key->n) + 1);

  /* m1 = c ^ (d mod (p-1)) mod p */
  mpi_sub_ui (h, key->p, 1);
  mpi_fdiv_r (h, key->d, h);   
  mpi_powm (m1, input, h, key->p);

  /* m2 = c ^ (d mod (q-1)) mod q */
  mpi_sub_ui (h, key->q, 1);
  mpi_fdiv_r (h, key->d, h);
  mpi_powm (m2, input, h, key->q);

  /* h = u * ( m2 - m1 ) mod q */
  mpi_sub (h, m2, m1);
  if (mpi_is_neg (h)) 
    mpi_add (h, h, key->q);
  mpi_mulm (h, key->u, h, key->q); 

  /* m = m2 + h * p */
  mpi_mul (h, h, key->p);
  mpi_add (output, m1, h);

  /* Ready.  */

  mpi_free (h);
  mpi_free (m1);
  mpi_free (m2);
#endif
}



static gcry_err_code_t
encrypt (gcry_mpi_t input,
	 key_public_t *key_public, data_encrypted_t *data_encrypted,
	 unsigned int flags)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t a;

  a = mpi_alloc (mpi_get_nlimbs (key_public->n));
  public (a, input, key_public);
  data_encrypted->a = a;

  return err;
}



gcry_err_code_t
verify (gcry_mpi_t data,
	key_public_t *key_public, data_signed_t *data_signed)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t s;

  s = gcry_mpi_new (160);
  public (s, data_signed->s, key_public);
  if (mpi_cmp (s, data))
    err = GPG_ERR_BAD_SIGNATURE;
  gcry_mpi_release (s);

  return err;
}



/* Perform RSA blinding.  */
static gcry_mpi_t
blind (gcry_mpi_t x, gcry_mpi_t r, gcry_mpi_t e, gcry_mpi_t n)
{
  /* A helper.  */
  gcry_mpi_t a;

  /* Result.  */
  gcry_mpi_t y;

  a = gcry_mpi_snew (gcry_mpi_get_nbits (n));
  y = gcry_mpi_snew (gcry_mpi_get_nbits (n));
  
  /* Now we calculate: y = (x * r^e) mod n, where r is the random
     number, e is the public exponent, x is the non-blinded data and n
     is the RSA modulus.  */
  gcry_mpi_powm (a, r, e, n);
  gcry_mpi_mulm (y, a, x, n);

  gcry_mpi_release (a);

  return y;
}

/* Undo RSA blinding.  */
static gcry_mpi_t
unblind (gcry_mpi_t x, gcry_mpi_t ri, gcry_mpi_t n)
{
  gcry_mpi_t y;

  y = gcry_mpi_snew (gcry_mpi_get_nbits (n));

  /* Here we calculate: y = (x * r^-1) mod n, where x is the blinded
     decrypted data, ri is the modular multiplicative inverse of r and
     n is the RSA modulus.  */

  gcry_mpi_mulm (y, ri, x, n);

  return y;
}

static gcry_err_code_t
decrypt (data_encrypted_t *data_encrypted, key_secret_t *key_secret,
	 gcry_mpi_t *data_decrypted, unsigned int flags)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t r = MPI_NULL;	/* Random number needed for blinding.  */
  gcry_mpi_t ri = MPI_NULL;	/* Modular multiplicative inverse of
				   r.  */
  gcry_mpi_t x = MPI_NULL;	/* Data to decrypt.  */
  gcry_mpi_t y;			/* Result.  */

  y = gcry_mpi_snew (gcry_mpi_get_nbits (key_secret->n));
  if (! (flags & GCRY_AC_FLAG_NO_BLINDING))
    {
      /* Initialize blinding.  */
      
      /* First, we need a random number r between 0 and n - 1, which
	 is relatively prime to n (i.e. it is neither p nor q).  */
      r = gcry_mpi_snew (gcry_mpi_get_nbits (key_secret->n));
      ri = gcry_mpi_snew (gcry_mpi_get_nbits (key_secret->n));
      
      gcry_mpi_randomize (r, gcry_mpi_get_nbits (key_secret->n),
			  GCRY_STRONG_RANDOM);
      gcry_mpi_mod (r, r, key_secret->n);

      /* Actually it should be okay to skip the check for equality
	 with either p or q here.  */

      /* Calculate inverse of r.  */
      if (! gcry_mpi_invm (ri, r, key_secret->n))
	BUG ();

      /* Do blinding.  */
      x = blind (data_encrypted->a, r, key_secret->e, key_secret->n);
    }
  else
    /* Skip blinding.  */
    x = data_encrypted->a;

  /* Do the encryption.  */
  secret (y, x, key_secret);

  if (! (flags & GCRY_AC_FLAG_NO_BLINDING))
    {
      /* Undo blinding.  */
      gcry_mpi_t a = gcry_mpi_copy (y);
      
      gcry_mpi_release (y);
      y = unblind (a, ri, key_secret->n);
    }

  if (! (flags & GCRY_AC_FLAG_NO_BLINDING))
    {
      /* Deallocate resources needed for blinding.  */
      gcry_mpi_release (x);
      gcry_mpi_release (r);
      gcry_mpi_release (ri);
    }

  /* Copy out result.  */
  *data_decrypted = y;
  
  return err;
}



gcry_err_code_t
sign (gcry_mpi_t input, key_secret_t *key_secret,
      data_signed_t *data_signed)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t s;

  /* Sign.  */
  s = mpi_alloc (mpi_get_nlimbs (key_secret->n));
  secret (s, input, key_secret);
  data_signed->s = s;

  return err;
}



/* Test wether the keys KEY_SECRET and KEY_PUBLIC work.  */
static void
keys_test (key_secret_t *key_secret, key_public_t *key_public,
	   unsigned int nbits)
{
  gcry_mpi_t test = gcry_mpi_new (nbits);
  gcry_mpi_t out1 = gcry_mpi_new (nbits);
  gcry_mpi_t out2 = gcry_mpi_new (nbits);

  gcry_mpi_randomize (test, nbits, GCRY_WEAK_RANDOM);

  public (out1, test, key_public);
  secret (out2, out1, key_secret);
  if (mpi_cmp (test, out2))
    log_fatal ("RSA operation: public, secret failed\n");

  secret (out1, test, key_secret);
  public (out2, out1, key_public);
  if (mpi_cmp (test, out2))
    log_fatal("RSA operation: secret, public failed\n");

  gcry_mpi_release (test);
  gcry_mpi_release (out1);
  gcry_mpi_release (out2);
}

/* Callback used by the prime generation to test whether the exponent
   is suitable. Returns 0 if the test has been passed. */
static int
check_exponent (void *arg, gcry_mpi_t a)
{
  gcry_mpi_t e = arg;
  gcry_mpi_t tmp;
  int result;

  mpi_sub_ui (a, a, 1);
  tmp = _gcry_mpi_alloc_like (a);
  result = !gcry_mpi_gcd(tmp, e, a); /* GCD is not 1. */
  gcry_mpi_release (tmp);
  mpi_add_ui (a, a, 1);
  return result;
}

/* Generate a key pair with a key of size NBITS.   */

/****************
 * Generate a key pair with a key of size NBITS.  
 * USE_E = 0 let Libcgrypt decide what exponent to use.
 *       = 1 request the use of a "secure" exponent; this is required by some 
 *           specification to be 65537.
 *       > 2 Try starting at this value until a working exponent is found.
 * Returns: 2 structures filled with all needed values
 */
static gcry_err_code_t
generate (key_secret_t *key_secret, key_public_t *key_public,
	  unsigned int nbits, void *spec_opaque, gcry_mpi_t **misc_data)
{
  gcry_ac_key_spec_rsa_t *spec = (gcry_ac_key_spec_rsa_t *) spec_opaque;
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned long use_e = 65537;
  gcry_mpi_t p, q; /* the two primes */
  gcry_mpi_t d;    /* the private key */
  gcry_mpi_t u;
  gcry_mpi_t t1, t2;
  gcry_mpi_t n;    /* the public key */
  gcry_mpi_t e;    /* the exponent */
  gcry_mpi_t phi;  /* helper: (p-1)(q-1) */
  gcry_mpi_t g;
  gcry_mpi_t f;

  /* Make sure that nbits is even so that we generate p, q of equal
     size.  */
  if (nbits & 1)
    nbits++; 

  if (spec)
    {
      switch (spec->e)
	{
	case 0:
	   /* This is a reasonable secure and fast value.  */
	  use_e = 41;
	  break;
	case 1:
	  /* Alias for a secure value.  This is the value demanded by
	     Sphinx.  */
	  use_e = 65537;
	  break;
	default:
	  use_e = spec->e;
	  if (! (use_e & 1))
	    /* Make sure this is odd.  */
	    use_e |= 1;
	  break;
	}
    }

  /* Public exponent:
     In general we use 41 as this is quite fast and more secure than the
     commonly used 17.  Benchmarking the RSA verify function
     with a 1024 bit key yields (2001-11-08): 
     e=17    0.54 ms
     e=41    0.75 ms
     e=257   0.95 ms
     e=65537 1.80 ms
  */
  e = mpi_alloc ((32 + BITS_PER_MPI_LIMB - 1) / BITS_PER_MPI_LIMB);
  mpi_set_ui (e, use_e);

  n = gcry_mpi_new (nbits);

  p = q = NULL;
  do {
    /* select two (very secret) primes */
    if (p)
      gcry_mpi_release (p);
    if (q)
      gcry_mpi_release (q);
    if (use_e)
      { /* Do an extra test to ensure that the given exponent is
	   suitable. */
	p = _gcry_generate_secret_prime (nbits/2, check_exponent, e);
	q = _gcry_generate_secret_prime (nbits/2, check_exponent, e);
      }
    else
      { /* We check the exponent later. */
	p = _gcry_generate_secret_prime (nbits/2, NULL, NULL);
	q = _gcry_generate_secret_prime (nbits/2, NULL, NULL);
      }
    if (mpi_cmp (p, q) > 0) /* p shall be smaller than q (for calc of u)*/
      mpi_swap (p,q);
    /* calculate the modulus */
    mpi_mul (n, p, q);
  } while (mpi_get_nbits (n) != nbits);

  /* Calculate Euler totient: phi = (p-1)(q-1).  */
  t1 = mpi_alloc_secure (mpi_get_nlimbs (p));
  t2 = mpi_alloc_secure (mpi_get_nlimbs (p));
  phi = gcry_mpi_snew (nbits);
  g = gcry_mpi_snew (nbits);
  f = gcry_mpi_snew (nbits);
  mpi_sub_ui (t1, p, 1);
  mpi_sub_ui (t2, q, 1);
  mpi_mul (phi, t1, t2);
  gcry_mpi_gcd (g, t1, t2);
  mpi_fdiv_q (f, phi, g);

  while (! gcry_mpi_gcd (t1, e, phi)) /* (while gcd is not 1) */
    {
      if (use_e)
	BUG (); /* The prime generator already made sure that we never
		   can get to here. */
      mpi_add_ui (e, e, 2);
    }

  /* Calculate the secret key d = e^1 mod phi.  */
  d = gcry_mpi_snew (nbits);
  mpi_invm (d, e, f);

  /* Calculate the inverse of p and q (used for chinese remainder
     theorem).  */
  u = gcry_mpi_snew (nbits);
  mpi_invm (u, p, q);

  if (DBG_CIPHER)
    {
      log_mpidump ("  p= ", p);
      log_mpidump ("  q= ", q);
      log_mpidump ("phi= ", phi);
      log_mpidump ("  g= ", g);
      log_mpidump ("  f= ", f);
      log_mpidump ("  n= ", n);
      log_mpidump ("  e= ", e);
      log_mpidump ("  d= ", d);
      log_mpidump ("  u= ", u);
    }

  gcry_mpi_release (t1);
  gcry_mpi_release (t2);
  gcry_mpi_release (phi);
  gcry_mpi_release (f);
  gcry_mpi_release (g);
  
  key_secret->n = n;
  key_secret->e = e;
  key_secret->p = p;
  key_secret->q = q;
  key_secret->d = d;
  key_secret->u = u;

  key_public->n = gcry_mpi_copy (n);
  key_public->e = gcry_mpi_copy (e);

  /* Now we can test our keys (this should never fail!).  */
  keys_test (key_secret, key_public, nbits - 64);

  return err;
}



/* Test wether the secret key is valid.  */
static gcry_err_code_t
key_secret_check (key_secret_t *key_secret)
{
  gcry_mpi_t temp = mpi_alloc (mpi_get_nlimbs (key_secret->p) * 2);
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  mpi_mul (temp, key_secret->p, key_secret->q);
  if (mpi_cmp (temp, key_secret->n))
    err = GPG_ERR_BAD_SECKEY;
  mpi_free (temp);

  return err;
}



static gcry_err_code_t
get_nbits (key_public_t *key_public, key_secret_t *key_secret,
	   unsigned int *key_nbits)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t mpi = NULL;

  if (key_public)
    mpi = key_public->n;
  else
    mpi = key_secret->n;
  *key_nbits = gcry_mpi_get_nbits (mpi);

  return err;
}



static gcry_err_code_t
get_grip (key_public_t *key_public, unsigned char *key_grip)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  err = _gcry_ac_key_get_grip_std (key_grip, 0, "n", key_public->n,
				   NULL);

  return err;
}



#define GCRY_AC_INTERFACE_ENCRYPTION
#define GCRY_AC_INTERFACE_SIGNING

#include "gcrypt-ac-glue.h"
