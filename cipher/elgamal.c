/* elgamal.c - ElGamal cryptography algorithm.
   Copyright (C) 1998, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.

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

/* For a description of the algorithm, see:
   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
   ISBN 0-471-11709-9. Pages 476 ff. */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"



#define GCRY_AC_ALGORITHM elg
#define GCRY_AC_ALIASES "ELG", "openpgp-elg", "openpgp-elg-sig"



typedef struct key_public
{
  gcry_mpi_t p;	    /* prime */
  gcry_mpi_t g;	    /* group generator */
  gcry_mpi_t y;	    /* g^x mod p */
} key_public_t;

typedef struct key_secret
{
  gcry_mpi_t p;	    /* prime */
  gcry_mpi_t g;	    /* group generator */
  gcry_mpi_t y;	    /* g^x mod p */
  gcry_mpi_t x;	    /* secret exponent */
} key_secret_t;

typedef struct data_encrypted
{
  gcry_mpi_t a;
  gcry_mpi_t b;
} data_encrypted_t;

typedef struct data_signed
{
  gcry_mpi_t r;
  gcry_mpi_t s;
} data_signed_t;



GCRY_AC_SPEC_KEY_PUBLIC =
  {
    GCRY_AC_ELEM_KEY_PUBLIC (p), GCRY_AC_ELEM_KEY_PUBLIC (g),
    GCRY_AC_ELEM_KEY_PUBLIC (y)
  };
GCRY_AC_SPEC_KEY_SECRET =
  {
    GCRY_AC_ELEM_KEY_SECRET (p), GCRY_AC_ELEM_KEY_SECRET (g),
    GCRY_AC_ELEM_KEY_SECRET (y), GCRY_AC_ELEM_KEY_SECRET (x)
  };
GCRY_AC_SPEC_DATA_ENCRYPTED =
  {
    GCRY_AC_ELEM_DATA_ENCRYPTED (a), GCRY_AC_ELEM_DATA_ENCRYPTED (b)
  };
GCRY_AC_SPEC_DATA_SIGNED =
  {
    GCRY_AC_ELEM_DATA_SIGNED (r), GCRY_AC_ELEM_DATA_SIGNED (s)
  };



#define progress(c) _gcry_ac_progress ("pk_elg", c)



/* Michael Wieners table on subgroup sizes to match field sizes
   (floating around somewhere - FIXME: need a reference).  */
static unsigned int
wiener_map (unsigned int n)
{
  static struct { unsigned int p_n, q_n; } t[] =
    {	/*   p	  q	 attack cost */
      {  512, 119 },	/* 9 x 10^17 */
      {  768, 145 },	/* 6 x 10^21 */
      { 1024, 165 },	/* 7 x 10^24 */
      { 1280, 183 },	/* 3 x 10^27 */
      { 1536, 198 },	/* 7 x 10^29 */
      { 1792, 212 },	/* 9 x 10^31 */
      { 2048, 225 },	/* 8 x 10^33 */
      { 2304, 237 },	/* 5 x 10^35 */
      { 2560, 249 },	/* 3 x 10^37 */
      { 2816, 259 },	/* 1 x 10^39 */
      { 3072, 269 },	/* 3 x 10^40 */
      { 3328, 279 },	/* 8 x 10^41 */
      { 3584, 288 },	/* 2 x 10^43 */
      { 3840, 296 },	/* 4 x 10^44 */
      { 4096, 305 },	/* 7 x 10^45 */
      { 4352, 313 },	/* 1 x 10^47 */
      { 4608, 320 },	/* 2 x 10^48 */
      { 4864, 328 },	/* 2 x 10^49 */
      { 5120, 335 },	/* 3 x 10^50 */
      { 0, 0 }
    };
  unsigned int i;

  for(i= 0; t[i].p_n; i++)
    if (n <= t[i].p_n)
      return t[i].q_n;

  /* Not in table - use some arbitrary high number ;-).  */
  return n / 8 + 200;
}

/* Generate a random secret exponent K from prime P, so that K is
   relatively prime to p - 1.  */
static gcry_mpi_t
gen_k (gcry_mpi_t p)
{
  gcry_mpi_t k = mpi_alloc_secure (0);
  gcry_mpi_t temp = mpi_alloc (mpi_get_nlimbs (p));
  gcry_mpi_t p_1 = mpi_copy (p);
  unsigned int orig_nbits = mpi_get_nbits (p);
  unsigned int nbits, nbytes;
  char *rndbuf = NULL;

  /* IMO using a k much lesser than p is sufficient and it greatly
   * improves the encryption performance.  We use Wiener's table and
   * add a large safety margin.
   */
  nbits = wiener_map (orig_nbits) * 3 / 2;
  if (nbits >= orig_nbits)
    BUG();

  nbytes = (nbits + 7) / 8;
  mpi_sub_ui (p_1, p, 1);
  for (;;)
    {
      if ((! rndbuf) || (nbits < 32))
	{
	  gcry_free (rndbuf);
	  rndbuf = gcry_random_bytes_secure (nbytes, GCRY_STRONG_RANDOM);
	}
      else
	{
	  /* Change only some of the higher bits.  We could improve
	     this by directly requesting more memory at the first call
	     to get_random_bytes() and use this here.  Maybe it is
	     easier to do this directly in random.c.  Anyway, it is
	     highly inlikely that we will ever reach this code.  */
	  char *pp = gcry_random_bytes_secure (4, GCRY_STRONG_RANDOM);
	  memcpy (rndbuf, pp, 4);
	  gcry_free (pp);
	  log_debug ("gen_k: tsss, never expected to reach this\n");
	}
      _gcry_mpi_set_buffer (k, rndbuf, nbytes, 0);

      for (;;)
	{
	  /* Hmm, actually we don't need this step here because we use
	     k much smaller than p - we do it anyway just in case the
	     keep on adding a one to k ;).  */
	  if (! (mpi_cmp (k, p_1) < 0))
	    {
	      /* Check: k < (p-1).  */
	      if (DBG_CIPHER)
		progress ('+');
	      break;
	    }

	  if (! (mpi_cmp_ui (k, 0) > 0))
	    {
	      /* Check: k > 0.  */
	      if (DBG_CIPHER)
		progress ('-');
	      break;
	    }
	  if (gcry_mpi_gcd (temp, k, p_1))
	    /* Okay, k is relatively prime to (p - 1).  */
	    goto found;
	  mpi_add_ui (k, k, 1);
	  if (DBG_CIPHER)
	    progress ('.');
	}
    }
  
 found:
  gcry_free (rndbuf);
  if (DBG_CIPHER)
    progress ('\n');

  mpi_free(p_1);
  mpi_free(temp);
  
  return k;
}



static void
do_encrypt (gcry_mpi_t a, gcry_mpi_t b, gcry_mpi_t input,
	    key_public_t *key_public)
{
  gcry_mpi_t k;

  /* Note: maybe we should change the interface, so that it
   * is possible to check that input is < p and return an
   * error code.
   */

  k = gen_k (key_public->p);
  gcry_mpi_powm (a, key_public->g, k, key_public->p);
  /* b = (y^k * input) mod p
   *	 = ((y^k mod p) * (input mod p)) mod p
   * and because input is < p
   *	 = ((y^k mod p) * input) mod p
   */
  gcry_mpi_powm (b, key_public->y, k, key_public->p);
  gcry_mpi_mulm (b, b, input, key_public->p);

  mpi_free (k);
}

static gcry_err_code_t
encrypt (gcry_mpi_t data,
	 key_public_t *key_public, data_encrypted_t *data_encrypted,
	 unsigned int flags)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  /* FIXME, is this check necessary?  */
  if (! (key_public->p && key_public->g && key_public->y))
    err = GPG_ERR_BAD_MPI;
  else
    {
      data_encrypted->a = mpi_alloc (mpi_get_nlimbs (key_public->p));
      data_encrypted->b = mpi_alloc (mpi_get_nlimbs (key_public->p));
      do_encrypt (data_encrypted->a, data_encrypted->b, data, key_public);
    }

  return err;
}



/****************
 * Returns true if the signature composed of A and B is valid.
 */
static gcry_err_code_t
do_verify (gcry_mpi_t input, gcry_mpi_t a, gcry_mpi_t b,
	   key_public_t *key_public)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t t1;
  gcry_mpi_t t2;
  gcry_mpi_t base[4];
  gcry_mpi_t exp[4];

  if (! (1
	 && (mpi_cmp_ui (a, 0) > 0)
	 && (mpi_cmp (a, key_public->p) < 0)))
    return 0;

  t1 = mpi_alloc (mpi_get_nlimbs (a));
  t2 = mpi_alloc (mpi_get_nlimbs (a));

#if 0

  /* t1 = (y^a mod p) * (a^b mod p) mod p */
  gcry_mpi_powm (t1, key_public->y, a, key_public->p);
  gcry_mpi_powm (t2, a, b, key_public->p);
  mpi_mulm (t1, t1, t2, key_public->p);

  /* t2 = g ^ input mod p */
  gcry_mpi_powm (t2, key_public->g, input, key_public->p);

  if (mpi_cmp (t1, t2))
    err = GPG_ERR_BAD_SIGNATURE;

#elif 0

  /* t1 = (y^a mod p) * (a^b mod p) mod p */
  base[0] = key_public->y;
  exp[0] = a;
  base[1] = a;
  exp[1] = b;
  base[2] = NULL;
  exp[2] = NULL;
  mpi_mulpowm (t1, base, exp, key_public->p);

  /* t2 = g ^ input mod p */
  gcry_mpi_powm (t2, key_public->g, input, key_public->p);

  if (mpi_cmp (t1, t2))
    err = GPG_ERR_BAD_SIGNATURE;

#else

  /* t1 = g ^ - input * y ^ a * a ^ b  mod p */
  mpi_invm (t2, key_public->g, key_public->p);
  base[0] = t2;
  exp[0] = input;
  base[1] = key_public->y;
  exp[1] = a;
  base[2] = a;
  exp[2] = b;
  base[3] = NULL;
  exp[3] = NULL;
  mpi_mulpowm (t1, base, exp, key_public->p);

  if (mpi_cmp_ui (t1, 1))
    err = GPG_ERR_BAD_SIGNATURE;

#endif

  mpi_free (t1);
  mpi_free (t2);

  return err;
}

static gcry_err_code_t
verify (gcry_mpi_t input,
	key_public_t *key_public, data_signed_t *data_signed)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  err = do_verify (input, data_signed->r, data_signed->s, key_public);

  return err;
}



static void
do_decrypt (gcry_mpi_t output, gcry_mpi_t a, gcry_mpi_t b,
	    key_secret_t *key_secret)
{
  gcry_mpi_t t1;

  t1 = mpi_alloc_secure (mpi_get_nlimbs (key_secret->p));

  /* output = b/(a^x) mod p */
  gcry_mpi_powm (t1, a, key_secret->x, key_secret->p);
  mpi_invm (t1, t1, key_secret->p);
  mpi_mulm (output, b, t1, key_secret->p);

  mpi_free (t1);
}

static gcry_err_code_t
decrypt (data_encrypted_t *data_encrypted, key_secret_t *key_secret,
	 gcry_mpi_t *data_decrypted, unsigned int flags)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  /* FIXME, is this check necessary?  */
  if (! (1
	 && data_encrypted->a && data_encrypted->b
	 && key_secret->p && key_secret->g
	 && key_secret->y && key_secret->x))
    err = GPG_ERR_BAD_MPI;
  else
    {
      *data_decrypted = mpi_alloc_secure (mpi_get_nlimbs (key_secret->p));
      do_decrypt (*data_decrypted, data_encrypted->a, data_encrypted->b,
		  key_secret);
    }

  return err;
}



static void
do_sign (gcry_mpi_t a, gcry_mpi_t b, gcry_mpi_t input,
	 key_secret_t *key_secret)
{
  gcry_mpi_t t = mpi_alloc (mpi_get_nlimbs (a));
  gcry_mpi_t inv = mpi_alloc (mpi_get_nlimbs (a));
  gcry_mpi_t p_1 = mpi_copy (key_secret->p);
  gcry_mpi_t k;

  /*
   * b = (t * inv) mod (p-1)
   * b = (t * inv(k,(p-1),(p-1)) mod (p-1)
   * b = (((M-x*a) mod (p-1)) * inv(k,(p-1),(p-1))) mod (p-1)
   *
   */
  mpi_sub_ui (p_1, p_1, 1);
  k = gen_k (key_secret->p);
  gcry_mpi_powm (a, key_secret->g, k, key_secret->p);
  mpi_mul (t, key_secret->x, a);
  mpi_subm (t, input, t, p_1);
  mpi_invm (inv, k, p_1);
  mpi_mulm (b, t, inv, p_1);

#if 0
  if (DBG_CIPHER)
    {
      log_mpidump("elg sign p= ", key_secret->p);
      log_mpidump("elg sign g= ", key_secret->g);
      log_mpidump("elg sign y= ", key_secret->y);
      log_mpidump("elg sign x= ", key_secret->x);
      log_mpidump("elg sign k= ", k);
      log_mpidump("elg sign M= ", input);
      log_mpidump("elg sign a= ", a);
      log_mpidump("elg sign b= ", b);
    }
#endif

  mpi_free(k);
  mpi_free(t);
  mpi_free(inv);
  mpi_free(p_1);
}

static gcry_err_code_t
sign (gcry_mpi_t input, key_secret_t *key_secret, data_signed_t *data_signed)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  /* FIXME, is this check necessary?  */
  if (! (input
	 && key_secret->p && key_secret->g
	 && key_secret->y && key_secret->x))
    err = GPG_ERR_BAD_MPI;
  else
    {
      data_signed->r = mpi_alloc (mpi_get_nlimbs (key_secret->p));
      data_signed->s = mpi_alloc (mpi_get_nlimbs (key_secret->p));
      do_sign (data_signed->r, data_signed->s, input, key_secret);
    }
  
  return err;
}



static void
keys_test (key_secret_t *key_secret, key_public_t *key_public,
	   unsigned int nbits)
{
  gcry_mpi_t test = gcry_mpi_new (0);
  gcry_mpi_t out1_a = gcry_mpi_new (nbits);
  gcry_mpi_t out1_b = gcry_mpi_new (nbits);
  gcry_mpi_t out2 = gcry_mpi_new (nbits);

  gcry_mpi_randomize (test, nbits, GCRY_WEAK_RANDOM);

  do_encrypt (out1_a, out1_b, test, key_public);
  do_decrypt (out2, out1_a, out1_b, key_secret);
  if (mpi_cmp (test, out2))
    log_fatal ("ElGamal operation: encrypt, decrypt failed\n");

  do_sign (out1_a, out1_b, test, key_secret);
  if (! do_verify (out1_a, out1_b, test, key_public))
    log_fatal ("ElGamal operation: sign, verify failed\n");

  gcry_mpi_release (test);
  gcry_mpi_release (out1_a);
  gcry_mpi_release (out1_b);
  gcry_mpi_release (out2);
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 *	    and an array with n-1 factors of (p-1)
 */
static gcry_err_code_t
generate (key_secret_t *key_secret, key_public_t *key_public,
	  unsigned int nbits, void *spec_opaque, gcry_mpi_t **ret_factors)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t p;    /* the prime */
  gcry_mpi_t p_min1;
  gcry_mpi_t g;
  gcry_mpi_t x;    /* the secret exponent */
  gcry_mpi_t y;
  gcry_mpi_t temp;
  unsigned int qbits;
  unsigned int xbits;
  byte *rndbuf;

  p_min1 = gcry_mpi_new (nbits);
  temp = gcry_mpi_new (nbits);
  qbits = wiener_map (nbits);
  if (qbits & 1)
     /* Better have a even one.  */
    qbits++;
  g = mpi_alloc (1);
  p = _gcry_generate_elg_prime (0, nbits, qbits, g, ret_factors);
  mpi_sub_ui (p_min1, p, 1);

  /* select a random number which has these properties:
   *	 0 < x < p-1
   * This must be a very good random number because this is the
   * secret part.  The prime is public and may be shared anyway,
   * so a random generator level of 1 is used for the prime.
   *
   * I don't see a reason to have a x of about the same size
   * as the p.  It should be sufficient to have one about the size
   * of q or the later used k plus a large safety margin. Decryption
   * will be much faster with such an x.
   */
  xbits = qbits * 3 / 2;
  if (xbits >= nbits)
    BUG();
  x = gcry_mpi_snew (xbits);
  if (DBG_CIPHER)
    log_debug ("choosing a random x of size %u", xbits);
  rndbuf = NULL;
  do
    {
      if (DBG_CIPHER)
	progress ('.');
      if (rndbuf)
	{
	  /* Change only some of the higher bits.  */
	  if (xbits < 16)
	    {
	      /* Should never happen.  */
	      gcry_free (rndbuf);
	      rndbuf = gcry_random_bytes_secure ((xbits + 7) / 8,
						 GCRY_VERY_STRONG_RANDOM);
	    }
	  else
	    {
	      char *r = gcry_random_bytes_secure (2,
						  GCRY_VERY_STRONG_RANDOM);
	      memcpy (rndbuf, r, 2);
	      gcry_free (r);
	    }
	}
      else
	{
	  rndbuf = gcry_random_bytes_secure ((xbits + 7) / 8,
					     GCRY_VERY_STRONG_RANDOM);
	}
      _gcry_mpi_set_buffer (x, rndbuf, (xbits + 7) / 8, 0);
      mpi_clear_highbit (x, xbits + 1);
    }
  while (! ((mpi_cmp_ui (x, 0) > 0) && (mpi_cmp (x, p_min1) < 0)));
  gcry_free (rndbuf);

  y = gcry_mpi_new (nbits);
  gcry_mpi_powm (y, g, x, p);
  
  if (DBG_CIPHER)
    {
      progress('\n');
      log_mpidump("elg  p= ", p );
      log_mpidump("elg  g= ", g );
      log_mpidump("elg  y= ", y );
      log_mpidump("elg  x= ", x );
    }

  /* Copy the stuff to the key structures.  */
  key_secret->p = p;
  key_secret->g = g;
  key_secret->y = y;
  key_secret->x = x;

  key_public->p = gcry_mpi_copy (p);
  key_public->g = gcry_mpi_copy (g);
  key_public->y = gcry_mpi_copy (y);

  /* Now we can test our keys (this should never fail!).  */
  keys_test (key_secret, key_public, nbits - 64);
  
  gcry_mpi_release (p_min1);
  gcry_mpi_release (temp);

  return err;
}



/* Test whether the secret key is valid.  */
static gcry_err_code_t
key_secret_check (key_secret_t *key_secret)
{
  gcry_mpi_t y = mpi_alloc (mpi_get_nlimbs(key_secret->y));
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  gcry_mpi_powm (y, key_secret->g, key_secret->x, key_secret->p);
  if (mpi_cmp (y, key_secret->y))
    err = GPG_ERR_BAD_SECKEY;
  mpi_free (y);
  
  return err;
}



static gcry_err_code_t
get_nbits (key_public_t *key_public, key_secret_t *key_secret,
	   unsigned int *key_nbits)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t mpi = NULL;

  if (key_public)
    mpi = key_public->p;
  else
    mpi = key_secret->p;
  *key_nbits = gcry_mpi_get_nbits (mpi);

  return err;
}



static gcry_err_code_t
get_grip (key_public_t *key_public, unsigned char *key_grip)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  err = _gcry_ac_key_get_grip_std (key_grip, GCRY_AC_KEY_GRIP_FLAG_SEXP,
				   "p", key_public->p,
				   "g", key_public->g,
				   "y", key_public->y,
				   NULL);
  
  return err;
}



#define GCRY_AC_INTERFACE_ENCRYPTION
#define GCRY_AC_INTERFACE_SIGNING

#include "gcrypt-ac-glue.h"
