/* dsa.c - DSA cryptography algorithm.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"



#define GCRY_AC_ALGORITHM dsa
#define GCRY_AC_ALIASES "DSA", "openpgp-dsa"



typedef struct key_public
{
  gcry_mpi_t p;			/* prime */
  gcry_mpi_t q;			/* group order */
  gcry_mpi_t g;			/* group generator */
  gcry_mpi_t y;			/* g^x mod p */
} key_public_t;

typedef struct key_secret
{
  gcry_mpi_t p;			/* prime */
  gcry_mpi_t q;			/* group order */
  gcry_mpi_t g;			/* group generator */
  gcry_mpi_t y;			/* g^x mod p */
  gcry_mpi_t x;			/* secret exponent */
} key_secret_t;

typedef struct data_signed
{
  gcry_mpi_t r;
  gcry_mpi_t s;
} data_signed_t;



GCRY_AC_SPEC_KEY_PUBLIC =
  {
    GCRY_AC_ELEM_KEY_PUBLIC (p), GCRY_AC_ELEM_KEY_PUBLIC (q),
    GCRY_AC_ELEM_KEY_PUBLIC (g), GCRY_AC_ELEM_KEY_PUBLIC (y)
  };
GCRY_AC_SPEC_KEY_SECRET =
  {
    GCRY_AC_ELEM_KEY_SECRET (p), GCRY_AC_ELEM_KEY_SECRET (q),
    GCRY_AC_ELEM_KEY_SECRET (g), GCRY_AC_ELEM_KEY_SECRET (y),
    GCRY_AC_ELEM_KEY_SECRET (x)
  };
GCRY_AC_SPEC_DATA_SIGNED =
  {
    GCRY_AC_ELEM_DATA_SIGNED (r), GCRY_AC_ELEM_DATA_SIGNED (s)
  };



#define progress(c) _gcry_ac_progress ("pk_dsa", c)



/****************
 * Generate a random secret exponent k less than q
 */
static gcry_mpi_t
gen_k (gcry_mpi_t q)
{
  gcry_mpi_t k = mpi_alloc_secure (mpi_get_nlimbs (q));
  unsigned int nbits = mpi_get_nbits (q);
  unsigned int nbytes = (nbits + 7) / 8;
  char *rndbuf = NULL;

  if (DBG_CIPHER)
    log_debug ("choosing a random k ");
  for (;;)
    {
      if (DBG_CIPHER)
	progress ('.');

      if (!rndbuf || nbits < 32)
	{
	  gcry_free (rndbuf);
	  rndbuf = gcry_random_bytes_secure ((nbits + 7) / 8,
					     GCRY_STRONG_RANDOM);
	}
      else
	{
	  /* change only some of the higher bits */
	  /* we could imporove this by directly requesting more memory
	   * at the first call to get_random_bytes() and use this the here
	   * maybe it is easier to do this directly in random.c */
	  char *pp = gcry_random_bytes_secure (4, GCRY_STRONG_RANDOM);
	  memcpy (rndbuf, pp, 4);
	  gcry_free (pp);
	}
      _gcry_mpi_set_buffer (k, rndbuf, nbytes, 0);
      if (mpi_test_bit (k, nbits - 1))
	mpi_set_highbit (k, nbits - 1);
      else
	{
	  mpi_set_highbit (k, nbits - 1);
	  mpi_clear_bit (k, nbits - 1);
	}

      if (!(mpi_cmp (k, q) < 0))
	{			/* check: k < q */
	  if (DBG_CIPHER)
	    progress ('+');
	  continue;		/* no  */
	}
      if (!(mpi_cmp_ui (k, 0) > 0))
	{			/* check: k > 0 */
	  if (DBG_CIPHER)
	    progress ('-');
	  continue;		/* no */
	}
      break;			/* okay */
    }
  gcry_free (rndbuf);
  if (DBG_CIPHER)
    progress ('\n');

  return k;
}



/****************
 * Returns true if the signature composed from R and S is valid.
 */
static gcry_err_code_t
do_verify (gcry_mpi_t r, gcry_mpi_t s, gcry_mpi_t data,
	   key_public_t *key_public)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t w, u1, u2, v;
  gcry_mpi_t base[3];
  gcry_mpi_t exp[3];

  if (! (0
	 || ((mpi_cmp_ui (r, 0) > 0) && (mpi_cmp (r, key_public->q) < 0))
	 || ((mpi_cmp_ui (s, 0) > 0) && (mpi_cmp (s, key_public->q) < 0))))
    err = GPG_ERR_BAD_SIGNATURE;
  else
    {
      w = mpi_alloc (mpi_get_nlimbs (key_public->q));
      u1 = mpi_alloc (mpi_get_nlimbs (key_public->q));
      u2 = mpi_alloc (mpi_get_nlimbs (key_public->q));
      v = mpi_alloc (mpi_get_nlimbs (key_public->p));

      /* w = s^(-1) mod q */
      mpi_invm (w, s, key_public->q);

      /* u1 = (data * w) mod q */
      mpi_mulm (u1, data, w, key_public->q);
      
      /* u2 = r * w mod q  */
      mpi_mulm (u2, r, w, key_public->q);
      
      /* v =  g^u1 * y^u2 mod p mod q */
      base[0] = key_public->g;
      exp[0] = u1;
      base[1] = key_public->y;
      exp[1] = u2;
      base[2] = NULL;
      exp[2] = NULL;
      mpi_mulpowm (v, base, exp, key_public->p);
      mpi_fdiv_r (v, v, key_public->q);
      
      if (mpi_cmp (v, r))
	err = GPG_ERR_BAD_SIGNATURE;
      
      mpi_free (w);
      mpi_free (u1);
      mpi_free (u2);
      mpi_free (v);
    }
  
  return err;
}

static gcry_err_code_t
verify (gcry_mpi_t input,
	key_public_t *key_public, data_signed_t *data_signed)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  err = do_verify (data_signed->r, data_signed->s, input, key_public);

  return err;
}



/****************
 * Make a DSA signature from HASH and put it into r and s.
 */
static void
do_sign (gcry_mpi_t r, gcry_mpi_t s, gcry_mpi_t data,
	 key_secret_t *key_secret)
{
  gcry_mpi_t kinv;
  gcry_mpi_t tmp;
  gcry_mpi_t k;

  /* select a random k with 0 < k < q */
  k = gen_k (key_secret->q);

  /* r = (a^k mod p) mod q */
  gcry_mpi_powm (r, key_secret->g, k, key_secret->p);
  mpi_fdiv_r (r, r, key_secret->q);

  /* kinv = k^(-1) mod q */
  kinv = mpi_alloc (mpi_get_nlimbs (k));
  mpi_invm (kinv, k, key_secret->q);

  /* s = (kinv * ( data + x * r)) mod q */
  tmp = mpi_alloc (mpi_get_nlimbs (key_secret->p));
  mpi_mul (tmp, key_secret->x, r);
  mpi_add (tmp, tmp, data);
  mpi_mulm (s, kinv, tmp, key_secret->q);

  mpi_free (k);
  mpi_free (kinv);
  mpi_free (tmp);
}

static gcry_err_code_t
sign (gcry_mpi_t input, key_secret_t *key_secret, data_signed_t *data_signed)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  if (! (input
	 && key_secret->p && key_secret->q
	 && key_secret->g && key_secret->y
	 && key_secret->x))
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
	   unsigned int qbits)
{
  gcry_mpi_t test = gcry_mpi_new (qbits);
  gcry_mpi_t out1_a = gcry_mpi_new (qbits);
  gcry_mpi_t out1_b = gcry_mpi_new (qbits);

  gcry_mpi_randomize (test, qbits, GCRY_WEAK_RANDOM);

  do_sign (out1_a, out1_b, test, key_secret);
  if (! do_verify (out1_a, out1_b, test, key_public))
    log_fatal ("DSA:: sign, verify failed\n");

  gcry_mpi_release (test);
  gcry_mpi_release (out1_a);
  gcry_mpi_release (out1_b);
}

/****************
 * Generate a DSA key pair with a key of size NBITS
 * Returns: 2 structures filled with all needed values
 *	    and an array with the n-1 factors of (p-1)
 */
static gcry_err_code_t
generate (key_secret_t *key_secret, key_public_t *key_public,
	  unsigned int nbits, void *spec_opaque, gcry_mpi_t **ret_factors)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t p;			/* the prime */
  gcry_mpi_t q;			/* the 160 bit prime factor */
  gcry_mpi_t g;			/* the generator */
  gcry_mpi_t y;			/* g^x mod p */
  gcry_mpi_t x;			/* the secret exponent */
  gcry_mpi_t h, e;		/* helper */
  unsigned int qbits;
  byte *rndbuf;

  assert (nbits >= 512 && nbits <= 1024);

  qbits = 160;
  p = _gcry_generate_elg_prime (1, nbits, qbits, NULL, ret_factors);
  /* get q out of factors */
  q = mpi_copy ((*ret_factors)[0]);
  if (mpi_get_nbits (q) != qbits)
    BUG();
  
  /* find a generator g (h and e are helpers) */
  /* e = (p-1)/q */
  e = mpi_alloc (mpi_get_nlimbs (p));
  mpi_sub_ui (e, p, 1);
  mpi_fdiv_q (e, e, q);
  g = mpi_alloc (mpi_get_nlimbs (p));
  h = mpi_alloc_set_ui (1);	/* we start with 2 */
  do
    {
      mpi_add_ui (h, h, 1);
      /* g = h^e mod p */
      gcry_mpi_powm (g, h, e, p);
    }
  while (!mpi_cmp_ui (g, 1));	/* continue until g != 1 */

  /* select a random number which has these properties:
   *     0 < x < q-1
   * This must be a very good random number because this
   * is the secret part. */
  if (DBG_CIPHER)
    log_debug ("choosing a random x ");
  assert (qbits >= 160);
  x = mpi_alloc_secure (mpi_get_nlimbs (q));
  mpi_sub_ui (h, q, 1);		/* put q-1 into h */
  rndbuf = NULL;
  do
    {
      if (DBG_CIPHER)
	progress ('.');
      if (!rndbuf)
	rndbuf = gcry_random_bytes_secure ((qbits + 7) / 8,
					   GCRY_VERY_STRONG_RANDOM);
      else
	{			/* change only some of the higher bits (= 2 bytes) */
	  char *r = gcry_random_bytes_secure (2,
					      GCRY_VERY_STRONG_RANDOM);
	  memcpy (rndbuf, r, 2);
	  gcry_free (r);
	}
      _gcry_mpi_set_buffer (x, rndbuf, (qbits + 7) / 8, 0);
      mpi_clear_highbit (x, qbits + 1);
    }
  while (!(mpi_cmp_ui (x, 0) > 0 && mpi_cmp (x, h) < 0));
  gcry_free (rndbuf);
  mpi_free (e);
  mpi_free (h);

  /* y = g^x mod p */
  y = mpi_alloc (mpi_get_nlimbs (p));
  gcry_mpi_powm (y, g, x, p);

  if (DBG_CIPHER)
    {
      progress ('\n');
      log_mpidump ("dsa  p= ", p);
      log_mpidump ("dsa  q= ", q);
      log_mpidump ("dsa  g= ", g);
      log_mpidump ("dsa  y= ", y);
      log_mpidump ("dsa  x= ", x);
    }

  /* copy the stuff to the key structures */
  key_secret->p = p;
  key_secret->q = q;
  key_secret->g = g;
  key_secret->y = y;
  key_secret->x = x;

  key_public->p = gcry_mpi_copy (p);
  key_public->q = gcry_mpi_copy (q);
  key_public->g = gcry_mpi_copy (g);
  key_public->y = gcry_mpi_copy (y);

  /* Now we can test our keys (this should never fail!).  */
  keys_test (key_secret, key_public, qbits);

  return err;
}



/****************
 * Test whether the secret key is valid.
 * Returns: if this is a valid key.
 */
static gcry_err_code_t
key_secret_check (key_secret_t *key_secret)
{
  gcry_mpi_t y = mpi_alloc (mpi_get_nlimbs (key_secret->y));
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
				   "q", key_public->q,
				   "g", key_public->g,
				   "y", key_public->y,
				   NULL);

  return err;
}



#define GCRY_AC_INTERFACE_SIGNING

#include "gcrypt-ac-glue.h"
