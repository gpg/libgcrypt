/* dsa.c  -  DSA signature scheme
 * Copyright (C) 1998, 2000, 2001, 2002, 2003, 2005 Free Software Foundation, Inc.
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
 */

#include <gcrypt-ac-internal.h>

#include <gcrypt-mpi-internal.h>
#include <gcrypt-random-internal.h>
#include <gcrypt-prime-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sha1.h>

#include "dsa.h"

typedef struct
{
  gcry_core_mpi_t p;			/* prime */
  gcry_core_mpi_t q;			/* group order */
  gcry_core_mpi_t g;			/* group generator */
  gcry_core_mpi_t y;			/* g^x mod p */
} DSA_public_key;


typedef struct
{
  gcry_core_mpi_t p;			/* prime */
  gcry_core_mpi_t q;			/* group order */
  gcry_core_mpi_t g;			/* group generator */
  gcry_core_mpi_t y;			/* g^x mod p */
  gcry_core_mpi_t x;			/* secret exponent */
} DSA_secret_key;


static gcry_core_mpi_t gen_k (gcry_core_context_t ctx, gcry_core_mpi_t q);
static void test_keys (gcry_core_context_t ctx, DSA_secret_key * sk,
		       unsigned qbits);
static int check_secret_key (gcry_core_context_t ctx, DSA_secret_key * sk);
static void generate (gcry_core_context_t ctx,
		      DSA_secret_key * sk, unsigned nbits,
		      gcry_core_mpi_t ** ret_factors);
static void sign (gcry_core_context_t ctx,
		  gcry_core_mpi_t r, gcry_core_mpi_t s, gcry_core_mpi_t input,
		  DSA_secret_key * skey);
static int verify (gcry_core_context_t ctx,
		   gcry_core_mpi_t r, gcry_core_mpi_t s, gcry_core_mpi_t input,
		   DSA_public_key * pkey);

#define progress(ctx, c) _gcry_core_progress (ctx, "pk_dsa", c, 0, 0)

/*
 * Generate a random secret exponent k less than q.
 */
static gcry_core_mpi_t
gen_k (gcry_core_context_t ctx, gcry_core_mpi_t q)
{
  gcry_core_mpi_t k = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, q));
  unsigned int nbits = gcry_core_mpi_get_nbits (ctx, q);
  unsigned int nbytes = (nbits + 7) / 8;
  char *rndbuf = NULL;

  if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
    log_debug (ctx, "choosing a random k ");
  for (;;)
    {
      if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
	progress (ctx, '.');

      if (!rndbuf || nbits < 32)
	{
	  gcry_core_free (ctx, rndbuf);
	  rndbuf = gcry_core_random_bytes_secure (ctx, (nbits + 7) / 8,
						  GCRY_STRONG_RANDOM);
	}
      else
	{			/* Change only some of the higher bits.  We could improve
				   this by directly requesting more memory at the first call
				   to get_random_bytes() and use this the here maybe it is
				   easier to do this directly in random.c. */
	  char *pp = gcry_core_random_bytes_secure (ctx, 4, GCRY_STRONG_RANDOM);
	  memcpy (rndbuf, pp, 4);
	  gcry_core_free (ctx, pp);
	}
      gcry_core_mpi_set_buffer (ctx, k, rndbuf, nbytes, 0);
      if (gcry_core_mpi_test_bit (ctx, k, nbits - 1))
	gcry_core_mpi_set_highbit (ctx, k, nbits - 1);
      else
	{
	  gcry_core_mpi_set_highbit (ctx, k, nbits - 1);
	  gcry_core_mpi_clear_bit (ctx, k, nbits - 1);
	}

      if (!(gcry_core_mpi_cmp (ctx, k, q) < 0))	/* check: k < q */
	{
	  if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
	    progress (ctx, '+');
	  continue;		/* no  */
	}
      if (!(gcry_core_mpi_cmp_ui (ctx, k, 0) > 0))	/* check: k > 0 */
	{
	  if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
	    progress (ctx, '-');
	  continue;		/* no */
	}
      break;			/* okay */
    }
  gcry_core_free (ctx, rndbuf);
  if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
    progress (ctx, '\n');

  return k;
}


static void
test_keys (gcry_core_context_t ctx, DSA_secret_key * sk, unsigned qbits)
{
  DSA_public_key pk;
  gcry_core_mpi_t test = gcry_core_mpi_new (ctx, qbits);
  gcry_core_mpi_t out1_a = gcry_core_mpi_new (ctx, qbits);
  gcry_core_mpi_t out1_b = gcry_core_mpi_new (ctx, qbits);

  pk.p = sk->p;
  pk.q = sk->q;
  pk.g = sk->g;
  pk.y = sk->y;
  gcry_core_mpi_randomize (ctx, test, qbits, GCRY_WEAK_RANDOM);

  sign (ctx, out1_a, out1_b, test, sk);
  if (!verify (ctx, out1_a, out1_b, test, &pk))
    log_fatal (ctx, "DSA:: sign, verify failed\n");

  gcry_core_mpi_release (ctx, test);
  gcry_core_mpi_release (ctx, out1_a);
  gcry_core_mpi_release (ctx, out1_b);
}



/*
   Generate a DSA key pair with a key of size NBITS.
   Returns: 2 structures filled with all needed values
 	    and an array with the n-1 factors of (p-1)
 */
static void
generate (gcry_core_context_t ctx,
	  DSA_secret_key * sk, unsigned nbits, gcry_core_mpi_t ** ret_factors)
{
  gcry_core_mpi_t p;			/* the prime */
  gcry_core_mpi_t q;			/* the 160 bit prime factor */
  gcry_core_mpi_t g;			/* the generator */
  gcry_core_mpi_t y;			/* g^x mod p */
  gcry_core_mpi_t x;			/* the secret exponent */
  gcry_core_mpi_t h, e;		/* helper */
  unsigned qbits;
  byte *rndbuf;

  assert (nbits >= 512 && nbits <= 1024);

  qbits = 160;
  p = gcry_core_prime_generate_elg (ctx, 1, nbits, qbits, NULL, ret_factors);
  /* get q out of factors */
  q = gcry_core_mpi_copy (ctx, (*ret_factors)[0]);
  if (gcry_core_mpi_get_nbits (ctx, q) != qbits)
    BUG (ctx);

  /* Find a generator g (h and e are helpers).
     e = (p-1)/q */
  e = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, p));
  gcry_core_mpi_sub_ui (ctx, e, p, 1);
  gcry_core_mpi_fdiv_q (ctx, e, e, q);
  g = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, p));
  h = gcry_core_mpi_alloc_set_ui (ctx, 1);	/* we start with 2 */
  do
    {
      gcry_core_mpi_add_ui (ctx, h, h, 1);
      /* g = h^e mod p */
      gcry_core_mpi_powm (ctx, g, h, e, p);
    }
  while (!gcry_core_mpi_cmp_ui (ctx, g, 1));	/* continue until g != 1 */

  /* Select a random number which has these properties:
   *     0 < x < q-1
   * This must be a very good random number because this
   * is the secret part. */
  if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
    log_debug (ctx, "choosing a random x ");
  assert (qbits >= 160);
  x = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, q));
  gcry_core_mpi_sub_ui (ctx, h, q, 1);		/* put q-1 into h */
  rndbuf = NULL;
  do
    {
      if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
	progress (ctx, '.');
      if (!rndbuf)
	rndbuf = gcry_core_random_bytes_secure (ctx,
						(qbits + 7) / 8,
						GCRY_VERY_STRONG_RANDOM);
      else
	{			/* Change only some of the higher bits (= 2 bytes) */
	  char *r = gcry_core_random_bytes_secure (ctx,
						   2, GCRY_VERY_STRONG_RANDOM);
	  memcpy (rndbuf, r, 2);
	  gcry_core_free (ctx, r);
	}

      gcry_core_mpi_set_buffer (ctx, x, rndbuf, (qbits + 7) / 8, 0);
      gcry_core_mpi_clear_highbit (ctx, x, qbits + 1);
    }
  while (!((gcry_core_mpi_cmp_ui (ctx, x, 0) > 0)
	   && (gcry_core_mpi_cmp (ctx, x, h) < 0)));
  gcry_core_free (ctx, rndbuf);
  gcry_core_mpi_release (ctx, e);
  gcry_core_mpi_release (ctx, h);

  /* y = g^x mod p */
  y = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, p));
  gcry_core_mpi_powm (ctx, y, g, x, p);

  if (GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
    {
      progress (ctx, '\n');
      _gcry_log_mpidump (ctx, "dsa  p= ", p);
      _gcry_log_mpidump (ctx, "dsa  q= ", q);
      _gcry_log_mpidump (ctx, "dsa  g= ", g);
      _gcry_log_mpidump (ctx, "dsa  y= ", y);
      _gcry_log_mpidump (ctx, "dsa  x= ", x);
    }

  /* Copy the stuff to the key structures. */
  sk->p = p;
  sk->q = q;
  sk->g = g;
  sk->y = y;
  sk->x = x;

  /* Now we can test our keys (this should never fail!). */
  test_keys (ctx, sk, qbits);
}



/*
   Test whether the secret key is valid.
   Returns: if this is a valid key.
 */
static int
check_secret_key (gcry_core_context_t ctx, DSA_secret_key * sk)
{
  int rc;
  gcry_core_mpi_t y = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, sk->y));

  gcry_core_mpi_powm (ctx, y, sk->g, sk->x, sk->p);
  rc = ! gcry_core_mpi_cmp (ctx, y, sk->y);
  gcry_core_mpi_release (ctx, y);

  return rc;
}



/*
   Make a DSA signature from HASH and put it into r and s.
 */
static void
sign (gcry_core_context_t ctx,
      gcry_core_mpi_t r, gcry_core_mpi_t s, gcry_core_mpi_t hash, DSA_secret_key * skey)
{
  gcry_core_mpi_t k;
  gcry_core_mpi_t kinv;
  gcry_core_mpi_t tmp;

  /* Select a random k with 0 < k < q */
  k = gen_k (ctx, skey->q);

  /* r = (a^k mod p) mod q */
  gcry_core_mpi_powm (ctx, r, skey->g, k, skey->p);
  gcry_core_mpi_fdiv_r (ctx, r, r, skey->q);

  /* kinv = k^(-1) mod q */
  kinv = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, k));
  gcry_core_mpi_invm (ctx, kinv, k, skey->q);

  /* s = (kinv * ( hash + x * r)) mod q */
  tmp = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, skey->p));
  gcry_core_mpi_mul (ctx, tmp, skey->x, r);
  gcry_core_mpi_add (ctx, tmp, tmp, hash);
  gcry_core_mpi_mulm (ctx, s, kinv, tmp, skey->q);

  gcry_core_mpi_release (ctx, k);
  gcry_core_mpi_release (ctx, kinv);
  gcry_core_mpi_release (ctx, tmp);
}


/*
   Returns true if the signature composed from R and S is valid.
 */
static int
verify (gcry_core_context_t ctx,
	gcry_core_mpi_t r, gcry_core_mpi_t s, gcry_core_mpi_t hash, DSA_public_key * pkey)
{
  int rc;
  gcry_core_mpi_t w, u1, u2, v;
  gcry_core_mpi_t base[3];
  gcry_core_mpi_t ex[3];

  if (!(gcry_core_mpi_cmp_ui (ctx, r, 0) > 0
	&& gcry_core_mpi_cmp (ctx, r, pkey->q) < 0))
    return 0;			/* assertion      0 < r < q  failed */
  if (!(gcry_core_mpi_cmp_ui (ctx, s, 0) > 0
	&& gcry_core_mpi_cmp (ctx, s, pkey->q) < 0))
    return 0;			/* assertion      0 < s < q  failed */

  w = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, pkey->q));
  u1 = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, pkey->q));
  u2 = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, pkey->q));
  v = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, pkey->p));

  /* w = s^(-1) mod q */
  gcry_core_mpi_invm (ctx, w, s, pkey->q);

  /* u1 = (hash * w) mod q */
  gcry_core_mpi_mulm (ctx, u1, hash, w, pkey->q);

  /* u2 = r * w mod q  */
  gcry_core_mpi_mulm (ctx, u2, r, w, pkey->q);

  /* v =  g^u1 * y^u2 mod p mod q */
  base[0] = pkey->g;
  ex[0] = u1;
  base[1] = pkey->y;
  ex[1] = u2;
  base[2] = NULL;
  ex[2] = NULL;
  gcry_core_mpi_mulpowm (ctx, v, base, ex, pkey->p);
  gcry_core_mpi_fdiv_r (ctx, v, v, pkey->q);

  rc = !gcry_core_mpi_cmp (ctx, v, r);

  gcry_core_mpi_release (ctx, w);
  gcry_core_mpi_release (ctx, u1);
  gcry_core_mpi_release (ctx, u2);
  gcry_core_mpi_release (ctx, v);

  return rc;
}


/*********************************************
 **************  interface  ******************
 *********************************************/

gcry_err_code_t
_gcry_dsa_generate (gcry_core_context_t ctx,
		    unsigned int flags,
		    unsigned nbits, void *spec,
		    gcry_core_mpi_t *skey, gcry_core_mpi_t **retfactors)
{
  DSA_secret_key sk;

  generate (ctx, &sk, nbits, retfactors);
  skey[0] = sk.p;
  skey[1] = sk.q;
  skey[2] = sk.g;
  skey[3] = sk.y;
  skey[4] = sk.x;

  return GPG_ERR_NO_ERROR;
}


gcry_err_code_t
_gcry_dsa_check_secret_key (gcry_core_context_t ctx,
		    unsigned int flags,
			    gcry_core_mpi_t *skey)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  DSA_secret_key sk;

  if ((!skey[0]) || (!skey[1]) || (!skey[2]) || (!skey[3]) || (!skey[4]))
    err = GPG_ERR_BAD_MPI;
  else
    {
      sk.p = skey[0];
      sk.q = skey[1];
      sk.g = skey[2];
      sk.y = skey[3];
      sk.x = skey[4];
      if (!check_secret_key (ctx, &sk))
	err = GPG_ERR_BAD_SECKEY;
    }

  return err;
}


gcry_err_code_t
_gcry_dsa_sign (gcry_core_context_t ctx,
		    unsigned int flags,
		gcry_core_mpi_t *resarr, gcry_core_mpi_t data,
		gcry_core_mpi_t *skey)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  DSA_secret_key sk;

  if ((!data)
      || (!skey[0]) || (!skey[1]) || (!skey[2]) || (!skey[3]) || (!skey[4]))
    err = GPG_ERR_BAD_MPI;
  else
    {
      sk.p = skey[0];
      sk.q = skey[1];
      sk.g = skey[2];
      sk.y = skey[3];
      sk.x = skey[4];
      resarr[0] = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, sk.p));
      resarr[1] = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, sk.p));
      sign (ctx, resarr[0], resarr[1], data, &sk);
    }
  return err;
}

gcry_err_code_t
_gcry_dsa_verify (gcry_core_context_t ctx,
		    unsigned int flags,
		  gcry_core_mpi_t hash, gcry_core_mpi_t *data,
		  gcry_core_mpi_t *pkey, int (*cmp) (void *, gcry_core_mpi_t),
		  void *opaquev)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  DSA_public_key pk;

  if ((!data[0]) || (!data[1]) || (!hash)
      || (!pkey[0]) || (!pkey[1]) || (!pkey[2]) || (!pkey[3]))
    err = GPG_ERR_BAD_MPI;
  else
    {
      pk.p = pkey[0];
      pk.q = pkey[1];
      pk.g = pkey[2];
      pk.y = pkey[3];
      if (!verify (ctx, data[0], data[1], hash, &pk))
	err = GPG_ERR_BAD_SIGNATURE;
    }
  return err;
}


unsigned int
_gcry_dsa_get_nbits (gcry_core_context_t ctx,
		    unsigned int flags,
		     gcry_core_mpi_t * pkey)
{
  return gcry_core_mpi_get_nbits (ctx, pkey[0]);
}

gcry_error_t
_gcry_dsa_keygrip (gcry_core_context_t ctx,
		    unsigned int flags,
		   gcry_core_mpi_t *pkey,
		   unsigned char *grip)
{
  gcry_core_md_spec_t algorithm;
  const char *elements;
  gcry_core_md_hd_t md;
  unsigned char *buffer;
  size_t buffer_n;
  unsigned char *hash;
  gcry_error_t err;
  unsigned int i;
  char buf[30];

  algorithm = gcry_core_digest_sha1;
  elements = gcry_core_ac_dsa->elements_grip;
  assert (elements);

  buffer = NULL;
  buffer_n = 0;
  md = NULL;
  
  err = gcry_core_md_open (ctx, &md, algorithm, 0);
  if (err)
    goto out;

  for (i = 0; elements[i]; i++)
    {
      err = gcry_core_mpi_aprint (ctx, GCRYMPI_FMT_STD,
				  &buffer, &buffer_n, pkey[i]);
      if (err)
	break;

      sprintf (buf, "(1:%c%u:", elements[i], (unsigned int) buffer_n);
      gcry_core_md_write (ctx, md, buf, strlen (buf));
      gcry_core_md_write (ctx, md, buffer, buffer_n);
      gcry_core_md_write (ctx, md, ")", 1);

      gcry_core_free (ctx, buffer);
      buffer = NULL;
      buffer_n = 0;
    }
  if (err)
    goto out;

  hash = gcry_core_md_read (ctx, md, NULL);
  assert (hash);		/* FIXME?  */

  memcpy (grip, hash, 20);	/* FIXME, constant.  */

 out:

  gcry_core_md_close (ctx, md);
  gcry_core_free (ctx, buffer);

  return err;
}



static char *dsa_names[] = {
  "dsa",
  "openpgp-dsa",
  NULL,
};

static struct gcry_core_ac_spec gcry_core_ac_dsa_struct = {
  "DSA", dsa_names,
  "pqgy", "pqgyx", "", "rs", "pqgy",
  GCRY_AC_KEY_USAGE_SIGN, 20,
  _gcry_dsa_generate,
  _gcry_dsa_check_secret_key,
  NULL,
  NULL,
  _gcry_dsa_sign,
  _gcry_dsa_verify,
  _gcry_dsa_get_nbits,
  _gcry_dsa_keygrip
};

gcry_core_ac_spec_t gcry_core_ac_dsa = &gcry_core_ac_dsa_struct;
