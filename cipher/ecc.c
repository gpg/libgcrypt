/* ecc.c  -  Elliptic Curve Cryptography
 * Copyright (C) 2007, 2008, 2010, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* This code is originally based on the Patch 0.1.6 for the gnupg
   1.4.x branch as retrieved on 2007-03-21 from
   http://www.calcurco.cat/eccGnuPG/src/gnupg-1.4.6-ecc0.2.0beta1.diff.bz2
   The original authors are:
     Written by
      Sergi Blanch i Torne <d4372211 at alumnes.eup.udl.es>,
      Ramiro Moreno Chiral <ramiro at eup.udl.es>
     Maintainers
      Sergi Blanch i Torne
      Ramiro Moreno Chiral
      Mikael Mylnikov (mmr)
  For use in Libgcrypt the code has been heavily modified and cleaned
  up. In fact there is not much left of the orginally code except for
  some variable names and the text book implementaion of the sign and
  verification algorithms.  The arithmetic functions have entirely
  been rewritten and moved to mpi/ec.c.

  ECDH encrypt and decrypt code written by Andrey Jivsov,
*/


/* TODO:

  - If we support point compression we need to uncompress before
    computing the keygrip

  - In mpi/ec.c we use mpi_powm for x^2 mod p: Either implement a
    special case in mpi_powm or check whether mpi_mulm is faster.

*/


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "context.h"
#include "ec-context.h"
#include "pubkey-internal.h"
#include "ecc-common.h"


/* Registered progress function and its callback value. */
static void (*progress_cb) (void *, const char*, int, int, int);
static void *progress_cb_data;


#define point_init(a)  _gcry_mpi_point_init ((a))
#define point_free(a)  _gcry_mpi_point_free_parts ((a))


/* Local prototypes. */
static void test_keys (ECC_secret_key * sk, unsigned int nbits);
static int check_secret_key (ECC_secret_key * sk);
static gpg_err_code_t sign (gcry_mpi_t input, ECC_secret_key *skey,
                            gcry_mpi_t r, gcry_mpi_t s,
                            int flags, int hashalgo);
static gpg_err_code_t verify (gcry_mpi_t input, ECC_public_key *pkey,
                              gcry_mpi_t r, gcry_mpi_t s);


static gcry_mpi_t gen_y_2 (gcry_mpi_t x, elliptic_curve_t * base);




void
_gcry_register_pk_ecc_progress (void (*cb) (void *, const char *,
                                            int, int, int),
                                void *cb_data)
{
  progress_cb = cb;
  progress_cb_data = cb_data;
}

/* static void */
/* progress (int c) */
/* { */
/*   if (progress_cb) */
/*     progress_cb (progress_cb_data, "pk_ecc", c, 0, 0); */
/* } */




/****************
 * Solve the right side of the equation that defines a curve.
 */
static gcry_mpi_t
gen_y_2 (gcry_mpi_t x, elliptic_curve_t *base)
{
  gcry_mpi_t three, x_3, axb, y;

  three = mpi_alloc_set_ui (3);
  x_3 = mpi_new (0);
  axb = mpi_new (0);
  y   = mpi_new (0);

  mpi_powm (x_3, x, three, base->p);
  mpi_mulm (axb, base->a, x, base->p);
  mpi_addm (axb, axb, base->b, base->p);
  mpi_addm (y, x_3, axb, base->p);

  mpi_free (x_3);
  mpi_free (axb);
  mpi_free (three);
  return y; /* The quadratic value of the coordinate if it exist. */
}


/*
 * First obtain the setup.  Over the finite field randomize an scalar
 * secret value, and calculate the public point.
 */
static gpg_err_code_t
generate_key (ECC_secret_key *sk, unsigned int nbits, const char *name,
              int transient_key,
              gcry_mpi_t g_x, gcry_mpi_t g_y,
              gcry_mpi_t q_x, gcry_mpi_t q_y,
              const char **r_usedcurve)
{
  gpg_err_code_t err;
  elliptic_curve_t E;
  mpi_point_struct Q;
  mpi_ec_t ctx;
  gcry_random_level_t random_level;

  *r_usedcurve = NULL;

  err = _gcry_ecc_fill_in_curve (nbits, name, &E, &nbits);
  if (err)
    return err;

  if (DBG_CIPHER)
    {
      log_mpidump ("ecgen curve  p", E.p);
      log_mpidump ("ecgen curve  a", E.a);
      log_mpidump ("ecgen curve  b", E.b);
      log_mpidump ("ecgen curve  n", E.n);
      log_mpidump ("ecgen curve Gx", E.G.x);
      log_mpidump ("ecgen curve Gy", E.G.y);
      log_mpidump ("ecgen curve Gz", E.G.z);
      if (E.name)
        log_debug   ("ecgen curve used: %s\n", E.name);
    }

  random_level = transient_key ? GCRY_STRONG_RANDOM : GCRY_VERY_STRONG_RANDOM;
  sk->d = _gcry_dsa_gen_k (E.n, random_level);

  /* Compute Q.  */
  point_init (&Q);
  ctx = _gcry_mpi_ec_p_internal_new (E.p, E.a);
  _gcry_mpi_ec_mul_point (&Q, sk->d, &E.G, ctx);

  /* Copy the stuff to the key structures. */
  sk->E.p = mpi_copy (E.p);
  sk->E.a = mpi_copy (E.a);
  sk->E.b = mpi_copy (E.b);
  point_init (&sk->E.G);
  point_set (&sk->E.G, &E.G);
  sk->E.n = mpi_copy (E.n);
  point_init (&sk->Q);

  /* We want the Q=(x,y) be a "compliant key" in terms of the
   * http://tools.ietf.org/html/draft-jivsov-ecc-compact, which simply
   * means that we choose either Q=(x,y) or -Q=(x,p-y) such that we
   * end up with the min(y,p-y) as the y coordinate.  Such a public
   * key allows the most efficient compression: y can simply be
   * dropped because we know that it's a minimum of the two
   * possibilities without any loss of security.  */
  {
    gcry_mpi_t x, y, p_y;
    const unsigned int pbits = mpi_get_nbits (E.p);

    x = mpi_new (pbits);
    y = mpi_new (pbits);
    p_y = mpi_new (pbits);

    if (_gcry_mpi_ec_get_affine (x, y, &Q, ctx))
      log_fatal ("ecgen: Failed to get affine coordinates for %s\n", "Q");

    mpi_sub (p_y, E.p, y);	/* p_y = p - y */

    if (mpi_cmp (p_y, y) < 0)   /* p - y < p */
      {
        /* We need to end up with -Q; this assures that new Q's y is
           the smallest one */
        mpi_sub (sk->d, E.n, sk->d);   /* d = order - d */
	gcry_mpi_point_snatch_set (&sk->Q, x, p_y, mpi_alloc_set_ui (1));

        if (DBG_CIPHER)
          log_debug ("ecgen converted Q to a compliant point\n");
      }
    else /* p - y >= p */
      {
        /* No change is needed exactly 50% of the time: just copy. */
	point_set (&sk->Q, &Q);
        if (DBG_CIPHER)
          log_debug ("ecgen didn't need to convert Q to a compliant point\n");

        mpi_free (p_y);
        mpi_free (x);
      }
    mpi_free (y);
  }

  /* We also return copies of G and Q in affine coordinates if
     requested.  */
  if (g_x && g_y)
    {
      if (_gcry_mpi_ec_get_affine (g_x, g_y, &sk->E.G, ctx))
        log_fatal ("ecgen: Failed to get affine coordinates for %s\n", "G");
    }
  if (q_x && q_y)
    {
      if (_gcry_mpi_ec_get_affine (q_x, q_y, &sk->Q, ctx))
        log_fatal ("ecgen: Failed to get affine coordinates for %s\n", "Q");
    }
  _gcry_mpi_ec_free (ctx);

  point_free (&Q);

  *r_usedcurve = E.name;
  _gcry_ecc_curve_free (&E);

  /* Now we can test our keys (this should never fail!).  */
  test_keys (sk, nbits - 64);

  return 0;
}


/*
 * To verify correct skey it use a random information.
 * First, encrypt and decrypt this dummy value,
 * test if the information is recuperated.
 * Second, test with the sign and verify functions.
 */
static void
test_keys (ECC_secret_key *sk, unsigned int nbits)
{
  ECC_public_key pk;
  gcry_mpi_t test = mpi_new (nbits);
  mpi_point_struct R_;
  gcry_mpi_t c = mpi_new (nbits);
  gcry_mpi_t out = mpi_new (nbits);
  gcry_mpi_t r = mpi_new (nbits);
  gcry_mpi_t s = mpi_new (nbits);

  if (DBG_CIPHER)
    log_debug ("Testing key.\n");

  point_init (&R_);

  pk.E = _gcry_ecc_curve_copy (sk->E);
  point_init (&pk.Q);
  point_set (&pk.Q, &sk->Q);

  gcry_mpi_randomize (test, nbits, GCRY_WEAK_RANDOM);

  if (sign (test, sk, r, s, 0, 0) )
    log_fatal ("ECDSA operation: sign failed\n");

  if (verify (test, &pk, r, s))
    {
      log_fatal ("ECDSA operation: sign, verify failed\n");
    }

  if (DBG_CIPHER)
    log_debug ("ECDSA operation: sign, verify ok.\n");

  point_free (&pk.Q);
  _gcry_ecc_curve_free (&pk.E);

  point_free (&R_);
  mpi_free (s);
  mpi_free (r);
  mpi_free (out);
  mpi_free (c);
  mpi_free (test);
}


/*
 * To check the validity of the value, recalculate the correspondence
 * between the public value and the secret one.
 */
static int
check_secret_key (ECC_secret_key * sk)
{
  int rc = 1;
  mpi_point_struct Q;
  gcry_mpi_t y_2, y2;
  gcry_mpi_t x1, x2;
  mpi_ec_t ctx = NULL;

  point_init (&Q);

  /* ?primarity test of 'p' */
  /*  (...) //!! */
  /* G in E(F_p) */
  y_2 = gen_y_2 (sk->E.G.x, &sk->E);   /*  y^2=x^3+a*x+b */
  y2 = mpi_alloc (0);
  x1 = mpi_alloc (0);
  x2 = mpi_alloc (0);
  mpi_mulm (y2, sk->E.G.y, sk->E.G.y, sk->E.p);      /*  y^2=y*y */
  if (mpi_cmp (y_2, y2))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: Point 'G' does not belong to curve 'E'!\n");
      goto leave;
    }
  /* G != PaI */
  if (!mpi_cmp_ui (sk->E.G.z, 0))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: 'G' cannot be Point at Infinity!\n");
      goto leave;
    }

  ctx = _gcry_mpi_ec_p_internal_new (sk->E.p, sk->E.a);

  _gcry_mpi_ec_mul_point (&Q, sk->E.n, &sk->E.G, ctx);
  if (mpi_cmp_ui (Q.z, 0))
    {
      if (DBG_CIPHER)
        log_debug ("check_secret_key: E is not a curve of order n\n");
      goto leave;
    }
  /* pubkey cannot be PaI */
  if (!mpi_cmp_ui (sk->Q.z, 0))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: Q can not be a Point at Infinity!\n");
      goto leave;
    }
  /* pubkey = [d]G over E */
  _gcry_mpi_ec_mul_point (&Q, sk->d, &sk->E.G, ctx);

  if (_gcry_mpi_ec_get_affine (x1, y_2, &Q, ctx))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: Q can not be a Point at Infinity!\n");
      goto leave;
    }

  /* Fast path for loaded secret keys - Q is already in affine coordinates */
  if (!mpi_cmp_ui (sk->Q.z, 1))
    {
      if (mpi_cmp (x1, sk->Q.x) || mpi_cmp (y_2, sk->Q.y))
        {
          if (DBG_CIPHER)
            log_debug
              ("Bad check: There is NO correspondence between 'd' and 'Q'!\n");
          goto leave;
        }
    }
  else
    {
      if (_gcry_mpi_ec_get_affine (x2, y2, &sk->Q, ctx))
        {
          if (DBG_CIPHER)
            log_debug ("Bad check: Q can not be a Point at Infinity!\n");
          goto leave;
        }

      if (mpi_cmp (x1, x2) || mpi_cmp (y_2, y2))
        {
          if (DBG_CIPHER)
            log_debug
              ("Bad check: There is NO correspondence between 'd' and 'Q'!\n");
          goto leave;
        }
    }
  rc = 0; /* Okay.  */

 leave:
  _gcry_mpi_ec_free (ctx);
  mpi_free (x2);
  mpi_free (x1);
  mpi_free (y2);
  mpi_free (y_2);
  point_free (&Q);
  return rc;
}


/*
 * Return the signature struct (r,s) from the message hash.  The caller
 * must have allocated R and S.
 */
static gpg_err_code_t
sign (gcry_mpi_t input, ECC_secret_key *skey, gcry_mpi_t r, gcry_mpi_t s,
      int flags, int hashalgo)
{
  gpg_err_code_t err = 0;
  int extraloops = 0;
  gcry_mpi_t k, dr, sum, k_1, x;
  mpi_point_struct I;
  gcry_mpi_t hash;
  const void *abuf;
  unsigned int abits, qbits;
  mpi_ec_t ctx;

  if (DBG_CIPHER)
    log_mpidump ("ecdsa sign hash  ", input );

  qbits = mpi_get_nbits (skey->E.n);

  /* Convert the INPUT into an MPI if needed.  */
  if (mpi_is_opaque (input))
    {
      abuf = gcry_mpi_get_opaque (input, &abits);
      err = gpg_err_code (gcry_mpi_scan (&hash, GCRYMPI_FMT_USG,
                                         abuf, (abits+7)/8, NULL));
      if (err)
        return err;
      if (abits > qbits)
        gcry_mpi_rshift (hash, hash, abits - qbits);
    }
  else
    hash = input;


  k = NULL;
  dr = mpi_alloc (0);
  sum = mpi_alloc (0);
  k_1 = mpi_alloc (0);
  x = mpi_alloc (0);
  point_init (&I);

  mpi_set_ui (s, 0);
  mpi_set_ui (r, 0);

  ctx = _gcry_mpi_ec_p_internal_new (skey->E.p, skey->E.a);

  while (!mpi_cmp_ui (s, 0)) /* s == 0 */
    {
      while (!mpi_cmp_ui (r, 0)) /* r == 0 */
        {
          /* Note, that we are guaranteed to enter this loop at least
             once because r has been intialized to 0.  We can't use a
             do_while because we want to keep the value of R even if S
             has to be recomputed.  */

          mpi_free (k);
          k = NULL;
          if ((flags & PUBKEY_FLAG_RFC6979) && hashalgo)
            {
              /* Use Pornin's method for deterministic DSA.  If this
                 flag is set, it is expected that HASH is an opaque
                 MPI with the to be signed hash.  That hash is also
                 used as h1 from 3.2.a.  */
              if (!mpi_is_opaque (input))
                {
                  err = GPG_ERR_CONFLICT;
                  goto leave;
                }

              abuf = gcry_mpi_get_opaque (input, &abits);
              err = _gcry_dsa_gen_rfc6979_k (&k, skey->E.n, skey->d,
                                             abuf, (abits+7)/8,
                                             hashalgo, extraloops);
              if (err)
                goto leave;
              extraloops++;
            }
          else
            k = _gcry_dsa_gen_k (skey->E.n, GCRY_STRONG_RANDOM);

          _gcry_mpi_ec_mul_point (&I, k, &skey->E.G, ctx);
          if (_gcry_mpi_ec_get_affine (x, NULL, &I, ctx))
            {
              if (DBG_CIPHER)
                log_debug ("ecc sign: Failed to get affine coordinates\n");
              err = GPG_ERR_BAD_SIGNATURE;
              goto leave;
            }
          mpi_mod (r, x, skey->E.n);  /* r = x mod n */
        }
      mpi_mulm (dr, skey->d, r, skey->E.n); /* dr = d*r mod n  */
      mpi_addm (sum, hash, dr, skey->E.n);  /* sum = hash + (d*r) mod n  */
      mpi_invm (k_1, k, skey->E.n);         /* k_1 = k^(-1) mod n  */
      mpi_mulm (s, k_1, sum, skey->E.n);    /* s = k^(-1)*(hash+(d*r)) mod n */
    }

  if (DBG_CIPHER)
    {
      log_mpidump ("ecdsa sign result r ", r);
      log_mpidump ("ecdsa sign result s ", s);
    }

 leave:
  _gcry_mpi_ec_free (ctx);
  point_free (&I);
  mpi_free (x);
  mpi_free (k_1);
  mpi_free (sum);
  mpi_free (dr);
  mpi_free (k);

  if (hash != input)
    mpi_free (hash);

  return err;
}


/*
 * Check if R and S verifies INPUT.
 */
static gpg_err_code_t
verify (gcry_mpi_t input, ECC_public_key *pkey, gcry_mpi_t r, gcry_mpi_t s)
{
  gpg_err_code_t err = 0;
  gcry_mpi_t h, h1, h2, x;
  mpi_point_struct Q, Q1, Q2;
  mpi_ec_t ctx;

  if( !(mpi_cmp_ui (r, 0) > 0 && mpi_cmp (r, pkey->E.n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < r < n  failed.  */
  if( !(mpi_cmp_ui (s, 0) > 0 && mpi_cmp (s, pkey->E.n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < s < n  failed.  */

  h  = mpi_alloc (0);
  h1 = mpi_alloc (0);
  h2 = mpi_alloc (0);
  x = mpi_alloc (0);
  point_init (&Q);
  point_init (&Q1);
  point_init (&Q2);

  ctx = _gcry_mpi_ec_p_internal_new (pkey->E.p, pkey->E.a);

  /* h  = s^(-1) (mod n) */
  mpi_invm (h, s, pkey->E.n);
  /* h1 = hash * s^(-1) (mod n) */
  mpi_mulm (h1, input, h, pkey->E.n);
  /* Q1 = [ hash * s^(-1) ]G  */
  _gcry_mpi_ec_mul_point (&Q1, h1, &pkey->E.G, ctx);
  /* h2 = r * s^(-1) (mod n) */
  mpi_mulm (h2, r, h, pkey->E.n);
  /* Q2 = [ r * s^(-1) ]Q */
  _gcry_mpi_ec_mul_point (&Q2, h2, &pkey->Q, ctx);
  /* Q  = ([hash * s^(-1)]G) + ([r * s^(-1)]Q) */
  _gcry_mpi_ec_add_points (&Q, &Q1, &Q2, ctx);

  if (!mpi_cmp_ui (Q.z, 0))
    {
      if (DBG_CIPHER)
          log_debug ("ecc verify: Rejected\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  if (_gcry_mpi_ec_get_affine (x, NULL, &Q, ctx))
    {
      if (DBG_CIPHER)
        log_debug ("ecc verify: Failed to get affine coordinates\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  mpi_mod (x, x, pkey->E.n); /* x = x mod E_n */
  if (mpi_cmp (x, r))   /* x != r */
    {
      if (DBG_CIPHER)
        {
          log_mpidump ("     x", x);
          log_mpidump ("     r", r);
          log_mpidump ("     s", s);
          log_debug ("ecc verify: Not verified\n");
        }
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  if (DBG_CIPHER)
    log_debug ("ecc verify: Accepted\n");

 leave:
  _gcry_mpi_ec_free (ctx);
  point_free (&Q2);
  point_free (&Q1);
  point_free (&Q);
  mpi_free (x);
  mpi_free (h2);
  mpi_free (h1);
  mpi_free (h);
  return err;
}



/*********************************************
 **************  interface  ******************
 *********************************************/

/* Extended version of ecc_generate.  */
static gcry_err_code_t
ecc_generate_ext (int algo, unsigned int nbits, unsigned long evalue,
                  const gcry_sexp_t genparms,
                  gcry_mpi_t *skey, gcry_mpi_t **retfactors,
                  gcry_sexp_t *r_extrainfo)
{
  gpg_err_code_t ec;
  ECC_secret_key sk;
  gcry_mpi_t g_x, g_y, q_x, q_y;
  char *curve_name = NULL;
  gcry_sexp_t l1;
  int transient_key = 0;
  const char *usedcurve = NULL;

  (void)algo;
  (void)evalue;

  if (genparms)
    {
      /* Parse the optional "curve" parameter. */
      l1 = gcry_sexp_find_token (genparms, "curve", 0);
      if (l1)
        {
          curve_name = _gcry_sexp_nth_string (l1, 1);
          gcry_sexp_release (l1);
          if (!curve_name)
            return GPG_ERR_INV_OBJ; /* No curve name or value too large. */
        }

      /* Parse the optional transient-key flag.  */
      l1 = gcry_sexp_find_token (genparms, "transient-key", 0);
      if (l1)
        {
          transient_key = 1;
          gcry_sexp_release (l1);
        }
    }

  /* NBITS is required if no curve name has been given.  */
  if (!nbits && !curve_name)
    return GPG_ERR_NO_OBJ; /* No NBITS parameter. */

  g_x = mpi_new (0);
  g_y = mpi_new (0);
  q_x = mpi_new (0);
  q_y = mpi_new (0);
  ec = generate_key (&sk, nbits, curve_name, transient_key, g_x, g_y, q_x, q_y,
                     &usedcurve);
  gcry_free (curve_name);
  if (ec)
    return ec;
  if (usedcurve)  /* Fixme: No error return checking.  */
    gcry_sexp_build (r_extrainfo, NULL, "(curve %s)", usedcurve);

  skey[0] = sk.E.p;
  skey[1] = sk.E.a;
  skey[2] = sk.E.b;
  skey[3] = _gcry_ecc_ec2os (g_x, g_y, sk.E.p);
  skey[4] = sk.E.n;
  skey[5] = _gcry_ecc_ec2os (q_x, q_y, sk.E.p);
  skey[6] = sk.d;

  mpi_free (g_x);
  mpi_free (g_y);
  mpi_free (q_x);
  mpi_free (q_y);

  point_free (&sk.E.G);
  point_free (&sk.Q);

  /* Make an empty list of factors.  */
  *retfactors = gcry_calloc ( 1, sizeof **retfactors );
  if (!*retfactors)
    return gpg_err_code_from_syserror ();  /* Fixme: relase mem?  */

  if (DBG_CIPHER)
    {
      log_mpidump ("ecgen result p", skey[0]);
      log_mpidump ("ecgen result a", skey[1]);
      log_mpidump ("ecgen result b", skey[2]);
      log_mpidump ("ecgen result G", skey[3]);
      log_mpidump ("ecgen result n", skey[4]);
      log_mpidump ("ecgen result Q", skey[5]);
      log_mpidump ("ecgen result d", skey[6]);
    }

  return 0;
}


static gcry_err_code_t
ecc_generate (int algo, unsigned int nbits, unsigned long evalue,
              gcry_mpi_t *skey, gcry_mpi_t **retfactors)
{
  (void)evalue;
  return ecc_generate_ext (algo, nbits, 0, NULL, skey, retfactors, NULL);
}


static gcry_err_code_t
ecc_check_secret_key (int algo, gcry_mpi_t *skey)
{
  gpg_err_code_t err;
  ECC_secret_key sk;

  (void)algo;

  /* FIXME:  This check looks a bit fishy:  Now long is the array?  */
  if (!skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4] || !skey[5]
      || !skey[6])
    return GPG_ERR_BAD_MPI;

  sk.E.p = skey[0];
  sk.E.a = skey[1];
  sk.E.b = skey[2];
  point_init (&sk.E.G);
  err = _gcry_ecc_os2ec (&sk.E.G, skey[3]);
  if (err)
    {
      point_free (&sk.E.G);
      return err;
    }
  sk.E.n = skey[4];
  point_init (&sk.Q);
  err = _gcry_ecc_os2ec (&sk.Q, skey[5]);
  if (err)
    {
      point_free (&sk.E.G);
      point_free (&sk.Q);
      return err;
    }

  sk.d = skey[6];

  if (check_secret_key (&sk))
    {
      point_free (&sk.E.G);
      point_free (&sk.Q);
      return GPG_ERR_BAD_SECKEY;
    }
  point_free (&sk.E.G);
  point_free (&sk.Q);
  return 0;
}


static gcry_err_code_t
ecc_sign (int algo, gcry_mpi_t *resarr, gcry_mpi_t data, gcry_mpi_t *skey,
          int flags, int hashalgo)
{
  gpg_err_code_t err;
  ECC_secret_key sk;

  (void)algo;

  if (!data || !skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4]
      || !skey[6] )
    return GPG_ERR_BAD_MPI;

  sk.E.p = skey[0];
  sk.E.a = skey[1];
  sk.E.b = skey[2];
  point_init (&sk.E.G);
  err = _gcry_ecc_os2ec (&sk.E.G, skey[3]);
  if (err)
    {
      point_free (&sk.E.G);
      return err;
    }
  sk.E.n = skey[4];
  /* Note: We don't have any need for Q here.  */
  sk.d = skey[6];

  resarr[0] = mpi_alloc (mpi_get_nlimbs (sk.E.p));
  resarr[1] = mpi_alloc (mpi_get_nlimbs (sk.E.p));
  err = sign (data, &sk, resarr[0], resarr[1], flags, hashalgo);
  if (err)
    {
      mpi_free (resarr[0]);
      mpi_free (resarr[1]);
      resarr[0] = NULL; /* Mark array as released.  */
    }
  point_free (&sk.E.G);
  return err;
}


static gcry_err_code_t
ecc_verify (int algo, gcry_mpi_t hash, gcry_mpi_t *data, gcry_mpi_t *pkey,
            int (*cmp)(void *, gcry_mpi_t), void *opaquev)
{
  gpg_err_code_t err;
  ECC_public_key pk;

  (void)algo;
  (void)cmp;
  (void)opaquev;

  if (!data[0] || !data[1] || !hash || !pkey[0] || !pkey[1] || !pkey[2]
      || !pkey[3] || !pkey[4] || !pkey[5] )
    return GPG_ERR_BAD_MPI;

  pk.E.p = pkey[0];
  pk.E.a = pkey[1];
  pk.E.b = pkey[2];
  point_init (&pk.E.G);
  err = _gcry_ecc_os2ec (&pk.E.G, pkey[3]);
  if (err)
    {
      point_free (&pk.E.G);
      return err;
    }
  pk.E.n = pkey[4];
  point_init (&pk.Q);
  err = _gcry_ecc_os2ec (&pk.Q, pkey[5]);
  if (err)
    {
      point_free (&pk.E.G);
      point_free (&pk.Q);
      return err;
    }

  if (mpi_is_opaque (hash))
    {
      const void *abuf;
      unsigned int abits, qbits;
      gcry_mpi_t a;

      qbits = mpi_get_nbits (pk.E.n);

      abuf = gcry_mpi_get_opaque (hash, &abits);
      err = gcry_mpi_scan (&a, GCRYMPI_FMT_USG, abuf, (abits+7)/8, NULL);
      if (!err)
        {
          if (abits > qbits)
            gcry_mpi_rshift (a, a, abits - qbits);

          err = verify (a, &pk, data[0], data[1]);
          gcry_mpi_release (a);
        }
    }
  else
    err = verify (hash, &pk, data[0], data[1]);

  point_free (&pk.E.G);
  point_free (&pk.Q);
  return err;
}


/* ecdh raw is classic 2-round DH protocol published in 1976.
 *
 * Overview of ecc_encrypt_raw and ecc_decrypt_raw.
 *
 * As with any PK operation, encrypt version uses a public key and
 * decrypt -- private.
 *
 * Symbols used below:
 *     G - field generator point
 *     d - private long-term scalar
 *    dG - public long-term key
 *     k - ephemeral scalar
 *    kG - ephemeral public key
 *   dkG - shared secret
 *
 * ecc_encrypt_raw description:
 *   input:
 *     data[0] : private scalar (k)
 *   output:
 *     result[0] : shared point (kdG)
 *     result[1] : generated ephemeral public key (kG)
 *
 * ecc_decrypt_raw description:
 *   input:
 *     data[0] : a point kG (ephemeral public key)
 *   output:
 *     result[0] : shared point (kdG)
 */
static gcry_err_code_t
ecc_encrypt_raw (int algo, gcry_mpi_t *resarr, gcry_mpi_t k,
                 gcry_mpi_t *pkey, int flags)
{
  ECC_public_key pk;
  mpi_ec_t ctx;
  gcry_mpi_t result[2];
  int err;

  (void)algo;
  (void)flags;

  if (!k
      || !pkey[0] || !pkey[1] || !pkey[2] || !pkey[3] || !pkey[4] || !pkey[5])
    return GPG_ERR_BAD_MPI;

  pk.E.p = pkey[0];
  pk.E.a = pkey[1];
  pk.E.b = pkey[2];
  point_init (&pk.E.G);
  err = _gcry_ecc_os2ec (&pk.E.G, pkey[3]);
  if (err)
    {
      point_free (&pk.E.G);
      return err;
    }
  pk.E.n = pkey[4];
  point_init (&pk.Q);
  err = _gcry_ecc_os2ec (&pk.Q, pkey[5]);
  if (err)
    {
      point_free (&pk.E.G);
      point_free (&pk.Q);
      return err;
    }

  ctx = _gcry_mpi_ec_p_internal_new (pk.E.p, pk.E.a);

  /* The following is false: assert( mpi_cmp_ui( R.x, 1 )==0 );, so */
  {
    mpi_point_struct R;  /* Result that we return.  */
    gcry_mpi_t x, y;

    x = mpi_new (0);
    y = mpi_new (0);

    point_init (&R);

    /* R = kQ  <=>  R = kdG  */
    _gcry_mpi_ec_mul_point (&R, k, &pk.Q, ctx);

    if (_gcry_mpi_ec_get_affine (x, y, &R, ctx))
      log_fatal ("ecdh: Failed to get affine coordinates for kdG\n");

    result[0] = _gcry_ecc_ec2os (x, y, pk.E.p);

    /* R = kG */
    _gcry_mpi_ec_mul_point (&R, k, &pk.E.G, ctx);

    if (_gcry_mpi_ec_get_affine (x, y, &R, ctx))
      log_fatal ("ecdh: Failed to get affine coordinates for kG\n");

    result[1] = _gcry_ecc_ec2os (x, y, pk.E.p);

    mpi_free (x);
    mpi_free (y);

    point_free (&R);
  }

  _gcry_mpi_ec_free (ctx);
  point_free (&pk.E.G);
  point_free (&pk.Q);

  if (!result[0] || !result[1])
    {
      mpi_free (result[0]);
      mpi_free (result[1]);
      return GPG_ERR_ENOMEM;
    }

  /* Success.  */
  resarr[0] = result[0];
  resarr[1] = result[1];

  return 0;
}

/*  input:
 *     data[0] : a point kG (ephemeral public key)
 *   output:
 *     resaddr[0] : shared point kdG
 *
 *  see ecc_encrypt_raw for details.
 */
static gcry_err_code_t
ecc_decrypt_raw (int algo, gcry_mpi_t *result, gcry_mpi_t *data,
                 gcry_mpi_t *skey, int flags)
{
  ECC_secret_key sk;
  mpi_point_struct R;	/* Result that we return.  */
  mpi_point_struct kG;
  mpi_ec_t ctx;
  gcry_mpi_t r;
  int err;

  (void)algo;
  (void)flags;

  *result = NULL;

  if (!data || !data[0]
      || !skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4]
      || !skey[5] || !skey[6] )
    return GPG_ERR_BAD_MPI;

  point_init (&kG);
  err = _gcry_ecc_os2ec (&kG, data[0]);
  if (err)
    {
      point_free (&kG);
      return err;
    }


  sk.E.p = skey[0];
  sk.E.a = skey[1];
  sk.E.b = skey[2];
  point_init (&sk.E.G);
  err = _gcry_ecc_os2ec (&sk.E.G, skey[3]);
  if (err)
    {
      point_free (&kG);
      point_free (&sk.E.G);
      return err;
    }
  sk.E.n = skey[4];
  point_init (&sk.Q);
  err = _gcry_ecc_os2ec (&sk.Q, skey[5]);
  if (err)
    {
      point_free (&kG);
      point_free (&sk.E.G);
      point_free (&sk.Q);
      return err;
    }
  sk.d = skey[6];

  ctx = _gcry_mpi_ec_p_internal_new (sk.E.p, sk.E.a);

  /* R = dkG */
  point_init (&R);
  _gcry_mpi_ec_mul_point (&R, sk.d, &kG, ctx);

  point_free (&kG);

  /* The following is false: assert( mpi_cmp_ui( R.x, 1 )==0 );, so:  */
  {
    gcry_mpi_t x, y;

    x = mpi_new (0);
    y = mpi_new (0);

    if (_gcry_mpi_ec_get_affine (x, y, &R, ctx))
      log_fatal ("ecdh: Failed to get affine coordinates\n");

    r = _gcry_ecc_ec2os (x, y, sk.E.p);
    mpi_free (x);
    mpi_free (y);
  }

  point_free (&R);
  _gcry_mpi_ec_free (ctx);
  point_free (&kG);
  point_free (&sk.E.G);
  point_free (&sk.Q);

  if (!r)
    return GPG_ERR_ENOMEM;

  /* Success.  */

  *result = r;

  return 0;
}


static unsigned int
ecc_get_nbits (int algo, gcry_mpi_t *pkey)
{
  (void)algo;

  return mpi_get_nbits (pkey[0]);
}


/* See rsa.c for a description of this function.  */
static gpg_err_code_t
compute_keygrip (gcry_md_hd_t md, gcry_sexp_t keyparam)
{
#define N_COMPONENTS 6
  static const char names[N_COMPONENTS+1] = "pabgnq";
  gpg_err_code_t ec = 0;
  gcry_sexp_t l1;
  gcry_mpi_t values[N_COMPONENTS];
  int idx;

  /* Clear the values for easier error cleanup.  */
  for (idx=0; idx < N_COMPONENTS; idx++)
    values[idx] = NULL;

  /* Fill values with all provided parameters.  */
  for (idx=0; idx < N_COMPONENTS; idx++)
    {
      l1 = gcry_sexp_find_token (keyparam, names+idx, 1);
      if (l1)
        {
          values[idx] = gcry_sexp_nth_mpi (l1, 1, GCRYMPI_FMT_USG);
	  gcry_sexp_release (l1);
	  if (!values[idx])
            {
              ec = GPG_ERR_INV_OBJ;
              goto leave;
            }
	}
    }

  /* Check whether a curve parameter is available and use that to fill
     in missing values.  */
  l1 = gcry_sexp_find_token (keyparam, "curve", 5);
  if (l1)
    {
      char *curve;
      gcry_mpi_t tmpvalues[N_COMPONENTS];

      for (idx = 0; idx < N_COMPONENTS; idx++)
        tmpvalues[idx] = NULL;

      curve = _gcry_sexp_nth_string (l1, 1);
      gcry_sexp_release (l1);
      if (!curve)
        {
          ec = GPG_ERR_INV_OBJ; /* Name missing or out of core. */
          goto leave;
        }
      ec = _gcry_ecc_get_param (curve, tmpvalues);
      gcry_free (curve);
      if (ec)
        goto leave;

      for (idx = 0; idx < N_COMPONENTS; idx++)
        {
          if (!values[idx])
            values[idx] = tmpvalues[idx];
          else
            mpi_free (tmpvalues[idx]);
        }
    }

  /* Check that all parameters are known and normalize all MPIs (that
     should not be required but we use an internal function later and
     thus we better make 100% sure that they are normalized). */
  for (idx = 0; idx < N_COMPONENTS; idx++)
    if (!values[idx])
      {
        ec = GPG_ERR_NO_OBJ;
        goto leave;
      }
    else
      _gcry_mpi_normalize (values[idx]);

  /* Hash them all.  */
  for (idx = 0; idx < N_COMPONENTS; idx++)
    {
      char buf[30];
      unsigned char *rawmpi;
      unsigned int rawmpilen;

      rawmpi = _gcry_mpi_get_buffer (values[idx], &rawmpilen, NULL);
      if (!rawmpi)
        {
          ec = gpg_err_code_from_syserror ();
          goto leave;
        }
      snprintf (buf, sizeof buf, "(1:%c%u:", names[idx], rawmpilen);
      gcry_md_write (md, buf, strlen (buf));
      gcry_md_write (md, rawmpi, rawmpilen);
      gcry_md_write (md, ")", 1);
      gcry_free (rawmpi);
    }

 leave:
  for (idx = 0; idx < N_COMPONENTS; idx++)
    _gcry_mpi_release (values[idx]);

  return ec;
#undef N_COMPONENTS
}



/*
   Low-level API helper functions.
 */

/* This is the wroker function for gcry_pubkey_get_sexp for ECC
   algorithms.  Note that the caller has already stored NULL at
   R_SEXP.  */
gpg_err_code_t
_gcry_pk_ecc_get_sexp (gcry_sexp_t *r_sexp, int mode, mpi_ec_t ec)
{
  gpg_err_code_t rc;
  gcry_mpi_t mpi_G = NULL;
  gcry_mpi_t mpi_Q = NULL;

  if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n)
    return GPG_ERR_BAD_CRYPT_CTX;

  if (mode == GCRY_PK_GET_SECKEY && !ec->d)
    return GPG_ERR_NO_SECKEY;

  /* Compute the public point if it is missing.  */
  if (!ec->Q && ec->d)
    {
      ec->Q = gcry_mpi_point_new (0);
      _gcry_mpi_ec_mul_point (ec->Q, ec->d, ec->G, ec);
    }

  /* Encode G and Q.  */
  mpi_G = _gcry_mpi_ec_ec2os (ec->G, ec);
  if (!mpi_G)
    {
      rc = GPG_ERR_BROKEN_PUBKEY;
      goto leave;
    }
  if (!ec->Q)
    {
      rc = GPG_ERR_BAD_CRYPT_CTX;
      goto leave;
    }
  mpi_Q = _gcry_mpi_ec_ec2os (ec->Q, ec);
  if (!mpi_Q)
    {
      rc = GPG_ERR_BROKEN_PUBKEY;
      goto leave;
    }

  /* Fixme: We should return a curve name instead of the parameters if
     if know that they match a curve.  */

  if (ec->d && (!mode || mode == GCRY_PK_GET_SECKEY))
    {
      /* Let's return a private key. */
      rc = gpg_err_code
        (gcry_sexp_build
         (r_sexp, NULL,
          "(private-key(ecc(p%m)(a%m)(b%m)(g%m)(n%m)(q%m)(d%m)))",
          ec->p, ec->a, ec->b, mpi_G, ec->n, mpi_Q, ec->d));
    }
  else if (ec->Q)
    {
      /* Let's return a public key.  */
      rc = gpg_err_code
        (gcry_sexp_build
         (r_sexp, NULL,
          "(public-key(ecc(p%m)(a%m)(b%m)(g%m)(n%m)(q%m)))",
          ec->p, ec->a, ec->b, mpi_G, ec->n, mpi_Q));
    }
  else
    rc = GPG_ERR_BAD_CRYPT_CTX;

 leave:
  mpi_free (mpi_Q);
  mpi_free (mpi_G);
  return rc;
}



/*
     Self-test section.
 */


static gpg_err_code_t
selftests_ecdsa (selftest_report_func_t report)
{
  const char *what;
  const char *errtxt;

  what = "low-level";
  errtxt = NULL; /*selftest ();*/
  if (errtxt)
    goto failed;

  /* FIXME:  need more tests.  */

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("pubkey", GCRY_PK_ECDSA, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}


/* Run a full self-test for ALGO and return 0 on success.  */
static gpg_err_code_t
run_selftests (int algo, int extended, selftest_report_func_t report)
{
  gpg_err_code_t ec;

  (void)extended;

  switch (algo)
    {
    case GCRY_PK_ECDSA:
      ec = selftests_ecdsa (report);
      break;
    default:
      ec = GPG_ERR_PUBKEY_ALGO;
      break;

    }
  return ec;
}




static const char *ecdsa_names[] =
  {
    "ecdsa",
    "ecc",
    NULL,
  };
static const char *ecdh_names[] =
  {
    "ecdh",
    "ecc",
    NULL,
  };

gcry_pk_spec_t _gcry_pubkey_spec_ecdsa =
  {
    "ECDSA", ecdsa_names,
    "pabgnq", "pabgnqd", "", "rs", "pabgnq",
    GCRY_PK_USAGE_SIGN,
    ecc_generate,
    ecc_check_secret_key,
    NULL,
    NULL,
    ecc_sign,
    ecc_verify,
    ecc_get_nbits
  };

gcry_pk_spec_t _gcry_pubkey_spec_ecdh =
  {
    "ECDH", ecdh_names,
    "pabgnq", "pabgnqd", "se", "", "pabgnq",
    GCRY_PK_USAGE_ENCR,
    ecc_generate,
    ecc_check_secret_key,
    ecc_encrypt_raw,
    ecc_decrypt_raw,
    NULL,
    NULL,
    ecc_get_nbits
  };


pk_extra_spec_t _gcry_pubkey_extraspec_ecdsa =
  {
    run_selftests,
    ecc_generate_ext,
    compute_keygrip,
    _gcry_ecc_get_param,
    _gcry_ecc_get_curve,
    _gcry_ecc_get_param_sexp
  };
