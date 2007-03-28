/* ecc.c  -  Elliptic Curve Cryptography
   Copyright (C) 2007 Free Software Foundation, Inc.

   This file is part of Libgcrypt.
  
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
  
   Libgcrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
   USA.  */

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
  been rewritten and moved to mpi/ec.c.  */


/* TODO:

  - If we support point compression we need to decide how to compute
    the keygrip - it should not change due to compression.

  - In mpi/ec.c we use mpi_powm for x^2 mod p: Either implement a
    special case in mpi_powm or check whether mpi_mulm is faster.

  - Decide whether we should hide the mpi_point_t definition.

  - Support more than just ECDSA.
*/


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"


/* Definition of a curve.  */
typedef struct
{
  gcry_mpi_t p;   /* Prime specifying the field GF(p).  */
  gcry_mpi_t a;   /* First coefficient of the Weierstrass equation.  */
  gcry_mpi_t b;   /* Second coefficient of the Weierstrass equation.  */
  mpi_point_t G;  /* Base point (generator).  */
  gcry_mpi_t n;   /* Order of G.  */
} elliptic_curve_t; 


typedef struct
{
  elliptic_curve_t E;
  mpi_point_t Q;  /* Q = [d]G  */
} ECC_public_key;

typedef struct
{
  elliptic_curve_t E;
  mpi_point_t Q;
  gcry_mpi_t d;
} ECC_secret_key;


/* This static table defines all available curves.  */
static const struct
{
  const char *desc;           /* Description of the curve.  */
  unsigned int nbits;         /* Number of bits.  */
  const char  *p;             /* Order of the prime field.  */
  const char *a, *b;          /* The coefficients. */
  const char *n;              /* The order of the base point.  */
  const char *g_x, *g_y;      /* Base point.  */
} domain_parms[] =
  {
    {
      "NIST P-192", 192,
      "0xfffffffffffffffffffffffffffffffeffffffffffffffff",
      "0xfffffffffffffffffffffffffffffffefffffffffffffffc",
      "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
      "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",

      "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
      "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
    },
    {
      "NIST P-224", 224,
      "0xffffffffffffffffffffffffffffffff000000000000000000000001",
      "0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
      "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
      "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d" ,

      "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
      "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"
    },
    {
      "NIST P-256", 256,
      "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
      "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
      "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",

      "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    },
    {
      "NIST P-384", 384,
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
      "ffffffff0000000000000000ffffffff",
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
      "ffffffff0000000000000000fffffffc",
      "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
      "c656398d8a2ed19d2a85c8edd3ec2aef",
      "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
      "581a0db248b0a77aecec196accc52973",

      "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
      "5502f25dbf55296c3a545e3872760ab7",
      "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
      "0a60b1ce1d7e819d7a431d7c90ea0e5f"
    },
    {
      "NIST P-521", 521,
      "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
      "0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10"
      "9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
      "0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",

      "0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d"
      "baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
      "0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6"
      "62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
    },
    { NULL, 0, NULL, NULL, NULL, NULL }
  };


/* Registered progress function and its callback value. */
static void (*progress_cb) (void *, const char*, int, int, int);
static void *progress_cb_data;


#define point_init(a)  _gcry_mpi_ec_point_init ((a))
#define point_free(a)  _gcry_mpi_ec_point_free ((a))



/* Local prototypes. */
static gcry_mpi_t gen_k (gcry_mpi_t p, int security_level);
static void test_keys (ECC_secret_key * sk, unsigned int nbits);
static int check_secret_key (ECC_secret_key * sk);
static gpg_err_code_t sign (gcry_mpi_t input, ECC_secret_key *skey,
                            gcry_mpi_t r, gcry_mpi_t s);
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




/* Set the value from S into D.  */
static void
point_set (mpi_point_t *d, mpi_point_t *s)
{
  mpi_set (d->x, s->x);
  mpi_set (d->y, s->y);
  mpi_set (d->z, s->z);
}


/*
 * Release a curve object.
 */
static void
curve_free (elliptic_curve_t *E)
{
  mpi_free (E->p); E->p = NULL;
  mpi_free (E->a); E->a = NULL;
  mpi_free (E->b);  E->b = NULL;
  point_free (&E->G);
  mpi_free (E->n);  E->n = NULL;
}


/*
 * Return a copy of a curve object.
 */
static elliptic_curve_t
curve_copy (elliptic_curve_t E)
{
  elliptic_curve_t R;

  R.p = mpi_copy (E.p);
  R.a = mpi_copy (E.a);
  R.b = mpi_copy (E.b);
  point_init (&R.G);
  point_set (&R.G, &E.G);
  R.n = mpi_copy (E.n);

  return R;
}



/* Helper to scan a hex string. */
static gcry_mpi_t
scanval (const char *string)
{
  gpg_error_t err;
  gcry_mpi_t val;

  err = gcry_mpi_scan (&val, GCRYMPI_FMT_HEX, string, 0, NULL);
  if (err)
    log_fatal ("scanning ECC parameter failed: %s\n", gpg_strerror (err));
  return val;
}





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





/* Generate a random secret scalar k with an order of p

   At the beginning this was identical to the code is in elgamal.c.
   Later imporved by mmr.   Further simplified by wk.  */
static gcry_mpi_t
gen_k (gcry_mpi_t p, int security_level)
{
  gcry_mpi_t k;
  unsigned int nbits;

  nbits = mpi_get_nbits (p);
  k = mpi_snew (nbits);
  if (DBG_CIPHER)
    log_debug ("choosing a random k of %u bits\n", nbits);

  gcry_mpi_randomize (k, nbits, security_level);

  mpi_mod (k, k, p);  /*  k = k mod p  */

  return k;
}

/****************
 * Generate the crypto system setup.
 * As of now the fix NIST recommended values are used.
 * The subgroup generator point is in another function: gen_big_point.
 */
static gpg_err_code_t
generate_curve (unsigned int nbits, elliptic_curve_t *curve)
{
  int idx;

  for (idx = 0; domain_parms[idx].desc; idx++)
    if (nbits == domain_parms[idx].nbits)
      break;
  if (!domain_parms[idx].desc)
    return GPG_ERR_INV_VALUE;

  curve->p = scanval (domain_parms[idx].p);
  curve->a = scanval (domain_parms[idx].a);
  curve->b = scanval (domain_parms[idx].b);
  curve->n = scanval (domain_parms[idx].n);
  curve->G.x = scanval (domain_parms[idx].g_x);
  curve->G.y = scanval (domain_parms[idx].g_y);
  curve->G.z = mpi_alloc_set_ui (1);

  return 0;
}


/*
 * First obtain the setup.  Over the finite field randomize an scalar
 * secret value, and calculate the public point.
 */
static gpg_err_code_t
generate_key (ECC_secret_key *sk, unsigned int nbits,
              gcry_mpi_t g_x, gcry_mpi_t g_y,
              gcry_mpi_t q_x, gcry_mpi_t q_y)
{
  gpg_err_code_t err;
  elliptic_curve_t E;
  gcry_mpi_t d;
  mpi_point_t Q, G;
  mpi_ec_t ctx;

  err = generate_curve (nbits, &E);
  if (err)
    return err;

  if (DBG_CIPHER)
    {
      log_mpidump ("ecc generation   p", E.p);
      log_mpidump ("ecc generation   a", E.a);
      log_mpidump ("ecc generation   b", E.b);
      log_mpidump ("ecc generation   n", E.n);
      log_mpidump ("ecc generation  Gx", E.G.x);
      log_mpidump ("ecc generation  Gy", E.G.y);
      log_mpidump ("ecc generation  Gz", E.G.z);
    }

  d = mpi_snew (nbits);
  if (DBG_CIPHER)
    log_debug ("choosing a random x of size %u\n", nbits);
  d = gen_k (E.n, GCRY_VERY_STRONG_RANDOM); 
  point_init (&G);
  point_set (&G, &E.G);

  /* Compute Q.  */
  point_init (&Q);
  ctx = _gcry_mpi_ec_init (E.p, E.a);
  _gcry_mpi_ec_mul_point (&Q, d, &E.G, ctx);

  /* Copy the stuff to the key structures. */
  sk->E.p = mpi_copy (E.p);
  sk->E.a = mpi_copy (E.a);
  sk->E.b = mpi_copy (E.b);
  point_init (&sk->E.G);
  point_set (&sk->E.G, &E.G);
  sk->E.n = mpi_copy (E.n);
  point_init (&sk->Q);
  point_set (&sk->Q, &Q);
  sk->d    = mpi_copy (d);
  /* We also return copies of G and Q in affine coordinates if
     requested.  */
  if (g_x && q_x)
    {
      if (_gcry_mpi_ec_get_affine (g_x, g_y, &sk->E.G, ctx))
        log_fatal ("ecc generate: Failed to get affine coordinates\n");
    }
  if (q_x && q_x)
    {
      if (_gcry_mpi_ec_get_affine (q_x, q_y, &sk->Q, ctx))
        log_fatal ("ecc generate: Failed to get affine coordinates\n");
    }
  _gcry_mpi_ec_free (ctx);

  point_free (&Q);
  mpi_free (d);
  curve_free (&E);

  /* Now we can test our keys (this should never fail!). */
  test_keys (sk, nbits - 64);

  return 0;
}


/****************
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
  mpi_point_t R_;
  gcry_mpi_t c = mpi_new (nbits);
  gcry_mpi_t out = mpi_new (nbits);
  gcry_mpi_t r = mpi_new (nbits);
  gcry_mpi_t s = mpi_new (nbits);

  if (DBG_CIPHER)
    log_debug ("Testing key.\n");

  point_init (&R_);

  pk.E = curve_copy (sk->E);
  point_init (&pk.Q);
  point_set (&pk.Q, &sk->Q);

  gcry_mpi_randomize (test, nbits, GCRY_WEAK_RANDOM);

  if (sign (test, sk, r, s) )
    log_fatal ("ECDSA operation: sign failed\n");

  if (verify (test, &pk, r, s))
    {
      log_fatal ("ECDSA operation: sign, verify failed\n");
    }

  if (DBG_CIPHER)
    log_debug ("ECDSA operation: sign, verify ok.\n");

  point_free (&pk.Q);
  curve_free (&pk.E);

  point_free (&R_);
  mpi_free (s);
  mpi_free (r);
  mpi_free (out);
  mpi_free (c);
  mpi_free (test);
}

/****************
 * To check the validity of the value, recalculate the correspondence
 * between the public value and the secret one.
 */
static int
check_secret_key (ECC_secret_key * sk)
{
  mpi_point_t Q;
  gcry_mpi_t y_2, y2 = mpi_alloc (0);
  mpi_ec_t ctx;

  /* ?primarity test of 'p' */
  /*  (...) //!! */
  /* G in E(F_p) */
  y_2 = gen_y_2 (sk->E.G.x, &sk->E);   /*  y^2=x^3+a*x+b */
  mpi_mulm (y2, sk->E.G.y, sk->E.G.y, sk->E.p);      /*  y^2=y*y */
  if (mpi_cmp (y_2, y2))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: Point 'G' does not belong to curve 'E'!\n");
      return (1);
    }
  /* G != PaI */
  if (!mpi_cmp_ui (sk->E.G.z, 0))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: 'G' cannot be Point at Infinity!\n");
      return (1);
    }

  point_init (&Q);
  ctx = _gcry_mpi_ec_init (sk->E.p, sk->E.a);
  _gcry_mpi_ec_mul_point (&Q, sk->E.n, &sk->E.G, ctx);
  if (mpi_cmp_ui (Q.z, 0))
    {
      if (DBG_CIPHER)
        log_debug ("check_secret_key: E is not a curve of order n\n");
      point_free (&Q);
      _gcry_mpi_ec_free (ctx);
      return 1;
    }
  /* pubkey cannot be PaI */
  if (!mpi_cmp_ui (sk->Q.z, 0))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: Q can not be a Point at Infinity!\n");
      _gcry_mpi_ec_free (ctx);
      return (1);
    }
  /* pubkey = [d]G over E */
  _gcry_mpi_ec_mul_point (&Q, sk->d, &sk->E.G, ctx);
  if ((Q.x == sk->Q.x) && (Q.y == sk->Q.y) && (Q.z == sk->Q.z))
    {
      if (DBG_CIPHER)
        log_debug
          ("Bad check: There is NO correspondence between 'd' and 'Q'!\n");
      _gcry_mpi_ec_free (ctx);
      return (1);
    }
  _gcry_mpi_ec_free (ctx);
  point_free (&Q);
  return 0;
}


/*
 * Return the signature struct (r,s) from the message hash.  The caller
 * must have allocated R and S.
 */
static gpg_err_code_t
sign (gcry_mpi_t input, ECC_secret_key *skey, gcry_mpi_t r, gcry_mpi_t s)
{
  gpg_err_code_t err = 0;
  gcry_mpi_t k, dr, sum, k_1, x;
  mpi_point_t I;
  mpi_ec_t ctx;

  k = NULL;
  dr = mpi_alloc (0);
  sum = mpi_alloc (0);
  k_1 = mpi_alloc (0);
  x = mpi_alloc (0);
  point_init (&I);

  mpi_set_ui (s, 0);
  mpi_set_ui (r, 0);

  ctx = _gcry_mpi_ec_init (skey->E.p, skey->E.a);

  while (!mpi_cmp_ui (s, 0)) /* s == 0 */
    {
      while (!mpi_cmp_ui (r, 0)) /* r == 0 */
        {
          /* Note, that we are guaranteed to enter this loop at least
             once because r has been intialized to 0.  We can't use a
             do_while because we want to keep the value of R even if S
             has to be recomputed.  */
          mpi_free (k);
          k = gen_k (skey->E.n, GCRY_STRONG_RANDOM);
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
      mpi_addm (sum, input, dr, skey->E.n); /* sum = hash + (d*r) mod n  */
      mpi_invm (k_1, k, skey->E.n);         /* k_1 = k^(-1) mod n  */
      mpi_mulm (s, k_1, sum, skey->E.n);    /* s = k^(-1)*(hash+(d*r)) mod n */
    }

 leave:
  _gcry_mpi_ec_free (ctx);
  point_free (&I);
  mpi_free (x);
  mpi_free (k_1);
  mpi_free (sum);
  mpi_free (dr);
  mpi_free (k);

  return err;
}

/*
 * Check if R and S verifies INPUT.
 */
static gpg_err_code_t
verify (gcry_mpi_t input, ECC_public_key *pkey, gcry_mpi_t r, gcry_mpi_t s)
{
  gpg_err_code_t err = 0;
  gcry_mpi_t h, h1, h2, x, y;
  mpi_point_t Q, Q1, Q2;
  mpi_ec_t ctx;

  if( !(mpi_cmp_ui (r, 0) > 0 && mpi_cmp (r, pkey->E.n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < r < n  failed.  */
  if( !(mpi_cmp_ui (s, 0) > 0 && mpi_cmp (s, pkey->E.n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < s < n  failed.  */

  h  = mpi_alloc (0);
  h1 = mpi_alloc (0);
  h2 = mpi_alloc (0);
  x = mpi_alloc (0);
  y = mpi_alloc (0);
  point_init (&Q);
  point_init (&Q1);
  point_init (&Q2);

  ctx = _gcry_mpi_ec_init (pkey->E.p, pkey->E.a);

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
  if (_gcry_mpi_ec_get_affine (x, y, &Q, ctx))
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
        log_debug ("ecc verify: Not verified\n");
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
  mpi_free (y);
  mpi_free (x);
  mpi_free (h2);
  mpi_free (h1);
  mpi_free (h);
  return err;
}



/*********************************************
 **************  interface  ******************
 *********************************************/
static gcry_mpi_t
ec2os (gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t p)
{
  gpg_error_t err;
  int pbytes = (mpi_get_nbits (p)+7)/8;
  size_t n;
  unsigned char *buf, *ptr;
  gcry_mpi_t result;

  buf = gcry_xmalloc ( 1 + 2*pbytes );
  *buf = 04; /* Uncompressed point.  */
  ptr = buf+1;
  err = gcry_mpi_print (GCRYMPI_FMT_USG, ptr, pbytes, &n, x);
  if (err)
    log_fatal ("mpi_print failed: %s\n", gpg_strerror (err));
  if (n < pbytes)
    {
      memmove (ptr+(pbytes-n), buf+1, n);
      memset (ptr, 0, (pbytes-n));
    }
  ptr += pbytes;
  err = gcry_mpi_print (GCRYMPI_FMT_USG, ptr, pbytes, &n, y);
  if (err)
    log_fatal ("mpi_print failed: %s\n", gpg_strerror (err));
  if (n < pbytes)
    {
      memmove (ptr+(pbytes-n), buf+1, n);
      memset (ptr, 0, (pbytes-n));
    }
  
  err = gcry_mpi_scan (&result, GCRYMPI_FMT_USG, buf, 1+2*pbytes, NULL);
  if (err)
    log_fatal ("mpi_scan failed: %s\n", gpg_strerror (err));
  gcry_free (buf);

  mpi_free (x);
  mpi_free (y);

  return result;
}

/* RESULT must have been initialized and is set on success to the
   point given by VALUE.  */
static gcry_error_t
os2ec (mpi_point_t *result, gcry_mpi_t value)
{
  gcry_error_t err;
  size_t n;
  unsigned char *buf;
  gcry_mpi_t x, y;

  n = (mpi_get_nbits (value)+7)/8;
  buf = gcry_xmalloc (n);
  err = gcry_mpi_print (GCRYMPI_FMT_USG, buf, n, &n, value);
  if (err)
    {
      gcry_free (buf);
      return err;
    }
  if (n < 1) 
    {
      gcry_free (buf);
      return GPG_ERR_INV_OBJ;
    }
  if (*buf != 4)
    {
      gcry_free (buf);
      return GPG_ERR_NOT_IMPLEMENTED; /* No support for point compression.  */
    }
  if ( ((n-1)%2) ) 
    {
      gcry_free (buf);
      return GPG_ERR_INV_OBJ;
    }
  n = (n-1)/2;
  err = gcry_mpi_scan (&x, GCRYMPI_FMT_USG, buf+1, n, NULL);
  if (err)
    {
      gcry_free (buf);
      return err;
    }
  err = gcry_mpi_scan (&y, GCRYMPI_FMT_USG, buf+1+n, n, NULL);
  gcry_free (buf);
  if (err)
    {
      mpi_free (x);
      return err;
    }

  mpi_set (result->x, x);
  mpi_set (result->y, y);
  mpi_set_ui (result->z, 1);

  mpi_free (x);
  mpi_free (y);
  
  return 0;
}

static gcry_err_code_t
ecc_generate (int algo, unsigned int nbits, unsigned long dummy,
              gcry_mpi_t *skey, gcry_mpi_t **retfactors)
{
  gpg_err_code_t err;
  ECC_secret_key sk;
  gcry_mpi_t g_x, g_y, q_x, q_y;

  (void)algo;

  /* Make an empty list of factors.  */
  *retfactors = gcry_calloc ( 1, sizeof **retfactors );
  if (!*retfactors)
    return gpg_err_code_from_syserror ();

  g_x = mpi_new (0);
  g_y = mpi_new (0);
  q_x = mpi_new (0);
  q_y = mpi_new (0);
  err = generate_key (&sk, nbits, g_x, g_y, q_x, q_y);
  if (err)
    {
      gcry_free (*retfactors);
      *retfactors = NULL;
      return err;
    }

  skey[0] = sk.E.p;
  skey[1] = sk.E.a;
  skey[2] = sk.E.b;
  skey[3] = ec2os (g_x, g_y, sk.E.p);
  skey[4] = sk.E.n;
  skey[5] = ec2os (q_x, q_y, sk.E.p);
  skey[6] = sk.d;

  return 0;
}


static gcry_err_code_t
ecc_check_secret_key (int algo, gcry_mpi_t *skey)
{
  gpg_err_code_t err;
  ECC_secret_key sk;

  (void)algo;

  if (!skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4] || !skey[5]
      || !skey[6] || !skey[7] || !skey[8] || !skey[9] || !skey[10])
    return GPG_ERR_BAD_MPI;

  sk.E.p = skey[0];
  sk.E.a = skey[1];
  sk.E.b = skey[2];
  point_init (&sk.E.G);
  err = os2ec (&sk.E.G, skey[3]);
  if (err)
    {
      point_free (&sk.E.G);
      return err;
    }
  sk.E.n = skey[4];
  point_init (&sk.Q);
  err = os2ec (&sk.Q, skey[5]);
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
ecc_sign (int algo, gcry_mpi_t *resarr, gcry_mpi_t data, gcry_mpi_t *skey)
{
  gpg_err_code_t err;
  ECC_secret_key sk;

  (void)algo;

  if (!data || !skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4]
      || !skey[5] || !skey[6] )
    return GPG_ERR_BAD_MPI;

  sk.E.p = skey[0];
  sk.E.a = skey[1];
  sk.E.b = skey[2];
  point_init (&sk.E.G);
  err = os2ec (&sk.E.G, skey[3]);
  if (err)
    {
      point_free (&sk.E.G);
      return err;
    }
  sk.E.n = skey[4];
  point_init (&sk.Q);
  err = os2ec (&sk.Q, skey[5]);
  if (err)
    {
      point_free (&sk.E.G);
      point_free (&sk.Q);
      return err;
    }
  sk.d = skey[6];

  resarr[0] = mpi_alloc (mpi_get_nlimbs (sk.E.p));
  resarr[1] = mpi_alloc (mpi_get_nlimbs (sk.E.p));
  err = sign (data, &sk, resarr[0], resarr[1]);
  if (err)
    {
      mpi_free (resarr[0]);
      mpi_free (resarr[1]);
      resarr[0] = NULL; /* Mark array as released.  */
    }
  point_free (&sk.E.G);
  point_free (&sk.Q);
  return err;
}

static gcry_err_code_t
ecc_verify (int algo, gcry_mpi_t hash, gcry_mpi_t *data, gcry_mpi_t *pkey,
            int (*cmp)(void *, gcry_mpi_t), void *opaquev)
{
  gpg_err_code_t err;
  ECC_public_key pk;

  (void)algo;

  if (!data[0] || !data[1] || !hash || !pkey[0] || !pkey[1] || !pkey[2]
      || !pkey[3] || !pkey[4] || !pkey[5] )
    return GPG_ERR_BAD_MPI;

  pk.E.p = pkey[0];
  pk.E.a = pkey[1];
  pk.E.b = pkey[2];
  point_init (&pk.E.G);
  err = os2ec (&pk.E.G, pkey[3]);
  if (err)
    {
      point_free (&pk.E.G);
      return err;
    }
  pk.E.n = pkey[4];
  point_init (&pk.Q);
  err = os2ec (&pk.Q, pkey[5]);
  if (err)
    {
      point_free (&pk.E.G);
      point_free (&pk.Q);
      return err;
    }

  err = verify (hash, &pk, data[0], data[1]);

  point_free (&pk.E.G);
  point_free (&pk.Q);
  return err;
}



static unsigned int
ecc_get_nbits (int algo, gcry_mpi_t *pkey)
{
  (void)algo;

  return mpi_get_nbits (pkey[0]);
}


static const char *ecdsa_names[] =
  {
    "ecdsa",
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

