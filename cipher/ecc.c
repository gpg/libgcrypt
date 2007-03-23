/* ecc.c  -  ECElGamal Public Key encryption & ECDSA signature algorithm
 * Copyright (C) 2004, 2005, 2006, 2007 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA. 
 */

/* TODO wk

  - Check whether we can LGPL the code.

  - Use affine coordinates for points with the public API and format
    them in the way described by BSI's TR-03111, 5.1.3.

  - If we support point compression we need to decide how to compute
    the keygrip it should not change due to compression.

  - mpi_mulm is quite slow which has never been a problem for the
    other algorithms.  However here we are using it several times in a
    row and thus it is an important performance factor.

  - We use mpi_powm for x^2 mod p: Either implement a special case in
    mpi_powm or check whether mpi_mulm is faster.



Algorithm       generate  100*sign  100*verify
----------------------------------------------
Orginal version:
ECDSA 192 bit      100ms    2630ms      5040ms
ECDSA 256 bit      120ms    2960ms      6070ms
ECDSA 384 bit      370ms    9570ms     18900ms

Using Barrett:
ECDSA 192 bit      130ms    3050ms      5620ms
ECDSA 256 bit      140ms    3410ms      6950ms
ECDSA 384 bit      400ms   10500ms     21670ms


*/

/* This code is a based on the 
 * Patch 0.1.6 for the gnupg 1.4.x branch
 * as retrieved on 2007-03-21 from
 * http://www.calcurco.cat/eccGnuPG/src/gnupg-1.4.6-ecc0.2.0beta1.diff.bz2
 *
 * Written by 
 *  Sergi Blanch i Torne <d4372211 at alumnes.eup.udl.es>, 
 *  Ramiro Moreno Chiral <ramiro at eup.udl.es>
 * Maintainers
 *  Sergi Blanch i Torne
 *  Ramiro Moreno Chiral
 *  Mikael Mylnikov (mmr)
 */

/*
 * This module are under development, it would not have to be used 
 * in a production environments. It can have bugs!
 * 
 * Made work:
 *  alex: found a bug over the passphrase.
 *  mmr: signature bug found and solved (afine conversion).
 *  mmr: found too many mistakes in the mathematical background transcription.
 *  mmr: improve the mathematical performance.
 *  mmr: solve ECElGamal IFP weakness.
 *       more polite gen_k() and its calls.
 *  mmr: extend the check_secret_key()
 * In progress:
 *  gen_big_point(): Randomize the point generation.
 *  improve te memory uses.
 *  Separation between sign & encrypt keys to facility the subkeys creation.
 *  read & reread the code in a bug search!
 * To do:
 *  2-isogeny: randomize the elliptic curves.
 *  E(F_{2^m})
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"


/* 
    ECC over F_p; E(F_p)
    T=(p,a,b,G,n,h)
             p:    big odd number
             a,b:  curve generators
             G:    Subgroup generator point
             n:    big int, in G order
             h:    cofactor
     y^2=x^3+ax+b --> (Y^2)Z=X^3+aX(Z^2)+b(Z^3)
    
    
             Q=[d]G, 1<=d<=n-1
*/


/* An object to hold a computation context.  */
struct ecc_ctx_s
{
  gcry_mpi_t m;   /* The modulus - may not be modified. */
  int m_copied;   /* If true, M needs to be released.  */
};
typedef struct ecc_ctx_s *ecc_ctx_t;


/* Point representation in projective coordinates. */
typedef struct
{
  gcry_mpi_t x_;
  gcry_mpi_t y_;
  gcry_mpi_t z_;
} point_t;


/* Definition of a curve.  */
typedef struct
{
  gcry_mpi_t p_;  /* Prime specifying the field GF(p).  */
  gcry_mpi_t a_;  /* First coefficient of the Weierstrass equation.  */
  gcry_mpi_t b_;  /* Second coefficient of teh Weierstrass equation.  */
  point_t G;      /* Base point (generator).  */
  gcry_mpi_t n_;  /* Order of G.  */
  /*gcry_mpi_t h_; =1  fixme: We will need to change this value in 2-isogeny */
} elliptic_curve_t;             /* Fixme: doubtful name */


typedef struct
{
  elliptic_curve_t E;
  point_t Q;                    /* Q=[d]G */
} ECC_public_key;               /* Q */

typedef struct
{
  elliptic_curve_t E;
  point_t Q;                    /* Q=[d]G */
  gcry_mpi_t d;
} ECC_secret_key;               /* d */


/* This static table defines all available curves.  */
static const struct
{
  const char *desc;           /* Description of the curve.  */
  unsigned int nbits;         /* Number of bits.  */
  const char  *p, *a, *b, *n; /* Parameters.  */
  const char *g_x, *g_y;      /* G_z is always 1.  */
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




/* Local prototypes. */
static gcry_mpi_t gen_k (gcry_mpi_t p, int secure);
static void test_keys (ECC_secret_key * sk, unsigned int nbits);
static int check_secret_key (ECC_secret_key * sk);
static gpg_err_code_t sign (gcry_mpi_t input, ECC_secret_key *skey, 
                            gcry_mpi_t r, gcry_mpi_t s);
static gpg_err_code_t verify (gcry_mpi_t input, ECC_public_key *pkey,
                              gcry_mpi_t r, gcry_mpi_t s);


static int point_at_infinity (point_t query);

static gcry_mpi_t gen_y_2 (gcry_mpi_t x, elliptic_curve_t * base);




void
_gcry_register_pk_ecc_progress (void (*cb) (void *, const char *,
                                            int, int, int),
                                void *cb_data)
{
  progress_cb = cb;
  progress_cb_data = cb_data;
}

static void
progress (int c)
{
  if (progress_cb)
    progress_cb (progress_cb_data, "pk_dsa", c, 0, 0);
  else
    fputc (c, stderr);
}


/*

    M P I  W R A P P E R

 */

static ecc_ctx_t 
ecc_ctx_init (gcry_mpi_t m, int copy)
{
  ecc_ctx_t ctx;

  ctx = gcry_xcalloc (1, sizeof *ctx);

  if (copy)
    {
      ctx->m = mpi_copy (m);
      ctx->m_copied = 1;
    }
  else
    ctx->m = m;

  return ctx;
}

static void
ecc_ctx_free (ecc_ctx_t ctx)
{
  if (!ctx)
    return;
  if (ctx->m_copied)
    mpi_free (ctx->m);
  gcry_free (ctx);
}

/* Our version of mpi_mod which uses a reduction algorithm depending
   on the the context.  The modulus is part of the context. */
static void
ecc_mod (gcry_mpi_t r, gcry_mpi_t x, ecc_ctx_t ctx)
{
  mpi_mod (r, x, ctx->m);
}

/* Our version of mpi_mulm which uses a reduction algorithm depending
   on the the context.  The modulus is part of the context. */
static void
ecc_mulm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, ecc_ctx_t ctx)
{
  /* Barrett is actually slower, so we don't do any switching here.
     Howerver, we should take advantage of fast reduction for the NIST
     curves.  */
  mpi_mulm (w, u, v, ctx->m);
}




/*

    O B J E C T   M A I N T E N A N C E

 */

/* Intialize a point object, so that its elements may be sued directly
   as MPI functions.  point_free is required for each initialzied
   point. */
static void
point_init (point_t *P)
{
  P->x_ = mpi_new (0);
  P->y_ = mpi_new (0);
  P->z_ = mpi_new (0);
}


/*
 * Release a point object.
 */
static void
point_free (point_t *P)
{
  mpi_free (P->x_); P->x_ = NULL;
  mpi_free (P->y_); P->y_ = NULL;
  mpi_free (P->z_); P->z_ = NULL;
}


/*
 * Return a copy of a point object.
 */
static point_t
point_copy (point_t P)
{
  point_t R;

  R.x_ = mpi_copy (P.x_);
  R.y_ = mpi_copy (P.y_);
  R.z_ = mpi_copy (P.z_);

  return R;
}


/*
 * Release a curve object.
 */
static void
curve_free (elliptic_curve_t *E)
{
  mpi_free (E->p_); E->p_ = NULL;
  mpi_free (E->a_); E->a_ = NULL;
  mpi_free (E->b_);  E->b_ = NULL;
  point_free (&E->G);
  mpi_free (E->n_);  E->n_ = NULL;
}


/*
 * Return a copy of a curve object.
 */
static elliptic_curve_t
curve_copy (elliptic_curve_t E)
{
  elliptic_curve_t R;

  R.p_ = mpi_copy (E.p_);
  R.a_ = mpi_copy (E.a_);
  R.b_ = mpi_copy (E.b_);
  R.G  = point_copy (E.G);
  R.n_ = mpi_copy (E.n_);

  return R;
}



/*

    A D D I T I O N A L   M P I   F U N C T I O N S

 */


/****************
 * Find, if it exist, the square root of one integer modulo a big prime.
 * Return the square root or NULL if it is not found.
 */
#if 0
static gcry_mpi_t
exist_square_root (gcry_mpi_t integer, gcry_mpi_t modulus)
{
  unsigned long int i = 0;
  gcry_mpi_t one, two, three, four, five, eight;
  gcry_mpi_t k, r, z, k1;
  gcry_mpi_t t1, t2, t3, t4;

  one = mpi_alloc_set_ui (1);
  two = mpi_alloc_set_ui (2);
  three = mpi_alloc_set_ui (3);
  four = mpi_alloc_set_ui (4);
  five = mpi_alloc_set_ui (5);
  eight = mpi_alloc_set_ui (8);
  k = mpi_alloc (mpi_get_nlimbs (modulus));
  r = mpi_alloc (mpi_get_nlimbs (modulus));
  z = mpi_alloc (mpi_get_nlimbs (modulus));
  k1 = mpi_alloc (mpi_get_nlimbs (modulus));
  t1 = mpi_alloc (mpi_get_nlimbs (modulus));
  t2 = mpi_alloc (mpi_get_nlimbs (modulus));
  t3 = mpi_alloc (mpi_get_nlimbs (modulus));
  t4 = mpi_alloc (mpi_get_nlimbs (modulus));

  if (DBG_CIPHER)
    log_mpidump ("?exist Square Root of ", integer);

  mpi_fdiv_qr (k, r, modulus, four);
  if (mpi_cmp (r, three))
    {                           /* p=3 (mod 4) */
      mpi_addm (k1, k, one, modulus);
      mpi_powm (z, integer, k1, modulus);
      if (DBG_CIPHER)
        {
          log_mpidump ("z=", z);
        }
      return z;                 /* value found */
    }
  mpi_fdiv_qr (k, r, modulus, eight);
  if (mpi_cmp (r, five))
    {                           /* p=5 (mod 8) */
      mpi_mulm (t1, two, integer, modulus);
      mpi_powm (t2, t1, k, modulus);
      mpi_powm (t2, t2, two, modulus);
      mpi_mulm (t2, t1, t2, modulus);
      mpi_mulm (t3, integer, t1, modulus);
      mpi_subm (t4, t2, one, modulus);
      mpi_mulm (z, t3, t4, modulus);
      if (DBG_CIPHER)
        {
          log_mpidump ("z=", z);
        }
      return z;                 /* value found */
    }
  if (mpi_cmp (r, one))
    {                           /* p=1 (mod 8) */
      while (i < 0xFF)
        {                       /* while not find z after 256 iterations */
          if (DBG_CIPHER)
            log_debug ("Square root bucle.\n");
          t1 = mpi_copy (integer);
          t2 = gen_k (modulus, 0);
          mpi_add_ui (t3, modulus, 1);  /* t3=p+1 */
          mpi_rshift (t3, t3, 1);       /* t3=t3/2 */
          lucas (t1, t2, t3, modulus, t4, t3);  /* t4=V_k */
          mpi_rshift (z, t4, 1);        /* z=V/2 */
          mpi_sub_ui (t3, modulus, 1);  /* t3=p-1 */
          mpi_rshift (t4, t3, 2);       /* t4=t3/2 */
          lucas (t1, t2, t4, modulus, t4, t1);  /* t1=Q_0 */
          mpi_powm (t2, z, two, modulus);       /* t2=z^2 */
          if (mpi_cmp (t1, integer))
            {
              if (DBG_CIPHER)
                {
                  log_mpidump ("z=", z);
                }
              return z;         /* value found */
            }
          if (t4 > mpi_alloc_set_ui (1) && t4 < t3)
            {
              if (DBG_CIPHER)
                log_debug ("Rejected.\n");
              return (0);       /* NULL */
            }
          if (DBG_CIPHER)
            log_debug ("Another loop.\n");
        }
    }
  if (DBG_CIPHER)
    log_debug ("iterations limit.\n");
  return (0);                   /* because this algorithm not always finish. */
}
#endif /*0*/

/****************
 * Formal definition:
 * V_0 = 2; V_1 = p
 * V_k = (p*V_(k-1)) - (q*V_(k-2))   for k >= 2
 */
#if 0
static void
lucas (gcry_mpi_t n, gcry_mpi_t p_, gcry_mpi_t q_,
       gcry_mpi_t k, gcry_mpi_t V_n, gcry_mpi_t Q_0)
{

  gcry_mpi_t v0, v1, q0, q1;
  gcry_mpi_t t1, t2;
  unsigned int r, i;

  v0 = mpi_alloc_set_ui (2);
  v1 = mpi_copy (p_);
  q0 = mpi_alloc_set_ui (1);
  q1 = mpi_alloc_set_ui (1);
  t1 = mpi_alloc_set_ui (0);
  t2 = mpi_alloc_set_ui (0);

  if (DBG_CIPHER)
    {
      log_debug ("Generating lucas sequence.\n");
      log_mpidump ("k=", k);
    }

  r = mpi_get_nbits (k) - 1;
  i = 0;
  while (mpi_test_bit (k, i) != 1)
    {                           /* search the first bit with value '1' */
      i++;
    }
  while (i < r)
    {
      if (DBG_CIPHER)
        {
          log_debug ("Lucas sequence bucle.\n");
          log_mpidump ("i=", mpi_alloc_set_ui (i));
          log_mpidump ("r=", mpi_alloc_set_ui (r));
        }
      mpi_mulm (q0, q0, q1, n);
      if (mpi_test_bit (k, i) == 1)
        {
          mpi_mulm (q1, q0, q_, n);
          mpi_mul (t1, v0, v1);
          mpi_mul (t2, p_, q0);
          mpi_subm (v0, t1, t2, n);
          mpi_powm (t1, v1, mpi_alloc_set_ui (2), n);
          mpi_mul (t2, mpi_alloc_set_ui (2), q1);
          mpi_subm (v1, t1, t2, n);
        }
      else
        {
          q1 = mpi_copy (q0);
          mpi_mul (t1, v0, v1);
          mpi_mul (t2, p_, q0);
          mpi_subm (v1, t1, t2, n);
          mpi_powm (t1, v0, mpi_alloc_set_ui (2), n);
          mpi_mul (t2, mpi_alloc_set_ui (2), q0);
          mpi_subm (v0, t1, t2, n);
        }
      i++;
    }
  V_n = mpi_copy (v0);
  Q_0 = mpi_copy (q0);
  if (DBG_CIPHER)
    {
      log_debug ("Lucas sequence generated.\n");
      log_mpidump ("V_n=", V_n);
      log_mpidump ("Q_0=", Q_0);
    }
}
#endif /*0*/


/* 

   P O I N T   A N D   C U R V E   O P E R A T I O N S

 */

/* fixme:
 * The point at infinity is needed to make 
 * a group structure to the elliptic curve.
 * Know if one point is it, is needed so 
 * much times in this code.
 *
 *  return true(1), false(0), or error(-1) for an invalid point
 */
static int
point_at_infinity (point_t query)
{
  if (!mpi_cmp_ui (query.z_, 0)) /* Z == 0 */
    {
      if ( /*mpi_cmp_ui(Query.x_,0) && */ mpi_cmp_ui (query.y_, 0))
        {
          /* X && Y != 0 & Z == 0 */
          /* Fixme: The above condition is not asserted.  We may get
             to here if X is 0 ! */
          if (DBG_CIPHER)
            log_debug ("True:It is a Point at Infinite.\n");
          return 1;
        }
      if (DBG_CIPHER)
        log_debug ("Error:It isn't an elliptic curve valid point.\n");
      return -1;
    }
  return 0;  /* It is a valid curve point, but not the point at infinity.  */
}


/*
 * Turn a projective coordinate P to affine.
 * Returns 0 on success and the affine coordinates at X and Y.
 *
 * Note, that Y is never used as we can do without it.
 */
static int
point_affine (point_t *P, gcry_mpi_t x, gcry_mpi_t y, elliptic_curve_t *base)
{
  gcry_mpi_t z1, z2, z3;

  if (point_at_infinity (*P))
    {
      if (DBG_CIPHER)
        log_debug ("ecc point_affine: "
                   "Point at Infinity does NOT exist in the affine plane!\n");
      return 1;
    }

  z1 = mpi_new (0);
  z2 = mpi_new (0);
  z3 = mpi_new (0);

  mpi_invm (z1, P->z_, base->p_);       /*       z1 =Z^{-1} (mod p) */
  mpi_mulm (z2, z1, z1, base->p_);      /*       z2 =Z^(-2) (mod p) */
  mpi_mulm (z3, z2, z1, base->p_);      /*       z3 =Z^(-3) (mod p) */
  mpi_mulm (x, P->x_, z2, base->p_);
  mpi_mulm (y, P->y_, z3, base->p_);

  mpi_free (z1);
  mpi_free (z2);
  mpi_free (z3);
  return 0;
}


/*
 * The point inversion over F_p is a simple modular inversion of the Y
 * coordinate.
 */
static void
invert_point (point_t *P, elliptic_curve_t *base)
{
  mpi_subm (P->y_, base->p_, P->y_, base->p_);  /* y = p - y mod p */
}


/*
 * Scalar multiplication of one point, with the integer fixed to 2.
 *  R = 2P
 */
static void
duplicate_point (point_t *R, point_t *P, elliptic_curve_t *base,
                 ecc_ctx_t pctx)
{
  gcry_mpi_t one, two, three, four, eight;
  gcry_mpi_t p_3, a;
  gcry_mpi_t t1, t2, t3, t4, t5, t6, t7;
  gcry_mpi_t aux;

  one = mpi_alloc_set_ui (1);
  two = mpi_alloc_set_ui (2);
  three = mpi_alloc_set_ui (3);
  four = mpi_alloc_set_ui (4);
  eight = mpi_alloc_set_ui (8);

  p_3 = mpi_alloc_like (base->p_);
  mpi_sub_ui (p_3, base->p_, 3);      /* p_3 = p - 3 */

  a  = mpi_copy (base->a_);
  t1 = mpi_alloc_like (base->p_);
  t2 = mpi_alloc_like (base->p_);
  t3 = mpi_alloc_like (base->p_);
  t4 = mpi_alloc_like (base->p_);
  t5 = mpi_alloc_like (base->p_);
  t6 = mpi_alloc_like (base->p_);
  t7 = mpi_alloc_like (base->p_);
  aux = mpi_alloc_like (base->p_);

  t1 = mpi_copy (P->x_);        /* t1=x1 */
  t2 = mpi_copy (P->y_);        /* t2=y1 */
  t3 = mpi_copy (P->z_);        /* t3=z1 */

  if (!mpi_cmp_ui (t2, 0) || !mpi_cmp_ui (t3, 0))
    {                           /* t2==0 | t3==0 => [1:1:0] */
      mpi_set_ui (R->x_, 1);
      mpi_set_ui (R->y_, 1);
      mpi_set_ui (R->z_, 0);
    }
  else
    {
      ecc_mod (a, a, pctx);        /* a mod p  FIXME: really needed? */
      if (!mpi_cmp (a, p_3))
        {                       /* a==p-3 */
          mpi_powm (t4, t3, two, base->p_);    /* t4=t3^2 mod p */
          mpi_subm (t5, t1, t4, base->p_);     /* t5=t1-t4 mod p */
          mpi_addm (t4, t1, t4, base->p_);     /* t4=t1+t4 mod p */
          ecc_mulm (t5, t4, t5, pctx);     /* t5=t4*t5 mod p */
          ecc_mulm (t4, three, t5, pctx);  /* t4=3*t5 mod p */
        }
      else
        {
          mpi_set (t4, a);              /* t4=a */
          mpi_powm (t5, t3, two, base->p_);    /* t5=t3^2 mod p */
          mpi_powm (t5, t5, two, base->p_);    /* t5=t5^2 mod p */
          ecc_mulm (t5, t4, t5, pctx);     /* t5=t4*t5 mod p */
          mpi_powm (t4, t1, two, base->p_);    /* t4=t1^2 mod p */
          ecc_mulm (t4, three, t4, pctx);  /* t4=3*t4 mod p */
          mpi_addm (t4, t4, t5, base->p_);     /* t4=t4+t5 mod p */
        }
      ecc_mulm (t3, t2, t3, pctx);         /* t3=t2*t3 mod p */
      ecc_mulm (t3, two, t3, pctx);        /* t3=2*t3 mod p  */
      mpi_powm (aux, t2, two, base->p_);       /* t2=t2^2 mod p */
      mpi_set (t2, aux);
      ecc_mulm (t5, t1, t2, pctx);         /* t5=t1*t2 mod p */
      ecc_mulm (t5, four, t5, pctx);       /* t5=4*t5 mod p */
      mpi_powm (t1, t4, two, base->p_);        /* t1=t4^2 mod p */
      ecc_mulm (aux, two, t5, pctx);
      mpi_subm (t1, t1, aux, base->p_);        /* t1=t1-2*t5 mod p */
      mpi_powm (aux, t2, two, base->p_);       /* t2=t2^2 mod p */
      mpi_set (t2, aux);
      ecc_mulm (t2, eight, t2, pctx);      /* t2=8*t2 mod p */
      mpi_subm (t5, t5, t1, base->p_); /* t5=t5-t1 mod p */
      ecc_mulm (t5, t4, t5, pctx); /* t5=t4*t5 mod p */
      mpi_subm (t2, t5, t2, base->p_); /* t2=t5-t2 mod p */

      mpi_set (R->x_, t1);
      mpi_set (R->y_, t2);
      mpi_set (R->z_, t3);
    }

  mpi_free (aux);
  mpi_free (t7);
  mpi_free (t6);
  mpi_free (t5);
  mpi_free (t4);
  mpi_free (t3);
  mpi_free (t2);
  mpi_free (t1);
  mpi_free (p_3);
  mpi_free (a);
  mpi_free (eight);
  mpi_free (four);
  mpi_free (three);
  mpi_free (two);
  mpi_free (one);
}


/*
   Point addition is the group operation.

   R = P0 + P1
 */
static void
sum_points (point_t *R, point_t *P0, point_t *P1, elliptic_curve_t *base,
            ecc_ctx_t pctx)
{

  if ( (!mpi_cmp (P1->x_, P0->x_))
       && (!mpi_cmp (P1->y_, P0->y_))
       && (!mpi_cmp (P1->z_, P0->z_)) ) /* P1 == P0 */
    {                           
      duplicate_point (R, P0, base, pctx);
    }
  else if (point_at_infinity (*P0)) /* R == 0 && P1 == P1 */
    {                           
      mpi_set (R->x_, P1->x_);
      mpi_set (R->y_, P1->y_);
      mpi_set (R->z_, P1->z_);
    }
  else if (point_at_infinity (*P1)) /* R == P0 && P0 == 0 */
    {           
      mpi_set (R->x_, P0->x_);
      mpi_set (R->y_, P0->y_);
      mpi_set (R->z_, P0->z_);
    }
  else
    {
      gcry_mpi_t two;
      gcry_mpi_t t1, t2, t3, t4, t5, t6, t7;

      two = mpi_alloc_set_ui (2);

      t1 = mpi_copy (P0->x_);   /* t1=x0 */
      t2 = mpi_copy (P0->y_);   /* t2=y0 */
      t3 = mpi_copy (P0->z_);   /* t3=z0 */
      t4 = mpi_copy (P1->x_);   /* t4=x1 */
      t5 = mpi_copy (P1->y_);   /* t5=y2 */
      t6 = mpi_new (0);
      t7 = mpi_new (0);

      if (mpi_cmp_ui (P1->z_, 1))  /* z1 != 1 */
        {                       
          mpi_set (t6, P1->z_);         /* t6=z1 */
          mpi_powm (t7, t6, two, base->p_);    /* t7=t6^2 mod p */
          ecc_mulm (t1, t1, t7, pctx);     /* t1=t1*t7 mod p */
          ecc_mulm (t7, t6, t7, pctx);     /* t7=t6*t7 mod p */
          ecc_mulm (t2, t2, t7, pctx);     /* t2=t2*t7 mod p */
        }
      mpi_powm (t7, t3, two, base->p_);/* t7=t3^2 mod p */
      ecc_mulm (t4, t4, t7, pctx); /* t4=t4*t7 mod p */
      ecc_mulm (t7, t3, t7, pctx); /* t7=t3*t7 mod p */
      ecc_mulm (t5, t5, t7, pctx); /* t5=t5*t7 mod p */
      mpi_subm (t4, t1, t4, base->p_); /* t4=t1-t4 mod p */
      mpi_subm (t5, t2, t5, base->p_); /* t5=t2-t5 mod p */

      if (!mpi_cmp_ui (t4, 0)) /* t4==0 */
        {                       
          if (!mpi_cmp_ui (t5, 0))
            {                   
              /* return (0:0:0), it has a special mean. */
              if (DBG_CIPHER)
                log_debug ("ecc sum_points: [0:0:0]!\n");
              mpi_set_ui (R->x_, 0);
              mpi_set_ui (R->y_, 0);
              mpi_set_ui (R->z_, 0);
            }
          else
            {           
              if (DBG_CIPHER)
                log_debug ("ecc sum_points: [1:1:0]!\n");
              mpi_set_ui (R->x_, 1);
              mpi_set_ui (R->y_, 1);
              mpi_set_ui (R->z_, 0);
            }
        }
      else
        {
          ecc_mulm (t1, two, t1, pctx);
          mpi_subm (t1, t1, t4, base->p_);     /* t1=2*t1-t4 mod p */
          ecc_mulm (t2, two, t2, pctx);
          mpi_subm (t2, t2, t5, base->p_);     /* t2=2*t2-t5 mod p */
          if (mpi_cmp_ui (P1->z_, 1)) /* z1 != 1 */
            {           
              ecc_mulm (t3, t3, t6, pctx); /* t3=t3*t6 */
            }
          ecc_mulm (t3, t3, t4, pctx);     /* t3=t3*t4 mod p */
          mpi_powm (t7, t4, two, base->p_);    /* t7=t4^2 mod p */
          ecc_mulm (t4, t4, t7, pctx);     /* t4=t4*t7 mod p */
          ecc_mulm (t7, t1, t7, pctx);     /* t7=t1*t7 mod p */
          mpi_powm (t1, t5, two, base->p_);    /* t1=t5^2 mod p */
          mpi_subm (t1, t1, t7, base->p_);     /* t1=t1-t7 mod p */
          ecc_mulm (t6, two, t1, pctx);
          mpi_subm (t7, t7, t6, base->p_);     /* t7=t7-2*t1 mod p */
          ecc_mulm (t5, t5, t7, pctx);     /* t5=t5*t7 mod p */
          ecc_mulm (t4, t2, t4, pctx);     /* t4=t2*t4 mod p */
          mpi_subm (t2, t5, t4, base->p_);     /* t2=t5-t4 mod p */
          mpi_invm (t6, two, base->p_);
          ecc_mulm (t2, t2, t6, pctx);     /* t2 = t2/2 */

          mpi_set (R->x_, t1);
          mpi_set (R->y_, t2);
          mpi_set (R->z_, t3);
        }
      mpi_free (t7);
      mpi_free (t6);
      mpi_free (t5);
      mpi_free (t4);
      mpi_free (t3);
      mpi_free (t2);
      mpi_free (t1);
      mpi_free (two);
    }
}

/****************
 * The modular power used without EC, 
 * is this function over EC.
   return R = escalarP

   ESCALAR = input
   P       = input
   BASE    = input
   R       = output (caller must have intialized this point)

 */
static void
escalar_mult (point_t *R, gcry_mpi_t escalar, point_t *P,
              elliptic_curve_t *base, ecc_ctx_t pctx)
{
  gcry_mpi_t one, two, three;
  gcry_mpi_t x1, y1, z1, z2, z3, k, h; 
  gcry_mpi_t xx, yy, zz;
  unsigned int i, loops;
  point_t P1, P2, P1_;

  if (DBG_CIPHER)
    log_debug ("escalar_mult: begin\n");

  one   = mpi_alloc_set_ui (1);
  two   = mpi_alloc_set_ui (2);
  three = mpi_alloc_set_ui (3);

  x1 = mpi_alloc_like (P->x_);
  y1 = mpi_alloc_like (P->y_);
  /* z1 is not yet intialized.  */
  z2 = mpi_alloc_like (P->z_);
  z3 = mpi_alloc_like (P->z_);
  /* k is not yet intialized.  */
  h  = mpi_alloc_like (P->z_);


  if (!mpi_cmp_ui (escalar, 0) || mpi_cmp_ui (P->z_, 0))
    {                           /* n=0 | Z=0 => [1:1:0] */
      mpi_set_ui (R->x_, 1);
      mpi_set_ui (R->y_, 1);
      mpi_set_ui (R->z_, 0);
    }
  xx = mpi_copy (P->x_);
  zz = mpi_copy (P->z_);
  z1 = mpi_copy (one);

  if (mpi_is_neg (escalar))
    {                           /* (-n)P=n(-P) */
      escalar->sign = 0;        /* +n */
      k = mpi_copy (escalar);
      yy = mpi_copy (P->y_);    /* -P */
      mpi_invm (yy, yy, base->p_);
    }
  else
    {
      k = mpi_copy (escalar);
      yy = mpi_copy (P->y_);
    }
  if (!mpi_cmp (zz, one))
    {                           /* zz==1 */
      x1 = mpi_copy (xx);
      y1 = mpi_copy (yy);
    }
  else
    {
      ecc_mulm (z2, zz, zz, pctx); /* z^2 */
      ecc_mulm (z3, zz, z2, pctx); /* z^3 */
      mpi_invm (z2, z2, base->p_);     /* 1/Z^2 */
      ecc_mulm (x1, xx, z2, pctx); /* xx/z^2 */
      mpi_invm (z3, z3, base->p_);     /* 1/z^3 */
      ecc_mulm (y1, yy, z3, pctx); /* yy/z^3 */
    }
  mpi_mul (h, three, k);        /* h=3k */
  loops = mpi_get_nbits (h);
  i = loops - 2;                /*  i = l-1 = loops-2 */
  mpi_set (R->x_, xx);
  mpi_set (R->y_, yy);
  mpi_set (R->z_, zz);
  P1.x_ = mpi_copy (x1);
  P1.y_ = mpi_copy (y1);
  P1.z_ = mpi_copy (z1);
  while (i > 0)
    {                           /*  A.10.9. step 11  i from l-1 downto 1 */
      duplicate_point (R, R, base, pctx);
      if (mpi_test_bit (h, i) == 1 && mpi_test_bit (k, i) == 0)
        {                       /* h_i=1 & k_i=0 */
          P2 = point_copy (*R);
          sum_points (R, &P2, &P1, base, pctx); /* R=P2+P1 over the base elliptic curve */
        }
      if (mpi_test_bit (h, i) == 0 && mpi_test_bit (k, i) == 1)
        {                       /* h_i=0 & k_i=1 */
          P2 = point_copy (*R);
          P1_ = point_copy (P1);
          invert_point (&P1_, base);
          sum_points (R, &P2, &P1_, base, pctx); /* R=P2+P1_ over the base elliptic curve */
        }
      i--;
    }

  if (DBG_CIPHER)
    log_debug ("escalar_mult: ready\n");

  point_free (&P1);
  point_free (&P2);
  point_free (&P1_);
  mpi_free (h);
  mpi_free (k);
  mpi_free (z3);
  mpi_free (z2);
  mpi_free (z1);
  mpi_free (y1);
  mpi_free (x1);
  mpi_free (zz);
  mpi_free (yy);
  mpi_free (xx);
  mpi_free (three);
  mpi_free (two);
  mpi_free (one);
}


/****************
 * Solve the right side of the equation that defines a curve.
 */
static gcry_mpi_t
gen_y_2 (gcry_mpi_t x, elliptic_curve_t *base)
{
  gcry_mpi_t three;
  gcry_mpi_t x_3, ax, axb, y;
  gcry_mpi_t a, b, p;
  unsigned int nbits;

  three = mpi_alloc_set_ui (3);
  a = mpi_copy (base->a_);
  b = mpi_copy (base->b_);
  p = mpi_copy (base->p_);
  nbits = mpi_get_nbits (p);
  x_3 = mpi_new (nbits);
  ax  = mpi_new (nbits);
  axb = mpi_new (nbits);
  y   = mpi_new (nbits);

  if (DBG_CIPHER)
    log_debug ("ecc gen_y_2: Solving an elliptic equation.\n");

  mpi_powm (x_3, x, three, p);  /* x_3=x^3 mod p */
  mpi_mulm (ax, a, x, p);       /* ax=a*x mod p */
  mpi_addm (axb, ax, b, p);     /* axb=ax+b mod p */
  mpi_addm (y, x_3, axb, p);    /* y=x^3+ax+b mod p */

  if (DBG_CIPHER)
    log_debug ("ecc gen_y_2: Solved.\n");

  return y; /* The quadratic value of the coordinate if it exist. */
}






/*

   E C C  C O R E  F U N C T I O N S
 
 */



/* Generate a random secret scalar k with an order of p

   At the beginning this was identical to the code is in elgamal.c.
   Later imporved by mmr.   Further simplified by wk.  */
static gcry_mpi_t
gen_k (gcry_mpi_t p, int secure)
{
  gcry_mpi_t k;
  unsigned int nbits;

  nbits = mpi_get_nbits (p);
  k = (secure
       ? mpi_alloc_secure ( mpi_get_nlimbs (p) )
       : mpi_alloc ( mpi_get_nlimbs (p) ));

  if (DBG_CIPHER)
    log_debug ("choosing a random k of %u bits\n", nbits);
  
  gcry_mpi_randomize (k, nbits, GCRY_STRONG_RANDOM);

  mpi_mod (k, k, p);  /*  k = k mod p  */

  if (DBG_CIPHER)
    progress ('\n');

  return k;
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

  curve->p_ = scanval (domain_parms[idx].p);
  curve->a_ = scanval (domain_parms[idx].a);
  curve->b_ = scanval (domain_parms[idx].b);
  curve->n_ = scanval (domain_parms[idx].n);
  curve->G.x_ = scanval (domain_parms[idx].g_x);
  curve->G.y_ = scanval (domain_parms[idx].g_y);
  curve->G.z_ = mpi_alloc_set_ui (1);

  /* Gx, Gy, Gz are planned to be generated by code like this:
     if ( gen_big_point (&curve->n_, curve, &curve->G, nbits) == -1)
      {
         log_fatal ("ECC operation: Point generation failed\n");
      }

     A point of order 'n' is needed to generate a cyclic subgroup.
     Over this cyclic subgroup it's defined the ECDLP.  Now it use a
     fix values from NIST FIPS PUB 186-2.  Returns -1 if it isn't
     possible.
     static int
     gen_big_point (gcry_mpi_t * prime, elliptic_curve_t * base, point_t * G,
                    unsigned int nbits)
     {
         unsigned int i=0;
         gcry_mpi_t one;
         point_t Big, P;
    
         one = mpi_alloc_set_ui(1);
         G->x_ = mpi_alloc(mpi_get_nlimbs(*prime));
         G->y_ = mpi_alloc(mpi_get_nlimbs(*prime));
         G->z_ = mpi_alloc(mpi_get_nlimbs(*prime));
    
         if( DBG_CIPHER )log_debug("Generating a Big point.\n");
         do{
         do{
         *P = genPoint(*prime,*base);
         }while(PointAtInfinity(*P));//A random point in the curve that it's not PaI
         escalarMult(base.h,&P,&G,&base);//cofactor (1 o 2), could be improved
         }while(PointAtInfinity(G));
         if( DBG_CIPHER )log_debug("Big point generated.\n");
         if( DBG_CIPHER ){
         log_mpidump("Gx=",G->x_);log_mpidump("Gy=",G->y_);log_mpidump("Gz=",G->z_);
         }
     return 0;
     }
  */

  if (DBG_CIPHER)
    {
      progress ('\n');
      log_mpidump ("ecc generation  p= ", curve->p_);
      log_mpidump ("ecc generation  a= ", curve->a_);
      log_mpidump ("ecc generation  b= ", curve->b_);
      log_mpidump ("ecc generation  n= ", curve->n_);
      log_mpidump ("ecc generation  Gx= ", curve->G.x_);
      log_mpidump ("ecc generation  Gy= ", curve->G.y_);
      log_mpidump ("ecc generation  Gz= ", curve->G.z_);
    }
  if (DBG_CIPHER)
    progress ('\n');

  return 0;
}


/****************
 * First obtain the setup.  Over the finite field randomize an scalar
 * secret value, and calculate the public point.
 */
static gpg_err_code_t
generate_key (ECC_secret_key *sk, unsigned int nbits)
{
  gpg_err_code_t err;
  elliptic_curve_t E;
  gcry_mpi_t d;
  point_t Q, G;
  ecc_ctx_t pctx;

  err = generate_curve (nbits, &E);
  if (err)
    return err;

  d = mpi_snew (nbits);
  if (DBG_CIPHER)
    log_debug ("choosing a random x of size %u\n", nbits);
  d = gen_k (E.n_, 2);          /* generate_secret_prime(nbits); */
  G = point_copy (E.G);

  /* Compute Q.  */
  point_init (&Q);
  pctx = ecc_ctx_init (E.p_, 0);
  escalar_mult (&Q, d, &E.G, &E, pctx);
  ecc_ctx_free (pctx);

  /* Copy the stuff to the key structures. */
  sk->E.p_ = mpi_copy (E.p_);
  sk->E.a_ = mpi_copy (E.a_);
  sk->E.b_ = mpi_copy (E.b_);
  sk->E.G  = point_copy (E.G);
  sk->E.n_ = mpi_copy (E.n_);
  sk->Q    = point_copy (Q);
  sk->d    = mpi_copy (d);

  /* Now we can test our keys (this should never fail!). */
  test_keys (sk, nbits - 64);

  point_free (&Q);
  mpi_free (d);
  curve_free (&E);

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
  point_t R_;
  gcry_mpi_t c = mpi_new (nbits);
  gcry_mpi_t out = mpi_new (nbits);
  gcry_mpi_t r = mpi_new (nbits);
  gcry_mpi_t s = mpi_new (nbits);

  if (DBG_CIPHER)
    log_debug ("Testing key.\n");

  point_init (&R_);

  pk.E = curve_copy (sk->E);
  pk.Q = point_copy (sk->Q);

  gcry_mpi_randomize (test, nbits, GCRY_WEAK_RANDOM);

#if 0  
  doEncrypt (test, &pk, &R_, c);

  out = decrypt (out, sk, R_, c);

  if (mpi_cmp (test, out))      /* test!=out */
    log_fatal ("ECELG operation: encrypt, decrypt failed\n");
  if (DBG_CIPHER)
    log_debug ("ECELG operation: encrypt, decrypt ok.\n");
#endif

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
 * between the public value and de secret one.
 */
static int
check_secret_key (ECC_secret_key * sk)
{
  point_t Q;
  gcry_mpi_t y_2, y2 = mpi_alloc (0);
  ecc_ctx_t pctx;

  /* ?primarity test of 'p' */
  /*  (...) //!! */
  /* G in E(F_p) */
  y_2 = gen_y_2 (sk->E.G.x_, &sk->E);   /*  y^2=x^3+a*x+b */
  mpi_mulm (y2, sk->E.G.y_, sk->E.G.y_, sk->E.p_);      /*  y^2=y*y */
  if (mpi_cmp (y_2, y2))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: Point 'G' does not belong to curve 'E'!\n");
      return (1);
    }
  /* G != PaI */
  if (point_at_infinity (sk->E.G))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: 'G' cannot be Point at Infinity!\n");
      return (1);
    }
  /* ?primarity test of 'n' */
  /*  (...) //!! */
  /* ?(p-sqrt(p)) < n < (p+sqrt(p)) */
  /* ?n!=p */
  /* ?(n^k) mod p !=1 for k=1 to 31 (from GOST) or k=1 to 50 (from MIRACL) */
  /* Q=[n]G over E = PaI */

  point_init (&Q);
  pctx = ecc_ctx_init (sk->E.p_, 0);
  escalar_mult (&Q, sk->E.n_, &sk->E.G, &sk->E, pctx);
  if (!point_at_infinity (Q))
    {
      if (DBG_CIPHER)
        log_debug ("check_secret_key: E is not a curve of order n\n");
      point_free (&Q);
      ecc_ctx_free (pctx);
      return 1;
    }
  /* pubkey cannot be PaI */
  if (point_at_infinity (sk->Q))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: Q can not be a Point at Infinity!\n");
      ecc_ctx_free (pctx);
      return (1);
    }
  /* pubkey = [d]G over E */
  escalar_mult (&Q, sk->d, &sk->E.G, &sk->E, pctx);
  if ((Q.x_ == sk->Q.x_) && (Q.y_ == sk->Q.y_) && (Q.z_ == sk->Q.z_))
    {
      if (DBG_CIPHER)
        log_debug
          ("Bad check: There is NO correspondence between 'd' and 'Q'!\n");
      ecc_ctx_free (pctx);
      return (1);
    }
  ecc_ctx_free (pctx);
  point_free (&Q);
  return 0;
}


#if 0
/****************
 * Encrypt a number and obtain and struct (R,c)
 */
static void
doEncrypt (gcry_mpi_t input, ECC_public_key * pkey, point_t * R, gcry_mpi_t c)
{

  gcry_mpi_t k, p, x, y;
  point_t P, Q, G;
  elliptic_curve_t E;

  k = mpi_alloc (0);
  p = mpi_copy (pkey->E.p_);
  x = mpi_alloc (0);
  y = mpi_alloc (0);
  Q = point_copy (pkey->Q);
  G = point_copy (pkey->E.G);
  E = curve_copy (pkey->E);

  k = gen_k (p, 1);             /* 2nd parametre: how much security? */
  escalarMult (k, &Q, &P, &E);  /* P=[k]Q=[k]([d]G) */
  escalarMult (k, &G, R, &E);   /* R=[k]G */
  /* IFP weakness//mpi_mul(c,input,Q.x_);//c=input*Q_x */
  /* MMR Use affine conversion befor extract x-coordinate */
  if (point_affine (&P, x, y, &E))
    {                           /* Q cannot turn to affine coordinate */
      if (DBG_CIPHER)
        {
          log_debug ("Encrypting: Cannot turn to affine.\n");
        }
    }
  /* MMR According to the standard P1363 we can not use x-coordinate directly. */
  /*  It is necessary to add hash-operation later.  */
  /*  As the maximal length of a key for the symmetric cipher is 256 bit it is possible to take hash-function SHA256. */
  sha256_hashing (x, &x);
  aes256_encrypting (x, input, &c);

  if (DBG_CIPHER)
    {
      log_debug ("doEncrypt: end.\n");
    }
}
#endif /*0*/

#if 0
/****************
 * Undo the ciphertext
 */
static gcry_mpi_t
decrypt (gcry_mpi_t output, ECC_secret_key * skey, point_t R, gcry_mpi_t c)
{

  gcry_mpi_t p, inv, x, y;
  point_t P, Q;
  elliptic_curve_t E;

  p = mpi_copy (skey->E.p_);
  inv = mpi_alloc (0);
  x = mpi_alloc (0);
  y = mpi_alloc (0);
  Q = point_copy (skey->Q);
  E = curve_copy (skey->E);

  escalarMult (skey->d, &R, &P, &E);    /* P=[d]R */
  /* That is like: mpi_fdiv_q(output,c,Q.x_); */
  /* IFP weakness//mpi_invm(inv,Q.x_,p);//inv=Q{_x}^-1 (mod p) */
  /* IFP weakness//mpi_mulm(output,c,inv,p);//output=c*inv (mod p) */
  /* MMR Use affine conversion befor extract x-coordinate */
  if (point_affine (&P, x, y, &E))
    {                           /* Q cannot turn to affine coordinate */
      if (DBG_CIPHER)
        {
          log_debug ("Encrypting: Cannot turn to affine.\n");
        }
    }
  sha256_hashing (x, &x);
  aes256_decrypting (x, c, &output);

  if (DBG_CIPHER)
    {
      log_debug ("decrypt: end.\n");
    }
  return (output);
}
#endif /*0*/


/*
 * Return the signature struct (r,s) from the message hash.  The caller
 * must have allocated R and S.
 */
static gpg_err_code_t
sign (gcry_mpi_t input, ECC_secret_key *skey, gcry_mpi_t r, gcry_mpi_t s)
{
  gpg_err_code_t err = 0;
  gcry_mpi_t k, dr, sum, k_1, x, y;
  point_t I;
  ecc_ctx_t pctx;
  
  k = NULL;
  dr = mpi_alloc (0);
  sum = mpi_alloc (0);
  k_1 = mpi_alloc (0);
  x = mpi_alloc (0);
  y = mpi_alloc (0);
  point_init (&I);

  mpi_set_ui (s, 0);
  mpi_set_ui (r, 0);

  pctx = ecc_ctx_init (skey->E.p_, 0);

  while (!mpi_cmp_ui (s, 0)) /* s == 0 */
    {                           
      while (!mpi_cmp_ui (r, 0)) /* r == 0 */
        {               
          /* Note, that we are guaranteed to enter this loop at least
             once because r has been intialized to 0.  We can't use a
             do_while because we want to keep the value of R even if S
             has to be recomputed.  */
          mpi_free (k);
          k = gen_k (skey->E.p_, 1); /* fixme:  shouldn't that be E.n ? */
          escalar_mult (&I, k, &skey->E.G, &skey->E, pctx); /* I = [k]G */
          if (point_affine (&I, x, y, &skey->E))
            {
              if (DBG_CIPHER)
                log_debug ("ecc sign: Cannot turn to affine. "
                           " Cannot complete sign.\n");
              err = GPG_ERR_BAD_SIGNATURE;
              goto leave;
            }
          mpi_mod (r, x, skey->E.n_);   /* r = x mod n */
        }
      mpi_mulm (dr, skey->d, r, skey->E.n_);/* dr = d*r mod n */
      mpi_addm (sum, input, dr, skey->E.n_);/* sum = hash + (d*r) mod n */
      mpi_invm (k_1, k, skey->E.n_);        /* k_1 = k^(-1) mod n */
      mpi_mulm (s, k_1, sum, skey->E.n_);   /* s = k^(-1)*(hash+(d*r)) mod n */
    }

 leave:
  ecc_ctx_free (pctx);
  point_free (&I);
  mpi_free (y);
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
  point_t Q, Q1, Q2;
  ecc_ctx_t pctx;

  if( !(mpi_cmp_ui (r, 0) > 0 && mpi_cmp (r, pkey->E.n_) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < r < n  failed.  */
  if( !(mpi_cmp_ui (s, 0) > 0 && mpi_cmp (s, pkey->E.n_) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < s < n  failed.  */

  h  = mpi_alloc (0);
  h1 = mpi_alloc (0);
  h2 = mpi_alloc (0);
  x = mpi_alloc (0);
  y = mpi_alloc (0);
  point_init (&Q);
  point_init (&Q1);
  point_init (&Q2);

  pctx = ecc_ctx_init (pkey->E.p_, 0);

  /* h  = s^(-1) (mod n) */
  mpi_invm (h, s, pkey->E.n_);           
  /* h1 = hash * s^(-1) (mod n) */
  mpi_mulm (h1, input, h, pkey->E.n_); 
  /* Q1 = [ hash * s^(-1) ]G  */
  escalar_mult (&Q1, h1, &pkey->E.G, &pkey->E, pctx );
  /* h2 = r * s^(-1) (mod n) */
  mpi_mulm (h2, r, h, pkey->E.n_);             
  /* Q2 = [ r * s^(-1) ]Q */
  escalar_mult (&Q2, h2, &pkey->Q, &pkey->E, pctx);
  /* Q  = ([hash * s^(-1)]G) + ([r * s^(-1)]Q) */
  sum_points (&Q, &Q1, &Q2, &pkey->E, pctx);

  if (point_at_infinity (Q))
    {
      if (DBG_CIPHER)
          log_debug ("ecc verification: Rejected.\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  if (point_affine (&Q, x, y, &pkey->E))
    {                   
      if (DBG_CIPHER)
        log_debug ("ecc verification: Cannot turn to affine. Rejected.\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  mpi_mod (x, x, pkey->E.n_); /* x = x mod E_n */
  if (mpi_cmp (x, r))   /* x != r */
    {                           
      if (DBG_CIPHER)
        log_debug ("ecc verification: Not verified.\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  if (DBG_CIPHER)
    log_debug ("ecc verification: Accepted.\n");

 leave:
  ecc_ctx_free (pctx);
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


/****************
 * Generate a random point over an Elliptic curve is the first step to
 * find a random cyclic subgroup generator.
 *
 *        !! At this moment it isn't used !!  //!!
 */
#if 0
static point_t
gen_point (gcry_mpi_t prime, elliptic_curve_t base)
{

  unsigned int i = 0;
  gcry_mpi_t x, y_2, y;
  gcry_mpi_t one, one_neg, bit;
  point_t P;

  x = mpi_alloc (mpi_get_nlimbs (base.p_));
  y_2 = mpi_alloc (mpi_get_nlimbs (base.p_));
  y = mpi_alloc (mpi_get_nlimbs (base.p_));
  one = mpi_alloc_set_ui (1);
  one_neg = mpi_alloc (mpi_get_nlimbs (one));
  mpi_invm (one_neg, one, base.p_);

  if (DBG_CIPHER)
    log_debug ("Generating a normal point.\n");
  do
    {
      x = gen_k (base.p_, 1);   /* generate_public_prime(mpi_get_nlimbs(base.n_)*BITS_PER_MPI_LIMB); */
      do
        {
          y_2 = gen_y_2 (x, &base);     /* x^3+ax+b (mod p) */
          mpi_add_ui (x, x, 1);
          i++;
        }
      while (!mpi_cmp_ui (y_2, 0) && i < 0xf);  /* Try to find a valid value until 16 iterations. */
      i = 0;
      y = existSquareRoot (y_2, base.p_);
    }
  while (!mpi_cmp_ui (y, 0));   /* Repeat until a valid coordinate is found. */
  bit = gen_bit ();             /* generate one bit */
  if (mpi_cmp_ui (bit, 1))
    {                           /* choose the y coordinate */
      mpi_invm (y, y, base.p_); /* mpi_powm(y, y, one_neg,base.p_); */
    }
  if (DBG_CIPHER)
    log_debug ("Normal point generated.\n");

  P.x_ = mpi_copy (x);
  P.y_ = mpi_copy (y);
  P.z_ = mpi_copy (one);

  mpi_free (bit);
  mpi_free (one_neg);
  mpi_free (one);
  mpi_free (y);
  mpi_free (y_2);
  mpi_free (x);

  return (P);
}
#endif /*0*/

/****************
 * Boolean generator to choose between to coordinates.
 */
#if 0
static gcry_mpi_t
gen_bit ()
{
  gcry_mpi_t aux = mpi_alloc_set_ui (0);

  /* FIXME: This is highly ineffective but the whole function is used
     only at one place. */

  /* Get one random bit, with less security level, and translate it to
     an MPI. */
  mpi_set_buffer (aux, get_random_bits (1, 0, 1), 1, 0);        /* gen_k(...) */

  return aux;                   /* b; */
}
#endif /*0*/



#if 0
/* Function to solve an IFP ECElGamal weakness: */
/*  sha256_hashing() */
/*  aes256_encrypting() */
/*  aes356_decrypting() */

/****************
 * Compute 256 bit hash value from input MPI.
 * Use SHA256 Algorithm.
 */
static void
sha256_hashing (gcry_mpi_t input, gcry_mpi_t * output)
{                               /*   */

  int sign;
  byte *hash_inp_buf;
  byte hash_out_buf[32];
  MD_HANDLE hash = md_open (8, 1);      /* algo SHA256 in secure mode */

  unsigned int nbytes;

  hash_inp_buf = mpi_get_secure_buffer (input, &nbytes, &sign); /* convert gcry_mpi_t input to string */

  md_write (hash, hash_inp_buf, nbytes);        /* hashing input string */
  wipememory (hash_inp_buf, sizeof hash_inp_buf);       /*  burn temp value  */
  xfree (hash_inp_buf);

  md_digest (hash, 8, hash_out_buf, 32);
  mpi_set_buffer (*output, hash_out_buf, 32, 0);        /*  convert 256 bit digest to MPI */

  wipememory (hash_out_buf, sizeof hash_out_buf);       /*  burn temp value  */
  md_close (hash);              /*  destroy and free hash state. */

}

/****************
 * Encrypt input MPI.
 * Use AES256 algorithm.
 */

static void
aes256_encrypting (gcry_mpi_t key, gcry_mpi_t input, gcry_mpi_t * output)
{                               /*   */

  int sign;
  byte *key_buf;
  byte *cipher_buf;

  unsigned int keylength;
  unsigned int nbytes;


  CIPHER_HANDLE cipher = cipher_open (9, CIPHER_MODE_CFB, 1);   /* algo AES256 CFB mode in secure memory */
  cipher_setiv (cipher, NULL, 0);       /*  Zero IV */

  key_buf = mpi_get_secure_buffer (key, &keylength, &sign);     /* convert MPI key to string */
  cipher_setkey (cipher, key_buf, keylength);
  wipememory (key_buf, sizeof key_buf); /*  burn temp value  */
  xfree (key_buf);

  cipher_buf = mpi_get_secure_buffer (input, &nbytes, &sign);   /* convert MPI input to string */

  cipher_encrypt (cipher, cipher_buf + 1, cipher_buf + 1, nbytes - 1);  /*  */
  cipher_close (cipher);        /*  destroy and free cipher state. */

  mpi_set_buffer (*output, cipher_buf, nbytes, 0);      /*  convert encrypted string to MPI */
  wipememory (cipher_buf, sizeof cipher_buf);   /*  burn temp value  */
  xfree (cipher_buf);
}

/****************
 * Decrypt input MPI.
 * Use AES256 algorithm.
 */

static void
aes256_decrypting (gcry_mpi_t key, gcry_mpi_t input, gcry_mpi_t * output)
{                               /*   */

  int sign;
  byte *key_buf;
  byte *cipher_buf;

  unsigned int keylength;
  unsigned int nbytes;


  CIPHER_HANDLE cipher = cipher_open (9, CIPHER_MODE_CFB, 1);   /* algo AES256 CFB mode in secure memory */
  cipher_setiv (cipher, NULL, 0);       /*  Zero IV */

  key_buf = mpi_get_secure_buffer (key, &keylength, &sign);     /* convert MPI input to string */
  cipher_setkey (cipher, key_buf, keylength);
  wipememory (key_buf, sizeof key_buf); /*  burn temp value  */
  xfree (key_buf);

  cipher_buf = mpi_get_secure_buffer (input, &nbytes, &sign);   /* convert MPI input to string; */

  cipher_decrypt (cipher, cipher_buf + 1, cipher_buf + 1, nbytes - 1);  /*  */
  cipher_close (cipher);        /*  destroy and free cipher state. */

  mpi_set_buffer (*output, cipher_buf, nbytes, 0);      /*  convert encrypted string to MPI */
  wipememory (cipher_buf, sizeof cipher_buf);   /*  burn temp value  */
  xfree (cipher_buf);
}

/* End of IFP ECElGamal weakness functions. */
#endif /*0*/

/*********************************************
 **************  interface  ******************
 *********************************************/

static gcry_err_code_t
ecc_generate (int algo, unsigned int nbits, unsigned long dummy,
              gcry_mpi_t *skey, gcry_mpi_t **retfactors)
{
  gpg_err_code_t err;
  ECC_secret_key sk;

  (void)algo;

  /* Make an empty list of factors.  */
  *retfactors = gcry_calloc ( 1, sizeof **retfactors );
  if (!*retfactors)
    return gpg_err_code_from_syserror ();

  err = generate_key (&sk, nbits);
  if (err)
    {
      gcry_free (*retfactors);
      *retfactors = NULL;
      return err;
    }

  skey[0] = sk.E.p_;
  skey[1] = sk.E.a_;
  skey[2] = sk.E.b_;
  skey[3] = sk.E.G.x_;
  skey[4] = sk.E.G.y_;
  skey[5] = sk.E.G.z_;
  skey[6] = sk.E.n_;
  skey[7] = sk.Q.x_;
  skey[8] = sk.Q.y_;
  skey[9] = sk.Q.z_;
  skey[10] = sk.d;

  if (DBG_CIPHER)
    {
      progress ('\n');

      log_mpidump ("[ecc]  p= ", skey[0]);
      log_mpidump ("[ecc]  a= ", skey[1]);
      log_mpidump ("[ecc]  b= ", skey[2]);
      log_mpidump ("[ecc]  Gx= ", skey[3]);
      log_mpidump ("[ecc]  Gy= ", skey[4]);
      log_mpidump ("[ecc]  Gz= ", skey[5]);
      log_mpidump ("[ecc]  n= ", skey[6]);
      log_mpidump ("[ecc]  Qx= ", skey[7]);
      log_mpidump ("[ecc]  Qy= ", skey[8]);
      log_mpidump ("[ecc]  Qz= ", skey[9]);
      log_mpidump ("[ecc]  d= ", skey[10]);
    }

  if (DBG_CIPHER)
    {
      log_debug ("ECC key Generated.\n");
    }
  return 0;
}


static gcry_err_code_t
ecc_check_secret_key (int algo, gcry_mpi_t *skey)
{
  ECC_secret_key sk;

  (void)algo;

  if (!skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4] || !skey[5]
      || !skey[6] || !skey[7] || !skey[8] || !skey[9] || !skey[10])
    return GPG_ERR_BAD_MPI;

  if (DBG_CIPHER)
    {
      log_debug ("ECC check secret key.\n");
    }
  sk.E.p_ = skey[0];
  sk.E.a_ = skey[1];
  sk.E.b_ = skey[2];
  sk.E.G.x_ = skey[3];
  sk.E.G.y_ = skey[4];
  sk.E.G.z_ = skey[5];
  sk.E.n_ = skey[6];
  sk.Q.x_ = skey[7];
  sk.Q.y_ = skey[8];
  sk.Q.z_ = skey[9];
  sk.d = skey[10];

  if (check_secret_key (&sk))
    {
      if (DBG_CIPHER)
        log_debug ("Bad check: Bad secret key.\n");
      return GPG_ERR_BAD_SECKEY;
    }
  return 0;
}


#if 0
static int
ecc_encrypt_FIXME (int algo, gcry_mpi_t * resarr, gcry_mpi_t data, gcry_mpi_t * pkey)
{
  ECC_public_key pk;
  point R;

  if (algo != PUBKEY_ALGO_ECC && algo != PUBKEY_ALGO_ECC_E)
    return G10ERR_PUBKEY_ALGO;
  if (!data || !pkey[0] || !pkey[1] || !pkey[2] || !pkey[3] || !pkey[4]
      || !pkey[5] || !pkey[6] || !pkey[7] || !pkey[8] || !pkey[9])
    return G10ERR_BAD_MPI;

  if (DBG_CIPHER)
    {
      log_debug ("ECC encrypt.\n");
    }
  pk.E.p_ = pkey[0];
  pk.E.a_ = pkey[1];
  pk.E.b_ = pkey[2];
  pk.E.G.x_ = pkey[3];
  pk.E.G.y_ = pkey[4];
  pk.E.G.z_ = pkey[5];
  pk.E.n_ = pkey[6];
  pk.Q.x_ = pkey[7];
  pk.Q.y_ = pkey[8];
  pk.Q.z_ = pkey[9];

  R.x_ = resarr[0] = mpi_alloc (mpi_get_nlimbs (pk.Q.x_));
  R.y_ = resarr[1] = mpi_alloc (mpi_get_nlimbs (pk.Q.y_));
  R.z_ = resarr[2] = mpi_alloc (mpi_get_nlimbs (pk.Q.z_));
  resarr[3] = mpi_alloc (mpi_get_nlimbs (pk.E.p_));

  doEncrypt (data, &pk, &R, resarr[3]);

  resarr[0] = mpi_copy (R.x_);
  resarr[1] = mpi_copy (R.y_);
  resarr[2] = mpi_copy (R.z_);
  return 0;
}

int
ecc_decrypt_FIXME (int algo, gcry_mpi_t * result, gcry_mpi_t * data, gcry_mpi_t * skey)
{
  ECC_secret_key sk;
  point R;

  if (algo != PUBKEY_ALGO_ECC && algo != PUBKEY_ALGO_ECC_E)
    return G10ERR_PUBKEY_ALGO;
  if (!data[0] || !data[1] || !data[2] || !data[3] || !skey[0] || !skey[1]
      || !skey[2] || !skey[3] || !skey[4] || !skey[5] || !skey[6] || !skey[7]
      || !skey[8] || !skey[9] || !skey[10])
    return G10ERR_BAD_MPI;

  if (DBG_CIPHER)
    {
      log_debug ("ECC decrypt.\n");
    }
  R.x_ = data[0];
  R.y_ = data[1];
  R.z_ = data[2];
  sk.E.p_ = skey[0];
  sk.E.a_ = skey[1];
  sk.E.b_ = skey[2];
  sk.E.G.x_ = skey[3];
  sk.E.G.y_ = skey[4];
  sk.E.G.z_ = skey[5];
  sk.E.n_ = skey[6];
  sk.Q.x_ = skey[7];
  sk.Q.y_ = skey[8];
  sk.Q.z_ = skey[9];
  sk.d = skey[10];

  *result = mpi_alloc_secure (mpi_get_nlimbs (sk.E.p_));
  *result = decrypt (*result, &sk, R, data[3]);
  return 0;
}
#endif /*0*/

static gcry_err_code_t
ecc_sign (int algo, gcry_mpi_t *resarr, gcry_mpi_t data, gcry_mpi_t *skey)
{
  gpg_err_code_t err;
  ECC_secret_key sk;

  (void)algo;

  if (!data || !skey[0] || !skey[1] || !skey[2] || !skey[3] || !skey[4]
      || !skey[5] || !skey[6] || !skey[7] || !skey[8] || !skey[9]
      || !skey[10])
    return GPG_ERR_BAD_MPI;

  sk.E.p_ = skey[0];
  sk.E.a_ = skey[1];
  sk.E.b_ = skey[2];
  sk.E.G.x_ = skey[3];
  sk.E.G.y_ = skey[4];
  sk.E.G.z_ = skey[5];
  sk.E.n_ = skey[6];
  sk.Q.x_ = skey[7];
  sk.Q.y_ = skey[8];
  sk.Q.z_ = skey[9];
  sk.d = skey[10];

  resarr[0] = mpi_alloc (mpi_get_nlimbs (sk.E.p_));
  resarr[1] = mpi_alloc (mpi_get_nlimbs (sk.E.p_));
  err = sign (data, &sk, resarr[0], resarr[1]);
  if (err)
    {
      mpi_free (resarr[0]);
      mpi_free (resarr[1]);
      resarr[0] = NULL; /* Mark array as released.  */
    }
  return err;
}

static gcry_err_code_t
ecc_verify (int algo, gcry_mpi_t hash, gcry_mpi_t *data, gcry_mpi_t *pkey,
            int (*cmp)(void *, gcry_mpi_t), void *opaquev)
{
  ECC_public_key pk;

  (void)algo;

  if (!data[0] || !data[1] || !hash || !pkey[0] || !pkey[1] || !pkey[2]
      || !pkey[3] || !pkey[4] || !pkey[5] || !pkey[6] || !pkey[7] || !pkey[8]
      || !pkey[9])
    return GPG_ERR_BAD_MPI;

  if (DBG_CIPHER)
    log_debug ("ECC verify.\n");
  pk.E.p_ = pkey[0];
  pk.E.a_ = pkey[1];
  pk.E.b_ = pkey[2];
  pk.E.G.x_ = pkey[3];
  pk.E.G.y_ = pkey[4];
  pk.E.G.z_ = pkey[5];
  pk.E.n_ = pkey[6];
  pk.Q.x_ = pkey[7];
  pk.Q.y_ = pkey[8];
  pk.Q.z_ = pkey[9];

  return verify (hash, &pk, data[0], data[1]);
}



static unsigned int
ecc_get_nbits (int algo, gcry_mpi_t *pkey)
{
  (void)algo;

  if (DBG_CIPHER)
    {
      log_debug ("ECC get nbits.\n");
    }

  if (DBG_CIPHER)
    {
      progress ('\n');

      log_mpidump ("[ecc]  p= ", pkey[0]);
      log_mpidump ("[ecc]  a= ", pkey[1]);
      log_mpidump ("[ecc]  b= ", pkey[2]);
      log_mpidump ("[ecc]  Gx= ", pkey[3]);
      log_mpidump ("[ecc]  Gy= ", pkey[4]);
      log_mpidump ("[ecc]  Gz= ", pkey[5]);
      log_mpidump ("[ecc]  n= ", pkey[6]);
      log_mpidump ("[ecc]  Qx= ", pkey[7]);
      log_mpidump ("[ecc]  Qy= ", pkey[8]);
      log_mpidump ("[ecc]  Qz= ", pkey[9]);
    }

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
    "pabxyznXYZ", "pabxyznXYZd", "", "rs", "pabxyznXYZ",
    GCRY_PK_USAGE_SIGN,
    ecc_generate,
    ecc_check_secret_key,
    NULL,
    NULL,
    ecc_sign,
    ecc_verify,
    ecc_get_nbits
  };



