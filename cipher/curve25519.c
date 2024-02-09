/*
 * Three implementations are better:
 *
 * 64-bit with ADX extention: 2^256-38 using ADCX/ADOX
 * 64-bit with no such extention: integer 51-bit limb
 * 32-bit with no such extention: integer 25.5-bit limb
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef _GCRYPT_IN_LIBGCRYPT
#include <stdarg.h>
#include <gpg-error.h>

#include "types.h"
#include "g10lib.h"
#include "gcrypt-int.h"
#include "const-time.h"
#include "bufhelp.h"
#endif
#include <stdint.h>

/* safegcd implementation */

/*
 * This implementation follows the explanation in the following document:
 *
 * The safegcd implementaion in libsecp256k1 explained:
 * https://github.com/bitcoin-core/secp256k1/blob/0775283/doc/safegcd_implementation.md
 *
 * While it suggests use of 62-bit integer representation for 64-bit
 * computer (and 30-bit representation for 32-bit computer), this
 * implementation uses N=31 and tweaked version of U in the transition
 * matrix, so that iteration can be 19 times for p25519.
 */

/*
 * Other references:
 *
 * [1] Daniel J. Bernstein, Bo-Yin Yang.
 *     Fast constant-time gcd and modular inversion.
 *     Date: 2019.04.13.
 *     https://gcd.cr.yp.to/papers.html#safegcd
 *
 * [2] Pieter Wuille.
 *     Bounds on divsteps iterations in safegcd.
 *     https://github.com/sipa/safegcd-bounds#readme
 */

/* Representation with signed 31-bit limb for bignum integer. */
#define SR256_WORDS 9
typedef struct sr256 {
  int32_t v[SR256_WORDS];
} sr256;

/* The modulus in signed 31-bit representation. */
static const sr256 modulus_25519 = {
  { -19, 0, 0, 0, 0, 0, 0, 0, 128 }
};
/* inv31: modulus^-1 (mod 2^31)
 * pow(modulus_25519,2**31-1,2**31)
 */
static const uint32_t modulus_inv31_25519 = 0x579435e5;

/*
 * Data type for transition matrix
 *
 * t = [ u  v ]
 *     [ q  r ]
 *
 * u_ is tweaked by -1, so that overflow never occurs.
 */
typedef struct {
  int32_t u_, v;
  int32_t q,  r;
} matrix_2x2;

static int32_t
modinv_divsteps (int32_t zeta, uint32_t f0, uint32_t g0, matrix_2x2 *t)
{
  uint32_t f, g;
  uint32_t u, v, q, r;
  int i = 0;

  f = f0;
  g = g0;
  u = 1;
  v = 0;
  q = 0;
  r = 1;

  for (;;)
    {
      uint32_t mask1, mask2;
      uint32_t x, y, z;         /* -f, -u, -v conditionally.  */

      mask1 = zeta >> 31;
      mask2 = 0UL - (g & 1);

      x = (f ^ mask1) - mask1;
      y = (u ^ mask1) - mask1;
      z = (v ^ mask1) - mask1;

      g += x & mask2;
      q += y & mask2;
      r += z & mask2;

      mask1 &= mask2;

      zeta = (zeta ^ mask1) - 1;
      f += g & mask1;
      u += q & mask1;
      v += r & mask1;

      g >>= 1;

      if (++i >= 31)
        break;
      u <<= 1;
      v <<= 1;
    }

  t->u_ = (int32_t)(u - 1 + u); /* double minus 1 */
  t->v = (int32_t)(v << 1);     /* double */
  t->q = (int32_t)q;
  t->r = (int32_t)r;

  return zeta;
}

/*
 */
static void
modinv_update_de (sr256 *d, sr256 *e, const matrix_2x2 *t,
                  const sr256 *modulus, uint32_t inv31)
{
  const int32_t u_ = t->u_, v = t->v, q = t->q, r = t->r;
  int32_t di, ei, me, sd, se;
  int64_t cd, ce;
  int32_t md_; /* MD_ stands for MD minus 1, which keeps <= 2**31-1 */
  int i;

  sd = d->v[8] >> 31;
  se = e->v[8] >> 31;
  md_ = (u_ & sd) + (v & se);
  me = (q & sd) + (r & se);
  di = d->v[0];
  ei = e->v[0];
  cd = (int64_t)u_ * di + di + (int64_t)v * ei;
  ce = (int64_t)q * di + (int64_t)r * ei;
  /* MD_ + 1 in the following expression may never overflow in uint32_t.
   * The value of MD_ may be 2**31-1, but the addition is by unsigned.  */
  md_ -= ((uint32_t)md_ + (1 & sd) + inv31 * (uint32_t)cd) & 0x7fffffff;
  me -= (inv31 * (uint32_t)ce + me) & 0x7fffffff;
  cd += (int64_t)modulus->v[0] * md_ + (int64_t)(modulus->v[0] & sd);
  ce += (int64_t)modulus->v[0] * me;
  cd >>= 31;
  ce >>= 31;
  for (i = 1; i < SR256_WORDS; i++)
    {
      di = d->v[i];
      ei = e->v[i];
      cd += (int64_t)u_ * di + di + (int64_t)v * ei;
      ce += (int64_t)q * di + (int64_t)r * ei;
      if (i == 1  || i == 8)
        {
          cd += (int64_t)modulus->v[i] * md_ + (int64_t)(modulus->v[i] & sd);
          ce += (int64_t)modulus->v[i] * me;
        }
      d->v[i - 1] = (int32_t)cd & 0x7fffffff;
      e->v[i - 1] = (int32_t)ce & 0x7fffffff;
      cd >>= 31;
      ce >>= 31;
    }

  d->v[8] = (int32_t)cd;
  e->v[8] = (int32_t)ce;
}

/*
 */
static void
modinv_update_fg (sr256 *f, sr256 *g, const matrix_2x2 *t)
{
  const int32_t u_ = t->u_, v = t->v, q = t->q, r = t->r;
  int32_t fi, gi;
  int64_t cf, cg;
  int i;

  fi = f->v[0];
  gi = g->v[0];
  cf = (int64_t)u_ * fi + fi + (int64_t)v * gi;
  cg = (int64_t)q * fi + (int64_t)r * gi;
  cf >>= 31;
  cg >>= 31;

  for (i = 1; i < SR256_WORDS; i++)
    {
      fi = f->v[i];
      gi = g->v[i];
      cf += (int64_t)u_ * fi + fi + (int64_t)v * gi;
      cg += (int64_t)q * fi + (int64_t)r * gi;
      f->v[i - 1] = (int32_t)cf & 0x7fffffff;
      g->v[i - 1] = (int32_t)cg & 0x7fffffff;
      cf >>= 31;
      cg >>= 31;
    }

  f->v[8] = (int32_t)cf;
  g->v[8] = (int32_t)cg;
}


static void
modinv_normalize (sr256 *r, int32_t sign, const sr256 *modulus)
{
  int32_t r0, r1, r2, r3, r4, r5, r6, r7, r8;
  int32_t mask_add, mask_neg;

  r0 = r->v[0];
  r1 = r->v[1];
  r2 = r->v[2];
  r3 = r->v[3];
  r4 = r->v[4];
  r5 = r->v[5];
  r6 = r->v[6];
  r7 = r->v[7];
  r8 = r->v[8];

  /* Negate if SIGN is negative.  */
  mask_neg = sign >> 31;
  r0 = (r0 ^ mask_neg) - mask_neg;
  r1 = (r1 ^ mask_neg) - mask_neg;
  r2 = (r2 ^ mask_neg) - mask_neg;
  r3 = (r3 ^ mask_neg) - mask_neg;
  r4 = (r4 ^ mask_neg) - mask_neg;
  r5 = (r5 ^ mask_neg) - mask_neg;
  r6 = (r6 ^ mask_neg) - mask_neg;
  r7 = (r7 ^ mask_neg) - mask_neg;
  r8 = (r8 ^ mask_neg) - mask_neg;
  r1 += r0 >> 31; r0 &= 0x7fffffff;
  r2 += r1 >> 31; r1 &= 0x7fffffff;
  r3 += r2 >> 31; r2 &= 0x7fffffff;
  r4 += r3 >> 31; r3 &= 0x7fffffff;
  r5 += r4 >> 31; r4 &= 0x7fffffff;
  r6 += r5 >> 31; r5 &= 0x7fffffff;
  r7 += r6 >> 31; r6 &= 0x7fffffff;
  r8 += r7 >> 31; r7 &= 0x7fffffff;

  /* Add the modulus if the input is negative. */
  mask_add = r8 >> 31;
  r0 += modulus->v[0] & mask_add;
  r1 += modulus->v[1] & mask_add;
  /* We know modulus->v[i] is zero for i=2..7.  */
  r8 += modulus->v[8] & mask_add;
  r1 += r0 >> 31; r0 &= 0x7fffffff;
  r2 += r1 >> 31; r1 &= 0x7fffffff;
  r3 += r2 >> 31; r2 &= 0x7fffffff;
  r4 += r3 >> 31; r3 &= 0x7fffffff;
  r5 += r4 >> 31; r4 &= 0x7fffffff;
  r6 += r5 >> 31; r5 &= 0x7fffffff;
  r7 += r6 >> 31; r6 &= 0x7fffffff;
  r8 += r7 >> 31; r7 &= 0x7fffffff;

  /* It brings r from range (-2*modulus,modulus) to range
     (-modulus,modulus). */

  /* Add the modulus again if the result is still negative. */
  mask_add = r8 >> 31;
  r0 += modulus->v[0] & mask_add;
  r1 += modulus->v[1] & mask_add;
  /* We know modulus->v[i] is zero for i=2..7.  */
  r8 += modulus->v[8] & mask_add;
  r1 += r0 >> 31; r0 &= 0x7fffffff;
  r2 += r1 >> 31; r1 &= 0x7fffffff;
  r3 += r2 >> 31; r2 &= 0x7fffffff;
  r4 += r3 >> 31; r3 &= 0x7fffffff;
  r5 += r4 >> 31; r4 &= 0x7fffffff;
  r6 += r5 >> 31; r5 &= 0x7fffffff;
  r7 += r6 >> 31; r6 &= 0x7fffffff;
  r8 += r7 >> 31; r7 &= 0x7fffffff;

  /* It brings r from range (-2*modulus,modulus) to range
     [0,modulus). */

  r->v[0] = r0;
  r->v[1] = r1;
  r->v[2] = r2;
  r->v[3] = r3;
  r->v[4] = r4;
  r->v[5] = r5;
  r->v[6] = r6;
  r->v[7] = r7;
  r->v[8] = r8;
}

/*
 * Multiplicative inverse by the safegcd
 */
static void
modinv_safegcd (sr256 *x, const sr256 *modulus, uint32_t inv31, int iterations)
{
  sr256 d = {{0}};
  sr256 e = {{1}};
  sr256 f = *modulus;
  sr256 g = *x;
  int32_t zeta = -1;
  int i;

  for (i = 0; i < iterations; i++)
    {
      matrix_2x2 t;

      zeta = modinv_divsteps (zeta, f.v[0], g.v[0], &t);
      modinv_update_de (&d, &e, &t, modulus, inv31);
      modinv_update_fg (&f, &g, &t);
    }

  modinv_normalize (&d, f.v[8], modulus);
  *x = d;
}

#if SIZEOF_UNSIGNED___INT128 == 16
#define USE_64BIT_51_LIMB   1
#else
#define USE_32BIT_25_5_LIMB 1
#endif

#if defined(USE_32BIT_25_5_LIMB)

/* Redundant representation with signed limb for bignum integer,
 * using 2^25.5 for the base.
 */
#define RR25519_WORDS 10
typedef struct rr25519 {
  int32_t w[RR25519_WORDS];
} rr25519;

/* X = 0 */
static inline void
rr25519_0 (rr25519 *x)
{
  memset(x, 0, sizeof (rr25519));
}

/* X = 1 */
static inline void
rr25519_1 (rr25519 *x)
{
  x->w[0] = 1;
  memset(&x->w[1], 0, sizeof (int32_t) * (RR25519_WORDS - 1));
}

/* DST = SRC */
static inline void
rr25519_copy (rr25519 *dst, const rr25519 *src)
{
  memcpy (dst, src, sizeof (rr25519));
}

/* A <=> B conditionally */
static void
rr25519_swap_cond (rr25519 *a, rr25519 *b, uint32_t c)
{
  int i;
  uint32_t mask = 0UL - c;
  uint32_t *p = (uint32_t *)a->w;
  uint32_t *q = (uint32_t *)b->w;

  asm volatile ("" : "+r" (mask) : : "memory");
  for (i = 0; i < RR25519_WORDS; i++)
    {
      uint32_t t = mask & (*p^*q);
      *p++ ^= t;
      *q++ ^= t;
    }
}

/* X = (A + B) mod 2^255-19 */
static void
rr25519_add (rr25519 *x, const rr25519 *a, const rr25519 *b)
{
  x->w[0] = a->w[0] + b->w[0];
  x->w[1] = a->w[1] + b->w[1];
  x->w[2] = a->w[2] + b->w[2];
  x->w[3] = a->w[3] + b->w[3];
  x->w[4] = a->w[4] + b->w[4];
  x->w[5] = a->w[5] + b->w[5];
  x->w[6] = a->w[6] + b->w[6];
  x->w[7] = a->w[7] + b->w[7];
  x->w[8] = a->w[8] + b->w[8];
  x->w[9] = a->w[9] + b->w[9];
}

/* X = (A - B) mod 2^255-19 */
static void
rr25519_sub (rr25519 *x, const rr25519 *a, const rr25519 *b)
{
  x->w[0] = a->w[0] - b->w[0];
  x->w[1] = a->w[1] - b->w[1];
  x->w[2] = a->w[2] - b->w[2];
  x->w[3] = a->w[3] - b->w[3];
  x->w[4] = a->w[4] - b->w[4];
  x->w[5] = a->w[5] - b->w[5];
  x->w[6] = a->w[6] - b->w[6];
  x->w[7] = a->w[7] - b->w[7];
  x->w[8] = a->w[8] - b->w[8];
  x->w[9] = a->w[9] - b->w[9];
}

/* Multiply two 32-bit integers, resulting 64-bit integer.  */
static inline int64_t
m32x32 (int32_t a, int32_t b)
{
  return a * (int64_t)b;
}

/* X = (A * B) mod 2^255-19 */
static void
rr25519_mul (rr25519 *x, const rr25519 *a, const rr25519 *b)
{
  int64_t carry0, carry1, carry2, carry3, carry4;
  int64_t carry5, carry6, carry7, carry8, carry9;

  int32_t a0 = a->w[0];
  int32_t a1 = a->w[1];
  int32_t a2 = a->w[2];
  int32_t a3 = a->w[3];
  int32_t a4 = a->w[4];
  int32_t a5 = a->w[5];
  int32_t a6 = a->w[6];
  int32_t a7 = a->w[7];
  int32_t a8 = a->w[8];
  int32_t a9 = a->w[9];

  int32_t b0 = b->w[0];
  int32_t b1 = b->w[1];
  int32_t b2 = b->w[2];
  int32_t b3 = b->w[3];
  int32_t b4 = b->w[4];
  int32_t b5 = b->w[5];
  int32_t b6 = b->w[6];
  int32_t b7 = b->w[7];
  int32_t b8 = b->w[8];
  int32_t b9 = b->w[9];

  int32_t b1_19 = 19 * b1;
  int32_t b2_19 = 19 * b2;
  int32_t b3_19 = 19 * b3;
  int32_t b4_19 = 19 * b4;
  int32_t b5_19 = 19 * b5;
  int32_t b6_19 = 19 * b6;
  int32_t b7_19 = 19 * b7;
  int32_t b8_19 = 19 * b8;
  int32_t b9_19 = 19 * b9;
  int32_t a1_2  = 2 * a1;
  int32_t a3_2  = 2 * a3;
  int32_t a5_2  = 2 * a5;
  int32_t a7_2  = 2 * a7;
  int32_t a9_2  = 2 * a9;

  int64_t a0b0    = m32x32 (a0, b0);
  int64_t a0b1    = m32x32 (a0, b1);
  int64_t a0b2    = m32x32 (a0, b2);
  int64_t a0b3    = m32x32 (a0, b3);
  int64_t a0b4    = m32x32 (a0, b4);
  int64_t a0b5    = m32x32 (a0, b5);
  int64_t a0b6    = m32x32 (a0, b6);
  int64_t a0b7    = m32x32 (a0, b7);
  int64_t a0b8    = m32x32 (a0, b8);
  int64_t a0b9    = m32x32 (a0, b9);
  int64_t a1b0    = m32x32 (a1, b0);
  int64_t a1b1_2  = m32x32 (a1_2, b1);
  int64_t a1b2    = m32x32 (a1, b2);
  int64_t a1b3_2  = m32x32 (a1_2, b3);
  int64_t a1b4    = m32x32 (a1, b4);
  int64_t a1b5_2  = m32x32 (a1_2, b5);
  int64_t a1b6    = m32x32 (a1, b6);
  int64_t a1b7_2  = m32x32 (a1_2, b7);
  int64_t a1b8    = m32x32 (a1, b8);
  int64_t a1b9_38 = m32x32 (a1_2, b9_19);
  int64_t a2b0    = m32x32 (a2, b0);
  int64_t a2b1    = m32x32 (a2, b1);
  int64_t a2b2    = m32x32 (a2, b2);
  int64_t a2b3    = m32x32 (a2, b3);
  int64_t a2b4    = m32x32 (a2, b4);
  int64_t a2b5    = m32x32 (a2, b5);
  int64_t a2b6    = m32x32 (a2, b6);
  int64_t a2b7    = m32x32 (a2, b7);
  int64_t a2b8_19 = m32x32 (a2, b8_19);
  int64_t a2b9_19 = m32x32 (a2, b9_19);
  int64_t a3b0    = m32x32 (a3, b0);
  int64_t a3b1_2  = m32x32 (a3_2, b1);
  int64_t a3b2    = m32x32 (a3, b2);
  int64_t a3b3_2  = m32x32 (a3_2, b3);
  int64_t a3b4    = m32x32 (a3, b4);
  int64_t a3b5_2  = m32x32 (a3_2, b5);
  int64_t a3b6    = m32x32 (a3, b6);
  int64_t a3b7_38 = m32x32 (a3_2, b7_19);
  int64_t a3b8_19 = m32x32 (a3, b8_19);
  int64_t a3b9_38 = m32x32 (a3_2, b9_19);
  int64_t a4b0    = m32x32 (a4, b0);
  int64_t a4b1    = m32x32 (a4, b1);
  int64_t a4b2    = m32x32 (a4, b2);
  int64_t a4b3    = m32x32 (a4, b3);
  int64_t a4b4    = m32x32 (a4, b4);
  int64_t a4b5    = m32x32 (a4, b5);
  int64_t a4b6_19 = m32x32 (a4, b6_19);
  int64_t a4b7_19 = m32x32 (a4, b7_19);
  int64_t a4b8_19 = m32x32 (a4, b8_19);
  int64_t a4b9_19 = m32x32 (a4, b9_19);
  int64_t a5b0    = m32x32 (a5, b0);
  int64_t a5b1_2  = m32x32 (a5_2, b1);
  int64_t a5b2    = m32x32 (a5, b2);
  int64_t a5b3_2  = m32x32 (a5_2, b3);
  int64_t a5b4    = m32x32 (a5, b4);
  int64_t a5b5_38 = m32x32 (a5_2, b5_19);
  int64_t a5b6_19 = m32x32 (a5, b6_19);
  int64_t a5b7_38 = m32x32 (a5_2, b7_19);
  int64_t a5b8_19 = m32x32 (a5, b8_19);
  int64_t a5b9_38 = m32x32 (a5_2, b9_19);
  int64_t a6b0    = m32x32 (a6, b0);
  int64_t a6b1    = m32x32 (a6, b1);
  int64_t a6b2    = m32x32 (a6, b2);
  int64_t a6b3    = m32x32 (a6, b3);
  int64_t a6b4_19 = m32x32 (a6, b4_19);
  int64_t a6b5_19 = m32x32 (a6, b5_19);
  int64_t a6b6_19 = m32x32 (a6, b6_19);
  int64_t a6b7_19 = m32x32 (a6, b7_19);
  int64_t a6b8_19 = m32x32 (a6, b8_19);
  int64_t a6b9_19 = m32x32 (a6, b9_19);
  int64_t a7b0    = m32x32 (a7, b0);
  int64_t a7b1_2  = m32x32 (a7_2, b1);
  int64_t a7b2    = m32x32 (a7, b2);
  int64_t a7b3_38 = m32x32 (a7_2, b3_19);
  int64_t a7b4_19 = m32x32 (a7, b4_19);
  int64_t a7b5_38 = m32x32 (a7_2, b5_19);
  int64_t a7b6_19 = m32x32 (a7, b6_19);
  int64_t a7b7_38 = m32x32 (a7_2, b7_19);
  int64_t a7b8_19 = m32x32 (a7, b8_19);
  int64_t a7b9_38 = m32x32 (a7_2, b9_19);
  int64_t a8b0    = m32x32 (a8, b0);
  int64_t a8b1    = m32x32 (a8, b1);
  int64_t a8b2_19 = m32x32 (a8, b2_19);
  int64_t a8b3_19 = m32x32 (a8, b3_19);
  int64_t a8b4_19 = m32x32 (a8, b4_19);
  int64_t a8b5_19 = m32x32 (a8, b5_19);
  int64_t a8b6_19 = m32x32 (a8, b6_19);
  int64_t a8b7_19 = m32x32 (a8, b7_19);
  int64_t a8b8_19 = m32x32 (a8, b8_19);
  int64_t a8b9_19 = m32x32 (a8, b9_19);
  int64_t a9b0    = m32x32 (a9, b0);
  int64_t a9b1_38 = m32x32 (a9_2, b1_19);
  int64_t a9b2_19 = m32x32 (a9, b2_19);
  int64_t a9b3_38 = m32x32 (a9_2, b3_19);
  int64_t a9b4_19 = m32x32 (a9, b4_19);
  int64_t a9b5_38 = m32x32 (a9_2, b5_19);
  int64_t a9b6_19 = m32x32 (a9, b6_19);
  int64_t a9b7_38 = m32x32 (a9_2, b7_19);
  int64_t a9b8_19 = m32x32 (a9, b8_19);
  int64_t a9b9_38 = m32x32 (a9_2, b9_19);

  int64_t x0 = (a0b0 + a1b9_38 + a2b8_19 + a3b7_38 + a4b6_19 + a5b5_38
                + a6b4_19 + a7b3_38 + a8b2_19 + a9b1_38);
  int64_t x1 = (a0b1 + a1b0 + a2b9_19 + a3b8_19 + a4b7_19 + a5b6_19 + a6b5_19
                + a7b4_19 + a8b3_19 + a9b2_19);
  int64_t x2 = (a0b2 + a1b1_2 + a2b0 + a3b9_38 + a4b8_19 + a5b7_38 + a6b6_19
                + a7b5_38 + a8b4_19 + a9b3_38);
  int64_t x3 = (a0b3 + a1b2 + a2b1 + a3b0 + a4b9_19 + a5b8_19 + a6b7_19
                + a7b6_19 + a8b5_19 + a9b4_19);
  int64_t x4 = (a0b4 + a1b3_2 + a2b2 + a3b1_2 + a4b0 + a5b9_38 + a6b8_19
                + a7b7_38 + a8b6_19 + a9b5_38);
  int64_t x5 = (a0b5 + a1b4 + a2b3 + a3b2 + a4b1 + a5b0 + a6b9_19 + a7b8_19
                + a8b7_19 + a9b6_19);
  int64_t x6 = (a0b6 + a1b5_2 + a2b4 + a3b3_2 + a4b2 + a5b1_2 + a6b0
                + a7b9_38 + a8b8_19 + a9b7_38);
  int64_t x7 = (a0b7 + a1b6 + a2b5 + a3b4 + a4b3 + a5b2 + a6b1 + a7b0
                + a8b9_19 + a9b8_19);
  int64_t x8 = (a0b8 + a1b7_2 + a2b6 + a3b5_2 + a4b4 + a5b3_2 + a6b2 + a7b1_2
                + a8b0 + a9b9_38);
  int64_t x9 = (a0b9 + a1b8 + a2b7 + a3b6 + a4b5 + a5b4 + a6b3 + a7b2
                + a8b1 + a9b0);

  carry0 = (x0 + (1 << 25)) >> 26;
  x1 += carry0;
  x0 -= (carry0 << 26);
  carry4 = (x4 + (1 << 25)) >> 26;
  x5 += carry4;
  x4 -= (carry4 << 26);

  carry1 = (x1 + (1 << 24)) >> 25;
  x2 += carry1;
  x1 -= (carry1 << 25);
  carry5 = (x5 + (1 << 24)) >> 25;
  x6 += carry5;
  x5 -= (carry5 << 25);

  carry2 = (x2 + (1 << 25)) >> 26;
  x3 += carry2;
  x2 -= (carry2 << 26);
  carry6 = (x6 + (1 << 25)) >> 26;
  x7 += carry6;
  x6 -= (carry6 << 26);

  carry3 = (x3 + (1 << 24)) >> 25;
  x4 += carry3;
  x3 -= (carry3 << 25);
  carry7 = (x7 + (1 << 24)) >> 25;
  x8 += carry7;
  x7 -= (carry7 << 25);

  carry4 = (x4 + (1 << 25)) >> 26;
  x5 += carry4;
  x4 -= (carry4 << 26);
  carry8 = (x8 + (1 << 25)) >> 26;
  x9 += carry8;
  x8 -= (carry8 << 26);

  carry9 = (x9 + (1 << 24)) >> 25;
  x0 += carry9 * 19;
  x9 -= (carry9 << 25);

  carry0 = (x0 + (1 << 25)) >> 26;
  x1 += carry0;
  x0 -= (carry0 << 26);

  x->w[0] = (int32_t)x0;
  x->w[1] = (int32_t)x1;
  x->w[2] = (int32_t)x2;
  x->w[3] = (int32_t)x3;
  x->w[4] = (int32_t)x4;
  x->w[5] = (int32_t)x5;
  x->w[6] = (int32_t)x6;
  x->w[7] = (int32_t)x7;
  x->w[8] = (int32_t)x8;
  x->w[9] = (int32_t)x9;
}

/* X = (A ^ 2) mod 2^255-19 */
static void
rr25519_sqr (rr25519 *x, const rr25519 *a)
{
  int64_t carry0, carry1, carry2, carry3, carry4;
  int64_t carry5, carry6, carry7, carry8, carry9;

  int32_t a0 = a->w[0];
  int32_t a1 = a->w[1];
  int32_t a2 = a->w[2];
  int32_t a3 = a->w[3];
  int32_t a4 = a->w[4];
  int32_t a5 = a->w[5];
  int32_t a6 = a->w[6];
  int32_t a7 = a->w[7];
  int32_t a8 = a->w[8];
  int32_t a9 = a->w[9];

  int32_t a0_2  = 2 * a0;
  int32_t a1_2  = 2 * a1;
  int32_t a2_2  = 2 * a2;
  int32_t a3_2  = 2 * a3;
  int32_t a4_2  = 2 * a4;
  int32_t a5_2  = 2 * a5;
  int32_t a6_2  = 2 * a6;
  int32_t a7_2  = 2 * a7;
  int32_t a5_38 = 38 * a5;
  int32_t a6_19 = 19 * a6;
  int32_t a7_38 = 38 * a7;
  int32_t a8_19 = 19 * a8;
  int32_t a9_38 = 38 * a9;

  int64_t a0a0    = m32x32 (a0, a0);
  int64_t a0a1_2  = m32x32 (a0_2, a1);
  int64_t a0a2_2  = m32x32 (a0_2, a2);
  int64_t a0a3_2  = m32x32 (a0_2, a3);
  int64_t a0a4_2  = m32x32 (a0_2, a4);
  int64_t a0a5_2  = m32x32 (a0_2, a5);
  int64_t a0a6_2  = m32x32 (a0_2, a6);
  int64_t a0a7_2  = m32x32 (a0_2, a7);
  int64_t a0a8_2  = m32x32 (a0_2, a8);
  int64_t a0a9_2  = m32x32 (a0_2, a9);
  int64_t a1a1_2  = m32x32 (a1_2, a1);
  int64_t a1a2_2  = m32x32 (a1_2, a2);
  int64_t a1a3_4  = m32x32 (a1_2, a3_2);
  int64_t a1a4_2  = m32x32 (a1_2, a4);
  int64_t a1a5_4  = m32x32 (a1_2, a5_2);
  int64_t a1a6_2  = m32x32 (a1_2, a6);
  int64_t a1a7_4  = m32x32 (a1_2, a7_2);
  int64_t a1a8_2  = m32x32 (a1_2, a8);
  int64_t a1a9_76 = m32x32 (a1_2, a9_38);
  int64_t a2a2    = m32x32 (a2, a2);
  int64_t a2a3_2  = m32x32 (a2_2, a3);
  int64_t a2a4_2  = m32x32 (a2_2, a4);
  int64_t a2a5_2  = m32x32 (a2_2, a5);
  int64_t a2a6_2  = m32x32 (a2_2, a6);
  int64_t a2a7_2  = m32x32 (a2_2, a7);
  int64_t a2a8_38 = m32x32 (a2_2, a8_19);
  int64_t a2a9_38 = m32x32 (a2, a9_38);
  int64_t a3a3_2  = m32x32 (a3_2, a3);
  int64_t a3a4_2  = m32x32 (a3_2, a4);
  int64_t a3a5_4  = m32x32 (a3_2, a5_2);
  int64_t a3a6_2  = m32x32 (a3_2, a6);
  int64_t a3a7_76 = m32x32 (a3_2, a7_38);
  int64_t a3a8_38 = m32x32 (a3_2, a8_19);
  int64_t a3a9_76 = m32x32 (a3_2, a9_38);
  int64_t a4a4    = m32x32 (a4, a4);
  int64_t a4a5_2  = m32x32 (a4_2, a5);
  int64_t a4a6_38 = m32x32 (a4_2, a6_19);
  int64_t a4a7_38 = m32x32 (a4, a7_38);
  int64_t a4a8_38 = m32x32 (a4_2, a8_19);
  int64_t a4a9_38 = m32x32 (a4, a9_38);
  int64_t a5a5_38 = m32x32 (a5, a5_38);
  int64_t a5a6_38 = m32x32 (a5_2, a6_19);
  int64_t a5a7_76 = m32x32 (a5_2, a7_38);
  int64_t a5a8_38 = m32x32 (a5_2, a8_19);
  int64_t a5a9_76 = m32x32 (a5_2, a9_38);
  int64_t a6a6_19 = m32x32 (a6, a6_19);
  int64_t a6a7_38 = m32x32 (a6, a7_38);
  int64_t a6a8_38 = m32x32 (a6_2, a8_19);
  int64_t a6a9_38 = m32x32 (a6, a9_38);
  int64_t a7a7_38 = m32x32 (a7, a7_38);
  int64_t a7a8_38 = m32x32 (a7_2, a8_19);
  int64_t a7a9_76 = m32x32 (a7_2, a9_38);
  int64_t a8a8_19 = m32x32 (a8, a8_19);
  int64_t a8a9_38 = m32x32 (a8, a9_38);
  int64_t a9a9_38 = m32x32 (a9, a9_38);

  int64_t x0 = a0a0 + a1a9_76 + a2a8_38 + a3a7_76 + a4a6_38 + a5a5_38;
  int64_t x1 = a0a1_2 + a2a9_38 + a3a8_38 + a4a7_38 + a5a6_38;
  int64_t x2 = a0a2_2 + a1a1_2 + a3a9_76 + a4a8_38 + a5a7_76 + a6a6_19;
  int64_t x3 = a0a3_2 + a1a2_2 + a4a9_38 + a5a8_38 + a6a7_38;
  int64_t x4 = a0a4_2 + a1a3_4 + a2a2 + a5a9_76 + a6a8_38 + a7a7_38;
  int64_t x5 = a0a5_2 + a1a4_2 + a2a3_2 + a6a9_38 + a7a8_38;
  int64_t x6 = a0a6_2 + a1a5_4 + a2a4_2 + a3a3_2 + a7a9_76 + a8a8_19;
  int64_t x7 = a0a7_2 + a1a6_2 + a2a5_2 + a3a4_2 + a8a9_38;
  int64_t x8 = a0a8_2 + a1a7_4 + a2a6_2 + a3a5_4 + a4a4 + a9a9_38;
  int64_t x9 = a0a9_2 + a1a8_2 + a2a7_2 + a3a6_2 + a4a5_2;

  carry0 = (x0 + (1 << 25)) >> 26;
  x1 += carry0;
  x0 -= (carry0 << 26);
  carry4 = (x4 + (1 << 25)) >> 26;
  x5 += carry4;
  x4 -= (carry4 << 26);

  carry1 = (x1 + (1 << 24)) >> 25;
  x2 += carry1;
  x1 -= (carry1 << 25);
  carry5 = (x5 + (1 << 24)) >> 25;
  x6 += carry5;
  x5 -= (carry5 << 25);

  carry2 = (x2 + (1 << 25)) >> 26;
  x3 += carry2;
  x2 -= (carry2 << 26);
  carry6 = (x6 + (1 << 25)) >> 26;
  x7 += carry6;
  x6 -= (carry6 << 26);

  carry3 = (x3 + (1 << 24)) >> 25;
  x4 += carry3;
  x3 -= (carry3 << 25);
  carry7 = (x7 + (1 << 24)) >> 25;
  x8 += carry7;
  x7 -= (carry7 << 25);

  carry4 = (x4 + (1 << 25)) >> 26;
  x5 += carry4;
  x4 -= (carry4 << 26);
  carry8 = (x8 + (1 << 25)) >> 26;
  x9 += carry8;
  x8 -= (carry8 << 26);

  carry9 = (x9 + (1 << 24)) >> 25;
  x0 += carry9 * 19;
  x9 -= (carry9 << 25);

  carry0 = (x0 + (1 << 25)) >> 26;
  x1 += carry0;
  x0 -= (carry0 << 26);

  x->w[0] = (int32_t)x0;
  x->w[1] = (int32_t)x1;
  x->w[2] = (int32_t)x2;
  x->w[3] = (int32_t)x3;
  x->w[4] = (int32_t)x4;
  x->w[5] = (int32_t)x5;
  x->w[6] = (int32_t)x6;
  x->w[7] = (int32_t)x7;
  x->w[8] = (int32_t)x8;
  x->w[9] = (int32_t)x9;
}

/*
 * A = 486662
 * a24 which stands for (A - 2)/4 = 121665
 */
static void
rr25519_mul_121665 (rr25519 *x, const rr25519 *a)
{
  int64_t carry0, carry1, carry2, carry3, carry4;
  int64_t carry5, carry6, carry7, carry8, carry9;
  int64_t v0 = m32x32 (a->w[0], 121665);
  int64_t v1 = m32x32 (a->w[1], 121665);
  int64_t v2 = m32x32 (a->w[2], 121665);
  int64_t v3 = m32x32 (a->w[3], 121665);
  int64_t v4 = m32x32 (a->w[4], 121665);
  int64_t v5 = m32x32 (a->w[5], 121665);
  int64_t v6 = m32x32 (a->w[6], 121665);
  int64_t v7 = m32x32 (a->w[7], 121665);
  int64_t v8 = m32x32 (a->w[8], 121665);
  int64_t v9 = m32x32 (a->w[9], 121665);

  carry1 = (v1 + (1 << 24)) >> 25;
  v2 += carry1;
  v1 -= (carry1 << 25);
  carry3 = (v3 + (1 << 24)) >> 25;
  v4 += carry3;
  v3 -= (carry3 << 25);
  carry5 = (v5 + (1 << 24)) >> 25;
  v6 += carry5;
  v5 -= (carry5 << 25);
  carry7 = (v7 + (1 << 24)) >> 25;
  v8 += carry7;
  v7 -= (carry7 << 25);
  carry9 = (v9 + (1 << 24)) >> 25;
  v0 += carry9 * 19;
  v9 -= (carry9 << 25);

  carry0 = (v0 + (1 << 25)) >> 26;
  v1 += carry0;
  v0 -= (carry0 << 26);
  carry2 = (v2 + (1 << 25)) >> 26;
  v3 += carry2;
  v2 -= (carry2 << 26);
  carry4 = (v4 + (1 << 25)) >> 26;
  v5 += carry4;
  v4 -= (carry4 << 26);
  carry6 = (v6 + (1 << 25)) >> 26;
  v7 += carry6;
  v6 -= (carry6 << 26);
  carry8 = (v8 + (1 << 25)) >> 26;
  v9 += carry8;
  v8 -= (carry8 << 26);

  x->w[0] = (int32_t)v0;
  x->w[1] = (int32_t)v1;
  x->w[2] = (int32_t)v2;
  x->w[3] = (int32_t)v3;
  x->w[4] = (int32_t)v4;
  x->w[5] = (int32_t)v5;
  x->w[6] = (int32_t)v6;
  x->w[7] = (int32_t)v7;
  x->w[8] = (int32_t)v8;
  x->w[9] = (int32_t)v9;
}

/* Copied from aes.c, changing the return type into 64-bit. */
static uint64_t
get_uint32_le (const unsigned char *b, unsigned int i)
{
  return (  ((uint64_t)b[i    ]      )
          | ((uint64_t)b[i + 1] <<  8)
          | ((uint64_t)b[i + 2] << 16)
          | ((uint64_t)b[i + 3] << 24));
}

static uint64_t
get_uint24_le (const unsigned char *b, unsigned int i)
{
  return (  ((uint64_t)b[i    ]      )
          | ((uint64_t)b[i + 1] <<  8)
          | ((uint64_t)b[i + 2] << 16));
}

/* Expand byte representation into the redundant representation.  */
static void
rr25519_expand (rr25519 *x, const unsigned char *src)
{
  int64_t carry0, carry1, carry2, carry3, carry4;
  int64_t carry5, carry6, carry7, carry8, carry9;
  int64_t v0 = get_uint32_le (src, 0);
  int64_t v1 = get_uint24_le (src, 4) << 6;
  int64_t v2 = get_uint24_le (src, 7) << 5;
  int64_t v3 = get_uint24_le (src, 10) << 3;
  int64_t v4 = get_uint24_le (src, 13) << 2;
  int64_t v5 = get_uint32_le (src, 16);
  int64_t v6 = get_uint24_le (src, 20) << 7;
  int64_t v7 = get_uint24_le (src, 23) << 5;
  int64_t v8 = get_uint24_le (src, 26) << 4;
  int64_t v9 = (get_uint24_le (src, 29) & 0x7fffff) << 2;

  carry1 = (v1 + (1 << 24)) >> 25;
  v2 += carry1;
  v1 -= (carry1 << 25);
  carry3 = (v3 + (1 << 24)) >> 25;
  v4 += carry3;
  v3 -= (carry3 << 25);
  carry5 = (v5 + (1 << 24)) >> 25;
  v6 += carry5;
  v5 -= (carry5 << 25);
  carry7 = (v7 + (1 << 24)) >> 25;
  v8 += carry7;
  v7 -= (carry7 << 25);
  carry9 = (v9 + (1 << 24)) >> 25;
  v0 += carry9 * 19;
  v9 -= (carry9 << 25);

  carry0 = (v0 + (1 << 25)) >> 26;
  v1 += carry0;
  v0 -= (carry0 << 26);
  carry2 = (v2 + (1 << 25)) >> 26;
  v3 += carry2;
  v2 -= (carry2 << 26);
  carry4 = (v4 + (1 << 25)) >> 26;
  v5 += carry4;
  v4 -= (carry4 << 26);
  carry6 = (v6 + (1 << 25)) >> 26;
  v7 += carry6;
  v6 -= (carry6 << 26);
  carry8 = (v8 + (1 << 25)) >> 26;
  v9 += carry8;
  v8 -= (carry8 << 26);

  x->w[0] = (int32_t)v0;
  x->w[1] = (int32_t)v1;
  x->w[2] = (int32_t)v2;
  x->w[3] = (int32_t)v3;
  x->w[4] = (int32_t)v4;
  x->w[5] = (int32_t)v5;
  x->w[6] = (int32_t)v6;
  x->w[7] = (int32_t)v7;
  x->w[8] = (int32_t)v8;
  x->w[9] = (int32_t)v9;
}

/* Strong reduce */
static void
rr25519_reduce (rr25519 *x, const rr25519 *a)
{
  int32_t q;
  int32_t carry0, carry1, carry2, carry3, carry4;
  int32_t carry5, carry6, carry7, carry8, carry9;
  int32_t x0 = a->w[0];
  int32_t x1 = a->w[1];
  int32_t x2 = a->w[2];
  int32_t x3 = a->w[3];
  int32_t x4 = a->w[4];
  int32_t x5 = a->w[5];
  int32_t x6 = a->w[6];
  int32_t x7 = a->w[7];
  int32_t x8 = a->w[8];
  int32_t x9 = a->w[9];

  q = (19 * x9 + (1 << 24)) >> 25;
  q = (x0 + q) >> 26;
  q = (x1 + q) >> 25;
  q = (x2 + q) >> 26;
  q = (x3 + q) >> 25;
  q = (x4 + q) >> 26;
  q = (x5 + q) >> 25;
  q = (x6 + q) >> 26;
  q = (x7 + q) >> 25;
  q = (x8 + q) >> 26;
  q = (x9 + q) >> 25;

  x0 += 19 * q;

  carry0 = x0 >> 26;
  x1 += carry0;
  x0 -= (carry0 << 26);
  carry1 = x1 >> 25;
  x2 += carry1;
  x1 -= (carry1 << 25);
  carry2 = x2 >> 26;
  x3 += carry2;
  x2 -= (carry2 << 26);
  carry3 = x3 >> 25;
  x4 += carry3;
  x3 -= (carry3 << 25);
  carry4 = x4 >> 26;
  x5 += carry4;
  x4 -= (carry4 << 26);
  carry5 = x5 >> 25;
  x6 += carry5;
  x5 -= (carry5 << 25);
  carry6 = x6 >> 26;
  x7 += carry6;
  x6 -= (carry6 << 26);
  carry7 = x7 >> 25;
  x8 += carry7;
  x7 -= (carry7 << 25);
  carry8 = x8 >> 26;
  x9 += carry8;
  x8 -= (carry8 << 26);
  carry9 = x9 >> 25;
  x9 -= (carry9 << 25);

  x->w[0] = x0;
  x->w[1] = x1;
  x->w[2] = x2;
  x->w[3] = x3;
  x->w[4] = x4;
  x->w[5] = x5;
  x->w[6] = x6;
  x->w[7] = x7;
  x->w[8] = x8;
  x->w[9] = x9;
}

static void
rr25519_contract (unsigned char *dst, const rr25519 *x)
{
  rr25519 t[1];

  rr25519_reduce (t, x);
  dst[0]  = t->w[0] >> 0;
  dst[1]  = t->w[0] >> 8;
  dst[2]  = t->w[0] >> 16;
  dst[3]  = (t->w[0] >> 24) | (t->w[1] << 2);
  dst[4]  = t->w[1] >> 6;
  dst[5]  = t->w[1] >> 14;
  dst[6]  = (t->w[1] >> 22) | (t->w[2] << 3);
  dst[7]  = t->w[2] >> 5;
  dst[8]  = t->w[2] >> 13;
  dst[9]  = (t->w[2] >> 21) | (t->w[3] << 5);
  dst[10] = t->w[3] >> 3;
  dst[11] = t->w[3] >> 11;
  dst[12] = (t->w[3] >> 19) | (t->w[4] << 6);
  dst[13] = t->w[4] >> 2;
  dst[14] = t->w[4] >> 10;
  dst[15] = t->w[4] >> 18;
  dst[16] = t->w[5] >> 0;
  dst[17] = t->w[5] >> 8;
  dst[18] = t->w[5] >> 16;
  dst[19] = (t->w[5] >> 24) | (t->w[6] << 1);
  dst[20] = t->w[6] >> 7;
  dst[21] = t->w[6] >> 15;
  dst[22] = (t->w[6] >> 23) | (t->w[7] << 3);
  dst[23] = t->w[7] >> 5;
  dst[24] = t->w[7] >> 13;
  dst[25] = (t->w[7] >> 21) | (t->w[8] << 4);
  dst[26] = t->w[8] >> 4;
  dst[27] = t->w[8] >> 12;
  dst[28] = (t->w[8] >> 20) | (t->w[9] << 6);
  dst[29] = t->w[9] >> 2;
  dst[30] = t->w[9] >> 10;
  dst[31] = t->w[9] >> 18;
}

/* fe: Field Element */
typedef rr25519 fe;
#define fe_add       rr25519_add
#define fe_sub       rr25519_sub
#define fe_mul       rr25519_mul
#define fe_sqr       rr25519_sqr
#define fe_a24       rr25519_mul_121665
#define fe_swap_cond rr25519_swap_cond
#define fe_0         rr25519_0
#define fe_1         rr25519_1
#define fe_copy      rr25519_copy
#define fe_expand    rr25519_expand
#define fe_contract  rr25519_contract

/**
 * @brief  Process Montgomery double-and-add
 *
 * With Q0, Q1, DIF (= Q0 - Q1), compute PRD = 2Q0, SUM = Q0 + Q1
 * On return, PRD is in Q0, SUM is in Q1
 * Caller provides temporary T0 and T1
 *
 * Note: indentation graphycally expresses the ladder.
 */
static void
montgomery_step (fe *x0, fe *z0, fe *x1, fe *z1, const fe *dif_x, fe *t0, fe *t1)
{
#define xp   x0
#define zp   z0
#define xs   x1
#define zs   z1
#define C       t0
#define D       t1
#define A       x1
#define B       x0
#define CB      t0
#define DA      t1
#define AA      z0
#define BB      x1
#define CBpDA   z1              /* CB + DA */
#define CBmDA   t0              /* CB - DA */
#define E       t1
#define CBmDAsq t0              /* (CB - DA)^2 */
#define a24E    t0
#define a24EpAA z0              /* AA + a24E */

                                    fe_add (C, x1, z1);
                                            fe_sub (D, x1, z1);
  fe_add (A, x0, z0);
          fe_sub (B, x0, z0);
                                    fe_mul (CB, B, C);
                                            fe_mul (DA, A, D);
  fe_sqr (AA, A);
          fe_sqr (BB, B);
                                    fe_add (CBpDA, CB, DA);
                                            fe_sub (CBmDA, CB, DA);
  fe_mul (xp, AA, BB);
          fe_sub (E, AA, BB);
                                    fe_sqr (xs, CBpDA);
                                            fe_sqr (CBmDAsq, CBmDA);
                                            fe_mul (zs, CBmDAsq, dif_x);
          fe_a24 (a24E, E);
          fe_add (a24EpAA, AA, a24E);
          fe_mul (zp, a24EpAA, E);
}
#undef xp
#undef zp
#undef xs
#undef zs
#undef C
#undef D
#undef A
#undef B
#undef CB
#undef DA
#undef AA
#undef BB
#undef CBpDA
#undef CBmDA
#undef E
#undef CBmDAsq
#undef a24E
#undef a24EpAA

typedef struct bn256 {
  uint32_t w[8];
} bn256;

typedef struct bn512 {
  uint32_t w[16];
} bn512;

static void
bn_to_signed31 (sr256 *r, const bn256 *a)
{
  uint32_t a0, a1, a2, a3, a4, a5, a6, a7;

  a0 = a->w[0];
  a1 = a->w[1];
  a2 = a->w[2];
  a3 = a->w[3];
  a4 = a->w[4];
  a5 = a->w[5];
  a6 = a->w[6];
  a7 = a->w[7];

  r->v[0] =               (a0 <<  0) & 0x7fffffff;
  r->v[1] = (a0 >> 31) | ((a1 <<  1) & 0x7fffffff);
  r->v[2] = (a1 >> 30) | ((a2 <<  2) & 0x7fffffff);
  r->v[3] = (a2 >> 29) | ((a3 <<  3) & 0x7fffffff);
  r->v[4] = (a3 >> 28) | ((a4 <<  4) & 0x7fffffff);
  r->v[5] = (a4 >> 27) | ((a5 <<  5) & 0x7fffffff);
  r->v[6] = (a5 >> 26) | ((a6 <<  6) & 0x7fffffff);
  r->v[7] = (a6 >> 25) | ((a7 <<  7) & 0x7fffffff);
  r->v[8] = (a7 >> 24);
}

static void
bn_from_signed31 (bn256 *a, const sr256 *r)
{
  uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8;

  /* Input must be [0,modulus)... */
  r0 = r->v[0];
  r1 = r->v[1];
  r2 = r->v[2];
  r3 = r->v[3];
  r4 = r->v[4];
  r5 = r->v[5];
  r6 = r->v[6];
  r7 = r->v[7];
  r8 = r->v[8];

  a->w[0] = (r0 >>  0) | (r1 << 31);
  a->w[1] = (r1 >>  1) | (r2 << 30);
  a->w[2] = (r2 >>  2) | (r3 << 29);
  a->w[3] = (r3 >>  3) | (r4 << 28);
  a->w[4] = (r4 >>  4) | (r5 << 27);
  a->w[5] = (r5 >>  5) | (r6 << 26);
  a->w[6] = (r6 >>  6) | (r7 << 25);
  a->w[7] = (r7 >>  7) | (r8 << 24);
  /* ... then, (r8 >> 24) should be zero, here.  */
}

static void
fe_invert (bn256 *R, const bn256 *X)
{
  sr256 s[1];

  memcpy (R, X, sizeof (bn256));

  bn_to_signed31 (s, R);
  modinv_safegcd (s, &modulus_25519, modulus_inv31_25519, 19);
  bn_from_signed31 (R, s);
}

static void
fe_tobyte (unsigned char *p, const bn256 *X)
{
  const uint32_t *x = X->w;

  buf_put_le32 (p,    x[0]);
  buf_put_le32 (p+4,  x[1]);
  buf_put_le32 (p+8,  x[2]);
  buf_put_le32 (p+12, x[3]);
  buf_put_le32 (p+16, x[4]);
  buf_put_le32 (p+20, x[5]);
  buf_put_le32 (p+24, x[6]);
  buf_put_le32 (p+28, x[7]);
}

static uint32_t
bn256_add_uint (bn256 *X, const bn256 *A, uint32_t w)
{
  int i;
  uint32_t carry = w;
  uint32_t *px = X->w;
  const uint32_t *pa = A->w;

  for (i = 0; i < 8; i++)
    {
      *px = *pa + carry;
      carry = (*px < carry);
      px++;
      pa++;
    }

  return carry;
}

static void
bn256_mul (bn512 *X, const bn256 *A, const bn256 *B)
{
  int i, j, k;
  int i_beg, i_end;
  uint32_t r0, r1, r2;

  r0 = r1 = r2 = 0;
  for (k = 0; k <= (8 - 1)*2; k++)
    {
      if (k < 8)
	{
	  i_beg = 0;
	  i_end = k;
	}
      else
	{
	  i_beg = k - 8 + 1;
	  i_end = 8 - 1;
	}

      for (i = i_beg; i <= i_end; i++)
	{
	  uint64_t uv;
	  uint32_t u, v;
	  uint32_t carry;

	  j = k - i;

	  uv = ((uint64_t )A->w[i])*((uint64_t )B->w[j]);
	  v = uv;
	  u = (uv >> 32);
	  r0 += v;
	  carry = (r0 < v);
	  r1 += carry;
	  carry = (r1 < carry);
	  r1 += u;
	  carry += (r1 < u);
	  r2 += carry;
	}

      X->w[k] = r0;
      r0 = r1;
      r1 = r2;
      r2 = 0;
    }

  X->w[k] = r0;
}

/**
 * @brief  X = A mod 2^256-38
 *
 * Note that the second argument is not "const bn512 *".
 * A is modified during the computation of modulo.
 *
 * It's not precisely modulo 2^256-38 for all cases,
 * but result may be redundant.
 */
static void
mod25638_reduce (bn256 *X, bn512 *A)
{
  const uint32_t *s;
  uint32_t *d;
  uint32_t w;

  s = &A->w[8]; d = &A->w[0]; w = 38;
  {
    int i;
    uint64_t r;
    uint32_t carry;

    r = 0;
    for (i = 0; i < 8; i++)
      {
	uint64_t uv;

	r += d[i];
	carry = (r < d[i]);

	uv = ((uint64_t)s[i])*w;
	r += uv;
	carry += (r < uv);

	d[i] = (uint32_t)r;
	r = ((r >> 32) | ((uint64_t)carry << 32));
      }

    carry = bn256_add_uint (X, (bn256 *)A, r * 38);
    X->w[0] += carry * 38;
  }
}

static void
mod25638_mul (bn256 *X, const bn256 *A, const bn256 *B)
{
  bn512 tmp[1];

  bn256_mul (tmp, A, B);
  mod25638_reduce (X, tmp);
}

static void
mod25519_reduce (bn256 *X)
{
  uint32_t q;
  bn256 R[1];

  q = (X->w[7] >> 31);
  X->w[7] &= 0x7fffffff;

  bn256_add_uint (X, X, q * 19);

  bn256_add_uint (R, X, 19);
  q = (R->w[7] >> 31);
  R->w[7] &= 0x7fffffff;

  ct_memmov_cond (X->w, R->w, 8 * sizeof (uint32_t), q);
}

int
crypto_scalarmult (unsigned char *q,
                   const unsigned char *secret,
                   const unsigned char *p)
{
  int i;
  uint32_t swap = 0;
  unsigned char n[32];
  fe X0[1], Z0[1], X1[1], Z1[1];
  fe T0[1], T1[1];
  fe X[1];
  bn256 x0bn[1], z0bn[1];
  bn256 res[1];

  for (i = 0; i < 32; i++)
    n[i] = secret[i];
  n[0] &= 248;
  n[31] &= 127;
  n[31] |= 64;

  /* P0 = O = (1:0)  */
  fe_1 (X0);
  fe_0 (Z0);

  /* P1 = (X:1) */
  fe_expand (X, p);
  fe_copy (X1, X);
  fe_copy (Z1, X0);

  for (i = 254; i >= 0; i--)
    {
      uint32_t b = (n[i>>3]>>(i&7))&1;

      swap ^= b;
      fe_swap_cond (X0, X1, swap);
      fe_swap_cond (Z0, Z1, swap);
      swap = b;
      montgomery_step (X0, Z0, X1, Z1, X, T0, T1);
    }

  fe_contract ((unsigned char *)x0bn, X0);
  fe_contract ((unsigned char *)z0bn, Z0);
  fe_invert (res, z0bn);
  mod25638_mul (res, res, x0bn);
  mod25519_reduce (res);
  fe_tobyte (q, res);
  return 0;
}
#else
typedef __int128_t int128_t;
typedef __uint128_t uint128_t;

typedef struct bn256 {
  uint64_t w[4];
} bn256;

typedef struct bn512 {
  uint64_t w[8];
} bn512;


static void
bn_to_signed31 (sr256 *r, const bn256 *a)
{
  uint32_t a0, a1, a2, a3, a4, a5, a6, a7;

  a0 = a->w[0];
  a1 = a->w[0] >> 32;
  a2 = a->w[1];
  a3 = a->w[1] >> 32;
  a4 = a->w[2];
  a5 = a->w[2] >> 32;
  a6 = a->w[3];
  a7 = a->w[3] >> 32;

  r->v[0] =               (a0 <<  0) & 0x7fffffff;
  r->v[1] = (a0 >> 31) | ((a1 <<  1) & 0x7fffffff);
  r->v[2] = (a1 >> 30) | ((a2 <<  2) & 0x7fffffff);
  r->v[3] = (a2 >> 29) | ((a3 <<  3) & 0x7fffffff);
  r->v[4] = (a3 >> 28) | ((a4 <<  4) & 0x7fffffff);
  r->v[5] = (a4 >> 27) | ((a5 <<  5) & 0x7fffffff);
  r->v[6] = (a5 >> 26) | ((a6 <<  6) & 0x7fffffff);
  r->v[7] = (a6 >> 25) | ((a7 <<  7) & 0x7fffffff);
  r->v[8] = (a7 >> 24);
}

static void
bn_from_signed31 (bn256 *a, const sr256 *r)
{
  uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8;

  /* Input must be [0,modulus)... */
  r0 = r->v[0];
  r1 = r->v[1];
  r2 = r->v[2];
  r3 = r->v[3];
  r4 = r->v[4];
  r5 = r->v[5];
  r6 = r->v[6];
  r7 = r->v[7];
  r8 = r->v[8];

  a->w[0] = (r0 >>  0) | (r1 << 31);
  a->w[0] |= (uint64_t)((r1 >>  1) | (r2 << 30)) << 32;
  a->w[1] = (r2 >>  2) | (r3 << 29);
  a->w[1] |= (uint64_t)((r3 >>  3) | (r4 << 28)) << 32;
  a->w[2] = (r4 >>  4) | (r5 << 27);
  a->w[2] |= (uint64_t)((r5 >>  5) | (r6 << 26)) << 32;
  a->w[3] = (r6 >>  6) | (r7 << 25);
  a->w[3] |= (uint64_t)((r7 >>  7) | (r8 << 24)) << 32;
  /* ... then, (r8 >> 24) should be zero, here.  */
}

/**
 * @brief R = X^(-1) mod N
 *
 * NOTE: If X==0, it return 0.
 *
 */
static void
fe_invert (bn256 *R, const bn256 *X)
{
  sr256 s[1];

  memcpy (R, X, sizeof (bn256));

  bn_to_signed31 (s, R);
  modinv_safegcd (s, &modulus_25519, modulus_inv31_25519, 19);
  bn_from_signed31 (R, s);
}

static uint64_t
bn256_add_uint (bn256 *X, const bn256 *A, uint64_t w)
{
  uint64_t carry = w;
  uint64_t v0;
  const uint64_t *a = A->w;
  uint64_t *x = X->w;

  v0 = *a++;
  v0 += carry;
  carry = (v0 < carry);
  *x++ = v0;

  v0 = *a++;
  v0 += carry;
  carry = (v0 < carry);
  *x++ = v0;

  v0 = *a++;
  v0 += carry;
  carry = (v0 < carry);
  *x++ = v0;

  v0 = *a++;
  v0 += carry;
  carry = (v0 < carry);
  *x++ = v0;

  return carry;
}

/* A*B */
#define mul128(r0,r1,r2,a,b) \
  uv = ((uint128_t)a)*b;     \
  u = (uv >> 64);            \
  v = uv;                    \
  r0 += v;                   \
  carry = (r0 < v);          \
  r1 += carry;               \
  carry = (r1 < carry);      \
  r1 += u;                   \
  carry += (r1 < u);         \
  r2 += carry

/* 2*A*B */
#define mul128_2(r0,r1,r2,a,b) \
  uv = ((uint128_t)a)*b;       \
  r2 += (uv >> 127);           \
  uv <<= 1;                    \
  u = (uv >> 64);              \
  v = uv;                      \
  r0 += v;                     \
  carry = (r0 < v);            \
  r1 += carry;                 \
  carry = (r1 < carry);        \
  r1 += u;                     \
  carry += (r1 < u);           \
  r2 += carry

/* 38*A */
#define mul128_38(r0,r1,a) \
  uv = ((uint128_t)a)*38;  \
  u = (uv >> 64);          \
  v = uv;                  \
  r0 += v;                 \
  r1 += (r0 < v);          \
  r1 += u

static void
bn256_mul (bn512 *X, const bn256 *A, const bn256 *B)
{
  uint128_t uv;
  uint64_t u, v;
  uint64_t r0, r1, r2;
  uint64_t carry;
  const uint64_t *a = A->w;
  const uint64_t *b = B->w;
  uint64_t *x = X->w;

  r0 = r1 = r2 = 0;

  mul128 (r0, r1, r2, a[0], b[0]);
  x[0] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[1], b[0]);
  mul128 (r0, r1, r2, a[0], b[1]);
  x[1] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[2], b[0]);
  mul128 (r0, r1, r2, a[1], b[1]);
  mul128 (r0, r1, r2, a[0], b[2]);
  x[2] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[3], b[0]);
  mul128 (r0, r1, r2, a[2], b[1]);
  mul128 (r0, r1, r2, a[1], b[2]);
  mul128 (r0, r1, r2, a[0], b[3]);
  x[3] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[3], b[1]);
  mul128 (r0, r1, r2, a[2], b[2]);
  mul128 (r0, r1, r2, a[1], b[3]);
  x[4] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[3], b[2]);
  mul128 (r0, r1, r2, a[2], b[3]);
  x[5] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[3], b[3]);
  x[6] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  x[7] = r0;
}


/* X = A mod 2^256-38
 *
 * A is modified during the computation.
 */
static void
mod25638_reduce (bn256 *X, bn512 *A)
{
  uint128_t uv;
  uint64_t u, v;
  const uint64_t *s;
  uint64_t *d;
  uint64_t r0, r1;
  uint64_t carry;
  uint64_t *a = A->w;
  uint64_t *x = X->w;

  s = &a[4]; d = &a[0];

  r0 = d[0];
  r1 = 0;
  mul128_38 (r0, r1, s[0]);
  d[0] = r0;
  r0 = r1;
  r1 = 0;

  r0 += d[1];
  r1 += (r0 < d[1]);
  mul128_38 (r0, r1, s[1]);
  d[1] = r0;
  r0 = r1;
  r1 = 0;

  r0 += d[2];
  r1 += (r0 < d[2]);
  mul128_38 (r0, r1, s[2]);
  d[2] = r0;
  r0 = r1;
  r1 = 0;

  r0 += d[3];
  r1 += (r0 < d[3]);
  mul128_38 (r0, r1, s[3]);
  d[3] = r0;
  r0 = r1;
  r1 = 0;

  carry = bn256_add_uint (X, (bn256 *)A, r0 * 38);
  x[0] += (0UL - carry) & 38;
}

static void
mod25519_reduce (bn256 *X)
{
  uint64_t q;
  bn256 R[1];

  q = (X->w[3] >> 63);
  X->w[3] &= 0x7fffffffffffffffUL;

  bn256_add_uint (X, X, q * 19);

  bn256_add_uint (R, X, 19);
  q = (R->w[3] >> 63);
  R->w[3] &= 0x7fffffffffffffffUL;

  ct_memmov_cond (X->w, R->w, 4 * sizeof (uint64_t), q);
}

/* X = (A * B) mod 2^256-38 */
static void
mod25638_mul (bn256 *X, const bn256 *A, const bn256 *B)
{
  bn512 tmp[1];

  bn256_mul (tmp, A, B);
  mod25638_reduce (X, tmp);
}

static void
fe_tobyte (unsigned char *p, const bn256 *X)
{
  const uint64_t *x = X->w;

  buf_put_le64 (p,    x[0]);
  buf_put_le64 (p+8,  x[1]);
  buf_put_le64 (p+16, x[2]);
  buf_put_le64 (p+24, x[3]);
}
# if defined(USE_64BIT_51_LIMB)

/* Redundant representation with signed limb for bignum integer,
 * using 2^51 for the base.
 */
#define RR25519_WORDS 5
typedef struct rr25519 {
  uint64_t w[RR25519_WORDS];
} rr25519;

/* X = 0 */
static inline void
rr25519_0 (rr25519 *x)
{
  memset(x, 0, sizeof (rr25519));
}

/* X = 1 */
static inline void
rr25519_1 (rr25519 *x)
{
  x->w[0] = 1;
  memset(&x->w[1], 0, sizeof (uint64_t) * (RR25519_WORDS - 1));
}

/* DST = SRC */
static inline void
rr25519_copy (rr25519 *dst, const rr25519 *src)
{
  memcpy (dst, src, sizeof (rr25519));
}

/* A <=> B conditionally */
static void
rr25519_swap_cond (rr25519 *a, rr25519 *b, uint64_t c)
{
  int i;
  uint64_t mask = 0UL - c;
  uint64_t *p = (uint64_t *)a->w;
  uint64_t *q = (uint64_t *)b->w;

  asm volatile ("" : "+r" (mask) : : "memory");
  for (i = 0; i < RR25519_WORDS; i++)
    {
      uint64_t t = mask & (*p^*q);
      *p++ ^= t;
      *q++ ^= t;
    }
}

/* X = (A + B) mod 2^255-19 */
static void
rr25519_add (rr25519 *x, const rr25519 *a, const rr25519 *b)
{
  x->w[0] = a->w[0] + b->w[0];
  x->w[1] = a->w[1] + b->w[1];
  x->w[2] = a->w[2] + b->w[2];
  x->w[3] = a->w[3] + b->w[3];
  x->w[4] = a->w[4] + b->w[4];
}

/* X = (A - B) mod 2^255-19 */
static void
rr25519_sub (rr25519 *x, const rr25519 *a, const rr25519 *b)
{
  const uint64_t mask = 0x7ffffffffffffUL;
  uint64_t a0 = a->w[0];
  uint64_t a1 = a->w[1];
  uint64_t a2 = a->w[2];
  uint64_t a3 = a->w[3];
  uint64_t a4 = a->w[4];

  uint64_t b0 = b->w[0];
  uint64_t b1 = b->w[1];
  uint64_t b2 = b->w[2];
  uint64_t b3 = b->w[3];
  uint64_t b4 = b->w[4];

  b1 += b0 >> 51;
  b0 &= mask;
  b2 += b1 >> 51;
  b1 &= mask;
  b3 += b2 >> 51;
  b2 &= mask;
  b4 += b3 >> 51;
  b3 &= mask;
  b0 += 19 * (b4 >> 51);
  b4 &= mask;

  b0 = (a0 + 0xfffffffffffdaUL) - b0;
  b1 = (a1 + 0xffffffffffffeUL) - b1;
  b2 = (a2 + 0xffffffffffffeUL) - b2;
  b3 = (a3 + 0xffffffffffffeUL) - b3;
  b4 = (a4 + 0xffffffffffffeUL) - b4;

  x->w[0] = b0;
  x->w[1] = b1;
  x->w[2] = b2;
  x->w[3] = b3;
  x->w[4] = b4;
}

/* Multiply two 64-bit integers, resulting 128-bit integer.  */
static inline uint128_t
m64x64 (uint64_t a, uint64_t b)
{
  return a * (uint128_t)b;
}

/*
 * Using SymPy:
from sympy import *

a, b = symbols('a b')
a0, a1, a2, a3, a4 = symbols('a0 a1 a2 a3 a4')
b0, b1, b2, b3, b4 = symbols('b0 b1 b2 b3 b4')
B = symbols('B')
a = a0 + a1*B + a2*B**2 + a3*B**3 + a4*B**4
b = b0 + b1*B + b2*B**2 + b3*B**3 + b4*B**4
x = symbols('x')
x = a*b

x_exp = collect(expand(x),B)

# i = 0
# for term in x_exp.args:
#     t_exp[i] = term
#     i = i + 1

term = Symbol('term')
t_exp = [ term for term in x_exp.args ]

# Swap 0-th and 1-th
tmp = t_exp[0]
t_exp[0] = t_exp[1]
t_exp[1] = tmp

# Only take the coefficients
t_exp[1] =  t_exp[1]  / (B)
t_exp[2] =  t_exp[2]  / (B*B)
t_exp[3] =  t_exp[3]  / (B*B*B)
t_exp[4] =  t_exp[4]  / (B*B*B*B)
t_exp[5] =  t_exp[5]  / (B*B*B*B*B)
t_exp[6] =  t_exp[6]  / (B*B*B*B*B*B)
t_exp[7] =  t_exp[7]  / (B*B*B*B*B*B*B)
t_exp[8] =  t_exp[8]  / (B*B*B*B*B*B*B*B)

for i in range(9):
    print_ccode(t_exp[i])

for i in range(4):
    t_exp[0+i] = t_exp[0+i] + t_exp[5+i]*19

for i in range(5):
    print_ccode(t_exp[i])

a0*b0 + 19*a1*b4 + 19*a2*b3 + 19*a3*b2 + 19*a4*b1
a0*b1 + a1*b0 + 19*a2*b4 + 19*a3*b3 + 19*a4*b2
a0*b2 + a1*b1 + a2*b0 + 19*a3*b4 + 19*a4*b3
a0*b3 + a1*b2 + a2*b1 + a3*b0 + 19*a4*b4
a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0

48

7f
>> 7
 */

/* X = (A * B) mod 2^255-19 */
static void
rr25519_mul (rr25519 *x, const rr25519 *a, const rr25519 *b)
{
  const uint64_t mask = 0x7ffffffffffffUL;
  uint64_t a0 = a->w[0];
  uint64_t a1 = a->w[1];
  uint64_t a2 = a->w[2];
  uint64_t a3 = a->w[3];
  uint64_t a4 = a->w[4];

  uint64_t b0 = b->w[0];
  uint64_t b1 = b->w[1];
  uint64_t b2 = b->w[2];
  uint64_t b3 = b->w[3];
  uint64_t b4 = b->w[4];

  uint64_t b1_19 = 19 * b1;
  uint64_t b2_19 = 19 * b2;
  uint64_t b3_19 = 19 * b3;
  uint64_t b4_19 = 19 * b4;

  uint128_t a0b0    = m64x64 (a0, b0);
  uint128_t a0b1    = m64x64 (a0, b1);
  uint128_t a0b2    = m64x64 (a0, b2);
  uint128_t a0b3    = m64x64 (a0, b3);
  uint128_t a0b4    = m64x64 (a0, b4);
  uint128_t a1b0    = m64x64 (a1, b0);
  uint128_t a1b1    = m64x64 (a1, b1);
  uint128_t a1b2    = m64x64 (a1, b2);
  uint128_t a1b3    = m64x64 (a1, b3);
  uint128_t a1b4_19 = m64x64 (a1, b4_19);
  uint128_t a2b0    = m64x64 (a2, b0);
  uint128_t a2b1    = m64x64 (a2, b1);
  uint128_t a2b2    = m64x64 (a2, b2);
  uint128_t a2b3_19 = m64x64 (a2, b3_19);
  uint128_t a2b4_19 = m64x64 (a2, b4_19);
  uint128_t a3b0    = m64x64 (a3, b0);
  uint128_t a3b1    = m64x64 (a3, b1);
  uint128_t a3b2_19 = m64x64 (a3, b2_19);
  uint128_t a3b3_19 = m64x64 (a3, b3_19);
  uint128_t a3b4_19 = m64x64 (a3, b4_19);
  uint128_t a4b0    = m64x64 (a4, b0);
  uint128_t a4b1_19 = m64x64 (a4, b1_19);
  uint128_t a4b2_19 = m64x64 (a4, b2_19);
  uint128_t a4b3_19 = m64x64 (a4, b3_19);
  uint128_t a4b4_19 = m64x64 (a4, b4_19);

  uint128_t x0 = (a0b0 + a1b4_19 + a2b3_19 + a3b2_19 + a4b1_19);
  uint128_t x1 = (a0b1 + a1b0    + a2b4_19 + a3b3_19 + a4b2_19);
  uint128_t x2 = (a0b2 + a1b1    + a2b0    + a3b4_19 + a4b3_19);
  uint128_t x3 = (a0b3 + a1b2    + a2b1    + a3b0    + a4b4_19);
  uint128_t x4 = (a0b4 + a1b3    + a2b2    + a3b1    + a4b0);

  uint64_t  r00, r01, r02, r03, r04;
  uint64_t  carry;

  r00    = ((uint64_t) x0) & mask;
  carry  = (x0 >> 51);
  x1    += carry;
  r01    = ((uint64_t) x1) & mask;
  carry  = (x1 >> 51);
  x2    += carry;
  r02    = ((uint64_t) x2) & mask;
  carry  = (x2 >> 51);
  x3    += carry;
  r03    = ((uint64_t) x3) & mask;
  carry  = (x3 >> 51);
  x4    += carry;
  r04    = ((uint64_t) x4) & mask;
  carry  = (x4 >> 51);
  r00   += 19 * carry;
  carry  = r00 >> 51;
  r00   &= mask;
  r01   += carry;
  carry  = r01 >> 51;
  r01   &= mask;
  r02   += carry;

  x->w[0] = r00;
  x->w[1] = r01;
  x->w[2] = r02;
  x->w[3] = r03;
  x->w[4] = r04;
}

/*
from sympy import *

a = symbols('a')
a0, a1, a2, a3, a4 = symbols('a0 a1 a2 a3 a4')
B = symbols('B')
a = a0 + a1*B + a2*B**2 + a3*B**3 + a4*B**4
x = symbols('x')
x = a*a

x_exp = collect(expand(x),B)

t = [ x_exp.coeff(B,i) for i in range(9) ]

# for i in range(9):
#     print_ccode(t[i])

print('==============')

for i in range(4):
    t[0+i] = t[0+i] + t[5+i]*19


for i in range(5):
    print_ccode(t[i])

==============
pow(a0, 2) + 38*a1*a4 + 38*a2*a3
2*a0*a1 + 38*a2*a4 + 19*pow(a3, 2)
2*a0*a2 + pow(a1, 2) + 38*a3*a4
2*a0*a3 + 2*a1*a2 + 19*pow(a4, 2)
2*a0*a4 + 2*a1*a3 + pow(a2, 2)
 */
/* X = (A ^ 2) mod 2^255-19 */
static void
rr25519_sqr (rr25519 *x, const rr25519 *a)
{
  const uint64_t mask = 0x7ffffffffffffUL;
  uint64_t a0 = a->w[0];
  uint64_t a1 = a->w[1];
  uint64_t a2 = a->w[2];
  uint64_t a3 = a->w[3];
  uint64_t a4 = a->w[4];

  uint64_t a0_2  = 2 * a0;
  uint64_t a1_2  = 2 * a1;
  uint64_t a2_2  = 2 * a2;
  uint64_t a3_2  = 2 * a3;
  uint64_t a3_19  = 19 * a3;
  uint64_t a4_19  = 19 * a4;

  uint128_t a0a0     = m64x64 (a0, a0);
  uint128_t a0a1_2   = m64x64 (a0_2, a1);
  uint128_t a0a2_2   = m64x64 (a0_2, a2);
  uint128_t a0a3_2   = m64x64 (a0_2, a3);
  uint128_t a0a4_2   = m64x64 (a0_2, a4);
  uint128_t a1a1     = m64x64 (a1, a1);
  uint128_t a1a2_2   = m64x64 (a1_2, a2);
  uint128_t a1a3_2   = m64x64 (a1_2, a3);
  uint128_t a1a4_38  = m64x64 (a1_2, a4_19);
  uint128_t a2a2     = m64x64 (a2, a2);
  uint128_t a2a3_38  = m64x64 (a2_2, a3_19);
  uint128_t a2a4_38  = m64x64 (a2_2, a4_19);
  uint128_t a3a3_19  = m64x64 (a3, a3_19);
  uint128_t a3a4_38  = m64x64 (a3_2, a4_19);
  uint128_t a4a4_19  = m64x64 (a4, a4_19);

  uint128_t x0 = a0a0   + a1a4_38 + a2a3_38;
  uint128_t x1 = a0a1_2 + a2a4_38 + a3a3_19;
  uint128_t x2 = a0a2_2 + a1a1    + a3a4_38;
  uint128_t x3 = a0a3_2 + a1a2_2  + a4a4_19;
  uint128_t x4 = a0a4_2 + a1a3_2  + a2a2;

  uint64_t  r00, r01, r02, r03, r04;
  uint64_t  carry;

  r00    = ((uint64_t) x0) & mask;
  carry  = (x0 >> 51);
  x1    += carry;
  r01    = ((uint64_t) x1) & mask;
  carry  = (x1 >> 51);
  x2    += carry;
  r02    = ((uint64_t) x2) & mask;
  carry  = (x2 >> 51);
  x3    += carry;
  r03    = ((uint64_t) x3) & mask;
  carry  = (x3 >> 51);
  x4    += carry;
  r04    = ((uint64_t) x4) & mask;
  carry  = (x4 >> 51);
  r00   += 19 * carry;
  carry  = r00 >> 51;
  r00   &= mask;
  r01   += carry;
  carry  = r01 >> 51;
  r01   &= mask;
  r02   += carry;

  x->w[0] = r00;
  x->w[1] = r01;
  x->w[2] = r02;
  x->w[3] = r03;
  x->w[4] = r04;
}

/*
 * A = 486662
 * a24 which stands for (A - 2)/4 = 121665
 */
static void
rr25519_mul_121665 (rr25519 *x, const rr25519 *a)
{
  const uint64_t mask = 0x7ffffffffffffUL;
  uint128_t x0 = m64x64 (a->w[0], 121665);
  uint128_t x1 = m64x64 (a->w[1], 121665);
  uint128_t x2 = m64x64 (a->w[2], 121665);
  uint128_t x3 = m64x64 (a->w[3], 121665);
  uint128_t x4 = m64x64 (a->w[4], 121665);
  uint64_t  r00, r01, r02, r03, r04;
  uint64_t  carry;

  r00    = ((uint64_t) x0) & mask;
  carry  = (x0 >> 51);
  x1    += carry;
  r01    = ((uint64_t) x1) & mask;
  carry  = (x1 >> 51);
  x2    += carry;
  r02    = ((uint64_t) x2) & mask;
  carry  = (x2 >> 51);
  x3    += carry;
  r03    = ((uint64_t) x3) & mask;
  carry  = (x3 >> 51);
  x4    += carry;
  r04    = ((uint64_t) x4) & mask;
  carry  = (x4 >> 51);
  r00   += 19 * carry;
  carry  = r00 >> 51;
  r00   &= mask;
  r01   += carry;
  carry  = r01 >> 51;
  r01   &= mask;
  r02   += carry;

  x->w[0] = r00;
  x->w[1] = r01;
  x->w[2] = r02;
  x->w[3] = r03;
  x->w[4] = r04;
}

/* Expand byte representation into the redundant representation.  */
static void
rr25519_expand (rr25519 *x, const unsigned char *src)
{
  const uint64_t mask = 0x7ffffffffffffUL;
  uint64_t v0 = (buf_get_le64 (src+ 0) >>  0) & mask;
  uint64_t v1 = (buf_get_le64 (src+ 6) >>  3) & mask;
  uint64_t v2 = (buf_get_le64 (src+12) >>  6) & mask;
  uint64_t v3 = (buf_get_le64 (src+19) >>  1) & mask;
  uint64_t v4 = (buf_get_le64 (src+24) >> 12) & mask;

  x->w[0] = v0;
  x->w[1] = v1;
  x->w[2] = v2;
  x->w[3] = v3;
  x->w[4] = v4;
}

/* Strong reduce */
static void
rr25519_reduce (rr25519 *x, const rr25519 *a)
{
  const uint64_t mask = 0x7ffffffffffffUL;
  uint64_t v0 = a->w[0];
  uint64_t v1 = a->w[1];
  uint64_t v2 = a->w[2];
  uint64_t v3 = a->w[3];
  uint64_t v4 = a->w[4];

  v1 += v0 >> 51;
  v0 &= mask;
  v2 += v1 >> 51;
  v1 &= mask;
  v3 += v2 >> 51;
  v2 &= mask;
  v4 += v3 >> 51;
  v3 &= mask;
  v0 += 19 * (v4 >> 51);
  v4 &= mask;

  v1 += v0 >> 51;
  v0 &= mask;
  v2 += v1 >> 51;
  v1 &= mask;
  v3 += v2 >> 51;
  v2 &= mask;
  v4 += v3 >> 51;
  v3 &= mask;
  v0 += 19 * (v4 >> 51);
  v4 &= mask;

  v0 += 19;

  v1 += v0 >> 51;
  v0 &= mask;
  v2 += v1 >> 51;
  v1 &= mask;
  v3 += v2 >> 51;
  v2 &= mask;
  v4 += v3 >> 51;
  v3 &= mask;
  v0 += 19 * (v4 >> 51);
  v4 &= mask;

  v0 += 0x8000000000000 - 19UL;
  v1 += 0x8000000000000 - 1UL;
  v2 += 0x8000000000000 - 1UL;
  v3 += 0x8000000000000 - 1UL;
  v4 += 0x8000000000000 - 1UL;

  v1 += v0 >> 51;
  v0 &= mask;
  v2 += v1 >> 51;
  v1 &= mask;
  v3 += v2 >> 51;
  v2 &= mask;
  v4 += v3 >> 51;
  v3 &= mask;
  v4 &= mask;

  x->w[0] = v0;
  x->w[1] = v1;
  x->w[2] = v2;
  x->w[3] = v3;
  x->w[4] = v4;
}

static void
rr25519_contract (unsigned char *dst, const rr25519 *x)
{
  rr25519 t[1];
  uint64_t t0, t1, t2, t3;

  rr25519_reduce (t, x);
  t0 = (t->w[0] >>  0) | (t->w[1] << 51);
  t1 = (t->w[1] >> 13) | (t->w[2] << 38);
  t2 = (t->w[2] >> 26) | (t->w[3] << 25);
  t3 = (t->w[3] >> 39) | (t->w[4] << 12);
  buf_put_le64 (dst +  0, t0);
  buf_put_le64 (dst +  8, t1);
  buf_put_le64 (dst + 16, t2);
  buf_put_le64 (dst + 24, t3);
}

/* fe: Field Element */
typedef rr25519 fe;
#define fe_add       rr25519_add
#define fe_sub       rr25519_sub
#define fe_mul       rr25519_mul
#define fe_sqr       rr25519_sqr
#define fe_a24       rr25519_mul_121665
#define fe_swap_cond rr25519_swap_cond
#define fe_0         rr25519_0
#define fe_1         rr25519_1
#define fe_copy      rr25519_copy
#define fe_expand    rr25519_expand
#define fe_contract  rr25519_contract

/**
 * @brief  Process Montgomery double-and-add
 *
 * With Q0, Q1, DIF (= Q0 - Q1), compute PRD = 2Q0, SUM = Q0 + Q1
 * On return, PRD is in Q0, SUM is in Q1
 * Caller provides temporary T0 and T1
 *
 * Note: indentation graphycally expresses the ladder.
 */
static void
montgomery_step (fe *x0, fe *z0, fe *x1, fe *z1, const fe *dif_x, fe *t0, fe *t1)
{
#define xp   x0
#define zp   z0
#define xs   x1
#define zs   z1
#define C       t0
#define D       t1
#define A       x1
#define B       x0
#define CB      t0
#define DA      t1
#define AA      z0
#define BB      x1
#define CBpDA   z1              /* CB + DA */
#define CBmDA   t0              /* CB - DA */
#define E       t1
#define CBmDAsq t0              /* (CB - DA)^2 */
#define a24E    t0
#define a24EpAA z0              /* AA + a24E */

                                    fe_add (C, x1, z1);
                                            fe_sub (D, x1, z1);
  fe_add (A, x0, z0);
          fe_sub (B, x0, z0);
                                    fe_mul (CB, B, C);
                                            fe_mul (DA, A, D);
  fe_sqr (AA, A);
          fe_sqr (BB, B);
                                    fe_add (CBpDA, CB, DA);
                                            fe_sub (CBmDA, CB, DA);
  fe_mul (xp, AA, BB);
          fe_sub (E, AA, BB);
                                    fe_sqr (xs, CBpDA);
                                            fe_sqr (CBmDAsq, CBmDA);
                                            fe_mul (zs, CBmDAsq, dif_x);
          fe_a24 (a24E, E);
          fe_add (a24EpAA, AA, a24E);
          fe_mul (zp, a24EpAA, E);
}
#undef xp
#undef zp
#undef xs
#undef zs
#undef C
#undef D
#undef A
#undef B
#undef CB
#undef DA
#undef AA
#undef BB
#undef CBpDA
#undef CBmDA
#undef E
#undef CBmDAsq
#undef a24E
#undef a24EpAA

int
crypto_scalarmult (unsigned char *q,
                   const unsigned char *secret,
                   const unsigned char *p)
{
  int i;
  uint32_t swap = 0;
  unsigned char n[32];
  fe X0[1], Z0[1], X1[1], Z1[1];
  fe T0[1], T1[1], q_x_rr[1];
  bn256 x0bn[1], z0bn[1];
  bn256 res[1];

  for (i = 0; i < 32; i++)
    n[i] = secret[i];
  n[0] &= 248;
  n[31] &= 127;
  n[31] |= 64;

  /* P0 = O = (1:0)  */
  fe_1 (X0);
  fe_0 (Z0);

  /* P1 = (X:1) */
  fe_expand (X1, p);
  fe_copy (q_x_rr, X1);
  fe_copy (Z1, X0);

  for (i = 254; i >= 0; i--)
    {
      uint32_t b = (n[i>>3]>>(i&7))&1;

      swap ^= b;
      fe_swap_cond (X0, X1, swap);
      fe_swap_cond (Z0, Z1, swap);
      swap = b;
      montgomery_step (X0, Z0, X1, Z1, q_x_rr, T0, T1);
    }

  fe_contract ((unsigned char *)x0bn, X0);
  fe_contract ((unsigned char *)z0bn, Z0);
  fe_invert (res, z0bn);
  mod25638_mul (res, res, x0bn);
  mod25519_reduce (res);
  fe_tobyte (q, res);
  return 0;
}
# else
/* Implementation for 64-bit, non-redundant representation (2^256-38)
 * so that we will be able to optimize with Intel ADX (ADCX and ADOX)
 * or similar.
 */
#define fe25638 bn256

#define fe fe25638
#define fe_copy bn256_copy
#define fe_add  fe25638_add
#define fe_sub  fe25638_sub
#define fe_mul  fe25638_mul
#define fe_sqr  fe25638_sqr
#define fe_reduce fe25638_reduce
#define fe_a24  fe25638_mul_121665

#define fe25638_mul mod25638_mul
#define fe25638_reduce mod25638_reduce
#define fe25519_reduce mod25519_reduce

static void
swap_cond (fe25638 *A, fe25638 *B, unsigned long op_enable)
{
  uint64_t mask1 = ct_uintptr_gen_mask(op_enable);
  uint64_t mask2 = ct_uintptr_gen_inv_mask(op_enable);
  size_t i;
  uint64_t *a = A->w;
  uint64_t *b = B->w;

  for (i = 0; i < 4; i++)
    {
      uint64_t xa = a[i];
      uint64_t xb = b[i];

      a[i] = (xa & mask2) | (xb & mask1);
      b[i] = (xa & mask1) | (xb & mask2);
    }
}


static void
bn256_copy (bn256 *X, const bn256 *A)
{
  const uint64_t *s = A->w;
  uint64_t *d = X->w;

  d[0] = s[0];
  d[1] = s[1];
  d[2] = s[2];
  d[3] = s[3];
}

static uint64_t
bn256_add (bn256 *X, const bn256 *A, const bn256 *B)
{
  uint64_t carry = 0;
  uint64_t v0;
  uint64_t v1;
  const uint64_t *a = A->w;
  const uint64_t *b = B->w;
  uint64_t *x = X->w;

  v0 = *a++;
  v1 = *b++;
  v1 += v0;
  carry = (v1 < v0);
  *x++ = v1;

  v0 = *a++;
  v1 = *b++;
  v1 += carry;
  carry = (v1 < carry);
  v1 += v0;
  carry += (v1 < v0);
  *x++ = v1;

  v0 = *a++;
  v1 = *b++;
  v1 += carry;
  carry = (v1 < carry);
  v1 += v0;
  carry += (v1 < v0);
  *x++ = v1;

  v0 = *a++;
  v1 = *b++;
  v1 += carry;
  carry = (v1 < carry);
  v1 += v0;
  carry += (v1 < v0);
  *x++ = v1;

  return carry;
}

static uint64_t
bn256_sub (bn256 *X, const bn256 *A, const bn256 *B)
{
  uint64_t borrow = 0;
  uint64_t v0;
  uint64_t v1;
  uint64_t borrow0;
  const uint64_t *a = A->w;
  const uint64_t *b = B->w;
  uint64_t *x = X->w;

  v0 = *a++;
  v1 = *b++;
  borrow = (v0 < v1);
  v0 -= v1;
  *x++ = v0;

  v0 = *a++;
  v1 = *b++;
  borrow0 = (v0 < borrow);
  v0 -= borrow;
  borrow = (v0 < v1) + borrow0;
  v0 -= v1;
  *x++ = v0;

  v0 = *a++;
  v1 = *b++;
  borrow0 = (v0 < borrow);
  v0 -= borrow;
  borrow = (v0 < v1) + borrow0;
  v0 -= v1;
  *x++ = v0;

  v0 = *a++;
  v1 = *b++;
  borrow0 = (v0 < borrow);
  v0 -= borrow;
  borrow = (v0 < v1) + borrow0;
  v0 -= v1;
  *x++ = v0;

  return borrow;
}


static uint64_t
bn256_sub_uint (bn256 *X, const bn256 *A, uint64_t w)
{
  int i;
  uint64_t borrow = w;
  const uint64_t *a = A->w;
  uint64_t *x = X->w;

  for (i = 0; i < 4; i++)
    {
      uint64_t v0 = *a++;
      uint64_t borrow0 = (v0 < borrow);

      v0 -= borrow;
      borrow = borrow0;
      *x++ = v0;
    }

  return borrow;
}

static void
bn256_sqr (bn512 *X, const bn256 *A)
{
  uint128_t uv;
  uint64_t u, v;
  uint64_t carry;
  uint64_t r0, r1, r2;
  const uint64_t *a = A->w;
  uint64_t *x = X->w;

  r0 = r1 = r2 = 0;
  mul128 (r0, r1, r2, a[0], a[0]);
  x[0] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128_2 (r0, r1, r2, a[1], a[0]);
  x[1] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128_2 (r0, r1, r2, a[2], a[0]);
  mul128 (r0, r1, r2, a[1], a[1]);
  x[2] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128_2 (r0, r1, r2, a[3], a[0]);
  mul128_2 (r0, r1, r2, a[2], a[1]);
  x[3] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128_2 (r0, r1, r2, a[3], a[1]);
  mul128 (r0, r1, r2, a[2], a[2]);
  x[4] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128_2 (r0, r1, r2, a[3], a[2]);
  x[5] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[3], a[3]);
  x[6] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  x[7] = r0;
}


/* X = (A + B) mod 2^256-38 */
static void
fe25638_add (fe25638 *X, const fe25638 *A, const fe25638 *B)
{
  uint64_t carry;
  uint64_t *x = X->w;

  carry = bn256_add (X, A, B);
  carry = bn256_add_uint (X, X, (0UL - carry) & 38);
  x[0] += (0UL - carry) & 38;
}

/* X = (A - B) mod 2^256-38 */
static void
fe25638_sub (fe25638 *X, const fe25638 *A, const fe25638 *B)
{
  uint64_t borrow;
  uint64_t *x = X->w;

  borrow = bn256_sub (X, A, B);
  borrow = bn256_sub_uint (X, X, (0UL - borrow) & 38);
  x[0] -= (0UL - borrow) & 38;
}


/* X = A * A mod 2^256-38 */
static void
fe25638_sqr (fe25638 *X, const fe25638 *A)
{
  bn512 tmp[1];

  bn256_sqr (tmp, A);
  fe25638_reduce (X, tmp);
}

static void
fe25638_mul_121665 (fe25638 *X, const fe25638 *A)
{
  uint128_t uv;
  uint64_t u, v;
  uint64_t carry;
  uint64_t r0, r1, r2;
  const uint64_t *a = A->w;
  uint64_t *x = X->w;

  r0 = r1 = r2 = 0;

  mul128 (r0, r1, r2, a[0], 121665UL);
  x[0] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[1], 121665UL);
  x[1] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[2], 121665UL);
  x[2] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[3], 121665UL);
  x[3] = r0;

  r0 = bn256_add_uint (X, X, r1 * 38);
  x[0] += (0UL - r0) & 38;
}




static void
montgomery_step (fe *x0, fe *z0, fe *x1, fe *z1, const fe *dif_x, fe *t0, fe *t1)
{
#define xp   x0
#define zp   z0
#define xs   x1
#define zs   z1
#define C       t0
#define D       t1
#define A       x1
#define B       x0
#define CB      t0
#define DA      t1
#define AA      z0
#define BB      x1
#define CBpDA   z1              /* CB + DA */
#define CBmDA   t0              /* CB - DA */
#define E       t1
#define CBmDAsq t0              /* (CB - DA)^2 */
#define a24E    t0
#define a24EpAA z0              /* AA + a24E */

                                    fe_add (C, x1, z1);
                                            fe_sub (D, x1, z1);
  fe_add (A, x0, z0);
          fe_sub (B, x0, z0);
                                    fe_mul (CB, B, C);
                                            fe_mul (DA, A, D);
  fe_sqr (AA, A);
          fe_sqr (BB, B);
                                    fe_add (CBpDA, CB, DA);
                                            fe_sub (CBmDA, CB, DA);
  fe_mul (xp, AA, BB);
          fe_sub (E, AA, BB);
                                    fe_sqr (xs, CBpDA);
                                            fe_sqr (CBmDAsq, CBmDA);
                                            fe_mul (zs, CBmDAsq, dif_x);
          fe_a24 (a24E, E);
          fe_add (a24EpAA, AA, a24E);
          fe_mul (zp, a24EpAA, E);
}
#undef xp
#undef zp
#undef xs
#undef zs
#undef C
#undef D
#undef A
#undef B
#undef CB
#undef DA
#undef AA
#undef BB
#undef CBpDA
#undef CBmDA
#undef E
#undef CBmDAsq
#undef a24E
#undef a24EpAA


static void
fe_frombyte (fe25638 *X, const unsigned char *p)
{
  uint64_t *x = X->w;

  x[0] = buf_get_le64 (p);
  x[1] = buf_get_le64 (p+8);
  x[2] = buf_get_le64 (p+16);
  x[3] = buf_get_le64 (p+24);
  x[3] &= 0x7fffffffffffffffUL;
}

int
crypto_scalarmult (unsigned char *q,
                   const unsigned char *secret,
                   const unsigned char *p)
{
  int i;
  unsigned int swap = 0;
  unsigned char n[32];
  fe25638 X0[1], Z0[1], X1[1], Z1[1];
  fe25638 T0[1], T1[1];
  fe25638 X[1];

  for (i = 0; i < 32; i++)
    n[i] = secret[i];
  n[0] &= 248;
  n[31] &= 127;
  n[31] |= 64;

  fe_frombyte (X, p);

  memset (X0->w, 0, sizeof (uint64_t)*4);
  X0->w[0] = 1;
  memset (Z0->w, 0, sizeof (uint64_t)*4);

  fe_copy (X1, X);
  fe_copy (Z1, X0);

  for (i = 254; i >= 0; i--)
    {
      unsigned int b =(n[i>>3]>>(i&7))&1;

      swap ^= b;
      swap_cond (X0, X1, swap);
      swap_cond (Z0, Z1, swap);
      swap = b;
      montgomery_step (X0, Z0, X1, Z1, X, T0, T1);
    }

  fe_invert (Z0, Z0);
  fe_mul (X0, X0, Z0);
  fe25519_reduce (X0);
  fe_tobyte (q, X0);
  return 0;
}
# endif
#endif
