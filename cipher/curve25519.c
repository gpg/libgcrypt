/* Implementation for 64-bit, non-redundant representation (2^256-38)
 * so that we will be able to optimize with Intel ADX (ADCX and ADOX)
 * or similar.
 */

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

#if SIZEOF_UNSIGNED___INT128 == 16
typedef __int128_t int128_t;
typedef __uint128_t uint128_t;

#define fe25638 bn256

typedef struct bn256 {
  uint64_t w[4];
} bn256;

typedef struct bn512 {
  uint64_t w[8];
} bn512;

#define fe fe25638
#define fe_copy bn256_copy
#define fe_add  fe25638_add
#define fe_sub  fe25638_sub
#define fe_mul  fe25638_mul
#define fe_sqr  fe25638_sqr
#define fe_a24  fe25638_mul_121665
#else
#error "For now, code for 64-bit computer is implemented."
#endif

static void
set_cond (uint64_t *x, const uint64_t *r, unsigned long op)
{
  ct_memmov_cond (x, r, 4 * sizeof (uint64_t), op);
}

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
  carry = bn256_add_uint (X, X, (0ULL - carry) & 38);
  x[0] += (0ULL - carry) & 38;
}

/* X = (A - B) mod 2^256-38 */
static void
fe25638_sub (fe25638 *X, const fe25638 *A, const fe25638 *B)
{
  uint64_t borrow;
  uint64_t *x = X->w;

  borrow = bn256_sub (X, A, B);
  borrow = bn256_sub_uint (X, X, (0ULL - borrow) & 38);
  x[0] -= (0ULL - borrow) & 38;
}


/* X = A mod 2^256-38
 *
 * A is modified during the computation.
 */
static void
fe25638_reduce (fe25638 *X, bn512 *A)
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
  x[0] += (0ULL - carry) & 38;
}

/* X = (A * B) mod 2^256-38 */
static void
fe25638_mul (fe25638 *X, const fe25638 *A, const fe25638 *B)
{
  bn512 tmp[1];

  bn256_mul (tmp, A, B);
  fe25638_reduce (X, tmp);
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

  mul128 (r0, r1, r2, a[0], 121665ULL);
  x[0] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[1], 121665ULL);
  x[1] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[2], 121665ULL);
  x[2] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;

  mul128 (r0, r1, r2, a[3], 121665ULL);
  x[3] = r0;

  r0 = bn256_add_uint (X, X, r1 * 38);
  x[0] += (0ULL - r0) & 38;
}


/* X = A mod 2^255-19 */
static void
fe25519_reduce (fe25638 *X)
{
  unsigned long q;
  bn256 R[1];
  uint64_t *x = X->w;
  uint64_t *r = R->w;

  q = (x[3] >> 63);
  x[3] &= 0x7fffffffffffffff;

  bn256_add_uint (X, X, q * 19);

  bn256_add_uint (R, X, 19);
  q = (r[3] >> 63);
  r[3] &= 0x7fffffffffffffff;

  set_cond (x, r, q);
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

static void
fe_tobyte (unsigned char *p, const fe25638 *X)
{
  const uint64_t *x = X->w;

  buf_put_le64 (p,    x[0]);
  buf_put_le64 (p+8,  x[1]);
  buf_put_le64 (p+16, x[2]);
  buf_put_le64 (p+24, x[3]);
}


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
 */
static void
modinv (sr256 *x, const sr256 *modulus, uint32_t inv31, int iterations)
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
 * Assume X and N are co-prime (or N is prime).
 * NOTE: If X==0, it return 0.
 *
 */
static void
fe_invert (bn256 *R, const bn256 *X)
{
  sr256 s[1];

  memcpy (R, X, sizeof (bn256));

  bn_to_signed31 (s, R);
  modinv (s, &modulus_25519, modulus_inv31_25519, 19);
  bn_from_signed31 (R, s);
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
