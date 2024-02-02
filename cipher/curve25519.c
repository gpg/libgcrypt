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
#define fe_sqr_times  fe25638_sqr_times
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

/* X = A^(2^COUNT) mod 2^256-38 */
static void
fe25638_sqr_times (fe25638 *X, const fe25638 *A, unsigned int count)
{
  bn512 tmp[1];
  unsigned int i;

  bn256_copy (X, A);
  for (i = 0; i < count; i++)
    {
      bn256_sqr (tmp, X);
      fe25638_reduce (X, tmp);
    }
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


static void
fe_invert (fe25638 *X, const fe25638 *A)
{
  fe25638 T0[1], T1[1], T2[1], T3[1];

  /* 2 */ fe_sqr (T0, A); /* T0 = 2 */
  /* 8 */ fe_sqr_times (T1, T0, 2);
  /* 9 */ fe_mul (T2, T1, A); /* T2 = 9 */
  /* 11 */ fe_mul (T0, T2, T0); /* T0 = 11 */
  /* 22 */ fe_sqr (T1, T0);
  /* 2^5 - 2^0 = 31 */ fe_mul (T2, T1, T2);
  /* 2^10 - 2^5 */ fe_sqr_times (T1, T2, 5);
  /* 2^10 - 2^0 */ fe_mul (T2, T1, T2);
  /* 2^20 - 2^10 */ fe_sqr_times (T1, T2, 10);
  /* 2^20 - 2^0 */ fe_mul (T3, T1, T2);
  /* 2^40 - 2^20 */ fe_sqr_times (T1, T3, 20);
  /* 2^40 - 2^0 */ fe_mul (T1, T1, T3);
  /* 2^50 - 2^10 */ fe_sqr_times (T1, T1, 10);
  /* 2^50 - 2^0 */ fe_mul (T2, T1, T2);
  /* 2^100 - 2^50 */ fe_sqr_times (T1, T2, 50);
  /* 2^100 - 2^0 */ fe_mul (T3, T1, T2);
  /* 2^200 - 2^100 */ fe_sqr_times (T1, T3, 100);
  /* 2^200 - 2^0 */ fe_mul (T1, T1, T3);
  /* 2^250 - 2^50 */ fe_sqr_times (T1, T1, 50);
  /* 2^250 - 2^0 */ fe_mul (T1, T1, T2);
  /* 2^255 - 2^5 */ fe_sqr_times (T1, T1, 5);
  /* 2^255 - 21 */ fe_mul (X, T1, T0);
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
