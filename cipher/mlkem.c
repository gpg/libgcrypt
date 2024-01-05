/* mlkem.c - ML-KEM implementation
 * Copyright (C) 2023 MTG AG
 * The code was created based on the reference implementation that is
 * part of the ML-KEM NIST submission.
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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <gpg-error.h>

#include "types.h"
#include "g10lib.h"
#include "gcrypt-int.h"
#include "mlkem.h"
#include "const-time.h"

typedef enum
{
  GCRY_MLKEM_512,
  GCRY_MLKEM_768,
  GCRY_MLKEM_1024
} gcry_mlkem_param_id;

typedef struct
{
  gcry_mlkem_param_id id;
  uint8_t k;
  uint8_t eta1;
  uint16_t polyvec_bytes;
  uint8_t poly_compressed_bytes;
  uint16_t polyvec_compressed_bytes;
  uint16_t public_key_bytes;
  uint16_t indcpa_secret_key_bytes;
  uint16_t secret_key_bytes;
  uint16_t ciphertext_bytes;

} gcry_mlkem_param_t;


#define GCRY_MLKEM_N 256
#define GCRY_MLKEM_Q 3329

#define GCRY_MLKEM_SYMBYTES 32 /* size in bytes of hashes, and seeds */
#define GCRY_MLKEM_SSBYTES 32  /* size in bytes of shared key */

#define GCRY_MLKEM_POLYBYTES 384
#define GCRY_MLKEM_POLYVECBYTES (MLKEM_K * GCRY_MLKEM_POLYBYTES)


#define GCRY_MLKEM_ETA1_MAX 3
#define GCRY_MLKEM_ETA2 2

#define GCRY_MLKEM_INDCPA_MSGBYTES (GCRY_MLKEM_SYMBYTES)
#if (GCRY_MLKEM_INDCPA_MSGBYTES != GCRY_MLKEM_N / 8)
#error "GCRY_MLKEM_INDCPA_MSGBYTES must be equal to GCRY_MLKEM_N/8 bytes!"
#endif


#define GCRY_MLKEM_COINS_SIZE (2 * GCRY_MLKEM_SYMBYTES)


#define GCRY_SHAKE128_RATE 168
#define GCRY_SHAKE256_RATE 136
#define GCRY_SHA3_256_RATE 136
#define GCRY_SHA3_512_RATE 72


#define GCRY_MLKEM_XOF_BLOCKBYTES GCRY_SHAKE128_RATE

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct
{
  int16_t coeffs[GCRY_MLKEM_N];
} gcry_mlkem_poly;


typedef struct
{
  gcry_mlkem_poly *vec;
} gcry_mlkem_polyvec;

#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16

/* Forward declarations */
static void _gcry_mlkem_shake128_absorb (
    gcry_md_hd_t h,
    const unsigned char seed[GCRY_MLKEM_SYMBYTES],
    unsigned char x,
    unsigned char y);

static gcry_err_code_t _gcry_mlkem_shake256_prf (
    uint8_t *out,
    size_t outlen,
    const uint8_t key[GCRY_MLKEM_SYMBYTES],
    uint8_t nonce);

static gcry_err_code_t _gcry_mlkem_shake128_squeezeblocks (gcry_md_hd_t h,
                                                    uint8_t *out,
                                                    size_t nblocks);

static gcry_err_code_t _gcry_mlkem_prf (uint8_t *out,
                                 size_t outlen,
                                 const uint8_t key[GCRY_MLKEM_SYMBYTES],
                                 uint8_t nonce);

static gcry_error_t _gcry_mlkem_polymatrix_create (gcry_mlkem_polyvec **polymat,
                                            gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polymatrix_destroy (gcry_mlkem_polyvec **polymat,
                                     gcry_mlkem_param_t const *param);

static gcry_error_t _gcry_mlkem_polyvec_create (gcry_mlkem_polyvec *polyvec,
                                         gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polyvec_destroy (gcry_mlkem_polyvec *polyvec);

static void _gcry_mlkem_polyvec_compress (uint8_t *r,
                                   const gcry_mlkem_polyvec *a,
                                   gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polyvec_decompress (gcry_mlkem_polyvec *r,
                                     const uint8_t *a,
                                     gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polyvec_tobytes (uint8_t *r,
                                  const gcry_mlkem_polyvec *a,
                                  gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polyvec_frombytes (gcry_mlkem_polyvec *r,
                                    const uint8_t *a,
                                    gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polyvec_ntt (gcry_mlkem_polyvec *r,
                              gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polyvec_invntt_tomont (gcry_mlkem_polyvec *r,
                                        gcry_mlkem_param_t const *param);

static gcry_err_code_t _gcry_mlkem_polyvec_basemul_acc_montgomery (
    gcry_mlkem_poly *r,
    const gcry_mlkem_polyvec *a,
    const gcry_mlkem_polyvec *b,
    gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polyvec_reduce (gcry_mlkem_polyvec *r,
                                 gcry_mlkem_param_t const *param);

static void _gcry_mlkem_polyvec_add (gcry_mlkem_polyvec *r,
                              const gcry_mlkem_polyvec *a,
                              const gcry_mlkem_polyvec *b,
                              gcry_mlkem_param_t const *param);

static void
_gcry_mlkem_poly_compress (unsigned char *r,
                           const gcry_mlkem_poly *a,
                           gcry_mlkem_param_t const *param);
static void
_gcry_mlkem_poly_decompress (gcry_mlkem_poly *r,
                             const unsigned char *a,
                             gcry_mlkem_param_t const *param);

static void
_gcry_mlkem_poly_frommsg (gcry_mlkem_poly *r,
                          const unsigned char msg[GCRY_MLKEM_INDCPA_MSGBYTES]);

static void
_gcry_mlkem_poly_tomsg (unsigned char msg[GCRY_MLKEM_INDCPA_MSGBYTES],
                        const gcry_mlkem_poly *a);

static void
_gcry_mlkem_poly_getnoise_eta1 (gcry_mlkem_poly *r,
                                const unsigned char seed[GCRY_MLKEM_SYMBYTES],
                                unsigned char nonce,
                                gcry_mlkem_param_t const *param);

static void
_gcry_mlkem_poly_getnoise_eta2 (gcry_mlkem_poly *r,
                                const unsigned char seed[GCRY_MLKEM_SYMBYTES],
                                unsigned char nonce);

static void
_gcry_mlkem_poly_tomont (gcry_mlkem_poly *r);

static void
_gcry_mlkem_poly_reduce (gcry_mlkem_poly *r);

static void
_gcry_mlkem_poly_add (gcry_mlkem_poly *r,
                      const gcry_mlkem_poly *a,
                      const gcry_mlkem_poly *b);

static void
_gcry_mlkem_poly_sub (gcry_mlkem_poly *r,
                      const gcry_mlkem_poly *a,
                      const gcry_mlkem_poly *b);

static void
_gcry_mlkem_invntt (int16_t r[256]);

static void
_gcry_mlkem_poly_invntt_tomont (gcry_mlkem_poly *r);

static void
_gcry_mlkem_polyvec_invntt_tomont (gcry_mlkem_polyvec *r,
                                   gcry_mlkem_param_t const *param);

/*************************************************
 * Name:        _gcry_mlkem_montgomery_reduce
 *
 * Description: Montgomery reduction; given a 32-bit integer a, computes
 *              16-bit integer congruent to a * R^-1 mod q, where R=2^16
 *
 * Arguments:   - int32_t a: input integer to be reduced;
 *                           has to be in {-q2^15,...,q2^15-1}
 *
 * Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
 **************************************************/
static int16_t
_gcry_mlkem_montgomery_reduce (int32_t a)
{
  int16_t t;

  t = (int16_t)a * QINV;
  t = (a - (int32_t)t * GCRY_MLKEM_Q) >> 16;
  return t;
}

/*************************************************
 * Name:        barrett_reduce
 *
 * Description: Barrett reduction; given a 16-bit integer a, computes
 *              centered representative congruent to a mod q in
 *{-(q-1)/2,...,(q-1)/2}
 *
 * Arguments:   - int16_t a: input integer to be reduced
 *
 * Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
 **************************************************/
static int16_t
_gcry_mlkem_barrett_reduce (int16_t a)
{
  int16_t t;
  const int16_t v = ((1 << 26) + GCRY_MLKEM_Q / 2) / GCRY_MLKEM_Q;

  t = ((int32_t)v * a + (1 << 25)) >> 26;
  t *= GCRY_MLKEM_Q;
  return a - t;
}

/*************************************************
 * Name:        load32_littleendian
 *
 * Description: load 4 bytes into a 32-bit integer
 *              in little-endian order
 *
 * Arguments:   - const uint8_t *x: pointer to input byte array
 *
 * Returns 32-bit unsigned integer loaded from x
 **************************************************/
static uint32_t
load32_littleendian (const uint8_t x[4])
{
  uint32_t r;
  r = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

/*************************************************
 * Name:        load24_littleendian
 *
 * Description: load 3 bytes into a 32-bit integer
 *              in little-endian order.
 *              This function is only needed for ML-KEM-512
 *
 * Arguments:   - const uint8_t *x: pointer to input byte array
 *
 * Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
 **************************************************/
static uint32_t
load24_littleendian (const uint8_t x[3])
{
  uint32_t r;
  r = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}


/*************************************************
 * Name:        cbd2
 *
 * Description: Given an array of uniformly random bytes, compute
 *              polynomial with coefficients distributed according to
 *              a centered binomial distribution with parameter eta=2
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const uint8_t *buf: pointer to input byte array
 **************************************************/
static void
cbd2 (gcry_mlkem_poly *r, const uint8_t buf[2 * GCRY_MLKEM_N / 4])
{
  unsigned int i, j;
  uint32_t t, d;
  int16_t a, b;

  for (i = 0; i < GCRY_MLKEM_N / 8; i++)
    {
      t = load32_littleendian (buf + 4 * i);
      d = t & 0x55555555;
      d += (t >> 1) & 0x55555555;

      for (j = 0; j < 8; j++)
        {
          a                    = (d >> (4 * j + 0)) & 0x3;
          b                    = (d >> (4 * j + 2)) & 0x3;
          r->coeffs[8 * i + j] = a - b;
        }
    }
}

/*************************************************
 * Name:        cbd3
 *
 * Description: Given an array of uniformly random bytes, compute
 *              polynomial with coefficients distributed according to
 *              a centered binomial distribution with parameter eta=3.
 *              This function is only needed for ML-KEM-512
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const uint8_t *buf: pointer to input byte array
 **************************************************/
static void
cbd3 (gcry_mlkem_poly *r, const uint8_t buf[3 * GCRY_MLKEM_N / 4])
{
  unsigned int i, j;
  uint32_t t, d;
  int16_t a, b;

  for (i = 0; i < GCRY_MLKEM_N / 4; i++)
    {
      t = load24_littleendian (buf + 3 * i);
      d = t & 0x00249249;
      d += (t >> 1) & 0x00249249;
      d += (t >> 2) & 0x00249249;

      for (j = 0; j < 4; j++)
        {
          a                    = (d >> (6 * j + 0)) & 0x7;
          b                    = (d >> (6 * j + 3)) & 0x7;
          r->coeffs[4 * i + j] = a - b;
        }
    }
}

static void
_gcry_mlkem_poly_cbd_eta1 (gcry_mlkem_poly *r,
                           const uint8_t *buf,
                           gcry_mlkem_param_t const *param)
{
  if (param->eta1 == 2)
    {
      cbd2 (r, buf);
    }
  else // eta1 = 3
    {
      cbd3 (r, buf);
    }
}

static void
_gcry_mlkem_poly_cbd_eta2 (
    gcry_mlkem_poly *r, const uint8_t buf[GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 4])
{
  cbd2 (r, buf);
}

#define GEN_MATRIX_NBLOCKS                                                    \
  ((12 * GCRY_MLKEM_N / 8 * (1 << 12) / GCRY_MLKEM_Q                          \
    + GCRY_MLKEM_XOF_BLOCKBYTES)                                              \
   / GCRY_MLKEM_XOF_BLOCKBYTES)



/*************************************************
 * Name:        _gcry_mlkem_pack_pk
 *
 * Description: Serialize the public key as concatenation of the
 *              serialized vector of polynomials pk
 *              and the public seed used to generate the matrix A.
 *
 * Arguments:   uint8_t *r: pointer to the output serialized public key
 *              gcry_mlkem_polyvec *pk: pointer to the input public-key
 *              gcry_mlkem_polyvec const uint8_t *seed: pointer to the input
 *public seed gcry_mlkem_param_t const *param: mlkem parameters
 *
 **************************************************/
static void
_gcry_mlkem_pack_pk (uint8_t *r,
                     gcry_mlkem_polyvec *pk,
                     const uint8_t seed[GCRY_MLKEM_SYMBYTES],
                     gcry_mlkem_param_t const *param)
{
  _gcry_mlkem_polyvec_tobytes (r, pk, param);
  memcpy (r + param->polyvec_bytes, seed, GCRY_MLKEM_SYMBYTES);
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: De-serialize public key from a byte array;
 *              approximate inverse of _gcry_mlkem_pack_pk
 *
 * Arguments:   - gcry_mlkem_polyvec *pk: pointer to output public-key
 *polynomial vector
 *              - uint8_t *seed: pointer to output seed to generate matrix A
 *              - const uint8_t *packedpk: pointer to input serialized public
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 *key
 **************************************************/
static void
_gcry_mlkem_unpack_pk (gcry_mlkem_polyvec *pk,
                       uint8_t seed[GCRY_MLKEM_SYMBYTES],
                       const uint8_t *packedpk,
                       gcry_mlkem_param_t const *param)
{
  _gcry_mlkem_polyvec_frombytes (pk, packedpk, param);
  memcpy (seed, packedpk + param->polyvec_bytes, GCRY_MLKEM_SYMBYTES);
}

/*************************************************
 * Name:        _gcry_mlkem_pack_sk
 *
 * Description: Serialize the secret key
 *
 * Arguments:   - uint8_t *r: pointer to output serialized secret key
 *              - gcry_mlkem_polyvec *sk: pointer to input vector of
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 *polynomials (secret key)
 **************************************************/
static void
_gcry_mlkem_pack_sk (uint8_t *r,
                     gcry_mlkem_polyvec *sk,
                     gcry_mlkem_param_t const *param)
{
  _gcry_mlkem_polyvec_tobytes (r, sk, param);
}

/*************************************************
 * Name:        _gcry_mlkem_unpack_sk
 *
 * Description: De-serialize the secret key; inverse of _gcry_mlkem_pack_sk
 *
 * Arguments:   - gcry_mlkem_polyvec *sk: pointer to output vector of
 *polynomials (secret key)
 *              - const uint8_t *packedsk: pointer to input serialized secret
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 *key
 **************************************************/
static void
_gcry_mlkem_unpack_sk (gcry_mlkem_polyvec *sk,
                       const uint8_t *packedsk,
                       gcry_mlkem_param_t const *param)
{
  _gcry_mlkem_polyvec_frombytes (sk, packedsk, param);
}

/*************************************************
 * Name:        _gcry_mlkem_pack_ciphertext
 *
 * Description: Serialize the ciphertext as concatenation of the
 *              compressed and serialized vector of polynomials b
 *              and the compressed and serialized polynomial v
 *
 * Arguments:   uint8_t *r: pointer to the output serialized ciphertext
 *              poly *pk: pointer to the input vector of polynomials b
 *              poly *v: pointer to the input polynomial v
 *              gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_pack_ciphertext (uint8_t *r,
                             gcry_mlkem_polyvec *b,
                             gcry_mlkem_poly *v,
                             gcry_mlkem_param_t const *param)
{
  _gcry_mlkem_polyvec_compress (r, b, param);
  _gcry_mlkem_poly_compress (r + param->polyvec_compressed_bytes, v, param);
}

/*************************************************
 * Name:        _gcry_mlkem_unpack_ciphertext
 *
 * Description: De-serialize and decompress ciphertext from a byte array;
 *              approximate inverse of pack_ciphertext
 *
 * Arguments:   - gcry_mlkem_polyvec *b: pointer to the output vector of
 *polynomials b
 *              - poly *v: pointer to the output polynomial v
 *              - const uint8_t *c: pointer to the input serialized ciphertext
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_unpack_ciphertext (gcry_mlkem_polyvec *b,
                               gcry_mlkem_poly *v,
                               const uint8_t *c,
                               gcry_mlkem_param_t const *param)
{
  _gcry_mlkem_polyvec_decompress (b, c, param);
  _gcry_mlkem_poly_decompress (v, c + param->polyvec_compressed_bytes, param);
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Run rejection sampling on uniform random bytes to generate
 *              uniform random integers mod q
 *
 * Arguments:   - int16_t *r: pointer to output buffer
 *              - unsigned int len: requested number of 16-bit integers
 *(uniform mod q)
 *              - const uint8_t *buf: pointer to input buffer (assumed to be
 *uniformly random bytes)
 *              - unsigned int buflen: length of input buffer in bytes
 *
 * Returns number of sampled 16-bit integers (at most len)
 **************************************************/
static unsigned int
_gcry_mlkem_rej_uniform (int16_t *r,
                         unsigned int len,
                         const uint8_t *buf,
                         unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while (ctr < len && pos + 3 <= buflen)
    {
      val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
      val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
      pos += 3;

      if (val0 < GCRY_MLKEM_Q)
        {
          r[ctr++] = val0;
        }
      if (ctr < len && val1 < GCRY_MLKEM_Q)
        {
          r[ctr++] = val1;
        }
    }

  return ctr;
}


/*************************************************
 * Name:        gen_matrix
 *
 * Description: Deterministically generate matrix A (or the transpose of A)
 *              from a seed. Entries of the matrix are polynomials that look
 *              uniformly random. Performs rejection sampling on output of
 *              a XOF
 *
 * Arguments:   - gcry_mlkem_polyvec *a: pointer to ouptput matrix A
 *              - const uint8_t *seed: pointer to input seed
 *              - int transposed: boolean deciding whether A or A^T is
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 *generated
 **************************************************/
static gcry_err_code_t
_gcry_mlkem_gen_matrix (gcry_mlkem_polyvec *a,
                        const uint8_t seed[GCRY_MLKEM_SYMBYTES],
                        int transposed,
                        gcry_mlkem_param_t const *param)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS * GCRY_MLKEM_XOF_BLOCKBYTES + 2];
  gcry_err_code_t ec = 0;

  for (i = 0; i < param->k; i++)
    {
      for (j = 0; j < param->k; j++)
        {

          gcry_md_hd_t h;
          ec = _gcry_md_open (&h, GCRY_MD_SHAKE128, GCRY_MD_FLAG_SECURE);
          if (ec)
            {
              return ec;
            }
          if (transposed)
            {
              _gcry_mlkem_shake128_absorb (h, seed, i, j);
            }
          else
            {
              _gcry_mlkem_shake128_absorb (h, seed, j, i);
            }

          _gcry_mlkem_shake128_squeezeblocks (h, buf, GEN_MATRIX_NBLOCKS);
          buflen = GEN_MATRIX_NBLOCKS * GCRY_MLKEM_XOF_BLOCKBYTES;

          ctr = _gcry_mlkem_rej_uniform (
              a[i].vec[j].coeffs, GCRY_MLKEM_N, buf, buflen);

          while (ctr < GCRY_MLKEM_N)
            {
              off = buflen % 3;
              for (k = 0; k < off; k++)
                {
                  buf[k] = buf[buflen - off + k];
                }

              _gcry_mlkem_shake128_squeezeblocks (h, buf + off, 1);
              buflen = off + GCRY_MLKEM_XOF_BLOCKBYTES;
              ctr += _gcry_mlkem_rej_uniform (
                  a[i].vec[j].coeffs + ctr, GCRY_MLKEM_N - ctr, buf, buflen);
            }

          _gcry_md_close (h);
        }
    }
  return 0;
}

/*************************************************
 * Name:        indcpa_keypair
 *
 * Description: Generates public and private key for the CPA-secure
 *              public-key encryption scheme underlying ML-KEM
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                             (of length MLKEM_INDCPA_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                             (of length MLKEM_INDCPA_SECRETKEYBYTES bytes)
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 *              - uint8_t *coins: random bytes of length GCRY_MLKEM_SYMBYTES
 **************************************************/
static gcry_err_code_t
_gcry_mlkem_indcpa_keypair (uint8_t *pk,
                            uint8_t *sk,
                            gcry_mlkem_param_t const *param,
                            uint8_t *coins)
{
  unsigned int i;
  uint8_t buf[2 * GCRY_MLKEM_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed  = buf + GCRY_MLKEM_SYMBYTES;
  uint8_t nonce             = 0;
  gcry_mlkem_polyvec *a = NULL, e = {.vec = NULL}, pkpv = {.vec = NULL},
                     skpv = {.vec = NULL};
  gcry_err_code_t ec         = 0;

  ec = _gcry_mlkem_polymatrix_create (&a, param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_mlkem_polyvec_create (&e, param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_mlkem_polyvec_create (&pkpv, param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_mlkem_polyvec_create (&skpv, param);
  if (ec)
    {
      goto leave;
    }


  _gcry_md_hash_buffer (GCRY_MD_SHA3_512, buf, coins, GCRY_MLKEM_SYMBYTES);
  ec = _gcry_mlkem_gen_matrix (a, publicseed, 0, param);
  if (ec)
    {
      goto leave;
    }

  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_getnoise_eta1 (&skpv.vec[i], noiseseed, nonce++, param);
    }
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_getnoise_eta1 (&e.vec[i], noiseseed, nonce++, param);
    }

  _gcry_mlkem_polyvec_ntt (&skpv, param);
  _gcry_mlkem_polyvec_ntt (&e, param);

  // matrix-vector multiplication
  for (i = 0; i < param->k; i++)
    {
      ec = _gcry_mlkem_polyvec_basemul_acc_montgomery (
          &pkpv.vec[i], &a[i], &skpv, param);
      if (ec)
        {
          goto leave;
        }
      _gcry_mlkem_poly_tomont (&pkpv.vec[i]);
    }

  _gcry_mlkem_polyvec_add (&pkpv, &pkpv, &e, param);
  _gcry_mlkem_polyvec_reduce (&pkpv, param);

  _gcry_mlkem_pack_sk (sk, &skpv, param);
  _gcry_mlkem_pack_pk (pk, &pkpv, publicseed, param);
leave:
  _gcry_mlkem_polymatrix_destroy (&a, param);
  _gcry_mlkem_polyvec_destroy (&e);
  _gcry_mlkem_polyvec_destroy (&pkpv);
  _gcry_mlkem_polyvec_destroy (&skpv);

  return ec;
}

/*************************************************
 * Name:        indcpa_enc
 *
 * Description: Encryption function of the CPA-secure
 *              public-key encryption scheme underlying ML-KEM.
 *
 * Arguments:   - uint8_t *c: pointer to output ciphertext
 *                            (of length MLKEM_INDCPA_BYTES bytes)
 *              - const uint8_t *m: pointer to input message
 *                                  (of length GCRY_MLKEM_INDCPA_MSGBYTES
 *bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                                   (of length MLKEM_INDCPA_PUBLICKEYBYTES)
 *              - const uint8_t *coins: pointer to input random coins used as
 *seed (of length GCRY_MLKEM_SYMBYTES) to deterministically generate all
 *randomness
 **************************************************/
static gcry_err_code_t
_gcry_mlkem_indcpa_enc (uint8_t *c,
                        const uint8_t *m,
                        const uint8_t *pk,
                        const uint8_t coins[GCRY_MLKEM_SYMBYTES],
                        gcry_mlkem_param_t const *param)
{
  unsigned int i;
  uint8_t seed[GCRY_MLKEM_SYMBYTES];
  uint8_t nonce         = 0;
  gcry_mlkem_polyvec sp = {.vec = NULL}, pkpv = {.vec = NULL},
                     ep = {.vec = NULL}, *at = NULL, b = {.vec = NULL};
  gcry_err_code_t ec = 0;
  gcry_mlkem_poly v, k, epp;

  ec = _gcry_mlkem_polyvec_create (&sp, param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_mlkem_polyvec_create (&pkpv, param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_mlkem_polyvec_create (&ep, param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_mlkem_polyvec_create (&b, param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_mlkem_polymatrix_create (&at, param);
  if (ec)
    {
      goto leave;
    }

  _gcry_mlkem_unpack_pk (&pkpv, seed, pk, param);
  _gcry_mlkem_poly_frommsg (&k, m);
  ec = _gcry_mlkem_gen_matrix (at, seed, 1, param);
  if (ec)
    {
      goto leave;
    }

  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_getnoise_eta1 (sp.vec + i, coins, nonce++, param);
    }
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_getnoise_eta2 (ep.vec + i, coins, nonce++);
    }
  _gcry_mlkem_poly_getnoise_eta2 (&epp, coins, nonce++);

  _gcry_mlkem_polyvec_ntt (&sp, param);

  // matrix-vector multiplication
  for (i = 0; i < param->k; i++)
    {
      ec = _gcry_mlkem_polyvec_basemul_acc_montgomery (
          &b.vec[i], &at[i], &sp, param);
      if (ec)
        {
          goto leave;
        }
    }

  ec = _gcry_mlkem_polyvec_basemul_acc_montgomery (&v, &pkpv, &sp, param);
  if (ec)
    {
      goto leave;
    }

  _gcry_mlkem_polyvec_invntt_tomont (&b, param);
  _gcry_mlkem_poly_invntt_tomont (&v);

  _gcry_mlkem_polyvec_add (&b, &b, &ep, param);
  _gcry_mlkem_poly_add (&v, &v, &epp);
  _gcry_mlkem_poly_add (&v, &v, &k);
  _gcry_mlkem_polyvec_reduce (&b, param);
  _gcry_mlkem_poly_reduce (&v);

  _gcry_mlkem_pack_ciphertext (c, &b, &v, param);
leave:

  _gcry_mlkem_polyvec_destroy (&sp);
  _gcry_mlkem_polyvec_destroy (&pkpv);
  _gcry_mlkem_polyvec_destroy (&ep);
  _gcry_mlkem_polyvec_destroy (&b);
  _gcry_mlkem_polymatrix_destroy (&at, param);

  return ec;
}

/*************************************************
 * Name:        indcpa_dec
 *
 * Description: Decryption function of the CPA-secure
 *              public-key encryption scheme underlying ML-KEM.
 *
 * Arguments:   - uint8_t *m: pointer to output decrypted message
 *                            (of length GCRY_MLKEM_INDCPA_MSGBYTES)
 *              - const uint8_t *c: pointer to input ciphertext
 *                                  (of length MLKEM_INDCPA_BYTES)
 *              - const uint8_t *sk: pointer to input secret key
 *                                   (of length MLKEM_INDCPA_SECRETKEYBYTES)
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static gcry_err_code_t
_gcry_mlkem_indcpa_dec (uint8_t *m,
                        const uint8_t *c,
                        const uint8_t *sk,
                        gcry_mlkem_param_t const *param)
{
  gcry_mlkem_polyvec b = {.vec = NULL}, skpv = {.vec = NULL};
  gcry_mlkem_poly v, mp;
  gcry_err_code_t ec = 0;

  ec = _gcry_mlkem_polyvec_create (&b, param);
  if (ec)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }
  ec = _gcry_mlkem_polyvec_create (&skpv, param);
  if (ec)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }

  _gcry_mlkem_unpack_ciphertext (&b, &v, c, param);
  _gcry_mlkem_unpack_sk (&skpv, sk, param);

  _gcry_mlkem_polyvec_ntt (&b, param);
  ec = _gcry_mlkem_polyvec_basemul_acc_montgomery (&mp, &skpv, &b, param);
  if (ec)
    {
      goto leave;
    }
  _gcry_mlkem_poly_invntt_tomont (&mp);

  _gcry_mlkem_poly_sub (&mp, &v, &mp);
  _gcry_mlkem_poly_reduce (&mp);

  _gcry_mlkem_poly_tomsg (m, &mp);
leave:
  _gcry_mlkem_polyvec_destroy (&skpv);
  _gcry_mlkem_polyvec_destroy (&b);
  return ec;
}


static gcry_err_code_t
_gcry_mlkem_kem_keypair_derand (uint8_t *pk,
                                uint8_t *sk,
                                const gcry_mlkem_param_t *param,
                                uint8_t *coins)
{
  gcry_err_code_t ec = 0;
  ec                = _gcry_mlkem_indcpa_keypair (pk, sk, param, coins);
  if (ec)
    {
      return ec;
    }
  memcpy (&sk[param->indcpa_secret_key_bytes], pk, param->public_key_bytes);
  _gcry_md_hash_buffer (GCRY_MD_SHA3_256,
                        sk + param->secret_key_bytes - 2 * GCRY_MLKEM_SYMBYTES,
                        pk,
                        param->public_key_bytes);
  /* Value z for pseudo-random output on reject */
  memcpy (sk + param->secret_key_bytes - GCRY_MLKEM_SYMBYTES,
          coins + GCRY_MLKEM_SYMBYTES,
          GCRY_MLKEM_SYMBYTES);
  return ec;
}

static gcry_err_code_t
_gcry_mlkem_mlkem_shake256_rkprf (uint8_t out[GCRY_MLKEM_SSBYTES],
                                  const uint8_t key[GCRY_MLKEM_SYMBYTES],
                                  const uint8_t *input,
                                  size_t input_length)
{
  gcry_md_hd_t h;
  gcry_err_code_t ec = 0;
  ec = _gcry_md_open (&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    {
      return ec;
    }
  _gcry_md_write (h, key, GCRY_MLKEM_SYMBYTES);
  _gcry_md_write (h, input, input_length);
  ec = _gcry_md_extract (h, GCRY_MD_SHAKE256, out, GCRY_MLKEM_SSBYTES);
  _gcry_md_close (h);
  return ec;
}

static const gcry_mlkem_param_t param_table[] = {
  { GCRY_MLKEM_512, 2, 3, 2*GCRY_MLKEM_POLYBYTES, 128, 2*320,
    2*GCRY_MLKEM_POLYBYTES+GCRY_MLKEM_SYMBYTES, 2*GCRY_MLKEM_POLYBYTES,
    2*GCRY_MLKEM_POLYBYTES+2*GCRY_MLKEM_POLYBYTES+GCRY_MLKEM_SYMBYTES+2*GCRY_MLKEM_SYMBYTES,
    128+2*320
  },
  { GCRY_MLKEM_768, 3, 2, 3*GCRY_MLKEM_POLYBYTES, 128, 3*320,
    3*GCRY_MLKEM_POLYBYTES+GCRY_MLKEM_SYMBYTES, 3*GCRY_MLKEM_POLYBYTES,
    3*GCRY_MLKEM_POLYBYTES+3*GCRY_MLKEM_POLYBYTES+GCRY_MLKEM_SYMBYTES+2*GCRY_MLKEM_SYMBYTES,
    128+3*320,
  },
  { GCRY_MLKEM_1024, 4, 2, 4*GCRY_MLKEM_POLYBYTES, 160, 4*352,
    4*GCRY_MLKEM_POLYBYTES+GCRY_MLKEM_SYMBYTES, 4*GCRY_MLKEM_POLYBYTES,
    4*GCRY_MLKEM_POLYBYTES+4*GCRY_MLKEM_POLYBYTES+GCRY_MLKEM_SYMBYTES+2*GCRY_MLKEM_SYMBYTES,
    160+4*352
  }
};

static const gcry_mlkem_param_t *
mlkem_get_param (int algo)
{
  switch (algo)
    {
    case GCRY_KEM_MLKEM512:
      return &param_table[0];
    case GCRY_KEM_MLKEM768:
      return &param_table[1];
    case GCRY_KEM_MLKEM1024:
      return &param_table[2];
    default:
      return NULL;
    }
}

gcry_err_code_t
mlkem_keypair (int algo, uint8_t *pk, uint8_t *sk)
{
  gcry_err_code_t ec = 0;
  uint8_t *coins     = NULL;
  const gcry_mlkem_param_t *param = mlkem_get_param (algo);

  if (!param)
    return GPG_ERR_PUBKEY_ALGO;

  coins              = xtrymalloc_secure (GCRY_MLKEM_COINS_SIZE);
  if (!coins)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }
  _gcry_randomize (coins, GCRY_MLKEM_COINS_SIZE, GCRY_VERY_STRONG_RANDOM);
  ec = _gcry_mlkem_kem_keypair_derand (pk, sk, param, coins);
leave:
  xfree (coins);
  return ec;
}

gcry_err_code_t
mlkem_decap (int algo, uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
  gcry_err_code_t ec = 0;
  unsigned int success;
  const gcry_mlkem_param_t *param = mlkem_get_param (algo);
  uint8_t buf[2 * GCRY_MLKEM_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2 * GCRY_MLKEM_SYMBYTES];
  uint8_t *cmp = NULL;
  const uint8_t *pk = sk + param->indcpa_secret_key_bytes;

  if (!param)
    return GPG_ERR_PUBKEY_ALGO;

  ec = _gcry_mlkem_indcpa_dec (buf, ct, sk, param);
  if (ec)
    {
      goto end;
    }

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy (buf + GCRY_MLKEM_SYMBYTES,
          sk + param->secret_key_bytes - 2 * GCRY_MLKEM_SYMBYTES,
          GCRY_MLKEM_SYMBYTES);
  _gcry_md_hash_buffer (GCRY_MD_SHA3_512, kr, buf, 2 * GCRY_MLKEM_SYMBYTES);


  cmp = xtrymalloc_secure (param->ciphertext_bytes);
  if (!cmp)
    {
      ec = gpg_err_code_from_syserror ();
      goto end;
    }
  ec = _gcry_mlkem_indcpa_enc (cmp, buf, pk, kr + GCRY_MLKEM_SYMBYTES, param);
  /* coins are in kr+GCRY_MLKEM_SYMBYTES */
  if (ec)
    {
      goto end;
    }

  success = ct_memequal (ct, cmp, param->ciphertext_bytes);

  ec = _gcry_mlkem_mlkem_shake256_rkprf (ss,
                                         sk + param->secret_key_bytes
                                             - GCRY_MLKEM_SYMBYTES,
                                         ct,
                                         param->ciphertext_bytes);
  /* Compute rejection key */
  if (ec)
    {
      goto end;
    }

  /* Copy true key to return buffer if SUCCESS is true */
  ct_memmov_cond (ss, kr, GCRY_MLKEM_SYMBYTES, success);

end:
  xfree (cmp);
  return ec;
}

static gcry_err_code_t
_gcry_mlkem_kem_enc_derand (uint8_t *ct,
                            uint8_t *ss,
                            const uint8_t *pk,
                            const gcry_mlkem_param_t *param,
                            uint8_t *coins)
{
  gpg_err_code_t ec = 0;
  uint8_t buf[2 * GCRY_MLKEM_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2 * GCRY_MLKEM_SYMBYTES];

  /* Don't release system RNG output */
  _gcry_md_hash_buffer (GCRY_MD_SHA3_256, buf, coins, GCRY_MLKEM_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */

  _gcry_md_hash_buffer (GCRY_MD_SHA3_256,
                        buf + GCRY_MLKEM_SYMBYTES,
                        pk,
                        param->public_key_bytes);

  _gcry_md_hash_buffer (GCRY_MD_SHA3_512, kr, buf, 2 * GCRY_MLKEM_SYMBYTES);

  /* coins are in kr+GCRY_MLKEM_SYMBYTES */
  ec = _gcry_mlkem_indcpa_enc (ct, buf, pk, kr + GCRY_MLKEM_SYMBYTES, param);
  if (ec)
    {
      goto end;
    }


  memcpy (ss, kr, GCRY_MLKEM_SYMBYTES);
end:
  return ec;
}

gcry_err_code_t
mlkem_encap (int algo, uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
  uint8_t coins[GCRY_MLKEM_SYMBYTES];
  const gcry_mlkem_param_t *param = mlkem_get_param (algo);

  if (!param)
    return GPG_ERR_PUBKEY_ALGO;

  _gcry_randomize (coins, GCRY_MLKEM_SYMBYTES, GCRY_VERY_STRONG_RANDOM);
  return _gcry_mlkem_kem_enc_derand (ct, ss, pk, param, coins);
}

/* For reference: code to generate zetas and zetas_inv used in the number-theoretic transform:

#define MLKEM_ROOT_OF_UNITY 17

static const uint8_t tree[128] = {
  0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
  4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
  2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
  6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
  1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
  5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
  3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
  7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127
};

void init_ntt() {
  unsigned int i;
  int16_t tmp[128];

  tmp[0] = MONT;
  for(i=1;i<128;i++)
    tmp[i] = fqmul(tmp[i-1],MONT*MLKEM_ROOT_OF_UNITY % GCRY_MLKEM_Q);

  for(i=0;i<128;i++) {
    zetas[i] = tmp[tree[i]];
    if(zetas[i] > GCRY_MLKEM_Q/2)
      zetas[i] -= GCRY_MLKEM_Q;
    if(zetas[i] < -GCRY_MLKEM_Q/2)
      zetas[i] += GCRY_MLKEM_Q;
  }
}
*/

static const int16_t zetas[128] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,  -171,  622,   1577,
    182,   962,   -1202, -1474, 1468,  573,   -1325, 264,  383,   -829,  1458,
    -1602, -130,  -681,  1017,  732,   608,   -1542, 411,  -205,  -1571, 1223,
    652,   -552,  1015,  -1293, 1491,  -282,  -1544, 516,  -8,    -320,  -666,
    -1618, -1162, 126,   1469,  -853,  -90,   -271,  830,  107,   -1421, -247,
    -951,  -398,  961,   -1508, -725,  448,   -1065, 677,  -1275, -1103, 430,
    555,   843,   -1251, 871,   1550,  105,   422,   587,  177,   -235,  -291,
    -460,  1574,  1653,  -246,  778,   1159,  -147,  -777, 1483,  -602,  1119,
    -1590, 644,   -872,  349,   418,   329,   -156,  -75,  817,   1097,  603,
    610,   1322,  -1285, -1465, 384,   -1215, -136,  1218, -1335, -874,  220,
    -1187, -1659, -1185, -1530, -1278, 794,   -1510, -854, -870,  478,   -108,
    -308,  996,   991,   958,   -1460, 1522,  1628};

/*************************************************
 * Name:        fqmul
 *
 * Description: Multiplication followed by Montgomery reduction
 *
 * Arguments:   - int16_t a: first factor
 *              - int16_t b: second factor
 *
 * Returns 16-bit integer congruent to a*b*R^{-1} mod q
 **************************************************/
static int16_t
fqmul (int16_t a, int16_t b)
{
  return _gcry_mlkem_montgomery_reduce ((int32_t)a * b);
}

/*************************************************
 * Name:        ntt
 *
 * Description: Inplace number-theoretic transform (NTT) in Rq.
 *              input is in standard order, output is in bitreversed order
 *
 * Arguments:   - int16_t r[256]: pointer to input/output vector of elements of
 *Zq
 **************************************************/
static void
_gcry_mlkem_ntt (int16_t r[256])
{
  unsigned int len, start, j, k;
  int16_t t, zeta;

  k = 1;
  for (len = 128; len >= 2; len >>= 1)
    {
      for (start = 0; start < 256; start = j + len)
        {
          zeta = zetas[k++];
          for (j = start; j < start + len; j++)
            {
              t          = fqmul (zeta, r[j + len]);
              r[j + len] = r[j] - t;
              r[j]       = r[j] + t;
            }
        }
    }
}

/*************************************************
 * Name:        invntt_tomont
 *
 * Description: Inplace inverse number-theoretic transform in Rq and
 *              multiplication by Montgomery factor 2^16.
 *              Input is in bitreversed order, output is in standard order
 *
 * Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
 **************************************************/
static void
_gcry_mlkem_invntt (int16_t r[256])
{
  unsigned int start, len, j, k;
  int16_t t, zeta;
  const int16_t f = 1441; // mont^2/128

  k = 127;
  for (len = 2; len <= 128; len <<= 1)
    {
      for (start = 0; start < 256; start = j + len)
        {
          zeta = zetas[k--];
          for (j = start; j < start + len; j++)
            {
              t          = r[j];
              r[j]       = _gcry_mlkem_barrett_reduce (t + r[j + len]);
              r[j + len] = r[j + len] - t;
              r[j + len] = fqmul (zeta, r[j + len]);
            }
        }
    }

  for (j = 0; j < 256; j++)
    r[j] = fqmul (r[j], f);
}

/*************************************************
 * Name:        basemul
 *
 * Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
 *              used for multiplication of elements in Rq in NTT domain
 *
 * Arguments:   - int16_t r[2]: pointer to the output polynomial
 *              - const int16_t a[2]: pointer to the first factor
 *              - const int16_t b[2]: pointer to the second factor
 *              - int zeta: integer defining the reduction polynomial as an offset into the zeta table
 *              - int sign: sign to apply to the zeta value
 **************************************************/
static void
_gcry_mlkem_basemul (int16_t r[2],
                     const int16_t a[2],
                     const int16_t b[2],
                     int zeta_offs,
                     int sign)
{
  uint16_t zeta = zetas[zeta_offs] * sign;
  r[0]          = fqmul (a[1], b[1]);
  r[0]          = fqmul (r[0], zeta);
  r[0] += fqmul (a[0], b[0]);
  r[1] = fqmul (a[0], b[1]);
  r[1] += fqmul (a[1], b[0]);
}

/*************************************************
 * Name:        poly_compress
 *
 * Description: Compression and subsequent serialization of a polynomial
 *
 * Arguments:   - unsigned char *r: pointer to output byte array
 *                            (of length MLKEM_POLYCOMPRESSEDBYTES)
 *              - const poly *a: pointer to input polynomial
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_poly_compress (unsigned char *r,
                           const gcry_mlkem_poly *a,
                           gcry_mlkem_param_t const *param)
{
  unsigned int i, j;
  int16_t u;
  unsigned char t[8];

  if (param->id != GCRY_MLKEM_1024)
    {
      for (i = 0; i < GCRY_MLKEM_N / 8; i++)
        {
          for (j = 0; j < 8; j++)
            {
              // map to positive standard representatives
              u = a->coeffs[8 * i + j];
              u += (u >> 15) & GCRY_MLKEM_Q;
              t[j] = ((((uint16_t)u << 4) + GCRY_MLKEM_Q / 2) / GCRY_MLKEM_Q)
                     & 15;
            }

          r[0] = t[0] | (t[1] << 4);
          r[1] = t[2] | (t[3] << 4);
          r[2] = t[4] | (t[5] << 4);
          r[3] = t[6] | (t[7] << 4);
          r += 4;
        }
    }
  else
    {
      for (i = 0; i < GCRY_MLKEM_N / 8; i++)
        {
          for (j = 0; j < 8; j++)
            {
              // map to positive standard representatives
              u = a->coeffs[8 * i + j];
              u += (u >> 15) & GCRY_MLKEM_Q;
              t[j] = ((((uint32_t)u << 5) + GCRY_MLKEM_Q / 2) / GCRY_MLKEM_Q)
                     & 31;
            }

          r[0] = (t[0] >> 0) | (t[1] << 5);
          r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
          r[2] = (t[3] >> 1) | (t[4] << 4);
          r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
          r[4] = (t[6] >> 2) | (t[7] << 3);
          r += 5;
        }
    }
}

/*************************************************
 * Name:        gcry_mlkem_poly_decompress
 *
 * Description: De-serialization and subsequent decompression of a
 *gcry_mlkem_polynomial; approximate inverse of gcry_mlkem_poly_compress
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output gcry_mlkem_polynomial
 *              - const unsigned char *a: pointer to input byte array
 *                                  (of length MLKEM_POLYCOMPRESSEDBYTES bytes)
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_poly_decompress (gcry_mlkem_poly *r,
                             const unsigned char *a,
                             gcry_mlkem_param_t const *param)
{
  unsigned int i;

  if (param->id != GCRY_MLKEM_1024)
    {
      for (i = 0; i < GCRY_MLKEM_N / 2; i++)
        {
          r->coeffs[2 * i + 0]
              = (((uint16_t)(a[0] & 15) * GCRY_MLKEM_Q) + 8) >> 4;
          r->coeffs[2 * i + 1]
              = (((uint16_t)(a[0] >> 4) * GCRY_MLKEM_Q) + 8) >> 4;
          a += 1;
        }
    }
  else
    {
      unsigned int j;
      unsigned char t[8];
      for (i = 0; i < GCRY_MLKEM_N / 8; i++)
        {
          t[0] = (a[0] >> 0);
          t[1] = (a[0] >> 5) | (a[1] << 3);
          t[2] = (a[1] >> 2);
          t[3] = (a[1] >> 7) | (a[2] << 1);
          t[4] = (a[2] >> 4) | (a[3] << 4);
          t[5] = (a[3] >> 1);
          t[6] = (a[3] >> 6) | (a[4] << 2);
          t[7] = (a[4] >> 3);
          a += 5;

          for (j = 0; j < 8; j++)
            {
              r->coeffs[8 * i + j]
                  = ((uint32_t)(t[j] & 31) * GCRY_MLKEM_Q + 16) >> 5;
            }
        }
    }
}

/*************************************************
 * Name:        gcry_mlkem_poly_tobytes
 *
 * Description: Serialization of a gcry_mlkem_polynomial
 *
 * Arguments:   - unsigned char *r: pointer to output byte array
 *                            (needs space for GCRY_MLKEM_POLYBYTES bytes)
 *              - const gcry_mlkem_poly *a: pointer to input polynomial
 **************************************************/
static void
_gcry_mlkem_poly_tobytes (unsigned char r[GCRY_MLKEM_POLYBYTES],
                          const gcry_mlkem_poly *a)
{
  unsigned int i;
  uint16_t t0, t1;

  for (i = 0; i < GCRY_MLKEM_N / 2; i++)
    {
      // map to positive standard representatives
      t0 = a->coeffs[2 * i];
      t0 += ((int16_t)t0 >> 15) & GCRY_MLKEM_Q;
      t1 = a->coeffs[2 * i + 1];
      t1 += ((int16_t)t1 >> 15) & GCRY_MLKEM_Q;
      r[3 * i + 0] = (t0 >> 0);
      r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
      r[3 * i + 2] = (t1 >> 4);
    }
}

/*************************************************
 * Name:        gcry_mlkem_poly_frombytes
 *
 * Description: De-serialization of a polynomial;
 *              inverse of gcry_mlkem_poly_tobytes
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const unsigned char *a: pointer to input byte array
 *                                  (of GCRY_MLKEM_POLYBYTES bytes)
 **************************************************/
static void
_gcry_mlkem_poly_frombytes (gcry_mlkem_poly *r,
                            const unsigned char a[GCRY_MLKEM_POLYBYTES])
{
  unsigned int i;
  for (i = 0; i < GCRY_MLKEM_N / 2; i++)
    {
      r->coeffs[2 * i]
          = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
      r->coeffs[2 * i + 1]
          = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

/*************************************************
 * Name:        gcry_mlkem_poly_frommsg
 *
 * Description: Convert 32-byte message to polynomial
 *
 * Arguments:   - poly *r: pointer to output polynomial
 *              - const unsigned char *msg: pointer to input message
 **************************************************/
static void
_gcry_mlkem_poly_frommsg (gcry_mlkem_poly *r,
                          const unsigned char msg[GCRY_MLKEM_INDCPA_MSGBYTES])
{
  unsigned int i, j;
  int16_t mask;


  for (i = 0; i < GCRY_MLKEM_N / 8; i++)
    {
      for (j = 0; j < 8; j++)
        {
          mask                 = -(int16_t)((msg[i] >> j) & 1);
          r->coeffs[8 * i + j] = mask & ((GCRY_MLKEM_Q + 1) / 2);
        }
    }
}

/*************************************************
 * Name:        gcry_mlkem_poly_tomsg
 *
 * Description: Convert polynomial to 32-byte message
 *
 * Arguments:   - unsigned char *msg: pointer to output message
 *              - const gcry_mlkem_poly *a: pointer to input polynomial
 **************************************************/
static void
_gcry_mlkem_poly_tomsg (unsigned char msg[GCRY_MLKEM_INDCPA_MSGBYTES],
                        const gcry_mlkem_poly *a)
{
  unsigned int i, j;
  uint16_t t;

  for (i = 0; i < GCRY_MLKEM_N / 8; i++)
    {
      msg[i] = 0;
      for (j = 0; j < 8; j++)
        {
          t = a->coeffs[8 * i + j];
          t += ((int16_t)t >> 15) & GCRY_MLKEM_Q;
          t = (((t << 1) + GCRY_MLKEM_Q / 2) / GCRY_MLKEM_Q) & 1;
          msg[i] |= t << j;
        }
    }
}

/*************************************************
 * Name:        gcry_mlkem_poly_getnoise_eta1
 *
 * Description: Sample a polynomial deterministically from a seed and a nonce,
 *              with output polynomial close to centered binomial distribution
 *              with parameter MLKEM_ETA1
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const unsigned char *seed: pointer to input seed
 *                                     (of length GCRY_MLKEM_SYMBYTES bytes)
 *              - unsigned char nonce: one-byte input nonce
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_poly_getnoise_eta1 (gcry_mlkem_poly *r,
                                const unsigned char seed[GCRY_MLKEM_SYMBYTES],
                                unsigned char nonce,
                                gcry_mlkem_param_t const *param)
{
  unsigned char buf[GCRY_MLKEM_ETA1_MAX * GCRY_MLKEM_N / 4];
  _gcry_mlkem_prf (buf, sizeof (buf), seed, nonce);
  _gcry_mlkem_poly_cbd_eta1 (r, buf, param);
}

/*************************************************
 * Name:        gcry_mlkem_poly_getnoise_eta2
 *
 * Description: Sample a polynomial deterministically from a seed and a nonce,
 *              with output polynomial close to centered binomial distribution
 *              with parameter GCRY_MLKEM_ETA2
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const unsigned char *seed: pointer to input seed
 *                                     (of length GCRY_MLKEM_SYMBYTES bytes)
 *              - unsigned char nonce: one-byte input nonce
 **************************************************/
static void
_gcry_mlkem_poly_getnoise_eta2 (gcry_mlkem_poly *r,
                                const unsigned char seed[GCRY_MLKEM_SYMBYTES],
                                unsigned char nonce)
{
  unsigned char buf[GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 4];
  _gcry_mlkem_prf (buf, sizeof (buf), seed, nonce);
  _gcry_mlkem_poly_cbd_eta2 (r, buf);
}


/*************************************************
 * Name:        gcry_mlkem_poly_ntt
 *
 * Description: Computes negacyclic number-theoretic transform (NTT) of
 *              a polynomial in place;
 *              inputs assumed to be in normal order, output in bitreversed
 *order
 *
 * Arguments:   - uint16_t *r: pointer to in/output polynomial
 **************************************************/
static void
_gcry_mlkem_poly_ntt (gcry_mlkem_poly *r)
{
  _gcry_mlkem_ntt (r->coeffs);
  _gcry_mlkem_poly_reduce (r);
}

/*************************************************
 * Name:        poly_invntt_tomont
 *
 * Description: Computes inverse of negacyclic number-theoretic transform (NTT)
 *              of a polynomial in place;
 *              inputs assumed to be in bitreversed order, output in normal
 *order
 *
 * Arguments:   - uint16_t *a: pointer to in/output polynomial
 **************************************************/
static void
_gcry_mlkem_poly_invntt_tomont (gcry_mlkem_poly *r)
{
  _gcry_mlkem_invntt (r->coeffs);
}

/*************************************************
 * Name:        poly_basemul_montgomery
 *
 * Description: Multiplication of two polynomials in NTT domain
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const gcry_mlkem_poly *a: pointer to first input polynomial
 *              - const gcry_mlkem_poly *b: pointer to second input polynomial
 **************************************************/
static void
_gcry_mlkem_poly_basemul_montgomery (gcry_mlkem_poly *r,
                                     const gcry_mlkem_poly *a,
                                     const gcry_mlkem_poly *b)
{
  unsigned int i;
  for (i = 0; i < GCRY_MLKEM_N / 4; i++)
    {
      _gcry_mlkem_basemul (
          &r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], 64 + i, 1);
      _gcry_mlkem_basemul (&r->coeffs[4 * i + 2],
                           &a->coeffs[4 * i + 2],
                           &b->coeffs[4 * i + 2],
                           64 + i,
                           -1);
    }
}

/*************************************************
 * Name:        poly_tomont
 *
 * Description: Inplace conversion of all coefficients of a polynomial
 *              from normal domain to Montgomery domain
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to input/output polynomial
 **************************************************/
static void
_gcry_mlkem_poly_tomont (gcry_mlkem_poly *r)
{
  unsigned int i;
  const int16_t f = (1ULL << 32) % GCRY_MLKEM_Q;
  for (i = 0; i < GCRY_MLKEM_N; i++)
    {
      r->coeffs[i] = _gcry_mlkem_montgomery_reduce ((int32_t)r->coeffs[i] * f);
    }
}

/*************************************************
 * Name:        poly_reduce
 *
 * Description: Applies Barrett reduction to all coefficients of a polynomial
 *              for details of the Barrett reduction see comments in reduce.c
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to input/output polynomial
 **************************************************/
static void
_gcry_mlkem_poly_reduce (gcry_mlkem_poly *r)
{
  unsigned int i;
  for (i = 0; i < GCRY_MLKEM_N; i++)
    {
      r->coeffs[i] = _gcry_mlkem_barrett_reduce (r->coeffs[i]);
    }
}

/*************************************************
 * Name:        poly_add
 *
 * Description: Add two polynomials; no modular reduction is performed
 *
 * Arguments: - gcry_mlkem_poly *r: pointer to output polynomial
 *            - const gcry_mlkem_poly *a: pointer to first input polynomial
 *            - const gcry_mlkem_poly *b: pointer to second input polynomial
 **************************************************/
static void
_gcry_mlkem_poly_add (gcry_mlkem_poly *r,
                      const gcry_mlkem_poly *a,
                      const gcry_mlkem_poly *b)
{
  unsigned int i;
  for (i = 0; i < GCRY_MLKEM_N; i++)
    {
      r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/*************************************************
 * Name:        poly_sub
 *
 * Description: Subtract two polynomials; no modular reduction is performed
 *
 * Arguments: - gcry_mlkem_poly *r:       pointer to output polynomial
 *            - const gcry_mlkem_poly *a: pointer to first input polynomial
 *            - const gcry_mlkem_poly *b: pointer to second input polynomial
 **************************************************/
static void
_gcry_mlkem_poly_sub (gcry_mlkem_poly *r,
                      const gcry_mlkem_poly *a,
                      const gcry_mlkem_poly *b)
{
  unsigned int i;
  for (i = 0; i < GCRY_MLKEM_N; i++)
    {
      r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

static gcry_err_code_t
_gcry_mlkem_polymatrix_create (gcry_mlkem_polyvec **polymat,
                               gcry_mlkem_param_t const *param)
{
  gcry_err_code_t ec = 0;
  unsigned i;
  *polymat = xtrymalloc (sizeof (**polymat) * param->k);
  if (!polymat)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }
  memset ((polymat)[0], 0, sizeof (**polymat) * param->k);

  for (i = 0; i < param->k; i++)
    {
      ec = _gcry_mlkem_polyvec_create (&(*polymat)[i], param);
      if (ec)
        {
          goto leave;
        }
    }
leave:
  return ec;
}


static void
_gcry_mlkem_polymatrix_destroy (gcry_mlkem_polyvec **polymat,
                                gcry_mlkem_param_t const *param)
{
  unsigned i;
  if (polymat == NULL)
    {
      return;
    }
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_polyvec_destroy (&(*polymat)[i]);
    }
  xfree (*polymat);
  *polymat = NULL;
}

static gcry_err_code_t
_gcry_mlkem_polyvec_create (gcry_mlkem_polyvec *polyvec,
                            gcry_mlkem_param_t const *param)
{

  polyvec->vec = xtrymalloc_secure (sizeof (*polyvec->vec) * param->k);
  if (polyvec->vec == NULL)
    {
      return gpg_err_code_from_syserror ();
    }
  return 0;
}

static void
_gcry_mlkem_polyvec_destroy (gcry_mlkem_polyvec *polyvec)
{
  xfree (polyvec->vec);
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_compress
 *
 * Description: Compress and serialize vector of polynomials
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *                            (needs space for MLKEM_POLYVECCOMPRESSEDBYTES)
 *              - const gcry_mlkem_polyvec *a: pointer to input vector of polynomials
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_polyvec_compress (uint8_t *r,
                              const gcry_mlkem_polyvec *a,
                              gcry_mlkem_param_t const *param)
{
  unsigned int i, j, k;
  switch (param->id)
    {
    case GCRY_MLKEM_1024:
      {
        uint16_t t[8];
        for (i = 0; i < param->k; i++)
          {
            for (j = 0; j < GCRY_MLKEM_N / 8; j++)
              {
                for (k = 0; k < 8; k++)
                  {
                    t[k] = a->vec[i].coeffs[8 * j + k];
                    t[k] += ((int16_t)t[k] >> 15) & GCRY_MLKEM_Q;
                    t[k] = ((((uint32_t)t[k] << 11) + GCRY_MLKEM_Q / 2)
                            / GCRY_MLKEM_Q)
                           & 0x7ff;
                  }

                r[0]  = (t[0] >> 0);
                r[1]  = (t[0] >> 8) | (t[1] << 3);
                r[2]  = (t[1] >> 5) | (t[2] << 6);
                r[3]  = (t[2] >> 2);
                r[4]  = (t[2] >> 10) | (t[3] << 1);
                r[5]  = (t[3] >> 7) | (t[4] << 4);
                r[6]  = (t[4] >> 4) | (t[5] << 7);
                r[7]  = (t[5] >> 1);
                r[8]  = (t[5] >> 9) | (t[6] << 2);
                r[9]  = (t[6] >> 6) | (t[7] << 5);
                r[10] = (t[7] >> 3);
                r += 11;
              }
          }
        break;
      }
    case GCRY_MLKEM_512:
    case GCRY_MLKEM_768:
      {

        uint16_t t[4];
        for (i = 0; i < param->k; i++)
          {
            for (j = 0; j < GCRY_MLKEM_N / 4; j++)
              {
                for (k = 0; k < 4; k++)
                  {
                    t[k] = a->vec[i].coeffs[4 * j + k];
                    t[k] += ((int16_t)t[k] >> 15) & GCRY_MLKEM_Q;
                    t[k] = ((((uint32_t)t[k] << 10) + GCRY_MLKEM_Q / 2)
                            / GCRY_MLKEM_Q)
                           & 0x3ff;
                  }

                r[0] = (t[0] >> 0);
                r[1] = (t[0] >> 8) | (t[1] << 2);
                r[2] = (t[1] >> 6) | (t[2] << 4);
                r[3] = (t[2] >> 4) | (t[3] << 6);
                r[4] = (t[3] >> 2);
                r += 5;
              }
          }
        break;
      }
    }
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_decompress
 *
 * Description: De-serialize and decompress vector of polynomials;
 *              approximate inverse of gcry_mlkem_polyvec_compress
 *
 * Arguments:   - gcry_mlkem_polyvec *r:       pointer to output vector of
 *polynomials
 *              - const uint8_t *a: pointer to input byte array
 *                                  (of length MLKEM_POLYVECCOMPRESSEDBYTES)
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_polyvec_decompress (gcry_mlkem_polyvec *r,
                                const uint8_t *a,
                                gcry_mlkem_param_t const *param)
{
  unsigned int i, j, k;
  switch (param->id)
    {
    case GCRY_MLKEM_1024:
      {
        uint16_t t[8];
        for (i = 0; i < param->k; i++)
          {
            for (j = 0; j < GCRY_MLKEM_N / 8; j++)
              {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 3) | ((uint16_t)a[2] << 5);
                t[2] = (a[2] >> 6) | ((uint16_t)a[3] << 2)
                       | ((uint16_t)a[4] << 10);
                t[3] = (a[4] >> 1) | ((uint16_t)a[5] << 7);
                t[4] = (a[5] >> 4) | ((uint16_t)a[6] << 4);
                t[5] = (a[6] >> 7) | ((uint16_t)a[7] << 1)
                       | ((uint16_t)a[8] << 9);
                t[6] = (a[8] >> 2) | ((uint16_t)a[9] << 6);
                t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
                a += 11;

                for (k = 0; k < 8; k++)
                  r->vec[i].coeffs[8 * j + k]
                      = ((uint32_t)(t[k] & 0x7FF) * GCRY_MLKEM_Q + 1024) >> 11;
              }
          }
        break;
      }
    case GCRY_MLKEM_768:
    case GCRY_MLKEM_512:
      {
        uint16_t t[4];
        for (i = 0; i < param->k; i++)
          {
            for (j = 0; j < GCRY_MLKEM_N / 4; j++)
              {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
                t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
                t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
                a += 5;

                for (k = 0; k < 4; k++)
                  {
                    r->vec[i].coeffs[4 * j + k]
                        = ((uint32_t)(t[k] & 0x3FF) * GCRY_MLKEM_Q + 512)
                          >> 10;
                  }
              }
          }
        break;
      }
    }
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_tobytes
 *
 * Description: Serialize vector of polynomials
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *                            (needs space for GCRY_MLKEM_POLYVECBYTES)
 *              - const gcry_mlkem_polyvec *a: pointer to input vector of polynomials
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_polyvec_tobytes (uint8_t *r,
                             const gcry_mlkem_polyvec *a,
                             gcry_mlkem_param_t const *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_tobytes (r + i * GCRY_MLKEM_POLYBYTES, &a->vec[i]);
    }
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_frombytes
 *
 * Description: De-serialize vector of polynomials;
 *              inverse of gcry_mlkem_polyvec_tobytes
 *
 * Arguments:   - uint8_t *r:       pointer to output byte array
 *              - const gcry_mlkem_polyvec *a: pointer to input vector of polynomials (of length GCRY_MLKEM_POLYVECBYTES)
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_polyvec_frombytes (gcry_mlkem_polyvec *r,
                               const uint8_t *a,
                               gcry_mlkem_param_t const *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_frombytes (&r->vec[i], a + i * GCRY_MLKEM_POLYBYTES);
    }
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_ntt
 *
 * Description: Apply forward NTT to all elements of a vector of polynomials
 *
 * Arguments:   - gcry_mlkem_polyvec *r: pointer to in/output vector of polynomials
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_polyvec_ntt (gcry_mlkem_polyvec *r,
                         gcry_mlkem_param_t const *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_ntt (&r->vec[i]);
    }
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_invntt_tomont
 *
 * Description: Apply inverse NTT to all elements of a vector of polynomials
 *              and multiply by Montgomery factor 2^16
 *
 * Arguments:   - gcry_mlkem_polyvec *r: pointer to in/output vector of polynomials
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_polyvec_invntt_tomont (gcry_mlkem_polyvec *r,
                                   gcry_mlkem_param_t const *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_invntt_tomont (&r->vec[i]);
    }
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_basemul_acc_montgomery
 *
 * Description: Multiply elements of a and b in NTT domain, accumulate into r,
 *              and multiply by 2^-16.
 *
 * Arguments: - poly *r: pointer to output polynomial
 *            - const gcry_mlkem_polyvec *a: pointer to first input vector of polynomials
 *            - const gcry_mlkem_polyvec *b: pointer to second input vector of polynomials
 *            - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static gcry_err_code_t
_gcry_mlkem_polyvec_basemul_acc_montgomery (gcry_mlkem_poly *r,
                                            const gcry_mlkem_polyvec *a,
                                            const gcry_mlkem_polyvec *b,
                                            gcry_mlkem_param_t const *param)
{
  gcry_err_code_t ec = 0;
  unsigned int i;
  gcry_mlkem_poly *t = NULL;
  t                  = (gcry_mlkem_poly *)xtrymalloc_secure (sizeof (*t));
  if (!t)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }


  _gcry_mlkem_poly_basemul_montgomery (r, &a->vec[0], &b->vec[0]);
  for (i = 1; i < param->k; i++)
    {
      _gcry_mlkem_poly_basemul_montgomery (t, &a->vec[i], &b->vec[i]);
      _gcry_mlkem_poly_add (r, r, t);
    }

  _gcry_mlkem_poly_reduce (r);
leave:
  xfree (t);
  return ec;
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_reduce
 *
 * Description: Applies Barrett reduction to each coefficient
 *              of each element of a vector of polynomials;
 *              for details of the Barrett reduction see comments in reduce.c
 *
 * Arguments:   - gcry_mlkem_polyvec *r: pointer to input/output polynomial
 *              - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_polyvec_reduce (gcry_mlkem_polyvec *r,
                            gcry_mlkem_param_t const *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_reduce (&r->vec[i]);
    }
}

/*************************************************
 * Name:        gcry_mlkem_polyvec_add
 *
 * Description: Add vectors of polynomials
 *
 * Arguments: - gcry_mlkem_polyvec *r: pointer to output vector of polynomials
 *            - const gcry_mlkem_polyvec *a: pointer to first input vector of polynomials
 *            - const gcry_mlkem_polyvec *b: pointer to second input vector of polynomials
 *            - gcry_mlkem_param_t const *param: mlkem parameters
 **************************************************/
static void
_gcry_mlkem_polyvec_add (gcry_mlkem_polyvec *r,
                         const gcry_mlkem_polyvec *a,
                         const gcry_mlkem_polyvec *b,
                         gcry_mlkem_param_t const *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    {
      _gcry_mlkem_poly_add (&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

static void
_gcry_mlkem_shake128_absorb (gcry_md_hd_t h,
                             const unsigned char seed[GCRY_MLKEM_SYMBYTES],
                             unsigned char x,
                             unsigned char y)
{
  unsigned char extseed[GCRY_MLKEM_SYMBYTES + 2];

  memcpy (extseed, seed, GCRY_MLKEM_SYMBYTES);
  extseed[GCRY_MLKEM_SYMBYTES + 0] = x;
  extseed[GCRY_MLKEM_SYMBYTES + 1] = y;

  _gcry_md_write (h, extseed, sizeof (extseed));
}


static gcry_err_code_t
_gcry_mlkem_shake128_squeezeblocks (gcry_md_hd_t h,
                                    uint8_t *out,
                                    size_t nblocks)
{
  return _gcry_md_extract (
      h, GCRY_MD_SHAKE128, out, GCRY_SHAKE128_RATE * nblocks);
}

static gcry_err_code_t
_gcry_mlkem_shake256_prf (unsigned char *out,
                          size_t outlen,
                          const unsigned char key[GCRY_MLKEM_SYMBYTES],
                          unsigned char nonce)
{
  unsigned char extkey[GCRY_MLKEM_SYMBYTES + 1];
  gcry_err_code_t ec = 0;
  gcry_md_hd_t h;

  memcpy (extkey, key, GCRY_MLKEM_SYMBYTES);
  extkey[GCRY_MLKEM_SYMBYTES] = nonce;
  ec = _gcry_md_open (&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    {
      return ec;
    }
  _gcry_md_write (h, extkey, sizeof (extkey));
  ec = _gcry_md_extract (h, GCRY_MD_SHAKE256, out, outlen);
  _gcry_md_close (h);
  return ec;
}

static gcry_err_code_t
_gcry_mlkem_prf (unsigned char *out,
                 size_t outlen,
                 const unsigned char key[GCRY_MLKEM_SYMBYTES],
                 unsigned char nonce)
{
  return _gcry_mlkem_shake256_prf (out, outlen, key, nonce);
}
