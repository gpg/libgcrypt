/* mlkem-common.c - general functions for ML-KEM
 * Copyright (C) 2023 MTG AG
 * The code was created based on the reference implementation that is part of the ML-KEM NIST submission.
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

#include <stddef.h>
#include <stdint.h>
// #include <config.h>
#include "mlkem-common.h"
#include "mlkem-params.h"
#include "mlkem-polyvec.h"
#include "mlkem-poly.h"
#include "mlkem-ntt.h"
#include "mlkem-aux.h"
#include "consttime.h"
#include "mlkem-symmetric.h"
#include "gcrypt.h"

#include "g10lib.h"

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
static gcry_error_t
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
  gcry_error_t ec         = 0;

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
static gcry_error_t
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
  gcry_error_t ec = 0;
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
static gcry_error_t
_gcry_mlkem_indcpa_dec (uint8_t *m,
                        const uint8_t *c,
                        const uint8_t *sk,
                        gcry_mlkem_param_t const *param)
{
  gcry_mlkem_polyvec b = {.vec = NULL}, skpv = {.vec = NULL};
  gcry_mlkem_poly v, mp;
  gcry_error_t ec = 0;

  ec = _gcry_mlkem_polyvec_create (&b, param);
  if (ec)
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }
  ec = _gcry_mlkem_polyvec_create (&skpv, param);
  if (ec)
    {
      ec = gpg_error_from_syserror ();
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


gcry_err_code_t
_gcry_mlkem_kem_keypair_derand (uint8_t *pk,
                                uint8_t *sk,
                                gcry_mlkem_param_t *param,
                                uint8_t *coins)
{
  gpg_err_code_t ec = 0;
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


gcry_err_code_t
_gcry_mlkem_kem_keypair (uint8_t *pk, uint8_t *sk, gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  uint8_t *coins     = NULL;
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
_gcry_mlkem_kem_dec (uint8_t *ss,
                     const uint8_t *ct,
                     const uint8_t *sk,
                     gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  int fail;
  uint8_t buf[2 * GCRY_MLKEM_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2 * GCRY_MLKEM_SYMBYTES];

  uint8_t *cmp = NULL;

  const uint8_t *pk = sk + param->indcpa_secret_key_bytes;

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

  fail = _gcry_consttime_bytes_differ (ct, cmp, param->ciphertext_bytes);

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

  /* Copy true key to return buffer if fail is false */
  _gcry_consttime_cmov (ss, kr, GCRY_MLKEM_SYMBYTES, !fail);

end:
  xfree (cmp);
  return ec;
}

gcry_err_code_t
_gcry_mlkem_kem_enc (uint8_t *ct,
                     uint8_t *ss,
                     const uint8_t *pk,
                     gcry_mlkem_param_t *param)
{
  uint8_t coins[GCRY_MLKEM_SYMBYTES];
  _gcry_randomize (coins, GCRY_MLKEM_SYMBYTES, GCRY_VERY_STRONG_RANDOM);
  return _gcry_mlkem_kem_enc_derand (ct, ss, pk, param, coins);
}

gcry_err_code_t
_gcry_mlkem_kem_enc_derand (uint8_t *ct,
                            uint8_t *ss,
                            const uint8_t *pk,
                            gcry_mlkem_param_t *param,
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
