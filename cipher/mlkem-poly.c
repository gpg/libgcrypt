/* mlkem-poly.c - functions related to polynomials for ML-KEM
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

#include <stdint.h>
#include "mlkem-params.h"
#include "mlkem-poly.h"
#include "mlkem-ntt.h"
#include "mlkem-aux.h"
#include "mlkem-cbd.h"
#include "mlkem-symmetric.h"

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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
void
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
