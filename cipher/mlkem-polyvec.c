/* mlkem-polyvec.c - functions related to vectors of polynomials for ML-KEM
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
#include "mlkem-polyvec.h"

gcry_error_t
_gcry_mlkem_polymatrix_create (gcry_mlkem_polyvec **polymat,
                               gcry_mlkem_param_t const *param)
{
  gcry_error_t ec = 0;
  unsigned i;
  *polymat = xtrymalloc (sizeof (**polymat) * param->k);
  if (!polymat)
    {
      ec = gpg_error_from_syserror ();
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


void
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

gcry_error_t
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

void
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
void
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
void
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
void
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
void
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
void
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
void
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
gcry_err_code_t
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
void
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
void
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
