/* ecc-common.h - Declarations of common ECC code
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

#ifndef GCRY_ECC_COMMON_H
#define GCRY_ECC_COMMON_H

/* Definition of a curve.  */
typedef struct
{
  enum gcry_mpi_ec_models model;/* The model descrinbing this curve.  */
  gcry_mpi_t p;         /* Prime specifying the field GF(p).  */
  gcry_mpi_t a;         /* First coefficient of the Weierstrass equation.  */
  gcry_mpi_t b;         /* Second coefficient of the Weierstrass equation.
                           or d as used by Twisted Edwards curves.  */
  mpi_point_struct G;   /* Base point (generator).  */
  gcry_mpi_t n;         /* Order of G.  */
  const char *name;     /* Name of the curve or NULL.  */
} elliptic_curve_t;


typedef struct
{
  elliptic_curve_t E;
  mpi_point_struct Q; /* Q = [d]G  */
} ECC_public_key;


typedef struct
{
  elliptic_curve_t E;
  mpi_point_struct Q;
  gcry_mpi_t d;
} ECC_secret_key;



/* Set the value from S into D.  */
static inline void
point_set (mpi_point_t d, mpi_point_t s)
{
  mpi_set (d->x, s->x);
  mpi_set (d->y, s->y);
  mpi_set (d->z, s->z);
}


/*-- ecc-curves.c --*/
gpg_err_code_t _gcry_ecc_fill_in_curve (unsigned int nbits,
                                        const char *name,
                                        elliptic_curve_t *curve,
                                        unsigned int *r_nbits);

const char *_gcry_ecc_get_curve (gcry_mpi_t *pkey,
                                 int iterator,
                                 unsigned int *r_nbits);
gcry_err_code_t _gcry_ecc_get_param (const char *name, gcry_mpi_t *pkey);
gcry_sexp_t     _gcry_ecc_get_param_sexp (const char *name);

/*-- ecc-misc.c --*/
void _gcry_ecc_curve_free (elliptic_curve_t *E);
elliptic_curve_t _gcry_ecc_curve_copy (elliptic_curve_t E);
const char *_gcry_ecc_model2str (enum gcry_mpi_ec_models model);
gcry_mpi_t   _gcry_ecc_ec2os (gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t p);
gcry_error_t _gcry_ecc_os2ec (mpi_point_t result, gcry_mpi_t value);


#endif /*GCRY_ECC_COMMON_H*/
