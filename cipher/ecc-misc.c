/* ecc-misc.c  -  Elliptic Curve miscellaneous functions
 * Copyright (C) 2007, 2008, 2010, 2011 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "mpi.h"
#include "context.h"
#include "ec-context.h"
#include "ecc-common.h"


/*
 * Release a curve object.
 */
void
_gcry_ecc_curve_free (elliptic_curve_t *E)
{
  mpi_free (E->p); E->p = NULL;
  mpi_free (E->a); E->a = NULL;
  mpi_free (E->b);  E->b = NULL;
  _gcry_mpi_point_free_parts (&E->G);
  mpi_free (E->n);  E->n = NULL;
}


/*
 * Return a copy of a curve object.
 */
elliptic_curve_t
_gcry_ecc_curve_copy (elliptic_curve_t E)
{
  elliptic_curve_t R;

  R.model = E.model;
  R.p = mpi_copy (E.p);
  R.a = mpi_copy (E.a);
  R.b = mpi_copy (E.b);
  _gcry_mpi_point_init (&R.G);
  point_set (&R.G, &E.G);
  R.n = mpi_copy (E.n);

  return R;
}


/*
 * Return a description of the curve model.
 */
const char *
_gcry_ecc_model2str (enum gcry_mpi_ec_models model)
{
  const char *str = "?";
  switch (model)
    {
    case MPI_EC_WEIERSTRASS:    str = "Weierstrass"; break;
    case MPI_EC_MONTGOMERY:     str = "Montgomery";  break;
    case MPI_EC_TWISTEDEDWARDS: str = "Twisted Edwards"; break;
    }
  return str;
}




gcry_mpi_t
_gcry_ecc_ec2os (gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t p)
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
      memmove (ptr+(pbytes-n), ptr, n);
      memset (ptr, 0, (pbytes-n));
    }
  ptr += pbytes;
  err = gcry_mpi_print (GCRYMPI_FMT_USG, ptr, pbytes, &n, y);
  if (err)
    log_fatal ("mpi_print failed: %s\n", gpg_strerror (err));
  if (n < pbytes)
    {
      memmove (ptr+(pbytes-n), ptr, n);
      memset (ptr, 0, (pbytes-n));
    }

  err = gcry_mpi_scan (&result, GCRYMPI_FMT_USG, buf, 1+2*pbytes, NULL);
  if (err)
    log_fatal ("mpi_scan failed: %s\n", gpg_strerror (err));
  gcry_free (buf);

  return result;
}


/* Convert POINT into affine coordinates using the context CTX and
   return a newly allocated MPI.  If the conversion is not possible
   NULL is returned.  This function won't print an error message.  */
gcry_mpi_t
_gcry_mpi_ec_ec2os (gcry_mpi_point_t point, mpi_ec_t ectx)
{
  gcry_mpi_t g_x, g_y, result;

  g_x = mpi_new (0);
  g_y = mpi_new (0);
  if (_gcry_mpi_ec_get_affine (g_x, g_y, point, ectx))
    result = NULL;
  else
    result = _gcry_ecc_ec2os (g_x, g_y, ectx->p);
  mpi_free (g_x);
  mpi_free (g_y);

  return result;
}


/* RESULT must have been initialized and is set on success to the
   point given by VALUE.  */
gcry_error_t
_gcry_ecc_os2ec (mpi_point_t result, gcry_mpi_t value)
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
