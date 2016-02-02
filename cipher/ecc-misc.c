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
#include "cipher.h"
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
  mpi_free (E->h);  E->h = NULL;
}


/*
 * Return a copy of a curve object.
 */
elliptic_curve_t
_gcry_ecc_curve_copy (elliptic_curve_t E)
{
  elliptic_curve_t R;

  R.model = E.model;
  R.dialect = E.dialect;
  R.name = E.name;
  R.p = mpi_copy (E.p);
  R.a = mpi_copy (E.a);
  R.b = mpi_copy (E.b);
  _gcry_mpi_point_init (&R.G);
  point_set (&R.G, &E.G);
  R.n = mpi_copy (E.n);
  R.h = mpi_copy (E.h);

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
    case MPI_EC_EDWARDS:        str = "Edwards"; break;
    }
  return str;
}


/*
 * Return a description of the curve dialect.
 */
const char *
_gcry_ecc_dialect2str (enum ecc_dialects dialect)
{
  const char *str = "?";
  switch (dialect)
    {
    case ECC_DIALECT_STANDARD:  str = "Standard"; break;
    case ECC_DIALECT_ED25519:   str = "Ed25519"; break;
    }
  return str;
}


gcry_mpi_t
_gcry_ecc_ec2os (gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t p)
{
  gpg_err_code_t rc;
  int pbytes = (mpi_get_nbits (p)+7)/8;
  size_t n;
  unsigned char *buf, *ptr;
  gcry_mpi_t result;

  buf = xmalloc ( 1 + 2*pbytes );
  *buf = 04; /* Uncompressed point.  */
  ptr = buf+1;
  rc = _gcry_mpi_print (GCRYMPI_FMT_USG, ptr, pbytes, &n, x);
  if (rc)
    log_fatal ("mpi_print failed: %s\n", gpg_strerror (rc));
  if (n < pbytes)
    {
      memmove (ptr+(pbytes-n), ptr, n);
      memset (ptr, 0, (pbytes-n));
    }
  ptr += pbytes;
  rc = _gcry_mpi_print (GCRYMPI_FMT_USG, ptr, pbytes, &n, y);
  if (rc)
    log_fatal ("mpi_print failed: %s\n", gpg_strerror (rc));
  if (n < pbytes)
    {
      memmove (ptr+(pbytes-n), ptr, n);
      memset (ptr, 0, (pbytes-n));
    }

  rc = _gcry_mpi_scan (&result, GCRYMPI_FMT_USG, buf, 1+2*pbytes, NULL);
  if (rc)
    log_fatal ("mpi_scan failed: %s\n", gpg_strerror (rc));
  xfree (buf);

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
gcry_err_code_t
_gcry_ecc_os2ec (mpi_point_t result, gcry_mpi_t value)
{
  gcry_err_code_t rc;
  size_t n;
  const unsigned char *buf;
  unsigned char *buf_memory;
  gcry_mpi_t x, y;

  if (mpi_is_opaque (value))
    {
      unsigned int nbits;

      buf = mpi_get_opaque (value, &nbits);
      if (!buf)
        return GPG_ERR_INV_OBJ;
      n = (nbits + 7)/8;
      buf_memory = NULL;
    }
  else
    {
      n = (mpi_get_nbits (value)+7)/8;
      buf_memory = xmalloc (n);
      rc = _gcry_mpi_print (GCRYMPI_FMT_USG, buf_memory, n, &n, value);
      if (rc)
        {
          xfree (buf_memory);
          return rc;
        }
      buf = buf_memory;
    }

  if (n < 1)
    {
      xfree (buf_memory);
      return GPG_ERR_INV_OBJ;
    }
  if (*buf != 4)
    {
      xfree (buf_memory);
      return GPG_ERR_NOT_IMPLEMENTED; /* No support for point compression.  */
    }
  if ( ((n-1)%2) )
    {
      xfree (buf_memory);
      return GPG_ERR_INV_OBJ;
    }
  n = (n-1)/2;
  rc = _gcry_mpi_scan (&x, GCRYMPI_FMT_USG, buf+1, n, NULL);
  if (rc)
    {
      xfree (buf_memory);
      return rc;
    }
  rc = _gcry_mpi_scan (&y, GCRYMPI_FMT_USG, buf+1+n, n, NULL);
  xfree (buf_memory);
  if (rc)
    {
      mpi_free (x);
      return rc;
    }

  mpi_set (result->x, x);
  mpi_set (result->y, y);
  mpi_set_ui (result->z, 1);

  mpi_free (x);
  mpi_free (y);

  return 0;
}


/* Compute the public key from the the context EC.  Obviously a
   requirement is that the secret key is available in EC.  On success
   Q is returned; on error NULL.  If Q is NULL a newly allocated point
   is returned.  If G or D are given they override the values taken
   from EC. */
mpi_point_t
_gcry_ecc_compute_public (mpi_point_t Q, mpi_ec_t ec,
                          mpi_point_t G, gcry_mpi_t d)
{
  if (!G)
    G = ec->G;
  if (!d)
    d = ec->d;

  if (!d || !G || !ec->p || !ec->a)
    return NULL;
  if (ec->model == MPI_EC_EDWARDS && !ec->b)
    return NULL;

  if (ec->dialect == ECC_DIALECT_ED25519
      && (ec->flags & PUBKEY_FLAG_EDDSA))
    {
      gcry_mpi_t a;
      unsigned char *digest;

      if (_gcry_ecc_eddsa_compute_h_d (&digest, d, ec))
        return NULL;

      a = mpi_snew (0);
      _gcry_mpi_set_buffer (a, digest, 32, 0);
      xfree (digest);

      /* And finally the public key.  */
      if (!Q)
        Q = mpi_point_new (0);
      if (Q)
        _gcry_mpi_ec_mul_point (Q, a, G, ec);
      mpi_free (a);
    }
  else
    {
      if (!Q)
        Q = mpi_point_new (0);
      if (Q)
        _gcry_mpi_ec_mul_point (Q, d, G, ec);
    }

  return Q;
}


gpg_err_code_t
_gcry_ecc_mont_decodepoint (gcry_mpi_t pk, mpi_ec_t ctx, mpi_point_t result)
{
  unsigned char *rawmpi;
  unsigned int rawmpilen;

  if (mpi_is_opaque (pk))
    {
      const unsigned char *buf;
      unsigned char *p;

      buf = mpi_get_opaque (pk, &rawmpilen);
      if (!buf)
        return GPG_ERR_INV_OBJ;
      rawmpilen = (rawmpilen + 7)/8;

      if (rawmpilen > 1 && (rawmpilen%2) && buf[0] == 0x40)
        {
          rawmpilen--;
          buf++;
        }

      rawmpi = xtrymalloc (rawmpilen? rawmpilen:1);
      if (!rawmpi)
        return gpg_err_code_from_syserror ();

      p = rawmpi + rawmpilen;
      while (p > rawmpi)
        *--p = *buf++;
    }
  else
    {
      unsigned int nbytes = (ctx->nbits+7)/8;

      rawmpi = _gcry_mpi_get_buffer (pk, nbytes, &rawmpilen, NULL);
      if (!rawmpi)
        return gpg_err_code_from_syserror ();
      /*
       * It is not reliable to assume that 0x40 means the prefix.
       *
       * For newer implementation, it is reliable since we always put
       * 0x40 for x-only coordinate.
       *
       * For data with older implementation (non-released development
       * version), it is possibe to have the 0x40 as a part of data.
       * Besides, when data was parsed as MPI, we might have 0x00
       * prefix.
       *
       * So, we need to check if it's really the prefix or not.
       * Only when it's the prefix, we remove it.
       */
      if (pk->nlimbs * BYTES_PER_MPI_LIMB < nbytes)
        {/*
          * It is possible for data created by older implementation
          * to have shorter length when it was parsed as MPI.
          */
          unsigned int len = pk->nlimbs * BYTES_PER_MPI_LIMB;

          memmove (rawmpi + nbytes - len, rawmpi, len);
          memset (rawmpi, 0, nbytes - len);
        }

      /*
       * When we have the prefix (0x40 or 0x00), it comes at the end,
       * since it is taken by _gcry_mpi_get_buffer with little endian.
       * Just setting RAWMPILEN to NBYTES is enough in this case.
       * Othewise, RAWMPILEN is NBYTES already.
       */
      rawmpilen = nbytes;
    }

  rawmpi[0] &= (1 << (ctx->nbits % 8)) - 1;
  _gcry_mpi_set_buffer (result->x, rawmpi, rawmpilen, 0);
  xfree (rawmpi);
  mpi_set_ui (result->z, 1);

  return 0;
}
