/* pubkey.c  -	pubkey dispatcher
 * Copyright (C) 1998, 1999, 2000, 2002, 2003, 2005,
 *               2007, 2008, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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
#include "ath.h"
#include "context.h"
#include "pubkey-internal.h"


/* This is the list of the public-key algorithms included in
   Libgcrypt.  */
static gcry_pk_spec_t *pubkey_list[] =
  {
#if USE_ECC
    &_gcry_pubkey_spec_ecdsa,
    &_gcry_pubkey_spec_ecdh,
#endif
#if USE_RSA
    &_gcry_pubkey_spec_rsa,
#endif
#if USE_DSA
    &_gcry_pubkey_spec_dsa,
#endif
#if USE_ELGAMAL
    &_gcry_pubkey_spec_elg,
    &_gcry_pubkey_spec_elg,
#endif
    NULL
  };


/* Return the spec structure for the public key algorithm ALGO.  For
   an unknown algorithm NULL is returned.  */
static gcry_pk_spec_t *
spec_from_algo (int algo)
{
  int idx;
  gcry_pk_spec_t *spec;

  for (idx = 0; (spec = pubkey_list[idx]); idx++)
    if (algo == spec->algo)
      return spec;
  return NULL;
}


/* Return the spec structure for the public key algorithm with NAME.
   For an unknown name NULL is returned.  */
static gcry_pk_spec_t *
spec_from_name (const char *name)
{
  gcry_pk_spec_t *spec;
  int idx;
  const char **aliases;

  for (idx=0; (spec = pubkey_list[idx]); idx++)
    {
      if (!stricmp (name, spec->name))
        return spec;
      for (aliases = spec->aliases; *aliases; aliases++)
        if (!stricmp (name, *aliases))
          return spec;
    }

  return NULL;
}


/* Disable the use of the algorithm ALGO.  This is not thread safe and
   should thus be called early.  */
static void
disable_pubkey_algo (int algo)
{
  gcry_pk_spec_t *spec = spec_from_algo (algo);

  if (spec)
    spec->flags.disabled = 1;
}



/* Free the MPIs stored in the NULL terminated ARRAY of MPIs and set
   the slots to NULL.  */
static void
release_mpi_array (gcry_mpi_t *array)
{
  for (; *array; array++)
    {
      mpi_free(*array);
      *array = NULL;
    }
}



/*
 * Map a string to the pubkey algo
 */
int
gcry_pk_map_name (const char *string)
{
  gcry_pk_spec_t *spec;

  if (!string)
    return 0;
  spec = spec_from_name (string);
  if (!spec)
    return 0;
  if (spec->flags.disabled)
    return 0;
  return spec->algo;
}


/* Map the public key algorithm whose ID is contained in ALGORITHM to
   a string representation of the algorithm name.  For unknown
   algorithm IDs this functions returns "?". */
const char *
gcry_pk_algo_name (int algo)
{
  gcry_pk_spec_t *spec;

  spec = spec_from_algo (algo);
  if (spec)
    return spec->name;
  return "?";
}


/****************
 * A USE of 0 means: don't care.
 */
static gcry_err_code_t
check_pubkey_algo (int algo, unsigned use)
{
  gcry_err_code_t err = 0;
  gcry_pk_spec_t *spec;

  spec = spec_from_algo (algo);
  if (spec)
    {
      if (((use & GCRY_PK_USAGE_SIGN)
	   && (! (spec->use & GCRY_PK_USAGE_SIGN)))
	  || ((use & GCRY_PK_USAGE_ENCR)
	      && (! (spec->use & GCRY_PK_USAGE_ENCR))))
	err = GPG_ERR_WRONG_PUBKEY_ALGO;
    }
  else
    err = GPG_ERR_PUBKEY_ALGO;

  return err;
}


/****************
 * Return the number of public key material numbers
 */
static int
pubkey_get_npkey (int algo)
{
  gcry_pk_spec_t *spec = spec_from_algo (algo);

  return spec? strlen (spec->elements_pkey) : 0;
}


/****************
 * Return the number of secret key material numbers
 */
static int
pubkey_get_nskey (int algo)
{
  gcry_pk_spec_t *spec = spec_from_algo (algo);

  return spec? strlen (spec->elements_skey) : 0;
}


/****************
 * Return the number of signature material numbers
 */
static int
pubkey_get_nsig (int algo)
{
  gcry_pk_spec_t *spec = spec_from_algo (algo);

  return spec? strlen (spec->elements_sig) : 0;
}

/****************
 * Return the number of encryption material numbers
 */
static int
pubkey_get_nenc (int algo)
{
  gcry_pk_spec_t *spec = spec_from_algo (algo);

  return spec? strlen (spec->elements_enc) : 0;
}


static gcry_err_code_t
pubkey_check_secret_key (int algo, gcry_mpi_t *skey)
{
  gcry_err_code_t rc;
  gcry_pk_spec_t *spec = spec_from_algo (algo);

  if (spec && spec->check_secret_key)
    rc = spec->check_secret_key (algo, skey);
  else if (spec)
    rc = GPG_ERR_NOT_IMPLEMENTED;
  else
    rc = GPG_ERR_PUBKEY_ALGO;

  return rc;
}


/* Internal function.   */
static gcry_err_code_t
sexp_elements_extract (gcry_sexp_t key_sexp, const char *element_names,
		       gcry_mpi_t *elements, const char *algo_name, int opaque)
{
  gcry_err_code_t err = 0;
  int i, idx;
  const char *name;
  gcry_sexp_t list;

  for (name = element_names, idx = 0; *name && !err; name++, idx++)
    {
      list = gcry_sexp_find_token (key_sexp, name, 1);
      if (!list)
	elements[idx] = NULL;
      else if (opaque)
        {
	  elements[idx] = _gcry_sexp_nth_opaque_mpi (list, 1);
	  gcry_sexp_release (list);
	  if (!elements[idx])
	    err = GPG_ERR_INV_OBJ;
        }
      else
	{
	  elements[idx] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
	  gcry_sexp_release (list);
	  if (!elements[idx])
	    err = GPG_ERR_INV_OBJ;
	}
    }

  if (!err)
    {
      /* Check that all elements are available.  */
      for (name = element_names, i = 0; *name; name++, i++)
        if (!elements[i])
          break;
      if (*name)
        {
          err = GPG_ERR_NO_OBJ;
          /* Some are missing.  Before bailing out we test for
             optional parameters.  */
          if (algo_name && !strcmp (algo_name, "RSA")
              && !strcmp (element_names, "nedpqu") )
            {
              /* This is RSA.  Test whether we got N, E and D and that
                 the optional P, Q and U are all missing.  */
              if (elements[0] && elements[1] && elements[2]
                  && !elements[3] && !elements[4] && !elements[5])
                err = 0;
            }
        }
    }


  if (err)
    {
      for (i = 0; i < idx; i++)
        if (elements[i])
          mpi_free (elements[i]);
    }
  return err;
}


/* Internal function used for ecc.  Note, that this function makes use
   of its intimate knowledge about the ECC parameters from ecc.c. */
static gcry_err_code_t
sexp_elements_extract_ecc (gcry_sexp_t key_sexp, const char *element_names,
                           gcry_mpi_t *elements, gcry_pk_spec_t *spec,
                           int want_private)

{
  gcry_err_code_t err = 0;
  int idx;
  const char *name;
  gcry_sexp_t list;

  /* Clear the array for easier error cleanup. */
  for (name = element_names, idx = 0; *name; name++, idx++)
    elements[idx] = NULL;
  gcry_assert (idx >= 5); /* We know that ECC has at least 5 elements
                             (params only) or 6 (full public key).  */
  if (idx == 5)
    elements[5] = NULL;   /* Extra clear for the params only case.  */


  /* Init the array with the available curve parameters. */
  for (name = element_names, idx = 0; *name && !err; name++, idx++)
    {
      list = gcry_sexp_find_token (key_sexp, name, 1);
      if (!list)
	elements[idx] = NULL;
      else
	{
          switch (idx)
            {
            case 5: /* The public and */
            case 6: /* the secret key must to be passed opaque.  */
              elements[idx] = _gcry_sexp_nth_opaque_mpi (list, 1);
              break;
            default:
              elements[idx] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_STD);
              break;
            }
	  gcry_sexp_release (list);
	  if (!elements[idx])
            {
              err = GPG_ERR_INV_OBJ;
              goto leave;
            }
	}
    }

  /* Check whether a curve parameter has been given and then fill any
     missing elements.  */
  list = gcry_sexp_find_token (key_sexp, "curve", 5);
  if (list)
    {
      if (spec->get_param)
        {
          char *curve;
          gcry_mpi_t params[6];

          for (idx = 0; idx < DIM(params); idx++)
            params[idx] = NULL;

          curve = _gcry_sexp_nth_string (list, 1);
          gcry_sexp_release (list);
          if (!curve)
            {
              /* No curve name given (or out of core). */
              err = GPG_ERR_INV_OBJ;
              goto leave;
            }
          err = spec->get_param (curve, params);
          gcry_free (curve);
          if (err)
            goto leave;

          for (idx = 0; idx < DIM(params); idx++)
            {
              if (!elements[idx])
                elements[idx] = params[idx];
              else
                mpi_free (params[idx]);
            }
        }
      else
        {
          gcry_sexp_release (list);
          err = GPG_ERR_INV_OBJ; /* "curve" given but ECC not supported. */
          goto leave;
        }
    }

  /* Check that all parameters are known.  */
  for (name = element_names, idx = 0; *name; name++, idx++)
    if (!elements[idx])
      {
        if (want_private && *name == 'q')
          ; /* Q is optional.  */
        else
          {
            err = GPG_ERR_NO_OBJ;
            goto leave;
          }
      }

 leave:
  if (err)
    {
      for (name = element_names, idx = 0; *name; name++, idx++)
        if (elements[idx])
          mpi_free (elements[idx]);
    }
  return err;
}



/****************
 * Convert a S-Exp with either a private or a public key to our
 * internal format. Currently we do only support the following
 * algorithms:
 *    dsa
 *    rsa
 *    openpgp-dsa
 *    openpgp-rsa
 *    openpgp-elg
 *    openpgp-elg-sig
 *    ecdsa
 *    ecdh
 * Provide a SE with the first element be either "private-key" or
 * or "public-key". It is followed by a list with its first element
 * be one of the above algorithm identifiers and the remaning
 * elements are pairs with parameter-id and value.
 * NOTE: we look through the list to find a list beginning with
 * "private-key" or "public-key" - the first one found is used.
 *
 * If OVERRIDE_ELEMS is not NULL those elems override the parameter
 * specification taken from the module.  This ise used by
 * gcry_pk_get_curve.
 *
 * Returns: A pointer to an allocated array of MPIs if the return value is
 *	    zero; the caller has to release this array.
 *
 * Example of a DSA public key:
 *  (private-key
 *    (dsa
 *	(p <mpi>)
 *	(g <mpi>)
 *	(y <mpi>)
 *	(x <mpi>)
 *    )
 *  )
 * The <mpi> are expected to be in GCRYMPI_FMT_USG
 */
static gcry_err_code_t
sexp_to_key (gcry_sexp_t sexp, int want_private, int use,
             const char *override_elems,
             gcry_mpi_t **retarray, gcry_pk_spec_t **r_spec, int *r_is_ecc)
{
  gcry_err_code_t err = 0;
  gcry_sexp_t list, l2;
  char *name;
  const char *elems;
  gcry_mpi_t *array;
  gcry_pk_spec_t *spec;
  int is_ecc;

  /* Check that the first element is valid.  If we are looking for a
     public key but a private key was supplied, we allow the use of
     the private key anyway.  The rationale for this is that the
     private key is a superset of the public key. */
  list = gcry_sexp_find_token (sexp,
                               want_private? "private-key":"public-key", 0);
  if (!list && !want_private)
    list = gcry_sexp_find_token (sexp, "private-key", 0);
  if (!list)
    return GPG_ERR_INV_OBJ; /* Does not contain a key object.  */

  l2 = gcry_sexp_cadr( list );
  gcry_sexp_release ( list );
  list = l2;
  name = _gcry_sexp_nth_string (list, 0);
  if (!name)
    {
      gcry_sexp_release ( list );
      return GPG_ERR_INV_OBJ;      /* Invalid structure of object. */
    }

  /* Fixme: We should make sure that an ECC key is always named "ecc"
     and not "ecdsa".  "ecdsa" should be used for the signature
     itself.  We need a function to test whether an algorithm given
     with a key is compatible with an application of the key (signing,
     encryption).  For RSA this is easy, but ECC is the first
     algorithm which has many flavours.

     We use an ugly hack here to decide whether to use ecdsa or ecdh.
  */
  if (!strcmp (name, "ecc"))
    is_ecc = 2;
  else if (!strcmp (name, "ecdsa") || !strcmp (name, "ecdh"))
    is_ecc = 1;
  else
    is_ecc = 0;

  if (is_ecc == 2 && (use & GCRY_PK_USAGE_SIGN))
    spec = spec_from_name ("ecdsa");
  else if (is_ecc == 2 && (use & GCRY_PK_USAGE_ENCR))
    spec = spec_from_name ("ecdh");
  else
    spec = spec_from_name (name);

  gcry_free (name);

  if (!spec)
    {
      gcry_sexp_release (list);
      return GPG_ERR_PUBKEY_ALGO; /* Unknown algorithm. */
    }

  if (override_elems)
    elems = override_elems;
  else if (want_private)
    elems = spec->elements_skey;
  else
    elems = spec->elements_pkey;
  array = gcry_calloc (strlen (elems) + 1, sizeof (*array));
  if (!array)
    err = gpg_err_code_from_syserror ();
  if (!err)
    {
      if (is_ecc)
        err = sexp_elements_extract_ecc (list, elems, array, spec,
                                         want_private);
      else
        err = sexp_elements_extract (list, elems, array, spec->name, 0);
    }

  gcry_sexp_release (list);

  if (err)
    {
      gcry_free (array);
    }
  else
    {
      *retarray = array;
      *r_spec = spec;
      if (r_is_ecc)
        *r_is_ecc = is_ecc;
    }

  return err;
}


/* Parse SEXP and store the elements into a newly allocated array of
   MPIs which will be stored at RETARRAY.  If OPAQUE is set, store the
   MPI as opaque data.  */
static gcry_err_code_t
sexp_to_sig (gcry_sexp_t sexp, gcry_mpi_t **retarray,
	     gcry_pk_spec_t **r_spec, int opaque)
{
  gcry_err_code_t err = 0;
  gcry_sexp_t list, l2;
  char *name;
  const char *elems;
  gcry_mpi_t *array;
  gcry_pk_spec_t *spec;

  /* Check that the first element is valid.  */
  list = gcry_sexp_find_token( sexp, "sig-val" , 0 );
  if (!list)
    return GPG_ERR_INV_OBJ; /* Does not contain a signature value object.  */

  l2 = gcry_sexp_nth (list, 1);
  if (!l2)
    {
      gcry_sexp_release (list);
      return GPG_ERR_NO_OBJ;   /* No cadr for the sig object.  */
    }
  name = _gcry_sexp_nth_string (l2, 0);
  if (!name)
    {
      gcry_sexp_release (list);
      gcry_sexp_release (l2);
      return GPG_ERR_INV_OBJ;  /* Invalid structure of object.  */
    }
  else if (!strcmp (name, "flags"))
    {
      /* Skip flags, since they are not used but here just for the
	 sake of consistent S-expressions.  */
      gcry_free (name);
      gcry_sexp_release (l2);
      l2 = gcry_sexp_nth (list, 2);
      if (!l2)
	{
	  gcry_sexp_release (list);
	  return GPG_ERR_INV_OBJ;
	}
      name = _gcry_sexp_nth_string (l2, 0);
    }

  spec = spec_from_name (name);
  gcry_free (name);
  name = NULL;

  if (!spec)
    {
      gcry_sexp_release (l2);
      gcry_sexp_release (list);
      return GPG_ERR_PUBKEY_ALGO;  /* Unknown algorithm. */
    }

  elems = spec->elements_sig;
  array = gcry_calloc (strlen (elems) + 1 , sizeof *array );
  if (!array)
    err = gpg_err_code_from_syserror ();

  if (!err)
    err = sexp_elements_extract (list, elems, array, NULL, opaque);

  gcry_sexp_release (l2);
  gcry_sexp_release (list);

  if (err)
    {
      gcry_free (array);
    }
  else
    {
      *retarray = array;
      *r_spec = spec;
    }

  return err;
}

static inline int
get_hash_algo (const char *s, size_t n)
{
  static const struct { const char *name; int algo; } hashnames[] = {
    { "sha1",   GCRY_MD_SHA1 },
    { "md5",    GCRY_MD_MD5 },
    { "sha256", GCRY_MD_SHA256 },
    { "ripemd160", GCRY_MD_RMD160 },
    { "rmd160", GCRY_MD_RMD160 },
    { "sha384", GCRY_MD_SHA384 },
    { "sha512", GCRY_MD_SHA512 },
    { "sha224", GCRY_MD_SHA224 },
    { "md2",    GCRY_MD_MD2 },
    { "md4",    GCRY_MD_MD4 },
    { "tiger",  GCRY_MD_TIGER },
    { "haval",  GCRY_MD_HAVAL },
    { NULL, 0 }
  };
  int algo;
  int i;

  for (i=0; hashnames[i].name; i++)
    {
      if ( strlen (hashnames[i].name) == n
	   && !memcmp (hashnames[i].name, s, n))
	break;
    }
  if (hashnames[i].name)
    algo = hashnames[i].algo;
  else
    {
      /* In case of not listed or dynamically allocated hash
	 algorithm we fall back to this somewhat slower
	 method.  Further, it also allows to use OIDs as
	 algorithm names. */
      char *tmpname;

      tmpname = gcry_malloc (n+1);
      if (!tmpname)
	algo = 0;  /* Out of core - silently give up.  */
      else
	{
	  memcpy (tmpname, s, n);
	  tmpname[n] = 0;
	  algo = gcry_md_map_name (tmpname);
	  gcry_free (tmpname);
	}
    }
  return algo;
}


/****************
 * Take sexp and return an array of MPI as used for our internal decrypt
 * function.
 * s_data = (enc-val
 *           [(flags [raw, pkcs1, oaep, no-blinding])]
 *           [(hash-algo <algo>)]
 *           [(label <label>)]
 *	      (<algo>
 *		(<param_name1> <mpi>)
 *		...
 *		(<param_namen> <mpi>)
 *	      ))
 * HASH-ALGO and LABEL are specific to OAEP.
 * RET_MODERN is set to true when at least an empty flags list has been found.
 * CTX is used to return encoding information; it may be NULL in which
 * case raw encoding is used.
 */
static gcry_err_code_t
sexp_to_enc (gcry_sexp_t sexp, gcry_mpi_t **retarray, gcry_pk_spec_t **r_spec,
             int *ret_modern, int *flags, struct pk_encoding_ctx *ctx)
{
  gcry_err_code_t err = 0;
  gcry_sexp_t list = NULL;
  gcry_sexp_t l2 = NULL;
  gcry_pk_spec_t *spec = NULL;
  char *name = NULL;
  size_t n;
  int parsed_flags = 0;
  const char *elems;
  gcry_mpi_t *array = NULL;

  *ret_modern = 0;

  /* Check that the first element is valid.  */
  list = gcry_sexp_find_token (sexp, "enc-val" , 0);
  if (!list)
    {
      err = GPG_ERR_INV_OBJ; /* Does not contain an encrypted value object.  */
      goto leave;
    }

  l2 = gcry_sexp_nth (list, 1);
  if (!l2)
    {
      err = GPG_ERR_NO_OBJ; /* No cdr for the data object.  */
      goto leave;
    }

  /* Extract identifier of sublist.  */
  name = _gcry_sexp_nth_string (l2, 0);
  if (!name)
    {
      err = GPG_ERR_INV_OBJ; /* Invalid structure of object.  */
      goto leave;
    }

  if (!strcmp (name, "flags"))
    {
      /* There is a flags element - process it.  */
      const char *s;
      int i;

      *ret_modern = 1;
      for (i = gcry_sexp_length (l2) - 1; i > 0; i--)
        {
          s = gcry_sexp_nth_data (l2, i, &n);
          if (! s)
            ; /* Not a data element - ignore.  */
          else if (n == 3 && !memcmp (s, "raw", 3)
                   && ctx->encoding == PUBKEY_ENC_UNKNOWN)
            ctx->encoding = PUBKEY_ENC_RAW;
          else if (n == 5 && !memcmp (s, "pkcs1", 5)
                   && ctx->encoding == PUBKEY_ENC_UNKNOWN)
	    ctx->encoding = PUBKEY_ENC_PKCS1;
          else if (n == 4 && !memcmp (s, "oaep", 4)
                   && ctx->encoding == PUBKEY_ENC_UNKNOWN)
	    ctx->encoding = PUBKEY_ENC_OAEP;
          else if (n == 3 && !memcmp (s, "pss", 3)
                   && ctx->encoding == PUBKEY_ENC_UNKNOWN)
	    {
	      err = GPG_ERR_CONFLICT;
	      goto leave;
	    }
          else if (n == 11 && ! memcmp (s, "no-blinding", 11))
            parsed_flags |= PUBKEY_FLAG_NO_BLINDING;
          else
            {
              err = GPG_ERR_INV_FLAG;
              goto leave;
            }
        }
      gcry_sexp_release (l2);

      /* Get the OAEP parameters HASH-ALGO and LABEL, if any. */
      if (ctx->encoding == PUBKEY_ENC_OAEP)
	{
	  /* Get HASH-ALGO. */
	  l2 = gcry_sexp_find_token (list, "hash-algo", 0);
	  if (l2)
	    {
	      s = gcry_sexp_nth_data (l2, 1, &n);
	      if (!s)
		err = GPG_ERR_NO_OBJ;
	      else
		{
		  ctx->hash_algo = get_hash_algo (s, n);
		  if (!ctx->hash_algo)
		    err = GPG_ERR_DIGEST_ALGO;
		}
	      gcry_sexp_release (l2);
	      if (err)
		goto leave;
	    }

	  /* Get LABEL. */
	  l2 = gcry_sexp_find_token (list, "label", 0);
	  if (l2)
	    {
	      s = gcry_sexp_nth_data (l2, 1, &n);
	      if (!s)
		err = GPG_ERR_NO_OBJ;
	      else if (n > 0)
		{
		  ctx->label = gcry_malloc (n);
		  if (!ctx->label)
		    err = gpg_err_code_from_syserror ();
		  else
		    {
		      memcpy (ctx->label, s, n);
		      ctx->labellen = n;
		    }
		}
	      gcry_sexp_release (l2);
	      if (err)
		goto leave;
	    }
	}

      /* Get the next which has the actual data - skip HASH-ALGO and LABEL. */
      for (i = 2; (l2 = gcry_sexp_nth (list, i)) != NULL; i++)
	{
	  s = gcry_sexp_nth_data (l2, 0, &n);
	  if (!(n == 9 && !memcmp (s, "hash-algo", 9))
	      && !(n == 5 && !memcmp (s, "label", 5))
	      && !(n == 15 && !memcmp (s, "random-override", 15)))
	    break;
	  gcry_sexp_release (l2);
	}

      if (!l2)
        {
          err = GPG_ERR_NO_OBJ; /* No cdr for the data object. */
          goto leave;
        }

      /* Extract sublist identifier.  */
      gcry_free (name);
      name = _gcry_sexp_nth_string (l2, 0);
      if (!name)
        {
          err = GPG_ERR_INV_OBJ; /* Invalid structure of object. */
          goto leave;
        }

      gcry_sexp_release (list);
      list = l2;
      l2 = NULL;
    }

  spec = spec_from_name (name);
  if (!spec)
    {
      err = GPG_ERR_PUBKEY_ALGO; /* Unknown algorithm.  */
      goto leave;
    }

  elems = spec->elements_enc;
  array = gcry_calloc (strlen (elems) + 1, sizeof (*array));
  if (!array)
    {
      err = gpg_err_code_from_syserror ();
      goto leave;
    }

  err = sexp_elements_extract (list, elems, array, NULL, 0);

 leave:
  gcry_sexp_release (list);
  gcry_sexp_release (l2);
  gcry_free (name);

  if (err)
    {
      gcry_free (array);
      gcry_free (ctx->label);
      ctx->label = NULL;
    }
  else
    {
      *retarray = array;
      *r_spec = spec;
      *flags = parsed_flags;
    }

  return err;
}


/* Callback for the pubkey algorithm code to verify PSS signatures.
   OPAQUE is the data provided by the actual caller.  The meaning of
   TMP depends on the actual algorithm (but there is only RSA); now
   for RSA it is the output of running the public key function on the
   input.  */
static int
pss_verify_cmp (void *opaque, gcry_mpi_t tmp)
{
  struct pk_encoding_ctx *ctx = opaque;
  gcry_mpi_t hash = ctx->verify_arg;

  return _gcry_rsa_pss_verify (hash, tmp, ctx->nbits - 1,
                               ctx->hash_algo, ctx->saltlen);
}


/* Take the hash value and convert into an MPI, suitable for
   passing to the low level functions.  We currently support the
   old style way of passing just a MPI and the modern interface which
   allows to pass flags so that we can choose between raw and pkcs1
   padding - may be more padding options later.

   (<mpi>)
   or
   (data
    [(flags [raw, direct, pkcs1, oaep, pss, no-blinding, rfc6979, eddsa])]
    [(hash <algo> <value>)]
    [(value <text>)]
    [(hash-algo <algo>)]
    [(label <label>)]
    [(salt-length <length>)]
    [(random-override <data>)]
   )

   Either the VALUE or the HASH element must be present for use
   with signatures.  VALUE is used for encryption.

   HASH-ALGO is specific to OAEP and EDDSA.

   LABEL is specific to OAEP.

   SALT-LENGTH is for PSS.

   RANDOM-OVERRIDE is used to replace random nonces for regression
   testing.  */
static gcry_err_code_t
sexp_data_to_mpi (gcry_sexp_t input, gcry_mpi_t *ret_mpi,
		  struct pk_encoding_ctx *ctx)
{
  gcry_err_code_t rc = 0;
  gcry_sexp_t ldata, lhash, lvalue;
  int i;
  size_t n;
  const char *s;
  int unknown_flag = 0;
  int parsed_flags = 0;
  int explicit_raw = 0;

  *ret_mpi = NULL;
  ldata = gcry_sexp_find_token (input, "data", 0);
  if (!ldata)
    { /* assume old style */
      *ret_mpi = gcry_sexp_nth_mpi (input, 0, 0);
      return *ret_mpi ? GPG_ERR_NO_ERROR : GPG_ERR_INV_OBJ;
    }

  /* see whether there is a flags object */
  {
    gcry_sexp_t lflags = gcry_sexp_find_token (ldata, "flags", 0);
    if (lflags)
      { /* parse the flags list. */
        for (i=gcry_sexp_length (lflags)-1; i > 0; i--)
          {
            s = gcry_sexp_nth_data (lflags, i, &n);
            if (!s)
              ; /* not a data element*/
	    else if (n == 7 && !memcmp (s, "rfc6979", 7))
	      parsed_flags |= PUBKEY_FLAG_RFC6979;
	    else if (n == 5 && !memcmp (s, "eddsa", 5))
              {
                ctx->encoding = PUBKEY_ENC_RAW;
                parsed_flags |= PUBKEY_FLAG_EDDSA;
              }
            else if ( n == 3 && !memcmp (s, "raw", 3)
                      && ctx->encoding == PUBKEY_ENC_UNKNOWN)
              {
                ctx->encoding = PUBKEY_ENC_RAW;
                explicit_raw = 1;
              }
            else if ( n == 5 && !memcmp (s, "pkcs1", 5)
                      && ctx->encoding == PUBKEY_ENC_UNKNOWN)
              {
                ctx->encoding = PUBKEY_ENC_PKCS1;
                parsed_flags |= PUBKEY_FLAG_FIXEDLEN;
              }
            else if ( n == 4 && !memcmp (s, "oaep", 4)
                      && ctx->encoding == PUBKEY_ENC_UNKNOWN)
              {
                ctx->encoding = PUBKEY_ENC_OAEP;
                parsed_flags |= PUBKEY_FLAG_FIXEDLEN;
              }
            else if ( n == 3 && !memcmp (s, "pss", 3)
                      && ctx->encoding == PUBKEY_ENC_UNKNOWN)
              {
                ctx->encoding = PUBKEY_ENC_PSS;
                parsed_flags |= PUBKEY_FLAG_FIXEDLEN;
              }
	    else if (n == 11 && ! memcmp (s, "no-blinding", 11))
	      parsed_flags |= PUBKEY_FLAG_NO_BLINDING;
            else
              unknown_flag = 1;
          }
        gcry_sexp_release (lflags);
      }
  }

  if (ctx->encoding == PUBKEY_ENC_UNKNOWN)
    ctx->encoding = PUBKEY_ENC_RAW; /* default to raw */

  /* Get HASH or MPI */
  lhash = gcry_sexp_find_token (ldata, "hash", 0);
  lvalue = lhash? NULL : gcry_sexp_find_token (ldata, "value", 0);

  if (!(!lhash ^ !lvalue))
    rc = GPG_ERR_INV_OBJ; /* none or both given */
  else if (unknown_flag)
    rc = GPG_ERR_INV_FLAG;
  else if (ctx->encoding == PUBKEY_ENC_RAW
           && (parsed_flags & PUBKEY_FLAG_EDDSA))
    {
      /* Prepare for EdDSA.  */
      gcry_sexp_t list;
      void *value;
      size_t valuelen;

      if (!lvalue)
        {
          rc = GPG_ERR_INV_OBJ;
          goto leave;
        }
      /* Get HASH-ALGO. */
      list = gcry_sexp_find_token (ldata, "hash-algo", 0);
      if (list)
        {
          s = gcry_sexp_nth_data (list, 1, &n);
          if (!s)
            rc = GPG_ERR_NO_OBJ;
          else
            {
              ctx->hash_algo = get_hash_algo (s, n);
              if (!ctx->hash_algo)
                rc = GPG_ERR_DIGEST_ALGO;
            }
          gcry_sexp_release (list);
        }
      else
        rc = GPG_ERR_INV_OBJ;
      if (rc)
        goto leave;

      /* Get VALUE.  */
      value = gcry_sexp_nth_buffer (lvalue, 1, &valuelen);
      if (!value)
        {
          /* We assume that a zero length message is meant by
             "(value)".  This is commonly used by test vectors.  Note
             that S-expression do not allow zero length items. */
          valuelen = 0;
          value = gcry_malloc (1);
          if (!value)
            rc = gpg_err_code_from_syserror ();
        }
      else if ((valuelen * 8) < valuelen)
        {
          gcry_free (value);
          rc = GPG_ERR_TOO_LARGE;
        }
      if (rc)
        goto leave;

      /* Note that mpi_set_opaque takes ownership of VALUE.  */
      *ret_mpi = gcry_mpi_set_opaque (NULL, value, valuelen*8);
    }
  else if (ctx->encoding == PUBKEY_ENC_RAW && lhash
           && (explicit_raw || (parsed_flags & PUBKEY_FLAG_RFC6979)))
    {
      /* Raw encoding along with a hash element.  This is commonly
         used for DSA.  For better backward error compatibility we
         allow this only if either the rfc6979 flag has been given or
         the raw flags was explicitly given.  */
      if (gcry_sexp_length (lhash) != 3)
        rc = GPG_ERR_INV_OBJ;
      else if ( !(s=gcry_sexp_nth_data (lhash, 1, &n)) || !n )
        rc = GPG_ERR_INV_OBJ;
      else
        {
          void *value;
          size_t valuelen;

	  ctx->hash_algo = get_hash_algo (s, n);
          if (!ctx->hash_algo)
            rc = GPG_ERR_DIGEST_ALGO;
          else if (!(value=gcry_sexp_nth_buffer (lhash, 2, &valuelen)))
            rc = GPG_ERR_INV_OBJ;
          else if ((valuelen * 8) < valuelen)
            {
              gcry_free (value);
              rc = GPG_ERR_TOO_LARGE;
            }
          else
            *ret_mpi = gcry_mpi_set_opaque (NULL, value, valuelen*8);
        }
    }
  else if (ctx->encoding == PUBKEY_ENC_RAW && lvalue)
    {
      /* RFC6969 may only be used with the a hash value and not the
         MPI based value.  */
      if (parsed_flags & PUBKEY_FLAG_RFC6979)
        {
          rc = GPG_ERR_CONFLICT;
          goto leave;
        }

      /* Get the value */
      *ret_mpi = gcry_sexp_nth_mpi (lvalue, 1, GCRYMPI_FMT_USG);
      if (!*ret_mpi)
        rc = GPG_ERR_INV_OBJ;
    }
  else if (ctx->encoding == PUBKEY_ENC_PKCS1 && lvalue
	   && ctx->op == PUBKEY_OP_ENCRYPT)
    {
      const void * value;
      size_t valuelen;
      gcry_sexp_t list;
      void *random_override = NULL;
      size_t random_override_len = 0;

      if ( !(value=gcry_sexp_nth_data (lvalue, 1, &valuelen)) || !valuelen )
        rc = GPG_ERR_INV_OBJ;
      else
        {
          /* Get optional RANDOM-OVERRIDE.  */
          list = gcry_sexp_find_token (ldata, "random-override", 0);
          if (list)
            {
              s = gcry_sexp_nth_data (list, 1, &n);
              if (!s)
                rc = GPG_ERR_NO_OBJ;
              else if (n > 0)
                {
                  random_override = gcry_malloc (n);
                  if (!random_override)
                    rc = gpg_err_code_from_syserror ();
                  else
                    {
                      memcpy (random_override, s, n);
                      random_override_len = n;
                    }
                }
              gcry_sexp_release (list);
              if (rc)
                goto leave;
            }

          rc = _gcry_rsa_pkcs1_encode_for_enc (ret_mpi, ctx->nbits,
                                               value, valuelen,
                                               random_override,
                                               random_override_len);
          gcry_free (random_override);
        }
    }
  else if (ctx->encoding == PUBKEY_ENC_PKCS1 && lhash
	   && (ctx->op == PUBKEY_OP_SIGN || ctx->op == PUBKEY_OP_VERIFY))
    {
      if (gcry_sexp_length (lhash) != 3)
        rc = GPG_ERR_INV_OBJ;
      else if ( !(s=gcry_sexp_nth_data (lhash, 1, &n)) || !n )
        rc = GPG_ERR_INV_OBJ;
      else
        {
          const void * value;
          size_t valuelen;

	  ctx->hash_algo = get_hash_algo (s, n);

          if (!ctx->hash_algo)
            rc = GPG_ERR_DIGEST_ALGO;
          else if ( !(value=gcry_sexp_nth_data (lhash, 2, &valuelen))
                    || !valuelen )
            rc = GPG_ERR_INV_OBJ;
          else
	    rc = _gcry_rsa_pkcs1_encode_for_sig (ret_mpi, ctx->nbits,
                                                 value, valuelen,
                                                 ctx->hash_algo);
        }
    }
  else if (ctx->encoding == PUBKEY_ENC_OAEP && lvalue
	   && ctx->op == PUBKEY_OP_ENCRYPT)
    {
      const void * value;
      size_t valuelen;

      if ( !(value=gcry_sexp_nth_data (lvalue, 1, &valuelen)) || !valuelen )
	rc = GPG_ERR_INV_OBJ;
      else
	{
	  gcry_sexp_t list;
          void *random_override = NULL;
          size_t random_override_len = 0;

	  /* Get HASH-ALGO. */
	  list = gcry_sexp_find_token (ldata, "hash-algo", 0);
	  if (list)
	    {
	      s = gcry_sexp_nth_data (list, 1, &n);
	      if (!s)
		rc = GPG_ERR_NO_OBJ;
	      else
		{
		  ctx->hash_algo = get_hash_algo (s, n);
		  if (!ctx->hash_algo)
		    rc = GPG_ERR_DIGEST_ALGO;
		}
	      gcry_sexp_release (list);
	      if (rc)
		goto leave;
	    }

	  /* Get LABEL. */
	  list = gcry_sexp_find_token (ldata, "label", 0);
	  if (list)
	    {
	      s = gcry_sexp_nth_data (list, 1, &n);
	      if (!s)
		rc = GPG_ERR_NO_OBJ;
	      else if (n > 0)
		{
		  ctx->label = gcry_malloc (n);
		  if (!ctx->label)
		    rc = gpg_err_code_from_syserror ();
		  else
		    {
		      memcpy (ctx->label, s, n);
		      ctx->labellen = n;
		    }
		}
	      gcry_sexp_release (list);
	      if (rc)
		goto leave;
	    }
          /* Get optional RANDOM-OVERRIDE.  */
          list = gcry_sexp_find_token (ldata, "random-override", 0);
          if (list)
            {
              s = gcry_sexp_nth_data (list, 1, &n);
              if (!s)
                rc = GPG_ERR_NO_OBJ;
              else if (n > 0)
                {
                  random_override = gcry_malloc (n);
                  if (!random_override)
                    rc = gpg_err_code_from_syserror ();
                  else
                    {
                      memcpy (random_override, s, n);
                      random_override_len = n;
                    }
                }
              gcry_sexp_release (list);
              if (rc)
                goto leave;
            }

	  rc = _gcry_rsa_oaep_encode (ret_mpi, ctx->nbits, ctx->hash_algo,
                                      value, valuelen,
                                      ctx->label, ctx->labellen,
                                      random_override, random_override_len);

          gcry_free (random_override);
	}
    }
  else if (ctx->encoding == PUBKEY_ENC_PSS && lhash
	   && ctx->op == PUBKEY_OP_SIGN)
    {
      if (gcry_sexp_length (lhash) != 3)
        rc = GPG_ERR_INV_OBJ;
      else if ( !(s=gcry_sexp_nth_data (lhash, 1, &n)) || !n )
        rc = GPG_ERR_INV_OBJ;
      else
        {
          const void * value;
          size_t valuelen;
          void *random_override = NULL;
          size_t random_override_len = 0;

	  ctx->hash_algo = get_hash_algo (s, n);

          if (!ctx->hash_algo)
            rc = GPG_ERR_DIGEST_ALGO;
          else if ( !(value=gcry_sexp_nth_data (lhash, 2, &valuelen))
                    || !valuelen )
            rc = GPG_ERR_INV_OBJ;
          else
	    {
	      gcry_sexp_t list;

	      /* Get SALT-LENGTH. */
	      list = gcry_sexp_find_token (ldata, "salt-length", 0);
	      if (list)
		{
		  s = gcry_sexp_nth_data (list, 1, &n);
		  if (!s)
		    {
		      rc = GPG_ERR_NO_OBJ;
		      goto leave;
		    }
		  ctx->saltlen = (unsigned int)strtoul (s, NULL, 10);
		  gcry_sexp_release (list);
		}

              /* Get optional RANDOM-OVERRIDE.  */
              list = gcry_sexp_find_token (ldata, "random-override", 0);
              if (list)
                {
                  s = gcry_sexp_nth_data (list, 1, &n);
                  if (!s)
                    rc = GPG_ERR_NO_OBJ;
                  else if (n > 0)
                    {
                      random_override = gcry_malloc (n);
                      if (!random_override)
                        rc = gpg_err_code_from_syserror ();
                      else
                        {
                          memcpy (random_override, s, n);
                          random_override_len = n;
                        }
                    }
                  gcry_sexp_release (list);
                  if (rc)
                    goto leave;
                }

              /* Encode the data.  (NBITS-1 is due to 8.1.1, step 1.) */
	      rc = _gcry_rsa_pss_encode (ret_mpi, ctx->nbits - 1,
                                         ctx->hash_algo,
                                         value, valuelen, ctx->saltlen,
                                         random_override, random_override_len);

              gcry_free (random_override);
	    }
        }
    }
  else if (ctx->encoding == PUBKEY_ENC_PSS && lhash
	   && ctx->op == PUBKEY_OP_VERIFY)
    {
      if (gcry_sexp_length (lhash) != 3)
        rc = GPG_ERR_INV_OBJ;
      else if ( !(s=gcry_sexp_nth_data (lhash, 1, &n)) || !n )
        rc = GPG_ERR_INV_OBJ;
      else
        {
	  ctx->hash_algo = get_hash_algo (s, n);

          if (!ctx->hash_algo)
            rc = GPG_ERR_DIGEST_ALGO;
	  else
	    {
	      *ret_mpi = gcry_sexp_nth_mpi (lhash, 2, GCRYMPI_FMT_USG);
	      if (!*ret_mpi)
		rc = GPG_ERR_INV_OBJ;
	      ctx->verify_cmp = pss_verify_cmp;
	      ctx->verify_arg = *ret_mpi;
	    }
	}
    }
  else
    rc = GPG_ERR_CONFLICT;

 leave:
  gcry_sexp_release (ldata);
  gcry_sexp_release (lhash);
  gcry_sexp_release (lvalue);

  if (!rc)
    ctx->flags = parsed_flags;
  else
    {
      gcry_free (ctx->label);
      ctx->label = NULL;
    }

  return rc;
}

static void
init_encoding_ctx (struct pk_encoding_ctx *ctx, enum pk_operation op,
		   unsigned int nbits)
{
  ctx->op = op;
  ctx->nbits = nbits;
  ctx->encoding = PUBKEY_ENC_UNKNOWN;
  ctx->flags = 0;
  ctx->hash_algo = GCRY_MD_SHA1;
  ctx->label = NULL;
  ctx->labellen = 0;
  ctx->saltlen = 20;
  ctx->verify_cmp = NULL;
  ctx->verify_arg = NULL;
}


/*
   Do a PK encrypt operation

   Caller has to provide a public key as the SEXP pkey and data as a
   SEXP with just one MPI in it. Alternatively S_DATA might be a
   complex S-Expression, similar to the one used for signature
   verification.  This provides a flag which allows to handle PKCS#1
   block type 2 padding.  The function returns a sexp which may be
   passed to to pk_decrypt.

   Returns: 0 or an errorcode.

   s_data = See comment for sexp_data_to_mpi
   s_pkey = <key-as-defined-in-sexp_to_key>
   r_ciph = (enc-val
               (<algo>
                 (<param_name1> <mpi>)
                 ...
                 (<param_namen> <mpi>)
               ))

*/
gcry_error_t
gcry_pk_encrypt (gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t s_pkey)
{
  gcry_err_code_t rc;
  gcry_mpi_t *pkey = NULL;
  gcry_mpi_t data = NULL;
  struct pk_encoding_ctx ctx;
  gcry_pk_spec_t *spec = NULL;
  int i;

  *r_ciph = NULL;

  /* Get the key. */
  rc = sexp_to_key (s_pkey, 0, GCRY_PK_USAGE_ENCR, NULL, &pkey, &spec, NULL);
  if (rc)
    goto leave;

  gcry_assert (spec);

  /* Get the stuff we want to encrypt. */
  init_encoding_ctx (&ctx, PUBKEY_OP_ENCRYPT, gcry_pk_get_nbits (s_pkey));
  rc = sexp_data_to_mpi (s_data, &data, &ctx);
  if (rc)
    goto leave;

  /* In fips mode DBG_CIPHER will never evaluate to true but as an
     extra failsafe protection we explicitly test for fips mode
     here. */
  if (DBG_CIPHER && !fips_mode ())
    {
      log_debug ("pubkey_encrypt: algo=%d\n", spec->algo);
      for(i = 0; i < pubkey_get_npkey (spec->algo); i++)
	log_mpidump ("  pkey", pkey[i]);
      log_mpidump ("  data", data);
    }

  if (spec->encrypt)
    rc = spec->encrypt (spec->algo, r_ciph, data, pkey, ctx.flags);
  else
    rc = GPG_ERR_NOT_IMPLEMENTED;


  /* if (DBG_CIPHER && !fips_mode ()) */
  /*   { */
  /*     for (i = 0; i < pubkey_get_nenc (spec->algo); i++) */
  /*       log_mpidump ("  encr", ciph[i]); */
  /*   } */

 leave:
  mpi_free (data);
  if (pkey)
    {
      release_mpi_array (pkey);
      gcry_free (pkey);
    }

  gcry_free (ctx.label);

  return gcry_error (rc);
}


/*
   Do a PK decrypt operation

   Caller has to provide a secret key as the SEXP skey and data in a
   format as created by gcry_pk_encrypt.  For historic reasons the
   function returns simply an MPI as an S-expression part; this is
   deprecated and the new method should be used which returns a real
   S-expressionl this is selected by adding at least an empty flags
   list to S_DATA.

   Returns: 0 or an errorcode.

   s_data = (enc-val
              [(flags [raw, pkcs1, oaep])]
              (<algo>
                (<param_name1> <mpi>)
                ...
                (<param_namen> <mpi>)
              ))
   s_skey = <key-as-defined-in-sexp_to_key>
   r_plain= Either an incomplete S-expression without the parentheses
            or if the flags list is used (even if empty) a real S-expression:
            (value PLAIN).  In raw mode (or no flags given) the returned value
            is to be interpreted as a signed MPI, thus it may have an extra
            leading zero octet even if not included in the original data.
            With pkcs1 or oaep decoding enabled the returned value is a
            verbatim octet string.
 */
gcry_error_t
gcry_pk_decrypt (gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t s_skey)
{
  gcry_err_code_t rc;
  gcry_mpi_t *skey = NULL;
  gcry_mpi_t *data = NULL;
  gcry_mpi_t plain = NULL;
  unsigned char *unpad = NULL;
  size_t unpadlen = 0;
  int i;
  int modern, flags;
  struct pk_encoding_ctx ctx;
  gcry_pk_spec_t *spec = NULL;
  gcry_pk_spec_t *spec_enc = NULL;

  *r_plain = NULL;
  ctx.label = NULL;

  rc = sexp_to_key (s_skey, 1, GCRY_PK_USAGE_ENCR, NULL,
                    &skey, &spec, NULL);
  if (rc)
    goto leave;

  init_encoding_ctx (&ctx, PUBKEY_OP_DECRYPT, gcry_pk_get_nbits (s_skey));
  rc = sexp_to_enc (s_data, &data, &spec_enc, &modern, &flags, &ctx);
  if (rc)
    goto leave;

  if (spec->algo != spec_enc->algo)
    {
      rc = GPG_ERR_CONFLICT; /* Key algo does not match data algo. */
      goto leave;
    }

  if (DBG_CIPHER && !fips_mode ())
    {
      log_debug ("gcry_pk_decrypt: algo=%d\n", spec->algo);
      for(i = 0; i < pubkey_get_nskey (spec->algo); i++)
	log_mpidump ("  skey", skey[i]);
      for(i = 0; i < pubkey_get_nenc (spec->algo); i++)
	log_mpidump ("  data", data[i]);
    }

  if (spec->decrypt)
    rc = spec->decrypt (spec->algo, &plain, data, skey, flags);
  else
    rc = GPG_ERR_NOT_IMPLEMENTED;
  if (rc)
    goto leave;

  if (DBG_CIPHER && !fips_mode ())
    log_mpidump (" plain", plain);

  /* Do un-padding if necessary. */
  switch (ctx.encoding)
    {
    case PUBKEY_ENC_PKCS1:
      rc = _gcry_rsa_pkcs1_decode_for_enc (&unpad, &unpadlen,
                                           gcry_pk_get_nbits (s_skey),
                                           plain);
      mpi_free (plain);
      plain = NULL;
      if (!rc)
        rc = gcry_err_code (gcry_sexp_build (r_plain, NULL, "(value %b)",
                                             (int)unpadlen, unpad));
      break;

    case PUBKEY_ENC_OAEP:
      rc = _gcry_rsa_oaep_decode (&unpad, &unpadlen,
                                  gcry_pk_get_nbits (s_skey), ctx.hash_algo,
                                  plain, ctx.label, ctx.labellen);
      mpi_free (plain);
      plain = NULL;
      if (!rc)
        rc = gcry_err_code (gcry_sexp_build (r_plain, NULL, "(value %b)",
                                             (int)unpadlen, unpad));
      break;

    default:
      /* Raw format.  For backward compatibility we need to assume a
         signed mpi by using the sexp format string "%m".  */
      rc = gcry_err_code (gcry_sexp_build
                          (r_plain, NULL, modern? "(value %m)" : "%m", plain));
      break;
    }

 leave:
  gcry_free (unpad);

  if (skey)
    {
      release_mpi_array (skey);
      gcry_free (skey);
    }

  mpi_free (plain);

  if (data)
    {
      release_mpi_array (data);
      gcry_free (data);
    }

  gcry_free (ctx.label);

  return gcry_error (rc);
}



/*
   Create a signature.

   Caller has to provide a secret key as the SEXP skey and data
   expressed as a SEXP list hash with only one element which should
   instantly be available as a MPI. Alternatively the structure given
   below may be used for S_HASH, it provides the abiliy to pass flags
   to the operation; the flags defined by now are "pkcs1" which does
   PKCS#1 block type 1 style padding and "pss" for PSS encoding.

   Returns: 0 or an errorcode.
            In case of 0 the function returns a new SEXP with the
            signature value; the structure of this signature depends on the
            other arguments but is always suitable to be passed to
            gcry_pk_verify

   s_hash = See comment for sexp_data_to_mpi

   s_skey = <key-as-defined-in-sexp_to_key>
   r_sig  = (sig-val
              (<algo>
                (<param_name1> <mpi>)
                ...
                (<param_namen> <mpi>))
             [(hash algo)])

  Note that (hash algo) in R_SIG is not used.
*/
gcry_error_t
gcry_pk_sign (gcry_sexp_t *r_sig, gcry_sexp_t s_hash, gcry_sexp_t s_skey)
{
  gcry_mpi_t *skey = NULL;
  gcry_mpi_t hash = NULL;
  gcry_pk_spec_t *spec = NULL;
  struct pk_encoding_ctx ctx;
  int i;
  int is_ecc;
  gcry_err_code_t rc;

  *r_sig = NULL;

  rc = sexp_to_key (s_skey, 1, GCRY_PK_USAGE_SIGN, NULL,
                    &skey, &spec, &is_ecc);
  if (rc)
    goto leave;

  gcry_assert (spec);

  /* Get the stuff we want to sign.  Note that pk_get_nbits does also
     work on a private key.  We don't need the number of bits for ECC
     here, thus set it to 0 so that we don't need to parse it.  */
  init_encoding_ctx (&ctx, PUBKEY_OP_SIGN,
                     is_ecc? 0 : gcry_pk_get_nbits (s_skey));
  rc = sexp_data_to_mpi (s_hash, &hash, &ctx);
  if (rc)
    goto leave;

  if (DBG_CIPHER && !fips_mode ())
    {
      log_debug ("gcry_pk_sign: algo=%d\n", spec->algo);
      for(i = 0; i < pubkey_get_nskey (spec->algo); i++)
        log_mpidump ("  skey", skey[i]);
      log_mpidump("  data", hash);
    }

  if (spec->sign)
    rc = spec->sign (spec->algo, r_sig, hash, skey, ctx.flags, ctx.hash_algo);
  else
    rc = GPG_ERR_NOT_IMPLEMENTED;

  if (rc)
    goto leave;

  /* Fixme: To print the result we need to print an sexp.  */
  /* if (!rc && DBG_CIPHER && !fips_mode ()) */
  /*   for (i = 0; i < pubkey_get_nsig (algo); i++) */
  /*     log_mpidump ("   sig", resarr[i]); */

 leave:
  if (skey)
    {
      if (is_ecc)
        /* Q is optional and may be NULL, while there is D after Q.  */
        for (i = 0; i < 7; i++)
          {
            if (skey[i])
              mpi_free (skey[i]);
            skey[i] = NULL;
          }
      else
        release_mpi_array (skey);
      gcry_free (skey);
    }

  mpi_free (hash);

  return gcry_error (rc);
}


/*
   Verify a signature.

   Caller has to supply the public key pkey, the signature sig and his
   hashvalue data.  Public key has to be a standard public key given
   as an S-Exp, sig is a S-Exp as returned from gcry_pk_sign and data
   must be an S-Exp like the one in sign too.  */
gcry_error_t
gcry_pk_verify (gcry_sexp_t s_sig, gcry_sexp_t s_hash, gcry_sexp_t s_pkey)
{
  gcry_err_code_t rc;
  gcry_pk_spec_t *spec = NULL;
  gcry_pk_spec_t *spec_sig = NULL;
  gcry_mpi_t *pkey = NULL;
  gcry_mpi_t hash = NULL;
  gcry_mpi_t *sig = NULL;
  struct pk_encoding_ctx ctx;
  int i;

  rc = sexp_to_key (s_pkey, 0, GCRY_PK_USAGE_SIGN, NULL,
                    &pkey, &spec, NULL);
  if (rc)
    goto leave;

  /* Get the stuff we want to verify. */
  init_encoding_ctx (&ctx, PUBKEY_OP_VERIFY, gcry_pk_get_nbits (s_pkey));
  rc = sexp_data_to_mpi (s_hash, &hash, &ctx);
  if (rc)
    goto leave;

  /* Get the signature.  */
  rc = sexp_to_sig (s_sig, &sig, &spec_sig,
                    !!(ctx.flags & PUBKEY_FLAG_EDDSA));
  if (rc)
    goto leave;
  /* Fixme: Check that the algorithm of S_SIG is compatible to the one
     of S_PKEY.  */

  if (spec->algo != spec_sig->algo)
    {
      rc = GPG_ERR_CONFLICT;
      goto leave;
    }

  if (DBG_CIPHER && !fips_mode ())
    {
      log_debug ("gcry_pk_verify: algo=%d\n", spec->algo);
      for (i = 0; i < pubkey_get_npkey (spec->algo); i++)
        log_mpidump ("  pkey", pkey[i]);
      for (i = 0; i < pubkey_get_nsig (spec->algo); i++)
        log_mpidump ("   sig", sig[i]);
      log_mpidump ("  hash", hash);
      }

  if (spec->verify)
    rc = spec->verify (spec->algo, hash, sig, pkey,
                       ctx.verify_cmp, &ctx, ctx.flags, ctx.hash_algo);
  else
    rc = GPG_ERR_NOT_IMPLEMENTED;


 leave:
  if (pkey)
    {
      release_mpi_array (pkey);
      gcry_free (pkey);
    }
  if (sig)
    {
      release_mpi_array (sig);
      gcry_free (sig);
    }
  if (hash)
    mpi_free (hash);

  return gcry_error (rc);
}


/*
   Test a key.

   This may be used either for a public or a secret key to see whether
   the internal structure is okay.

   Returns: 0 or an errorcode.

   s_key = <key-as-defined-in-sexp_to_key> */
gcry_error_t
gcry_pk_testkey (gcry_sexp_t s_key)
{
  gcry_pk_spec_t *spec = NULL;
  gcry_mpi_t *key = NULL;
  gcry_err_code_t rc;

  /* Note we currently support only secret key checking. */
  rc = sexp_to_key (s_key, 1, 0, NULL, &key, &spec, NULL);
  if (!rc)
    {
      rc = pubkey_check_secret_key (spec->algo, key);
      release_mpi_array (key);
      gcry_free (key);
    }
  return gcry_error (rc);
}


/*
  Create a public key pair and return it in r_key.
  How the key is created depends on s_parms:
  (genkey
   (algo
     (parameter_name_1 ....)
      ....
     (parameter_name_n ....)
  ))
  The key is returned in a format depending on the
  algorithm. Both, private and secret keys are returned
  and optionally some additional informatin.
  For elgamal we return this structure:
  (key-data
   (public-key
     (elg
 	(p <mpi>)
 	(g <mpi>)
 	(y <mpi>)
     )
   )
   (private-key
     (elg
 	(p <mpi>)
 	(g <mpi>)
 	(y <mpi>)
 	(x <mpi>)
     )
   )
   (misc-key-info
      (pm1-factors n1 n2 ... nn)
   ))
 */
gcry_error_t
gcry_pk_genkey (gcry_sexp_t *r_key, gcry_sexp_t s_parms)
{
  gcry_pk_spec_t *spec = NULL;
  gcry_sexp_t list = NULL;
  gcry_sexp_t l2 = NULL;
  gcry_sexp_t l3 = NULL;
  char *name = NULL;
  size_t n;
  gcry_err_code_t rc = GPG_ERR_NO_ERROR;
  unsigned int nbits = 0;
  unsigned long use_e = 0;

  *r_key = NULL;

  list = gcry_sexp_find_token (s_parms, "genkey", 0);
  if (!list)
    {
      rc = GPG_ERR_INV_OBJ; /* Does not contain genkey data. */
      goto leave;
    }

  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  l2 = NULL;
  if (! list)
    {
      rc = GPG_ERR_NO_OBJ; /* No cdr for the genkey. */
      goto leave;
    }

  name = _gcry_sexp_nth_string (list, 0);
  if (!name)
    {
      rc = GPG_ERR_INV_OBJ; /* Algo string missing.  */
      goto leave;
    }

  spec = spec_from_name (name);
  gcry_free (name);
  name = NULL;
  if (!spec)
    {
      rc = GPG_ERR_PUBKEY_ALGO; /* Unknown algorithm.  */
      goto leave;
    }

  /* Handle the optional rsa-use-e element.  Actually this belong into
     the algorithm module but we have this parameter in the public
     module API, so we need to parse it right here.  */
  l2 = gcry_sexp_find_token (list, "rsa-use-e", 0);
  if (l2)
    {
      char buf[50];
      const char *s;

      s = gcry_sexp_nth_data (l2, 1, &n);
      if ( !s || n >= DIM (buf) - 1 )
        {
          rc = GPG_ERR_INV_OBJ; /* No value or value too large.  */
          goto leave;
        }
      memcpy (buf, s, n);
      buf[n] = 0;
      use_e = strtoul (buf, NULL, 0);
      gcry_sexp_release (l2);
      l2 = NULL;
    }
  else
    use_e = 65537; /* Not given, use the value generated by old versions. */


  /* Get the "nbits" parameter.  */
  l2 = gcry_sexp_find_token (list, "nbits", 0);
  if (l2)
    {
      char buf[50];
      const char *s;

      s = gcry_sexp_nth_data (l2, 1, &n);
      if (!s || n >= DIM (buf) - 1 )
        {
          rc = GPG_ERR_INV_OBJ; /* NBITS given without a cdr.  */
          goto leave;
        }
      memcpy (buf, s, n);
      buf[n] = 0;
      nbits = (unsigned int)strtoul (buf, NULL, 0);
      gcry_sexp_release (l2); l2 = NULL;
    }
  else
    nbits = 0;

  if (spec->generate)
    rc = spec->generate (spec->algo, nbits, use_e, list, r_key);
  else
    rc = GPG_ERR_NOT_IMPLEMENTED;

 leave:
  gcry_sexp_release (list); list = NULL;
  gcry_free (name);
  gcry_sexp_release (l3);
  gcry_sexp_release (l2);
  gcry_sexp_release (list);

  return gcry_error (rc);
}


/*
   Get the number of nbits from the public key.

   Hmmm: Should we have really this function or is it better to have a
   more general function to retrieve different properties of the key?  */
unsigned int
gcry_pk_get_nbits (gcry_sexp_t key)
{
  gcry_pk_spec_t *spec;
  gcry_mpi_t *keyarr = NULL;
  unsigned int nbits = 0;
  gcry_err_code_t rc;

  /* FIXME: Parsing KEY is often too much overhead.  For example for
     ECC we would only need to look at P and stop parsing right
     away.  */

  rc = sexp_to_key (key, 0, 0, NULL, &keyarr, &spec, NULL);
  if (rc == GPG_ERR_INV_OBJ)
    rc = sexp_to_key (key, 1, 0, NULL, &keyarr, &spec, NULL);
  if (rc)
    return 0; /* Error - 0 is a suitable indication for that. */

  nbits = spec->get_nbits (spec->algo, keyarr);

  release_mpi_array (keyarr);
  gcry_free (keyarr);

  return nbits;
}


/* Return the so called KEYGRIP which is the SHA-1 hash of the public
   key parameters expressed in a way depending on the algorithm.

   ARRAY must either be 20 bytes long or NULL; in the latter case a
   newly allocated array of that size is returned, otherwise ARRAY or
   NULL is returned to indicate an error which is most likely an
   unknown algorithm.  The function accepts public or secret keys. */
unsigned char *
gcry_pk_get_keygrip (gcry_sexp_t key, unsigned char *array)
{
  gcry_sexp_t list = NULL;
  gcry_sexp_t l2 = NULL;
  gcry_pk_spec_t *spec = NULL;
  const char *s;
  char *name = NULL;
  int idx;
  const char *elems;
  gcry_md_hd_t md = NULL;
  int okay = 0;

  /* Check that the first element is valid. */
  list = gcry_sexp_find_token (key, "public-key", 0);
  if (! list)
    list = gcry_sexp_find_token (key, "private-key", 0);
  if (! list)
    list = gcry_sexp_find_token (key, "protected-private-key", 0);
  if (! list)
    list = gcry_sexp_find_token (key, "shadowed-private-key", 0);
  if (! list)
    return NULL; /* No public- or private-key object. */

  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  l2 = NULL;

  name = _gcry_sexp_nth_string (list, 0);
  if (!name)
    goto fail; /* Invalid structure of object. */

  spec = spec_from_name (name);
  if (!spec)
    goto fail; /* Unknown algorithm.  */

  elems = spec->elements_grip;
  if (!elems)
    goto fail; /* No grip parameter.  */

  if (gcry_md_open (&md, GCRY_MD_SHA1, 0))
    goto fail;

  if (spec->comp_keygrip)
    {
      /* Module specific method to compute a keygrip.  */
      if (spec->comp_keygrip (md, list))
        goto fail;
    }
  else
    {
      /* Generic method to compute a keygrip.  */
      for (idx = 0, s = elems; *s; s++, idx++)
        {
          const char *data;
          size_t datalen;
          char buf[30];

          l2 = gcry_sexp_find_token (list, s, 1);
          if (! l2)
            goto fail;
          data = gcry_sexp_nth_data (l2, 1, &datalen);
          if (! data)
            goto fail;

          snprintf (buf, sizeof buf, "(1:%c%u:", *s, (unsigned int)datalen);
          gcry_md_write (md, buf, strlen (buf));
          gcry_md_write (md, data, datalen);
          gcry_sexp_release (l2);
          l2 = NULL;
          gcry_md_write (md, ")", 1);
        }
    }

  if (!array)
    {
      array = gcry_malloc (20);
      if (! array)
        goto fail;
    }

  memcpy (array, gcry_md_read (md, GCRY_MD_SHA1), 20);
  okay = 1;

 fail:
  gcry_free (name);
  gcry_sexp_release (l2);
  gcry_md_close (md);
  gcry_sexp_release (list);
  return okay? array : NULL;
}



const char *
gcry_pk_get_curve (gcry_sexp_t key, int iterator, unsigned int *r_nbits)
{
  gcry_mpi_t *pkey = NULL;
  gcry_sexp_t list = NULL;
  gcry_sexp_t l2;
  char *name = NULL;
  const char *result = NULL;
  int want_private = 1;
  gcry_pk_spec_t *spec = NULL;

  if (r_nbits)
    *r_nbits = 0;

  if (key)
    {
      iterator = 0;

      /* Check that the first element is valid. */
      list = gcry_sexp_find_token (key, "public-key", 0);
      if (list)
        want_private = 0;
      if (!list)
        list = gcry_sexp_find_token (key, "private-key", 0);
      if (!list)
        return NULL; /* No public- or private-key object. */

      l2 = gcry_sexp_cadr (list);
      gcry_sexp_release (list);
      list = l2;
      l2 = NULL;

      name = _gcry_sexp_nth_string (list, 0);
      if (!name)
        goto leave; /* Invalid structure of object. */

      /* Get the key.  We pass the names of the parameters for
         override_elems; this allows to call this function without the
         actual public key parameter.  */
      if (sexp_to_key (key, want_private, 0, "pabgn", &pkey, &spec, NULL))
        goto leave;
    }
  else
    {
      spec = spec_from_name ("ecc");
      if (!spec)
        goto leave;
    }

  if (!spec || !spec->get_curve)
    goto leave;

  result = spec->get_curve (pkey, iterator, r_nbits);

 leave:
  if (pkey)
    {
      release_mpi_array (pkey);
      gcry_free (pkey);
    }
  gcry_free (name);
  gcry_sexp_release (list);
  return result;
}



gcry_sexp_t
gcry_pk_get_param (int algo, const char *name)
{
  gcry_sexp_t result = NULL;
  gcry_pk_spec_t *spec = NULL;

  if (algo != GCRY_PK_ECDSA && algo != GCRY_PK_ECDH)
    return NULL;

  spec = spec_from_name ("ecc");
  if (spec)
    {
      if (spec && spec->get_curve_param)
        result = spec->get_curve_param (name);
    }
  return result;
}



gcry_error_t
gcry_pk_ctl (int cmd, void *buffer, size_t buflen)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  switch (cmd)
    {
    case GCRYCTL_DISABLE_ALGO:
      /* This one expects a buffer pointing to an integer with the
         algo number.  */
      if ((! buffer) || (buflen != sizeof (int)))
	err = GPG_ERR_INV_ARG;
      else
	disable_pubkey_algo (*((int *) buffer));
      break;

    default:
      err = GPG_ERR_INV_OP;
    }

  return gcry_error (err);
}


/* Return information about the given algorithm

   WHAT selects the kind of information returned:

    GCRYCTL_TEST_ALGO:
        Returns 0 when the specified algorithm is available for use.
        Buffer must be NULL, nbytes  may have the address of a variable
        with the required usage of the algorithm. It may be 0 for don't
        care or a combination of the GCRY_PK_USAGE_xxx flags;

    GCRYCTL_GET_ALGO_USAGE:
        Return the usage flags for the given algo.  An invalid algo
        returns 0.  Disabled algos are ignored here because we
        only want to know whether the algo is at all capable of
        the usage.

   Note: Because this function is in most cases used to return an
   integer value, we can make it easier for the caller to just look at
   the return value.  The caller will in all cases consult the value
   and thereby detecting whether a error occurred or not (i.e. while
   checking the block size) */
gcry_error_t
gcry_pk_algo_info (int algorithm, int what, void *buffer, size_t *nbytes)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  switch (what)
    {
    case GCRYCTL_TEST_ALGO:
      {
	int use = nbytes ? *nbytes : 0;
	if (buffer)
	  err = GPG_ERR_INV_ARG;
	else if (check_pubkey_algo (algorithm, use))
	  err = GPG_ERR_PUBKEY_ALGO;
	break;
      }

    case GCRYCTL_GET_ALGO_USAGE:
      {
	gcry_pk_spec_t *spec;

	spec = spec_from_algo (algorithm);
        *nbytes = spec? spec->use : 0;
	break;
      }

    case GCRYCTL_GET_ALGO_NPKEY:
      {
	/* FIXME?  */
	int npkey = pubkey_get_npkey (algorithm);
	*nbytes = npkey;
	break;
      }
    case GCRYCTL_GET_ALGO_NSKEY:
      {
	/* FIXME?  */
	int nskey = pubkey_get_nskey (algorithm);
	*nbytes = nskey;
	break;
      }
    case GCRYCTL_GET_ALGO_NSIGN:
      {
	/* FIXME?  */
	int nsign = pubkey_get_nsig (algorithm);
	*nbytes = nsign;
	break;
      }
    case GCRYCTL_GET_ALGO_NENCR:
      {
	/* FIXME?  */
	int nencr = pubkey_get_nenc (algorithm);
	*nbytes = nencr;
	break;
      }

    default:
      err = GPG_ERR_INV_OP;
    }

  return gcry_error (err);
}


/* Return an S-expression representing the context CTX.  Depending on
   the state of that context, the S-expression may either be a public
   key, a private key or any other object used with public key
   operations.  On success a new S-expression is stored at R_SEXP and
   0 is returned, on error NULL is store there and an error code is
   returned.  MODE is either 0 or one of the GCRY_PK_GET_xxx values.

   As of now it only support certain ECC operations because a context
   object is right now only defined for ECC.  Over time this function
   will be extended to cover more algorithms.  Note also that the name
   of the function is gcry_pubkey_xxx and not gcry_pk_xxx.  The idea
   is that we will eventually provide variants of the existing
   gcry_pk_xxx functions which will take a context parameter.   */
gcry_err_code_t
_gcry_pubkey_get_sexp (gcry_sexp_t *r_sexp, int mode, gcry_ctx_t ctx)
{
  mpi_ec_t ec;

  if (!r_sexp)
    return GPG_ERR_INV_VALUE;
  *r_sexp = NULL;
  switch (mode)
    {
    case 0:
    case GCRY_PK_GET_PUBKEY:
    case GCRY_PK_GET_SECKEY:
      break;
    default:
      return GPG_ERR_INV_VALUE;
    }
  if (!ctx)
    return GPG_ERR_NO_CRYPT_CTX;

  ec = _gcry_ctx_find_pointer (ctx, CONTEXT_TYPE_EC);
  if (ec)
    return _gcry_pk_ecc_get_sexp (r_sexp, mode, ec);

  return GPG_ERR_WRONG_CRYPT_CTX;
}



/* Explicitly initialize this module.  */
gcry_err_code_t
_gcry_pk_init (void)
{
  return 0;
}


/* Run the selftests for pubkey algorithm ALGO with optional reporting
   function REPORT.  */
gpg_error_t
_gcry_pk_selftest (int algo, int extended, selftest_report_func_t report)
{
  gcry_err_code_t ec;
  gcry_pk_spec_t *spec = spec_from_algo (algo);

  if (spec && spec->selftest)
    ec = spec->selftest (algo, extended, report);
  else
    {
      ec = GPG_ERR_PUBKEY_ALGO;
      if (report)
        report ("pubkey", algo, "module",
                spec && !spec->flags.disabled?
                "no selftest available" :
                spec? "algorithm disabled" :
                "algorithm not found");
    }

  return gpg_error (ec);
}
