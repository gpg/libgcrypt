/* pubkey.c - S-Expression based  interface for asymmetric cryptography.
   Copyright (C) 1998, 1999, 2000, 2002, 2003 Free Software Foundation, Inc.
 
   This file is part of Libgcrypt.
  
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
  
   Libgcrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

/* Note: This interface was rewritten to act as a wrapper-interface
   for the new gcry_ac_* interface.  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "ath.h"



/* Types of cryptographic S-Expressions...  */
typedef enum
  {
    PK_SEXP_TYPE_KEY_SECRET,
    PK_SEXP_TYPE_KEY_PUBLIC,
    PK_SEXP_TYPE_ENCRYPTION,
    PK_SEXP_TYPE_SIGNATURE,
 }
pk_sexp_type_t;

/* ... and their corresponding properties.  */
static struct
{
  const char *identifier;	/* String identifier.  */
} pk_sexp_types[] =
  {
    { "private-key" },
    { "public-key"  },
    { "enc-val"     },
    { "sig-val"     },
    { NULL,         }
  };

typedef enum
  {
    PK_KEY_TYPE_ANY,
    PK_KEY_TYPE_PUBLIC,
    PK_KEY_TYPE_SECRET,
  }
pk_key_type_t;




/* Flags for S-Expressions...  */
#define PK_SEXP_FLAG_RAW         (1 << 0)
#define PK_SEXP_FLAG_PKCS1_V1_5  (1 << 1)
#define PK_SEXP_FLAG_NO_BLINDING (1 << 2)

/* ... and their corresponding properties.  */
static struct
{
  unsigned int flag;		/* Numeric flag.  */
  const char *identifier;	/* String identifier.  */
} pk_sexp_flags[] =
  {
    { PK_SEXP_FLAG_RAW,         "raw"         },
    { PK_SEXP_FLAG_PKCS1_V1_5,  "pkcs1"       },
    { PK_SEXP_FLAG_NO_BLINDING, "no-blinding" },
    { 0,                        NULL          }
  };

/* General flags specifying modes of operation.  */

/* `Modern' S-Expressions are used.  */
#define PK_FLAG_MODERN          (1 << 0)



/* Extract an unsigned number that is expected in the S-Expression
   SEXP at position IDX.  */
static gcry_err_code_t
sexp_nth_number (gcry_sexp_t sexp, int idx, unsigned long int *number)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned long int number_new = 0;
  const char *data = NULL;
  size_t data_length = 0;

  data = gcry_sexp_nth_data (sexp, idx, &data_length);
  if (! data)
    err = GPG_ERR_INV_OBJ;
  else
    {
      char *buf = gcry_malloc (data_length + 1);

      if (! buf)
	err = GPG_ERR_INTERNAL;	/* FIXME!  */
      else
	{
	  memcpy (buf, data, data_length);
	  buf[data_length] = 0;
	  number_new = (unsigned int) strtoul (buf, NULL, 0);
	  gcry_free (buf);
	}
    }

  if (! err)
    *number = number_new;
  
  return err;
}

static gcry_err_code_t
sexp_extract_flags (gcry_sexp_t flags_sexp, unsigned int *flags)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned int flags_sexp_length = 0;
  unsigned int flags_new = 0;
  const char *identifier = NULL;
  size_t identifier_length = 0;
  unsigned int i = 0, j = 0;

  flags_sexp_length = gcry_sexp_length (flags_sexp);
  for (i = 1; (i < flags_sexp_length) && (! err); i++)
    {
      identifier = gcry_sexp_nth_data (flags_sexp, i, &identifier_length);
      if (identifier)
	{
	  /* Iterate through list of known flags.  */
	  for (j = 0; pk_sexp_flags[j].identifier; j++)
	    if ((identifier_length == strlen (pk_sexp_flags[j].identifier))
		&& (! memcmp (identifier, pk_sexp_flags[j].identifier,
			      identifier_length)))
	      {
		flags_new |= pk_sexp_flags[j].flag;
		break;
	      }
	  
	  if (! pk_sexp_flags[j].identifier)
	    /* Flag not found.  */
	    err = GPG_ERR_INV_FLAG;
	}
    }

  if (! err)
    *flags = flags_new;

  return err;
}


/* Extract the MPI values from the S-Expression contained in SEXP that
   has to be of type TYPE into a newly allocated array that is to be
   stored in RETARRAY; the flags contained in the S-Expression are
   stored in SEXP_FLAGS; general flags specifying the mode of
   operation are stored in FLAGS.  A new handle for the according
   algorithm is stored in HANDLE, addotinally the algorithm
   information block is stored in ALGORITHM_INFO_BLOCK.  */
static gcry_err_code_t
sexp_extract_std (gcry_sexp_t sexp, pk_sexp_type_t type, gcry_ac_data_t *data,
		  unsigned int *sexp_flags, unsigned int *flags,
		  gcry_ac_handle_t *handle)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle_new = NULL;
  gcry_ac_data_t data_new = NULL;
  unsigned int sexp_flags_parsed = 0;
  unsigned int flags_parsed = 0;
  gcry_sexp_t list2 = NULL;
  gcry_sexp_t list = NULL;
  const char *identifier = NULL;
  size_t identifier_length = 0;
  gcry_ac_id_t algorithm_id = 0;
  unsigned int i = 0;

  /* Check that the first element is valid.  */
  list = gcry_sexp_find_token (sexp, pk_sexp_types[type].identifier, 0);
  if (! list)
    err = GPG_ERR_INV_OBJ;
  
  if (! err)
    {
      /* Extract inner list.  */
      list2 = gcry_sexp_cadr (list);
      if (! list2)
 	err = GPG_ERR_NO_OBJ;
    }

  if (! err)
    {
      /* Extract identifier of inner list.  */
      identifier = gcry_sexp_nth_data (list2, 0, &identifier_length);
      if (! identifier)
	err = GPG_ERR_INV_OBJ;
    }

  if (! err)
    {
      if ((identifier_length == 5) && (! memcmp (identifier, "flags", 5)))
	{
	  /* Seems to be a `modern' S-Expression.  */
	  flags_parsed |= PK_FLAG_MODERN;
	  err = sexp_extract_flags (list2, &sexp_flags_parsed);

	  if (! err)
	    {
	      /* Fetch the next S-Expression.  */
	      gcry_sexp_release (list2);
	      list2 = gcry_sexp_nth (list, 2);
	      if (! list2)
		err = GPG_ERR_INV_OBJ;
	    }
      
	  if (! err)
	    /* Extract identifier.  */
	    identifier = gcry_sexp_nth_data (list2, 0, &identifier_length);
	}
    }

  if (! err)
    {
      /* Convert identifier into an algorithm ID.  */
      char *name_terminated;

      name_terminated = gcry_xmalloc (identifier_length + 1);
      strncpy (name_terminated, identifier, identifier_length);
      name_terminated[identifier_length] = 0;

      err = _gcry_ac_name_to_id (name_terminated, &algorithm_id);

      free (name_terminated);
    }

  if (! err)
    {
      if (*handle)
	{
	  /* There's already an according handle, therefore we check
	     wether the new algorithm ID matches the one of the
	     already opened handled. */

	  gcry_ac_id_t id;

	  _gcry_ac_info_get (*handle, &id, NULL);
	  if (id != algorithm_id)
	    err = GPG_ERR_CONFLICT;
	}
      else
	{
	  /* Create new handle.  */
	  err = _gcry_ac_open (&handle_new, algorithm_id, 0);
	}
    }
  
  if (! err)
    /* Allocate data set for MPIs.  */
    err = _gcry_ac_data_new (&data_new);

  if (! err)
    {
      /* Extract MPI values.  */

      gcry_sexp_t elem_list = NULL;
      gcry_sexp_t data_list = NULL;
      unsigned int data_list_n = 0;
      size_t tmp_data_length = 0;
      gcry_mpi_t mpi = NULL;
      char *name;

      data_list = gcry_sexp_nth (list2, 1);
      if (data_list)
	{
	  if (! gcry_sexp_nth_data (data_list, 0, &tmp_data_length))
	    {
	      /* Seems that all the data element lists are contained
		 in another sub list.  */
	      i = 0;
	    }
	  else
	    {
	      data_list = list2;
	      i = 1;
	    }

	}
      else
	err = GPG_ERR_INV_OBJ;

      data_list_n = gcry_sexp_length (data_list);
      for (; i < data_list_n; i++)
	{
	  mpi = NULL;
	  elem_list = gcry_sexp_nth (data_list, i);
	  
	  if (! elem_list)
	    err = GPG_ERR_INV_OBJ; /* FIXME?  */
	  if (! err)
	    {
	      identifier = gcry_sexp_nth_data (elem_list, 0, &identifier_length);
	      if (identifier_length != 1)
		/* FIXME?  Should this be an error or should it be
		   ignored?  */
		err = GPG_ERR_INV_OBJ;
	    }
	  if (! err)
	    {
	      mpi = gcry_sexp_nth_mpi (elem_list, 1, GCRYMPI_FMT_USG);
	      if (! mpi)
		err = GPG_ERR_INV_OBJ;
	    }
	  if (! err)
	    {
	      name = gcry_malloc (identifier_length + 1);
	      if (! name)
		err = gcry_err_code_from_errno (ENOMEM);
	      else
		{
		  strncpy (name, identifier, identifier_length);
		  name[identifier_length] = 0;

		  err = _gcry_ac_data_set (data_new, GCRY_AC_FLAG_DEALLOC, name, mpi);
		  if (err)
		    gcry_free (name);
		}
	    }
	  if (elem_list)
	    gcry_sexp_release (elem_list);
	}

      if (data_list != list2)
	gcry_sexp_release (data_list);
    }

  if (list)
    gcry_sexp_release (list);
  if (list2)
    gcry_sexp_release (list2);
  
  if (! err)
    {
      /* Copy out.  */
      if (! *handle)
	*handle = handle_new;
      *data = data_new;
      if (sexp_flags)
	*sexp_flags = sexp_flags_parsed;
      if (flags)
	*flags = flags_parsed;
    }
  else
    {
      /* Deallocate resources.  */
      if (handle_new)
	_gcry_ac_close (handle_new);
      if (data_new)
	_gcry_ac_data_destroy (data_new);
    }

  return err;
}

static gcry_err_code_t
sexp_extract_key (gcry_sexp_t sexp, pk_key_type_t which, gcry_ac_key_t *key,
		  gcry_ac_handle_t *handle)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle_new = NULL;
  gcry_ac_key_t key_new = NULL;
  gcry_ac_key_type_t key_type = 0;
  gcry_ac_data_t data = NULL;

  if ((which == PK_KEY_TYPE_PUBLIC) || (which == PK_KEY_TYPE_ANY))
    {
      err = sexp_extract_std (sexp, PK_SEXP_TYPE_KEY_PUBLIC, &data,
			      NULL, NULL, &handle_new);
      if (! err)
	key_type = GCRY_AC_KEY_PUBLIC;
    }
  if ((which == PK_KEY_TYPE_SECRET) || ((which == PK_KEY_TYPE_ANY)
					&& (err == GPG_ERR_INV_OBJ)))
    {
      err = sexp_extract_std (sexp, PK_SEXP_TYPE_KEY_SECRET, &data,
			      NULL, NULL, &handle_new);
      if (! err)
	key_type = GCRY_AC_KEY_SECRET;
    }
  
  if (! err)
    err = _gcry_ac_key_init (&key_new, handle_new, key_type, data);

  if (! err)
    {
      *handle = handle_new;
      *key = key_new;
    }
  else
    {
      if (handle_new)
	_gcry_ac_close (handle_new);
      if (key_new)
	_gcry_ac_key_destroy (key_new);
      else if (data)
	_gcry_ac_data_destroy (data);
    }

  return err;
}

/* Convert a `data'-S-Expression into an MPI value, suitable for
   passing to the low level functions.  Two different styles for the
   input S-Expression are supported: to use the `old' style, the input
   S-Expression must simply consist of a single MPI value;
   `modern'-style S-Expression follow a more complex structure:

   (data
    [(flags <flag identifiers>)]
    [(hash <algorithm identifier> <text>)]
    [(value <value>)])

    For encryption, the `value'-S-Expression must be present.  For
    non-encryption-data (i.e. for signatures) either the `value'- or
    the `hash'-S-Expression must be present (the latter one has higher
    priority).  */
static gcry_err_code_t
sexp_extract_data (gcry_sexp_t data_sexp, gcry_ac_handle_t handle,
		   gcry_ac_key_t key, gcry_mpi_t *data,
		   unsigned int for_encryption, unsigned int *flags)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t data_sexp_inner = NULL;

  gcry_mpi_t data_new = NULL;
  unsigned int flags_parsed = 0;

  data_sexp_inner = gcry_sexp_find_token (data_sexp, "data", 0);
  if (! data_sexp_inner)
    {
      /* Assume old style.  */

      data_new = gcry_sexp_nth_mpi (data_sexp, 0, 0);
      if (! data_new)
	err = GPG_ERR_INV_OBJ;
    }
  else
    {
      /* Assume modern style.  */

      gcry_sexp_t flags_sexp = NULL;
      gcry_sexp_t hash_sexp = NULL;
      gcry_sexp_t value_sexp = NULL;
      
      unsigned int i = 0;

      unsigned int nbits = 0;

      err = _gcry_ac_key_get_nbits (handle, key, &nbits);
      if (! err)
	{
	  flags_sexp = gcry_sexp_find_token (data_sexp_inner, "flags", 0);
	  if (flags_sexp)
	    {
	      err = sexp_extract_flags (flags_sexp, &flags_parsed);
	      gcry_sexp_release (flags_sexp);
	    }
	}

      if (! err)
	{
	  if (! (flags_parsed & (PK_SEXP_FLAG_PKCS1_V1_5 | PK_SEXP_FLAG_RAW)))
	     /* Default to `raw'.  */
	    flags_parsed |= PK_SEXP_FLAG_RAW;

	  /* Get `hash'- or `value'-S-Expression. */
	  hash_sexp = gcry_sexp_find_token (data_sexp_inner, "hash", 0);
	  if (! hash_sexp)
	    value_sexp = gcry_sexp_find_token (data_sexp_inner, "value", 0);

	  if (! ((! hash_sexp) ^ (! value_sexp)))
	    /* None or both given.  */
	    err = GPG_ERR_INV_OBJ;
	  else if (1
		   && (flags_parsed & PK_SEXP_FLAG_PKCS1_V1_5)
		   && (flags_parsed & PK_SEXP_FLAG_RAW)
		   && (! for_encryption))
	    err = GPG_ERR_CONFLICT;
	  else if ((flags_parsed & PK_SEXP_FLAG_RAW) && value_sexp)
	    {
	      /* Raw value, this can be used for both, signing and
		 encryption.  */
	      data_new = gcry_sexp_nth_mpi (value_sexp, 1, 0);
	      if (! data_new)
		err = GPG_ERR_INV_OBJ;
	    }
	  else if (1
		   && (flags_parsed & PK_SEXP_FLAG_PKCS1_V1_5)
		   && value_sexp
		   && for_encryption)
	    {
	      /* Create PKCS#1 block type 2 padding.  Only used for
		 encryption.  */

	      unsigned char *frame = NULL;
	      size_t nframe = (nbits + 7) / 8;
	      const void *value;
	      size_t valuelen;
	      unsigned char *p;
	  
	      value = gcry_sexp_nth_data (value_sexp, 1, &valuelen);
	      if (! (value && valuelen))
		err = GPG_ERR_INV_OBJ;
	      else if ((valuelen + 7 > nframe) || (! nframe))
		/* Can't encode a VALUELEN value in a NFRAME bytes
		   frame.  The key is too short. */
		err = GPG_ERR_TOO_SHORT;
	      else if (! (frame = gcry_malloc_secure (nframe)))
		err = gcry_err_code_from_errno (errno);
	      else
		{
		  unsigned int n = 0;
		  
		  frame[n++] = 0;
		  frame[n++] = 2; /* Block type.  */
		  i = nframe - 3 - valuelen;
		  assert (i > 0);
		  p = gcry_random_bytes_secure (i, GCRY_STRONG_RANDOM);
		  /* Replace zero bytes by new values.  */
		  for (;;)
		    {
		      int j, k;
		      unsigned char *pp;
		  
		      /* Count the zero bytes.  */
		      for (j = k = 0; j < i; j++)
			{
			  if (! p[j])
			    k++;
			}
		      if (! k)
			/* Okay, no (more) zero bytes.  */
			break;

		      k += k/128; /* Better get some more.  */
		      pp = gcry_random_bytes_secure (k, GCRY_STRONG_RANDOM);
		      for (j = 0; j < i && k; j++)
			{
			  if (! p[j])
			    p[j] = pp[--k];
			}
		      gcry_free (pp);
		    }
		  memcpy (frame + n, p, i);
		  n += i;
		  gcry_free (p);

		  frame[n++] = 0;
		  memcpy (frame + n, value, valuelen);
		  n += valuelen;
		  assert (n == nframe);

		  /* FIXME, error checking?  */
		  gcry_mpi_scan (&data_new, GCRYMPI_FMT_USG, frame, n, &nframe);
		}

	      gcry_free (frame);
	    }
	  else if (1
		   && (flags_parsed & PK_SEXP_FLAG_PKCS1_V1_5)
		   && hash_sexp
		   && (! for_encryption))
	    {
	      /* Create PKCS#1 block type 1 padding.  Only used for
		 signing.  */

	      const char *identifier = NULL;
	      size_t identifier_length = 0;

	      if (gcry_sexp_length (hash_sexp) != 3)
		err = GPG_ERR_INV_OBJ;
	      if (! err)
		{
		  identifier = gcry_sexp_nth_data (hash_sexp, 1, &identifier_length);
		  if (! identifier_length)
		    err = GPG_ERR_INV_OBJ;
		}

	      if (! err)
		{
		  static struct
		  {
		    const char *name;
		    int algo;
		  } hashnames[] = 
		    {
		      { "sha1",   GCRY_MD_SHA1 },
		      { "md5",    GCRY_MD_MD5 },
		      { "rmd160", GCRY_MD_RMD160 },
		      { "sha256", GCRY_MD_SHA256 },
		      { "sha384", GCRY_MD_SHA384 },
		      { "sha512", GCRY_MD_SHA512 },
		      { "md2",    GCRY_MD_MD2 },
		      { "md4",    GCRY_MD_MD4 },
		      { "tiger",  GCRY_MD_TIGER },
		      { "haval",  GCRY_MD_HAVAL },
		      { NULL }
		    };
		  int algo;
		  byte asn[100];
		  byte *frame = NULL;
		  size_t nframe = (nbits+7) / 8;
		  const void * value;
		  size_t valuelen;
		  size_t asnlen, dlen;
	      
		  for (i = 0; hashnames[i].name; i++)
		    if ((strlen (hashnames[i].name) == identifier_length)
			&& (! memcmp (hashnames[i].name, identifier,
				      identifier_length)))
		      break;

		  algo = hashnames[i].algo;
		  asnlen = DIM (asn);
		  dlen = gcry_md_get_algo_dlen (algo);

		  if (! hashnames[i].name)
		    err = GPG_ERR_DIGEST_ALGO;
		  else if (! ((value = gcry_sexp_nth_data (hash_sexp, 2,
							   &valuelen))
			      && valuelen))
		    err = GPG_ERR_INV_OBJ;
		  else if (gcry_md_algo_info (algo, GCRYCTL_GET_ASNOID, asn,
					      &asnlen))
		    /* We don't have all of the above algorithms.  */
		    err = GPG_ERR_NOT_IMPLEMENTED;
		  else if (valuelen != dlen)
		    /* Hash value does not match the length of digest for
		       the given algorithm.  */
		    err = GPG_ERR_CONFLICT;
		  else if ((! dlen) || (dlen + asnlen + 4 > nframe))
		    /* Can't encode an DLEN byte digest MD into a NFRAME
		       byte frame.  */
		    err = GPG_ERR_TOO_SHORT;
		  else if (! (frame = gcry_malloc (nframe)))
		    err = gcry_err_code_from_errno (errno);
		  else
		    {
		      /* Assemble the PKCS#1-V1_5 block type 1. */
		      unsigned int n = 0;
		      frame[n++] = 0;
		      frame[n++] = 1; /* Block type.  */
		      i = nframe - valuelen - asnlen - 3 ;
		      assert (i > 1);
		      memset (frame+n, 0xff, i );
		      n += i;
		      frame[n++] = 0;
		      memcpy (frame+n, asn, asnlen);
		      n += asnlen;
		      memcpy (frame+n, value, valuelen );
		      n += valuelen;
		      assert (n == nframe);

		      /* Convert it into an MPI, FIXME: error checking?  */
		      gcry_mpi_scan (&data_new, GCRYMPI_FMT_USG, frame, n, &nframe);
		    }
		  
		  gcry_free (frame);
		}
	    }
	  else
	    err = GPG_ERR_CONFLICT;
      
	  if (data_sexp_inner)
	    gcry_sexp_release (data_sexp_inner);
	  if (hash_sexp)
	    gcry_sexp_release (hash_sexp);
	  if (value_sexp)
	    gcry_sexp_release (value_sexp);
	}
    }

  if (! err)
    {
      *data = data_new;
      if (flags)
	*flags = flags_parsed;
    }

  return err;
}


/* sexp_construct and sexp_extract operate on S-Expressions of the
   following form:

     (<sexp identifier>
      (<algorithm identifier>
       [(flags <flag identifiers>)]
       (<mpi identifier 0> <mpi value 0>)
       ...)) */

/* Construct a new S-Expression that is to be stored in SEXP.  TYPE
   specifies the type of the S-Expression; ARRAY contains MPI values
   that are to be inserted into the S-Expression; ALGORITHM_INFO is
   used for looking up properties according to TYPE.  */
static gcry_err_code_t
sexp_construct_std (gcry_sexp_t *sexp, pk_sexp_type_t type,
		    gcry_ac_handle_t handle, gcry_ac_data_t data)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  const char *algorithm_name = NULL;
  gcry_ac_id_t algorithm_id = 0;
  char *format_string = NULL;
  unsigned int elements_n = 0;
  gcry_sexp_t sexp_new = NULL;
  const char *name = NULL;
  void **arg_list = NULL;
  size_t size = 0;
  unsigned int i;

  /* Figure out algorithm name.  */
  _gcry_ac_info_get (handle, &algorithm_id, NULL);
  err = _gcry_ac_id_to_name (algorithm_id, &algorithm_name);

  if (! err)
    {
      /* Calc.  */
      elements_n = _gcry_ac_data_length (data);
      size = 5 + strlen (pk_sexp_types[type].identifier) + (elements_n * 5);
      size += strlen (algorithm_name);
      
      /* Allocate.  */
      format_string = gcry_malloc (size);
      if (! format_string)
	err = GPG_ERR_INTERNAL;	/* FIXME!  */
    }

  if (! err)
    {
      /* Construct format string.  */

      char *p = format_string;

      p += sprintf (p, "(%s(%s",
		    pk_sexp_types[type].identifier, algorithm_name);

      for (i = 0; i < elements_n && (! err); i++)
	{
	  err = _gcry_ac_data_get_index (data, 0, i, &name, NULL);
	  if (! err)
	    p += sprintf (p, "(%s%%m)", name);
	}

      p += sprintf (p, "))");
    }

  if (! err)
    /* Construct argument list.  */
    err = _gcry_ac_arg_list_from_data (data, &arg_list);

  if (! err)
    /* Construct S-Expression.  */
    err = gcry_sexp_build_array (&sexp_new, NULL, format_string, arg_list);

  /* Deallocate resources.  */
  if (format_string)
    gcry_free (format_string);
  if (arg_list)
    gcry_free (arg_list);

  if (! err)
    /* Copy out.  */
    *sexp = sexp_new;

  return err;
}

static gcry_err_code_t
sexp_mpi_arg_list_create (gcry_mpi_t *mpis, void ***arg_list)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  void **arg_list_new = NULL;
  unsigned int i = 0;

  /* Count.  */
  for (i = 0; mpis[i]; i++);

  /* Allocate.  */
  arg_list_new = gcry_malloc (sizeof (void *) * i);
  if (! arg_list_new)
    err = GPG_ERR_INTERNAL;	/* FIXME.  */

  if (! err)
    /* Fill.  */
    for (i = 0; mpis[i]; i++)
      arg_list_new[0] = (void *) &mpis[i];
  
  if (! err)
    *arg_list = arg_list_new;
  else
    {
      if (arg_list_new)
	gcry_free (arg_list_new);
    }

  return err;
}


static gcry_err_code_t
sexp_construct_factors (gcry_sexp_t *sexp, gcry_mpi_t *factors)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t sexp_new = NULL;
  unsigned int factors_n = 0;
  char *format_string = NULL;
  void **arg_list = NULL;
  size_t size = 0;

  err = sexp_mpi_arg_list_create (factors, &arg_list);
  if (! err)
    {
      /* Calculate length and allocate format string.  */

      for (factors_n = 0; factors[factors_n]; factors_n++);
      size += 30 + factors_n * 2;

      format_string = gcry_malloc (size);
      if (! format_string)
	err = GPG_ERR_INTERNAL;	/* FIXME!  */
    }

  if (! err)
    {
      /* Construct format string.  */
      
      unsigned char *p = format_string;
      unsigned int i = 0;

      p += sprintf (p, "(misc-key-info(pm1-factors");
      for (i = 0; i < factors_n; i++)
	p += sprintf (p, "%m");
      p += sprintf (p, "))");

      err = gcry_sexp_build_array (&sexp_new, NULL, format_string, arg_list);
    }

  if (format_string)
    gcry_free (format_string);
  if (arg_list)
    gcry_free (arg_list);

  if (! err)
    *sexp = sexp_new;
  
  return err;
}

static gcry_err_code_t
sexp_construct_genkey (gcry_sexp_t *genkey_sexp,
		       gcry_ac_handle_t handle,
		       gcry_ac_key_pair_t key_pair, gcry_mpi_t *misc_data)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t genkey_sexp_new = NULL;
  gcry_sexp_t key_public_sexp = NULL;
  gcry_sexp_t key_secret_sexp = NULL;
  gcry_sexp_t key_factors_sexp = NULL;
  gcry_ac_data_t key_public = NULL;
  gcry_ac_data_t key_secret = NULL;
  char *format_string = NULL;
  size_t size = 0;

  key_public = _gcry_ac_key_data_get (_gcry_ac_key_pair_extract (key_pair,
							       GCRY_AC_KEY_PUBLIC));
  key_secret = _gcry_ac_key_data_get (_gcry_ac_key_pair_extract (key_pair,
							       GCRY_AC_KEY_SECRET));

  err = sexp_construct_std (&key_public_sexp, PK_SEXP_TYPE_KEY_PUBLIC,
			    handle, key_public);
  if (! err)
    err = sexp_construct_std (&key_secret_sexp, PK_SEXP_TYPE_KEY_SECRET,
			      handle, key_secret);
  if (! err)
    if (misc_data)
      err = sexp_construct_factors (&key_factors_sexp, misc_data);
  
  if (! err)
    {
      /* Calculate size and allocate format string.  */
      size += 11;
      size += gcry_sexp_sprint (key_public_sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
      size += gcry_sexp_sprint (key_secret_sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
      if (key_factors_sexp)
	size += gcry_sexp_sprint (key_factors_sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);

      format_string = gcry_malloc (size);
      if (! format_string)
	err = GPG_ERR_INTERNAL;	/* FIXME!  */
    }

  if (! err)
    {
      char *p = format_string;

      p += sprintf (p, "(key-data");
      p += gcry_sexp_sprint (key_public_sexp, GCRYSEXP_FMT_ADVANCED, p,
			     size - (p - format_string)) - 1;
      p += gcry_sexp_sprint (key_secret_sexp, GCRYSEXP_FMT_ADVANCED, p,
			     size - (p - format_string)) - 1;
      if (key_factors_sexp)
	p += gcry_sexp_sprint (key_factors_sexp, GCRYSEXP_FMT_ADVANCED, p,
			       size - (p - format_string)) - 1;
      p += sprintf (p, ")");

      err = gcry_sexp_build (&genkey_sexp_new, NULL, format_string);
    }
  
  if (format_string)
    gcry_free (format_string);
  if (key_public_sexp)
    gcry_sexp_release (key_public_sexp);
  if (key_secret_sexp)
    gcry_sexp_release (key_secret_sexp);
  if (key_factors_sexp)
    gcry_sexp_release (key_factors_sexp);

  if (! err)
    *genkey_sexp = genkey_sexp_new;
  else
    {
      if (genkey_sexp_new)
	gcry_sexp_release (genkey_sexp_new);
    }

  return err;
}



/* Map a string to the algorithm ID.  */
int
gcry_pk_map_name (const char *string)
{
  gcry_ac_id_t algorithm_id = 0;

  _gcry_ac_name_to_id (string, &algorithm_id);

  return algorithm_id;
}


/* Map an algorithm ID to it's name.  */
const char *
gcry_pk_algo_name (int algorithm)
{
  const char *algorithm_name = NULL;

  _gcry_ac_id_to_name (algorithm, &algorithm_name);

  return algorithm_name;
}



/*
   Do a PK encrypt operation
  
   Caller has to provide a public key as the SEXP pkey and data as a
   SEXP with just one MPI in it. Alternativly S_DATA might be a
   complex S-Expression, similar to the one used for signature
   verification.  This provides a flag which allows to handle PKCS#1
   block type 2 padding.  The function returns a a sexp which may be
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
gcry_pk_encrypt (gcry_sexp_t *data_encrypted_sexp,
		 gcry_sexp_t data_plain_sexp,
		 gcry_sexp_t key_public_sexp)
{
  gcry_sexp_t data_encrypted_sexp_new = NULL;
  gcry_ac_data_t data_encrypted = NULL;
  gcry_ac_key_t key_public = NULL;
  gcry_mpi_t data_plain = NULL;

  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle = NULL;
 
  /* Extract key.  */
  err = sexp_extract_key (key_public_sexp, PK_KEY_TYPE_PUBLIC,
			  &key_public, &handle);
  if (! err)
    /* Extract plain data.  */
    err = sexp_extract_data (data_plain_sexp, handle, key_public,
			     &data_plain, 1, NULL);

  if (! err)
    /* Encrypt.  */
    err = _gcry_ac_data_encrypt (handle, 0, key_public, data_plain,
				&data_encrypted);

  if (! err)
    /* Build the return list.  */
    err = sexp_construct_std (&data_encrypted_sexp_new, PK_SEXP_TYPE_ENCRYPTION,
			      handle, data_encrypted);

  /* Deallocate resources.  */
  
  if (handle)
    _gcry_ac_close (handle);
  if (key_public)
    _gcry_ac_key_destroy (key_public);
  if (data_plain)
    gcry_mpi_release (data_plain);
  if (data_encrypted)
    _gcry_ac_data_destroy (data_encrypted);

  if (! err)
    *data_encrypted_sexp = data_encrypted_sexp_new;
  else
    {
      if (data_encrypted_sexp_new)
	gcry_sexp_release (data_encrypted_sexp_new);
    }

  return gcry_error (err);
}

/****************
 * Do a PK decrypt operation
 *
 * Caller has to provide a secret key as the SEXP skey and data in a
 * format as created by gcry_pk_encrypt.  For historic reasons the
 * function returns simply an MPI as an S-expression part; this is
 * deprecated and the new method should be used which returns a real
 * S-expressionl this is selected by adding at least an empty flags
 * list to S_DATA.
 * 
 * Returns: 0 or an errorcode.
 *
 * s_data = (enc-val
 *            [(flags)]
 *	      (<algo>
 *		(<param_name1> <mpi>)
 *		...
 *		(<param_namen> <mpi>)
 *	      ))
 * s_skey = <key-as-defined-in-sexp_to_key>
 * r_plain= Either an incomplete S-expression without the parentheses
 *          or if the flags list is used (even if empty) a real S-expression:
 *          (value PLAIN).  */
gcry_error_t
gcry_pk_decrypt (gcry_sexp_t *data_decrypted_sexp,
		 gcry_sexp_t data_encrypted_sexp,
		 gcry_sexp_t key_secret_sexp)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  gcry_sexp_t data_decrypted_sexp_new = NULL;
  gcry_ac_data_t data_encrypted = NULL;
  gcry_mpi_t data_decrypted = NULL;
  gcry_ac_key_t key_secret = NULL;

  gcry_ac_handle_t handle = NULL;

  unsigned int sexp_flags_data = 0;
  unsigned int ac_flags = 0;
  unsigned int flags = 0;

  /* Extract key.  */
  err = sexp_extract_key (key_secret_sexp, PK_KEY_TYPE_SECRET,
			  &key_secret, &handle);

  if (! err)
    {
      /* Extract encrypted data.  */
      err = sexp_extract_std (data_encrypted_sexp, PK_SEXP_TYPE_ENCRYPTION,
			      &data_encrypted, &sexp_flags_data, &flags,
			      &handle);
      if (! err)
	{
	  /* Convert flags.  */
	  if (sexp_flags_data & PK_SEXP_FLAG_NO_BLINDING)
	    ac_flags |= GCRY_AC_FLAG_NO_BLINDING;
	}
    }

  if (! err)
    /* Decrypt.  */
    err = _gcry_ac_data_decrypt (handle, ac_flags, key_secret,
				&data_decrypted, data_encrypted);

  if (! err)
    {
      /* Build the return list.  */
      if (flags & PK_FLAG_MODERN)
	err = gcry_sexp_build (&data_decrypted_sexp_new, NULL,
			       "(value %m)", data_decrypted);
      else
	err = gcry_sexp_build (&data_decrypted_sexp_new, NULL,
			       "%m", data_decrypted);
    }

  /* Deallocate resources.  */
  
  if (handle)
    _gcry_ac_close (handle);
  if (key_secret)
    _gcry_ac_key_destroy (key_secret);
  if (data_decrypted)
    gcry_mpi_release (data_decrypted);
  if (data_encrypted)
    _gcry_ac_data_destroy (data_encrypted);

  if (! err)
    *data_decrypted_sexp = data_decrypted_sexp_new;
  else
    {
      if (data_decrypted_sexp_new)
	gcry_sexp_release (data_decrypted_sexp_new);
    }

  return gcry_error (err);
}

/****************
 * Create a signature.
 *
 * Caller has to provide a secret key as the SEXP skey and data
 * expressed as a SEXP list hash with only one element which should
 * instantly be available as a MPI. Alternatively the structure given
 * below may be used for S_HASH, it provides the abiliy to pass flags
 * to the operation; the only flag defined by now is "pkcs1" which
 * does PKCS#1 block type 1 style padding.
 *
 * Returns: 0 or an errorcode.
 *	    In case of 0 the function returns a new SEXP with the
 *	    signature value; the structure of this signature depends on the
 *	    other arguments but is always suitable to be passed to
 *	    gcry_pk_verify
 *
 * s_hash = See comment for sexp_data_to_mpi
 *             
 * s_skey = <key-as-defined-in-sexp_to_key>
 * r_sig  = (sig-val
 *	      (<algo>
 *		(<param_name1> <mpi>)
 *		...
 *		(<param_namen> <mpi>)
 * )) */
gcry_error_t
gcry_pk_sign (gcry_sexp_t *data_signed_sexp,
	      gcry_sexp_t data_sexp,
	      gcry_sexp_t key_secret_sexp)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t data_signed_sexp_new = NULL;
  gcry_ac_data_t data_signed = NULL;
  gcry_ac_key_t key_secret = NULL;
  gcry_ac_handle_t handle = NULL;
  gcry_mpi_t data = NULL;

  *data_signed_sexp = NULL;

  /* Extract key.  */
  err = sexp_extract_key (key_secret_sexp, PK_KEY_TYPE_SECRET,
			  &key_secret, &handle);
  
  if (! err)
    /* Extract data.  */
    err = sexp_extract_data (data_sexp, handle, key_secret,
			     &data, 0, NULL);

  if (! err)
    /* Sign data.  */
    err = _gcry_ac_data_sign (handle, key_secret, data, &data_signed);

  if (! err)
    /* Build the return list.  */
    err = sexp_construct_std (&data_signed_sexp_new, PK_SEXP_TYPE_SIGNATURE,
			      handle, data_signed);

  /* Deallocate resources.  */

  if (handle)
    _gcry_ac_close (handle);
  if (key_secret)
    _gcry_ac_key_destroy (key_secret);
  if (data_signed)
    _gcry_ac_data_destroy (data_signed);
  if (data)
    gcry_mpi_release (data);

  if (! err)
    *data_signed_sexp = data_signed_sexp_new;
  else
    {
      if (data_signed_sexp_new)
	gcry_sexp_release (data_signed_sexp_new);
    }

  return gcry_error (err);
}

/****************
 * Verify a signature.  Caller has to supply the public key pkey, the
 * signature sig and his hashvalue data.  Public key has to be a
 * standard public key given as an S-Exp, sig is a S-Exp as returned
 * from gcry_pk_sign and data must be an S-Exp like the one in sign
 * too.
 */
gcry_error_t
gcry_pk_verify (gcry_sexp_t data_signed_sexp,
		gcry_sexp_t data_sexp,
		gcry_sexp_t key_public_sexp)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_data_t data_signed = NULL;
  gcry_ac_key_t key_public = NULL;
  gcry_ac_handle_t handle = NULL;
  gcry_mpi_t data = NULL;

  /* Extract key.  */
  err = sexp_extract_key (key_public_sexp, PK_KEY_TYPE_PUBLIC,
			  &key_public, &handle);

  if (! err)
    /* Extract signed data.  */
    err = sexp_extract_std (data_signed_sexp, PK_SEXP_TYPE_SIGNATURE,
			    &data_signed, NULL, NULL, &handle);
  if (! err)
    /* Extract data.  */
    err = sexp_extract_data (data_sexp, handle, key_public, &data, 0, NULL);

  if (! err)
    /* Verify signature.  */
    err = _gcry_ac_data_verify (handle, key_public, data, data_signed);

  /* Deallocate resources.  */
  if (handle)
    _gcry_ac_close (handle);
  if (key_public)
    _gcry_ac_key_destroy (key_public);
  if (data)
    gcry_mpi_release (data);
  if (data_signed)
    _gcry_ac_data_destroy (data_signed);

  return gcry_error (err);
}

/* Test a key. */
gcry_error_t
gcry_pk_testkey (gcry_sexp_t key_secret_sexp)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle = NULL;
  gcry_ac_key_t key_secret = NULL;

  /* Extract key.  */
  err = sexp_extract_key (key_secret_sexp, PK_KEY_TYPE_SECRET,
			  &key_secret, &handle);

  if (! err)
    /* Check.  */
    err = _gcry_ac_key_test (handle, key_secret);

  /* Deallocate resources.  */
  if (handle)
    _gcry_ac_close (handle);
  if (key_secret)
    _gcry_ac_key_destroy (key_secret);

  return gcry_error (err);
}


/****************
 * Create a public key pair and return it in r_key.
 * How the key is created depends on s_parms:
 * (genkey
 *  (algo
 *    (parameter_name_1 ....)
 *     ....
 *    (parameter_name_n ....)
 * ))
 * The key is returned in a format depending on the
 * algorithm. Both, private and secret keys are returned
 * and optionally some additional informatin.
 * For elgamal we return this structure:
 * (key-data
 *  (public-key
 *    (elg
 *	(p <mpi>)
 *	(g <mpi>)
 *	(y <mpi>)
 *    )
 *  )
 *  (private-key
 *    (elg
 *	(p <mpi>)
 *	(g <mpi>)
 *	(y <mpi>)
 *	(x <mpi>)
 *    )
 *  )
 *  (misc-key-info
 *     (pm1-factors n1 n2 ... nn)
 *  )
 * )
 */
gcry_error_t
gcry_pk_genkey (gcry_sexp_t *key_pair_sexp, gcry_sexp_t key_spec)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle = NULL;

  gcry_sexp_t key_pair_sexp_new = NULL;
  gcry_ac_key_pair_t key_pair = NULL;
  gcry_mpi_t *misc_data = NULL;

  unsigned long int nbits = 0;

  gcry_ac_key_spec_rsa_t spec_rsa = { 65537 };
  void *spec = NULL;

  gcry_sexp_t list = NULL;
  gcry_sexp_t list2 = NULL;

  const char *identifier = NULL;
  size_t identifier_length = 0;

  gcry_ac_id_t algorithm_id = 0;

  *key_pair_sexp = NULL;

  list = gcry_sexp_find_token (key_spec, "genkey", 0);
  if (! list)
    /* Does not contain genkey data.  */
    err = GPG_ERR_INV_OBJ;

  if (! err)
    {
      /* Extract inner list.  */
      list2 = gcry_sexp_cadr (list);
      if (list2)
	{
	  gcry_sexp_release (list);
	  list = list2;
	  list2 = NULL;
	}
      else
	/* No cdr for the genkey.  */
	err = GPG_ERR_NO_OBJ;
    }

  if (! err)
    {
      /* Extract algorithm name.  */
      identifier = gcry_sexp_nth_data (list, 0, &identifier_length);
      if (! identifier)
	err = GPG_ERR_INV_OBJ;
    }

  if (! err)
    {
      /* Convert identifier into an algorithm ID.  */
      char *name_terminated;

      name_terminated = gcry_xmalloc (identifier_length + 1);
      strncpy (name_terminated, identifier, identifier_length);
      name_terminated[identifier_length] = 0;

      err = _gcry_ac_name_to_id (name_terminated, &algorithm_id);

      free (name_terminated);
    }

  if (! err)
    err = _gcry_ac_open (&handle, algorithm_id, 0);

  if (! err)
    {
      /* RSA special case.  */
      
      list2 = gcry_sexp_find_token (list, "rsa-use-e", 0);
      if (list2)
	{
	  spec = (void *) &spec_rsa;
	  err = sexp_nth_number (list2, 1, &spec_rsa.e);
	  gcry_sexp_release (list2);
	  list2 = NULL;
	}
    }

  if (! err)
    {
      /* Extract nbits.  */
      
      list2 = gcry_sexp_find_token (list, "nbits", 0);
      if (list2)
	{
	  err = sexp_nth_number (list2, 1, &nbits);
	  gcry_sexp_release (list2);
	  list2 = NULL;
	}
      else
	err = GPG_ERR_NO_OBJ;
    }

  if (! err)
    /* Generate key pair.  */
    err = _gcry_ac_key_pair_generate (handle, (unsigned int) nbits, spec,
				      &key_pair, &misc_data);

  if (! err)
    /* Construct return list.  */
    err = sexp_construct_genkey (&key_pair_sexp_new, handle,
				 key_pair, misc_data);

  /* Deallocate resources.  */
  if (handle)
    _gcry_ac_close (handle);
  if (key_pair)
    _gcry_ac_key_pair_destroy (key_pair);
  if (misc_data)
    gcry_free (misc_data);

  if (list2)
    gcry_sexp_release (list2);
  if (list)
    gcry_sexp_release (list);

  if (! err)
    *key_pair_sexp = key_pair_sexp_new;

  return gcry_error (err);
}

/* Get the number of nbits from the public key.  */
unsigned int
gcry_pk_get_nbits (gcry_sexp_t key_sexp)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle = NULL;
  gcry_ac_key_t key = NULL;
  unsigned int nbits = 0;

  /* Extract key.  */
  err = sexp_extract_key (key_sexp, PK_KEY_TYPE_ANY, &key, &handle);
  if (! err)
    err = _gcry_ac_key_get_nbits (handle, key, &nbits);

  if (handle)
    _gcry_ac_close (handle);
  if (key)
    _gcry_ac_key_destroy (key);

  return nbits;
}

/* Return the so called KEYGRIP which is the SHA-1 hash of the public
   key parameters expressed in a way depended on the algorithm.

   ARRAY must either be 20 bytes long or NULL; in the latter case a
   newly allocated array of that size is returned, otherwise ARRAY or
   NULL is returned to indicate an error which is most likely an
   unknown algorithm.  The function accepts public or secret keys. */
unsigned char *
gcry_pk_get_keygrip (gcry_sexp_t key_sexp, unsigned char *key_grip)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle = NULL;
  gcry_ac_key_t key = NULL;

  err = sexp_extract_key (key_sexp, PK_KEY_TYPE_ANY, &key, &handle);
  if (! err)
    err = _gcry_ac_key_get_grip (handle, key, key_grip);

  if (handle)
    _gcry_ac_close (handle);
  if (key)
    _gcry_ac_key_destroy (key);

  return err ? NULL : key_grip;
}

gcry_error_t
gcry_pk_ctl (int cmd, void *buffer, size_t buflen)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle = NULL;

  switch (cmd)
    {
    case GCRYCTL_DISABLE_ALGO:
      /* This one expects a buffer pointing to an integer with the
	 algorithm ID.  */
      if ((! buffer) || (buflen != sizeof (int)))
	err = GPG_ERR_CIPHER_ALGO;
      else
	{
	  err = _gcry_ac_open (&handle, *((int *) buffer), 0);
	  if (! err)
	    {
	      _gcry_ac_algorithm_disable (handle);
	      _gcry_ac_close (handle);
	    }
	}

    default:
      err = GPG_ERR_INV_OP;
    }

  return gcry_error (err);
}


/****************
 * Return information about the given algorithm
 * WHAT select the kind of information returned:
 *  GCRYCTL_TEST_ALGO:
 *	Returns 0 when the specified algorithm is available for use.
 *	Buffer must be NULL, nbytes  may have the address of a variable
 *	with the required usage of the algorithm. It may be 0 for don't
 *	care or a combination of the GCRY_PK_USAGE_xxx flags;
 *  GCRYCTL_GET_ALGO_USAGE:
 *      Return the usage glafs for the give algo.  An invalid alog
 *      does return 0.  Disabled algos are ignored here becuase we
 *      only want to know whether the algo is at all capable of
 *      the usage.
 *
 * Note:  Because this function is in most cases used to return an
 * integer value, we can make it easier for the caller to just look at
 * the return value.  The caller will in all cases consult the value
 * and thereby detecting whether a error occured or not (i.e. while checking
 * the block size)
 */
gcry_error_t
gcry_pk_algo_info (int algorithm, int what, void *buffer, size_t *number)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  gcry_ac_handle_t handle = NULL;
  size_t number_new = 0;

  err = _gcry_ac_open (&handle, algorithm, 0);

  if (! err)
    switch (what)
      {
      case GCRYCTL_TEST_ALGO:
	{
	  int use = number ? *number : 0;
	  
	  if (buffer)
	    err = GPG_ERR_INV_ARG;
	  else
	    {
	      unsigned int use_flags;

	      _gcry_ac_info_get (handle, NULL, &use_flags);
	      
	      if ((use & use_flags) != use)
		err = GPG_ERR_PUBKEY_ALGO;
	    }

	  break;
	}

      case GCRYCTL_GET_ALGO_USAGE:
	{
	  _gcry_ac_info_get (handle, NULL, &number_new);

	  break;
	}

      case GCRYCTL_GET_ALGO_NPKEY:
	{
	  _gcry_ac_elements_amount_get (handle,
					NULL, &number_new,
					NULL, NULL);

	  break;

	}
	
      case GCRYCTL_GET_ALGO_NSKEY:
	{
	  _gcry_ac_elements_amount_get (handle,
					&number_new, NULL,
					NULL, NULL);

	  break;
	}
      case GCRYCTL_GET_ALGO_NSIGN:
	{
	  _gcry_ac_elements_amount_get (handle,
					NULL, NULL,
					NULL, &number_new);

	  break;
	}
	
      case GCRYCTL_GET_ALGO_NENCR:
	{
	  _gcry_ac_elements_amount_get (handle,
					NULL, NULL,
					&number_new, NULL);

	  break;
	}

      default:
	err = GPG_ERR_INV_OP;
      }
  
  if (handle)
    _gcry_ac_close (handle);

  if (number_new)
    *number = number_new;

  return gcry_error (err);
}

/* Get a list consisting of the IDs of the loaded pubkey modules.  If
   LIST is zero, write the number of loaded pubkey modules to
   LIST_LENGTH and return.  If LIST is non-zero, the first
   *LIST_LENGTH algorithm IDs are stored in LIST, which must be of
   according size.  In case there are less pubkey modules than
   *LIST_LENGTH, *LIST_LENGTH is updated to the correct number.  */
gcry_error_t
gcry_pk_list (int *list, int *list_length)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  err = _gcry_ac_list (list, list_length);

  return gcry_error (err);
}
