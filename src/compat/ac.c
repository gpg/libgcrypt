/* ac.c - Alternative interface for asymmetric cryptography.
   Copyright (C) 2003, 2005 Free Software Foundation, Inc.
 
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

#include <gcrypt-internal.h>
#include <gcrypt-ath-internal.h>
#include <gcrypt-ac-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#if USE_RSA
# include <rsa.h>
#endif
#if USE_DSA
# include <dsa.h>
#endif
#if USE_ELGAMAL
# include <elg.h>
#endif

/* FIXME, actually, building of this file should be disabled in case
   building of SHA1 is disabled - alternatively we should mark SHA1
   required.  */
#include <sha1.h>



struct gcry_ac_handle
{
  gcry_module_t module;
  gcry_ac_id_t id;
  gcry_core_ac_handle_t handle;
};

/* A named MPI value.  */
typedef struct gcry_ac_mpi
{
  const char *name_provided;	/* Provided name of MPI value. */
  char *name;			/* Self-maintained copy of name.  */
  gcry_core_mpi_t mpi;		/* MPI value.         */
  unsigned int flags;		/* Flags.             */
} gcry_ac_mpi_t;

/* A data set, that is simply a list of named MPI values.  */
struct gcry_ac_data
{
  gcry_ac_mpi_t *data;		/* List of named values.      */
  unsigned int data_n;		/* Number of values in DATA.  */
};

typedef struct gcry_module_spec
{
  gcry_core_ac_spec_t spec;
  gcry_ac_spec_t *spec_old;
} gcry_module_spec_t;

/* This is the list of the default ciphers, which are included in
   libgcrypt.  */
static struct algorithm_table_entry
{
  gcry_core_ac_spec_t *spec_ptr;
  gcry_module_spec_t spec;
  unsigned int id;
} algorithm_table[] =
  {
#if USE_RSA
    { &gcry_core_ac_rsa, { NULL, NULL },   GCRY_AC_RSA },
#endif
#if USE_DSA
    { &gcry_core_ac_dsa, { NULL, NULL },   GCRY_AC_DSA },
#endif
#if USE_ELGAMAL
    { &gcry_core_ac_elg, { NULL, NULL },   GCRY_AC_ELG },
#endif
    { NULL, { NULL, NULL },                0 }
  };

static gcry_module_t algorithms_registered;

static gcry_core_ath_mutex_t algorithms_registered_lock = ATH_MUTEX_INITIALIZER;



/* Internal function.  Register all the ciphers included in
   CIPHER_TABLE.  Note, that this function gets only used by the macro
   REGISTER_DEFAULT_CIPHERS which protects it using a mutex. */
static void
register_default (void)
{
  gcry_error_t err = 0;
  unsigned int i;
  
  for (i = 0; algorithm_table[i].id; i++)
    {
      algorithm_table[i].spec.spec = *algorithm_table[i].spec_ptr;
      err = _gcry_module_add (&algorithms_registered,
			      algorithm_table[i].id,
			      &algorithm_table[i].spec,
			      NULL);
      if (err)
	break;
    }

  if (err)
    BUG (context);
}



/* Internal callback function.  Used via _gcry_module_lookup.  */
static int
lookup_func_name (void *opaque, const void *data)
{
  gcry_module_spec_t *spec = opaque;
  char **aliases = spec->spec->aliases;
  const char *name = data;
  int ret = stricmp (name, spec->spec->name);

  while (ret && *aliases)
    ret = stricmp (name, *aliases++);

  return ! ret;
}

/* Internal function.  Lookup a pubkey entry by it's name.  */
static gcry_module_t 
module_lookup_by_name (const char *name)
{
  return _gcry_module_lookup (algorithms_registered, name, lookup_func_name);
}




/* Init.  */

gcry_error_t
_gcry_ac_init (void)
{
  register_default ();

  return 0;
}



/* Creates a new, empty data set and store it in DATA.  */
static gcry_error_t
ac_data_new (gcry_core_context_t ctx,
	     unsigned int flags,
	     gcry_ac_data_t *data)
{
  gcry_ac_data_t data_new;
  gcry_error_t err;

  data_new = gcry_core_malloc (ctx, sizeof (*data_new));
  if (! data_new)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  data_new->data = NULL;
  data_new->data_n = 0;
  *data = data_new;
  err = 0;

 out:

  return err;
}

/* Destroys all the entries in DATA, but not DATA itself.  */
static void
ac_data_values_destroy (gcry_core_context_t ctx, gcry_ac_data_t data)
{
  unsigned int i;
  
  for (i = 0; i < data->data_n; i++)
    if (data->data[i].flags & GCRY_AC_FLAG_DEALLOC)
      {
	gcry_core_mpi_release (ctx, data->data[i].mpi);
	gcry_core_free (ctx, data->data[i].name);
      }
}

/* Destroys the data set DATA.  */
static void
ac_data_destroy (gcry_core_context_t ctx,
		 unsigned int flags, gcry_ac_data_t data)
{
  if (data)
    {
      ac_data_values_destroy (ctx, data);
      gcry_core_free (ctx, data->data);
      gcry_core_free (ctx, data);
    }
}

/* This function creates a copy of the array of named MPIs DATA_MPIS,
   which is of length DATA_MPIS_N; the copy is stored in
   DATA_MPIS_CP.  */
static gcry_error_t
ac_data_mpi_copy (gcry_core_context_t ctx,
		  gcry_ac_mpi_t *data_mpis, unsigned int data_mpis_n,
		  gcry_ac_mpi_t **data_mpis_cp)
{
  gcry_ac_mpi_t *data_mpis_new;
  gcry_error_t err;
  unsigned int i;
  gcry_core_mpi_t mpi;
  char *label;

  data_mpis_new = gcry_core_malloc (ctx, sizeof (*data_mpis_new) * data_mpis_n);
  if (! data_mpis_new)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }
  memset (data_mpis_new, 0, sizeof (*data_mpis_new) * data_mpis_n);

  err = 0;
  for (i = 0; i < data_mpis_n; i++)
    {
      /* Copy values.  */

      if (data_mpis[i].name)
	label = gcry_core_strdup (ctx, data_mpis[i].name);
      else
	label = gcry_core_strdup (ctx, data_mpis[i].name_provided);
      mpi = gcry_core_mpi_copy (ctx, data_mpis[i].mpi);
      if (! (label && mpi))
	{
	  err = gcry_core_error_from_errno (errno);
	  gcry_core_mpi_release (ctx, mpi);
	  gcry_core_free (ctx, label);
	  break;
	}

      data_mpis_new[i].flags = GCRY_AC_FLAG_DEALLOC;
      data_mpis_new[i].name = label;
      data_mpis_new[i].mpi = mpi;
    }
  if (err)
    goto out;

  *data_mpis_cp = data_mpis_new;
  err = 0;

 out:

  if (err)
    if (data_mpis_new)
      {
	for (i = 0; i < data_mpis_n; i++)
	  {
	    gcry_core_mpi_release (ctx, data_mpis_new[i].mpi);
	    gcry_core_free (ctx, data_mpis_new[i].name);
	  }
	gcry_core_free (ctx, data_mpis_new);
      }

  return err;
}

/* Create a copy of the data set DATA and store it in DATA_CP.  */
static gcry_error_t
ac_data_copy (gcry_core_context_t ctx,
	      unsigned int flags,
	      gcry_ac_data_t *data_cp, gcry_ac_data_t data)
{
  gcry_ac_mpi_t *data_mpis;
  gcry_ac_data_t data_new;
  gcry_error_t err;

  /* Allocate data set.  */
  data_new = gcry_core_malloc (ctx, sizeof (*data_new));
  if (! data_new)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  err = ac_data_mpi_copy (ctx, data->data, data->data_n, &data_mpis);
  if (err)
    goto out;
  
  data_new->data_n = data->data_n;
  data_new->data = data_mpis;
  *data_cp = data_new;

 out:

  if (err)
    gcry_core_free (ctx, data_new);

  return err;
}

static unsigned int
ac_data_length (gcry_core_context_t ctx,
		unsigned int flags,
		gcry_ac_data_t data)
{
  return data->data_n;
}

/* Add the value MPI to DATA with the label NAME.  If FLAGS contains
   GCRY_AC_FLAG_COPY, the data set will contain copies of NAME
   and MPI.  If FLAGS contains GCRY_AC_FLAG_DEALLOC or
   GCRY_AC_FLAG_COPY, the values contained in the data set will
   be deallocated when they are to be removed from the data set.  */
static gcry_error_t
ac_data_set (gcry_core_context_t ctx,
	     unsigned int flags,
	     gcry_ac_data_t data,
	     const char *name, gcry_core_mpi_t mpi)
{
  gcry_error_t err;
  gcry_core_mpi_t mpi_cp;
  char *name_cp;
  unsigned int i;

  name_cp = NULL;
  mpi_cp = NULL;

  if (flags & ~(GCRY_AC_FLAG_DEALLOC | GCRY_AC_FLAG_COPY))
    {
      /* Unexpected flags set.  */
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto out;
    }

  if (flags & GCRY_AC_FLAG_COPY)
    {
      /* Copy provided data.  */

      name_cp = gcry_core_strdup (ctx, name);
      mpi_cp = gcry_core_mpi_copy (ctx, mpi);
      if (! (name_cp && mpi_cp))
	{
	  err = gcry_core_error_from_errno (errno);
	  goto out;
	}
    }

  /* Search for existing entry.  */
  for (i = 0; i < data->data_n; i++)
    if (! strcmp (name,
		  data->data[i].name
		  ? data->data[i].name : data->data[i].name_provided))
      break;
  if (i < data->data_n)
    {
      /* An entry for NAME does already exist, dealloc if
	 necessary.  */
      if (data->data[i].flags & GCRY_AC_FLAG_DEALLOC)
	{
	  gcry_core_mpi_release (ctx, data->data[i].mpi);
	  gcry_core_free (ctx, data->data[i].name);
	}
    }
  else
    {
      /* Create a new entry.  */

      gcry_ac_mpi_t *ac_mpis;

      ac_mpis = gcry_core_realloc (ctx, data->data,
				   sizeof (*data->data) * (data->data_n + 1));
      if (! ac_mpis)
	{
	  err = gcry_core_error_from_errno (errno);
	  goto out;
	}

      if (data->data != ac_mpis)
	data->data = ac_mpis;
      data->data_n++;
    }

  /* Update data set.  */
  data->data[i].name_provided = name_cp ? NULL : name;
  data->data[i].name = name_cp;
  data->data[i].mpi = mpi_cp ? mpi_cp : mpi;
  data->data[i].flags = flags;
  err = 0;

 out:

  if (err)
    {
      gcry_core_mpi_release (ctx, mpi_cp);
      gcry_core_free (ctx, name_cp);
    }

  return err;
}

/* Stores the value labelled with NAME found in the data set DATA in
   MPI.  The returned MPI value will be released in case
   gcry_core_ac_data_set is used to associate the label NAME with a
   different MPI value.  */
static gcry_error_t
ac_data_get_name (gcry_core_context_t ctx,
		  unsigned int flags,
		  gcry_ac_data_t data,
		  const char *name, gcry_core_mpi_t *mpi)
{
  gcry_core_mpi_t mpi_return;
  gcry_error_t err;
  unsigned int i;

  if (flags & ~(GCRY_AC_FLAG_COPY))
    {
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto out;
    }

  for (i = 0; i < data->data_n; i++)
    if (! strcmp (name,
		  data->data[i].name ?
		  data->data[i].name : data->data[i].name_provided))
      break;
  if (i == data->data_n)
    {
      err = gcry_core_error (GPG_ERR_NOT_FOUND);
      goto out;
    }

  if (flags & GCRY_AC_FLAG_COPY)
    {
      mpi_return = gcry_core_mpi_copy (ctx, data->data[i].mpi);
      if (! mpi_return)
	{
	  err = gcry_core_error_from_errno (errno); /* FIXME? */
	  goto out;
	}
    }
  else
    mpi_return = data->data[i].mpi;

  *mpi = mpi_return;
  err = 0;

 out:

  return err;
}

/* Stores in NAME and MPI the named MPI value contained in the data
   set DATA with the index IDX.  NAME or MPI may be NULL.  The
   returned MPI value will be released in case gcry_core_ac_data_set is
   used to associate the label NAME with a different MPI value.  */
static gcry_error_t
ac_data_get_index (gcry_core_context_t ctx,
		   unsigned int flags,
		   gcry_ac_data_t data,
		   unsigned int idx,
		   const char **name, gcry_core_mpi_t *mpi)
{
  gcry_error_t err;
  gcry_core_mpi_t mpi_cp;
  char *name_cp;

  name_cp = NULL;
  mpi_cp = NULL;

  if (flags & ~(GCRY_AC_FLAG_COPY))
    {
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto out;
    }

  if (idx >= data->data_n)
    {
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto out;
    }

  if (flags & GCRY_AC_FLAG_COPY)
    {
      /* Return copies to the user.  */
      if (name)
	{
	  if (data->data[idx].name_provided)
	    name_cp = gcry_core_strdup (ctx, data->data[idx].name_provided);
	  else
	    name_cp = gcry_core_strdup (ctx, data->data[idx].name);
	  if (! name_cp)
	    {
	      err = gcry_core_error_from_errno (errno);
	      goto out;
	    }
	}
      if (mpi)
	{
	  mpi_cp = gcry_core_mpi_copy (ctx, data->data[idx].mpi);
	  if (! mpi_cp)
	    {
	      err = gcry_core_error_from_errno (errno);
	      goto out;
	    }
	}
    }

  if (name)
    *name = name_cp ? name_cp : (data->data[idx].name
				 ? data->data[idx].name
				 : data->data[idx].name_provided);
  if (mpi)
    *mpi = mpi_cp ? mpi_cp : data->data[idx].mpi;
  err = 0;

 out:

  if (err)
    {
      gcry_core_mpi_release (ctx, mpi_cp);
      gcry_core_free (ctx, name_cp);
    }

  return err;
}

/* Convert the data set DATA into a new S-Expression, which is to be
   stored in SEXP, according to the identifiers contained in
   IDENTIFIERS.  */
static gcry_error_t
ac_data_to_sexp (gcry_core_context_t ctx,
		 unsigned int flags,
		 gcry_ac_data_t data, gcry_core_sexp_t *sexp,
		 const char **identifiers)
{
  gcry_core_sexp_t sexp_new;
  gcry_error_t err;
  char *sexp_buffer;
  size_t sexp_buffer_n;
  size_t identifiers_n;
  const char *label;
  gcry_core_mpi_t mpi;
  void **arg_list;
  size_t data_n;
  unsigned int i;

  /* The shortest S-Expression possible is the empty one "()".  */
  sexp_buffer_n = 3;
  sexp_buffer = NULL;
  arg_list = NULL;
  err = 0;

  /* Calculate size of S-expression representation.  */

  i = 0;
  if (identifiers)
    /* Process identifiers.  */
    while (identifiers[i])
      {
	/* For each identifier, we add "(<IDENTIFIER>)".  */
	sexp_buffer_n += 1 + strlen (identifiers[i]) + 1;
	i++;
      }
  identifiers_n = i;

  /* Process data set.  */
  data_n = ac_data_length (ctx, 0, data);
  for (i = 0; i < data_n; i++)
    {
      err = ac_data_get_index (ctx, 0, data, i, &label, NULL);
      if (err)
	break;
      /* For each entry in the data set we add "(<LABEL> %m)".  */
      sexp_buffer_n += 1 + strlen (label) + 4;
    }
  if (err)
    goto out;

  /* Allocate buffer.  */
  sexp_buffer = gcry_core_malloc (ctx, sexp_buffer_n);
  if (! sexp_buffer)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  /* Fill buffer.  */

  *sexp_buffer = 0;
  sexp_buffer_n = 0;

  /* Add identifiers: (<IDENTIFIER0>(<IDENTIFIER1>...)).  */
  for (i = 0; i < identifiers_n; i++)
    sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n, "(%s",
			      identifiers[i]);

  /* Add data set entries.  */
  sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n, "(");
  arg_list = gcry_core_malloc (ctx, sizeof (*arg_list) * (data_n + 1));
  if (! arg_list)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }
  for (i = 0; i < data_n; i++)
    {
      err = ac_data_get_index (ctx, 0, data, i, &label, &mpi);
      if (err)
	break;
      sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n,
				"(%s %%m)", label);
      arg_list[i] = &data->data[i].mpi;
    }
  if (err)
    goto out;
  sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n, ")");

  /* Add closing braces for identifier list.  */
  for (i = 0; i < identifiers_n; i++)
    sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n, ")");

  /* Construct.  */
  err = gcry_core_sexp_build_array (ctx, &sexp_new, NULL, sexp_buffer, arg_list);
  if (err)
    goto out;

  *sexp = sexp_new;

 out:

  gcry_core_free (ctx, sexp_buffer);
  gcry_core_free (ctx, arg_list);

  return err;
}

/* Create a new data set, which is to be stored in DATA_SET, from the
   S-Expression SEXP, according to the identifiers contained in
   IDENTIFIERS.  */
static gcry_error_t
ac_data_from_sexp (gcry_core_context_t ctx,
		   unsigned int flags,
		   gcry_ac_data_t *data_set, gcry_core_sexp_t sexp,
		   const char **identifiers)
{
  gcry_ac_data_t data_set_new;
  gcry_error_t err;
  gcry_core_sexp_t sexp_cur;
  gcry_core_sexp_t sexp_tmp;
  gcry_core_mpi_t mpi;
  char *string;
  const char *data;
  size_t data_n;
  size_t sexp_n;
  unsigned int i;

  data_set_new = NULL;
  sexp_cur = sexp;
  sexp_tmp = NULL;
  string = NULL;
  mpi = NULL;
  err = 0;

  /* Process S-expression/identifiers.  */

  if (identifiers)
    {
      for (i = 0; identifiers[i]; i++)
	{
	  data = gcry_core_sexp_nth_data (ctx, sexp_cur, 0, &data_n);
	  if (! ((data_n == strlen (identifiers[i]))
		 && (! strncmp (data, identifiers[i], data_n))))
	    {
	      /* Identifier mismatch.  */
	      err = gcry_core_error (GPG_ERR_INV_SEXP);
	      break;
	    }
	  sexp_tmp = gcry_core_sexp_nth (ctx, sexp_cur, 1);
	  if (! sexp_tmp)
	    {
	      /* gcry_sexp_nth() does also return NULL in case the
		 requested element is simple an empty list.  That's
		 why we have to add this special case.  */

	      if ((gcry_core_sexp_length (ctx, sexp_cur) == 1)
		  || identifiers[i + 1])
		{
		  err = gcry_core_error (GPG_ERR_INV_SEXP);
		  break;
		}
	    }
	  if (sexp_cur != sexp)
	    gcry_core_sexp_release (ctx, sexp_cur);
	  sexp_cur = sexp_tmp;
	}
      if (err)
	goto out;
    }

  /* Create data set from S-expression data.  */
  
  err = ac_data_new (ctx, 0, &data_set_new);
  if (err)
    goto out;

  if (sexp_cur)
    sexp_n = gcry_core_sexp_length (ctx, sexp_cur);
  else
    sexp_n = 0;

  for (i = 0; i < sexp_n; i++)
    {
      sexp_tmp = gcry_core_sexp_nth (ctx, sexp_cur, i);
      if (! sexp_tmp)
	{
	  err = gcry_core_error (GPG_ERR_INV_SEXP);
	  break;
	}

      data = gcry_core_sexp_nth_data (ctx, sexp_tmp, 0, &data_n);
      string = gcry_core_malloc (ctx, data_n + 1);
      if (! string)
	{
	  err = gcry_core_error_from_errno (errno);
	  break;
	}
      memcpy (string, data, data_n);
      string[data_n] = 0;

      mpi = gcry_core_sexp_nth_mpi (ctx, sexp_tmp, 1, 0);
      if (! mpi)
	{
	  err = gcry_core_error (GPG_ERR_INV_SEXP); /* FIXME? */
	  break;
	}

      err = ac_data_set (ctx, GCRY_AC_FLAG_DEALLOC,
			 data_set_new, string, mpi);
      if (err)
	break;

      string = NULL;
      mpi = NULL;

      gcry_core_sexp_release (ctx,sexp_tmp);
      sexp_tmp = NULL;
    }
  if (err)
    goto out;

  *data_set = data_set_new;

 out:

  gcry_core_sexp_release (ctx, sexp_tmp);
  gcry_core_mpi_release (ctx, mpi);
  gcry_core_free (ctx, string);
  
  if (err)
    ac_data_destroy (ctx, 0, data_set_new);

  return err;
}

/* Destroys any values contained in the data set DATA.  */
static void
ac_data_clear (gcry_core_context_t ctx,
	       unsigned int flags,
	       gcry_ac_data_t data)
{
  ac_data_values_destroy (ctx, data);
  gcry_core_free (ctx, data->data);
  data->data = NULL;
  data->data_n = 0;
}



gcry_error_t
gcry_ac_data_new (gcry_ac_data_t *data)
{
  _gcry_init ();
  return ac_data_new (context, 0, data);
}

void
gcry_ac_data_destroy (gcry_ac_data_t data)
{
  _gcry_init ();
  return ac_data_destroy (context, 0, data);
}

gcry_error_t
gcry_ac_data_copy (gcry_ac_data_t *data_cp, gcry_ac_data_t data)
{
  _gcry_init ();
  return ac_data_copy (context, 0, data_cp, data);
}

unsigned int
gcry_ac_data_length (gcry_ac_data_t data)
{
  _gcry_init ();
  return ac_data_length (context, 0, data);
}

gcry_error_t
gcry_ac_data_set (gcry_ac_data_t data, unsigned int flags,
		  const char *name, gcry_mpi_t mpi)
{
  _gcry_init ();
  return ac_data_set (context, flags, data, name, mpi);
}

gcry_error_t
gcry_ac_data_get_name (gcry_ac_data_t data, unsigned int flags,
		       const char *name, gcry_mpi_t *mpi)
{
  _gcry_init ();
  return ac_data_get_name (context, flags, data, name, mpi);
}

gcry_error_t
gcry_ac_data_get_index (gcry_ac_data_t data, unsigned int flags,
			unsigned int idx,
			const char **name, gcry_mpi_t *mpi)
{
  _gcry_init ();
  return ac_data_get_index (context, flags, data, idx, name, mpi);
}

gcry_error_t
gcry_ac_data_to_sexp (gcry_ac_data_t data, gcry_sexp_t *sexp,
		      const char **identifiers)
{
  _gcry_init ();
  return ac_data_to_sexp (context, 0, data, sexp, identifiers);
}

gcry_error_t
gcry_ac_data_from_sexp (gcry_ac_data_t *data_set, gcry_sexp_t sexp,
			const char **identifiers)
{
  _gcry_init ();
  return ac_data_from_sexp (context, 0, data_set, sexp, identifiers);
}

void
gcry_ac_data_clear (gcry_ac_data_t data)
{
  _gcry_init ();
  return ac_data_clear (context, 0, data);
}



/*
 * Functions implementing the conversion between old data sets and new
 * data sets.
 */

static gcry_error_t
ac_data_convert_to_new (gcry_ac_data_t data_old, gcry_core_ac_data_t *data_new)
{
  gcry_core_ac_data_t data;
  gcry_error_t err;
  unsigned int length;
  unsigned int i;
  const char *name;
  gcry_mpi_t mpi;

  err = gcry_core_ac_data_new (context, 0, &data);
  if (err)
    goto out;

  length = ac_data_length (context, 0, data_old);
  for (i = 0; i < length; i++)
    {
      err = ac_data_get_index (context, 0, data_old, i, &name, &mpi);
      if (err)
	break;
      err = gcry_core_ac_data_set (context, 0, data, name, mpi);
      if (err)
	break;
    }
  if (err)
    goto out;

  *data_new = data;

 out:

  if (err)
    gcry_core_ac_data_destroy (context, 0, data);

  return err;
}

static gcry_error_t
ac_data_convert_from_new (gcry_ac_data_t *data_old, gcry_core_ac_data_t data_new)
{
  gcry_ac_data_t data;
  gcry_error_t err;
  unsigned int length;
  unsigned int i;
  char *name;
  gcry_mpi_t mpi;

  err = ac_data_new (context, 0, &data);
  if (err)
    goto out;

  length = gcry_core_ac_data_length (context, 0, data_new);
  for (i = 0; i < length; i++)
    {
      err = gcry_core_ac_data_get_idx (context, 0, data_new, i, &name, &mpi);
      if (err)
	break;
      err = ac_data_set (context, GCRY_AC_FLAG_DEALLOC,
			 data, name, mpi);
      if (err)
	break;
    }
  if (err)
    goto out;

  *data_old = data;

 out:

  if (err)
    ac_data_destroy (context, 0, data);

  return err;
}



/* Backward compatibility cruft.  */

/* This function gets called by the callback function whenever the
   calculation of a keygrip is requested.  We do not need to
   distinguish between the RSA and the non-RSA case, since this
   function is only called for algorithm modules loaded by the user;
   loading RSA modules does not make sense, since RSA is included in
   the library.  */
static gcry_error_t
compat_calculate_keygrip (gcry_core_mpi_t *key,
			  unsigned char *grip, const char *elems)
{
  gcry_core_md_hd_t md_hd;
  gcry_error_t err;
  unsigned int i;
  const char *s;
  char buf[30];			/* FIXME?  */
  size_t data_n;
  unsigned char *data;
  
  err = gcry_core_md_open (context, &md_hd, gcry_core_digest_sha1, 0);
  if (err)
    goto out;

  for (i = 0, s = elems; *s; s++, i++)
    {
      err = gcry_core_mpi_aprint (context, GCRYMPI_FMT_STD,
				  &data, &data_n,
				  key[0]);
      if (err)
	break;

      sprintf (buf, "(1:%c%u:", *s, (unsigned int) data_n);
      gcry_core_md_write (context, md_hd, buf, strlen (buf));
      gcry_core_md_write (context, md_hd, data, data_n);
      gcry_core_md_write (context, md_hd, ")", 1);
      gcry_core_free (context, data);
    }
  if (err)
    goto out;

  memcpy (grip, gcry_core_md_read (context, md_hd, gcry_core_digest_sha1), 20);
  gcry_core_md_close (context, md_hd);

 out:

  return err;
}

static gcry_error_t
ac_compat_callback (gcry_core_context_t ctx,
		    void *opaque,
		    gcry_core_ac_cb_type_t type,
		    void *args)
{
  gcry_ac_spec_t *spec;
  gcry_error_t err;

  spec = opaque;

  switch (type)
    {
    case GCRY_CORE_AC_CB_GENERATE:
      {
	gcry_core_ac_cb_generate_t *cb_data = args;
	err = (*spec->generate) (0, cb_data->nbits, 0,
				 cb_data->skey, cb_data->retfactors);
      }
      break;

    case GCRY_CORE_AC_CB_CHECK:
      {
	gcry_core_ac_cb_check_t *cb_data = args;
	err = (*spec->check_secret_key) (0, cb_data->skey);
      }
      break;

    case GCRY_CORE_AC_CB_NBITS:
      {
	gcry_core_ac_cb_nbits_t *cb_data = args;
	*cb_data->n = (*spec->get_nbits) (0, cb_data->key);
	err = 0;
      }
      break;

    case GCRY_CORE_AC_CB_GRIP:
      {
	gcry_core_ac_cb_grip_t *cb_data = args;
	err = compat_calculate_keygrip (cb_data->key,
					cb_data->grip, cb_data->elems);
      }
      break;

    case GCRY_CORE_AC_CB_ENCRYPT:
      {
	gcry_core_ac_cb_encrypt_t *cb_data = args;
	err = (*spec->encrypt) (0, cb_data->resarr, cb_data->data,
				cb_data->pkey, cb_data->flags);
      }
      break;

    case GCRY_CORE_AC_CB_DECRYPT:
      {
	gcry_core_ac_cb_decrypt_t *cb_data = args;
	err = (*spec->decrypt) (0, cb_data->result, cb_data->data,
				cb_data->skey, cb_data->flags);
      }
      break;

    case GCRY_CORE_AC_CB_SIGN:
      {
	gcry_core_ac_cb_sign_t *cb_data = args;
	err = (*spec->sign) (0, cb_data->resarr, cb_data->data,
			     cb_data->skey);
      }
      break;

    case GCRY_CORE_AC_CB_VERIFY:
      {
	gcry_core_ac_cb_verify_t *cb_data = args;
	err = (*spec->verify) (0, cb_data->hash, cb_data->data,
			       cb_data->pkey, NULL, NULL);
      }
      break;

    default:
      abort ();
      err = 0;
      break;
    }

  /* FIXME: verify.  */
  return err;
}



/* FIXME, moritz, comment.  */

static int
ac_spec_in_table_p (gcry_core_ac_spec_t spec)
{
  unsigned int i;

  for (i = 0; i < DIM (algorithm_table); i++)
    if (spec == algorithm_table[i].spec.spec)
      break;
  if (i == DIM (algorithm_table))
    return 0;
  else
    return 1;
}



static void
module_release (gcry_module_t module)
{
  gcry_module_spec_t *module_spec;

  if (_gcry_module_last_reference_p (module))
    module_spec = module->spec;
  else
    module_spec = NULL;

  _gcry_module_release (module);

  if (module_spec)
    if (module_spec->spec_old)
      {
	/* In case spec_old is non NULL, this is a user-registered
	   module.  */
	gcry_core_free (context, module_spec->spec);
	gcry_core_free (context, module_spec);
      }
}

/* Handle management.  */

gcry_error_t
gcry_ac_open (gcry_ac_handle_t *handle,
	      gcry_ac_id_t algorithm_id, unsigned int flags)
{
  gcry_ac_handle_t handle_new;
  gcry_module_spec_t *spec;
  gcry_core_ac_handle_t h;
  gcry_module_t module;
  gcry_error_t err;

  handle_new = NULL;

  _gcry_init ();

  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
  module = _gcry_module_lookup_id (algorithms_registered, algorithm_id);
  if (module)
    {
      /* Found module.  */

      if (module->flags & FLAG_MODULE_DISABLED)
	{
	  /* Not available for use.  */
	  err = gpg_error (GPG_ERR_CIPHER_ALGO);
	  module_release (module);
	  spec = NULL;
	}
      else
	{
	  spec = module->spec;
	  err = 0;
	}
    }
  else
    {
      err = gpg_error (GPG_ERR_CIPHER_ALGO);
      spec = NULL;
    }
  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);
  if (err)
    goto out;

  err = gcry_core_ac_open (context, flags, &h, spec->spec);
  if ((! err) && spec->spec_old)
    gcry_core_ac_set_cb (context, h, 0, ac_compat_callback, spec->spec_old);
  if (err)
    goto out;

  /* FIXME.  */
  handle_new = gcry_core_xmalloc (context, sizeof (*handle_new));
  handle_new->handle = h;
  handle_new->id = algorithm_id;
  handle_new->module = module;

 out:

  if (err)
    {
      if (module)
	{
	  /* Release module.  */
	  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
	  module_release (module);
	  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);
	}
    }

  *handle = err ? NULL : handle_new;

  return err;
}

void
gcry_ac_close (gcry_ac_handle_t handle)
{
  _gcry_init ();
  gcry_core_ac_close (context, handle->handle, 0);
  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
  module_release (handle->module);
  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);
}


/* Key management.  */

gcry_error_t
gcry_ac_key_init (gcry_ac_key_t *key, gcry_ac_handle_t handle,
		  gcry_ac_key_type_t type, gcry_ac_data_t data)
{
  gcry_core_ac_data_t data_new;
  gcry_error_t err;

  _gcry_init ();

  err = ac_data_convert_to_new (data, &data_new);
  if (err)
    goto out;

  /* Hah!  Away with HANDLE.  */
  err = gcry_core_ac_key_init (context, 0, key, type, data_new);
  //  gcry_core_ac_data_destroy (context, 0, data_new);

 out:

  return err;
}

gcry_error_t
gcry_ac_key_pair_generate (gcry_ac_handle_t handle, unsigned int nbits,
			   void *key_spec, gcry_ac_key_pair_t *key_pair,
			   gcry_mpi_t **misc_data)
{
  gcry_core_ac_key_spec_rsa_t key_spec_new;
  gcry_ac_key_spec_rsa_t *key_spec_old;
  void *key_spec_use;
  gcry_error_t err;
  
  _gcry_init ();

  if (handle->id == GCRY_PK_RSA)
    {
      if (key_spec)
	{
	  unsigned long int e;
	  
	  key_spec_old = key_spec;
	  err = gcry_core_mpi_get_ui (context, key_spec_old->e, &e);
	  assert (! err);		/* FIXME? */
	  if (e == 0)
	    key_spec_new.e = 41;
	  else if (e == 1)
	    key_spec_new.e = 65537;
	  else
	    key_spec_new.e = e;
	}
      else
	key_spec_new.e = 65537;
      key_spec_use = &key_spec_new;
    }
  else
    key_spec_use = key_spec;

  err = gcry_core_ac_key_pair_generate (context, handle->handle, 0, nbits,
					key_spec_use, key_pair, misc_data);

  return err;
}

gcry_ac_key_t
gcry_ac_key_pair_extract (gcry_ac_key_pair_t key_pair, gcry_ac_key_type_t which)
{
  _gcry_init ();
  return gcry_core_ac_key_pair_extract (context, 0, key_pair, which);
}

void
gcry_ac_key_destroy (gcry_ac_key_t key)
{
  _gcry_init ();
  gcry_core_ac_key_destroy (context, 0, key);
}

void
gcry_ac_key_pair_destroy (gcry_ac_key_pair_t key_pair)
{
  _gcry_init ();
  gcry_core_ac_key_pair_destroy (context, 0, key_pair);
}

gcry_ac_data_t
gcry_ac_key_data_get (gcry_ac_key_t key)
{
  gcry_core_ac_data_t data_new;
  gcry_ac_data_t data;
  gcry_error_t err;

  _gcry_init ();

  data_new = gcry_core_ac_key_data_get (context, 0, key);
  assert (data_new);		/* FIXME? */

  err = ac_data_convert_from_new (&data, data_new);

  return err ? NULL : data;
}

gcry_error_t
gcry_ac_key_test (gcry_ac_handle_t handle, gcry_ac_key_t key)
{
  _gcry_init ();
  return gcry_core_ac_key_test (context, handle->handle, 0, key);
}

gcry_error_t
gcry_ac_key_get_nbits (gcry_ac_handle_t handle,
		       gcry_ac_key_t key, unsigned int *nbits)
{
  _gcry_init ();
  return gcry_core_ac_key_get_nbits (context, handle->handle, 0, key, nbits);
}

gcry_error_t
gcry_ac_key_get_grip (gcry_ac_handle_t handle, gcry_ac_key_t key,
		      unsigned char *key_grip)
{
  size_t key_grip_size;
  gcry_error_t err;

  _gcry_init ();

  err = gcry_core_ac_key_get_grip (context, handle->handle, 0, key, NULL, &key_grip_size);
  if (err)
    goto out;

  assert (key_grip_size == 20);

  err = gcry_core_ac_key_get_grip (context, handle->handle, 0, key, key_grip, &key_grip_size);

 out:

  return err;
}

gcry_error_t
gcry_ac_data_encrypt (gcry_ac_handle_t handle, unsigned int flags,  gcry_ac_key_t key,
		      gcry_mpi_t data_plain, gcry_ac_data_t *data_encrypted)
{
  gcry_core_ac_data_t data_new;
  gcry_error_t err;

  _gcry_init ();

  data_new = NULL;

  err = gcry_core_ac_data_encrypt (context, handle->handle, flags, key,
				   data_plain, &data_new);
  if (err)
    goto out;

  err = ac_data_convert_from_new (data_encrypted, data_new);
  if (err)
    goto out;

 out:

  gcry_core_ac_data_destroy (context, 0, data_new);

  return err;
}

gcry_error_t
gcry_ac_data_decrypt (gcry_ac_handle_t handle, unsigned int flags,
		      gcry_ac_key_t key, gcry_mpi_t *data_decrypted,
		      gcry_ac_data_t data_encrypted)
{
  gcry_core_ac_data_t data_new;
  gcry_error_t err;

  _gcry_init ();

  data_new = NULL;

  err = ac_data_convert_to_new (data_encrypted, &data_new);
  if (err)
    goto out;

  err = gcry_core_ac_data_decrypt (context, handle->handle, flags, key,
				   data_decrypted, data_new);
  if (err)
    goto out;

 out:

  gcry_core_ac_data_destroy (context, 0, data_new);

  return err;
}

gcry_error_t
gcry_ac_data_sign (gcry_ac_handle_t handle, gcry_ac_key_t key,
		   gcry_mpi_t data, gcry_ac_data_t *data_signed)
{
  gcry_core_ac_data_t data_new;
  gcry_error_t err;

  _gcry_init ();

  data_new = NULL;
  
  err = gcry_core_ac_data_sign (context, handle->handle, 0,
				key, data, &data_new);
  if (err)
    goto out;

  err = ac_data_convert_from_new (data_signed, data_new);
  if (err)
    goto out;

 out:

  gcry_core_ac_data_destroy (context, 0, data_new);

  return err;
}

gcry_error_t
gcry_ac_data_verify (gcry_ac_handle_t handle, gcry_ac_key_t key,
		     gcry_mpi_t data, gcry_ac_data_t data_signed)
{
  gcry_core_ac_data_t data_new;
  gcry_error_t err;

  _gcry_init ();

  data_new = NULL;

  err = ac_data_convert_to_new (data_signed, &data_new);
  if (err)
    goto out;

  err = gcry_core_ac_data_verify (context, handle->handle, 0,
				  key, data, data_new);
  if (err)
    goto out;

 out:

  gcry_core_ac_data_destroy (context, 0, data_new);

  return err;
}

void
gcry_ac_io_init (gcry_ac_io_t *ac_io, gcry_ac_io_mode_t mode,
		 gcry_ac_io_type_t type, ...)
{
  va_list ap;

  _gcry_init ();
  va_start (ap, type);
  gcry_core_ac_io_init_va (context, 0, ac_io, mode, type, ap);
  va_end (ap);
}

void
gcry_ac_io_init_va (gcry_ac_io_t *ac_io, gcry_ac_io_mode_t mode,
		    gcry_ac_io_type_t type, va_list ap)
{
  _gcry_init ();
  gcry_core_ac_io_init_va (context, 0, ac_io, mode, type, ap);
}

gcry_error_t
gcry_ac_data_encode (gcry_ac_em_t method, unsigned int flags, void *opts,
		     gcry_ac_io_t *io_read, gcry_ac_io_t *io_write)
{
  gcry_module_t module;
  gcry_error_t err;
  void *opts_tmp;

  _gcry_init ();

  module = NULL;

  /* We might need to convert the opaque options.  */

  if ((method == GCRY_AC_EMSA_PKCS_V1_5) && opts)
    {
      gcry_ac_emsa_pkcs_v1_5_t *options = opts;
      gcry_core_ac_emsa_pkcs_v1_5_t *options_new;
      gcry_core_md_spec_t md_spec;

      opts_tmp = gcry_core_malloc (context,
				   sizeof (gcry_core_ac_emsa_pkcs_v1_5_t));
      if (! opts_tmp)
	err = gpg_error_from_errno (errno);
      else
	{
	  /* Lookup module specification.  */

	  err = _gcry_md_lookup_module_spec (options->md, &module, &md_spec);
	  if (! err)
	    {
	      options_new = opts_tmp;
	      options_new->md = md_spec;
	      options_new->em_n = options->em_n;
	    }
	}
    }
  else
    {
      opts_tmp = opts;
      err = 0;
    }
  if (err)
    goto out;

  err = gcry_core_ac_data_encode (context, method, flags, opts_tmp,
				  io_read, io_write);

 out:

  if ((method == GCRY_AC_EMSA_PKCS_V1_5) && opts)
    {
      gcry_core_free (context, opts_tmp);
      _gcry_md_release_module (module);
    }

  return err;
}

gcry_error_t
gcry_ac_data_decode (gcry_ac_em_t method, unsigned int flags, void *opts,
		     gcry_ac_io_t *io_read, gcry_ac_io_t *io_write)
{
  gcry_module_t module;
  gcry_error_t err;
  void *opts_tmp;

  _gcry_init ();

  module = NULL;

  /* We might need to convert the opaque options.  */

  if ((method == GCRY_AC_EMSA_PKCS_V1_5) && opts)
    {
      gcry_ac_emsa_pkcs_v1_5_t *options = opts;
      gcry_core_ac_emsa_pkcs_v1_5_t *options_new;
      gcry_core_md_spec_t md_spec;

      opts_tmp = gcry_core_malloc (context,
				   sizeof (gcry_core_ac_emsa_pkcs_v1_5_t));
      if (! opts_tmp)
	err = gpg_error_from_errno (errno);
      else
	{
	  /* Lookup module specification.  */

	  err = _gcry_md_lookup_module_spec (options->md, &module, &md_spec);
	  if (! err)
	    {
	      options_new = opts_tmp;
	      options_new->md = md_spec;
	      options_new->em_n = options->em_n;
	    }
	}
    }
  else
    {
      opts_tmp = opts;
      err = 0;
    }
  if (err)
    goto out;

  err = gcry_core_ac_data_decode (context, method, flags, opts_tmp,
				  io_read, io_write);

 out:

  if ((method == GCRY_AC_EMSA_PKCS_V1_5) && opts)
    {
      gcry_core_free (context, opts_tmp);
      _gcry_md_release_module (module);
    }

  return err;
}

void
gcry_ac_mpi_to_os (gcry_mpi_t mpi, unsigned char *os, size_t os_n)
{
  _gcry_init ();
  gcry_core_ac_mpi_to_os (context, 0, mpi, os, os_n);
}

gcry_error_t
gcry_ac_mpi_to_os_alloc (gcry_mpi_t mpi, unsigned char **os, size_t *os_n)
{
  _gcry_init ();
  return gcry_core_ac_mpi_to_os_alloc (context, 0, mpi, os, os_n);
}

void
gcry_ac_os_to_mpi (gcry_mpi_t mpi, unsigned char *os, size_t os_n)
{
  _gcry_init ();
  gcry_core_ac_os_to_mpi (context, 0, mpi, os, os_n);
}

gcry_error_t
gcry_ac_data_encrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			     unsigned int flags, void *opts, gcry_ac_key_t key,
			     gcry_ac_io_t *io_read, gcry_ac_io_t *io_write)
{
  _gcry_init ();
  return gcry_core_ac_data_encrypt_scheme (context, handle->handle, scheme_id, flags,
					   opts, key, io_read, io_write);
}

gcry_error_t
gcry_ac_data_decrypt_scheme (gcry_ac_handle_t handle,
			     gcry_ac_scheme_t scheme,
			     unsigned int flags, void *opts,
			     gcry_ac_key_t key,
			     gcry_ac_io_t *io_cipher,
			     gcry_ac_io_t *io_message)
{
  _gcry_init ();
  return gcry_core_ac_data_decrypt_scheme (context, handle->handle, scheme, flags, opts,
					   key, io_cipher, io_message);
}

gcry_error_t
gcry_ac_data_sign_scheme (gcry_ac_handle_t handle,
			  gcry_ac_scheme_t scheme,
			  unsigned int flags, void *opts,
			  gcry_ac_key_t key,
			  gcry_ac_io_t *io_message,
			  gcry_ac_io_t *io_signature)
{
  gcry_module_t module;
  gcry_error_t err;
  void *opts_tmp;

  _gcry_init ();

  module = NULL;

  /* We might need to convert the opaque options.  */

  if ((scheme == GCRY_AC_SSA_PKCS_V1_5) && opts)
    {
      gcry_ac_ssa_pkcs_v1_5_t *options = opts;
      gcry_core_ac_ssa_pkcs_v1_5_t *options_new;
      gcry_core_md_spec_t md_spec;

      opts_tmp = gcry_core_malloc (context,
				   sizeof (gcry_core_ac_ssa_pkcs_v1_5_t));
      if (! opts_tmp)
	err = gpg_error_from_errno (errno);
      else
	{
	  /* Lookup module specification.  */

	  err = _gcry_md_lookup_module_spec (options->md, &module, &md_spec);
	  if (! err)
	    {
	      options_new = opts_tmp;
	      options_new->md = md_spec;
	    }
	}
    }
  else
    {
      opts_tmp = opts;
      err = 0;
    }
  if (err)
    goto out;

  err = gcry_core_ac_data_sign_scheme (context, handle->handle, scheme, flags,
				       opts_tmp, key,
				       io_message, io_signature);

 out:

  if ((scheme == GCRY_AC_SSA_PKCS_V1_5) && opts)
    {
      gcry_core_free (context, opts_tmp);
      _gcry_md_release_module (module);
    }

  return err;
}

gcry_error_t
gcry_ac_data_verify_scheme (gcry_ac_handle_t handle,
			    gcry_ac_scheme_t scheme,
			    unsigned int flags, void *opts,
			    gcry_ac_key_t key,
			    gcry_ac_io_t *io_message,
			    gcry_ac_io_t *io_signature)
{
  gcry_module_t module;
  gcry_error_t err;
  void *opts_tmp;

  _gcry_init ();

  module = NULL;

  /* We might need to convert the opaque options.  */

  if ((scheme == GCRY_AC_SSA_PKCS_V1_5) && opts)
    {
      gcry_ac_ssa_pkcs_v1_5_t *options = opts;
      gcry_core_ac_ssa_pkcs_v1_5_t *options_new;
      gcry_core_md_spec_t md_spec;

      opts_tmp = gcry_core_malloc (context,
				   sizeof (gcry_core_ac_ssa_pkcs_v1_5_t));
      if (! opts_tmp)
	err = gpg_error_from_errno (errno);
      else
	{
	  /* Lookup module specification.  */

	  err = _gcry_md_lookup_module_spec (options->md, &module, &md_spec);
	  if (! err)
	    {
	      options_new = opts_tmp;
	      options_new->md = md_spec;
	    }
	}
    }
  else
    {
      opts_tmp = opts;
      err = 0;
    }
  if (err)
    goto out;

  err = gcry_core_ac_data_verify_scheme (context, handle->handle, scheme, flags,
					 opts_tmp,
					 key, io_message, io_signature);

 out:

  if ((scheme == GCRY_AC_SSA_PKCS_V1_5) && opts)
    {
      gcry_core_free (context, opts_tmp);
      _gcry_md_release_module (module);
    }

  return err;
}



/*
 * Support functions for pubkey.c.
 */

/* Mark the algorithm identitified by HANDLE as `disabled'.  */
gcry_error_t
_gcry_ac_algorithm_disable (gcry_ac_handle_t handle)
{
  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
  handle->module->flags |= FLAG_MODULE_DISABLED;
  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);

  return 0;
}

/* Return the amount of `elements' for certain cryptographic objects
   like keys (secret, public) and data (encrypted, signed).  */
void
_gcry_ac_elements_amount_get (gcry_ac_handle_t handle,
			      unsigned int *elements_key_secret,
			      unsigned int *elements_key_public,
			      unsigned int *elements_encrypted,
			      unsigned int *elements_signed)
{
  gcry_core_ac_spec_t algorithm;
  gcry_module_spec_t *spec;

  spec = handle->module->spec;
  algorithm = spec->spec;

  if (elements_key_secret)
    *elements_key_secret = strlen (algorithm->elements_skey);
  if (elements_key_public)
    *elements_key_public = strlen (algorithm->elements_pkey);
  if (elements_encrypted)
    *elements_encrypted = strlen (algorithm->elements_enc);
  if (elements_signed)
    *elements_signed = strlen (algorithm->elements_sig);
}

/* Stores the textual representation of the algorithm whose id is
   given in ALGORITHM in NAME.  */
gcry_error_t
_gcry_ac_id_to_name (gcry_ac_id_t algorithm_id, const char **algorithm_name,
		     int try_alias)
{
  gcry_module_spec_t *spec;
  gcry_module_t module;
  gcry_error_t err;
  const char *name;

  name = NULL;
  
  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
  do
    {
      module = _gcry_module_lookup_id (algorithms_registered, algorithm_id);
      if (! module)
	{
	  err = GPG_ERR_PUBKEY_ALGO;
	  break;
	}

      spec = module->spec;
      if (spec->spec->aliases && spec->spec->aliases[0])
	name = gcry_strdup (spec->spec->aliases[0]);
      else
	name = gcry_strdup (spec->spec->name);
      module_release (module);

      if (! name)
	{
	  err = gpg_error_from_errno (errno);
	  break;
	}
      else
	err = 0;
    }
  while (0);
  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);

  if (err)
    goto out;

  *algorithm_name = name;

 out:

  return err;
}

gcry_error_t
gcry_ac_id_to_name (gcry_ac_id_t algorithm_id, const char **algorithm_name)
{
  _gcry_init ();
  return _gcry_ac_id_to_name (algorithm_id, algorithm_name, 0);
}

/* Stores the numeric ID of the algorithm whose textual representation
   is contained in NAME in ALGORITHM.  */
gcry_error_t
_gcry_ac_name_to_id (const char *name, gcry_ac_id_t *algorithm_id)
{
  gcry_module_t module;
  unsigned int mod_id;
  gcry_error_t err;

  mod_id = 0;

  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
  do
    {
      module = module_lookup_by_name (name);
      if (! module)
	{
	  err = GPG_ERR_PUBKEY_ALGO;
	  break;
	}

      err = 0;
      mod_id = module->mod_id;
      module_release (module);
    }
  while (0);
  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);

  if (err)
    goto out;

  *algorithm_id = mod_id;

 out:

  return err;
}

gcry_error_t
gcry_ac_name_to_id (const char *name, gcry_ac_id_t *algorithm_id)
{
  _gcry_init ();
  return _gcry_ac_name_to_id (name, algorithm_id);
}
  
/* Get a list consisting of the IDs of the loaded ac modules.  If LIST
   is zero, write the number of loaded message digest modules to
   LIST_LENGTH and return.  If LIST is non-zero, the first
   *LIST_LENGTH algorithm IDs are stored in LIST, which must be of
   according size.  In case there are less message digest modules than
   *LIST_LENGTH, *LIST_LENGTH is updated to the correct number.  */
gcry_error_t
_gcry_ac_list (int *list, int *list_length)
{
  gcry_error_t err;

  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
  err = _gcry_module_list (algorithms_registered, list, list_length);
  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);

  return err;
}

/* Convert the MPIs contained in the data set into an arg list
   suitable for passing to gcry_sexp_build_array().  */
gcry_error_t
_gcry_ac_arg_list_from_data (gcry_ac_data_t data, void ***arg_list)
{
  void **arg_list_new;
  unsigned int size;
  gcry_error_t err;
  gcry_mpi_t *mpi_ptr;
  gcry_mpi_t mpi;
  unsigned int i;

  size = gcry_ac_data_length (data);
  if (size)
    {
      arg_list_new = gcry_xcalloc (size, sizeof (void *));
      if (! arg_list_new)
	err = gpg_error_from_errno (errno);
      else
	err = 0;
    }
  else
    {
      arg_list_new = NULL;
      err = 0;
    }
  if (err)
    goto out;

  for (i = 0; i < size; i++)
    {
      err = gcry_ac_data_get_index (data, 0, i, NULL, &mpi);
      if (err)
	break;
      mpi_ptr = gcry_xmalloc (sizeof (*mpi_ptr));
      *mpi_ptr = mpi;
      arg_list_new[i] = mpi_ptr;
    }
  if (err)
    goto out;

  *arg_list = arg_list_new;
  err = 0;

 out:

  if (err)
    {
      if (arg_list_new)
	for (i = 0; i < size; i++)
	  gcry_free (arg_list_new[i]);
    }

  return err;
}

/* Internal function used by pubkey.c.  Extract certain information
   from a given handle.  */
void
_gcry_ac_info_get (gcry_ac_handle_t handle, unsigned int *algorithm_use_flags)
{
  gcry_core_ac_spec_t algorithm;
  gcry_module_spec_t *spec;

  spec = handle->module->spec;
  algorithm = spec->spec;

  if (algorithm_use_flags)
    *algorithm_use_flags = (0
			    | (algorithm->sign
			       ? GCRY_PK_USAGE_SIGN : 0)
			    | (algorithm->encrypt
			       ? GCRY_PK_USAGE_ENCR : 0));
}

/* Register a new pubkey module whose specification can be found in
   PUBKEY.  On success, a new algorithm ID is stored in ALGORITHM_ID
   and a pointer representhing this module is stored in MODULE.  */
gcry_error_t
gcry_ac_register (gcry_ac_spec_t *ac_old,
		  unsigned int *algorithm_id,
		  gcry_module_t *module)
{
  gcry_core_ac_spec_t ac;
  gcry_module_spec_t *spec;
  gcry_error_t err = 0;
  gcry_module_t mod;

  _gcry_init ();

  /* FIXME?  */
  ac = gcry_core_xmalloc (context, sizeof (*ac));
  spec = gcry_core_xmalloc (context, sizeof (*spec));
  
  ac->name = ac_old->name;
  ac->aliases = ac_old->aliases;
  ac->elements_pkey = ac_old->elements_pkey;
  ac->elements_skey = ac_old->elements_skey;
  ac->elements_enc = ac_old->elements_enc;
  ac->elements_sig = ac_old->elements_sig;
  ac->elements_grip = ac_old->elements_grip;
  ac->use = ac_old->use;
  ac->keygrip_size = 20;	/* FIXME?  */
  ac->generate = NULL;
  ac->check_secret_key = NULL;
  ac->encrypt = NULL;
  ac->decrypt = NULL;
  ac->sign = NULL;
  ac->verify = NULL;
  ac->get_nbits = NULL;
  ac->keygrip = NULL;

  spec->spec = ac;
  spec->spec_old = ac_old;

  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
  err = _gcry_module_add (&algorithms_registered, 0, spec, &mod);
  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);

  if (! err)
    {
      *module = mod;
      *algorithm_id = mod->mod_id;
    }

  return err;
}

/* Unregister the pubkey identified by ID, which must have been
   registered with gcry_pk_register.  */
void
gcry_ac_unregister (gcry_module_t module)
{
  gcry_module_spec_t *spec;

  _gcry_init ();
  _gcry_core_ath_mutex_lock (context, &algorithms_registered_lock);
  spec = module->spec;
  if (! ac_spec_in_table_p (spec->spec))
    {
      gcry_core_free (context, spec->spec);
      gcry_core_free (context, spec);
    }
  module_release (module);
  _gcry_core_ath_mutex_unlock (context, &algorithms_registered_lock);
}
