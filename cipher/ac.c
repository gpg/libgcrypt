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

#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

#include "g10lib.h"
#include "cipher.h"
#include "ath.h"
#include "mpi.h"



/* Handle structure.  */
struct gcry_ac_handle
{
  gcry_ac_id_t algorithm;	/* Algorithm ID associated with this
				   handle.  */
  const char *algorithm_name;	/* Name of the algorithm.  */
  unsigned int flags;		/* Flags, not used yet.  */
  gcry_module_t module;	        /* Reference to the algorithm
				   module.  */
};

/* A named MPI value.  */
typedef struct gcry_ac_mpi
{
  const char *name;		/* Name of MPI value. */
  gcry_mpi_t mpi;		/* MPI value.         */
  unsigned int flags;		/* Flags.             */
} gcry_ac_mpi_t;

/* A data set, that is simply a list of named MPI values.  */
struct gcry_ac_data
{
  gcry_ac_mpi_t *data;		/* List of named values.      */
  unsigned int data_n;		/* Number of values in DATA.  */
};

/* A single key.  */
struct gcry_ac_key
{
  gcry_ac_data_t data;		/* Data in native ac structure.  */
  gcry_ac_key_type_t type;	/* Type of the key.              */
};

/* A key pair.  */
struct gcry_ac_key_pair
{
  gcry_ac_key_t public;		/* Public key.  */
  gcry_ac_key_t secret;		/* Secret key.  */
};



/* Given a module reference, return the ac specific structure.  */
#define AC_MOD_SPEC(module) ((gcry_pk_spec_t *) ((module)->spec))

/* Call the function FUNCTION contained in the module MODULE and store
   the return code in ERR.  In case the module does not implement the
   specified function, an error code is returned directly.  */
#define AC_MODULE_CALL(err, module, function, ...)                               \
  {                                                                              \
    gcry_pk_##function##_t func = ((AC_MOD_SPEC (module))->function);            \
    if (func)                                                                    \
      err = (*func) (__VA_ARGS__);                                               \
    else                                                                         \
      {                                                                          \
        log_bug ("ac: no implementation of `%s' for algorithm: %i\n",            \
                 #function, module->mod_id);                                     \
        err = GPG_ERR_PUBKEY_ALGO;                                               \
      }                                                                          \
  }



/* This is the list of the asymmetric algorithms included in the
   library.  */
static struct pubkey_table_entry
{
  gcry_pk_spec_t *algorithm;	/* Algorithm specification.  */
  gcry_ac_id_t algorithm_id;	/* Algorithm ID.             */
} algorithm_table[] =
  {
#if USE_RSA
    { &_gcry_pubkey_spec_rsa, GCRY_AC_RSA },
#endif
#if USE_ELGAMAL
    { &_gcry_pubkey_spec_elg, GCRY_AC_ELG },
    /* FIXME: add entry for ELG_E?  */
#endif
#if USE_DSA
    { &_gcry_pubkey_spec_dsa, GCRY_AC_DSA },
#endif
    { NULL },
  };

/* List of registered algorithm modules.  */
static gcry_module_t algorithms;

/* Lock protecting accesses to ALGORITHMS.  */
static ath_mutex_t algorithms_lock;

/* Locking macros.  */
#define ALGORITHMS_LOCK   ath_mutex_lock   (&algorithms_lock)
#define ALGORITHMS_UNLOCK ath_mutex_unlock (&algorithms_lock)

/* If non-zero, initialization of the ac subsystem is done.  */
static int ac_initialized;

/* Lock, protecting the initialization of the ac subsystem.  */
static ath_mutex_t ac_init_lock;

/* Locking macros.  */
#define AC_INIT_LOCK   ath_mutex_lock   (&ac_init_lock)
#define AC_INIT_UNLOCK ath_mutex_unlock (&ac_init_lock)

/* Convenient macro for initializing the ac subsystem.  */
#define AC_INIT               \
  do                          \
    {                         \
      AC_INIT_LOCK;           \
      if (! ac_initialized)   \
        {                     \
          ac_init ();         \
          ac_initialized = 1; \
        }                     \
      AC_INIT_UNLOCK;         \
    }                         \
  while (0)



/*
 * Progress callback support.
 */

static gcry_handler_progress_t progress_cb;
static void *progress_cb_data;

/* Register CB as a progress callback function, passing CB_DATA for
   each invocation.  */
void
_gcry_ac_progress_register (gcry_handler_progress_t cb,
			    void *cb_data)
{
  progress_cb = cb;
  progress_cb_data = cb_data;
}

/* To be used by algorithm implementations.  */
void
_gcry_ac_progress (const char *identifier, int c)
{
  if (progress_cb)
    progress_cb (progress_cb_data, identifier, c, 0, 0);
}

/* 
 * Module related functions.
 */

/* Internal callback function.  Used via _gcry_module_lookup.  */
static int
gcry_ac_lookup_func_name (void *spec_opaque, void *data)
{
  gcry_pk_spec_t *spec;
  unsigned int i;
  char *name;
  int ret;

  spec = spec_opaque;
  name = data;

  ret = stricmp (name, spec->name);
  if (ret)
    for (i = 0; spec->aliases[i] && ret; i++)
      ret = stricmp (name, spec->aliases[i]);

  return ! ret;
}

/* Internal function.  Lookup a pubkey entry by it's name.  */
static gcry_module_t 
gcry_ac_lookup_name (const char *name)
{
  gcry_module_t algorithm;

  algorithm = _gcry_module_lookup (algorithms,
				   (void *) name, gcry_ac_lookup_func_name);

  return algorithm;
}

/* Register a new algorithm module whose specification can be found in
   ALGORITHM.  On success, a new algorithm ID is stored in
   ALGORITHM_ID and a pointer representhing this module is stored in
   MODULE.  */
gcry_error_t
gcry_ac_register (gcry_pk_spec_t *algorithm,
		  unsigned int *algorithm_id, gcry_module_t *module)
{
  gcry_err_code_t err;
  gcry_module_t mod;

  ALGORITHMS_LOCK;
  err = _gcry_module_add (&algorithms, 0, algorithm, &mod);
  ALGORITHMS_UNLOCK;

  if (err)
    goto out;
  
  *module = mod;
  *algorithm_id = mod->mod_id;

 out:
  
  return err;
}

/* Unregister the algorithm identified by MODULE, which must have been
   registered with gcry_ac_register.  */
void
gcry_ac_unregister (gcry_module_t module)
{
  ALGORITHMS_LOCK;
  _gcry_module_release (module);
  ALGORITHMS_UNLOCK;
}

/* Internal function.  Register all the pubkeys included in
   PUBKEY_TABLE.  Returns zero on success or an error code.  */
static void
gcry_ac_register_algorithms (void)
{
  gcry_err_code_t err;
  unsigned int i;

  ALGORITHMS_LOCK;
  err = 0;
  for (i = 0; algorithm_table[i].algorithm && (! err); i++)
    err = _gcry_module_add (&algorithms,
			    algorithm_table[i].algorithm_id,
			    algorithm_table[i].algorithm, NULL);
  ALGORITHMS_UNLOCK;

  if (err)
    BUG ();
}



/* 
 * Initialization.
 */

/* Initialize the ac subsystem.  */
static void
ac_init (void)
{
  gcry_ac_register_algorithms ();
}

/* Initialize the ac subsystem.  */
gcry_err_code_t
_gcry_ac_init (void)
{
  AC_INIT;

  return 0;
}



/* 
 * Functions for working with data sets.
 */

/* Creates a new, empty data set and stores it in DATA.  */
static gcry_err_code_t
ac_data_new (gcry_ac_data_t *data)
{
  gcry_ac_data_t data_new;
  gcry_err_code_t err;

  data_new = gcry_malloc (sizeof (*data_new));
  if (! data_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
  
  data_new->data = NULL;
  data_new->data_n = 0;
  *data = data_new;
  err = 0;

 out:

  return err;
}

/* Creates a new, empty data set and stores it in DATA.  */
gcry_err_code_t
_gcry_ac_data_new (gcry_ac_data_t *data)
{
  gcry_err_code_t err;

  err = ac_data_new (data);

  return err;
}

/* Creates a new, empty data set and stores it in DATA.  */
gcry_error_t
gcry_ac_data_new (gcry_ac_data_t *data)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_new (data);

  return gcry_error (err);
}

static void
ac_data_values_destroy (gcry_ac_data_t data)
{
  unsigned int i;
  
  for (i = 0; i < data->data_n; i++)
    {
      if (data->data[i].flags & GCRY_AC_FLAG_DEALLOC)
	{
	  gcry_free ((char *) data->data[i].name);
	  gcry_mpi_release (data->data[i].mpi);
	}
    }
}

/* Destroys the data set DATA.  */
static void
ac_data_destroy (gcry_ac_data_t data)
{
  if (data)
    {
      ac_data_values_destroy (data);
      gcry_free (data->data);
      gcry_free (data);
    }
}

/* Destroys the data set DATA.  */
void
_gcry_ac_data_destroy (gcry_ac_data_t data)
{
  return ac_data_destroy (data);
}

/* Destroys the data set DATA.  */
void
gcry_ac_data_destroy (gcry_ac_data_t data)
{
  return _gcry_ac_data_destroy (data);
}

static gcry_err_code_t
ac_data_mpi_copy (gcry_ac_mpi_t *data_mpis, unsigned int data_mpis_n,
		  gcry_ac_mpi_t **data_mpis_cp)
{
  gcry_ac_mpi_t *data_mpis_new;
  gcry_err_code_t err;
  unsigned int i;
  gcry_mpi_t mpi;
  const char *label;

  data_mpis_new = NULL;
  label = NULL;
  mpi = NULL;

  data_mpis_new = gcry_malloc (sizeof (*data_mpis_new) * data_mpis_n);
  if (! data_mpis_new)
    {
      err = gcry_err_code_from_errno (errno);
      goto out;
    }
  memset (data_mpis_new, 0, sizeof (*data_mpis_new) * data_mpis_n);

  for (i = 0; i < data_mpis_n; i++)
    {
      if (data_mpis[i].flags & GCRY_AC_FLAG_DEALLOC)
	{
	  /* FIXME: semantics of FLAG_COPY?? */
	  /* Copy values.  */

	  label = strdup (data_mpis[i].name);
	  mpi = gcry_mpi_copy (data_mpis[i].mpi);
	  if (! (label && mpi))
	    {
	      err = gcry_err_code_from_errno (errno);
	      if (label)
		free ((void *) label);
	      if (mpi)
		gcry_mpi_release (mpi);
	      goto out;
	    }
	}
      else
	{
	  /* Reference existing values.  */

	  label = data_mpis[i].name;
	  mpi = data_mpis[i].mpi;
	}

      data_mpis_new[i].flags = data_mpis[i].flags;
      data_mpis_new[i].name = label;
      data_mpis_new[i].mpi = mpi;
    }

  *data_mpis_cp = data_mpis_new;
  err = 0;

 out:

  if (err)
    {
      if (data_mpis_new)
	{
	  for (i = 0; i < data_mpis_n; i++)
	    if (data_mpis_new[i].flags & GCRY_AC_FLAG_COPY)
	      {
		gcry_free ((void *) data_mpis_new[i].name);
		gcry_mpi_release (data_mpis_new[i].mpi);
	      }
	  gcry_free (data_mpis_new);
	}
    }

  return err;
}

/* Create a copy of the data set DATA and store it in DATA_CP.  */
static gcry_err_code_t
ac_data_copy (gcry_ac_data_t *data_cp, gcry_ac_data_t data)
{
  gcry_ac_mpi_t *data_mpis;
  gcry_ac_data_t data_new;
  gcry_err_code_t err;

  /* Allocate data set.  */
  data_new = gcry_malloc (sizeof (*data_new));
  if (! data_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  err = ac_data_mpi_copy (data->data, data->data_n, &data_mpis);
  if (err)
    goto out;
  
  data_new->data_n = data->data_n;
  data_new->data = data_mpis;
  *data_cp = data_new;

 out:

  if (err)
    gcry_free (data_new);

  return err;
}

/* Create a copy of the data set DATA and store it in DATA_CP.  */
gcry_err_code_t
_gcry_ac_data_copy (gcry_ac_data_t *data_cp, gcry_ac_data_t data)
{
  return ac_data_copy (data_cp, data);
}

/* Create a copy of the data set DATA and store it in DATA_CP.  */
gcry_error_t
gcry_ac_data_copy (gcry_ac_data_t *data_cp, gcry_ac_data_t data)
{
  return gcry_error (_gcry_ac_data_copy (data_cp, data));
}

/* Returns the number of named MPI values inside of the data set
   DATA.  */
static unsigned int
ac_data_length (gcry_ac_data_t data)
{
  return data->data_n;
}

/* Returns the number of named MPI values inside of the data set
   DATA.  */
unsigned int
_gcry_ac_data_length (gcry_ac_data_t data)
{
  return ac_data_length (data);
}
/* Returns the number of named MPI values inside of the data set
   DATA.  */
unsigned int
gcry_ac_data_length (gcry_ac_data_t data)
{
  return _gcry_ac_data_length (data);
}

/* Add the value MPI to DATA with the label NAME.  If FLAGS contains
   GCRY_AC_FLAG_COPY, the data set will contain copies of NAME
   and MPI.  If FLAGS contains GCRY_AC_FLAG_DEALLOC or
   GCRY_AC_FLAG_COPY, the values contained in the data set will
   be deallocated when they are to be removed from the data set.  */
static gcry_err_code_t
ac_data_set (gcry_ac_data_t data, unsigned int flags,
	     const char *name, gcry_mpi_t mpi)
{
  const char *name_final;
  gcry_mpi_t mpi_final;
  gcry_err_code_t err;
  unsigned int i;

  mpi_final = NULL;
  name_final = NULL;

  if (flags & ~(GCRY_AC_FLAG_DEALLOC | GCRY_AC_FLAG_COPY))
    {
      err = GPG_ERR_INV_ARG;
      goto out;
    }

  if (flags & GCRY_AC_FLAG_COPY)
    {
      /* Create copies.  */

      name_final = strdup (name);
      mpi_final = gcry_mpi_copy (mpi);
      if (! (name_final && mpi_final))
	{
	  err = gpg_err_code_from_errno (ENOMEM);
	  if (name_final)
	    free ((void *) name_final);
	  if (mpi_final)
	    gcry_mpi_release (mpi_final);
	  goto out;
	}
    }
  else
    {
      name_final = name;
      mpi_final = mpi;
    }

  /* Search for existing entry.  */
  for (i = 0; i < data->data_n; i++)
    if (! strcmp (name, data->data[i].name))
      break;
  if (i < data->data_n)
    {
      /* An entry for NAME does already exist, deallocate values.  */
      if (data->data[i].flags & GCRY_AC_FLAG_DEALLOC)
	{
	  gcry_free ((char *) data->data[i].name);
	  gcry_mpi_release (data->data[i].mpi);
	}
    }
  else
    {
      /* Create a new entry.  */

      gcry_ac_mpi_t *ac_mpis;

      ac_mpis = gcry_realloc (data->data,
			      sizeof (*data->data) * (data->data_n + 1));
      if (! ac_mpis)
	{
	  err = gpg_err_code_from_errno (errno);
	  goto out;
	}
      
      if (data->data != ac_mpis)
	data->data = ac_mpis;
      data->data_n++;
    }

  data->data[i].name = name_final;
  data->data[i].mpi = mpi_final;
  data->data[i].flags = flags;
  err = 0;

 out:

  if (err)
    {
      if (name_final != name)
	gcry_free ((void *) name_final);
      if (mpi_final != mpi)
	gcry_mpi_release (mpi);
    }

  return err;
}

/* Adds the value MPI to the data set DATA with the label NAME.  If
   there is already a value with that label, it is replaced, otherwise
   a new value is added. */
gcry_err_code_t
_gcry_ac_data_set (gcry_ac_data_t data, unsigned int flags,
		   const char *name, gcry_mpi_t mpi)
{
  return ac_data_set (data, flags, name, mpi);
}

/* Adds the value MPI to the data set DATA with the label NAME.  If
   there is already a value with that label, it is replaced, otherwise
   a new value is added. */
gcry_error_t
gcry_ac_data_set (gcry_ac_data_t data, unsigned int flags,
		  const char *name, gcry_mpi_t mpi)
{
  return gcry_error (_gcry_ac_data_set (data, flags, name, mpi));
}

/* Stores the value labelled with NAME found in the data set DATA in
   MPI.  The returned MPI value will be released in case
   gcry_ac_data_set is used to associate the label NAME with a
   different MPI value.  */
static gcry_err_code_t
ac_data_get_name (gcry_ac_data_t data, unsigned int flags,
		  const char *name, gcry_mpi_t *mpi)
{
  gcry_mpi_t mpi_return;
  gcry_err_code_t err;
  unsigned int i;

  if (flags & ~(GCRY_AC_FLAG_COPY))
    {
      err = GPG_ERR_INV_ARG;
      goto out;
    }

  for (i = 0; i < data->data_n; i++)
    if (! strcmp (data->data[i].name, name))
      break;
  if (i == data->data_n)
    {
      err = GPG_ERR_NOT_FOUND;
      goto out;
    }

  if (flags & GCRY_AC_FLAG_COPY)
    {
      mpi_return = gcry_mpi_copy (data->data[i].mpi);
      if (! mpi_return)
	{
	  err = gpg_err_code_from_errno (errno); /* FIXME? */
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

/* Stores the value labelled with NAME found in the data set DATA in
   MPI.  The returned MPI value will be released in case
   gcry_ac_data_set is used to associate the label NAME with a
   different MPI value.  */
gcry_err_code_t
_gcry_ac_data_get_name (gcry_ac_data_t data, unsigned int flags,
			const char *name, gcry_mpi_t *mpi)
{
  return ac_data_get_name (data, flags, name, mpi);
}

/* Stores the value labelled with NAME found in the data set DATA in
   MPI.  The returned MPI value will be released in case
   gcry_ac_data_set is used to associate the label NAME with a
   different MPI value.  */
gcry_error_t
gcry_ac_data_get_name (gcry_ac_data_t data, unsigned int flags,
		       const char *name, gcry_mpi_t *mpi)
{
  return gcry_error (_gcry_ac_data_get_name (data, flags, name, mpi));
}

/* Stores in NAME and MPI the named MPI value contained in the data
   set DATA with the index INDEX.  NAME or MPI may be NULL.  The
   returned MPI value will be released in case gcry_ac_data_set is
   used to associate the label NAME with a different MPI value.  */
static gcry_err_code_t
ac_data_get_index (gcry_ac_data_t data, unsigned int flags, unsigned int idx,
		   const char **name, gcry_mpi_t *mpi)
{
  const char *name_return;
  gcry_mpi_t mpi_return;
  gcry_err_code_t err;

  if (flags & ~(GCRY_AC_FLAG_COPY))
    {
      err = GPG_ERR_INV_ARG;
      goto out;
    }

  if (idx >= data->data_n)
    {
      err = GPG_ERR_INV_ARG;
      goto out;
    }

  name_return = NULL;
  mpi_return = NULL;
  if (flags & GCRY_AC_FLAG_COPY)
    {
      /* Return copies to the user.  */
      if (name)
	name_return = strdup (data->data[idx].name);
      if (mpi)
	mpi_return = gcry_mpi_copy (data->data[idx].mpi);
      
      if (! (name_return && mpi_return))
	{
	  if (name_return)
	    free ((void *) name_return);
	  if (mpi_return)
	    gcry_mpi_release (mpi_return);
	  err = gcry_err_code_from_errno (ENOMEM);
	  goto out;
	}
    }
  else
    {
      name_return = data->data[idx].name;
      mpi_return = data->data[idx].mpi;
    }

  if (name)
    *name = name_return;
  if (mpi)
    *mpi = mpi_return;
  err = 0;

 out:

  return err;
}

/* Stores in NAME and MPI the named MPI value contained in the data
   set DATA with the index INDEX.  NAME or MPI may be NULL.  The
   returned MPI value will be released in case gcry_ac_data_set is
   used to associate the label NAME with a different MPI value.  */
gcry_err_code_t
_gcry_ac_data_get_index (gcry_ac_data_t data, unsigned int flags, unsigned int index,
			 const char **name, gcry_mpi_t *mpi)
{
  return ac_data_get_index (data, flags, index, name, mpi);
}

/* Stores in NAME and MPI the named MPI value contained in the data
   set DATA with the index INDEX.  NAME or MPI may be NULL.  The
   returned MPI value will be released in case gcry_ac_data_set is
   used to associate the label NAME with a different MPI value.  */
gcry_error_t
gcry_ac_data_get_index (gcry_ac_data_t data, unsigned int flags, unsigned int index,
			const char **name, gcry_mpi_t *mpi)
{
  return gcry_error (_gcry_ac_data_get_index (data, flags, index, name, mpi));
}

gcry_error_t
gcry_ac_data_to_sexp (gcry_ac_data_t data, gcry_sexp_t *sexp,
		      const char **identifiers)
{
  gcry_sexp_t sexp_new;
  gcry_err_code_t err;
  char *sexp_buffer;
  size_t sexp_buffer_n;
  size_t identifiers_n;
  const char *label;
  gcry_mpi_t mpi;
  void **arg_list;
  gcry_mpi_t *mpi_list;
  size_t data_n;
  unsigned int i;

  sexp_buffer = NULL;
  sexp_buffer_n = 3;
  mpi_list = NULL;
  arg_list = NULL;
  err = 0;

  /* Calculate size of S-expression representation.  */

  i = 0;
  if (identifiers)
    while (identifiers[i])
      {
	sexp_buffer_n += 1 + strlen (identifiers[i]) + 1;
	i++;
      }
  identifiers_n = i;
  
  data_n = ac_data_length (data);
  for (i = 0; i < data_n; i++)
    {
      err = gcry_ac_data_get_index (data, 0, i, &label, NULL);
      if (err)
	break;
      sexp_buffer_n += 1 + strlen (label) + 4;
    }
  if (err)
    goto out;

  /* Allocate buffer.  */

  sexp_buffer = gcry_malloc (sexp_buffer_n);
  if (! sexp_buffer)
    {
      err = ENOMEM;
      goto out;
    }

  /* Fill buffer.  */

  *sexp_buffer = 0;
  sexp_buffer_n = 0;
  for (i = 0; i < identifiers_n; i++)
    sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n, "(%s",
			      identifiers[i]);

  sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n, "(");
  arg_list = gcry_malloc (sizeof (*arg_list) * (data_n + 1));
  if (! arg_list)
    {
      err = gcry_err_code_from_errno (errno);
      goto out;
    }

  for (i = 0; i < data_n; i++)
    {
      err = gcry_ac_data_get_index (data, 0, i, &label, &mpi);
      if (err)
	break;
      
      sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n,
				"(%s %%m)", label);

      arg_list[i] = &data->data[i].mpi;
    }

  sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n, ")");
  for (i = 0; i < identifiers_n; i++)
    sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n, ")");

  err = gcry_sexp_build_array (&sexp_new, NULL, sexp_buffer, arg_list);
  if (err)
    goto out;

  *sexp = sexp_new;

 out:

  gcry_free (arg_list);
  gcry_free (mpi_list);
  
  if (err)
    gcry_free (sexp_buffer);

  return gcry_error (err);
}

gcry_error_t
gcry_ac_data_from_sexp (gcry_ac_data_t *data_set, gcry_sexp_t sexp,
			const char **identifiers)
{
  gcry_ac_data_t data_set_new;
  gcry_err_code_t err;
  gcry_sexp_t sexp_cur;
  gcry_sexp_t sexp_tmp;
  gcry_mpi_t mpi;
  char *string;
  const char *data;
  size_t data_n;
  size_t sexp_n;
  unsigned int i;

  sexp_cur = sexp;
  sexp_tmp = NULL;
  string = NULL;
  mpi = NULL;
  err = 0;
  
  /* Process S-expression/identifiers.  */

  i = 0;
  if (identifiers)
    while (identifiers[i])
      {
	data = gcry_sexp_nth_data (sexp_cur, 0, &data_n);
	if ((! data) || strncmp (data, identifiers[i], data_n))
	  {
	    err = GPG_ERR_INV_SEXP;
	    break;
	  }
	sexp_tmp = gcry_sexp_nth (sexp_cur, 1);
	if (! sexp_tmp)
	  {
	    err = GPG_ERR_INTERNAL; /* FIXME? */
	    break;
	  }
	if (sexp_cur != sexp)
	  gcry_sexp_release (sexp_cur);
	sexp_cur = sexp_tmp;
	i++;
      }
  if (err)
    goto out;

  /* Create data set from S-expression data.  */
  
  err = gcry_ac_data_new (&data_set_new);
  if (err)
    goto out;

  sexp_n = gcry_sexp_length (sexp);
  if (sexp_n < 1)
    {
      err = GPG_ERR_INV_SEXP;
      goto out;
    }

  for (i = 0; i < sexp_n; i++)
    {
      sexp_tmp = gcry_sexp_nth (sexp_cur, i);
      if (! sexp_tmp)
	{
	  err = GPG_ERR_INV_SEXP;
	  break;
	}

      data = gcry_sexp_nth_data (sexp_tmp, 0, &data_n);
      string = gcry_malloc (data_n + 1);
      if (! string)
	{
	  err = gcry_err_code_from_errno (ENOMEM);
	  break;
	}
      memcpy (string, data, data_n);
      string[data_n] = 0;

      mpi = gcry_sexp_nth_mpi (sexp_tmp, 1, 0);
      if (! mpi)
	{
	  err = GPG_ERR_INV_SEXP; /* FIXME? */
	  break;
	}

      err = gcry_ac_data_set (data_set_new, GCRY_AC_FLAG_DEALLOC, string, mpi);
      if (err)
	break;

      string = NULL;
      mpi = NULL;

      gcry_sexp_release (sexp_tmp);
    }
  if (err)
    goto out;

  *data_set = data_set_new;

 out:

  gcry_free (string);
  gcry_mpi_release (mpi);
  gcry_sexp_release (sexp_tmp);
  
  if (err)
    gcry_ac_data_destroy (data_set_new);

  return err;
}

/* Destroys any values contained in the data set DATA.  */
static void
ac_data_clear (gcry_ac_data_t data)
{
  ac_data_values_destroy (data);
  gcry_free (data->data);
  data->data = NULL;
  data->data_n = 0;
}

/* Destroys any values contained in the data set DATA.  */
void
_gcry_ac_data_clear (gcry_ac_data_t data)
{
  return ac_data_clear (data);
}

/* Destroys any values contained in the data set DATA.  */
void
gcry_ac_data_clear (gcry_ac_data_t data)
{
  return _gcry_ac_data_clear (data);
}



/*
 * Handle management.
 */

/* Creates a new handle for the algorithm ALGORITHM and store it in
   HANDLE.  FLAGS is not used yet.  */
static gcry_err_code_t
ac_open (gcry_ac_handle_t *handle, gcry_ac_id_t algorithm, unsigned int flags)
{
  gcry_ac_handle_t handle_new;
  gcry_module_t module;
  gcry_err_code_t err;

  AC_INIT;

  ALGORITHMS_LOCK;

  module = _gcry_module_lookup_id (algorithms, algorithm);
  if ((! module) || (module->flags & FLAG_MODULE_DISABLED))
    {
      err = GPG_ERR_PUBKEY_ALGO;
      goto out;
    }

  /* Allocate.  */
  handle_new = gcry_malloc (sizeof (*handle_new));
  if (! handle_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  /* Done.  */
  handle_new->algorithm = algorithm;
  handle_new->flags = flags;
  handle_new->module = module;
  *handle = handle_new;
  err = 0;

 out:

  if (err)
    {
      /* Deallocate resources.  */
      if (module)
	_gcry_module_release (module);
    }

  ALGORITHMS_UNLOCK;

  return err;
}

/* Creates a new handle for the algorithm ALGORITHM and store it in
   HANDLE.  FLAGS is not used yet.  */
gcry_err_code_t
_gcry_ac_open (gcry_ac_handle_t *handle, gcry_ac_id_t algorithm, unsigned int flags)
{
  return ac_open (handle, algorithm, flags);
}

/* Creates a new handle for the algorithm ALGORITHM and store it in
   HANDLE.  FLAGS is not used yet.  */
gcry_error_t
gcry_ac_open (gcry_ac_handle_t *handle, gcry_ac_id_t algorithm, unsigned int flags)
{
  gcry_err_code_t err;

  err = _gcry_ac_open (handle, algorithm, flags);

  return gcry_error (err);
}

/* Destroys the handle HANDLE.  */
static void
ac_close (gcry_ac_handle_t handle)
{
  /* Release reference to pubkey module.  */
  ALGORITHMS_LOCK;
  _gcry_module_release (handle->module);
  ALGORITHMS_UNLOCK;
  gcry_free (handle);
}

/* Destroys the handle HANDLE.  */
void
_gcry_ac_close (gcry_ac_handle_t handle)
{
  ac_close (handle);
}

/* Destroys the handle HANDLE.  */
void
gcry_ac_close (gcry_ac_handle_t handle)
{
  _gcry_ac_close (handle);
}



/* 
 * Key management.
 */

/* Creates a new key of type TYPE, consisting of the MPI values
   contained in the data set DATA and stores it in KEY.  */
gcry_err_code_t
ac_key_init (gcry_ac_key_t *key, gcry_ac_handle_t handle,
	     gcry_ac_key_type_t type, gcry_ac_data_t data)
{
  gcry_ac_data_t data_new;
  gcry_ac_key_t key_new;
  gcry_err_code_t err;

  /* Allocate.  */
  key_new = gcry_malloc (sizeof (*key_new));
  if (! key_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  /* Copy data set.  */
  err = ac_data_copy (&data_new, data);
  if (err)
    goto out;

  /* Done.  */
  key_new->data = data_new;
  key_new->type = type;
  *key = key_new;

 out:

  if (err)
    {
      /* Deallocate resources.  */
      gcry_free (key_new);
    }

  return err;
}

/* Creates a new key of type TYPE, consisting of the MPI values
   contained in the data set DATA and stores it in KEY.  */
gcry_err_code_t
_gcry_ac_key_init (gcry_ac_key_t *key, gcry_ac_handle_t handle,
		   gcry_ac_key_type_t type, gcry_ac_data_t data)
{
  return ac_key_init (key, handle, type, data);
}

/* Creates a new key of type TYPE, consisting of the MPI values
   contained in the data set DATA and stores it in KEY.  */
gcry_error_t
gcry_ac_key_init (gcry_ac_key_t *key, gcry_ac_handle_t handle,
		  gcry_ac_key_type_t type, gcry_ac_data_t data)
{
  gcry_err_code_t err;

  err = _gcry_ac_key_init (key, handle, type, data);

  return gcry_error (err);
}

static gcry_err_code_t
ac_mpi_array_to_data_set (gcry_ac_data_t *data_set,
			  gcry_mpi_t *mpis, const char *elems)
{
  gcry_ac_data_t data_set_new;
  gcry_err_code_t err;
  unsigned int i;
  char name[2];

  err = ac_data_new (&data_set_new);
  if (err)
    goto out;

  name[1] = 0;
  for (i = 0; elems[i]; i++)
    {
      name[0] = elems[i];

      err = ac_data_set (data_set_new, GCRY_AC_FLAG_DEALLOC | GCRY_AC_FLAG_COPY,
			 name, mpis[i]);
      if (err)
	goto out;
    }

  *data_set = data_set_new;

 out:

  if (err)
    gcry_ac_data_destroy (data_set_new);

  return err;
}

static gcry_err_code_t
ac_mpi_array_from_data_set (gcry_ac_data_t data_set,
			    gcry_mpi_t **mpis, const char *elems)
{
  gcry_mpi_t *mpis_new;
  gcry_err_code_t err;
  gcry_mpi_t mpi;
  unsigned int i;
  size_t elems_n;
  char name[2];

  elems_n = strlen (elems);
  mpis_new = gcry_xcalloc (elems_n, sizeof (*mpis_new));
  if (! mpis_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  name[1] = 0;
  for (i = 0; i < elems_n; i++)
    {
      name[0] = elems[i];

      err = ac_data_get_name (data_set, 0, name, &mpi);
      if (err)
	goto out;

      mpis_new[i] = mpi;
    }

  *mpis = mpis_new;
  err = 0;

 out:

  if (err)
    gcry_free (mpis_new);

  return err;
}

static void
ac_mpi_array_release (gcry_mpi_t *mpis)
{
  unsigned int i;
  
  if (mpis)
    {
      for (i = 0; mpis[i]; i++)
	gcry_mpi_release (mpis[i]);
      gcry_free (mpis);
    }
}



/* Generates a new key pair via the handle HANDLE of NBITS bits and
   stores it in KEY_PAIR.  In case non-standard settings are wanted, a
   pointer to a structure of type gcry_ac_key_spec_<algorithm>_t,
   matching the selected algorithm, can be given as KEY_SPEC.  If
   MISC_DATA is non-zero, return an algorithm-dependent list of MPI
   values that were created during the generation process.  */
static gcry_err_code_t
ac_key_pair_generate (gcry_ac_handle_t handle, unsigned int nbits, void *key_spec,
		      gcry_ac_key_pair_t *key_pair, gcry_mpi_t **misc_data)
{
  gcry_err_code_t err;
  gcry_ac_key_pair_t key_pair_new;
  gcry_ac_data_t key_data_secret;
  gcry_ac_data_t key_data_public;
  unsigned long use_e;
  gcry_mpi_t elems_key_secret[10];
  gcry_mpi_t *factors;
  gcry_pk_spec_t *spec;
  gcry_ac_key_t key_secret;
  gcry_ac_key_t key_public;

  spec = AC_MOD_SPEC (handle->module);

  key_data_secret = NULL;
  key_data_public = NULL;
  key_pair_new = NULL;
  key_secret = NULL;
  key_public = NULL;
  factors = NULL;

  /* FIXME: hackish.  */
  if ((handle->algorithm == GCRY_AC_RSA) && key_spec)
    use_e = ((gcry_ac_key_spec_rsa_t *) key_spec)->e;
  else
    use_e = 65537;

  /* Generate keys.  */
  AC_MODULE_CALL (err, handle->module, generate,
		  handle->module->mod_id, nbits, use_e,
		  elems_key_secret, &factors);
  if (err)
    goto out;

  /* Convert MPI array into data sets.  */

  err = ac_mpi_array_to_data_set (&key_data_secret,
				  elems_key_secret, spec->elements_skey);
  if (err)
    goto out;

  err = ac_mpi_array_to_data_set (&key_data_public,
				  elems_key_secret, spec->elements_pkey);
  if (err)
    goto out;

  /* Allocate key pair.  */
  key_pair_new = gcry_malloc (sizeof (*key_pair_new));
  if (! key_pair_new)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  /* Allocate keys.  */
  key_secret = gcry_malloc (sizeof (*key_secret));
  if (! key_secret)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
  key_public = gcry_malloc (sizeof (*key_public));
  if (! key_public)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  key_secret->type = GCRY_AC_KEY_SECRET;
  key_secret->data = key_data_secret;
  key_public->type = GCRY_AC_KEY_PUBLIC;
  key_public->data = key_data_public;
  key_pair_new->secret = key_secret;
  key_pair_new->public = key_public;

  *key_pair = key_pair_new;
  if (misc_data)
    *misc_data = factors;

 out:

  /* Deallocate resources.  */

  if (factors && ((! misc_data) || err))
    ac_mpi_array_release (factors);

  if (err)
    {
      ac_data_destroy (key_data_secret);
      ac_data_destroy (key_data_public);
      gcry_free (key_secret);
      gcry_free (key_public);
      gcry_free (key_pair_new);
    }

  return err;
}

/* Generates a new key pair via the handle HANDLE of NBITS bits and
   stores it in KEY_PAIR.  In case non-standard settings are wanted, a
   pointer to a structure of type gcry_ac_key_spec_<algorithm>_t,
   matching the selected algorithm, can be given as KEY_SPEC.  */
gcry_err_code_t
_gcry_ac_key_pair_generate (gcry_ac_handle_t handle, unsigned int nbits,
			    void *key_spec, gcry_ac_key_pair_t *key_pair,
			    gcry_mpi_t **misc_data)
{
  return ac_key_pair_generate (handle, nbits, key_spec, key_pair, misc_data);
}

/* Generates a new key pair via the handle HANDLE of NBITS bits and
   stores it in KEY_PAIR.  In case non-standard settings are wanted, a
   pointer to a structure of type gcry_ac_key_spec_<algorithm>_t,
   matching the selected algorithm, can be given as KEY_SPEC.  */
gcry_error_t
gcry_ac_key_pair_generate (gcry_ac_handle_t handle, unsigned int nbits,
			   void *key_spec, gcry_ac_key_pair_t *key_pair,
			   gcry_mpi_t **misc_data)
{
  return gcry_error (_gcry_ac_key_pair_generate (handle, nbits, key_spec,
						 key_pair, misc_data));
}

/* Returns the key of type WHICH out of the key pair KEY_PAIR.  */
static gcry_ac_key_t
ac_key_pair_extract (gcry_ac_key_pair_t key_pair, gcry_ac_key_type_t which)
{
  gcry_ac_key_t key;

  switch (which)
    {
    case GCRY_AC_KEY_SECRET:
      key = key_pair->secret;
      break;

    case GCRY_AC_KEY_PUBLIC:
      key = key_pair->public;
      break;

    default:
      key = NULL;
      break;
    }

  return key;
}

/* Returns the key of type WHICH out of the key pair KEY_PAIR.  */
gcry_ac_key_t
_gcry_ac_key_pair_extract (gcry_ac_key_pair_t key_pair, gcry_ac_key_type_t which)
{
  return ac_key_pair_extract (key_pair, which);
}

/* Returns the key of type WHICH out of the key pair KEY_PAIR.  */
gcry_ac_key_t
gcry_ac_key_pair_extract (gcry_ac_key_pair_t key_pair, gcry_ac_key_type_t which)
{
  return _gcry_ac_key_pair_extract (key_pair, which);
}

/* Destroys the key KEY.  */
static void
key_destroy (gcry_ac_key_t key)
{
  ac_data_destroy (key->data);
  gcry_free (key);
}

/* Destroys the key KEY.  */
void
_gcry_ac_key_destroy (gcry_ac_key_t key)
{
  key_destroy (key);
}

/* Destroys the key KEY.  */
void
gcry_ac_key_destroy (gcry_ac_key_t key)
{
  _gcry_ac_key_destroy (key);
}

/* Destroys the key pair KEY_PAIR.  */
static void
key_pair_destroy (gcry_ac_key_pair_t key_pair)
{
  key_destroy (key_pair->secret);
  key_destroy (key_pair->public);
  gcry_free (key_pair);
}

/* Destroys the key pair KEY_PAIR.  */
void
_gcry_ac_key_pair_destroy (gcry_ac_key_pair_t key_pair)
{
  key_pair_destroy (key_pair);
}

/* Destroys the key pair KEY_PAIR.  */
void
gcry_ac_key_pair_destroy (gcry_ac_key_pair_t key_pair)
{
  _gcry_ac_key_pair_destroy (key_pair);
}

/* Returns the data set contained in the key KEY.  */
gcry_ac_data_t
_gcry_ac_key_data_get (gcry_ac_key_t key)
{
  return key->data;
}

/* Returns the data set contained in the key KEY.  */
gcry_ac_data_t
gcry_ac_key_data_get (gcry_ac_key_t key)
{
  return _gcry_ac_key_data_get (key);
}

/* Verifies that the key KEY is sane.  */
static gcry_err_code_t
key_test (gcry_ac_handle_t handle, gcry_ac_key_t key)
{
  gcry_pk_spec_t *spec;
  gcry_err_code_t err;
  gcry_mpi_t *mpis;

  spec = AC_MOD_SPEC (handle->module);

  err = ac_mpi_array_from_data_set (key->data, &mpis, spec->elements_skey);
  if (err)
    goto out;

  AC_MODULE_CALL (err, handle->module, check_secret_key,
		  handle->module->mod_id, mpis);
  gcry_free (mpis);

 out:

  return err;
}

/* Verifies that the key KEY is sane.  */
gcry_err_code_t
_gcry_ac_key_test (gcry_ac_handle_t handle, gcry_ac_key_t key)
{
  return key_test (handle, key);
}

/* Verifies that the key KEY is sane.  */
gcry_error_t
gcry_ac_key_test (gcry_ac_handle_t handle, gcry_ac_key_t key)
{
  gcry_error_t err;

  err = _gcry_ac_key_test (handle, key);

  return gcry_error (err);
}

/* Stores the number of bits of the key KEY in NBITS.  */
static gcry_err_code_t
key_get_nbits (gcry_ac_handle_t handle,
	       gcry_ac_key_t key, unsigned int *nbits)
{
  unsigned int nbits_new;
  gcry_pk_spec_t *spec;
  gcry_err_code_t err;
  gcry_mpi_t *mpis;

  spec = AC_MOD_SPEC (handle->module);

  err = ac_mpi_array_from_data_set (key->data, &mpis, spec->elements_pkey);
  if (err)
    goto out;

  AC_MODULE_CALL (nbits_new, handle->module, get_nbits,
		  handle->module->mod_id, mpis);
  gcry_free (mpis);
  if (err)
    goto out;
  
  *nbits = nbits_new;

 out:

  return err;
}

/* Stores the number of bits of the key KEY in NBITS.  */
gcry_err_code_t
_gcry_ac_key_get_nbits (gcry_ac_handle_t handle,
			gcry_ac_key_t key, unsigned int *nbits)
{
  return key_get_nbits (handle, key, nbits);
}

gcry_error_t
gcry_ac_key_get_nbits (gcry_ac_handle_t handle,
		       gcry_ac_key_t key, unsigned int *nbits)
{
  gcry_err_code_t err;

  err = _gcry_ac_key_get_nbits (handle, key, nbits);

  return gcry_error (err);
}

/* Writes the 20 byte long key grip of the key KEY to KEY_GRIP.  */
static gcry_err_code_t
key_get_grip (gcry_ac_handle_t handle, gcry_ac_key_t key,
	      unsigned char *key_grip)
{
  gcry_pk_spec_t *spec;
  gcry_err_code_t err;
  unsigned char *mpi_buffer;
  size_t mpi_buffer_size;
  gcry_mpi_t mpi;
  gcry_md_hd_t md;
  unsigned int i;
  char buf[2];
  int is_rsa;
  
  spec = AC_MOD_SPEC (handle->module);

  is_rsa = (handle->module->mod_id == GCRY_PK_RSA);
  buf[0] = 0;

  err = gcry_md_open (&md, GCRY_MD_SHA1, 0); /* FIXME: err code vs. error.  */
  if (err)
    goto out;

  for (i = 0; spec->elements_pkey[i]; i++)
    {
      buf[1] = spec->elements_pkey[i];

      err = ac_data_get_name (key->data, 0, buf, &mpi);
      if (err)
	break;
	  
      err = gcry_mpi_aprint (GCRYMPI_FMT_USG,
			     &mpi_buffer, &mpi_buffer_size, mpi);
      if (err)
	break;

      if (! is_rsa)
	{
	  char buffer[30];
	  sprintf (buffer, "(1:%c%u:",
		   spec->elements_pkey[i], (unsigned int) mpi_buffer_size);
	  gcry_md_write (md, buffer, strlen (buffer));
	}

      gcry_md_write (md, mpi_buffer, mpi_buffer_size);
      gcry_free (mpi_buffer);
      mpi_buffer = NULL;

      if (! is_rsa)
	gcry_md_write (md, ")", 1);
    }
  if (err)
    goto out;

  memcpy (key_grip, gcry_md_read (md, GCRY_MD_SHA1), 20);

 out:

  gcry_md_close (md);
  gcry_free (mpi_buffer);

  return err;
}

/* Writes the 20 byte long key grip of the key KEY to KEY_GRIP.  */
gcry_err_code_t
_gcry_ac_key_get_grip (gcry_ac_handle_t handle, gcry_ac_key_t key,
		       unsigned char *key_grip)
{
  return key_get_grip (handle, key, key_grip);
}

/* Writes the 20 byte long key grip of the key KEY to KEY_GRIP.  */
gcry_error_t
gcry_ac_key_get_grip (gcry_ac_handle_t handle, gcry_ac_key_t key,
		      unsigned char *key_grip)
{
  gcry_err_code_t err;

  err = _gcry_ac_key_get_grip (handle, key, key_grip);

  return gcry_error (err);
}



/* 
 * Functions performing cryptographic operations.
 */

/* Encrypts the plain text MPI value DATA_PLAIN with the public key
   KEY under the control of the flags FLAGS and stores the resulting
   data set into DATA_ENCRYPTED.  */
static gcry_err_code_t
ac_data_encrypt (gcry_ac_handle_t handle, unsigned int flags, gcry_ac_key_t key,
		 gcry_mpi_t data_plain, gcry_ac_data_t *data_encrypted)
{
  gcry_ac_data_t data_encrypted_new;
  gcry_pk_spec_t *spec;
  gcry_err_code_t err;
  gcry_mpi_t *mpis_encrypted;
  gcry_mpi_t *pkey;

  spec = AC_MOD_SPEC (handle->module);
  mpis_encrypted = NULL;
  pkey = NULL;

  if (key->type != GCRY_AC_KEY_PUBLIC)
    {
      err = GPG_ERR_WRONG_KEY_USAGE;
      goto out;
    }

  err = ac_mpi_array_from_data_set (key->data, &pkey, spec->elements_pkey);
  if (err)
    goto out;

  mpis_encrypted = gcry_xcalloc (strlen (spec->elements_enc) + 1,
				 sizeof (*mpis_encrypted));
  if (! mpis_encrypted)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  /* Encrypt.  */
  AC_MODULE_CALL (err, handle->module, encrypt, handle->module->mod_id,
		  mpis_encrypted, data_plain, pkey, flags);
  if (err)
    goto out;

  /* Convert encrypted data into data set.  */
  err = ac_mpi_array_to_data_set (&data_encrypted_new,
				  mpis_encrypted, spec->elements_enc);
  if (err)
    goto out;

  gcry_free (mpis_encrypted);
  mpis_encrypted = NULL;

  *data_encrypted = data_encrypted_new;

 out:

  /* Deallocate resources.  */
  ac_mpi_array_release (mpis_encrypted);
  gcry_free (pkey);

  return err;
}

/* Encrypts the plain text MPI value DATA_PLAIN with the public key
   KEY under the control of the flags FLAGS and stores the resulting
   data set into DATA_ENCRYPTED.  */
gcry_err_code_t
_gcry_ac_data_encrypt (gcry_ac_handle_t handle, unsigned int flags,
		       gcry_ac_key_t key, gcry_mpi_t data_plain,
		       gcry_ac_data_t *data_encrypted)
{
  return ac_data_encrypt (handle, flags, key, data_plain, data_encrypted);
}

/* Encrypts the plain text MPI value DATA_PLAIN with the public key
   KEY under the control of the flags FLAGS and stores the resulting
   data set into DATA_ENCRYPTED.  */
gcry_error_t
gcry_ac_data_encrypt (gcry_ac_handle_t handle, unsigned int flags,  gcry_ac_key_t key,
		      gcry_mpi_t data_plain, gcry_ac_data_t *data_encrypted)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_encrypt (handle, flags, key, data_plain, data_encrypted);

  return gcry_error (err);
}

/* Decrypts the encrypted data contained in the data set
   DATA_ENCRYPTED with the secret key KEY under the control of the
   flags FLAGS and stores the resulting plain text MPI value in
   DATA_PLAIN.  */
static gcry_err_code_t
ac_data_decrypt (gcry_ac_handle_t handle, unsigned int flags, gcry_ac_key_t key,
		 gcry_mpi_t *data_decrypted, gcry_ac_data_t data_encrypted)
{
  gcry_mpi_t data_decrypted_new;
  gcry_pk_spec_t *spec;
  gcry_err_code_t err;
  gcry_mpi_t *mpis_encrypted;
  gcry_mpi_t *skey;

  spec = AC_MOD_SPEC (handle->module);
  mpis_encrypted = NULL;
  skey = NULL;

  if (key->type != GCRY_AC_KEY_SECRET)
    {
      err = GPG_ERR_WRONG_KEY_USAGE;
      goto out;
    }

  /* Convert key.  */
  err = ac_mpi_array_from_data_set (key->data, &skey, spec->elements_skey);
  if (err)
    goto out;

  /* Convert encrypted data.  */
  err = ac_mpi_array_from_data_set (data_encrypted,
				    &mpis_encrypted, spec->elements_enc);
  if (err)
    goto out;

  /* Decrypt.  */
  AC_MODULE_CALL (err, handle->module, decrypt, handle->module->mod_id,
		  &data_decrypted_new, mpis_encrypted, skey, flags);
  if (err)
    goto out;

  *data_decrypted = data_decrypted_new;

 out:

  /* Deallocate resources.  */
  gcry_free (mpis_encrypted);
  gcry_free (skey);

  return err;
}

/* Decrypts the encrypted data contained in the data set
   DATA_ENCRYPTED with the secret key KEY under the control of the
   flags FLAGS and stores the resulting plain text MPI value in
   DATA_PLAIN.  */
gcry_err_code_t
_gcry_ac_data_decrypt (gcry_ac_handle_t handle, unsigned int flags,
		       gcry_ac_key_t key, gcry_mpi_t *data_decrypted,
		       gcry_ac_data_t data_encrypted)
{
  return ac_data_decrypt (handle, flags, key, data_decrypted, data_encrypted);
}

/* Decrypts the encrypted data contained in the data set
   DATA_ENCRYPTED with the secret key KEY under the control of the
   flags FLAGS and stores the resulting plain text MPI value in
   DATA_PLAIN.  */
gcry_error_t
gcry_ac_data_decrypt (gcry_ac_handle_t handle, unsigned int flags,
		      gcry_ac_key_t key, gcry_mpi_t *data_decrypted,
		      gcry_ac_data_t data_encrypted)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_decrypt (handle, flags, key, data_decrypted, data_encrypted);

  return gcry_error (err);
}

/* Signs the data contained in DATA with the secret key KEY and stores
   the resulting signature data set in DATA_SIGNATURE.  */
static gcry_err_code_t
ac_data_sign (gcry_ac_handle_t handle,  gcry_ac_key_t key,
	      gcry_mpi_t data, gcry_ac_data_t *data_signed)
{
  gcry_ac_data_t data_signed_new;
  gcry_pk_spec_t *spec;
  gcry_err_code_t err;
  gcry_mpi_t *mpis_signature;
  gcry_mpi_t *skey;

  spec = AC_MOD_SPEC (handle->module);
  mpis_signature = NULL;
  skey = NULL;

  if (key->type != GCRY_AC_KEY_SECRET)
    {
      err = GPG_ERR_WRONG_KEY_USAGE;
      goto out;
    }

  /* Convert key.  */
  err = ac_mpi_array_from_data_set (key->data, &skey, spec->elements_skey);
  if (err)
    goto out;

  mpis_signature = gcry_xcalloc (strlen (spec->elements_sig) + 1,
				 sizeof (*mpis_signature));
  if (! mpis_signature)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  /* Sign.  */
  AC_MODULE_CALL (err, handle->module, sign, handle->module->mod_id,
		  mpis_signature, data, skey);
  if (err)
    goto out;

  /* Convert signed data into data set.  */
  err = ac_mpi_array_to_data_set (&data_signed_new,
				  mpis_signature, spec->elements_sig);
  if (err)
    goto out;

  gcry_free (mpis_signature);
  mpis_signature = NULL;

  *data_signed = data_signed_new;

 out:
  
  /* Deallocate resources.  */
  ac_mpi_array_release (mpis_signature);
  gcry_free (skey);

  return err;
}

/* Signs the data contained in DATA with the secret key KEY and stores
   the resulting signature data set in DATA_SIGNATURE.  */
gcry_err_code_t
_gcry_ac_data_sign (gcry_ac_handle_t handle, gcry_ac_key_t key,
		    gcry_mpi_t data, gcry_ac_data_t *data_signed)
{
  return ac_data_sign (handle, key, data, data_signed);
}

/* Signs the data contained in DATA with the secret key KEY and stores
   the resulting signature data set in DATA_SIGNATURE.  */
gcry_error_t
gcry_ac_data_sign (gcry_ac_handle_t handle, gcry_ac_key_t key,
		   gcry_mpi_t data, gcry_ac_data_t *data_signed)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_sign (handle, key, data, data_signed);

  return gcry_error (err);
}

/* Verifies that the signature contained in the data set
   DATA_SIGNATURE is indeed the result of signing the data contained
   in DATA with the secret key belonging to the public key KEY.  */
static gcry_err_code_t
ac_data_verify (gcry_ac_handle_t handle, gcry_ac_key_t key,
		gcry_mpi_t data, gcry_ac_data_t data_signed)
{
  gcry_mpi_t *mpis_signature;
  gcry_pk_spec_t *spec;
  gcry_err_code_t err;
  gcry_mpi_t *pkey;

  spec = AC_MOD_SPEC (handle->module);
  mpis_signature = NULL;
  pkey = NULL;

  if (key->type != GCRY_AC_KEY_PUBLIC)
    {
      err = GPG_ERR_WRONG_KEY_USAGE;
      goto out;
    }

  err = ac_mpi_array_from_data_set (key->data, &pkey, spec->elements_pkey);
  if (err)
    goto out;

  err = ac_mpi_array_from_data_set (data_signed,
				    &mpis_signature, spec->elements_sig);
  if (err)
    goto out;

  /* Verify signature.  */
  AC_MODULE_CALL (err, handle->module, verify, handle->module->mod_id,
		  data, mpis_signature, pkey, NULL, NULL);
  if (err)
    goto out;

 out:

  gcry_free (mpis_signature);
  gcry_free (pkey);

  return err;
}

/* Verifies that the signature contained in the data set
   DATA_SIGNATURE is indeed the result of signing the data contained
   in DATA with the secret key belonging to the public key KEY.  */
gcry_err_code_t
_gcry_ac_data_verify (gcry_ac_handle_t handle, gcry_ac_key_t key,
		      gcry_mpi_t data, gcry_ac_data_t data_signed)
{
  return ac_data_verify (handle, key, data, data_signed);
}

/* Verifies that the signature contained in the data set
   DATA_SIGNATURE is indeed the result of signing the data contained
   in DATA with the secret key belonging to the public key KEY.  */
gcry_error_t
gcry_ac_data_verify (gcry_ac_handle_t handle,
		     gcry_ac_key_t key,
		     gcry_mpi_t data,
		     gcry_ac_data_t data_signed)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_verify (handle, key, data, data_signed);

  return gcry_error (err);
}



/* 
 * General functions.
 */

/* Stores the textual representation of the algorithm whose id is
   given in ALGORITHM in NAME.  */
static gcry_err_code_t
ac_id_to_name (gcry_ac_id_t algorithm_id, const char **algorithm_name)
{
  gcry_module_t module;
  gcry_err_code_t err;
  const char *name;
  
  AC_INIT;

  name = NULL;
  err = 0;

  ALGORITHMS_LOCK;
  do
    {
      module = _gcry_module_lookup_id (algorithms, algorithm_id);
      if (! module)
	{
	  err = GPG_ERR_PUBKEY_ALGO;
	  break;
	}

      name = strdup ((AC_MOD_SPEC (module))->name);
      _gcry_module_release (module);
      if (! name)
	{
	  err = gpg_err_code_from_errno (errno);
	  break;
	}
    }
  while (0);
  ALGORITHMS_UNLOCK;
  if (err)
    goto out;

  *algorithm_name = name;

 out:

  return err;
}

/* Stores the textual representation of the algorithm whose id is
   given in ALGORITHM in NAME.  */
gcry_err_code_t
_gcry_ac_id_to_name (gcry_ac_id_t algorithm_id, const char **algorithm_name)
{
  return ac_id_to_name (algorithm_id, algorithm_name);
}

/* Stores the textual representation of the algorithm whose id is
   given in ALGORITHM in NAME.  */
gcry_error_t
gcry_ac_id_to_name (gcry_ac_id_t algorithm_id, const char **algorithm_name)
{
  gcry_err_code_t err;
  
  err = _gcry_ac_id_to_name (algorithm_id, algorithm_name);

  return gcry_error (err);
}

/* Stores the numeric ID of the algorithm whose textual representation
   is contained in NAME in ALGORITHM.  */
static gcry_err_code_t
ac_name_to_id (const char *name, gcry_ac_id_t *algorithm_id)
{
  gcry_module_t module;
  gcry_err_code_t err;
  unsigned int mod_id;

  AC_INIT;

  mod_id = 0;
  err = 0;

  ALGORITHMS_LOCK;
  do
    {
      module = gcry_ac_lookup_name (name);
      if (! module)
	{
	  err = GPG_ERR_PUBKEY_ALGO;
	  break;
	}

      mod_id = module->mod_id;
      _gcry_module_release (module);
    }
  while (0);
  ALGORITHMS_UNLOCK;
  if (err)
    goto out;

  *algorithm_id = mod_id;

 out:

  return err;
}

/* Stores the numeric ID of the algorithm whose textual representation
   is contained in NAME in ALGORITHM.  */
gcry_err_code_t
_gcry_ac_name_to_id (const char *name, gcry_ac_id_t *algorithm_id)
{
  return ac_name_to_id (name, algorithm_id);
}

/* Stores the numeric ID of the algorithm whose textual representation
   is contained in NAME in ALGORITHM.  */
gcry_error_t
gcry_ac_name_to_id (const char *name, gcry_ac_id_t *algorithm_id)
{
  gcry_err_code_t err;

  err = _gcry_ac_name_to_id (name, algorithm_id);

  return gcry_error (err);
}

/* Get a list consisting of the IDs of the loaded ac modules.  If LIST
   is zero, write the number of loaded message digest modules to
   LIST_LENGTH and return.  If LIST is non-zero, the first
   *LIST_LENGTH algorithm IDs are stored in LIST, which must be of
   according size.  In case there are less message digest modules than
   *LIST_LENGTH, *LIST_LENGTH is updated to the correct number.  */
static gcry_error_t
ac_list (int *list, int *list_length)
{
  gcry_err_code_t err;

  AC_INIT;

  ALGORITHMS_LOCK;
  err = _gcry_module_list (algorithms, list, list_length);
  ALGORITHMS_UNLOCK;

  return err;
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
  return ac_list (list, list_length);
}

/* Get a list consisting of the IDs of the loaded algorithm modules.
   If LIST is zero, write the number of loaded pubkey modules to
   LIST_LENGTH and return.  If LIST is non-zero, the first
   *LIST_LENGTH algorithm IDs are stored in LIST, which must be of
   according size.  In case there are less pubkey modules than
   *LIST_LENGTH, *LIST_LENGTH is updated to the correct number.  */
gcry_error_t
gcry_ac_list (int *list, int *list_length)
{
  gcry_err_code_t err;

  err = _gcry_ac_list (list, list_length);

  return gcry_error (err);
}



/*
 * Implementation of encoding methods (em).
 */

/* Type for functions that encode or decode (hence the name) a
   message.  */
typedef gcry_err_code_t (*gcry_ac_em_dencode_t) (unsigned int flags,
						 void *options,
						 unsigned char *in,
						 size_t in_n,
						 unsigned char **out,
						 size_t *out_n);

/* Fill the buffer BUFFER which is BUFFER_N bytes long with non-zero
   random bytes of random level LEVEL.  */
static void
em_randomize_nonzero (unsigned char *buffer, size_t buffer_n,
		      gcry_random_level_t level)
{
  unsigned char *buffer_rand;
  unsigned int buffer_rand_n;
  unsigned int zeros;
  unsigned int i;
  unsigned int j;

  for (i = 0; i < buffer_n; i++)
    buffer[i] = 0;
  
  do
    {
      /* Count zeros.  */
      for (i = zeros = 0; i < buffer_n; i++)
	if (! buffer[i])
	  zeros++;

      if (zeros)
	{
	  /* Get random bytes.  */
	  buffer_rand_n = zeros + (zeros / 128);
	  buffer_rand = gcry_random_bytes_secure (buffer_rand_n, level);

	  /* Substitute zeros with non-zero random bytes.  */
	  for (i = j = 0; zeros && (i < buffer_n) && (j < buffer_rand_n); i++)
	    if (! buffer[i])
	      {
		while ((j < buffer_rand_n) && (! buffer_rand[j]))
		  j++;
		if (j < buffer_rand_n)
		  {
		    buffer[i] = buffer_rand[j++];
		    zeros--;
		  }
		else
		  break;
	      }
	  gcry_free (buffer_rand);
	}
    }
  while (zeros);
}

/* Encode a message according to the Encoding Method for Encryption
   `PKCS-V1_5' (EME-PKCS-V1_5).  */
static gcry_err_code_t
eme_pkcs_v1_5_encode (unsigned int flags, void *opts,
		      unsigned char *m, size_t m_n,
		      unsigned char **em, size_t *em_n)
{
  gcry_ac_eme_pkcs_v1_5_t *options;
  gcry_err_code_t err;
  unsigned char *buffer;
  unsigned char *ps;
  unsigned int ps_n;
  unsigned int k;

  options = opts;

  /* Figure out key length in bytes.  */
  err = _gcry_ac_key_get_nbits (options->handle, options->key, &k);
  if (err)
    goto out;

  k /= 8;
  if (m_n > k - 11)
    {
      /* Key is too short for message.  */
      err = GPG_ERR_TOO_SHORT;
      goto out;
    }

  /* Allocate buffer.  */
  buffer = gcry_malloc (k);
  if (! buffer)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  /* Generate an octet string PS of length k - mLen - 3 consisting
     of pseudorandomly generated nonzero octets.  The length of PS
     will be at least eight octets.  */
  ps_n = k - m_n - 3;
  ps = buffer + 2;
  em_randomize_nonzero (ps, ps_n, GCRY_STRONG_RANDOM);

  /* Concatenate PS, the message M, and other padding to form an
     encoded message EM of length k octets as:

     EM = 0x00 || 0x02 || PS || 0x00 || M.  */

  buffer[0] = 0x00;
  buffer[1] = 0x02;
  buffer[ps_n + 2] = 0x00;
  memcpy (buffer + ps_n + 3, m, m_n);
  *em = buffer;
  *em_n = k;

 out:

  return err;
}

/* Decode a message according to the Encoding Method for Encryption
   `PKCS-V1_5' (EME-PKCS-V1_5).  */
static gcry_err_code_t
eme_pkcs_v1_5_decode (unsigned int flags, void *opts,
		      unsigned char *em, size_t em_n,
		      unsigned char **m, size_t *m_n)
{
  unsigned char *buffer;
  gcry_err_code_t err;
  unsigned int i;

  if (! ((em_n >= 12) && (em[0] == 0x00) && (em[1] == 0x02)))
    {
      err = GPG_ERR_TOO_SHORT;	/* FIXME: err code always
				   appropriate?  */
      goto out;
    }

  for (i = 2; (i < em_n) && em[i]; i++);
  i++;

  if ((i == em_n) || ((i - 2) < 8))
    {
      err = GPG_ERR_INTERNAL;	/* FIXME?  */
      goto out;
    }

  buffer = gcry_malloc (em_n - i);
  if (! buffer)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  memcpy (buffer, em + i, em_n - i);
  *m = buffer;
  *m_n = em_n - i;
  err = 0;

 out:

  return err;
}

/* Encode a message according to the Encoding Method for Signatures
   with Appendix `PKCS-V1_5' (EMSA-PKCS-V1_5).  */
static gcry_err_code_t
emsa_pkcs_v1_5_encode (unsigned int flags, void *opts,
		       unsigned char *m, size_t m_n,
		       unsigned char **em, size_t *em_n)
{
  gcry_ac_emsa_pkcs_v1_5_t *options;
  gcry_err_code_t err;
  gcry_md_hd_t md;
  unsigned char *t;
  size_t t_n;
  unsigned char *h;
  size_t h_n;
  unsigned char *ps;
  size_t ps_n;
  unsigned char *buffer;
  size_t buffer_n;
  unsigned char asn[100];	/* FIXME, always enough?  */
  size_t asn_n;
  unsigned int i;
  
  options = opts;
  md = NULL;
  ps = NULL;
  t = NULL;

  /* Create hashing handle and get the necessary information.  */
  err = gcry_md_open (&md, options->md, 0);
  if (err)
    goto out;

  asn_n = DIM (asn);
  err = gcry_md_algo_info (options->md, GCRYCTL_GET_ASNOID, asn, &asn_n);
  if (err)
    goto out;

  h_n = gcry_md_get_algo_dlen (options->md);

  /* Apply the hash function to the message M to produce a hash
     value H.  */
  gcry_md_write (md, m, m_n);

  h = gcry_md_read (md, 0);

  /* Encode the algorithm ID for the hash function and the hash value
     into an ASN.1 value of type DigestInfo with the Distinguished
     Encoding Rules (DER), where the type DigestInfo has the syntax:

     DigestInfo ::== SEQUENCE {
     digestAlgorithm AlgorithmIdentifier,
     digest OCTET STRING
     }

     The first field identifies the hash function and the second
     contains the hash value.  Let T be the DER encoding of the
     DigestInfo value and let tLen be the length in octets of T.  */

  t_n = asn_n + h_n;
  t = gcry_malloc (t_n);
  if (! t)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  for (i = 0; i < asn_n; i++)
    t[i] = asn[i];
  for (i = 0; i < h_n; i++)
    t[asn_n + i] = h[i];

  /* If emLen < tLen + 11, output "intended encoded message length
     too short" and stop.  */
  if (options->em_n < t_n + 11)
    {
      err = GPG_ERR_TOO_SHORT;
      goto out;
    }

  /* Generate an octet string PS consisting of emLen - tLen - 3 octets
     with hexadecimal value 0xFF.  The length of PS will be at least 8
     octets.  */
  ps_n = options->em_n - t_n - 3;
  ps = gcry_malloc (ps_n);
  if (! ps)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
  for (i = 0; i < ps_n; i++)
    ps[i] = 0xFF;

  /* Concatenate PS, the DER encoding T, and other padding to form the
     encoded message EM as:

     EM = 0x00 || 0x01 || PS || 0x00 || T.  */

  buffer_n = ps_n + t_n + 3;
  buffer = gcry_malloc (buffer_n);
  if (! buffer)
    {
      err = gpg_err_code_from_errno (ENOMEM);
      goto out;
    }

  buffer[0] = 0x00;
  buffer[1] = 0x01;
  for (i = 0; i < ps_n; i++)
    buffer[2 + i] = ps[i];
  buffer[2 + ps_n] = 0x00;
  for (i = 0; i < t_n; i++)
    buffer[3 + ps_n + i] = t[i];

  *em = buffer;
  *em_n = buffer_n;

 out:

  gcry_md_close (md);

  gcry_free (ps);
  gcry_free (t);

  return err;
}

/* `Actions' for data_dencode().  */
typedef enum dencode_action
  {
    DATA_ENCODE,
    DATA_DECODE,
  }
dencode_action_t;

/* Encode or decode a message according to the the encoding method
   METHOD; ACTION specifies wether the message that is contained in
   BUFFER_IN and of length BUFFER_IN_N should be encoded or decoded.
   The resulting message will be stored in a newly allocated buffer in
   BUFFER_OUT and BUFFER_OUT_N.  */
static gcry_err_code_t
ac_data_dencode (gcry_ac_em_t method, dencode_action_t action,
		 unsigned int flags, void *options,
		 unsigned char *buffer_in, size_t buffer_in_n,
		 unsigned char **buffer_out, size_t *buffer_out_n)
{
  struct
  {
    gcry_ac_em_t method;
    gcry_ac_em_dencode_t encode;
    gcry_ac_em_dencode_t decode;
  } methods[] =
    {
      { GCRY_AC_EME_PKCS_V1_5,
	eme_pkcs_v1_5_encode, eme_pkcs_v1_5_decode },
      { GCRY_AC_EMSA_PKCS_V1_5,
	emsa_pkcs_v1_5_encode, NULL },
    };
  size_t methods_n;
  gcry_err_code_t err;
  unsigned int i;

  methods_n = sizeof (methods) / sizeof (*methods);

  for (i = 0; i < methods_n; i++)
    if (methods[i].method == method)
      break;
  if (i == methods_n)
    {
      err = GPG_ERR_NOT_FOUND;	/* FIXME? */
      goto out;
    }

  err = 0;
  switch (action)
    {
    case DATA_ENCODE:
      if (methods[i].encode)
	/* FIXME? */
	err = (*methods[i].encode) (flags, options,
				    buffer_in, buffer_in_n,
				    buffer_out, buffer_out_n);
      break;

    case DATA_DECODE:
      if (methods[i].decode)
	/* FIXME? */
	err = (*methods[i].decode) (flags, options,
				    buffer_in, buffer_in_n,
				    buffer_out, buffer_out_n);
      break;

    default:
      err = GPG_ERR_INV_ARG;
      break;
    }

 out:

  return err;
}

/* Encode a message according to the encoding method METHOD.  OPTIONS
   must be a pointer to a method-specific structure
   (gcry_ac_em*_t).  */
gcry_err_code_t
_gcry_ac_data_encode (gcry_ac_em_t method, unsigned int flags, void *options,
		      unsigned char *m, size_t m_n, unsigned char **em, size_t *em_n)
{
  return ac_data_dencode (method, DATA_ENCODE, flags, options,
			  m, m_n, em, em_n);
}

/* Encode a message according to the encoding method METHOD.  OPTIONS
   must be a pointer to a method-specific structure
   (gcry_ac_em*_t).  */
gcry_error_t
gcry_ac_data_encode (gcry_ac_em_t method, unsigned int flags, void *options,
		     unsigned char *m, size_t m_n, unsigned char **em, size_t *em_n)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_encode (method, flags, options, m, m_n, em, em_n);

  return gcry_error (err);
}

/* Dencode a message according to the encoding method METHOD.  OPTIONS
   must be a pointer to a method-specific structure
   (gcry_ac_em*_t).  */
gcry_err_code_t
_gcry_ac_data_decode (gcry_ac_em_t method, unsigned int flags, void *options,
		      unsigned char *em, size_t em_n,
		      unsigned char **m, size_t *m_n)
{
  return ac_data_dencode (method,
			  DATA_DECODE, flags, options, em, em_n, m, m_n);
}

gcry_error_t
gcry_ac_data_decode (gcry_ac_em_t method, unsigned int flags, void *options,
		     unsigned char *em, size_t em_n,
		     unsigned char **m, size_t *m_n)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_decode (method, flags, options, em, em_n, m, m_n);

  return gcry_error (err);
}

/* Convert an MPI into an octet string.  */
static void
ac_mpi_to_os (gcry_mpi_t mpi, unsigned char *os, size_t os_n)
{
  unsigned long digit;
  gcry_mpi_t base;
  unsigned int i;
  unsigned int n;
  gcry_mpi_t m;
  gcry_mpi_t d;

  base = gcry_mpi_new (0);
  gcry_mpi_set_ui (base, 256);

  n = 0;
  m = gcry_mpi_copy (mpi);
  while (gcry_mpi_cmp_ui (m, 0))
    {
      n++;
      gcry_mpi_div (m, NULL, m, base, 0);
    }

  gcry_mpi_set (m, mpi);
  d = gcry_mpi_new (0);
  for (i = 0; (i < n) && (i < os_n); i++)
    {
      gcry_mpi_mod (d, m, base);
      _gcry_mpi_get_ui (d, &digit);
      gcry_mpi_div (m, NULL, m, base, 0);
      os[os_n - i - 1] = (digit & 0xFF);
    }

  for (; i < os_n; i++)
    os[os_n - i - 1] = 0;

  gcry_mpi_release (base);
  gcry_mpi_release (d);
  gcry_mpi_release (m);
}

/* Convert an MPI into an octet string.  */
void
_gcry_ac_mpi_to_os (gcry_mpi_t mpi, unsigned char *os, size_t os_n)
{
  ac_mpi_to_os (mpi, os, os_n);
}

/* Convert an MPI into an octet string (I2OSP). */
void
gcry_ac_mpi_to_os (gcry_mpi_t mpi, unsigned char *os, size_t os_n)
{
  _gcry_ac_mpi_to_os (mpi, os, os_n);
}

/* Convert an MPI into an newly allocated octet string.  */
gcry_err_code_t
_gcry_ac_mpi_to_os_alloc (gcry_mpi_t mpi, unsigned char **os, size_t *os_n)
{
  unsigned char *buffer;
  size_t buffer_n;
  gcry_err_code_t err;
  unsigned int nbits;

  nbits = gcry_mpi_get_nbits (mpi);
  buffer_n = (nbits + 7) / 8;
  buffer = gcry_malloc (buffer_n);
  if (! buffer)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
      
  _gcry_ac_mpi_to_os (mpi, buffer, buffer_n);
  *os = buffer;
  *os_n = buffer_n;
  err = 0;

 out:

  return err;
}

/* Convert an MPI into an newly allocated octet string.  */
gcry_error_t
gcry_ac_mpi_to_os_alloc (gcry_mpi_t mpi, unsigned char **os, size_t *os_n)
{
  gcry_err_code_t err;

  err = _gcry_ac_mpi_to_os_alloc (mpi, os, os_n);

  return gcry_error (err);
}

/* Convert an octet string into an MPI.  */
static void
ac_os_to_mpi (gcry_mpi_t mpi, unsigned char *os, size_t os_n)
{
  unsigned int i;
  gcry_mpi_t xi;
  gcry_mpi_t x;
  gcry_mpi_t a;
  
  a = gcry_mpi_new (0);
  gcry_mpi_set_ui (a, 1);
  x = gcry_mpi_new (0);
  gcry_mpi_set_ui (x, 0);
  xi = gcry_mpi_new (0);

  for (i = 0; i < os_n; i++)
    {
      gcry_mpi_mul_ui (xi, a, os[os_n - i - 1]);
      gcry_mpi_add (x, x, xi);
      gcry_mpi_mul_ui (a, a, 256);
    }
      
  gcry_mpi_release (xi);
  gcry_mpi_release (a);

  gcry_mpi_set (mpi, x);
  gcry_mpi_release (x);		/* FIXME: correct? */
}

/* Convert an octet string into an MPI.  */
void
_gcry_ac_os_to_mpi (gcry_mpi_t mpi, unsigned char *os, size_t os_n)
{
  ac_os_to_mpi (mpi, os, os_n);
}

/* Convert an octet string into an MPI (OS2IP).  */
void
gcry_ac_os_to_mpi (gcry_mpi_t mpi, unsigned char *os, size_t os_n)
{
  _gcry_ac_os_to_mpi (mpi, os, os_n);
}



/* 
 * Implementation of Encryption Schemes (ES) and Signature Schemes
 * with Appendix (SSA).
 */

/* Schemes consist of two things: encoding methods and cryptographic
   primitives.

   Since encoding methods are accessible through a common API with
   method-specific options passed as an anonymous struct, schemes have
   to provide functions that construct this method-specific structure;
   this is what the functions of type `gcry_ac_dencode_prepare_t' are
   there for.

   Besides the actual encoding of an octet string into an encoded
   octet string, the conversion of an MPI to an octet string might be
   method-dependent as well.  For instance for EME-PKCS-V1_5, the
   decrypted MPI value has to be converted into an octet string that
   has the same length as the provided key.  This is implemented by
   the functions of type `gcry_ac_dencode_to_os_t'.  */

typedef gcry_err_code_t (*gcry_ac_dencode_prepare_t) (gcry_ac_handle_t handle,
						      gcry_ac_key_t key,
						      void *opts,
						      void *opts_em);

typedef gcry_err_code_t (*gcry_ac_dencode_to_os_t) (gcry_ac_handle_t handle,
						    gcry_ac_key_t key,
						    void *opts,
						    gcry_mpi_t mpi,
						    unsigned char **os,
						    size_t *os_n);

/* The `dencode_prepare' function for ES-PKCS-V1_5.  */
static gcry_err_code_t
ac_es_dencode_prepare_pkcs_v1_5 (gcry_ac_handle_t handle, gcry_ac_key_t key,
				 void *opts, void *opts_em)
{
  gcry_ac_eme_pkcs_v1_5_t *options_em;

  options_em = opts_em;

  options_em->handle = handle;
  options_em->key = key;

  return 0;
}

/* The `dencode_to_os' function for ES-PKCS-V1_5.  */
static gcry_err_code_t
ac_es_dencode_to_os_pkcs_v1_5 (gcry_ac_handle_t handle, gcry_ac_key_t key,
			       void *opts, gcry_mpi_t mpi,
			       unsigned char **os, size_t *os_n)
{
  unsigned char buffer_n;
  unsigned char *buffer;
  gcry_err_code_t err;
  unsigned int k;

  err = _gcry_ac_key_get_nbits (handle, key, &k);
  if (err)
    goto out;

  buffer_n = (k + 7) / 8;
  buffer = gcry_malloc (buffer_n);
  if (! buffer)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }

  gcry_ac_mpi_to_os (mpi, buffer, buffer_n);
  *os = buffer;
  *os_n = buffer_n;

 out:

  return err;
}

/* The `dencode_prepare' function for SSA-PKCS-V1_5.  */
static gcry_err_code_t
ac_ssa_dencode_prepare_pkcs_v1_5 (gcry_ac_handle_t handle, gcry_ac_key_t key,
				  void *opts, void *opts_em)
{
  gcry_ac_emsa_pkcs_v1_5_t *options_em;
  gcry_ac_ssa_pkcs_v1_5_t *options;
  gcry_err_code_t err;
  unsigned int k;

  options_em = opts_em;
  options = opts;

  err = _gcry_ac_key_get_nbits (handle, key, &k);
  if (err)
    goto out;

  k = (k + 7) / 8;
  options_em->md = options->md;
  options_em->em_n = k;

 out:

  return err;
}

/* Type holding the information about each supported
   Encryption/Signature Scheme.  */
typedef struct ac_scheme
{
  gcry_ac_scheme_t scheme;
  gcry_ac_em_t scheme_encoding;
  gcry_ac_dencode_prepare_t dencode_prepare;
  gcry_ac_dencode_to_os_t dencode_to_os;
  size_t options_em_n;
} ac_scheme_t;

/* List of supported Schemes.  */
static ac_scheme_t ac_schemes[] =
  {
    { GCRY_AC_ES_PKCS_V1_5, GCRY_AC_EME_PKCS_V1_5,
      ac_es_dencode_prepare_pkcs_v1_5, ac_es_dencode_to_os_pkcs_v1_5,
      sizeof (gcry_ac_eme_pkcs_v1_5_t) },
    { GCRY_AC_SSA_PKCS_V1_5, GCRY_AC_EMSA_PKCS_V1_5,
      ac_ssa_dencode_prepare_pkcs_v1_5, NULL,
      sizeof (gcry_ac_emsa_pkcs_v1_5_t) }
  };

/* Lookup a scheme by it's ID.  */
static ac_scheme_t *
ac_scheme_get (gcry_ac_scheme_t scheme)
{
  ac_scheme_t *ac_scheme;
  unsigned int i;

  for (i = 0; i < DIM (ac_schemes); i++)
    if (scheme == ac_schemes[i].scheme)
      break;
  if (i == DIM (ac_schemes))
    ac_scheme = NULL;
  else
    ac_scheme = ac_schemes + i;

  return ac_scheme;
}

/* Prepares the encoding/decoding by creating an according option
   structure.  */
static gcry_err_code_t
ac_dencode_prepare (gcry_ac_handle_t handle, gcry_ac_key_t key, void *opts,
		    ac_scheme_t scheme, void **opts_em)
{
  gcry_err_code_t err;
  void *options_em;

  options_em = gcry_malloc (scheme.options_em_n);
  if (! options_em)
    {
      err = gpg_err_code_from_errno (errno);
      goto out;
    }
  
  err = (*scheme.dencode_prepare) (handle, key, opts, options_em);
  if (err)
    goto out;

  *opts_em = options_em;

 out:

  if (err)
    free (options_em);

  return err;
}

/* Converts an MPI into an octet string according to the specified
   scheme.  */
static gcry_err_code_t
ac_es_dencode_to_os (gcry_ac_handle_t handle, gcry_ac_key_t key, void *opts,
		     ac_scheme_t scheme, gcry_mpi_t mpi, unsigned char **os, size_t *os_n)
{
  gcry_err_code_t err;

  err = (*scheme.dencode_to_os) (handle, key, opts, mpi, os, os_n);

  return err;
}

/* Types of `data sets' that are known to ac_data_set_to_mpi.  */
typedef enum ac_scheme_data_type
  {
    DATA_TYPE_ENCRYPTED,
    DATA_TYPE_SIGNED,
  }
ac_scheme_data_type_t;

/* Extracts the MPI from a data set.  */
static gcry_err_code_t
ac_data_set_to_mpi (gcry_ac_handle_t handle, ac_scheme_data_type_t type,
		    gcry_ac_data_t data, gcry_mpi_t *mpi)
{
  gcry_err_code_t err;
  gcry_mpi_t mpi_new;
  unsigned int elems;
  gcry_pk_spec_t *spec;
  char name[2];

  spec = AC_MOD_SPEC (handle->module);
  name[1] = 0;
  elems = 0;

  switch (type)
    {
    case DATA_TYPE_ENCRYPTED:
      elems = strlen (spec->elements_enc);
      name[0] = spec->elements_enc[0];
      break;

    case DATA_TYPE_SIGNED:
      elems = strlen (spec->elements_sig);
      name[0] = spec->elements_sig[0];
      break;
    }

  if (elems != 1)
    {
      /* FIXME: I guess, we should be more flexible in this respect by
	 allowing the actual encryption/signature schemes to implement
	 this conversion mechanism.  */
      err = GPG_ERR_CONFLICT;
      goto out;
    }

  err = _gcry_ac_data_get_name (data, GCRY_AC_FLAG_COPY, name, &mpi_new);
  if (err)
    goto out;

  *mpi = mpi_new;

 out:

  return err;
}

/* Creates a new data set containing the provided MPI.  */
static gcry_err_code_t
ac_mpi_to_data_set (gcry_ac_handle_t handle, ac_scheme_data_type_t type,
		    gcry_ac_data_t *data, gcry_mpi_t mpi)
{
  gcry_ac_data_t data_new;
  gcry_pk_spec_t *spec;
  gcry_err_code_t err;
  unsigned int elems;
  char name[2];

  data_new = NULL;
  spec = AC_MOD_SPEC (handle->module);
  name[1] = 0;
  elems = 0;

  switch (type)
    {
    case DATA_TYPE_ENCRYPTED:
      elems = strlen (spec->elements_enc);
      name[0] = spec->elements_enc[0];
      break;

    case DATA_TYPE_SIGNED:
      elems = strlen (spec->elements_sig);
      name[0] = spec->elements_sig[0];
      break;
    }

  if (elems != 1)
    {
      err = GPG_ERR_CONFLICT;
      goto out;
    }

  err = ac_data_new (&data_new);
  if (err)
    goto out;

  err = ac_data_set (data_new, GCRY_AC_FLAG_COPY | GCRY_AC_FLAG_DEALLOC,
		     name, mpi);
  if (err)
    goto out;

  *data = data_new;

 out:

  if (err)
    ac_data_destroy (data_new);

  return err;
}

/* Encrypts the plain text message contained in M, which is of size
   M_N, with the public key KEY_PUBLIC according to the Encryption
   Scheme SCHEME_ID.  HANDLE is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The encrypted message will be stored in C and C_N.  */
static gcry_err_code_t
ac_data_encrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			unsigned int flags, void *opts, gcry_ac_key_t key,
			unsigned char *m, size_t m_n,
			unsigned char **c, size_t *c_n)
{
  gcry_err_code_t err;
  unsigned char *em;
  size_t em_n;
  gcry_mpi_t mpi_plain;
  gcry_ac_data_t data_encrypted;
  gcry_mpi_t mpi_encrypted;
  unsigned char *buffer;
  size_t buffer_n;
  void *opts_em;
  ac_scheme_t *scheme;

  data_encrypted = NULL;
  mpi_encrypted = NULL;
  mpi_plain = NULL;
  opts_em = NULL;
  em = NULL;

  scheme = ac_scheme_get (scheme_id);
  if (! scheme)
    {
      err = GPG_ERR_NO_ENCRYPTION_SCHEME;
      goto out;
    }

  if (key->type != GCRY_AC_KEY_PUBLIC)
    {
      err = GPG_ERR_WRONG_KEY_USAGE;
      goto out;
    }

  err = ac_dencode_prepare (handle, key, opts, *scheme, &opts_em);
  if (err)
    goto out;

  err = _gcry_ac_data_encode (scheme->scheme_encoding,
			      0, opts_em, m, m_n, &em, &em_n);
  if (err)
    goto out;

  mpi_plain = gcry_mpi_snew (0);
  gcry_ac_os_to_mpi (mpi_plain, em, em_n);

  err = _gcry_ac_data_encrypt (handle, 0, key, mpi_plain, &data_encrypted);
  if (err)
    goto out;

  err = ac_data_set_to_mpi (handle, DATA_TYPE_ENCRYPTED,
			    data_encrypted, &mpi_encrypted);
  if (err)
    goto out;

  err = _gcry_ac_mpi_to_os_alloc (mpi_encrypted, &buffer, &buffer_n);
  if (err)
    goto out;

  *c = buffer;
  *c_n = buffer_n;

 out:

  gcry_ac_data_destroy (data_encrypted);
  gcry_mpi_release (mpi_encrypted);
  gcry_mpi_release (mpi_plain);
  gcry_free (opts_em);
  gcry_free (em);

  return err;
}

/* Encrypts the plain text message contained in M, which is of size
   M_N, with the public key KEY_PUBLIC according to the Encryption
   Scheme SCHEME_ID.  HANDLE is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The encrypted message will be stored in C and C_N.  */
gcry_err_code_t
_gcry_ac_data_encrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			      unsigned int flags, void *opts, gcry_ac_key_t key,
			      unsigned char *m, size_t m_n, unsigned char **c, size_t *c_n)
{
  return ac_data_encrypt_scheme (handle, scheme_id, flags, opts, key,
				 m, m_n, c, c_n);
}

/* Encrypts the plain text message contained in M, which is of size
   M_N, with the public key KEY_PUBLIC according to the Encryption
   Scheme SCHEME_ID.  HANDLE is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The encrypted message will be stored in C and C_N.  */
gcry_error_t
gcry_ac_data_encrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			     unsigned int flags, void *opts, gcry_ac_key_t key,
			     unsigned char *m, size_t m_n,
			     unsigned char **c, size_t *c_n)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_encrypt_scheme (handle, scheme_id, flags, opts, key,
				      m, m_n, c, c_n);

  return gcry_error (err);
}

/* Decryptes the cipher message contained in C, which is of size C_N,
   with the secret key KEY_SECRET according to the Encryption Scheme
   SCHEME_ID.  Handle is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The decrypted message will be stored in M and M_N.  */
static gcry_err_code_t
ac_data_decrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			unsigned int flags, void *opts, gcry_ac_key_t key,
			unsigned char *c, size_t c_n,
			unsigned char **m, size_t *m_n)
{
  gcry_err_code_t err;
  gcry_ac_data_t data_encrypted;
  unsigned char *em;
  size_t em_n;
  gcry_mpi_t mpi_encrypted;
  gcry_mpi_t mpi_decrypted;
  unsigned char *buffer;
  size_t buffer_n;
  void *opts_em;
  ac_scheme_t *scheme;

  data_encrypted = NULL;
  mpi_encrypted = NULL;
  mpi_decrypted = NULL;
  opts_em = NULL;
  em = NULL;

  scheme = ac_scheme_get (scheme_id);
  if (! scheme)
    {
      err = GPG_ERR_NO_ENCRYPTION_SCHEME;
      goto out;
    }

  if (key->type != GCRY_AC_KEY_SECRET)
    {
      err = GPG_ERR_WRONG_KEY_USAGE;
      goto out;
    }

  mpi_encrypted = gcry_mpi_snew (0);
  gcry_ac_os_to_mpi (mpi_encrypted, c, c_n);

  err = ac_mpi_to_data_set (handle, DATA_TYPE_ENCRYPTED, &data_encrypted, mpi_encrypted);
  if (err)
    goto out;

  gcry_mpi_release (mpi_encrypted);
  mpi_encrypted = NULL;

  err = _gcry_ac_data_decrypt (handle, 0, key, &mpi_decrypted, data_encrypted);
  if (err)
    goto out;
  
  err = ac_es_dencode_to_os (handle, key, opts, *scheme, mpi_decrypted, &em, &em_n);
  if (err)
    goto out;

  err = ac_dencode_prepare (handle, key, opts, *scheme, &opts_em);
  if (err)
    goto out;

  err = _gcry_ac_data_decode (scheme->scheme_encoding,
			      0, opts_em, em, em_n, &buffer, &buffer_n);
  if (err)
    goto out;

  *m = buffer;
  *m_n = buffer_n;

 out:
  
  ac_data_destroy (data_encrypted);
  gcry_mpi_release (mpi_encrypted);
  gcry_mpi_release (mpi_decrypted);
  gcry_free (opts_em);
  gcry_free (em);

  return err;
}

/* Decryptes the cipher message contained in C, which is of size C_N,
   with the secret key KEY according to the Encryption Scheme
   SCHEME_ID.  Handle is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The decrypted message will be stored in M and M_N.  */
gcry_err_code_t
_gcry_ac_data_decrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			      unsigned int flags, void *opts, gcry_ac_key_t key,
			      unsigned char *c, size_t c_n,
			      unsigned char **m, size_t *m_n)
{
  return ac_data_decrypt_scheme (handle, scheme_id, flags, opts, key,
				 c, c_n, m, m_n);
}

/* Decryptes the cipher message contained in C, which is of size C_N,
   with the secret key KEY according to the Encryption Scheme
   SCHEME_ID.  Handle is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The decrypted message will be stored in M and M_N.  */
gcry_error_t
gcry_ac_data_decrypt_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			     unsigned int flags, void *opts, gcry_ac_key_t key,
			     unsigned char *c, size_t c_n, unsigned char **m, size_t *m_n)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_decrypt_scheme (handle, scheme_id, flags, opts, key,
				      c, c_n, m, m_n);

  return gcry_error (err);
}  

/* Signs the message contained in M, which is of size M_N, with the
   secret key KEY according to the Signature Scheme SCHEME_ID.  Handle
   is used for accessing the low-level cryptographic primitives.  If
   OPTS is not NULL, it has to be an anonymous structure specific to
   the chosen scheme (gcry_ac_ssa_*_t).  The signed message will be
   stored in S and S_N.  */
static gcry_err_code_t
ac_data_sign_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
		     unsigned int flags, void *opts, gcry_ac_key_t key,
		     unsigned char *m, size_t m_n,
		     unsigned char **s, size_t *s_n)
{
  gcry_err_code_t err;
  gcry_ac_data_t data_signed;
  unsigned char *em;
  size_t em_n;
  gcry_mpi_t mpi;
  void *opts_em;
  unsigned char *buffer;
  size_t buffer_n;
  gcry_mpi_t mpi_signed;
  ac_scheme_t *scheme;

  data_signed = NULL;
  mpi_signed = NULL;
  opts_em = NULL;
  mpi = NULL;
  em = NULL;

  if (key->type != GCRY_AC_KEY_SECRET)
    {
      err = GPG_ERR_WRONG_KEY_USAGE;
      goto out;
    }

  scheme = ac_scheme_get (scheme_id);
  if (! scheme)
    {
      /* FIXME: adjust api of scheme_get in respect to err codes.  */
      err = GPG_ERR_NO_SIGNATURE_SCHEME;
      goto out;
    }

  err = ac_dencode_prepare (handle, key, opts, *scheme, &opts_em);
  if (err)
    goto out;

  err = _gcry_ac_data_encode (scheme->scheme_encoding, 0, opts_em, m, m_n, &em, &em_n);
  if (err)
    goto out;

  mpi = gcry_mpi_new (0);
  _gcry_ac_os_to_mpi (mpi, em, em_n);

  err = _gcry_ac_data_sign (handle, key, mpi, &data_signed);
  if (err)
    goto out;

  err = ac_data_set_to_mpi (handle, DATA_TYPE_SIGNED, data_signed, &mpi_signed);
  if (err)
    goto out;

  err = _gcry_ac_mpi_to_os_alloc (mpi_signed, &buffer, &buffer_n);
  if (err)
    goto out;

  *s = buffer;
  *s_n = buffer_n;

 out:

  _gcry_ac_data_destroy (data_signed);
  gcry_mpi_release (mpi_signed);
  gcry_mpi_release (mpi);
  gcry_free (opts_em);
  gcry_free (em);

  return err;
}

/* Signs the message contained in M, which is of size M_N, with the
   secret key KEY_SECRET according to the Signature Scheme SCHEME_ID.
   Handle is used for accessing the low-level cryptographic
   primitives.  If OPTS is not NULL, it has to be an anonymous
   structure specific to the chosen scheme (gcry_ac_ssa_*_t).  The
   signed message will be stored in S and S_N.  */
gcry_err_code_t
_gcry_ac_data_sign_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			   unsigned int flags, void *opts, gcry_ac_key_t key,
			   unsigned char *m, size_t m_n,
			   unsigned char **s, size_t *s_n)
{
  return ac_data_sign_scheme (handle, scheme_id, flags, opts, key,
			      m, m_n, s, s_n);
}

/* Signs the message contained in M, which is of size M_N, with the
   secret key KEY_SECRET according to the Signature Scheme SCHEME_ID.
   Handle is used for accessing the low-level cryptographic
   primitives.  If OPTS is not NULL, it has to be an anonymous
   structure specific to the chosen scheme (gcry_ac_ssa_*_t).  The
   signed message will be stored in S and S_N.  */
gcry_error_t
gcry_ac_data_sign_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
			  unsigned int flags, void *opts, gcry_ac_key_t key,
			  unsigned char *m, size_t m_n, unsigned char **s, size_t *s_n)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_sign_scheme (handle, scheme_id, flags, opts, key,
				   m, m_n, s, s_n);

  return gcry_error (err);
}

/* Verifies that the signature contained in S, which is of length S_N,
   is indeed the result of signing the message contained in M, which
   is of size M_N, with the secret key belonging to the public key
   KEY_PUBLIC.  If OPTS is not NULL, it has to be an anonymous
   structure (gcry_ac_ssa_*_t) specific to the Signature Scheme, whose
   ID is contained in SCHEME_ID.  */
static gcry_err_code_t
ac_data_verify_scheme (gcry_ac_handle_t handle, gcry_ac_scheme_t scheme_id,
		       unsigned int flags, void *opts, gcry_ac_key_t key,
		       unsigned char *m, size_t m_n,
		       unsigned char *s, size_t s_n)
{
  gcry_err_code_t err;
  gcry_ac_data_t data_signed;
  unsigned char *em;
  size_t em_n;
  void *opts_em;
  gcry_mpi_t mpi_signature;
  gcry_mpi_t mpi_data;
  ac_scheme_t *scheme;

  mpi_signature = NULL;
  mpi_data = NULL;
  opts_em = NULL;
  em = NULL;

  if (key->type != GCRY_AC_KEY_PUBLIC)
    {
      err = GPG_ERR_WRONG_KEY_USAGE;
      goto out;
    }

  scheme = ac_scheme_get (scheme_id);
  if (! scheme)
    {
      err = GPG_ERR_NO_SIGNATURE_SCHEME;
      goto out;
    }

  err = ac_dencode_prepare (handle, key, opts, *scheme, &opts_em);
  if (err)
    goto out;

  err = _gcry_ac_data_encode (scheme->scheme_encoding,
			      0, opts_em, m, m_n, &em, &em_n);
  if (err)
    goto out;

  mpi_data = gcry_mpi_new (0);
  _gcry_ac_os_to_mpi (mpi_data, em, em_n);

  mpi_signature = gcry_mpi_new (0);
  _gcry_ac_os_to_mpi (mpi_signature, s, s_n);

  err = ac_mpi_to_data_set (handle, DATA_TYPE_SIGNED,
			    &data_signed, mpi_signature);
  if (err)
    goto out;

  gcry_mpi_release (mpi_signature);
  mpi_signature = NULL;

  err = _gcry_ac_data_verify (handle, key, mpi_data, data_signed);

 out:

  ac_data_destroy (data_signed);
  gcry_mpi_release (mpi_signature);
  gcry_mpi_release (mpi_data);
  gcry_free (opts_em);
  gcry_free (em);

  return err;
}

/* Verifies that the signature contained in S, which is of length S_N,
   is indeed the result of signing the message contained in M, which
   is of size M_N, with the secret key belonging to the public key
   KEY_PUBLIC.  If OPTS is not NULL, it has to be an anonymous
   structure (gcry_ac_ssa_*_t) specific to the Signature Scheme, whose
   ID is contained in SCHEME_ID.  */
gcry_err_code_t
_gcry_ac_data_verify_scheme (gcry_ac_handle_t handle,
			     gcry_ac_scheme_t scheme_id,
			     unsigned int flags, void *opts, gcry_ac_key_t key,
			     unsigned char *m, size_t m_n,
			     unsigned char *s, size_t s_n)
{
  return ac_data_verify_scheme (handle, scheme_id, flags, opts, key,
				m, m_n, s, s_n);
}

/* Verifies that the signature contained in S, which is of length S_N,
   is indeed the result of signing the message contained in M, which
   is of size M_N, with the secret key belonging to the public key
   KEY_PUBLIC.  If OPTS is not NULL, it has to be an anonymous
   structure (gcry_ac_ssa_*_t) specific to the Signature Scheme, whose
   ID is contained in SCHEME_ID.  */
gcry_error_t
gcry_ac_data_verify_scheme (gcry_ac_handle_t handle,
			    gcry_ac_scheme_t scheme_id,
			    unsigned int flags, void *opts, gcry_ac_key_t key,
			    unsigned char *m, size_t m_n,
			    unsigned char *s, size_t s_n)
{
  gcry_err_code_t err;

  err = _gcry_ac_data_verify_scheme (handle, scheme_id, flags, opts, key,
				     m, m_n, s, s_n);

  return gcry_error (err);
}



/*
 * Support functions for pubkey.c.
 */

/* Mark the algorithm identitified by HANDLE as `enabled' (this is the
   default).  */
gcry_error_t
_gcry_ac_algorithm_enable (gcry_ac_handle_t handle)
{
  ALGORITHMS_LOCK;
  handle->module->flags &= ~FLAG_MODULE_DISABLED;
  ALGORITHMS_UNLOCK;

  return 0;
}

/* Mark the algorithm identitified by HANDLE as `disabled'.  */
gcry_error_t
_gcry_ac_algorithm_disable (gcry_ac_handle_t handle)
{
  ALGORITHMS_LOCK;
  handle->module->flags |= FLAG_MODULE_DISABLED;
  ALGORITHMS_UNLOCK;

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
  struct
  {
    unsigned int *elements_n;
    const char *elements_s;
  } elements_specs[] =
    {
      { elements_key_secret, (AC_MOD_SPEC (handle->module))->elements_skey },
      { elements_key_public, (AC_MOD_SPEC (handle->module))->elements_skey },
      { elements_encrypted,  (AC_MOD_SPEC (handle->module))->elements_enc  },
      { elements_signed,     (AC_MOD_SPEC (handle->module))->elements_sig  },
    };
  unsigned int i;

  for (i = 0; i < DIM (elements_specs); i++)
    if (elements_specs[i].elements_n)
      *elements_specs[i].elements_n = strlen (elements_specs[i].elements_s);
}

/* Internal function used by pubkey.c.  Extract certain information
   from a given handle.  */
void
_gcry_ac_info_get (gcry_ac_handle_t handle,
		   gcry_ac_id_t *algorithm_id, unsigned int *algorithm_use_flags)
{
  if (algorithm_id)
    *algorithm_id = handle->algorithm;
  if (algorithm_use_flags)
    *algorithm_use_flags = (0
			    | ((AC_MOD_SPEC (handle->module))->sign
			       ? GCRY_PK_USAGE_SIGN : 0)
			    | ((AC_MOD_SPEC (handle->module))->encrypt
			       ? GCRY_PK_USAGE_ENCR : 0));
}

/* Convert the MPIs contained in the data set into an arg list
   suitable for passing to gcry_sexp_build_array().  */
gcry_err_code_t
_gcry_ac_arg_list_from_data (gcry_ac_data_t data, void ***arg_list)
{
  gcry_err_code_t err;
  void **arg_list_new;
  unsigned int i;

  if (data->data_n)
    {
      arg_list_new = gcry_xcalloc (data->data_n, sizeof (void *));
      if (! arg_list_new)
	{
	  err = gpg_err_code_from_errno (errno);
	  goto out;
	}
    }
  else
    arg_list_new = NULL;

  for (i = 0; i < data->data_n; i++)
    arg_list_new[i] = &data->data[i].mpi;

  *arg_list = arg_list_new;
  err = 0;

 out:

  return err;
}
