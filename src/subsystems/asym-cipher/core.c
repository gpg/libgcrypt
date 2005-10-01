/* ac.c - Alternative interface for asymmetric cryptography.
   Copyright (C) 2003, 2004, 2005 Free Software Foundation, Inc.
 
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

#include <gcrypt-ac-internal.h>

#include <gcrypt-sexp-internal.h>
#include <gcrypt-mpi-internal.h>
#include <gcrypt-md-internal.h>
#include <gcrypt-random-internal.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <assert.h>



/* Handle structure.  */
struct gcry_core_ac_handle
{
  gcry_core_ac_spec_t algorithm;
  unsigned int flags;		/* Flags, not used yet.  */
  struct
  {
    gcry_core_ac_cb_t cb;
    void *opaque;
  } cb;
};

/* A named MPI value.  */
typedef struct gcry_core_ac_mpi
{
  char *name;			/* MPI name.  */
  gcry_core_mpi_t mpi;		/* MPI value.         */
  unsigned int flags;		/* Flags.             */
} gcry_core_ac_mpi_t;

/* A data set, that is simply a list of named MPI values.  */
struct gcry_core_ac_data
{
  gcry_core_ac_mpi_t *data;		/* List of named values.      */
  unsigned int data_n;		/* Number of values in DATA.  */
};

/* A single key.  */
struct gcry_core_ac_key
{
  gcry_core_ac_data_t data;		/* Data in native ac structure.  */
  gcry_core_ac_key_type_t type;	/* Type of the key.              */
};

/* A key pair.  */
struct gcry_core_ac_key_pair
{
  gcry_core_ac_key_t public;
  gcry_core_ac_key_t secret;
};



/* 
 * Functions for working with data sets.
 */

/* Creates a new, empty data set and store it in DATA.  */
static gcry_error_t
_gcry_core_ac_data_new (gcry_core_context_t ctx,
			unsigned int flags,
			gcry_core_ac_data_t *data)
{
  gcry_core_ac_data_t data_new;
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
ac_data_values_destroy (gcry_core_context_t ctx, gcry_core_ac_data_t data)
{
  unsigned int i;
  
  for (i = 0; i < data->data_n; i++)
    {
      gcry_core_mpi_release (ctx, data->data[i].mpi);
      gcry_core_free (ctx, data->data[i].name);
    }
}

/* Destroys the data set DATA.  */
static void
ac_data_destroy (gcry_core_context_t ctx, gcry_core_ac_data_t data)
{
  if (data)
    {
      ac_data_values_destroy (ctx, data);
      gcry_core_free (ctx, data->data);
      gcry_core_free (ctx, data);
    }
}

static void
_gcry_core_ac_data_destroy (gcry_core_context_t ctx,
			unsigned int flags,
			    gcry_core_ac_data_t data)
{
  return ac_data_destroy (ctx, data);
}

/* This function creates a copy of the array of named MPIs DATA_MPIS,
   which is of length DATA_MPIS_N; the copy is stored in
   DATA_MPIS_CP.  */
static gcry_error_t
ac_data_mpi_copy (gcry_core_context_t ctx,
		  gcry_core_ac_mpi_t *data_mpis, unsigned int data_mpis_n,
		  gcry_core_ac_mpi_t **data_mpis_cp)
{
  gcry_core_ac_mpi_t *data_mpis_new;
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

      label = gcry_core_strdup (ctx, data_mpis[i].name);
      mpi = gcry_core_mpi_copy (ctx, data_mpis[i].mpi);
      if (! (label && mpi))
	{
	  err = gcry_core_error_from_errno (errno);
	  gcry_core_mpi_release (ctx, mpi);
	  gcry_core_free (ctx, label);
	  break;
	}

      data_mpis_new[i].flags = 0;
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
_gcry_core_ac_data_copy (gcry_core_context_t ctx,
			unsigned int flags,
			 gcry_core_ac_data_t *data_cp, gcry_core_ac_data_t data)
{
  gcry_core_ac_mpi_t *data_mpis;
  gcry_core_ac_data_t data_new;
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
_gcry_core_ac_data_length (gcry_core_context_t ctx,
			   unsigned int flags,
			   gcry_core_ac_data_t data)
{
  return data->data_n;
}

/* Add the value MPI to DATA with the label NAME.  If FLAGS contains
   GCRY_CORE_AC_FLAG_COPY, the data set will contain copies of NAME
   and MPI.  If FLAGS contains GCRY_CORE_AC_FLAG_DEALLOC or
   GCRY_CORE_AC_FLAG_COPY, the values contained in the data set will
   be deallocated when they are to be removed from the data set.  */
static gcry_error_t
_gcry_core_ac_data_set (gcry_core_context_t ctx,
			unsigned int flags,
			gcry_core_ac_data_t data,
			const char *name, gcry_core_mpi_t mpi)
{
  gcry_error_t err;
  gcry_core_mpi_t mpi_cp;
  char *name_cp;
  unsigned int i;

  name_cp = NULL;
  mpi_cp = NULL;

  if (flags)
    {
      /* Unexpected flags set.  */
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto out;
    }

  /* Copy provided data.  */

  name_cp = gcry_core_strdup (ctx, name);
  mpi_cp = gcry_core_mpi_copy (ctx, mpi);
  if (! (name_cp && mpi_cp))
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  /* Search for existing entry.  */
  for (i = 0; i < data->data_n; i++)
    if (! strcmp (name, data->data[i].name))
      break;
  if (i < data->data_n)
    {
      /* An entry for NAME does already exist, deallocate.  */
      gcry_core_mpi_release (ctx, data->data[i].mpi);
      gcry_core_free (ctx, data->data[i].name);
    }
  else
    {
      /* Create a new entry.  */

      gcry_core_ac_mpi_t *ac_mpis;

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
_gcry_core_ac_data_get (gcry_core_context_t ctx,
			unsigned int flags,
			gcry_core_ac_data_t data,
			const char *name, gcry_core_mpi_t *mpi)
{
  gcry_core_mpi_t mpi_return;
  gcry_error_t err;
  unsigned int i;

  if (flags)
    {
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto out;
    }

  for (i = 0; i < data->data_n; i++)
    if (! strcmp (name, data->data[i].name))
      break;
  if (i == data->data_n)
    {
      err = gcry_core_error (GPG_ERR_NOT_FOUND);
      goto out;
    }

  mpi_return = gcry_core_mpi_copy (ctx, data->data[i].mpi);
  if (! mpi_return)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

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
_gcry_core_ac_data_get_idx (gcry_core_context_t ctx,
			    unsigned int flags,
			    gcry_core_ac_data_t data,
			    unsigned int idx,
			    char **name,
			    gcry_core_mpi_t *mpi)
{
  gcry_error_t err;
  gcry_core_mpi_t mpi_cp;
  char *name_cp;

  name_cp = NULL;
  mpi_cp = NULL;

  if (flags)
    {
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto out;
    }

  if (idx >= data->data_n)
    {
      err = gcry_core_error (GPG_ERR_INV_ARG);
      goto out;
    }

  if (name)
    {
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

  if (name)
    *name = name_cp;
  if (mpi)
    *mpi = mpi_cp;
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
_gcry_core_ac_data_to_sexp (gcry_core_context_t ctx,
			    unsigned int flags,
			    gcry_core_ac_data_t data, gcry_core_sexp_t *sexp,
			    const char **identifiers)
{
  gcry_core_sexp_t sexp_new;
  gcry_error_t err;
  char *sexp_buffer;
  size_t sexp_buffer_n;
  size_t identifiers_n;
  char *label;
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
  data_n = _gcry_core_ac_data_length (ctx, 0, data);
  for (i = 0; i < data_n; i++)
    {
      err = _gcry_core_ac_data_get_idx (ctx, 0, data, i, &label, NULL);
      if (err)
	break;
      /* For each entry in the data set we add "(<LABEL> %m)".  */
      sexp_buffer_n += 1 + strlen (label) + 4;
      gcry_core_free (ctx, label);
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
      err = _gcry_core_ac_data_get_idx (ctx, 0, data, i, &label, NULL);
      if (err)
	break;
      sexp_buffer_n += sprintf (sexp_buffer + sexp_buffer_n,
				"(%s %%m)", label);
      arg_list[i] = &data->data[i].mpi;
      gcry_core_free (ctx, label);
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
_gcry_core_ac_data_from_sexp (gcry_core_context_t ctx,
			      unsigned int flags,
			      gcry_core_ac_data_t *data_set, gcry_core_sexp_t sexp,
			      const char **identifiers)
{
  gcry_core_ac_data_t data_set_new;
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
  
  err = _gcry_core_ac_data_new (ctx, 0, &data_set_new);
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

      err = _gcry_core_ac_data_set (ctx, 0,
				    data_set_new, string, mpi);
      gcry_core_mpi_release (ctx, mpi);
      gcry_core_free (ctx, string);
      string = NULL;
      mpi = NULL;
      if (err)
	break;

      gcry_core_sexp_release (ctx, sexp_tmp);
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
    _gcry_core_ac_data_destroy (ctx, 0, data_set_new);

  return err;
}

/* Destroys any values contained in the data set DATA.  */
static void
_gcry_core_ac_data_clear (gcry_core_context_t ctx,
			  unsigned int flags,
			  gcry_core_ac_data_t data)
{
  ac_data_values_destroy (ctx, data);
  gcry_core_free (ctx, data->data);
  data->data = NULL;
  data->data_n = 0;
}



/*
 * Implementation of `ac io' objects.
 */

/* Initialize AC_IO according to MODE, TYPE and the variable list of
   arguments AP.  The list of variable arguments to specify depends on
   the given TYPE.  */
static void
_gcry_core_ac_io_init_va (gcry_core_context_t ctx,
			  unsigned int flags,
			  gcry_core_ac_io_t *ac_io, gcry_core_ac_io_mode_t mode,
			  gcry_core_ac_io_type_t type, va_list ap)
{
  memset (ac_io, 0, sizeof (*ac_io));

  assert ((mode == GCRY_CORE_AC_IO_READABLE) || (mode == GCRY_CORE_AC_IO_WRITABLE));
  assert ((type == GCRY_CORE_AC_IO_STRING) || (type == GCRY_CORE_AC_IO_STRING));

  ac_io->mode = mode;
  ac_io->type = type;

  switch (mode)
    {
    case GCRY_CORE_AC_IO_READABLE:
      switch (type)
	{
	case GCRY_CORE_AC_IO_STRING:
	  ac_io->readable.string.data = va_arg (ap, unsigned char *);
	  ac_io->readable.string.data_n = va_arg (ap, size_t);
	  break;

	case GCRY_CORE_AC_IO_CALLBACK:
	  ac_io->readable.callback.cb = va_arg (ap, gcry_core_ac_data_read_cb_t);
	  ac_io->readable.callback.opaque = va_arg (ap, void *);
	  break;
	}
      break;
    case GCRY_CORE_AC_IO_WRITABLE:
      switch (type)
	{
	case GCRY_CORE_AC_IO_STRING:
	  ac_io->writable.string.data = va_arg (ap, unsigned char **);
	  ac_io->writable.string.data_n = va_arg (ap, size_t *);
	  break;

	case GCRY_CORE_AC_IO_CALLBACK:
	  ac_io->writable.callback.cb = va_arg (ap, gcry_core_ac_data_write_cb_t);
	  ac_io->writable.callback.opaque = va_arg (ap, void *);
	  break;
	}
      break;
    }
}

static void
_gcry_core_ac_io_init (gcry_core_context_t ctx,
			      unsigned int flags,
		       gcry_core_ac_io_t *ac_io,
		       gcry_core_ac_io_mode_t mode, gcry_core_ac_io_type_t type, ...)
{
  va_list ap;

  va_start (ap, type);
  _gcry_core_ac_io_init_va (ctx, 0, ac_io, mode, type, ap);
  va_end (ap);
}

/* Write to the IO object AC_IO BUFFER_N bytes from BUFFER.  Return
   zero on success or error code.  */
static gcry_error_t
_gcry_core_ac_io_write (gcry_core_context_t ctx,
			      unsigned int flags,
			gcry_core_ac_io_t *ac_io,
			unsigned char *buffer, size_t buffer_n)
{
  gcry_error_t err;

  assert (ac_io->mode == GCRY_CORE_AC_IO_WRITABLE);

  switch (ac_io->type)
    {
    case GCRY_CORE_AC_IO_STRING:
      {
	unsigned char *p;

	if (*ac_io->writable.string.data)
	  {
	    p = gcry_core_realloc (ctx,
				   *ac_io->writable.string.data,
				   *ac_io->writable.string.data_n + buffer_n);
	    if (! p)
	      err = gcry_core_error_from_errno (errno);
	    else
	      {
		if (*ac_io->writable.string.data != p)
		  *ac_io->writable.string.data = p;
		memcpy (p + *ac_io->writable.string.data_n, buffer, buffer_n);
		*ac_io->writable.string.data_n += buffer_n;
		err = 0;
	      }
	  }
	else
	  {
	    if (gcry_core_is_secure (ctx, buffer))
	      p = gcry_core_malloc_secure (ctx, buffer_n);
	    else
	      p = gcry_core_malloc (ctx, buffer_n);
	    if (! p)
	      err = gcry_core_error_from_errno (errno);
	    else
	      {
		memcpy (p, buffer, buffer_n);
		*ac_io->writable.string.data = p;
		*ac_io->writable.string.data_n = buffer_n;
		err = 0;
	      }
	  }
      }
      break;

    case GCRY_CORE_AC_IO_CALLBACK:
      err = (*ac_io->writable.callback.cb) (ctx,
					    ac_io->writable.callback.opaque,
					    buffer, buffer_n);
      break;

    default:
      abort ();
      err = 0;
    }

  return err;
}

/* Read *BUFFER_N bytes from the IO object AC_IO into BUFFER; NREAD
   bytes have already been read from the object; on success, store the
   amount of bytes read in *BUFFER_N; zero bytes read means EOF.
   Return zero on success or error code.  */
static gcry_error_t
_gcry_core_ac_io_read (gcry_core_context_t ctx,
			      unsigned int flags,
		       gcry_core_ac_io_t *ac_io,
		       unsigned int nread,
		       unsigned char *buffer, size_t *buffer_n)
{
  gcry_error_t err;
  
  assert (ac_io->mode == GCRY_CORE_AC_IO_READABLE);

  switch (ac_io->type)
    {
    case GCRY_CORE_AC_IO_STRING:
      {
	size_t bytes_available;
	size_t bytes_to_read;
	size_t bytes_wanted;

	bytes_available = ac_io->readable.string.data_n - nread;
	bytes_wanted = *buffer_n;

	if (bytes_wanted > bytes_available)
	  bytes_to_read = bytes_available;
	else
	  bytes_to_read = bytes_wanted;

	memcpy (buffer, ac_io->readable.string.data + nread, bytes_to_read);
	*buffer_n = bytes_to_read;
	err = 0;
	break;
      }

    case GCRY_CORE_AC_IO_CALLBACK:
      err = (*ac_io->readable.callback.cb) (ctx,
					    ac_io->readable.callback.opaque,
					    buffer, buffer_n);
      break;

    default:
      abort ();
      err = 0;
    }

  return err;
}

/* Read all data available from the IO object AC_IO into newly
   allocated memory, storing an appropriate pointer in *BUFFER and the
   amount of bytes read in *BUFFER_N.  Return zero on success or error
   code.  */
static gcry_error_t
_gcry_core_ac_io_read_all (gcry_core_context_t ctx,
			      unsigned int flags,
			   gcry_core_ac_io_t *ac_io,
			   unsigned char **buffer, size_t *buffer_n)
{
  unsigned char *buffer_new;
  size_t buffer_new_n;
  unsigned char buf[BUFSIZ];
  size_t buf_n;
  unsigned char *p;
  gcry_error_t err;

  buffer_new = NULL;
  buffer_new_n = 0;

  while (1)
    {
      buf_n = sizeof (buf);
      err = _gcry_core_ac_io_read (ctx, 0, ac_io, buffer_new_n, buf, &buf_n);
      if (err)
	break;

      if (buf_n)
	{
	  /* Data has been read -> add it to the buffer.  */
	  p = gcry_core_realloc (ctx, buffer_new, buffer_new_n + buf_n);
	  if (! p)
	    {
	      err = gcry_core_error_from_errno (errno);
	      break;
	    }
	  
	  if (buffer_new != p)
	    buffer_new = p;

	  memcpy (buffer_new + buffer_new_n, buf, buf_n);
	  buffer_new_n += buf_n;
	}
      else
	/* Nothing read this time -> all data has been read.  */
	break;
    }
  if (err)
    goto out;

  *buffer_n = buffer_new_n;
  *buffer = buffer_new;

 out:

  if (err)
    gcry_core_free (ctx, buffer_new);

  return err;
}

/* Read data chunks from the IO object AC_IO until EOF, feeding them
   to the callback function CB.  Return zero on success or error
   code.  */
static gcry_error_t
_gcry_core_ac_io_process (gcry_core_context_t ctx,
			      unsigned int flags,
			  gcry_core_ac_io_t *ac_io,
			  gcry_core_ac_data_write_cb_t cb, void *opaque)
{
  unsigned char buffer[BUFSIZ];
  unsigned int nread;
  size_t buffer_n;
  gcry_error_t err;

  nread = 0;

  while (1)
    {
      buffer_n = sizeof (buffer);
      err = _gcry_core_ac_io_read (ctx, 0, ac_io, nread, buffer, &buffer_n);
      if (err)
	break;

      if (buffer_n)
	{
	  /* Data has been read -> process through callback.  */
	  err = (*cb) (ctx, opaque, buffer, buffer_n);
	  if (err)
	    break;
	  nread += buffer_n;
	}
      else
	/* No data has been read this time -> all data has been
	   read.  */
	break;
    }

  return err;
}



/*
 * Handle management.
 */

/* Creates a new handle for the algorithm ALGORITHM and stores it in
   HANDLE.  FLAGS is not used yet.  */
static gcry_error_t
_gcry_core_ac_open (gcry_core_context_t ctx,
			      unsigned int flags,
		    gcry_core_ac_handle_t *handle,
		    gcry_core_ac_spec_t spec)
{
  gcry_core_ac_handle_t handle_new;
  gcry_error_t err;

  *handle = NULL;

  /* Allocate.  */
  handle_new = gcry_core_malloc (ctx, sizeof (*handle_new));
  if (! handle_new)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  /* Done.  */
  handle_new->algorithm = spec;
  handle_new->flags = flags;
  *handle = handle_new;
  err = 0;

 out:

  return err;
}

static void
_gcry_core_ac_set_cb (gcry_core_context_t ctx,
		      gcry_core_ac_handle_t handle,
		      unsigned int flags,
		      gcry_core_ac_cb_t cb,
		      void *opaque)
{
  handle->cb.cb = cb;
  handle->cb.opaque = opaque;
}

/* Destroys the handle HANDLE.  */
static void
_gcry_core_ac_close (gcry_core_context_t ctx,
		     gcry_core_ac_handle_t handle,
		     unsigned int flags)
{
  gcry_core_free (ctx, handle);
}



/* 
 * Key management.
 */

/* Initialize a key from a given data set.  */
static gcry_error_t
_gcry_core_ac_key_init (gcry_core_context_t ctx,
		      unsigned int flags,
			gcry_core_ac_key_t *key,
			gcry_core_ac_key_type_t type,
			gcry_core_ac_data_t data)
{
  gcry_core_ac_data_t data_new;
  gcry_core_ac_key_t key_new;
  gcry_error_t err;

  /* Allocate.  */
  key_new = gcry_core_malloc (ctx, sizeof (*key_new));
  if (! key_new)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  /* Copy data set.  */
  err = _gcry_core_ac_data_copy (ctx, 0, &data_new, data);
  if (err)
    goto out;

  /* Done.  */
  key_new->data = data_new;
  key_new->type = type;
  *key = key_new;

 out:

  if (err)
    /* Deallocate resources.  */
    gcry_core_free (ctx, key_new);

  return err;
}



static gcry_error_t
ac_mpi_array_to_data_set (gcry_core_context_t ctx,
			  gcry_core_ac_data_t *data_set,
			  gcry_core_mpi_t *mpis,
			  const char *elems)
{
  gcry_core_ac_data_t data_set_new;
  gcry_error_t err;
  unsigned int i;
  char name[2];

  err = _gcry_core_ac_data_new (ctx, 0, &data_set_new);
  if (err)
    goto out;

  name[1] = 0;
  for (i = 0; elems[i]; i++)
    {
      name[0] = elems[i];

      err = _gcry_core_ac_data_set (ctx, 0,
				    data_set_new,
				    name, mpis[i]);
      if (err)
	goto out;
    }

  *data_set = data_set_new;

 out:

  if (err)
    _gcry_core_ac_data_destroy (ctx, 0, data_set_new);

  return err;
}

static gcry_error_t
ac_mpi_array_from_data_set (gcry_core_context_t ctx,
			    gcry_core_ac_data_t data_set,
			    gcry_core_mpi_t **mpis,
			    const char *elems)
{
  gcry_core_mpi_t *mpis_new;
  gcry_error_t err;
  gcry_core_mpi_t mpi;
  unsigned int i;
  size_t elems_n;
  char name[2];

  elems_n = strlen (elems);
  mpis_new = gcry_core_xcalloc (ctx, elems_n + 1, sizeof (*mpis_new));
  if (! mpis_new)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  name[1] = 0;
  for (i = 0; i < elems_n; i++)
    {
      name[0] = elems[i];

      err = _gcry_core_ac_data_get (ctx, 0, data_set, name, &mpi);
      if (err)
	goto out;

      mpis_new[i] = mpi;
    }

  *mpis = mpis_new;
  err = 0;

 out:

  if (err)
    gcry_core_free (ctx, mpis_new);

  return err;
}

static void
ac_mpi_array_release (gcry_core_context_t ctx,
		      gcry_core_mpi_t *mpis)
{
  unsigned int i;
  
  if (mpis)
    {
      for (i = 0; mpis[i]; i++)
	gcry_core_mpi_release (ctx, mpis[i]);
      gcry_core_free (ctx, mpis);
    }
}



/* Generates a new key pair via the handle HANDLE of NBITS bits and
   stores it in KEY_PAIR.  In case non-standard settings are wanted, a
   pointer to a structure of type gcry_ac_key_spec_<algorithm>_t,
   matching the selected algorithm, can be given as KEY_SPEC.
   MISC_DATA is not used yet.  */
static gcry_error_t
_gcry_core_ac_key_pair_generate (gcry_core_context_t ctx,
				 gcry_core_ac_handle_t handle,
				 unsigned int flags,
				 unsigned int nbits,
				 void *spec,
				 gcry_core_ac_key_pair_t *pair,
				 gcry_core_mpi_t **misc_data)
{
  gcry_core_ac_spec_t algorithm;
  gcry_core_ac_data_t key_data_secret;
  gcry_core_ac_data_t key_data_public;
  gcry_core_ac_key_pair_t key_pair_new;
  gcry_core_mpi_t *key_secret_mpis;
  gcry_core_mpi_t *factors;
  gcry_core_ac_key_t key_secret;
  gcry_core_ac_key_t key_public;
  gcry_error_t err;

  algorithm = handle->algorithm;

  key_data_secret = NULL;
  key_data_public = NULL;
  key_secret_mpis = NULL;
  factors = NULL;
  key_secret = NULL;
  key_public = NULL;

  /* Allocate key pair.  */
  key_pair_new = gcry_core_malloc (ctx,
				   sizeof (struct gcry_core_ac_key_pair));
  if (! key_pair_new)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  /* Allocate keys.  */
  key_secret = gcry_core_malloc (ctx,
				 sizeof (*key_secret));
  if (! key_secret)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }
  key_public = gcry_core_malloc (ctx,
				 sizeof (*key_public));
  if (! key_public)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  key_secret_mpis = gcry_core_calloc (ctx,
				      sizeof (*key_secret_mpis),
				      strlen (algorithm->elements_skey));
  if (! key_secret_mpis)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  assert (algorithm->generate || handle->cb.cb);

  if (algorithm->generate)
    err = (*algorithm->generate) (ctx, flags, nbits, spec,
				  key_secret_mpis,
				  &factors);
  else
    {
      gcry_core_ac_cb_generate_t cb_data;

      cb_data.nbits = nbits;
      cb_data.spec = spec;
      cb_data.skey = key_secret_mpis;
      cb_data.retfactors = &factors;

      err = (*handle->cb.cb) (ctx, handle->cb.opaque,
			      GCRY_CORE_AC_CB_GENERATE, &cb_data);
    }
  if (err)
    goto out;

  err = ac_mpi_array_to_data_set (ctx, &key_data_secret,
				  key_secret_mpis,
				  algorithm->elements_skey);
  if (err)
    goto out;

  err = ac_mpi_array_to_data_set (ctx, &key_data_public,
				  key_secret_mpis,
				  algorithm->elements_pkey);
  if (err)
    goto out;

  /* Done.  */

  key_secret->type = GCRY_CORE_AC_KEY_SECRET;
  key_secret->data = key_data_secret;
  key_public->type = GCRY_CORE_AC_KEY_PUBLIC;
  key_public->data = key_data_public;
  key_pair_new->secret = key_secret;
  key_pair_new->public = key_public;
  *pair = key_pair_new;

 out:

  /* Deallocate resources.  */
  
  if (err)
    {
      _gcry_core_ac_data_destroy (ctx, 0, key_data_secret);
      _gcry_core_ac_data_destroy (ctx, 0, key_data_public);
      ac_mpi_array_release (ctx, key_secret_mpis);
      gcry_core_free (ctx, key_secret);
      gcry_core_free (ctx, key_public);
      gcry_core_free (ctx, key_pair_new);
    }

  return err;
}

/* Returns the key of type WHICH out of the key pair KEY_PAIR.  */
static gcry_core_ac_key_t
_gcry_core_ac_key_pair_extract (gcry_core_context_t ctx,
		      unsigned int flags,
				gcry_core_ac_key_pair_t pair,
				gcry_core_ac_key_type_t type)
{
  gcry_core_ac_key_t key;

  switch (type)
    {
    case GCRY_CORE_AC_KEY_SECRET:
      key = pair->secret;
      break;

    case GCRY_CORE_AC_KEY_PUBLIC:
      key = pair->public;
      break;

    default:
      abort ();
      key = NULL;
      break;
    }

  return key;
}

/* Destroys the key KEY.  */
static void
_gcry_core_ac_key_destroy (gcry_core_context_t ctx,
		      unsigned int flags,
			   gcry_core_ac_key_t key)
{
  if (key)
    {
      _gcry_core_ac_data_destroy (ctx, 0, key->data);
      gcry_core_free (ctx, key);
    }
}

/* Destroys the key pair KEY_PAIR.  */
static void
_gcry_core_ac_key_pair_destroy (gcry_core_context_t ctx,
		      unsigned int flags,
				gcry_core_ac_key_pair_t pair)
{
  if (pair)
    {
      _gcry_core_ac_key_destroy (ctx, 0, pair->secret);
      _gcry_core_ac_key_destroy (ctx, 0, pair->public);
      gcry_core_free (ctx, pair);
    }
}

/* Returns the data set contained in the key KEY.  */
static gcry_core_ac_data_t
_gcry_core_ac_key_data_get (gcry_core_context_t ctx,
		      unsigned int flags,
			    gcry_core_ac_key_t key)
{
  return key->data;
}

/* Verifies that the key KEY is sane via HANDLE.  */
static gcry_error_t
_gcry_core_ac_key_test (gcry_core_context_t ctx,
			gcry_core_ac_handle_t handle,
			unsigned int flags,
			gcry_core_ac_key_t key)
{
  gcry_core_ac_spec_t algorithm;
  gcry_error_t err;
  gcry_core_mpi_t *mpis;

  algorithm = handle->algorithm;
  mpis = NULL;

  assert (algorithm->check_secret_key || handle->cb.cb);

  err = ac_mpi_array_from_data_set (ctx,
				    key->data,
				    &mpis,
				    algorithm->elements_skey);
  if (err)
    goto out;

  if (algorithm->check_secret_key)
    err = (*algorithm->check_secret_key) (ctx, flags, mpis);
  else
    {
      gcry_core_ac_cb_check_t cb_data;

      cb_data.skey = mpis;
      err = (*handle->cb.cb) (ctx, handle->cb.opaque,
			      GCRY_CORE_AC_CB_CHECK, &cb_data);
    }

 out:

  ac_mpi_array_release (ctx, mpis);

  return err;
}

/* Stores the number of bits of the key KEY in NBITS via HANDLE.  */
static gcry_error_t
_gcry_core_ac_key_get_nbits (gcry_core_context_t ctx,
			     gcry_core_ac_handle_t handle,
			     unsigned int flags,
			     gcry_core_ac_key_t key,
			     unsigned int *nbits)
{
  gcry_core_ac_spec_t algorithm;
  gcry_core_mpi_t *mpis;
  gcry_error_t err;
  unsigned int n;

  algorithm = handle->algorithm;
  mpis = NULL;

  assert (algorithm->get_nbits || handle->cb.cb);

  err = ac_mpi_array_from_data_set (ctx,
				    key->data,
				    &mpis,
				    algorithm->elements_pkey);
  if (err)
    goto out;

  if (algorithm->get_nbits)
    {
      n = (*algorithm->get_nbits) (ctx, flags, mpis);
      if (! n)
	/* FIXME, correct interface between lib and mod here?  */
	err = gcry_core_error (GPG_ERR_PUBKEY_ALGO);
    }
  else
    {
      gcry_core_ac_cb_nbits_t cb_data;

      cb_data.key = mpis;
      cb_data.n = &n;
      err = (*handle->cb.cb) (ctx, handle->cb.opaque,
			      GCRY_CORE_AC_CB_NBITS, &cb_data);
    }
  if (err)
    goto out;

  *nbits = n;

 out:

  ac_mpi_array_release (ctx, mpis);

  return err;
}

/* Writes the 20 byte long key grip of the key KEY to KEY_GRIP via
   HANDLE.  */
gcry_error_t
_gcry_core_ac_key_get_grip (gcry_core_context_t ctx,
			    gcry_core_ac_handle_t handle,
			    unsigned int flags,
			    gcry_core_ac_key_t key,
			    unsigned char *key_grip,
			    size_t *key_grip_n)
{
  gcry_core_ac_spec_t algorithm;
  gcry_core_mpi_t *mpis;
  gcry_error_t err;

  algorithm = handle->algorithm;
  mpis = NULL;

  assert (algorithm->keygrip || handle->cb.cb);

  if (key_grip)
    {
      err = ac_mpi_array_from_data_set (ctx,
					key->data, &mpis, algorithm->elements_pkey);
      if (err)
	goto out;

      if (*key_grip_n < algorithm->keygrip_size)
	{
	  err = gpg_error (GPG_ERR_TOO_SHORT);
	  goto out;
	}

      if (algorithm->keygrip)
	err = (*algorithm->keygrip) (ctx, flags, mpis, key_grip);
      else
	{
	  gcry_core_ac_cb_grip_t cb_data;

	  cb_data.key = mpis;
	  cb_data.grip = key_grip;
	  cb_data.elems = algorithm->elements_grip;

	  err = (*handle->cb.cb) (ctx, handle->cb.opaque,
				  GCRY_CORE_AC_CB_GRIP, &cb_data);
	}
      if (err)
	goto out;

      if (*key_grip_n != algorithm->keygrip_size)
	*key_grip_n = algorithm->keygrip_size;
      err = 0;
    }
  else
    {
      *key_grip_n = algorithm->keygrip_size;
      err = 0;
    }

 out:

  ac_mpi_array_release (ctx, mpis);

  return err;
}



/* 
 * Functions performing cryptographic operations.
 */

/* Encrypts the plain text MPI value DATA_PLAIN with the key public
   KEY under the control of the flags FLAGS and stores the resulting
   data set into DATA_ENCRYPTED.  */
static gcry_error_t
_gcry_core_ac_data_encrypt (gcry_core_context_t ctx,
			    gcry_core_ac_handle_t handle,
			    unsigned int flags,
			    gcry_core_ac_key_t key,
			    gcry_core_mpi_t data_plain,
			    gcry_core_ac_data_t *data_encrypted)
{
  gcry_core_ac_data_t data_encrypted_new;
  gcry_core_ac_spec_t algorithm;
  gcry_core_ac_data_t data_value;
  gcry_core_mpi_t *mpis_encrypted;
  gcry_core_mpi_t *mpis_key;
  gcry_error_t err;

  algorithm = handle->algorithm;
  data_encrypted_new = NULL;
  mpis_encrypted = NULL;
  mpis_key = NULL;
  data_value = NULL;

  assert (algorithm->encrypt || handle->cb.cb);

  if (key->type != GCRY_CORE_AC_KEY_PUBLIC)
    {
      err = gcry_core_error (GPG_ERR_WRONG_KEY_USAGE);
      goto out;
    }

  err = ac_mpi_array_from_data_set (ctx, key->data, &mpis_key,
				    algorithm->elements_pkey);
  if (err)
    goto out;

  mpis_encrypted = gcry_core_xcalloc (ctx,
				      strlen (algorithm->elements_enc) + 1,
				      sizeof (*mpis_encrypted));
  if (! mpis_encrypted)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  if (algorithm->encrypt)
    err = (*algorithm->encrypt) (ctx, flags,
				 mpis_encrypted, data_plain, mpis_key);
  else
    {
      gcry_core_ac_cb_encrypt_t cb_data;

      cb_data.resarr = mpis_encrypted;
      cb_data.data = data_plain;
      cb_data.pkey = mpis_key;
      cb_data.flags = flags;

      err = (*handle->cb.cb) (ctx, handle->cb.opaque,
			      GCRY_CORE_AC_CB_ENCRYPT, &cb_data);
    }
  if (err)
    goto out;

  /* Convert encrypted data into data set.  */
  err = ac_mpi_array_to_data_set (ctx, &data_encrypted_new,
				  mpis_encrypted, algorithm->elements_enc);
  if (err)
    goto out;

  *data_encrypted = data_encrypted_new;

 out:

  /* Deallocate resources.  */

  ac_mpi_array_release (ctx, mpis_encrypted);
  ac_mpi_array_release (ctx, mpis_key);

  return err;
}

/* Decrypts the encrypted data contained in the data set
   DATA_ENCRYPTED with the secret key KEY under the control of the
   flags FLAGS and stores the resulting plain text MPI value in
   DATA_PLAIN.  */
static gcry_error_t
_gcry_core_ac_data_decrypt (gcry_core_context_t ctx,
			    gcry_core_ac_handle_t handle,
			    unsigned int flags,
			    gcry_core_ac_key_t key,
			    gcry_core_mpi_t *data_plain,
			    gcry_core_ac_data_t data_encrypted)
{
  gcry_core_ac_spec_t algorithm;
  gcry_core_mpi_t data_decrypted;
  gcry_core_mpi_t *mpis_encrypted;
  gcry_core_mpi_t *mpis_key;
  gcry_error_t err;

  algorithm = handle->algorithm;
  data_decrypted = NULL;
  mpis_encrypted = NULL;
  mpis_key = NULL;

  assert (algorithm->decrypt || handle->cb.cb);

  if (key->type != GCRY_CORE_AC_KEY_SECRET)
    {
      err = gcry_core_error (GPG_ERR_WRONG_KEY_USAGE);
      goto out;
    }

  err = ac_mpi_array_from_data_set (ctx, key->data, &mpis_key,
				    algorithm->elements_skey);
  if (err)
    goto out;

  /* Convert encrypted data.  */
  err = ac_mpi_array_from_data_set (ctx, data_encrypted,
				    &mpis_encrypted, algorithm->elements_enc);
  if (err)
    goto out;

  if (algorithm->decrypt)
    err = (*algorithm->decrypt) (ctx, flags, &data_decrypted,
				 mpis_encrypted, mpis_key);
  else
    {
      gcry_core_ac_cb_decrypt_t cb_data;

      cb_data.result = &data_decrypted;
      cb_data.data = mpis_encrypted;
      cb_data.skey = mpis_key;
      cb_data.flags = flags;

      err = (*handle->cb.cb) (ctx, handle->cb.opaque,
			      GCRY_CORE_AC_CB_DECRYPT, &cb_data);
    }
  if (err)
    goto out;

  *data_plain = data_decrypted;

 out:

  /* Deallocate resources.  */
  ac_mpi_array_release (ctx, mpis_encrypted);
  ac_mpi_array_release (ctx, mpis_key);

  return err;
}

/* Signs the data contained in DATA with the secret key KEY and stores
   the resulting signature data set in DATA_SIGNATURE.  */
static gcry_error_t
_gcry_core_ac_data_sign (gcry_core_context_t ctx,
			 gcry_core_ac_handle_t handle,
			 unsigned int flags,
			 gcry_core_ac_key_t key,
			 gcry_core_mpi_t data,
			 gcry_core_ac_data_t *data_signature)
{
  gcry_core_ac_spec_t algorithm;
  gcry_core_ac_data_t data_signed;
  gcry_core_ac_data_t data_value;
  gcry_core_mpi_t *mpis_signature;
  gcry_core_mpi_t *mpis_key;
  gcry_error_t err;

  algorithm = handle->algorithm;
  data_signed = NULL;
  data_value = NULL;
  mpis_signature = NULL;
  mpis_key = NULL;

  assert (algorithm->sign || handle->cb.cb);

  if (key->type != GCRY_CORE_AC_KEY_SECRET)
    {
      err = gcry_core_error (GPG_ERR_WRONG_KEY_USAGE);
      goto out;
    }

  /* Convert key.  */
  err = ac_mpi_array_from_data_set (ctx, key->data, &mpis_key,
				    algorithm->elements_skey);
  if (err)
    goto out;

  mpis_signature = gcry_core_xcalloc (ctx,
				      strlen (algorithm->elements_sig) + 1,
				      sizeof (*mpis_signature));
  if (! mpis_signature)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* Sign.  */
  if (algorithm->sign)
    err = (*algorithm->sign) (ctx, flags, mpis_signature, data, mpis_key);
  else
    {
      gcry_core_ac_cb_sign_t cb_data;

      cb_data.resarr = mpis_signature;
      cb_data.data = data;
      cb_data.skey = mpis_key;
      cb_data.flags = 0;	/* FIXME?  */

      err = (*handle->cb.cb) (ctx, handle->cb.opaque,
			      GCRY_CORE_AC_CB_SIGN, &cb_data);
    }
  if (err)
    goto out;

  /* Convert signed data into data set.  */
  err = ac_mpi_array_to_data_set (ctx, &data_signed,
				  mpis_signature, algorithm->elements_sig);
  if (err)
    goto out;

  /* Done.  */
  *data_signature = data_signed;

 out:

  /* Deallocate resources.  */
  ac_mpi_array_release (ctx, mpis_signature);
  ac_mpi_array_release (ctx, mpis_key);

  return err;
}

/* Verifies that the signature contained in the data set
   DATA_SIGNATURE is indeed the result of signing the data contained
   in DATA with the secret key belonging to the public key KEY.  */
static gcry_error_t
_gcry_core_ac_data_verify (gcry_core_context_t ctx,
			   gcry_core_ac_handle_t handle,
			   unsigned int flags,
			   gcry_core_ac_key_t key,
			   gcry_core_mpi_t data,
			   gcry_core_ac_data_t data_signature)
{
  gcry_core_ac_spec_t algorithm;
  gcry_core_mpi_t *mpis_signature;
  gcry_core_mpi_t *mpis_key;
  gcry_error_t err;

  algorithm = handle->algorithm;
  mpis_signature = NULL;
  mpis_key = NULL;

  assert (algorithm->verify || handle->cb.cb);

  if (key->type != GCRY_CORE_AC_KEY_PUBLIC)
    {
      err = gcry_core_error (GPG_ERR_WRONG_KEY_USAGE);
      goto out;
    }

  err = ac_mpi_array_from_data_set (ctx, key->data, &mpis_key,
				    algorithm->elements_pkey);
  if (err)
    goto out;

  err = ac_mpi_array_from_data_set (ctx, data_signature,
				    &mpis_signature, algorithm->elements_sig);
  if (err)
    goto out;

  /* Verify signature.  */
  if (algorithm->verify)
    err = (*algorithm->verify) (ctx, flags,
				data, mpis_signature, mpis_key, NULL, NULL);
  else
    {
      gcry_core_ac_cb_verify_t cb_data;

      cb_data.hash = data;
      cb_data.data = mpis_signature;
      cb_data.pkey = mpis_key;
      cb_data.flags = 0;	/* FIXME?  */

      err = (*handle->cb.cb) (ctx, handle->cb.opaque,
			      GCRY_CORE_AC_CB_VERIFY, &cb_data);
    }

 out:

  ac_mpi_array_release (ctx, mpis_signature);
  ac_mpi_array_release (ctx, mpis_key);

  return err;
}




/*
 * Implementation of encoding methods (em).
 */

/* Type for functions that encode or decode (hence the name) a
   message.  */
typedef gcry_error_t (*gcry_core_ac_em_dencode_t) (gcry_core_context_t ctx,
						   unsigned int flags,
						   void *options,
						   gcry_core_ac_io_t *io_read,
						   gcry_core_ac_io_t *io_write);

/* Fill the buffer BUFFER which is BUFFER_N bytes long with non-zero
   random bytes of random level LEVEL.  */
static void
em_randomize_nonzero (gcry_core_context_t ctx,
		      unsigned char *buffer, size_t buffer_n,
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
	  buffer_rand = gcry_core_random_bytes_secure (ctx,
						       buffer_rand_n, level);

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
	  gcry_core_free (ctx, buffer_rand);
	}
    }
  while (zeros);
}

/* Encode a message according to the Encoding Method for Encryption
   `PKCS-V1_5' (EME-PKCS-V1_5).  */
static gcry_error_t
eme_pkcs_v1_5_encode (gcry_core_context_t ctx,
		      unsigned int flags, void *opts,
		      gcry_core_ac_io_t *ac_io_read,
		      gcry_core_ac_io_t *ac_io_write)
{
  gcry_core_ac_eme_pkcs_v1_5_t *options;
  gcry_error_t err;
  unsigned char *buffer;
  unsigned char *ps;
  unsigned char *m;
  size_t m_n;
  unsigned int ps_n;
  unsigned int k;

  options = opts;
  buffer = NULL;
  m = NULL;

  err = _gcry_core_ac_io_read_all (ctx, 0, ac_io_read, &m, &m_n);
  if (err)
    goto out;

  /* Figure out key length in bytes.  */
  err = _gcry_core_ac_key_get_nbits (ctx, options->handle, 0, options->key, &k);
  if (err)
    goto out;

  k /= 8;
  if (m_n > k - 11)
    {
      /* Key is too short for message.  */
      err = gcry_core_error (GPG_ERR_TOO_SHORT);
      goto out;
    }

  /* According to this encoding method, the first byte of the encoded
     message is zero.  This byte will be lost anyway, when the encoded
     message is to be converted into an MPI, that's why we skip
     it.  */

  /* Allocate buffer.  */
  buffer = gcry_core_malloc (ctx, k - 1);
  if (! buffer)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  /* Generate an octet string PS of length k - mLen - 3 consisting
     of pseudorandomly generated nonzero octets.  The length of PS
     will be at least eight octets.  */
  ps_n = k - m_n - 3;
  ps = buffer + 1;
  em_randomize_nonzero (ctx, ps, ps_n, GCRY_STRONG_RANDOM);

  /* Concatenate PS, the message M, and other padding to form an
     encoded message EM of length k octets as:

     EM = 0x00 || 0x02 || PS || 0x00 || M.  */

  buffer[0] = 0x02;
  buffer[ps_n + 1] = 0x00;
  memcpy (buffer + ps_n + 2, m, m_n);

  err = _gcry_core_ac_io_write (ctx, 0, ac_io_write, buffer, k - 1);

 out:

  gcry_core_free (ctx, buffer);
  gcry_core_free (ctx, m);

  return err;
}

/* Decode a message according to the Encoding Method for Encryption
   `PKCS-V1_5' (EME-PKCS-V1_5).  */
static gcry_error_t
eme_pkcs_v1_5_decode (gcry_core_context_t ctx,
		      unsigned int flags, void *opts,
		      gcry_core_ac_io_t *ac_io_read,
		      gcry_core_ac_io_t *ac_io_write)
{
  gcry_core_ac_eme_pkcs_v1_5_t *options;
  unsigned char *buffer;
  unsigned char *em;
  size_t em_n;
  gcry_error_t err;
  unsigned int i;
  unsigned int k;

  options = opts;
  buffer = NULL;
  em = NULL;

  err = _gcry_core_ac_io_read_all (ctx, 0, ac_io_read, &em, &em_n);
  if (err)
    goto out;

  err = _gcry_core_ac_key_get_nbits (ctx, options->handle, 0, options->key, &k);
  if (err)
    goto out;
  k /= 8;

  /* Search for zero byte.  */
  for (i = 0; (i < em_n) && em[i]; i++);

  /* According to this encoding method, the first byte of the encoded
     message should be zero.  This byte is lost.  */

  if (! ((em_n >= 10)
	 && (em_n == (k - 1))
	 && (em[0] == 0x02)
	 && (i < em_n)
	 && ((i - 1) >= 8)))
    {
      err = gcry_core_error (GPG_ERR_DECRYPT_FAILED);
      goto out;
    }

  i++;
  buffer = gcry_core_malloc (ctx, em_n - i);
  if (! buffer)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  memcpy (buffer, em + i, em_n - i);
  err = _gcry_core_ac_io_write (ctx, 0, ac_io_write, buffer, em_n - i);

 out:

  gcry_core_free (ctx, buffer);
  gcry_core_free (ctx, em);

  return err;
}

static gcry_error_t
emsa_pkcs_v1_5_encode_data_cb (gcry_core_context_t ctx, void *opaque,
			       unsigned char *buffer, size_t buffer_n)
{
  gcry_core_md_hd_t md_handle;

  md_handle = opaque;
  gcry_core_md_write (ctx, md_handle, buffer, buffer_n);

  return 0;
}


/* Encode a message according to the Encoding Method for Signatures
   with Appendix `PKCS-V1_5' (EMSA-PKCS-V1_5).  */
static gcry_error_t
emsa_pkcs_v1_5_encode (gcry_core_context_t ctx,
		       unsigned int flags, void *opts,
		       gcry_core_ac_io_t *ac_io_read,
		       gcry_core_ac_io_t *ac_io_write)
{
  gcry_core_ac_emsa_pkcs_v1_5_t *options;
  gcry_error_t err;
  gcry_core_md_hd_t md;
  unsigned char *t;
  size_t t_n;
  unsigned char *h;
  size_t h_n;
  unsigned char *ps;
  size_t ps_n;
  unsigned char *buffer;
  size_t buffer_n;
  unsigned char *asn;
  size_t asn_n;
  unsigned int i;
  
  options = opts;
  buffer = NULL;
  md = NULL;
  ps = NULL;
  t = NULL;

  /* Create hashing handle and get the necessary information.  */
  err = gcry_core_md_open (ctx, &md, options->md, 0);
  if (err)
    goto out;

  asn_n = DIM (asn);
  asn = options->md->asnoid;
  asn_n = options->md->asnlen;
  h_n = options->md->mdlen;

  err = _gcry_core_ac_io_process (ctx, 0,
				  ac_io_read, emsa_pkcs_v1_5_encode_data_cb, md);
  if (err)
    goto out;

  h = gcry_core_md_read (ctx, md, 0);

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
  t = gcry_core_malloc (ctx, t_n);
  if (! t)
    {
      err = gcry_core_error_from_errno (errno);
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
      err = gcry_core_error (GPG_ERR_TOO_SHORT);
      goto out;
    }

  /* Generate an octet string PS consisting of emLen - tLen - 3 octets
     with hexadecimal value 0xFF.  The length of PS will be at least 8
     octets.  */
  ps_n = options->em_n - t_n - 3;
  ps = gcry_core_malloc (ctx, ps_n);
  if (! ps)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }
  for (i = 0; i < ps_n; i++)
    ps[i] = 0xFF;

  /* Concatenate PS, the DER encoding T, and other padding to form the
     encoded message EM as:

     EM = 0x00 || 0x01 || PS || 0x00 || T.  */

  buffer_n = ps_n + t_n + 3;
  buffer = gcry_core_malloc (ctx, buffer_n);
  if (! buffer)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  buffer[0] = 0x00;
  buffer[1] = 0x01;
  for (i = 0; i < ps_n; i++)
    buffer[2 + i] = ps[i];
  buffer[2 + ps_n] = 0x00;
  for (i = 0; i < t_n; i++)
    buffer[3 + ps_n + i] = t[i];

  err = _gcry_core_ac_io_write (ctx, 0, ac_io_write, buffer, buffer_n);

 out:

  gcry_core_md_close (ctx, md);

  gcry_core_free (ctx, buffer);
  gcry_core_free (ctx, ps);
  gcry_core_free (ctx, t);

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
static gcry_error_t
ac_data_dencode (gcry_core_context_t ctx,
		 gcry_core_ac_em_t method, dencode_action_t action,
		 unsigned int flags, void *options,
		 gcry_core_ac_io_t *ac_io_read,
		 gcry_core_ac_io_t *ac_io_write)
{
  struct
  {
    gcry_core_ac_em_t method;
    gcry_core_ac_em_dencode_t encode;
    gcry_core_ac_em_dencode_t decode;
  } methods[] =
    {
      { GCRY_CORE_AC_EME_PKCS_V1_5,
	eme_pkcs_v1_5_encode, eme_pkcs_v1_5_decode },
      { GCRY_CORE_AC_EMSA_PKCS_V1_5,
	emsa_pkcs_v1_5_encode, NULL },
    };
  size_t methods_n;
  gcry_error_t err;
  unsigned int i;

  methods_n = sizeof (methods) / sizeof (*methods);

  for (i = 0; i < methods_n; i++)
    if (methods[i].method == method)
      break;
  if (i == methods_n)
    {
      err = gcry_core_error (GPG_ERR_NOT_FOUND);
      goto out;
    }

  err = 0;
  switch (action)
    {
    case DATA_ENCODE:
      if (methods[i].encode)
	/* FIXME? */
	err = (*methods[i].encode) (ctx, flags, options, ac_io_read, ac_io_write);
      break;

    case DATA_DECODE:
      if (methods[i].decode)
	/* FIXME? */
	err = (*methods[i].decode) (ctx, flags, options, ac_io_read, ac_io_write);
      break;

    default:
      err = gcry_core_error (GPG_ERR_INV_ARG);
      break;
    }

 out:

  return err;
}

/* Encode a message according to the encoding method METHOD.  OPTIONS
   must be a pointer to a method-specific structure
   (gcry_ac_em*_t).  */
static gcry_error_t
ac_data_encode (gcry_core_context_t ctx,
		gcry_core_ac_em_t method,
		unsigned int flags, void *options,
		gcry_core_ac_io_t *ac_io_read,
		gcry_core_ac_io_t *ac_io_write)
{
  return ac_data_dencode (ctx, method, DATA_ENCODE, flags, options,
			  ac_io_read, ac_io_write);
}

static gcry_error_t
_gcry_core_ac_data_encode (gcry_core_context_t ctx,
			   gcry_core_ac_em_t method,
			   unsigned int flags, void *options,
			   gcry_core_ac_io_t *ac_io_read,
			   gcry_core_ac_io_t *ac_io_write)
{
  return ac_data_encode (ctx, method, flags, options, ac_io_read, ac_io_write);
}
			   

/* Dencode a message according to the encoding method METHOD.  OPTIONS
   must be a pointer to a method-specific structure
   (gcry_ac_em*_t).  */
static gcry_error_t
ac_data_decode (gcry_core_context_t ctx,
		gcry_core_ac_em_t method,
		unsigned int flags, void *options,
		gcry_core_ac_io_t *ac_io_read,
		gcry_core_ac_io_t *ac_io_write)
{
  return ac_data_dencode (ctx, method, DATA_DECODE, flags, options,
			  ac_io_read, ac_io_write);
}

static gcry_error_t
_gcry_core_ac_data_decode (gcry_core_context_t ctx,
			   gcry_core_ac_em_t method,
			   unsigned int flags, void *options,
			   gcry_core_ac_io_t *ac_io_read,
			   gcry_core_ac_io_t *ac_io_write)
{
  return ac_data_decode (ctx, method, flags, options, ac_io_read, ac_io_write);
}

/* Convert an MPI into an octet string.  */
static void
_gcry_core_ac_mpi_to_os (gcry_core_context_t ctx,
		      unsigned int flags,
			 gcry_core_mpi_t mpi, unsigned char *os, size_t os_n)
{
  unsigned long digit;
  gcry_core_mpi_t base;
  unsigned int i;
  unsigned int n;
  gcry_core_mpi_t m;
  gcry_core_mpi_t d;

  base = gcry_core_mpi_new (ctx, 0);
  gcry_core_mpi_set_ui (ctx, base, 256);

  n = 0;
  m = gcry_core_mpi_copy (ctx, mpi);
  while (gcry_core_mpi_cmp_ui (ctx, m, 0))
    {
      n++;
      gcry_core_mpi_div (ctx, m, NULL, m, base, 0);
    }

  gcry_core_mpi_set (ctx, m, mpi);
  d = gcry_core_mpi_new (ctx, 0);
  for (i = 0; (i < n) && (i < os_n); i++)
    {
      gcry_core_mpi_mod (ctx, d, m, base);
      gcry_core_mpi_get_ui (ctx, d, &digit);
      gcry_core_mpi_div (ctx, m, NULL, m, base, 0);
      os[os_n - i - 1] = (digit & 0xFF);
    }

  for (; i < os_n; i++)
    os[os_n - i - 1] = 0;

  gcry_core_mpi_release (ctx, base);
  gcry_core_mpi_release (ctx, d);
  gcry_core_mpi_release (ctx, m);
}

/* Convert an MPI into an newly allocated octet string.  */
static gcry_error_t
_gcry_core_ac_mpi_to_os_alloc (gcry_core_context_t ctx,
		      unsigned int flags,
			       gcry_core_mpi_t mpi, unsigned char **os, size_t *os_n)
{
  unsigned char *buffer;
  size_t buffer_n;
  gcry_error_t err;
  unsigned int nbits;

  nbits = gcry_core_mpi_get_nbits (ctx, mpi);
  buffer_n = (nbits + 7) / 8;
  buffer = gcry_core_malloc (ctx, buffer_n);
  if (! buffer)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }

  _gcry_core_ac_mpi_to_os (ctx, 0, mpi, buffer, buffer_n);
  *os = buffer;
  *os_n = buffer_n;
  err = 0;

 out:

  return err;
}

/* Convert an octet string into an MPI.  */
static void
_gcry_core_ac_os_to_mpi (gcry_core_context_t ctx,
		      unsigned int flags,
			 gcry_core_mpi_t mpi, unsigned char *os, size_t os_n)
{
  unsigned int i;
  gcry_core_mpi_t xi;
  gcry_core_mpi_t x;
  gcry_core_mpi_t a;
  
  a = gcry_core_mpi_new (ctx, 0);
  gcry_core_mpi_set_ui (ctx, a, 1);
  x = gcry_core_mpi_new (ctx, 0);
  gcry_core_mpi_set_ui (ctx, x, 0);
  xi = gcry_core_mpi_new (ctx, 0);

  for (i = 0; i < os_n; i++)
    {
      gcry_core_mpi_mul_ui (ctx, xi, a, os[os_n - i - 1]);
      gcry_core_mpi_add (ctx, x, x, xi);
      gcry_core_mpi_mul_ui (ctx, a, a, 256);
    }
      
  gcry_core_mpi_release (ctx, xi);
  gcry_core_mpi_release (ctx, a);

  gcry_core_mpi_set (ctx, mpi, x);
  gcry_core_mpi_release (ctx, x);
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
   there for.  */

typedef gcry_error_t (*gcry_core_ac_dencode_prepare_t) (gcry_core_context_t ctx,
							gcry_core_ac_handle_t h,
							gcry_core_ac_key_t key,
							void *opts,
							void *opts_em);

/* The `dencode_prepare' function for ES-PKCS-V1_5.  */
static gcry_error_t
ac_es_dencode_prepare_pkcs_v1_5 (gcry_core_context_t ctx,
				 gcry_core_ac_handle_t handle,
				 gcry_core_ac_key_t key,
				 void *opts, void *opts_em)
{
  gcry_core_ac_eme_pkcs_v1_5_t *options_em;

  options_em = opts_em;

  options_em->handle = handle;
  options_em->key = key;

  return 0;
}

/* The `dencode_prepare' function for SSA-PKCS-V1_5.  */
static gcry_error_t
ac_ssa_dencode_prepare_pkcs_v1_5 (gcry_core_context_t ctx,
				  gcry_core_ac_handle_t handle,
				  gcry_core_ac_key_t key,
				  void *opts, void *opts_em)
{
  gcry_core_ac_emsa_pkcs_v1_5_t *options_em;
  gcry_core_ac_ssa_pkcs_v1_5_t *options;
  gcry_error_t err;
  unsigned int k;

  options_em = opts_em;
  options = opts;

  err = _gcry_core_ac_key_get_nbits (ctx, handle, 0, key, &k);
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
  gcry_core_ac_scheme_t scheme;
  gcry_core_ac_em_t scheme_encoding;
  gcry_core_ac_dencode_prepare_t dencode_prepare;
  size_t options_em_n;
} ac_scheme_t;

/* List of supported Schemes.  */
static ac_scheme_t ac_schemes[] =
  {
    { GCRY_CORE_AC_ES_PKCS_V1_5, GCRY_CORE_AC_EME_PKCS_V1_5,
      ac_es_dencode_prepare_pkcs_v1_5,
      sizeof (gcry_core_ac_eme_pkcs_v1_5_t) },
    { GCRY_CORE_AC_SSA_PKCS_V1_5, GCRY_CORE_AC_EMSA_PKCS_V1_5,
      ac_ssa_dencode_prepare_pkcs_v1_5,
      sizeof (gcry_core_ac_emsa_pkcs_v1_5_t) }
  };

/* Lookup a scheme by it's ID.  */
static ac_scheme_t *
ac_scheme_get (gcry_core_ac_scheme_t scheme)
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
static gcry_error_t
ac_dencode_prepare (gcry_core_context_t ctx, gcry_core_ac_handle_t handle,
		    gcry_core_ac_key_t key, void *opts,
		    ac_scheme_t scheme, void **opts_em)
{
  gcry_error_t err;
  void *options_em;

  options_em = gcry_core_malloc (ctx, scheme.options_em_n);
  if (! options_em)
    {
      err = gcry_core_error_from_errno (errno);
      goto out;
    }
  
  err = (*scheme.dencode_prepare) (ctx, handle, key, opts, options_em);
  if (err)
    goto out;

  *opts_em = options_em;

 out:

  if (err)
    free (options_em);

  return err;
}

/* Convert a data set into a single MPI; currently, this is only
   supported for data sets containing a single MPI.  */
static gcry_error_t
ac_data_set_to_mpi (gcry_core_context_t ctx,
		    gcry_core_ac_data_t data, gcry_core_mpi_t *mpi)
{
  gcry_error_t err;
  gcry_core_mpi_t mpi_new;
  unsigned int elems;

  elems = _gcry_core_ac_data_length (ctx, 0, data);

  if (elems != 1)
    {
      /* FIXME: I guess, we should be more flexible in this respect by
	 allowing the actual encryption/signature schemes to implement
	 this conversion mechanism.  */
      err = gcry_core_error (GPG_ERR_CONFLICT);
      goto out;
    }

  err = _gcry_core_ac_data_get_idx (ctx, 0,
				    data, 0,
				    NULL, &mpi_new);
  if (err)
    goto out;

  *mpi = mpi_new;

 out:

  return err;
}

/* Encrypts the plain text message contained in M, which is of size
   M_N, with the public key KEY_PUBLIC according to the Encryption
   Scheme SCHEME_ID.  HANDLE is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The encrypted message will be stored in C and C_N.  */
static gcry_error_t
_gcry_core_ac_data_encrypt_scheme (gcry_core_context_t ctx,
				   gcry_core_ac_handle_t handle,
				   gcry_core_ac_scheme_t scheme_id,
				   unsigned int flags, void *opts,
				   gcry_core_ac_key_t key,
				   gcry_core_ac_io_t *io_message,
				   gcry_core_ac_io_t *io_cipher)
{
  gcry_error_t err;
  gcry_core_ac_io_t io_em;
  unsigned char *em;
  size_t em_n;
  gcry_core_mpi_t mpi_plain;
  gcry_core_ac_data_t data_encrypted;
  gcry_core_mpi_t mpi_encrypted;
  unsigned char *buffer;
  size_t buffer_n;
  void *opts_em;
  ac_scheme_t *scheme;

  data_encrypted = NULL;
  mpi_encrypted = NULL;
  mpi_plain = NULL;
  opts_em = NULL;
  buffer = NULL;
  em = NULL;

  scheme = ac_scheme_get (scheme_id);
  if (! scheme)
    {
      err = gcry_core_error (GPG_ERR_NO_ENCRYPTION_SCHEME);
      goto out;
    }

  if (key->type != GCRY_CORE_AC_KEY_PUBLIC)
    {
      err = gcry_core_error (GPG_ERR_WRONG_KEY_USAGE);
      goto out;
    }

  err = ac_dencode_prepare (ctx, handle, key, opts, *scheme, &opts_em);
  if (err)
    goto out;

  _gcry_core_ac_io_init (ctx, 0, &io_em, GCRY_CORE_AC_IO_WRITABLE,
			 GCRY_CORE_AC_IO_STRING, &em, &em_n);

  err = _gcry_core_ac_data_encode (ctx, scheme->scheme_encoding, 0, opts_em,
				   io_message, &io_em);
  if (err)
    goto out;

  mpi_plain = gcry_core_mpi_snew (ctx, 0);
  _gcry_core_ac_os_to_mpi (ctx, 0, mpi_plain, em, em_n);

  err = _gcry_core_ac_data_encrypt (ctx, handle, 0, key,
				    mpi_plain, &data_encrypted);
  if (err)
    goto out;

  err = ac_data_set_to_mpi (ctx, data_encrypted, &mpi_encrypted);
  if (err)
    goto out;

  err = _gcry_core_ac_mpi_to_os_alloc (ctx, 0,
				       mpi_encrypted, &buffer, &buffer_n);
  if (err)
    goto out;

  err = _gcry_core_ac_io_write (ctx, 0, io_cipher, buffer, buffer_n);

 out:

  _gcry_core_ac_data_destroy (ctx, 0, data_encrypted);
  gcry_core_mpi_release (ctx, mpi_encrypted);
  gcry_core_mpi_release (ctx, mpi_plain);
  gcry_core_free (ctx, opts_em);
  gcry_core_free (ctx, buffer);
  gcry_core_free (ctx, em);

  return err;
}


/* Decryptes the cipher message contained in C, which is of size C_N,
   with the secret key KEY_SECRET according to the Encryption Scheme
   SCHEME_ID.  Handle is used for accessing the low-level
   cryptographic primitives.  If OPTS is not NULL, it has to be an
   anonymous structure specific to the chosen scheme (gcry_ac_es_*_t).
   The decrypted message will be stored in M and M_N.  */
static gcry_error_t
_gcry_core_ac_data_decrypt_scheme (gcry_core_context_t ctx,
				   gcry_core_ac_handle_t handle,
				   gcry_core_ac_scheme_t scheme_id,
				   unsigned int flags, void *opts,
				   gcry_core_ac_key_t key,
				   gcry_core_ac_io_t *io_cipher,
				   gcry_core_ac_io_t *io_message)
{
  gcry_core_ac_io_t io_em;
  gcry_error_t err;
  gcry_core_ac_data_t data_encrypted;
  unsigned char *em;
  size_t em_n;
  gcry_core_mpi_t mpi_encrypted;
  gcry_core_mpi_t mpi_decrypted;
  void *opts_em;
  ac_scheme_t *scheme;
  const char *elements_enc;
  size_t elements_enc_n;
  unsigned char *c;
  size_t c_n;

  data_encrypted = NULL;
  mpi_encrypted = NULL;
  mpi_decrypted = NULL;
  elements_enc = NULL;
  opts_em = NULL;
  em = NULL;
  c = NULL;

  scheme = ac_scheme_get (scheme_id);
  if (! scheme)
    {
      err = gcry_core_error (GPG_ERR_NO_ENCRYPTION_SCHEME);
      goto out;
    }

  if (key->type != GCRY_CORE_AC_KEY_SECRET)
    {
      err = gcry_core_error (GPG_ERR_WRONG_KEY_USAGE);
      goto out;
    }

  err = _gcry_core_ac_io_read_all (ctx, 0, io_cipher, &c, &c_n);
  if (err)
    goto out;

  mpi_encrypted = gcry_core_mpi_snew (ctx, 0);
  _gcry_core_ac_os_to_mpi (ctx, 0, mpi_encrypted, c, c_n);

  elements_enc = handle->algorithm->elements_enc;
  elements_enc_n = strlen (elements_enc);
  if (elements_enc_n != 1)
    {
      /* FIXME? */
      err = gcry_core_error (GPG_ERR_CONFLICT);
      goto out;
    }

  err = _gcry_core_ac_data_new (ctx, 0, &data_encrypted);
  if (err)
    goto out;

  err = _gcry_core_ac_data_set (ctx, 0,
				data_encrypted,
				elements_enc, mpi_encrypted);
  if (err)
    goto out;

  err = _gcry_core_ac_data_decrypt (ctx, handle, 0, key,
				    &mpi_decrypted, data_encrypted);
  if (err)
    goto out;

  err = _gcry_core_ac_mpi_to_os_alloc (ctx, 0, mpi_decrypted, &em, &em_n);
  if (err)
    goto out;

  err = ac_dencode_prepare (ctx, handle, key, opts, *scheme, &opts_em);
  if (err)
    goto out;

  _gcry_core_ac_io_init (ctx, 0, &io_em,
			 GCRY_CORE_AC_IO_READABLE, GCRY_CORE_AC_IO_STRING,
			 em, em_n);

  err = _gcry_core_ac_data_decode (ctx, scheme->scheme_encoding, 0, opts_em,
				   &io_em, io_message);
  if (err)
    goto out;

 out:
  
  _gcry_core_ac_data_destroy (ctx, 0, data_encrypted);
  gcry_core_mpi_release (ctx, mpi_encrypted);
  gcry_core_mpi_release (ctx, mpi_decrypted);
  gcry_core_free (ctx, opts_em);
  gcry_core_free (ctx, em);
  gcry_core_free (ctx, c);

  return err;
}

/* Signs the message contained in M, which is of size M_N, with the
   secret key KEY according to the Signature Scheme SCHEME_ID.  Handle
   is used for accessing the low-level cryptographic primitives.  If
   OPTS is not NULL, it has to be an anonymous structure specific to
   the chosen scheme (gcry_ac_ssa_*_t).  The signed message will be
   stored in S and S_N.  */
static gcry_error_t
_gcry_core_ac_data_sign_scheme (gcry_core_context_t ctx,
				gcry_core_ac_handle_t handle,
				gcry_core_ac_scheme_t scheme_id,
				unsigned int flags, void *opts,
				gcry_core_ac_key_t key,
				gcry_core_ac_io_t *io_message,
				gcry_core_ac_io_t *io_signature)
{
  gcry_core_ac_io_t io_em;
  gcry_error_t err;
  gcry_core_ac_data_t data_signed;
  unsigned char *em;
  size_t em_n;
  gcry_core_mpi_t mpi;
  void *opts_em;
  unsigned char *buffer;
  size_t buffer_n;
  gcry_core_mpi_t mpi_signed;
  ac_scheme_t *scheme;

  data_signed = NULL;
  mpi_signed = NULL;
  opts_em = NULL;
  buffer = NULL;
  mpi = NULL;
  em = NULL;

  if (key->type != GCRY_CORE_AC_KEY_SECRET)
    {
      err = gcry_core_error (GPG_ERR_WRONG_KEY_USAGE);
      goto out;
    }

  scheme = ac_scheme_get (scheme_id);
  if (! scheme)
    {
      /* FIXME: adjust api of scheme_get in respect to err codes.  */
      err = gcry_core_error (GPG_ERR_NO_SIGNATURE_SCHEME);
      goto out;
    }

  err = ac_dencode_prepare (ctx, handle, key, opts, *scheme, &opts_em);
  if (err)
    goto out;

  _gcry_core_ac_io_init (ctx, 0, &io_em, GCRY_CORE_AC_IO_WRITABLE,
			 GCRY_CORE_AC_IO_STRING, &em, &em_n);

  err = _gcry_core_ac_data_encode (ctx, scheme->scheme_encoding, 0, opts_em,
				   io_message, &io_em);
  if (err)
    goto out;

  mpi = gcry_core_mpi_new (ctx, 0);
  _gcry_core_ac_os_to_mpi (ctx, 0, mpi, em, em_n);

  err = _gcry_core_ac_data_sign (ctx, handle, 0, key, mpi, &data_signed);
  if (err)
    goto out;

  err = ac_data_set_to_mpi (ctx, data_signed, &mpi_signed);
  if (err)
    goto out;

  err = _gcry_core_ac_mpi_to_os_alloc (ctx, 0,
				       mpi_signed, &buffer, &buffer_n);
  if (err)
    goto out;

  err = _gcry_core_ac_io_write (ctx, 0,
				io_signature, buffer, buffer_n);

 out:

  _gcry_core_ac_data_destroy (ctx, 0, data_signed);
  gcry_core_mpi_release (ctx, mpi_signed);
  gcry_core_mpi_release (ctx, mpi);
  gcry_core_free (ctx, opts_em);
  gcry_core_free (ctx,buffer);
  gcry_core_free (ctx, em);

  return err;
}

/* Verifies that the signature contained in S, which is of length S_N,
   is indeed the result of signing the message contained in M, which
   is of size M_N, with the secret key belonging to the public key
   KEY_PUBLIC.  If OPTS is not NULL, it has to be an anonymous
   structure (gcry_ac_ssa_*_t) specific to the Signature Scheme, whose
   ID is contained in SCHEME_ID.  */
static gcry_error_t
_gcry_core_ac_data_verify_scheme (gcry_core_context_t ctx,
				  gcry_core_ac_handle_t handle,
				  gcry_core_ac_scheme_t scheme_id,
				  unsigned int flags, void *opts,
				  gcry_core_ac_key_t key,
				  gcry_core_ac_io_t *io_message,
				  gcry_core_ac_io_t *io_signature)
{
  gcry_core_ac_io_t io_em;
  gcry_error_t err;
  gcry_core_ac_data_t data_signed;
  unsigned char *em;
  size_t em_n;
  void *opts_em;
  gcry_core_mpi_t mpi_signature;
  gcry_core_mpi_t mpi_data;
  ac_scheme_t *scheme;
  const char *elements_sig;
  size_t elements_sig_n;
  unsigned char *s;
  size_t s_n;

  mpi_signature = NULL;
  elements_sig = NULL;
  data_signed = NULL;
  mpi_data = NULL;
  opts_em = NULL;
  em = NULL;
  s = NULL;

  if (key->type != GCRY_CORE_AC_KEY_PUBLIC)
    {
      err = gcry_core_error (GPG_ERR_WRONG_KEY_USAGE);
      goto out;
    }

  scheme = ac_scheme_get (scheme_id);
  if (! scheme)
    {
      err = gcry_core_error (GPG_ERR_NO_SIGNATURE_SCHEME);
      goto out;
    }

  err = ac_dencode_prepare (ctx, handle, key, opts, *scheme, &opts_em);
  if (err)
    goto out;

  _gcry_core_ac_io_init (ctx, 0,
			 &io_em, GCRY_CORE_AC_IO_WRITABLE,
			 GCRY_CORE_AC_IO_STRING, &em, &em_n);

  err = _gcry_core_ac_data_encode (ctx,
				   scheme->scheme_encoding, 0, opts_em,
				   io_message, &io_em);
  if (err)
    goto out;

  mpi_data = gcry_core_mpi_new (ctx,0);
  _gcry_core_ac_os_to_mpi (ctx, 0, mpi_data, em, em_n);

  err = _gcry_core_ac_io_read_all (ctx, 0, io_signature, &s, &s_n);
  if (err)
    goto out;

  mpi_signature = gcry_core_mpi_new (ctx, 0);
  _gcry_core_ac_os_to_mpi (ctx, 0, mpi_signature, s, s_n);

  elements_sig = handle->algorithm->elements_sig;
  elements_sig_n = strlen (elements_sig);
  if (elements_sig_n != 1)
    {
      /* FIXME? */
      err = gcry_core_error (GPG_ERR_CONFLICT);
      goto out;
    }

  err = _gcry_core_ac_data_new (ctx, 0, &data_signed);
  if (err)
    goto out;

  err = _gcry_core_ac_data_set (ctx, 0,
				data_signed,
				elements_sig, mpi_signature);
  if (err)
    goto out;

  gcry_core_mpi_release (ctx,mpi_signature);
  mpi_signature = NULL;
  
  err = _gcry_core_ac_data_verify (ctx, handle, 0,
				   key, mpi_data, data_signed);

 out:

  _gcry_core_ac_data_destroy (ctx, 0, data_signed);
  gcry_core_mpi_release (ctx, mpi_signature);
  gcry_core_mpi_release (ctx, mpi_data);
  gcry_core_free (ctx,opts_em);
  gcry_core_free (ctx, em);
  gcry_core_free (ctx, s);

  return err;
}



struct gcry_core_subsystem_ac _gcry_subsystem_ac =
  {
    NULL,
    _gcry_core_ac_data_new,
    _gcry_core_ac_data_destroy,
    _gcry_core_ac_data_copy,
    _gcry_core_ac_data_length,
    _gcry_core_ac_data_clear,
    _gcry_core_ac_data_set,
    _gcry_core_ac_data_get,
    _gcry_core_ac_data_get_idx,
    _gcry_core_ac_data_to_sexp,
    _gcry_core_ac_data_from_sexp,
    _gcry_core_ac_io_init_va,
    _gcry_core_ac_open,
    _gcry_core_ac_set_cb,
    _gcry_core_ac_close,
    _gcry_core_ac_key_init,
    _gcry_core_ac_key_pair_generate,
    _gcry_core_ac_key_pair_extract,
    _gcry_core_ac_key_data_get,
    _gcry_core_ac_key_test,
    _gcry_core_ac_key_get_nbits,
    _gcry_core_ac_key_get_grip,
    _gcry_core_ac_key_destroy,
    _gcry_core_ac_key_pair_destroy,
    _gcry_core_ac_data_encode,
    _gcry_core_ac_data_decode,
    _gcry_core_ac_mpi_to_os,
    _gcry_core_ac_mpi_to_os_alloc,
    _gcry_core_ac_os_to_mpi,
    _gcry_core_ac_data_encrypt,
    _gcry_core_ac_data_decrypt,
    _gcry_core_ac_data_sign,
    _gcry_core_ac_data_verify,
    _gcry_core_ac_data_encrypt_scheme,
    _gcry_core_ac_data_decrypt_scheme,
    _gcry_core_ac_data_sign_scheme,
    _gcry_core_ac_data_verify_scheme
  };

gcry_core_subsystem_ac_t gcry_core_subsystem_ac = &_gcry_subsystem_ac;

/* EOF */
