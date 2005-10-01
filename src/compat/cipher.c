/* cipher.c  -	cipher dispatcher
 * Copyright (C) 1998,1999,2000,2001,2002,2003,2005 Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gcrypt-internal.h>
#include <gcrypt-ath-internal.h>
#include <gcrypt-cipher-internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#if USE_BLOWFISH
#include <blowfish.h>
#endif
#if USE_DES
#include <des.h>
#endif
#if USE_ARCFOUR
#include <arcfour.h>
#endif
#if USE_CAST5
#include <cast5.h>
#endif
#if USE_AES
#include <rijndael.h>
#endif
#if USE_TWOFISH
#include <twofish.h>
#endif
#if USE_SERPENT
#include <serpent.h>
#endif
#if USE_RFC2268
#include <rfc2268.h>
#endif



/* This is the type of a (compat) cipher handle, which wraps the
   cipher handle used by Libgcrypt-core.  */
struct gcry_cipher_hd
{
  gcry_module_t module;
  gcry_core_cipher_hd_t handle;
};


/* This is the type holding the cipher specification structures of
   each loaded algorithm module.  */
typedef struct gcry_module_spec
{
  gcry_core_cipher_spec_t spec;	/* Cipher specification as used by
				   Libgcrypt-core.  */
  gcry_cipher_spec_t *spec_old;	/* Cipher specification as used by
				   Libgcrypt 1.x.  */
} gcry_module_spec_t;


/* This is the list of the default ciphers, which are included in
   libgcrypt.  */
static struct cipher_table_entry
{
  gcry_core_cipher_spec_t *spec_ptr; /* Pointer to the cipher
					specification.  */
  gcry_module_spec_t spec;	/* Module specification storage to
				   use.  */
  unsigned int algorithm;	/* Algorithm identifier.  */
} cipher_table[] =
  {
#if USE_BLOWFISH
    { &gcry_core_cipher_blowfish, { NULL, NULL },   GCRY_CIPHER_BLOWFISH },
#endif
#if USE_DES
    { &gcry_core_cipher_des, { NULL, NULL },        GCRY_CIPHER_DES },
    { &gcry_core_cipher_tripledes, { NULL, NULL },  GCRY_CIPHER_3DES },
#endif
#if USE_ARCFOUR
    { &gcry_core_cipher_arcfour, { NULL, NULL },    GCRY_CIPHER_ARCFOUR },
#endif
#if USE_CAST5
    { &gcry_core_cipher_cast5, { NULL, NULL },      GCRY_CIPHER_CAST5 },
#endif
#if USE_AES
    { &gcry_core_cipher_aes, { NULL, NULL },        GCRY_CIPHER_AES },
    { &gcry_core_cipher_aes192, { NULL, NULL },     GCRY_CIPHER_AES192 },
    { &gcry_core_cipher_aes256, { NULL, NULL },     GCRY_CIPHER_AES256 },
#endif
#if USE_TWOFISH
    { &gcry_core_cipher_twofish, { NULL, NULL },    GCRY_CIPHER_TWOFISH },
    { &gcry_core_cipher_twofish128, { NULL, NULL }, GCRY_CIPHER_TWOFISH128 },
#endif
#if USE_SERPENT
    { &gcry_core_cipher_serpent128, { NULL, NULL }, GCRY_CIPHER_SERPENT128 },
    { &gcry_core_cipher_serpent192, { NULL, NULL }, GCRY_CIPHER_SERPENT192 },
    { &gcry_core_cipher_serpent256, { NULL, NULL }, GCRY_CIPHER_SERPENT256 },
#endif
#ifdef USE_RFC2268
    { &gcry_core_cipher_rfc2268_40, { NULL, NULL }, GCRY_CIPHER_RFC2268_40 },
#endif
    { NULL, { NULL, NULL }, 0                    },
  };

/* List of registered ciphers.  */
static gcry_module_t ciphers_registered;

/* This is the lock protecting CIPHERS_REGISTERED.  */
static gcry_core_ath_mutex_t ciphers_registered_lock = ATH_MUTEX_INITIALIZER;



/* Internal function.  Register all the ciphers included in
   CIPHER_TABLE.  Note, that this function gets only used by the macro
   REGISTER_DEFAULT_CIPHERS which protects it using a mutex. */
static void
register_default (void)
{
  gcry_error_t err = 0;
  int i;
  
  for (i = 0; cipher_table[i].spec_ptr; i++)
    {
      cipher_table[i].spec.spec = *cipher_table[i].spec_ptr;
      err = _gcry_module_add (&ciphers_registered,
			      cipher_table[i].algorithm,
			      &cipher_table[i].spec,
			      NULL);
      if (err)
	break;
    }

  if (err)
    BUG (context);
}

/* Internal callback function.  Used via _gcry_module_lookup.  */
static int
cipher_lookup_func_name (void *opaque, const void *data)
{
  gcry_module_spec_t *spec = opaque;
  const char *name = data;
  const char **aliases = spec->spec->aliases;
  int i, ret = ! stricmp (name, spec->spec->name);

  if (aliases)
    for (i = 0; aliases[i] && (! ret); i++)
      ret = ! stricmp (name, aliases[i]);

  return ret;
}

/* Internal callback function.  Used via _gcry_module_lookup.  */
static int
cipher_lookup_func_oid (void *opaque, const void *data)
{
  gcry_module_spec_t *spec = opaque;
  const char *oid = data;
  gcry_cipher_oid_spec_t *oid_specs = spec->spec->oids;
  int ret = 0, i;

  if (oid_specs)
    for (i = 0; oid_specs[i].oid && (! ret); i++)
      if (! stricmp (oid, oid_specs[i].oid))
	ret = 1;

  return ret;
}

/* Internal function.  Lookup a cipher entry by it's name.  */
static gcry_module_t
cipher_lookup_name (const char *name)
{
  gcry_module_t cipher;

  cipher = _gcry_module_lookup (ciphers_registered, name,
				cipher_lookup_func_name);

  return cipher;
}

/* Internal function.  Lookup a cipher entry by it's oid.  */
static gcry_module_t
cipher_lookup_oid (const char *oid)
{
  gcry_module_t cipher;

  cipher = _gcry_module_lookup (ciphers_registered, oid,
				cipher_lookup_func_oid);

  return cipher;
}



/* Backward compatibility cruft.  */

/* This is the callback function, to which operations on a cipher
   handle using an old-style specification structure are
   deligated.  */
static gcry_error_t
cipher_compat_callback (gcry_core_context_t ctx,
			void *opaque,
			gcry_core_cipher_cb_type_t type,
			void *args)
{
  gcry_cipher_spec_t *spec;
  gcry_error_t err;

  spec = opaque;

  switch (type)
    {
      /* Handle setkey command.  */
    case GCRY_CORE_CIPHER_CB_SETKEY:
      {
	gcry_core_cipher_cb_setkey_t *cb_data = args;
	err = (*spec->setkey) (cb_data->c, cb_data->key, cb_data->keylen);
      }
      break;

      /* Handle encrypt command.  */
    case GCRY_CORE_CIPHER_CB_ENCRYPT:
      {
	gcry_core_cipher_cb_encrypt_t *cb_data = args;
	(*spec->encrypt) (cb_data->c, cb_data->outbuf, cb_data->inbuf);
	err = 0;
      }
      break;

      /* Handle decrypt command.  */
    case GCRY_CORE_CIPHER_CB_DECRYPT:
      {
	gcry_core_cipher_cb_decrypt_t *cb_data = args;
	(*spec->decrypt) (cb_data->c, cb_data->outbuf, cb_data->inbuf);
	err = 0;
      }
      break;

      /* Handle stencrypt command.  */
    case GCRY_CORE_CIPHER_CB_STENCRYPT:
      {
	gcry_core_cipher_cb_stencrypt_t *cb_data = args;
	(*spec->stencrypt) (cb_data->c, cb_data->outbuf, cb_data->inbuf, cb_data->n);
	err = 0;
      }
      break;

      /* Handle stdecrypt command.  */
    case GCRY_CORE_CIPHER_CB_STDECRYPT:
      {
	gcry_core_cipher_cb_stdecrypt_t *cb_data = args;
	(*spec->stdecrypt) (cb_data->c, cb_data->outbuf, cb_data->inbuf, cb_data->n);
	err = 0;
      }
      break;

      /* Die.  */
    default:
      abort ();
      err = 0;
      break;
    }

  return err;
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

/* Register a new cipher module whose specification can be found in
   SPEC_OLD.  On success, a new algorithm ID is stored in ALGORITHM_ID
   and a pointer representhing this module is stored in MODULE.  */
gcry_error_t
gcry_cipher_register (gcry_cipher_spec_t *spec_old,
		      unsigned int *algorithm_id,
		      gcry_module_t *module)
{
  gcry_core_cipher_spec_t spec_new;
  gcry_module_spec_t *module_spec;
  gcry_module_t mod;
  gcry_error_t err;

  _gcry_init ();

  module_spec = NULL;
  spec_new = NULL;

  /* Allocate object holding the newly created cipher specification
     structure.  */
  spec_new = gcry_core_malloc (context, sizeof (*spec_new));
  if (! spec_new)
    {
      err = gcry_error_from_errno (errno);
      goto out;
    }

  /* Allocate object wrapping both, the old-style and the new-style
     specification structures  */
  module_spec = gcry_core_malloc (context, sizeof (*module_spec));
  if (! module_spec)
    {
      err = gcry_error_from_errno (errno);
      goto out;
    }

  /* Fill structures.  */

  spec_new->name = spec_old->name;
  spec_new->aliases = spec_old->aliases;
  spec_new->oids = spec_old->oids;
  spec_new->blocksize = spec_old->blocksize;
  spec_new->keylen = spec_old->keylen;
  spec_new->contextsize = spec_old->contextsize;
  spec_new->setkey = NULL;
  spec_new->encrypt = NULL;
  spec_new->decrypt = NULL;
  spec_new->stencrypt = NULL;
  spec_new->stdecrypt = NULL;

  module_spec->spec = spec_new;
  module_spec->spec_old = spec_old;

  /* Register module.  */
  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  err = _gcry_module_add (&ciphers_registered, 0, module_spec, &mod);
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);
  if (err)
    goto out;

  /* Done.  */
  *module = mod;
  *algorithm_id = mod->mod_id;

 out:

  if (err)
    {
      /* Deallocate resources.  */
      gcry_core_free (context, module_spec);
      gcry_core_free (context, spec_new);
    }

  return gcry_error (err);
}

/* Unregister the cipher identified by MODULE, which must have been
   registered with gcry_cipher_register.  */
void
gcry_cipher_unregister (gcry_module_t module)
{

  _gcry_init ();

  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  module_release (module);
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);
}

/* Locate the OID in the oid table and return the index or -1 when not
   found.  An opitonal "oid." or "OID." prefix in OID is ignored, the
   OID is expected to be in standard IETF dotted notation.  The
   internal algorithm number is returned in ALGORITHM unless it
   ispassed as NULL.  A pointer to the specification of the module
   implementing this algorithm is return in OID_SPEC unless passed as
   NULL.*/
static int 
search_oid (const char *oid, int *algorithm, gcry_cipher_oid_spec_t *oid_spec)
{
  gcry_module_t module;
  int ret = 0;

  if (oid && ((! strncmp (oid, "oid.", 4))
	      || (! strncmp (oid, "OID.", 4))))
    oid += 4;

  module = cipher_lookup_oid (oid);
  if (module)
    {
      gcry_module_spec_t *spec = module->spec;
      gcry_core_cipher_spec_t cipher = spec->spec;
      unsigned int i;

      for (i = 0; cipher->oids[i].oid && !ret; i++)
	if (! stricmp (oid, cipher->oids[i].oid))
	  {
	    if (algorithm)
	      *algorithm = module->mod_id;
	    if (oid_spec)
	      *oid_spec = cipher->oids[i];
	    ret = 1;
	  }
      module_release (module);
    }

  return ret;
}

/* Map STRING to the cipher algorithm identifier.  Returns the
   algorithm ID of the cipher for the given name or 0 if the name is
   not known.  It is valid to pass NULL for STRING which results in a
   return value of 0. */
int
gcry_cipher_map_name (const char *string)
{
  gcry_module_t cipher;
  int ret, algorithm = 0;

  _gcry_init ();

  if (! string)
    return 0;

  /* If the string starts with a digit (optionally prefixed with
     either "OID." or "oid."), we first look into our table of ASN.1
     object identifiers to figure out the algorithm */

  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);

  ret = search_oid (string, &algorithm, NULL);
  if (! ret)
    {
      cipher = cipher_lookup_name (string);
      if (cipher)
	{
	  algorithm = cipher->mod_id;
	  module_release (cipher);
	}
    }

  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);
  
  return algorithm;
}


/* Given a STRING with an OID in dotted decimal notation, this
   function returns the cipher mode (GCRY_CIPHER_MODE_*) associated
   with that OID or 0 if no mode is known.  Passing NULL for string
   yields a return value of 0. */
int
gcry_cipher_mode_from_oid (const char *string)
{
  gcry_cipher_oid_spec_t oid_spec;
  int ret = 0, mode = 0;

  _gcry_init ();

  if (!string)
    return 0;

  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  ret = search_oid (string, NULL, &oid_spec);
  if (ret)
    mode = oid_spec.mode;
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);

  return mode;
}


/* Map the cipher algorithm identifier ALGORITHM to a string
   representing this algorithm.  This string is the default name as
   used by Libgcrypt.  NULL is returned for an unknown algorithm.  */
static const char *
cipher_algo_to_string (int algorithm)
{
  gcry_module_t cipher;
  const char *name = NULL;

  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  cipher = _gcry_module_lookup_id (ciphers_registered, algorithm);
  if (cipher)
    {
      gcry_module_spec_t *spec = cipher->spec;
      name = spec->spec->name;
      module_release (cipher);
    }
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);

  return name;
}

/* Map the cipher algorithm identifier ALGORITHM to a string
   representing this algorithm.  This string is the default name as
   used by Libgcrypt.  An pointer to an empty string is returned for
   an unknown algorithm.  NULL is never returned. */
const char *
gcry_cipher_algo_name (int algorithm)
{
  const char *s;

  _gcry_init ();
  s = cipher_algo_to_string (algorithm);
  return s ? s : "";
}


/* Flag the cipher algorithm with the identifier ALGORITHM as
   disabled.  There is no error return, the function does nothing for
   unknown algorithms.  Disabled algorithms are vitually not available
   in Libgcrypt. */
static void
disable_cipher_algo (int algorithm)
{
  gcry_module_t cipher;

  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  cipher = _gcry_module_lookup_id (ciphers_registered, algorithm);
  if (cipher)
    {
      if (! (cipher->flags & FLAG_MODULE_DISABLED))
	cipher->flags |= FLAG_MODULE_DISABLED;
      module_release (cipher);
    }
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);
}


/* Return 0 if the cipher algorithm with indentifier ALGORITHM is
   available. Returns a basic error code value if it is not available.  */
static gcry_error_t
check_cipher_algo (int algorithm)
{
  gcry_module_t module;
  gcry_error_t err;

  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  module = _gcry_module_lookup_id (ciphers_registered, algorithm);
  if (module)
    {
      if (module->flags & FLAG_MODULE_DISABLED)
	err = gcry_error (GPG_ERR_CIPHER_ALGO);
      else
	err = 0;
      module_release (module);
    }
  else
    err = gcry_error (GPG_ERR_CIPHER_ALGO);
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);
  
  return err;
}

/* Return the standard length of the key for the cipher algorithm with
   the identifier ALGORITHM.  This function expects a valid algorithm
   and will abort if the algorithm is not available or the length of
   the key is not known. */
static unsigned int
cipher_get_keylen (int algorithm_id)
{
  gcry_module_t module;
  unsigned int len;

  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);

  module = _gcry_module_lookup_id (ciphers_registered, algorithm_id);
  if (module)
    {
      len = ((gcry_module_spec_t *) module->spec)->spec->keylen;
      if (! len)
	log_bug (context, "cipher %d w/o key length\n", algorithm_id);
      module_release (module);
    }
  else
    {
      log_bug (context, "cipher %d not found\n", algorithm_id);
      len = 0;
    }

  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);

  return len;
}

/* Return the block length of the cipher algorithm with the identifier
   ALGORITHM.  This function expects a valid algorithm and will abort
   if the algorithm is not available or the length of the key is not
   known. */
static unsigned int
cipher_get_blocksize (int algorithm_id)
{
  gcry_module_t module;
  unsigned int len;

  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);

  module = _gcry_module_lookup_id (ciphers_registered, algorithm_id);
  if (module)
    {
      len = ((gcry_module_spec_t *) module->spec)->spec->blocksize;
      if (! len)
	log_bug (context, "cipher %d w/o blocksize\n", algorithm_id);
      module_release (module);
    }
  else
    {
      log_bug (context, "cipher %d not found\n", algorithm_id);
      len = 0;
    }

  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);

  return len;
}


/*
   Open a cipher handle for use with cipher algorithm ALGORITHM, using
   the cipher mode MODE (one of the GCRY_CIPHER_MODE_*) and return a
   handle in HANDLE.  Put NULL into HANDLE and return an error code if
   something goes wrong.  FLAGS may be used to modify the
   operation.  The defined flags are:

   GCRY_CIPHER_SECURE:  allocate all internal buffers in secure memory.
   GCRY_CIPHER_ENABLE_SYNC:  Enable the sync operation as used in OpenPGP.
   GCRY_CIPHER_CBC_CTS:  Enable CTS mode.
   GCRY_CIPHER_CBC_MAC:  Enable MAC mode.

   Values for these flags may be combined using OR.
 */
gcry_error_t
gcry_cipher_open (gcry_cipher_hd_t *handle,
		  int algo, int mode, unsigned int flags)
{
  gcry_cipher_hd_t handle_new = NULL;
  gcry_module_spec_t *spec = NULL;
  gcry_module_t module = NULL;
  gcry_core_cipher_hd_t h = NULL;
  gcry_error_t err = 0;

  _gcry_init ();

  /* Fetch the according module and check wether the cipher is marked
     available for use.  */
  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  module = _gcry_module_lookup_id (ciphers_registered, algo);
  if (module)
    {
      /* Found module.  */

      if (module->flags & FLAG_MODULE_DISABLED)
	/* Not available for use.  */
	err = gcry_error (GPG_ERR_CIPHER_ALGO);
    }
  else
    err = gcry_error (GPG_ERR_CIPHER_ALGO);
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);
  if (err)
    goto out;
  else
    spec = module->spec;

  err = gcry_core_cipher_open (context, &h, spec->spec, mode, flags);
  if (err)
    goto out;
  else
    {
      if (spec->spec_old)
	gcry_core_cipher_set_cb (context,
				 h, cipher_compat_callback, spec->spec_old);
    }

  handle_new = gcry_core_malloc (context, sizeof (*handle_new));
  if (! handle_new)
    {
      err = gcry_error_from_errno (errno);
      goto out;
    }

  handle_new->handle = h;
  handle_new->module = module;

 out:

  if (err)
    {
      if (module)
	{
	  /* Release module.  */
	  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
	  module_release (module);
	  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);
	}
      if (h)
	gcry_core_cipher_close (context, h);
    }

  *handle = err ? NULL : handle_new;

  return err;
}

/* Release all resources associated with the cipher handle H. H may be
   NULL in which case this is a no-operation. */
void
gcry_cipher_close (gcry_cipher_hd_t h)
{
  _gcry_init ();
  gcry_core_cipher_close (context, h->handle);
  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  module_release (h->module);
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);
  gcry_core_free (context, h);
}


gcry_error_t
gcry_cipher_encrypt (gcry_cipher_hd_t h, byte *out, size_t outsize,
                     const byte *in, size_t inlen)
{
  _gcry_init ();
  return gcry_core_cipher_encrypt (context, h->handle,
				   out, outsize, in, inlen);
}


gcry_error_t
gcry_cipher_decrypt (gcry_cipher_hd_t h, byte *out, size_t outsize,
		     const byte  *in, size_t inlen)
{
  _gcry_init ();
  return gcry_core_cipher_decrypt (context, h->handle,
				   out,outsize, in, inlen);
}


gcry_error_t
gcry_cipher_ctl( gcry_cipher_hd_t h, int cmd, void *buffer, size_t buflen)
{
  gcry_error_t rc = 0;

  _gcry_init ();

  switch (cmd)
    {
    case GCRYCTL_SET_KEY:
      rc = gcry_core_cipher_setkey(context, h->handle, buffer, buflen );
      break;
    case GCRYCTL_SET_IV:
      gcry_core_cipher_setiv(context, h->handle, buffer, buflen );
      break;
    case GCRYCTL_RESET:
      gcry_core_cipher_reset (context, h->handle);
      break;
    case GCRYCTL_CFB_SYNC:
      gcry_core_cipher_sync (context, h->handle);
      break;
    case GCRYCTL_SET_CBC_CTS:
      rc = gcry_core_cipher_cts (context, h->handle, buflen);
      break;
    case GCRYCTL_SET_CBC_MAC:
      rc = gcry_core_cipher_set_cbc_mac (context, h->handle, buflen);
      break;
    case GCRYCTL_DISABLE_ALGO:
      /* this one expects a NULL handle and buffer pointing to an
       * integer with the algo number.
       */
      if( h || !buffer || buflen != sizeof(int) )
	return gcry_error (GPG_ERR_CIPHER_ALGO);
      disable_cipher_algo( *(int*)buffer );
      break;
    case GCRYCTL_SET_CTR:
      rc = gcry_core_cipher_setctr (context, h->handle, buffer, buflen);
      break;

    default:
      rc = gcry_error (GPG_ERR_INV_OP);
    }

  return rc;
}


/****************
 * Return information about the cipher handle.
 */
gcry_error_t
gcry_cipher_info( gcry_cipher_hd_t h, int cmd, void *buffer, size_t *nbytes)
{
  _gcry_init ();
  return gcry_error (GPG_ERR_INV_OP);
}

/****************
 * Return information about the given cipher algorithm
 * WHAT select the kind of information returned:
 *  GCRYCTL_GET_KEYLEN:
 *	Return the length of the key, if the algorithm
 *	supports multiple key length, the maximum supported value
 *	is returnd.  The length is return as number of octets.
 *	buffer and nbytes must be zero.
 *	The keylength is returned in _bytes_.
 *  GCRYCTL_GET_BLKLEN:
 *	Return the blocklength of the algorithm counted in octets.
 *	buffer and nbytes must be zero.
 *  GCRYCTL_TEST_ALGO:
 *	Returns 0 when the specified algorithm is available for use.
 *	buffer and nbytes must be zero.
 *
 * Note:  Because this function is in most cases used to return an
 * integer value, we can make it easier for the caller to just look at
 * the return value.  The caller will in all cases consult the value
 * and thereby detecting whether a error occured or not (i.e. while checking
 * the block size)
 */
gcry_error_t
gcry_cipher_algo_info (int algo, int what, void *buffer, size_t *nbytes)
{
  gcry_error_t err = 0;
  unsigned int ui;

  _gcry_init ();

  switch (what)
    {
    case GCRYCTL_GET_KEYLEN:
      if (buffer || (! nbytes))
	err = gcry_error (GPG_ERR_CIPHER_ALGO);
      else
	{
	  ui = cipher_get_keylen (algo);
	  if ((ui > 0) && (ui <= 512))
	    *nbytes = (size_t) ui / 8;
	  else
	    /* The only reason is an invalid algo or a strange
	       blocksize.  */
	    err = gcry_error (GPG_ERR_CIPHER_ALGO);
	}
      break;

    case GCRYCTL_GET_BLKLEN:
      if (buffer || (! nbytes))
	err = gcry_error (GPG_ERR_CIPHER_ALGO);
      else
	{
	  ui = cipher_get_blocksize (algo);
	  if ((ui > 0) && (ui < 10000))
	    *nbytes = ui;
	  else
	    /* The only reason is an invalid algo or a strange
	       blocksize.  */
	    err = gcry_error (GPG_ERR_CIPHER_ALGO);
	}
      break;

    case GCRYCTL_TEST_ALGO:
      if (buffer || nbytes)
	err = gcry_error (GPG_ERR_INV_ARG);
      else
	err = check_cipher_algo (algo);
      break;

      default:
	err = gcry_error (GPG_ERR_INV_OP);
    }

  return err;
}


size_t
gcry_cipher_get_algo_keylen (int algo) 
{
  size_t n;

  _gcry_init ();
  if (gcry_cipher_algo_info( algo, GCRYCTL_GET_KEYLEN, NULL, &n))
    n = 0;
  return n;
}


size_t
gcry_cipher_get_algo_blklen (int algo) 
{
  size_t n;

  _gcry_init ();
  if (gcry_cipher_algo_info( algo, GCRYCTL_GET_BLKLEN, NULL, &n))
    n = 0;
  return n;
}


gcry_error_t
_gcry_cipher_init (void)
{
  register_default ();

  return 0;
}

/* Get a list consisting of the IDs of the loaded cipher modules.  If
   LIST is zero, write the number of loaded cipher modules to
   LIST_LENGTH and return.  If LIST is non-zero, the first
   *LIST_LENGTH algorithm IDs are stored in LIST, which must be of
   according size.  In case there are less cipher modules than
   *LIST_LENGTH, *LIST_LENGTH is updated to the correct number.  */
gcry_error_t
gcry_cipher_list (int *list, int *list_length)
{
  gcry_error_t err = 0;

  _gcry_init ();
  _gcry_core_ath_mutex_lock (context, &ciphers_registered_lock);
  err = _gcry_module_list (ciphers_registered, list, list_length);
  _gcry_core_ath_mutex_unlock (context, &ciphers_registered_lock);

  return err;
}
