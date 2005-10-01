/* md.c  -  message digest dispatcher
 * Copyright (C) 1998, 1999, 2002, 2003, 2005 Free Software Foundation, Inc.
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
#include <gcrypt-md-internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#if USE_RMD160
#include <rmd160.h>
#endif
#if USE_SHA1
#include <sha1.h>
#endif
#if USE_CRC
#include <crc.h>
#endif
#if USE_MD4
#include <md4.h>
#endif
#if USE_MD5
#include <md5.h>
#endif
#if USE_SHA256
#include <sha256.h>
#endif
#if USE_SHA512
#include <sha512.h>
#endif
#if USE_TIGER
#include <tiger.h>
#endif
#if USE_WHIRLPOOL
#include <whirlpool.h>
#endif



struct gcry_md_hd
{
  gcry_module_t *modules;
  size_t modules_n;
  gcry_core_md_hd_t handle;
};

typedef struct gcry_module_spec
{
  gcry_core_md_spec_t spec;
  gcry_md_spec_t *spec_old;
} gcry_module_spec_t;

static struct digest_table_entry
{
  gcry_core_md_spec_t *spec_ptr;
  gcry_module_spec_t spec;
  unsigned int id;
} digest_table[] =
  {
#if USE_RMD160
    { &gcry_core_digest_rmd160, { NULL, NULL }, GCRY_MD_RMD160 },
#endif
#if USE_SHA1
    { &gcry_core_digest_sha1, { NULL, NULL }, GCRY_MD_SHA1 },
#endif
#if USE_CRC    
    { &gcry_core_digest_crc32, { NULL, NULL }, GCRY_MD_CRC32 },
    { &gcry_core_digest_crc32_rfc1510, { NULL, NULL }, GCRY_MD_CRC32_RFC1510 },
    { &gcry_core_digest_crc24_rfc2440, { NULL, NULL }, GCRY_MD_CRC24_RFC2440 },
#endif
#if USE_MD4
    { &gcry_core_digest_md4, { NULL, NULL }, GCRY_MD_MD4 },
#endif
#if USE_MD5
    { &gcry_core_digest_md5, { NULL, NULL }, GCRY_MD_MD5 },
#endif
#if USE_SHA256
    { &gcry_core_digest_sha256, { NULL, NULL }, GCRY_MD_SHA256 },
#endif
#if USE_SHA512
    { &gcry_core_digest_sha512, { NULL, NULL }, GCRY_MD_SHA512 },
    { &gcry_core_digest_sha384, { NULL, NULL }, GCRY_MD_SHA384 },
#endif
#if USE_TIGER
    { &gcry_core_digest_tiger, { NULL, NULL }, GCRY_MD_TIGER },
#endif
#if USE_WHIRLPOOL
    { &gcry_core_digest_whirlpool, { NULL, NULL }, GCRY_MD_WHIRLPOOL },
#endif
    { NULL, { NULL, NULL }, 0 },
  };

/* List of registered digests.  */
static gcry_module_t digests_registered;

/* This is the lock protecting DIGESTS_REGISTERED.  */
static gcry_core_ath_mutex_t digests_registered_lock = ATH_MUTEX_INITIALIZER;

typedef struct gcry_md_list
{
  gcry_core_md_spec_t digest;
  gcry_module_t module;
  struct gcry_md_list *next;
  size_t actual_struct_size;     /* Allocated size of this structure. */
  PROPERLY_ALIGNED_TYPE context;
} GcryDigestEntry;

/* this structure is put right after the gcry_core_md_hd_t buffer, so that
 * only one memory block is needed. */
struct gcry_md_context
{
  int  magic;
  size_t actual_handle_size;     /* Allocated size of this handle. */
  int  secure;
  FILE  *debug;
  int finalized;
  GcryDigestEntry *list;
  byte *macpads;
};


#define CTX_MAGIC_NORMAL 0x11071961
#define CTX_MAGIC_SECURE 0x16917011



static const char * digest_algo_to_string( int algo );
static gcry_error_t check_digest_algo (int algo);
static gcry_error_t md_open (gcry_md_hd_t *h, int algo, unsigned int flags);
static gcry_error_t md_enable (gcry_md_hd_t hd, int algo);
static gcry_error_t md_copy (gcry_md_hd_t a, gcry_md_hd_t *b);
static void md_close (gcry_md_hd_t a);
static void md_write (gcry_md_hd_t a, const byte *inbuf, size_t inlen);
static void md_final(gcry_md_hd_t a);
static byte *md_read( gcry_md_hd_t a, int algo );
static int md_get_algo( gcry_md_hd_t a );
static int md_digest_length( int algo );
static const byte *md_asn_oid( int algo, size_t *asnlen, size_t *mdlen );
static void md_start_debug( gcry_md_hd_t a, char *suffix );
static void md_stop_debug( gcry_md_hd_t a );




/* Internal function.  Register all the ciphers included in
   CIPHER_TABLE.  Returns zero on success or an error code.  */
static void
register_default (void)
{
  gcry_error_t err = 0;
  int i;
  
  for (i = 0; (! err) && digest_table[i].spec_ptr; i++)
    {
      digest_table[i].spec.spec = *digest_table[i].spec_ptr;
      err = _gcry_module_add (&digests_registered,
			      digest_table[i].id,
			      &digest_table[i].spec,
			      NULL);
    }

  if (err)
    BUG (context);
}

/* Internal callback function.  */
static int
md_lookup_func_name (void *opaque, const void *data)
{
  gcry_module_spec_t *spec = opaque;
  const char *name = data;

  return (! stricmp (spec->spec->name, name));
}

/* Internal callback function.  Used via _gcry_module_lookup.  */
static int
md_lookup_func_oid (void *opaque, const void *data)
{
  gcry_module_spec_t *spec = opaque;
  const char *oid = data;
  gcry_md_oid_spec_t *oid_specs = spec->spec->oids;
  int ret = 0, i;

  if (oid_specs)
    {
      for (i = 0; oid_specs[i].oidstring && (! ret); i++)
        if (! stricmp (oid, oid_specs[i].oidstring))
          ret = 1;
    }

  return ret;
}

/* Internal function.  Lookup a digest entry by it's name.  */
static gcry_module_t 
md_lookup_name (const char *name)
{
  gcry_module_t digest;

  digest = _gcry_module_lookup (digests_registered, name,
				md_lookup_func_name);

  return digest;
}

/* Internal function.  Lookup a cipher entry by it's oid.  */
static gcry_module_t
md_lookup_oid (const char *oid)
{
  gcry_module_t digest;

  digest = _gcry_module_lookup (digests_registered, oid,
				md_lookup_func_oid);

  return digest;
}



/* Backward compatibility cruft.  */

static gcry_error_t
md_compat_callback (gcry_core_context_t ctx,
		    void *opaque,
		    gcry_core_md_cb_type_t type,
		    void *args)
{
  gcry_md_spec_t *spec;
  gcry_error_t err;

  spec = opaque;

  switch (type)
    {
    case GCRY_CORE_MD_CB_INIT:
      {
	gcry_core_md_cb_init_t *cb_data = args;
	(*spec->init) (cb_data->c);
	err = 0;
      }
      break;

    case GCRY_CORE_MD_CB_FINAL:
      {
	gcry_core_md_cb_final_t *cb_data = args;
	(*spec->final) (cb_data->c);
	err = 0;
      }
      break;

    case GCRY_CORE_MD_CB_WRITE:
      {
	gcry_core_md_cb_write_t *cb_data = args;
	(*spec->write) (cb_data->c, cb_data->buf, cb_data->nbytes);
	err = 0;
      }
      break;

    case GCRY_CORE_MD_CB_READ:
      {
	gcry_core_md_cb_read_t *cb_data = args;
	*cb_data->result = (*spec->read) (cb_data->c);
	err = 0;
      }
      break;

    default:
      abort ();
      err = 0;
      break;
    }

  return err;
}

/* FIXME, moritz, comment.  */
static int
md_spec_in_table_p (gcry_core_md_spec_t md)
{
  unsigned int i;

  for (i = 0; i < DIM (digest_table); i++)
    if (md == digest_table[i].spec.spec)
      break;
  if (i == DIM (digest_table))
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

/* Register a new digest module whose specification can be found in
   DIGEST.  On success, a new algorithm ID is stored in ALGORITHM_ID
   and a pointer representhing this module is stored in MODULE.  */
gcry_error_t
gcry_md_register (gcry_md_spec_t *digest_old,
		  unsigned int *algorithm_id,
		  gcry_module_t *module)
{
  gcry_core_md_spec_t digest;
  gcry_module_spec_t *spec;
  gcry_error_t err = 0;
  gcry_module_t mod;

  _gcry_init ();

  /* FIXME, moritz?  */
  digest = gcry_core_xmalloc (context, sizeof (*digest));
  spec = gcry_core_xmalloc (context, sizeof (*spec));

  digest->name = digest_old->name;
  digest->asnoid = digest_old->asnoid;
  digest->asnlen = digest_old->asnlen;
  digest->oids = digest_old->oids;
  digest->mdlen = digest_old->mdlen;
  digest->init = NULL;
  digest->write = NULL;
  digest->final = NULL;
  digest->read = NULL;
  digest->hash = NULL;
  digest->contextsize = digest_old->contextsize;

  spec->spec = digest;
  spec->spec_old = digest_old;

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  err = _gcry_module_add (&digests_registered, 0, spec, &mod);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
  
  if (! err)
    {
      *module = mod;
      *algorithm_id = mod->mod_id;
    }

  return err;
}

/* Unregister the digest identified by ID, which must have been
   registered with gcry_digest_register.  */
void
gcry_md_unregister (gcry_module_t module)
{
  gcry_module_spec_t *spec;

  _gcry_init ();
  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  spec = module->spec;
  if (! md_spec_in_table_p (spec->spec))
    {
      gcry_core_free (context, spec->spec);
      gcry_core_free (context, spec);
    }
  module_release (module);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
}


static int 
search_oid (const char *oid, int *algorithm, gcry_md_oid_spec_t *oid_spec)
{
  gcry_module_t module;
  int ret = 0;

  if (oid && ((! strncmp (oid, "oid.", 4))
	      || (! strncmp (oid, "OID.", 4))))
    oid += 4;

  module = md_lookup_oid (oid);
  if (module)
    {
      gcry_core_md_spec_t digest;
      gcry_module_spec_t *spec;
      int i;

      spec = module->spec;
      digest = spec->spec;

      for (i = 0; digest->oids[i].oidstring && !ret; i++)
	if (! stricmp (oid, digest->oids[i].oidstring))
	  {
	    if (algorithm)
	      *algorithm = module->mod_id;
	    if (oid_spec)
	      *oid_spec = digest->oids[i];
	    ret = 1;
	  }
      module_release (module);
    }

  return ret;
}

/****************
 * Map a string to the digest algo
 */
int
gcry_md_map_name (const char *string)
{
  gcry_module_t module;
  int ret, algorithm = 0;

  _gcry_init ();

  if (! string)
    return 0;

  /* If the string starts with a digit (optionally prefixed with
     either "OID." or "oid."), we first look into our table of ASN.1
     object identifiers to figure out the algorithm */

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);

  ret = search_oid (string, &algorithm, NULL);
  if (! ret)
    {
      /* Not found, search for an acording diget name.  */
      module = md_lookup_name (string);
      if (module)
	{
	  algorithm = module->mod_id;
	  module_release (module);
	}
    }
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  return algorithm;
}


/****************
 * Map a digest algo to a string
 */
static const char *
digest_algo_to_string (int algorithm)
{
  const char *name = NULL;
  gcry_module_spec_t *spec;
  gcry_module_t module;

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module = _gcry_module_lookup_id (digests_registered, algorithm);
  if (module)
    {
      spec = module->spec;
      name = spec->spec->name;
      module_release (module);
    }
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  return name;
}

/****************
 * This function simply returns the name of the algorithm or some constant
 * string when there is no algo.  It will never return NULL.
 * Use	the macro gcry_md_test_algo() to check whether the algorithm
 * is valid.
 */
const char *
gcry_md_algo_name (int algorithm)
{
  const char *s;

  _gcry_init ();
  s = digest_algo_to_string (algorithm);
  return s ? s : "?";
}


static gcry_error_t
check_digest_algo (int algorithm)
{
  gcry_error_t rc = 0;
  gcry_module_t module;

  /* FIXME: is this correct?  */
  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module = _gcry_module_lookup_id (digests_registered, algorithm);
  if (module)
    module_release (module);
  else
    rc = gcry_error (GPG_ERR_DIGEST_ALGO);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  return rc;
}



/****************
 * Open a message digest handle for use with algorithm ALGO.
 * More algorithms may be added by md_enable(). The initial algorithm
 * may be 0.
 */
static gcry_error_t
md_open (gcry_md_hd_t *h, int algo, unsigned int flags)
{
  gcry_module_spec_t *spec = NULL;
  gcry_error_t err = 0;
  gcry_module_t module = NULL;
  gcry_core_md_hd_t core_hd;
  gcry_md_hd_t hd;

  if ((flags & ~(GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC)))
    return gcry_error (GPG_ERR_INV_ARG);

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module = _gcry_module_lookup_id (digests_registered, algo);
  if (module)
    {
      /* Found module.  */

      if (module->flags & FLAG_MODULE_DISABLED)
	{
	  /* Not available for use.  */
	  err = gcry_error (GPG_ERR_CIPHER_ALGO); /* FIXME, moritz, error?  */
	  module_release (module);
	}
      else
	spec = module->spec;
    }
  else
    err = gcry_error (GPG_ERR_CIPHER_ALGO);	/* FIXME, moritz, error?  */
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  err = gcry_core_md_open (context, &core_hd, spec->spec, flags);
  if ((! err) && spec->spec_old)
    gcry_core_md_set_cb (context, core_hd, spec->spec,
			 md_compat_callback, spec->spec_old);

  /* FIXME.  */
  hd = gcry_core_xmalloc (context, sizeof (*hd));
  hd->modules = gcry_core_xmalloc (context, sizeof (*hd->modules));

  hd->handle = core_hd;
  hd->modules[0] = module;
  hd->modules_n = 1;

  if (err)
    {
      if (module)
	{
	  /* Release module.  */
	  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
	  module_release (module);
	  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
	}
    }

  if (! err)
    *h = hd;

  return err;
}

/* Create a message digest object for algorithm ALGO.  FLAGS may be
   given as an bitwise OR of the gcry_md_flags values.  ALGO may be
   given as 0 if the algorithms to be used are later set using
   gcry_md_enable. H is guaranteed to be a valid handle or NULL on
   error.  */
gcry_error_t
gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags)
{
  gcry_error_t err = 0;
  gcry_md_hd_t hd;

  _gcry_init ();
  err = md_open (&hd, algo, flags);
  *h = err ? NULL : hd;

  return err;
}


static gcry_error_t
md_enable (gcry_md_hd_t hd, int algorithm)
{
  gcry_module_spec_t *spec = NULL;
  gcry_module_t module;
  gcry_error_t err = 0;
  int is_enabled;

  /* FIXME, moritz, fast check if already enabled?  */

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module = _gcry_module_lookup_id (digests_registered, algorithm);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
  if (! module)
    {
      log_debug (context, "md_enable: algorithm %d not available\n", algorithm);
      err = gcry_error (GPG_ERR_DIGEST_ALGO);
    }
  else
    spec = module->spec;

  is_enabled = gcry_core_md_is_enabled (context, hd->handle, spec->spec);

  if (! is_enabled)
    {
      /* FIXME: error condition properly handled: enabling an
	 algorithm twice?  */
      err = gcry_core_md_enable (context, hd->handle, spec->spec);
      if ((! err) && (spec->spec_old))
	gcry_core_md_set_cb (context, hd->handle, spec->spec,
			     md_compat_callback, spec->spec_old);

      /* FIXME.  */
      hd->modules = gcry_core_xrealloc (context, hd->modules,
					(sizeof (*hd->modules)
					 * (hd->modules_n + 1)));
      hd->modules[hd->modules_n] = module;
      hd->modules_n++;
    }
  

  if (err || is_enabled)
    {
      if (module)
	{
	   _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
	   module_release (module);
	   _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
	}
    }

  return err;
}

gcry_error_t
gcry_md_enable (gcry_md_hd_t hd, int algorithm)
{
  gcry_error_t err;

  _gcry_init ();
  err = md_enable (hd, algorithm);
  return err;
}

static gcry_error_t
md_copy (gcry_md_hd_t ahd, gcry_md_hd_t *b_hd)
{
  gcry_core_md_hd_t hd_core_cp;
  gcry_md_hd_t hd_cp;
  gcry_error_t err;
  unsigned int i;

  /* FIXME.  */
  err = gcry_core_md_copy (context, &hd_core_cp, ahd->handle);
  if (err)
    goto out;

  hd_cp = gcry_core_xmalloc (context, sizeof (*hd_cp));
  if (ahd->modules_n)
    {
      hd_cp->modules = gcry_core_xmalloc (context,
					  (sizeof (*ahd->modules)
					   * ahd->modules_n));
      memcpy (hd_cp->modules, ahd->modules,
	      sizeof (*ahd->modules) * ahd->modules_n);
      hd_cp->modules_n = ahd->modules_n;
    }

  /* Increment reference counters.  */
  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  for (i = 0; i < hd_cp->modules_n; i++)
    _gcry_module_use (hd_cp->modules[i]);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  hd_cp->handle = hd_core_cp;
  *b_hd = hd_cp;

 out:

  return err;
}

gcry_error_t
gcry_md_copy (gcry_md_hd_t *handle, gcry_md_hd_t hd)
{
  gcry_error_t err;

  _gcry_init ();
  err = md_copy (hd, handle);
  if (err)
    *handle = NULL;
  return err;
}

/*
 * Reset all contexts and discard any buffered stuff.  This may be used
 * instead of a md_close(); md_open().
 */
void
gcry_md_reset (gcry_md_hd_t a)
{
  _gcry_init ();
  gcry_core_md_reset (context, a->handle);
}

static void
md_close (gcry_md_hd_t a)
{
  unsigned int i;

  if (! a)
    return;

  gcry_core_md_close (context, a->handle);

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  for (i = 0; i < a->modules_n; i++)
    module_release (a->modules[i]);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  gcry_core_free (context, a->modules);
  gcry_core_free (context, a);
}

void
gcry_md_close (gcry_md_hd_t hd)
{
  _gcry_init ();
  md_close (hd);
}

static void
md_write (gcry_md_hd_t a, const byte *inbuf, size_t inlen)
{
  gcry_core_md_write (context, a->handle, inbuf, inlen);
}

void
gcry_md_write (gcry_md_hd_t hd, const void *inbuf, size_t inlen)
{
  _gcry_init ();
  md_write (hd, inbuf, inlen);
}

void
gcry_md_putc_do (gcry_md_hd_t hd, unsigned char c)
{
  _gcry_init ();
  gcry_core_md_putc (context, hd->handle, c);
}

static void
md_final (gcry_md_hd_t a)
{
  gcry_core_md_final (context, a->handle);
}

gcry_error_t
gcry_md_ctl (gcry_md_hd_t hd, int cmd, byte *buffer, size_t buflen)
{
  gcry_error_t rc = 0;
  
  _gcry_init ();
  switch (cmd)
    {
    case GCRYCTL_FINALIZE:
      md_final (hd);
      break;
    case GCRYCTL_SET_KEY:
      rc = gcry_md_setkey (hd, buffer, buflen);
      break;
    case GCRYCTL_START_DUMP:
      md_start_debug (hd, buffer);
      break;
    case GCRYCTL_STOP_DUMP:
      md_stop_debug (hd);
      break;
    default:
      rc = gcry_error (GPG_ERR_INV_OP);
    }
  return rc;
}

gcry_error_t
gcry_md_setkey (gcry_md_hd_t hd, const void *key, size_t keylen)
{
  _gcry_init ();
  return gcry_core_md_setkey (context, hd->handle, key, keylen);
}


/****************
 * if ALGO is null get the digest for the used algo (which should be only one)
 */
static byte *
md_read( gcry_md_hd_t a, int algo )
{
  gcry_error_t err = 0;
  gcry_module_spec_t *spec = NULL;
  gcry_module_t module = NULL;
  byte *ret = NULL;

  if (algo)
    {
      _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
      module = _gcry_module_lookup_id (digests_registered, algo);
      if (module)
	/* Found module.  */
	spec = module->spec;
      else
	err = gcry_error (GPG_ERR_CIPHER_ALGO);	/* FIXME, moritz, error?  */
      _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
    }
  else
    /* Use first algorithm.  */
    spec = a->modules[0]->spec;

  if (! err)
    ret = gcry_core_md_read (context, a->handle, spec->spec);
  else
    ret = NULL;

  /* FIXME: this function can be implemented with the help of the
     modules array in the handle structure.  FIXME: why so inconsisten
     like right now?  */

  if (algo && module)
    module_release (module);

  return ret;
}

/*
 * Read out the complete digest, this function implictly finalizes
 * the hash.
 */
byte *
gcry_md_read (gcry_md_hd_t hd, int algo)
{
  _gcry_init ();
  gcry_md_ctl (hd, GCRYCTL_FINALIZE, NULL, 0);
  return md_read (hd, algo);
}

/*
 * Read out an intermediate digest.  Not yet fucntional.
 */
gcry_error_t
gcry_md_get (gcry_md_hd_t hd, int algo, byte *buffer, int buflen)
{
  _gcry_init ();
  /*md_digest ... */
  return gcry_error (GPG_ERR_INTERNAL);
}


/*
 * Shortcut function to hash a buffer with a given algo. The only
 * guaranteed supported algorithms are RIPE-MD160 and SHA-1. The
 * supplied digest buffer must be large enough to store the resulting
 * hash.  No error is returned, the function will abort on an invalid
 * algo.  DISABLED_ALGOS are ignored here.  */
void
gcry_md_hash_buffer (int algo, void *digest,
                     const void *buffer, size_t length)
{
  gcry_module_spec_t *spec;
  gcry_module_t module;
  gcry_error_t err;

  _gcry_init ();
  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module = _gcry_module_lookup_id (digests_registered, algo);
  assert (module);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  spec = module->spec;
  err = gcry_core_md_hash_buffer (context, spec->spec, digest,
				  buffer, length);
  assert (! err);

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module_release (module);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
}

static int
md_get_algo (gcry_md_hd_t a)
{
  gcry_core_md_spec_t spec;
  unsigned int i;

  spec = gcry_core_md_get_algo (context, a->handle, 0);
  assert (spec);

  /* FIXME? a bit hackish...  but since this warning does not make
     sense anymore in libgcrypt-core, because of the new API, we need
     to emulate the behaviour here.  */
  if (gcry_core_md_get_algo (context, a->handle, 1))
    log_error (context, "WARNING: more than one algorithm in md_get_algo()\n");

  for (i = 0; i < DIM (digest_table); i++)
    if (spec == digest_table[i].spec.spec)
      break;
  
  if (i == DIM (digest_table))
    return 0;
  else
    return digest_table[i].id;
}

int
gcry_md_get_algo (gcry_md_hd_t hd)
{
  _gcry_init ();
  return md_get_algo (hd);
}

/****************
 * Return the length of the digest
 */
static int
md_digest_length (int algorithm)
{
  gcry_module_spec_t *spec;
  gcry_module_t module;
  int mdlen = 0;

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module = _gcry_module_lookup_id (digests_registered, algorithm);
  if (module)
    {
      spec = module->spec;
      mdlen = spec->spec->mdlen;
      module_release (module);
    }
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  return mdlen;
}

/****************
 * Return the length of the digest in bytes.
 * This function will return 0 in case of errors.
 */
unsigned int
gcry_md_get_algo_dlen (int algorithm)
{
  _gcry_init ();
  return md_digest_length (algorithm);
}

/* Hmmm: add a mode to enumerate the OIDs
 *	to make g10/sig-check.c more portable */
static const byte *
md_asn_oid (int algorithm, size_t *asnlen, size_t *mdlen)
{
  const byte *asnoid = NULL;
  gcry_module_spec_t *spec;
  gcry_module_t module;

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module = _gcry_module_lookup_id (digests_registered, algorithm);
  if (module)
    {
      spec = module->spec;
      if (asnlen)
	*asnlen = spec->spec->asnlen;
      if (mdlen)
	*mdlen = spec->spec->mdlen;

      /* FIXME: asnoid cannot be NULL?  */
      asnoid = spec->spec->asnoid;
      module_release (module);
    }
  else
    log_bug (context,
	     "no ASN.1 OID for md algo %d\n", algorithm);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  return asnoid;
}



/****************
 * Return information about the given cipher algorithm
 * WHAT select the kind of information returned:
 *  GCRYCTL_TEST_ALGO:
 *	Returns 0 when the specified algorithm is available for use.
 *	buffer and nbytes must be zero.
 *  GCRYCTL_GET_ASNOID:
 *	Return the ASNOID of the algorithm in buffer. if buffer is NULL, only
 *	the required length is returned.
 *
 * Note:  Because this function is in most cases used to return an
 * integer value, we can make it easier for the caller to just look at
 * the return value.  The caller will in all cases consult the value
 * and thereby detecting whether a error occured or not (i.e. while checking
 * the block size)
 */
gcry_error_t
gcry_md_algo_info (int algo, int what, void *buffer, size_t *nbytes)
{
  gcry_error_t err = 0;

  _gcry_init ();
  switch (what)
    {
    case GCRYCTL_TEST_ALGO:
      if (buffer || nbytes)
	err = gcry_error (GPG_ERR_INV_ARG);
      else
	err = check_digest_algo (algo);
      break;

    case GCRYCTL_GET_ASNOID:
      {
	const char unsigned *asn;
	size_t asnlen;

	asn = md_asn_oid (algo, &asnlen, NULL);
	if (buffer && (*nbytes >= asnlen))
	  {
	    memcpy (buffer, asn, asnlen);
	    *nbytes = asnlen;
	  }
	else if ((! buffer) && nbytes)
	  *nbytes = asnlen;
	else
	  {
	    if (buffer)
	      err = gcry_error (GPG_ERR_TOO_SHORT);
	    else
	      err = gcry_error (GPG_ERR_INV_ARG);
	  }
	break;
      }

  default:
    err = gcry_error (GPG_ERR_INV_OP);
  }

  return err;
}


static void
md_start_debug( gcry_md_hd_t md, char *suffix )
{
  gcry_core_md_debug_start (context, md->handle, suffix);
}

static void
md_stop_debug( gcry_md_hd_t md )
{
  gcry_core_md_debug_stop (context, md->handle);
}



/*
 * Return information about the digest handle.
 *  GCRYCTL_IS_SECURE:
 *	Returns 1 when the handle works on secured memory
 *	otherwise 0 is returned.  There is no error return.
 *  GCRYCTL_IS_ALGO_ENABLED:
 *     Returns 1 if the algo is enanled for that handle.
 *     The algo must be passed as the address of an int.
 */
gcry_error_t
gcry_md_info (gcry_md_hd_t h, int cmd, void *buffer, size_t *nbytes)
{
  gcry_error_t err = 0;

  _gcry_init ();
  switch (cmd)
    {
    case GCRYCTL_IS_SECURE:
      *nbytes = gcry_core_md_is_secure (context, h->handle);
      break;

    case GCRYCTL_IS_ALGO_ENABLED:
      {
	gcry_module_spec_t *spec;
	gcry_module_t module;
	int algo;

	algo = *((int *) buffer);
	_gcry_core_ath_mutex_lock (context, &digests_registered_lock);
	module = _gcry_module_lookup_id (digests_registered, algo);
	spec = module->spec;
	*nbytes = gcry_core_md_is_enabled (context, h->handle, spec->spec);
	module_release (module);
	_gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
	break;
      }

    default:
      err = gcry_error (GPG_ERR_INV_OP);
    }

  return err;
}

gcry_error_t
_gcry_md_init (void)
{
  register_default ();

  return 0;
}


int
gcry_md_is_secure (gcry_md_hd_t a) 
{
  size_t value;

  _gcry_init ();
  if (gcry_md_info (a, GCRYCTL_IS_SECURE, NULL, &value))
    value = 1; /* It seems to be better to assume secure memory on
                  error. */
  return value;
}


int
gcry_md_is_enabled (gcry_md_hd_t a, int algo) 
{
  size_t value;

  _gcry_init ();
  value = sizeof algo;
  if (gcry_md_info (a, GCRYCTL_IS_ALGO_ENABLED, &algo, &value))
    value = 0;
  return value;
}

/* Get a list consisting of the IDs of the loaded message digest
   modules.  If LIST is zero, write the number of loaded message
   digest modules to LIST_LENGTH and return.  If LIST is non-zero, the
   first *LIST_LENGTH algorithm IDs are stored in LIST, which must be
   of according size.  In case there are less message digest modules
   than *LIST_LENGTH, *LIST_LENGTH is updated to the correct
   number.  */
gcry_error_t
gcry_md_list (int *list, int *list_length)
{
  gcry_error_t err = 0;

  _gcry_init ();
  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  err = _gcry_module_list (digests_registered, list, list_length);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);

  return err;
}

/* This function looks up a message digest module by it's module id
   ALGO.  In case the module could be found, the module will be stored
   in MODULE (with one additional reference), it's internal
   specification will be stored in SPEC; otherwise an error will be
   returned.

   It is necessary to return the modules' specification structure
   directly, since the type (gcry_module_spec_t) required for
   resolving the pointer chain down to the modules' specification is
   internal to this file.

   This function is necessary, since the API for the encoding/decoding
   of data (ac.c) depends on message digest identifiers, not on
   message digest specification structures.  */
gcry_error_t
_gcry_md_lookup_module_spec (int algo,
			     gcry_module_t *module, gcry_core_md_spec_t *spec)
{
  gcry_module_spec_t *mod_spec;
  gcry_module_t mod;
  gcry_error_t err;

  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  mod = _gcry_module_lookup_id (digests_registered, algo);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
  if (module)
    {
      mod_spec = mod->spec;
      *module = mod;
      *spec = mod_spec->spec;
      err = 0;
    }
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);

  return err;
}

/* This function releases a reference to the message digest module
   MODULE.  */
void
_gcry_md_release_module (gcry_module_t module)
{
  _gcry_core_ath_mutex_lock (context, &digests_registered_lock);
  module_release (module);
  _gcry_core_ath_mutex_unlock (context, &digests_registered_lock);
}
