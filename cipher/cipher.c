/* cipher.c  -	cipher dispatcher
 * Copyright (C) 1998,1999,2000,2001,2002,2003 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "g10lib.h"
#include "cipher.h"
#include "ath.h"

#define MAX_BLOCKSIZE 16
#define TABLE_SIZE 14
#define CTX_MAGIC_NORMAL 0x24091964
#define CTX_MAGIC_SECURE 0x46919042

static struct
{
  const char *oidstring;
  int algo;
  int mode;
} oid_table[] =
  {
    { "1.2.840.113549.3.7",      GCRY_CIPHER_3DES,   GCRY_CIPHER_MODE_CBC },

    /* OIDs from NIST. See http://csrc.nist.gov.csor/ */
    { "2.16.840.1.101.3.4.1.1",  GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.2",  GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.3",  GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.4",  GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB },
    { "2.16.840.1.101.3.4.1.21", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.22", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.23", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.24", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB },
    { "2.16.840.1.101.3.4.1.41", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.42", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.43", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.44", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB },

    /* Teletrust specific OID for 3DES. */
    { "1.3.36.3.1.3.2.1",        GCRY_CIPHER_3DES,   GCRY_CIPHER_MODE_CBC },

    { NULL }
  };

/* This is the list of the default ciphers, which are included in
   libgcrypt.  */
static struct
{
  GcryCipherSpec *cipher;
} cipher_table[] =
  {
#if USE_BLOWFISH
    { &cipher_spec_blowfish,  },
#endif
#if USE_DES
    { &cipher_spec_des        },
    { &cipher_spec_tripledes  },
#endif
#if USE_ARCFOUR
    { &cipher_spec_arcfour    },
#endif
#if USE_CAST5
    { &cipher_spec_cast5      },
#endif
#if USE_AES
    { &cipher_spec_aes        },
    { &cipher_spec_aes192     },
    { &cipher_spec_aes256     },
#endif
#if USE_TWOFISH
    { &cipher_spec_twofish    },
    { &cipher_spec_twofish128 },
#endif
    { NULL                    },
  };

/* List of registered ciphers.  */
static GcryModule *ciphers_registered;

/* This is the lock protecting CIPHERS_REGISTERED.  */
static ath_mutex_t ciphers_registered_lock = ATH_MUTEX_INITIALIZER;

/* Flag to check wether the default ciphers have already been
   registered.  */
static int default_ciphers_registered;

/* Convenient macro for registering the default ciphers.  */
#define REGISTER_DEFAULT_CIPHERS                   \
  do                                               \
    {                                              \
      ath_mutex_lock (&ciphers_registered_lock);   \
      if (! default_ciphers_registered)            \
        {                                          \
          gcry_cipher_register_default ();         \
          default_ciphers_registered = 1;          \
        }                                          \
      ath_mutex_unlock (&ciphers_registered_lock); \
    }                                              \
  while (0)


/* These dummy functions are used in case a cipher implementation
   refuses to provide it's own functions.  */

static int
dummy_setkey (void *c, const unsigned char *key, unsigned keylen)
{
  return 0;
}

static void
dummy_encrypt_block (void *c,
		     unsigned char *outbuf, const unsigned char *inbuf)
{
  BUG();
}

static void
dummy_decrypt_block (void *c,
		     unsigned char *outbuf, const unsigned char *inbuf)
{
  BUG();
}

static void
dummy_encrypt_stream (void *c,
		      unsigned char *outbuf, const unsigned char *inbuf,
		      unsigned int n)
{
  BUG();
}

static void
dummy_decrypt_stream (void *c,
		      unsigned char *outbuf, const unsigned char *inbuf,
		      unsigned int n)
{
  BUG();
}

/* Internal function.  Register all the ciphers included in
   CIPHER_TABLE.  */
static void
gcry_cipher_register_default (void)
{
  int i, err = 0;
  
  for (i = 0; (! err) && cipher_table[i].cipher; i++)
    {
      if (! cipher_table[i].cipher->setkey)
	cipher_table[i].cipher->setkey = dummy_setkey;
      if (! cipher_table[i].cipher->encrypt)
	cipher_table[i].cipher->encrypt = dummy_encrypt_block;
      if (! cipher_table[i].cipher->decrypt)
	cipher_table[i].cipher->decrypt = dummy_decrypt_block;
      if (! cipher_table[i].cipher->stencrypt)
	cipher_table[i].cipher->stencrypt = dummy_encrypt_stream;
      if (! cipher_table[i].cipher->stdecrypt)
	cipher_table[i].cipher->stdecrypt = dummy_decrypt_stream;

      err = _gcry_module_add (&ciphers_registered,
			      (void *) cipher_table[i].cipher,
			      NULL);
    }

  if (err)
    BUG ();
}

/* Internal callback function.  Used via _gcry_module_lookup.  */
static int
gcry_cipher_lookup_func_id (void *spec, void *data)
{
  GcryCipherSpec *cipher = (GcryCipherSpec *) spec;
  int id = *((int *) data);

  return (cipher->id == id);
}

/* Internal callback function.  Used via _gcry_module_lookup.  */
static int
gcry_cipher_lookup_func_name (void *spec, void *data)
{
  GcryCipherSpec *cipher = (GcryCipherSpec *) spec;
  char *name = (char *) data;

  return (! stricmp (cipher->name, name));
}

/* Internal function.  Lookup a cipher entry by it's ID.  */
static GcryModule *
gcry_cipher_lookup_id (int id)
{
  GcryModule *cipher;

  cipher = _gcry_module_lookup (ciphers_registered, (void *) &id,
				gcry_cipher_lookup_func_id);

  return cipher;
}

/* Internal function.  Lookup a cipher entry by it's name.  */
static GcryModule *
gcry_cipher_lookup_name (const char *name)
{
  GcryModule *cipher;

  cipher = _gcry_module_lookup (ciphers_registered, (void *) name,
				gcry_cipher_lookup_func_name);

  return cipher;
}

/* Return a new, unused cipher ID for a user-provided cipher
   implementation.  */
static int
gcry_cipher_id_new (void)
{
  int id, id_start = 500, id_end = 600;	/* FIXME.  */
  
  for (id = id_start; id < id_end; id++)
    if (! gcry_cipher_lookup_id (id))
      return id;

  return 0;
}

/* Public function.  Register a provided CIPHER.  Returns zero on
   success, in which case the chosen cipher ID has been stored in
   CIPHER, or an error code.  */
int
gcry_cipher_register (GcryCipherSpec *cipher,
		      GcryModule **module)
{
  int id, err = 0;
  GcryModule *mod;

  ath_mutex_lock (&ciphers_registered_lock);

  id = gcry_cipher_id_new ();
  if (! id)
    err = GCRYERR_INTERNAL;	/* FIXME?  */
  else
    {
      cipher->id = id;
      err = _gcry_module_add (&ciphers_registered, (void *) cipher,
			      &mod);
    }
  ath_mutex_unlock (&ciphers_registered_lock);

  if (! err)
    *module = mod;

  return err;
}

/* Public function.  Unregister the cipher identified by MODULE, which
   must have been registered with gcry_cipher_register.  */
void
gcry_cipher_unregister (GcryModule *module)
{
  ath_mutex_lock (&ciphers_registered_lock);
  _gcry_module_release (module);
  ath_mutex_unlock (&ciphers_registered_lock);
}

/* The handle structure.  */
struct gcry_cipher_handle
{
  int magic;
  GcryCipherSpec *cipher;
  GcryModule *module;
  int  mode;
  unsigned int flags;
  byte iv[MAX_BLOCKSIZE];	/* (this should be ulong aligned) */
  byte lastiv[MAX_BLOCKSIZE];
  int  unused;  /* in IV */
  byte ctr[MAX_BLOCKSIZE];    /* for Counter (CTR) mode */
  PROPERLY_ALIGNED_TYPE context;
};

/* locate the OID in the oid table and return the index or -1 when not
   found */
static int 
search_oid (const char *string)
{
  const char *s;
  int i;

  if (string && (digitp (string)
                 || !strncmp (string, "oid.", 4) 
                 || !strncmp (string, "OID.", 4) ))
    {
      s =  digitp(string)? string : (string+4);

      for (i=0; oid_table[i].oidstring; i++)
        {
          if (!strcmp (s, oid_table[i].oidstring))
            return i;
        }
    }
  return -1;
}

/****************
 * Map a string to the cipher algo.
 * Returns: The algo ID of the cipher for the gioven name or
 *	    0 if the name is not known.
 */
int
gcry_cipher_map_name( const char *string )
{
  GcryModule *cipher;
  int i, id = 0;
  
  if (!string)
    return 0;

  /* kludge to alias RIJNDAEL to AES */
  if ( *string == 'R' || *string == 'r')
    {
      if (!strcasecmp (string, "RIJNDAEL"))
        string = "AES";
      else if (!strcasecmp (string, "RIJNDAEL192"))
        string = "AES192";
      else if (!strcasecmp (string, "RIJNDAEL256"))
        string = "AES256";
    }

  /* If the string starts with a digit (optionally prefixed with
     either "OID." or "oid."), we first look into our table of ASN.1
     object identifiers to figure out the algorithm */
  i = search_oid (string);
  if (i != -1)
    return oid_table[i].algo;

  REGISTER_DEFAULT_CIPHERS;

  ath_mutex_lock (&ciphers_registered_lock);
  cipher = gcry_cipher_lookup_name (string);
  if (cipher)
    {
      id = ((GcryCipherSpec *) cipher->spec)->id;
      _gcry_module_release (cipher);
    }
  ath_mutex_unlock (&ciphers_registered_lock);
  
  return id;
}

int
gcry_cipher_mode_from_oid (const char *string)
{
  int i;

  i = search_oid (string);
  return i == -1? 0 : oid_table[i].mode;
}


/****************
 * Map a cipher algo to a string
 */
static const char *
cipher_algo_to_string (int id)
{
  GcryModule *cipher;
  const char *name = NULL;

  REGISTER_DEFAULT_CIPHERS;

  ath_mutex_lock (&ciphers_registered_lock);
  cipher = gcry_cipher_lookup_id (id);
  if (cipher)
    {
      name = ((GcryCipherSpec *) cipher->spec)->name;
      _gcry_module_release (cipher);
    }
  ath_mutex_unlock (&ciphers_registered_lock);

  return name;
}

/****************
 * This function simply returns the name of the algorithm or some constant
 * string when there is no algo.  It will never return NULL.
 */
const char *
gcry_cipher_algo_name (int id)
{
  const char *s = cipher_algo_to_string (id);
  return s ? s : "";
}


static void
disable_cipher_algo (int id)
{
  GcryModule *cipher;

  REGISTER_DEFAULT_CIPHERS;

  ath_mutex_lock (&ciphers_registered_lock);
  cipher = gcry_cipher_lookup_id (id);
  if (cipher)
    {
      if (! (cipher->flags & FLAG_MODULE_DISABLED))
	cipher->flags |= FLAG_MODULE_DISABLED;
      _gcry_module_release (cipher);
    }
  ath_mutex_unlock (&ciphers_registered_lock);
}


/****************
 * Return 0 if the cipher algo is available.
 */

static int
check_cipher_algo (int id)
{
  GcryModule *cipher;
  int err = 0;

  REGISTER_DEFAULT_CIPHERS;

  ath_mutex_lock (&ciphers_registered_lock);
  cipher = gcry_cipher_lookup_id (id);
  if (cipher)
    {
      if (cipher->flags & FLAG_MODULE_DISABLED)
	err = GCRYERR_INV_CIPHER_ALGO;
      _gcry_module_release (cipher);
    }
  else
    err = GCRYERR_INV_CIPHER_ALGO;
  ath_mutex_unlock (&ciphers_registered_lock);
  
  return err;
}

static unsigned
cipher_get_keylen (int id)
{
  GcryModule *cipher;
  unsigned len = 0;

  REGISTER_DEFAULT_CIPHERS;

  ath_mutex_lock (&ciphers_registered_lock);
  cipher = gcry_cipher_lookup_id (id);
  if (cipher)
    {
      len = ((GcryCipherSpec *) cipher->spec)->keylen;
      if (! len)
	log_bug ("cipher %d w/o key length\n", id);
      _gcry_module_release (cipher);
    }
  else
    log_bug ("cipher %d not found\n", id);
  ath_mutex_unlock (&ciphers_registered_lock);

  return len;
}

static unsigned
cipher_get_blocksize (int id)
{
  GcryModule *cipher;
  unsigned len = 0;

  REGISTER_DEFAULT_CIPHERS;

  ath_mutex_lock (&ciphers_registered_lock);
  cipher = gcry_cipher_lookup_id (id);
  if (cipher)
    {
      len = ((GcryCipherSpec *) cipher->spec)->blocksize;
      if (! len)
	  log_bug ("cipher %d w/o blocksize\n", id);
      _gcry_module_release (cipher);
    }
  else
    log_bug ("cipher %d not found\n", id);
  ath_mutex_unlock (&ciphers_registered_lock);

  return len;
}


/****************
 * Open a cipher handle for use with algorithm ALGO, in mode MODE
 * and return the handle.  Return NULL and set the internal error variable
 * if something goes wrong.
 */

GCRY_CIPHER_HD
gcry_cipher_open( int algo, int mode, unsigned int flags )
{
    GCRY_CIPHER_HD h;
    int secure = (flags & GCRY_CIPHER_SECURE);
    GcryCipherSpec *cipher;
    GcryModule *module;

    fast_random_poll();

    REGISTER_DEFAULT_CIPHERS;

    /* Fetch the according module and check wether the cipher is
       marked available for use.  */
    ath_mutex_lock (&ciphers_registered_lock);
    module = gcry_cipher_lookup_id (algo);
    if (module)
      {
	if (module->flags & FLAG_MODULE_DISABLED)
	  {
	    set_lasterr (GCRYERR_INV_CIPHER_ALGO);
	    _gcry_module_release (module);
	    return NULL;
	  }
      }
    else
      {
	set_lasterr (GCRYERR_INV_CIPHER_ALGO);
	return NULL;
      }
    cipher = (GcryCipherSpec *) module->spec;
    ath_mutex_unlock (&ciphers_registered_lock);

    /* check flags */
    if( (flags & ~(GCRY_CIPHER_SECURE|
		   GCRY_CIPHER_ENABLE_SYNC|
		   GCRY_CIPHER_CBC_CTS|
		   GCRY_CIPHER_CBC_MAC)) ||
	(flags & GCRY_CIPHER_CBC_CTS & GCRY_CIPHER_CBC_MAC)) {
	set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	return NULL;
    }

    /* check that a valid mode has been requested */
    switch( mode ) {
      case GCRY_CIPHER_MODE_ECB:
      case GCRY_CIPHER_MODE_CBC:
      case GCRY_CIPHER_MODE_CFB:
      case GCRY_CIPHER_MODE_CTR:
        if ((cipher->encrypt == dummy_encrypt_block)
	    || (cipher->decrypt == dummy_decrypt_block))
	  {
            set_lasterr( GCRYERR_INV_CIPHER_MODE );
            return NULL;
	  }
        break;
      case GCRY_CIPHER_MODE_STREAM:
        if ((cipher->stencrypt == dummy_encrypt_stream)
	    || (cipher->stdecrypt == dummy_decrypt_stream))
	  {
            set_lasterr( GCRYERR_INV_CIPHER_MODE );
            return NULL;
	  }
	break;
      case GCRY_CIPHER_MODE_NONE:
	/* FIXME: issue a warning when this mode is used */
	break;
      default:
	set_lasterr( GCRYERR_INV_CIPHER_MODE );
	return NULL;
    }

    /* ? perform selftest here and mark this with a flag in cipher_table ? */

    h = secure ? gcry_calloc_secure( 1,
				     sizeof *h
				     + 2 * cipher->contextsize
				     - sizeof (PROPERLY_ALIGNED_TYPE) )
	       : gcry_calloc( 1,
			      sizeof *h
			      + 2 * cipher->contextsize
			      - sizeof (PROPERLY_ALIGNED_TYPE) );
    if( !h ) {
	set_lasterr( GCRYERR_NO_MEM );
	return NULL;
    }
    h->magic = secure ? CTX_MAGIC_SECURE : CTX_MAGIC_NORMAL;
    h->cipher = cipher;
    h->module = module;
    h->mode = mode;
    h->flags = flags;

    return h;
}


void
gcry_cipher_close( GCRY_CIPHER_HD h )
{
    if( !h )
	return;
    if( h->magic != CTX_MAGIC_SECURE && h->magic != CTX_MAGIC_NORMAL )
	_gcry_fatal_error(GCRYERR_INTERNAL,
			"gcry_cipher_close: already closed/invalid handle");
    h->magic = 0;

    ath_mutex_lock (&ciphers_registered_lock);
    _gcry_module_release (h->module);
    ath_mutex_unlock (&ciphers_registered_lock);
    gcry_free(h);
}


static int
cipher_setkey( GCRY_CIPHER_HD c, byte *key, unsigned keylen )
{
    int ret;

    ret = (*c->cipher->setkey)( &c->context.c, key, keylen );
    if (! ret)
      memcpy ((void *) ((char *) &c->context.c
			+ c->cipher->contextsize),
	      (void *) &c->context.c,
	      c->cipher->contextsize);
    return ret;
}


static void
cipher_setiv( GCRY_CIPHER_HD c, const byte *iv, unsigned ivlen )
{
    memset( c->iv, 0, c->cipher->blocksize );
    if( iv ) {
	if( ivlen != c->cipher->blocksize )
	    log_info("WARNING: cipher_setiv: ivlen=%u blklen=%u\n",
		     ivlen, (unsigned) c->cipher->blocksize );
	if (ivlen > c->cipher->blocksize)
	  ivlen = c->cipher->blocksize;
	memcpy( c->iv, iv, ivlen );
    }
    c->unused = 0;
}


static void
cipher_reset (GCRY_CIPHER_HD c)
{
  memcpy ((void *) &c->context.c,
	  (void *) ((char *) &c->context.c
		    + c->cipher->contextsize),
	  c->cipher->contextsize);
  memset (c->iv, 0, c->cipher->blocksize);
  memset (c->lastiv, 0, c->cipher->blocksize);
  memset (c->ctr, 0, c->cipher->blocksize);
}


static void
do_ecb_encrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->cipher->encrypt)( &c->context.c, outbuf, (byte*)/*arggg*/inbuf );
	inbuf  += c->cipher->blocksize;
	outbuf += c->cipher->blocksize;
    }
}

static void
do_ecb_decrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	(*c->cipher->decrypt)( &c->context.c, outbuf, (byte*)/*arggg*/inbuf );
	inbuf  += c->cipher->blocksize;
	outbuf += c->cipher->blocksize;
    }
}

static void
do_cbc_encrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nbytes )
{
    unsigned int n;
    byte *ivp;
    int i;
    size_t blocksize = c->cipher->blocksize;
    unsigned nblocks = nbytes / blocksize;

    if ((c->flags & GCRY_CIPHER_CBC_CTS) && nbytes > blocksize) {
      if ((nbytes % blocksize) == 0)
	nblocks--;
    }

    for(n=0; n < nblocks; n++ ) {
	/* fixme: the xor should works on words and not on
	 * bytes.  Maybe it is a good idea to enhance the cipher backend
	 * API to allow for CBC handling in the backend */
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    outbuf[i] = inbuf[i] ^ *ivp++;
	(*c->cipher->encrypt)( &c->context.c, outbuf, outbuf );
	memcpy(c->iv, outbuf, blocksize );
	inbuf  += c->cipher->blocksize;
	if (!(c->flags & GCRY_CIPHER_CBC_MAC))
	  outbuf += c->cipher->blocksize;
    }

    if ((c->flags & GCRY_CIPHER_CBC_CTS) && nbytes > blocksize)
      {
	int restbytes;

	if ((nbytes % blocksize) == 0)
	  restbytes = blocksize;
	else
	  restbytes = nbytes % blocksize;

	memcpy(outbuf, outbuf - c->cipher->blocksize, restbytes);
	outbuf -= c->cipher->blocksize;

	for(ivp=c->iv,i=0; i < restbytes; i++ )
	    outbuf[i] = inbuf[i] ^ *ivp++;
	for(; i < blocksize; i++ )
	    outbuf[i] = 0 ^ *ivp++;

	(*c->cipher->encrypt)( &c->context.c, outbuf, outbuf );
	memcpy(c->iv, outbuf, blocksize );
      }
}

static void
do_cbc_decrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nbytes )
{
    unsigned int n;
    byte *ivp;
    int i;
    size_t blocksize = c->cipher->blocksize;
    unsigned nblocks = nbytes / blocksize;

    if ((c->flags & GCRY_CIPHER_CBC_CTS) && nbytes > blocksize) {
      nblocks--;
      if ((nbytes % blocksize) == 0)
	nblocks--;
      memcpy(c->lastiv, c->iv, blocksize );
    }

    for(n=0; n < nblocks; n++ ) {
	/* because outbuf and inbuf might be the same, we have
	 * to save the original ciphertext block.  We use lastiv
	 * for this here because it is not used otherwise */
	memcpy(c->lastiv, inbuf, blocksize );
	(*c->cipher->decrypt)( &c->context.c, outbuf, (char*)/*argggg*/inbuf );
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    outbuf[i] ^= *ivp++;
	memcpy(c->iv, c->lastiv, blocksize );
	inbuf  += c->cipher->blocksize;
	outbuf += c->cipher->blocksize;
    }

    if ((c->flags & GCRY_CIPHER_CBC_CTS) && nbytes > blocksize) {
	int restbytes;

	if ((nbytes % blocksize) == 0)
	  restbytes = blocksize;
	else
	  restbytes = nbytes % blocksize;

	memcpy(c->lastiv, c->iv, blocksize ); /* save Cn-2 */
	memcpy(c->iv, inbuf + blocksize, restbytes ); /* save Cn */

	(*c->cipher->decrypt)( &c->context.c, outbuf, (char*)/*argggg*/inbuf );
	for(ivp=c->iv,i=0; i < restbytes; i++ )
	    outbuf[i] ^= *ivp++;

	memcpy(outbuf + blocksize, outbuf, restbytes);
	for(i=restbytes; i < blocksize; i++)
	  c->iv[i] = outbuf[i];
	(*c->cipher->decrypt)( &c->context.c, outbuf, c->iv );
	for(ivp=c->lastiv,i=0; i < blocksize; i++ )
	    outbuf[i] ^= *ivp++;
	/* c->lastiv is now really lastlastiv, does this matter? */
    }
}


static void
do_cfb_encrypt( GCRY_CIPHER_HD c,
                byte *outbuf, const byte *inbuf, unsigned nbytes )
{
    byte *ivp;
    size_t blocksize = c->cipher->blocksize;

    if( nbytes <= c->unused ) {
	/* short enough to be encoded by the remaining XOR mask */
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv+c->cipher->blocksize - c->unused; nbytes; nbytes--, c->unused-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	return;
    }

    if( c->unused ) {
	/* XOR the input with the IV and store input into IV */
	nbytes -= c->unused;
	for(ivp=c->iv+blocksize - c->unused; c->unused; c->unused-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
    }

    /* now we can process complete blocks */
    while( nbytes >= blocksize ) {
	int i;
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->cipher->encrypt)( &c->context.c, c->iv, c->iv );
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	nbytes -= blocksize;
    }
    if( nbytes ) { /* process the remaining bytes */
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->cipher->encrypt)( &c->context.c, c->iv, c->iv );
	c->unused = blocksize;
	/* and apply the xor */
	c->unused -= nbytes;
	for(ivp=c->iv; nbytes; nbytes-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
    }
}

static void
do_cfb_decrypt( GCRY_CIPHER_HD c,
                byte *outbuf, const byte *inbuf, unsigned nbytes )
{
    byte *ivp;
    ulong temp;
    size_t blocksize = c->cipher->blocksize;

    if( nbytes <= c->unused ) {
	/* short enough to be encoded by the remaining XOR mask */
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv+blocksize - c->unused; nbytes; nbytes--,c->unused--){
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
	return;
    }

    if( c->unused ) {
	/* XOR the input with the IV and store input into IV */
	nbytes -= c->unused;
	for(ivp=c->iv+blocksize - c->unused; c->unused; c->unused-- ) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
    }

    /* now we can process complete blocks */
    while( nbytes >= blocksize ) {
	int i;
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->cipher->encrypt)( &c->context.c, c->iv, c->iv );
	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv,i=0; i < blocksize; i++ ) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
	nbytes -= blocksize;
    }
    if( nbytes ) { /* process the remaining bytes */
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );
	(*c->cipher->encrypt)( &c->context.c, c->iv, c->iv );
	c->unused = blocksize;
	/* and apply the xor */
	c->unused -= nbytes;
	for(ivp=c->iv; nbytes; nbytes-- ) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
    }
}


static void
do_ctr_encrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nbytes )
{
  unsigned int n;
  byte tmp[MAX_BLOCKSIZE];
  int i;

  for(n=0; n < nbytes; n++)
    {
      if ((n % c->cipher->blocksize) == 0)
	{
	  (*c->cipher->encrypt) (&c->context.c, tmp, c->ctr);

	  for (i = c->cipher->blocksize; i > 0; i--)
	    {
	      c->ctr[i-1]++;
	      if (c->ctr[i-1] != 0)
		break;
	    }
	}

      /* XOR input with encrypted counter and store in output */
      outbuf[n] = inbuf[n] ^ tmp[n % c->cipher->blocksize];
    }
}

static void
do_ctr_decrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf, unsigned nbytes )
{
  return do_ctr_encrypt (c, outbuf, inbuf, nbytes);
}


/****************
 * Encrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some contraints apply to NBYTES.
 */
static int
cipher_encrypt( GCRY_CIPHER_HD c, byte *outbuf,
				  const byte *inbuf, unsigned int nbytes )
{
    int rc = 0;

    switch( c->mode ) {
      case GCRY_CIPHER_MODE_ECB:
	if (!(nbytes%c->cipher->blocksize))
            do_ecb_encrypt(c, outbuf, inbuf, nbytes/c->cipher->blocksize );
        else 
            rc = GCRYERR_INV_ARG;
	break;
      case GCRY_CIPHER_MODE_CBC:
	if (!(nbytes%c->cipher->blocksize) || (nbytes > c->cipher->blocksize && 
				       (c->flags & GCRY_CIPHER_CBC_CTS)))
            do_cbc_encrypt(c, outbuf, inbuf, nbytes );
        else 
            rc = GCRYERR_INV_ARG;
	break;
      case GCRY_CIPHER_MODE_CFB:
	do_cfb_encrypt(c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_CTR:
	do_ctr_encrypt(c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_STREAM:
        (*c->cipher->stencrypt)( &c->context.c,
				 outbuf, (byte*)/*arggg*/inbuf, nbytes );
        break;
      case GCRY_CIPHER_MODE_NONE:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
      default:
        log_fatal("cipher_encrypt: invalid mode %d\n", c->mode );
        rc = GCRYERR_INV_CIPHER_MODE;
        break;
    }
    return rc;
}


/****************
 * Encrypt IN and write it to OUT.  If IN is NULL, in-place encryption has
 * been requested,
 */
int
gcry_cipher_encrypt (GcryCipherHd h, byte *out, size_t outsize,
                     const byte  *in, size_t inlen )
{
  int rc;

  if (!in)
    {
      /* caller requested in-place encryption */
      /* actullay cipher_encrypt() does not need to know about it, but
       * we may change this to get better performace */
      rc = cipher_encrypt ( h, out, out, outsize );
    }
  else
    {
      if ( outsize < ((h->flags & GCRY_CIPHER_CBC_MAC) ? h->cipher->blocksize : inlen))
        rc = GCRYERR_TOO_SHORT;
      else if ((h->mode == GCRY_CIPHER_MODE_ECB
                || (h->mode == GCRY_CIPHER_MODE_CBC
                    && !((h->flags & GCRY_CIPHER_CBC_CTS)
                         && (inlen > h->cipher->blocksize))
                    )
                )  
               && (inlen % h->cipher->blocksize))
        rc = GCRYERR_INV_ARG;
      else
        rc = cipher_encrypt (h, out, in, inlen);
    }

  if (rc && out)
    memset (out, 0x42, outsize); /* Failsafe: Make sure that the
                                    plaintext will never make it into
                                    OUT. */

  return rc? set_lasterr (rc):0;
}



/****************
 * Decrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some some contraints apply to NBYTES.
 */
static int
cipher_decrypt( GCRY_CIPHER_HD c, byte *outbuf, const byte *inbuf,
							unsigned nbytes )
{
    int rc = 0;

    switch( c->mode ) {
      case GCRY_CIPHER_MODE_ECB:
	if (!(nbytes%c->cipher->blocksize))
            do_ecb_decrypt(c, outbuf, inbuf, nbytes/c->cipher->blocksize );
        else 
            rc = GCRYERR_INV_ARG;
	break;
      case GCRY_CIPHER_MODE_CBC:
	if (!(nbytes%c->cipher->blocksize) || (nbytes > c->cipher->blocksize && 
					       (c->flags & GCRY_CIPHER_CBC_CTS)))
            do_cbc_decrypt(c, outbuf, inbuf, nbytes );
        else 
            rc = GCRYERR_INV_ARG;
	break;
      case GCRY_CIPHER_MODE_CFB:
	do_cfb_decrypt(c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_CTR:
	do_ctr_decrypt(c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_STREAM:
        (*c->cipher->stdecrypt)( &c->context.c,
				 outbuf, (byte*)/*arggg*/inbuf, nbytes );
        break;
      case GCRY_CIPHER_MODE_NONE:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
      default:
        log_fatal ("cipher_decrypt: invalid mode %d\n", c->mode );
        rc = GCRYERR_INV_CIPHER_MODE;
        break;
    }
    return rc;
}


int
gcry_cipher_decrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				 const byte  *in, size_t inlen )
{
    int rc;

    if( !in ) {
	/* caller requested in-place encryption */
	/* actullay cipher_encrypt() does not need to know about it, but
	 * we may chnage this to get better performace */
	rc = cipher_decrypt( h, out, out, outsize );
    }
    else {
	if( outsize < inlen )
	    return set_lasterr( GCRYERR_TOO_SHORT );
        if ( ( h->mode == GCRY_CIPHER_MODE_ECB ||
               (h->mode == GCRY_CIPHER_MODE_CBC && 
		!((h->flags & GCRY_CIPHER_CBC_CTS) &&
		  (inlen > h->cipher->blocksize)))) &&
	     (inlen % h->cipher->blocksize) != 0 )
            return set_lasterr( GCRYERR_INV_ARG );

	rc = cipher_decrypt( h, out, in, inlen );
    }
    return rc? set_lasterr (rc):0;
}



/****************
 * Used for PGP's somewhat strange CFB mode. Only works if
 * the corresponding flag is set.
 */
static void
cipher_sync( GCRY_CIPHER_HD c )
{
    if( (c->flags & GCRY_CIPHER_ENABLE_SYNC) && c->unused ) {
	memmove(c->iv + c->unused, c->iv, c->cipher->blocksize - c->unused );
	memcpy(c->iv, c->lastiv + c->cipher->blocksize - c->unused, c->unused);
	c->unused = 0;
    }
}


int
gcry_cipher_ctl( GCRY_CIPHER_HD h, int cmd, void *buffer, size_t buflen)
{
  int rc = 0;

  switch (cmd)
    {
    case GCRYCTL_SET_KEY:
      rc = cipher_setkey( h, buffer, buflen );
      break;
    case GCRYCTL_SET_IV:
      cipher_setiv( h, buffer, buflen );
      break;
    case GCRYCTL_RESET:
      cipher_reset (h);
      break;
    case GCRYCTL_CFB_SYNC:
      cipher_sync( h );
      break;
    case GCRYCTL_SET_CBC_CTS:
      if (buflen)
	if (h->flags & GCRY_CIPHER_CBC_MAC)
	  rc = GCRYERR_INV_FLAG;
	else
	  h->flags |= GCRY_CIPHER_CBC_CTS;
      else
	h->flags &= ~GCRY_CIPHER_CBC_CTS;
      break;
    case GCRYCTL_SET_CBC_MAC:
      if (buflen)
	if (h->flags & GCRY_CIPHER_CBC_CTS)
	  rc = GCRYERR_INV_FLAG;
	else
	  h->flags |= GCRY_CIPHER_CBC_MAC;
      else
	h->flags &= ~GCRY_CIPHER_CBC_MAC;
      break;
    case GCRYCTL_DISABLE_ALGO:
      /* this one expects a NULL handle and buffer pointing to an
       * integer with the algo number.
       */
      if( h || !buffer || buflen != sizeof(int) )
        return set_lasterr( GCRYERR_INV_CIPHER_ALGO );
      disable_cipher_algo( *(int*)buffer );
      break;
    case GCRYCTL_SET_CTR:
      if (buffer && buflen == h->cipher->blocksize)
	memcpy (h->ctr, buffer, h->cipher->blocksize);
      else if (buffer == NULL || buflen == 0)
	memset (h->ctr, 0, h->cipher->blocksize);
      else
	rc = GCRYERR_INV_ARG;
      break;

    default:
      rc = GCRYERR_INV_OP;
    }
  return set_lasterr (rc);
}


/****************
 * Return information about the cipher handle.
 * -1 is returned on error and gcry_errno() may be used to get more information
 * about the error.
 */
int
gcry_cipher_info( GCRY_CIPHER_HD h, int cmd, void *buffer, size_t *nbytes)
{
    switch( cmd ) {
      default:
	set_lasterr( GCRYERR_INV_OP );
	return -1;
    }
    return 0;
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
 * On error the value -1 is returned and the error reason may be
 * retrieved by gcry_errno().
 * Note:  Because this function is in most cases used to return an
 * integer value, we can make it easier for the caller to just look at
 * the return value.  The caller will in all cases consult the value
 * and thereby detecting whether a error occured or not (i.e. while checking
 * the block size)
 */
int
gcry_cipher_algo_info( int algo, int what, void *buffer, size_t *nbytes)
{
    unsigned int ui;

    switch( what ) {
      case GCRYCTL_GET_KEYLEN:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	    break;
	}
	ui = cipher_get_keylen( algo );
	if( ui > 0 && ui <= 512 )
	    return (int)ui/8;
	/* the only reason is an invalid algo or a strange blocksize */
	set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	break;

      case GCRYCTL_GET_BLKLEN:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	    break;
	}
	ui = cipher_get_blocksize( algo );
	if( ui > 0 && ui < 10000 )
	    return (int)ui;
	/* the only reason is an invalid algo or a strange blocksize */
	set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	break;

      case GCRYCTL_TEST_ALGO:
	if( buffer || nbytes ) {
	    set_lasterr( GCRYERR_INV_ARG );
	    break;
	}
	if( check_cipher_algo( algo ) ) {
	    set_lasterr( GCRYERR_INV_CIPHER_ALGO );
	    break;
	}
	return 0;

      default:
	set_lasterr( GCRYERR_INV_OP );
    }
    return -1;
}
