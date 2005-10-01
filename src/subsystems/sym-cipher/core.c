/* cipher.c  -	cipher dispatcher
 * Copyright (C) 1998, 1999, 2000,2001,2002,2003, 2005 Free Software Foundation, Inc.
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

#include <gcrypt-cipher-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>



#define MAX_BLOCKSIZE 16
#define TABLE_SIZE 14
#define CTX_MAGIC_NORMAL 0x24091964
#define CTX_MAGIC_SECURE 0x46919042



/* The handle structure.  */
struct gcry_cipher_handle
{
  int magic;
  size_t actual_handle_size;     /* Allocated size of this handle. */
  gcry_core_cipher_spec_t cipher;
  int mode;
  unsigned int flags;
  unsigned char iv[MAX_BLOCKSIZE];	/* (this should be ulong aligned) */
  unsigned char lastiv[MAX_BLOCKSIZE];
  int unused;  /* in IV */
  unsigned char ctr[MAX_BLOCKSIZE];     /* For Counter (CTR) mode. */
  struct
  {
    gcry_core_ac_cb_t cb;
    void *opaque;
  } cb;
  PROPERLY_ALIGNED_TYPE context;
};



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
_gcry_core_cipher_open (gcry_core_context_t ctx,
			gcry_core_cipher_hd_t *handle,
			gcry_core_cipher_spec_t cipher,
			int mode, unsigned int flags)
{
  int secure = (flags & GCRY_CIPHER_SECURE);
  gcry_core_cipher_hd_t h = NULL;
  gcry_err_code_t err = 0;

  /* If the application missed to call the random poll function, we do
     it here to ensure that it is used once in a while. */
  if (! (ctx->flags & GCRY_CORE_FLAG_DISABLE_AUTO_PRNG_POOL_FILLING))
    gcry_core_random_fast_poll (ctx);

  /* check flags */
  if ((! err)
      && ((flags & ~(0 
		     | GCRY_CIPHER_SECURE
		     | GCRY_CIPHER_ENABLE_SYNC
		     | GCRY_CIPHER_CBC_CTS
		     | GCRY_CIPHER_CBC_MAC))
	  || (flags & GCRY_CIPHER_CBC_CTS & GCRY_CIPHER_CBC_MAC)))
    err = GPG_ERR_CIPHER_ALGO;

  /* check that a valid mode has been requested */
  if (! err)
    switch (mode)
      {
      case GCRY_CIPHER_MODE_ECB:
      case GCRY_CIPHER_MODE_CBC:
      case GCRY_CIPHER_MODE_CFB:
      case GCRY_CIPHER_MODE_CTR:
#if 0
	/* FIXME: Seems, that this check needs to be removed, because
	   of the callback mechanism.  */
	if (! (cipher->encrypt && cipher->decrypt))
	  err = GPG_ERR_INV_CIPHER_MODE;
#endif
	break;

      case GCRY_CIPHER_MODE_STREAM:
#if 0
	/* FIXME: Seems, that this check needs to be removed, because
	   of the callback mechanism.  */
	if (! (cipher->stencrypt && cipher->stdecrypt))
	  err = GPG_ERR_INV_CIPHER_MODE;
#endif
	break;

      case GCRY_CIPHER_MODE_NONE:
	/* FIXME: issue a warning when this mode is used */
	break;

      default:
	err = GPG_ERR_INV_CIPHER_MODE;
      }

  if (! err)
    {
      size_t size = (sizeof (*h)
                     + 2 * cipher->contextsize
                     - sizeof (PROPERLY_ALIGNED_TYPE));

      if (secure)
	h = gcry_core_calloc_secure (ctx, 1, size);
      else
	h = gcry_core_calloc (ctx, 1, size);

      if (! h)
	err = gpg_err_code_from_errno (errno);
      else
	{
	  h->magic = secure ? CTX_MAGIC_SECURE : CTX_MAGIC_NORMAL;
          h->actual_handle_size = size;
	  h->cipher = cipher;
	  h->mode = mode;
	  h->flags = flags;
	}
    }

  /* Done.  */

  *handle = err ? NULL : h;

  return gcry_core_error (err);
}


void
_gcry_core_cipher_set_cb (gcry_core_context_t ctx,
			  gcry_core_cipher_hd_t handle,
			  gcry_core_cipher_cb_t cb,
			  void *opaque)
{
  handle->cb.cb = cb;
  handle->cb.opaque = opaque;
}


/* Release all resources associated with the cipher handle H. H may be
   NULL in which case this is a no-operation. */
void
_gcry_core_cipher_close (gcry_core_context_t ctx, gcry_core_cipher_hd_t h)
{
  if (! h)
    return;

  if ((h->magic != CTX_MAGIC_SECURE)
      && (h->magic != CTX_MAGIC_NORMAL))
    _gcry_core_fatal_error(ctx,
		      GPG_ERR_INTERNAL,
		      "gcry_cipher_close: already closed/invalid handle");
  else
    h->magic = 0;

  /* We always want to wipe out the memory even when the context has
     been allocated in secure memory.  The user might have disabled
     secure memory or is using his own implementation which does not
     do the wiping.  To accomplish this we need to keep track of the
     actual size of this structure because we have no way to known
     how large the allocated area was when using a standard malloc. */
  wipememory (h, h->actual_handle_size);

  gcry_core_free (ctx, h);
}


/* Set the key to be used for the encryption context C to KEY with
   length KEYLEN.  The length should match the required length. */
static gcry_error_t
cipher_setkey (gcry_core_context_t ctx,
	       gcry_core_cipher_hd_t c, const byte *key, unsigned keylen)
{
  gcry_err_code_t ret;

  assert (c->cipher->setkey || c->cb.cb);
  if (c->cipher->setkey)
    ret = (*c->cipher->setkey) (ctx, &c->context.c, key, keylen);
  else
    {
      gcry_core_cipher_cb_setkey_t cb_data;

      cb_data.c = &c->context.c;
      cb_data.key = key;
      cb_data.keylen = keylen;

      ret = (*c->cb.cb) (ctx, c->cb.opaque,
			 GCRY_CORE_CIPHER_CB_SETKEY, &cb_data);
    }

  if (! ret)
    /* Duplicate initial context.  */
    memcpy ((void *) ((char *) &c->context.c + c->cipher->contextsize),
	    (void *) &c->context.c,
	    c->cipher->contextsize);

  return gcry_core_error (ret);
}


/* Set the IV to be used for the encryption context C to IV with
   length IVLEN.  The length should match the required length. */
static void
cipher_setiv( gcry_core_context_t ctx,
	      gcry_core_cipher_hd_t c, const byte *iv, unsigned ivlen )
{
    memset( c->iv, 0, c->cipher->blocksize );
    if( iv ) {
	if( ivlen != c->cipher->blocksize )
	    log_info(ctx,
		     "WARNING: cipher_setiv: ivlen=%u blklen=%u\n",
		     ivlen, (unsigned) c->cipher->blocksize );
	if (ivlen > c->cipher->blocksize)
	  ivlen = c->cipher->blocksize;
	memcpy( c->iv, iv, ivlen );
    }
    c->unused = 0;
}


/* Reset the cipher context to the initial contex.  This is basically
   the same as an release followed by a new. */
static void
cipher_reset (gcry_core_context_t ctx, gcry_core_cipher_hd_t c)
{
  memcpy (&c->context.c,
	  (char *) &c->context.c + c->cipher->contextsize,
	  c->cipher->contextsize);
  memset (c->iv, 0, c->cipher->blocksize);
  memset (c->lastiv, 0, c->cipher->blocksize);
  memset (c->ctr, 0, c->cipher->blocksize);
}

static void
do_encrypt (gcry_core_context_t ctx,
	    gcry_core_cipher_hd_t handle,
	    byte *outbuf, const byte *inbuf)
{
  assert (handle->cipher->encrypt || handle->cb.cb);

  if (handle->cipher->encrypt)
    /* FIXME, const.  */
    (*handle->cipher->encrypt) (ctx, &handle->context.c, outbuf, inbuf);
  else
    {
      gcry_core_cipher_cb_encrypt_t cb_data;

      cb_data.c = &handle->context.c;
      cb_data.outbuf = outbuf;
      cb_data.inbuf = inbuf;	/* FIXME, const.  */

      (*handle->cb.cb) (ctx, handle->cb.opaque,
			GCRY_CORE_CIPHER_CB_ENCRYPT, &cb_data);
    }
}
static void
do_decrypt (gcry_core_context_t ctx,
	    gcry_core_cipher_hd_t handle,
	    byte *outbuf, const byte *inbuf)
{
  assert (handle->cipher->decrypt || handle->cb.cb);

  if (handle->cipher->decrypt)
    /* FIXME, const.  */
    (*handle->cipher->decrypt) (ctx, &handle->context.c, outbuf, inbuf);
  else
    {
      gcry_core_cipher_cb_decrypt_t cb_data;

      cb_data.c = &handle->context.c;
      cb_data.outbuf = outbuf;
      cb_data.inbuf = inbuf;	/* FIXME, const.  */

      (*handle->cb.cb) (ctx, handle->cb.opaque,
			GCRY_CORE_CIPHER_CB_DECRYPT, &cb_data);
    }
}

static void
do_ecb_encrypt( gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c, byte *outbuf, const byte *inbuf,
                unsigned int nblocks )
{
    unsigned int n;

    for(n=0; n < nblocks; n++ )
      {
	do_encrypt (ctx, c, outbuf, inbuf);
	inbuf  += c->cipher->blocksize;
	outbuf += c->cipher->blocksize;
    }
}

static void
do_ecb_decrypt( gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c, byte *outbuf, const byte *inbuf,
                unsigned int nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ )
      {
	do_decrypt (ctx, c, outbuf, inbuf);
	inbuf  += c->cipher->blocksize;
	outbuf += c->cipher->blocksize;
    }
}

static void
do_cbc_encrypt( gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c, byte *outbuf, const byte *inbuf,
                unsigned int nbytes )
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
	/* fixme: the xor should work on words and not on
	 * bytes.  Maybe it is a good idea to enhance the cipher backend
	 * API to allow for CBC handling direct in the backend */
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    outbuf[i] = inbuf[i] ^ *ivp++;

	do_encrypt (ctx, c, outbuf, outbuf);

	memcpy(c->iv, outbuf, blocksize );
	inbuf  += blocksize;
	if (!(c->flags & GCRY_CIPHER_CBC_MAC))
	  outbuf += blocksize;
    }

    if ((c->flags & GCRY_CIPHER_CBC_CTS) && nbytes > blocksize)
      {
	/* We have to be careful here, since outbuf might be equal to
	   inbuf.  */

	int restbytes;
	byte b;

	if ((nbytes % blocksize) == 0)
	  restbytes = blocksize;
	else
	  restbytes = nbytes % blocksize;

	outbuf -= blocksize;
	for (ivp = c->iv, i = 0; i < restbytes; i++)
	  {
	    b = inbuf[i];
	    outbuf[blocksize + i] = outbuf[i];
	    outbuf[i] = b ^ *ivp++;
	  }
	for (; i < blocksize; i++)
	  outbuf[i] = 0 ^ *ivp++;

	do_encrypt (ctx, c, outbuf, outbuf);
	memcpy (c->iv, outbuf, blocksize);
      }
}

static void
do_cbc_decrypt( gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c, byte *outbuf, const byte *inbuf,
                unsigned int nbytes )
{
    unsigned int n;
    byte *ivp;
    int i;
    size_t blocksize = c->cipher->blocksize;
    unsigned int nblocks = nbytes / blocksize;

    if ((c->flags & GCRY_CIPHER_CBC_CTS) && nbytes > blocksize) {
      nblocks--;
      if ((nbytes % blocksize) == 0)
	nblocks--;
      memcpy(c->lastiv, c->iv, blocksize );
    }

    for(n=0; n < nblocks; n++ ) {
	/* Because outbuf and inbuf might be the same, we have
	 * to save the original ciphertext block.  We use lastiv
	 * for this here because it is not used otherwise. */
	memcpy(c->lastiv, inbuf, blocksize );

	do_decrypt (ctx, c, outbuf, inbuf);

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

	do_decrypt (ctx, c, outbuf, inbuf);

	for(ivp=c->iv,i=0; i < restbytes; i++ )
	    outbuf[i] ^= *ivp++;

	memcpy(outbuf + blocksize, outbuf, restbytes);
	for(i=restbytes; i < blocksize; i++)
	  c->iv[i] = outbuf[i];
	c->cipher->decrypt (ctx, &c->context.c, outbuf, c->iv );
	for(ivp=c->lastiv,i=0; i < blocksize; i++ )
	    outbuf[i] ^= *ivp++;
	/* c->lastiv is now really lastlastiv, does this matter? */
    }
}


static void
do_cfb_encrypt( gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c,
                byte *outbuf, const byte *inbuf, unsigned nbytes )
{
    byte *ivp;
    size_t blocksize = c->cipher->blocksize;

    if( nbytes <= c->unused ) {
	/* Short enough to be encoded by the remaining XOR mask. */
	/* XOR the input with the IV and store input into IV. */
	for (ivp=c->iv+c->cipher->blocksize - c->unused;
             nbytes;
             nbytes--, c->unused-- )
          *outbuf++ = (*ivp++ ^= *inbuf++);
	return;
    }

    if( c->unused ) {
	/* XOR the input with the IV and store input into IV */
	nbytes -= c->unused;
	for(ivp=c->iv+blocksize - c->unused; c->unused; c->unused-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
    }

    /* Now we can process complete blocks. */
    while( nbytes >= blocksize ) {
	int i;
	/* Encrypt the IV (and save the current one). */

	memcpy( c->lastiv, c->iv, blocksize );

	do_encrypt (ctx, c, c->iv, c->iv);

	/* XOR the input with the IV and store input into IV */
	for(ivp=c->iv,i=0; i < blocksize; i++ )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
	nbytes -= blocksize;
    }
    if( nbytes ) { /* process the remaining bytes */
	/* encrypt the IV (and save the current one) */
	memcpy( c->lastiv, c->iv, blocksize );

	do_encrypt (ctx, c, c->iv, c->iv);

	c->unused = blocksize;
	/* and apply the xor */
	c->unused -= nbytes;
	for(ivp=c->iv; nbytes; nbytes-- )
	    *outbuf++ = (*ivp++ ^= *inbuf++);
    }
}

static void
do_cfb_decrypt( gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c,
                byte *outbuf, const byte *inbuf, unsigned int nbytes )
{
    byte *ivp;
    ulong temp;
    size_t blocksize = c->cipher->blocksize;

    if( nbytes <= c->unused ) {
	/* Short enough to be encoded by the remaining XOR mask. */
	/* XOR the input with the IV and store input into IV. */
	for(ivp=c->iv+blocksize - c->unused; nbytes; nbytes--,c->unused--) {
	    temp = *inbuf++;
	    *outbuf++ = *ivp ^ temp;
	    *ivp++ = temp;
	}
	return;
    }

    if( c->unused ) {
	/* XOR the input with the IV and store input into IV. */
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

	do_encrypt (ctx, c, c->iv, c->iv);

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
	do_encrypt (ctx, c, c->iv, c->iv);
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
do_ctr_encrypt( gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c, byte *outbuf, const byte *inbuf,
                unsigned int nbytes )
{
  unsigned int n;
  byte tmp[MAX_BLOCKSIZE];
  int i;

  for(n=0; n < nbytes; n++)
    {
      if ((n % c->cipher->blocksize) == 0)
	{
	  do_encrypt (ctx, c, tmp, c->ctr);

	  for (i = c->cipher->blocksize; i > 0; i--)
	    {
	      c->ctr[i-1]++;
	      if (c->ctr[i-1] != 0)
		break;
	    }
	}

      /* XOR input with encrypted counter and store in output. */
      outbuf[n] = inbuf[n] ^ tmp[n % c->cipher->blocksize];
    }
}

static void
do_ctr_decrypt(gcry_core_context_t ctx,
	       gcry_core_cipher_hd_t c, byte *outbuf, const byte *inbuf,
                unsigned int nbytes )
{
  do_ctr_encrypt (ctx, c, outbuf, inbuf, nbytes);
}


/****************
 * Encrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some contraints apply to NBYTES.
 */
static gcry_err_code_t
cipher_encrypt (gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c, byte *outbuf,
		const byte *inbuf, unsigned int nbytes)
{
    gcry_err_code_t rc = GPG_ERR_NO_ERROR;

    switch( c->mode ) {
      case GCRY_CIPHER_MODE_ECB:
	if (!(nbytes%c->cipher->blocksize))
            do_ecb_encrypt(ctx, c, outbuf, inbuf, nbytes/c->cipher->blocksize );
        else 
            rc = GPG_ERR_INV_ARG;
	break;
      case GCRY_CIPHER_MODE_CBC:
	if (!(nbytes%c->cipher->blocksize)
            || (nbytes > c->cipher->blocksize
                && (c->flags & GCRY_CIPHER_CBC_CTS)))
            do_cbc_encrypt(ctx, c, outbuf, inbuf, nbytes );
        else 
            rc = GPG_ERR_INV_ARG;
	break;
      case GCRY_CIPHER_MODE_CFB:
	do_cfb_encrypt(ctx, c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_CTR:
	do_ctr_encrypt(ctx, c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_STREAM:
	assert (c->cipher->stencrypt || c->cb.cb);

	if (c->cipher->stencrypt)
	  (*c->cipher->stencrypt) (ctx, &c->context.c,
				   outbuf, (byte *) inbuf, nbytes); /* FIXME:
								       ugly
								       cast.  */
	else
	  {
	    gcry_core_cipher_cb_stencrypt_t cb_data;

	    cb_data.c = &c->context.c;
	    cb_data.outbuf = outbuf;
	    cb_data.inbuf = inbuf;
	    cb_data.n = nbytes;

	    (*c->cb.cb) (ctx, c->cb.opaque,
			 GCRY_CORE_CIPHER_CB_STENCRYPT, &cb_data);
	  }

        break;
      case GCRY_CIPHER_MODE_NONE:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
      default:
        log_fatal(ctx, "cipher_encrypt: invalid mode %d\n", c->mode );
        rc = GPG_ERR_INV_CIPHER_MODE;
        break;
    }
    return rc;
}


/****************
 * Encrypt IN and write it to OUT.  If IN is NULL, in-place encryption has
 * been requested.
 */
gcry_error_t
_gcry_core_cipher_encrypt (gcry_core_context_t ctx,
			   gcry_core_cipher_hd_t h, byte *out, size_t outsize,
			   const byte *in, size_t inlen)
{
  gcry_err_code_t err;

  if (!in)
    /* Caller requested in-place encryption. */
    /* Actullay cipher_encrypt() does not need to know about it, but
     * we may change this to get better performance. */
    err = cipher_encrypt (ctx, h, out, out, outsize);
  else if (outsize < ((h->flags & GCRY_CIPHER_CBC_MAC) ?
                      h->cipher->blocksize : inlen))
    err = GPG_ERR_TOO_SHORT;
  else if ((h->mode == GCRY_CIPHER_MODE_ECB
	    || (h->mode == GCRY_CIPHER_MODE_CBC
		&& (! ((h->flags & GCRY_CIPHER_CBC_CTS)
		       && (inlen > h->cipher->blocksize)))))
	   && (inlen % h->cipher->blocksize))
    err = GPG_ERR_INV_ARG;
  else
    err = cipher_encrypt (ctx, h, out, in, inlen);

  if (err && out)
    memset (out, 0x42, outsize); /* Failsafe: Make sure that the
                                    plaintext will never make it into
                                    OUT. */

  return gcry_core_error (err);
}



/****************
 * Decrypt INBUF to OUTBUF with the mode selected at open.
 * inbuf and outbuf may overlap or be the same.
 * Depending on the mode some some contraints apply to NBYTES.
 */
static gcry_err_code_t
cipher_decrypt (gcry_core_context_t ctx,
		gcry_core_cipher_hd_t c, byte *outbuf, const byte *inbuf,
		unsigned int nbytes)
{
    gcry_err_code_t rc = GPG_ERR_NO_ERROR;

    switch( c->mode ) {
      case GCRY_CIPHER_MODE_ECB:
	if (!(nbytes%c->cipher->blocksize))
            do_ecb_decrypt(ctx, c, outbuf, inbuf, nbytes/c->cipher->blocksize );
        else 
            rc = GPG_ERR_INV_ARG;
	break;
      case GCRY_CIPHER_MODE_CBC:
	if (!(nbytes%c->cipher->blocksize)
            || (nbytes > c->cipher->blocksize
                && (c->flags & GCRY_CIPHER_CBC_CTS)))
            do_cbc_decrypt(ctx, c, outbuf, inbuf, nbytes );
        else 
            rc = GPG_ERR_INV_ARG;
	break;
      case GCRY_CIPHER_MODE_CFB:
	do_cfb_decrypt(ctx, c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_CTR:
	do_ctr_decrypt(ctx, c, outbuf, inbuf, nbytes );
	break;
      case GCRY_CIPHER_MODE_STREAM:
	assert (c->cipher->stdecrypt || c->cb.cb);

	if (c->cipher->stdecrypt)
	  (*c->cipher->stdecrypt) (ctx, &c->context.c,
				   outbuf, (byte *) inbuf, nbytes); /* FIXME:
								       ugly
								       cast.  */
	else
	  {
	    gcry_core_cipher_cb_stdecrypt_t cb_data;

	    cb_data.c = &c->context.c;
	    cb_data.outbuf = outbuf;
	    cb_data.inbuf = inbuf;
	    cb_data.n = nbytes;

	    (*c->cb.cb) (ctx, c->cb.opaque,
			 GCRY_CORE_CIPHER_CB_STDECRYPT, &cb_data);
	  }
        break;
      case GCRY_CIPHER_MODE_NONE:
	if( inbuf != outbuf )
	    memmove( outbuf, inbuf, nbytes );
	break;
      default:
        log_fatal (ctx, "cipher_decrypt: invalid mode %d\n", c->mode );
        rc = GPG_ERR_INV_CIPHER_MODE;
        break;
    }
    return rc;
}


gcry_error_t
_gcry_core_cipher_decrypt (gcry_core_context_t ctx,
			   gcry_core_cipher_hd_t h, byte *out, size_t outsize,
			   const byte  *in, size_t inlen)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  if (! in)
    /* Caller requested in-place encryption. */
    /* Actullay cipher_encrypt() does not need to know about it, but
     * we may chnage this to get better performance. */
    err = cipher_decrypt (ctx, h, out, out, outsize);
  else if (outsize < inlen)
    err = GPG_ERR_TOO_SHORT;
  else if (((h->mode == GCRY_CIPHER_MODE_ECB)
	    || ((h->mode == GCRY_CIPHER_MODE_CBC)
		&& (! ((h->flags & GCRY_CIPHER_CBC_CTS)
		       && (inlen > h->cipher->blocksize)))))
	   && (inlen % h->cipher->blocksize) != 0)
    err = GPG_ERR_INV_ARG;
  else
    err = cipher_decrypt (ctx, h, out, in, inlen);

  return gcry_core_error (err);
}



/****************
 * Used for PGP's somewhat strange CFB mode. Only works if
 * the corresponding flag is set.
 */
static void
cipher_sync( gcry_core_context_t ctx, gcry_core_cipher_hd_t c )
{
    if( (c->flags & GCRY_CIPHER_ENABLE_SYNC) && c->unused ) {
	memmove(c->iv + c->unused, c->iv, c->cipher->blocksize - c->unused );
	memcpy(c->iv, c->lastiv + c->cipher->blocksize - c->unused, c->unused);
	c->unused = 0;
    }
}

gcry_error_t
_gcry_core_cipher_setkey (gcry_core_context_t ctx, gcry_core_cipher_hd_t handle,
			  const char *key, size_t length)
{
  return cipher_setkey (ctx, handle, key, length);
}

gcry_error_t
_gcry_core_cipher_setiv (gcry_core_context_t ctx, gcry_core_cipher_hd_t handle,
			 const char *iv, size_t length)
{
  cipher_setiv (ctx, handle, iv, length);
  return 0;
}

gcry_error_t
_gcry_core_cipher_reset (gcry_core_context_t ctx, gcry_core_cipher_hd_t handle)
{
  cipher_reset (ctx, handle);
  return 0;
}

gcry_error_t
_gcry_core_cipher_sync (gcry_core_context_t ctx, gcry_core_cipher_hd_t handle)
{
  cipher_sync (ctx, handle);
  return 0;
}

gcry_error_t
_gcry_core_cipher_cts (gcry_core_context_t ctx, gcry_core_cipher_hd_t handle,
		       unsigned int onoff)
{
  gcry_error_t err;

  if (onoff)
    {
      if (handle->flags & GCRY_CIPHER_CBC_MAC)
	err = GPG_ERR_INV_FLAG;
      else
	{
	  handle->flags |= GCRY_CIPHER_CBC_CTS;
	  err = 0;
	}
    }
  else
    {
      handle->flags &= ~GCRY_CIPHER_CBC_CTS;
      err = 0;
    }

  return err;
}

gcry_error_t
_gcry_core_cipher_setctr (gcry_core_context_t ctx, gcry_core_cipher_hd_t handle,
			  const char *k, size_t l)
{
  gcry_error_t err;
  
  if (k && l == handle->cipher->blocksize)
    {
      memcpy (handle->ctr, k, handle->cipher->blocksize);
      err  = 0;
    }
  else if (k == NULL || l == 0)
    {
      memset (handle->ctr, 0, handle->cipher->blocksize);
      err = 0;
    }
  else
    err = GPG_ERR_INV_ARG;

  return err;
}

gcry_error_t
_gcry_core_cipher_set_cbc_mac (gcry_core_context_t ctx, gcry_core_cipher_hd_t handle,
			       unsigned int onoff)
{
  gcry_error_t err;

  if (onoff)
    {
      if (handle->flags & GCRY_CIPHER_CBC_CTS)
	err = GPG_ERR_INV_FLAG;
      else
	{
	  handle->flags |= GCRY_CIPHER_CBC_MAC;
	  err = 0;
	}
    }
  else
    {
      handle->flags &= ~GCRY_CIPHER_CBC_MAC;
      err = 0;
    }

  return err;
}



struct gcry_core_subsystem_cipher _gcry_subsystem_cipher =
  {
    _gcry_core_cipher_open,
    _gcry_core_cipher_set_cb,
    _gcry_core_cipher_close,
    _gcry_core_cipher_setkey,
    _gcry_core_cipher_setiv,
    _gcry_core_cipher_reset,
    _gcry_core_cipher_sync,
    _gcry_core_cipher_cts,
    _gcry_core_cipher_setctr,
    _gcry_core_cipher_set_cbc_mac,
    _gcry_core_cipher_encrypt,
    _gcry_core_cipher_decrypt
  };

gcry_core_subsystem_cipher_t gcry_core_subsystem_cipher = &_gcry_subsystem_cipher;
