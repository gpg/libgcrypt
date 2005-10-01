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

#include <gcrypt-md-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>



typedef struct gcry_md_list
{
  gcry_core_md_spec_t digest;
  struct gcry_md_list *next;
  size_t actual_struct_size;	/* Allocated size of this structure. */
  struct
  {
    gcry_core_md_cb_t cb;
    void *opaque;
  } cb;
  PROPERLY_ALIGNED_TYPE context;
} GcryDigestEntry;

/* this structure is put right after the gcry_core_md_hd_t buffer, so that
 * only one memory block is needed. */
struct gcry_md_context
{
  int magic;
  size_t actual_handle_size;	/* Allocated size of this handle. */
  int secure;
  FILE *debug;
  int finalized;
  GcryDigestEntry *list;
  byte *macpads;
};


#define CTX_MAGIC_NORMAL 0x11071961
#define CTX_MAGIC_SECURE 0x16917011

static gcry_err_code_t md_open (gcry_core_context_t ctx, gcry_core_md_hd_t * h,
				gcry_core_md_spec_t algo, int secure, int hmac);
static gcry_err_code_t md_enable (gcry_core_context_t ctx, gcry_core_md_hd_t hd,
				  gcry_core_md_spec_t algo);
static gcry_err_code_t md_copy (gcry_core_context_t ctx, gcry_core_md_hd_t a,
				gcry_core_md_hd_t * b);
static void md_close (gcry_core_context_t ctx, gcry_core_md_hd_t a);
static void md_write (gcry_core_context_t ctx, gcry_core_md_hd_t a,
		      byte * inbuf, size_t inlen);
static void md_final (gcry_core_context_t ctx, gcry_core_md_hd_t a);
static byte *md_read (gcry_core_context_t ctx, gcry_core_md_hd_t a, gcry_core_md_spec_t algo);
static gcry_core_md_spec_t md_get_algo (gcry_core_context_t ctx,
					gcry_core_md_hd_t a, unsigned int nth);
static void md_start_debug (gcry_core_context_t ctx, gcry_core_md_hd_t a,
			    const char *suffix);
static void md_stop_debug (gcry_core_context_t ctx, gcry_core_md_hd_t a);
gcry_error_t _gcry_core_md_hash_buffer (gcry_core_context_t ctx, gcry_core_md_spec_t algo,
					void *digest, const void *buffer, size_t length);

/****************
 * Open a message digest handle for use with algorithm ALGO.
 * More algorithms may be added by md_enable(). The initial algorithm
 * may be 0.
 */
static gcry_err_code_t
md_open (gcry_core_context_t ctx, gcry_core_md_hd_t * h,
	 gcry_core_md_spec_t algo, int secure, int hmac)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  int bufsize = secure ? 512 : 1024;
  gcry_core_md_hd_t hd;
  size_t n;

  /* Allocate a memory area to hold the caller visible buffer with it's
   * control information and the data required by this module. Set the
   * context pointer at the beginning to this area.
   * We have to use this strange scheme because we want to hide the
   * internal data but have a variable sized buffer.
   *
   *    +---+------+---........------+-------------+
   *    !ctx! bctl !  buffer         ! private     !
   *    +---+------+---........------+-------------+
   *      !                           ^
   *      !---------------------------!
   *
   * We have to make sure that private is well aligned.
   */
  n = sizeof (struct gcry_md_handle) + bufsize;
  n = ((n + sizeof (PROPERLY_ALIGNED_TYPE) - 1)
       / sizeof (PROPERLY_ALIGNED_TYPE)) * sizeof (PROPERLY_ALIGNED_TYPE);

  /* Allocate and set the Context pointer to the private data */
  if (secure)
    hd = gcry_core_malloc_secure (ctx, n + sizeof (struct gcry_md_context));
  else
    hd = gcry_core_malloc (ctx, n + sizeof (struct gcry_md_context));

  if (!hd)
    err = gpg_err_code_from_errno (errno);

  if (!err)
    {
      hd->ctx = (struct gcry_md_context *) ((char *) hd + n);
      /* Setup the globally visible data (bctl in the diagram). */
      hd->bufsize = n - sizeof (struct gcry_md_handle) + 1;
      hd->bufpos = 0;

      /* Initialize the private data. */
      memset (hd->ctx, 0, sizeof *hd->ctx);
      hd->ctx->magic = secure ? CTX_MAGIC_SECURE : CTX_MAGIC_NORMAL;
      hd->ctx->actual_handle_size = n + sizeof (struct gcry_md_context);
      hd->ctx->secure = secure;

      if (hmac)
	{
	  hd->ctx->macpads = gcry_core_malloc_secure (ctx, 128);
	  if (!hd->ctx->macpads)
	    {
	      md_close (ctx, hd);
	      err = gpg_err_code_from_errno (errno);
	    }
	}
    }

  if (!err)
    {
      /* FIXME: should we really do that? - yes [-wk] */
      if (! (ctx->flags & GCRY_CORE_FLAG_DISABLE_AUTO_PRNG_POOL_FILLING))
	gcry_core_random_fast_poll (ctx);

      if (algo)
	{
	  err = md_enable (ctx, hd, algo);
	  if (err)
	    md_close (ctx, hd);
	}
    }

  if (!err)
    *h = hd;

  return err;
}

/* Create a message digest object for algorithm ALGO.  FLAGS may be
   given as an bitwise OR of the gcry_md_flags values.  ALGO may be
   given as 0 if the algorithms to be used are later set using
   gcry_md_enable. H is guaranteed to be a valid handle or NULL on
   error.  */
gcry_error_t
_gcry_core_md_open (gcry_core_context_t ctx, gcry_core_md_hd_t * h,
		    gcry_core_md_spec_t algo, unsigned int flags)
{
  gcry_err_code_t err;
  gcry_core_md_hd_t hd;

  if ((flags & ~(GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC)))
    err = GPG_ERR_INV_ARG;
  else
    err = md_open (ctx, &hd, algo,
		   (flags & GCRY_MD_FLAG_SECURE),
		   (flags & GCRY_MD_FLAG_HMAC));

  *h = err ? NULL : hd;

  return gcry_core_error (err);
}

void
_gcry_core_md_set_cb (gcry_core_context_t ctx,
		      gcry_core_md_hd_t handle,
		      gcry_core_md_spec_t algo,
		      gcry_core_md_cb_t cb,
		      void *opaque)
{
  GcryDigestEntry *entry;

  for (entry = handle->ctx->list; entry; entry = entry->next)
    if (entry->digest == algo)
      break;

  if (entry)
    {
      entry->cb.cb = cb;
      entry->cb.opaque = opaque;
    }
}

static gcry_err_code_t
md_enable (gcry_core_context_t ctx, gcry_core_md_hd_t hd, gcry_core_md_spec_t digest)
{
  struct gcry_md_context *h = hd->ctx;
  GcryDigestEntry *entry;
  gcry_err_code_t err = 0;
  size_t size;

  for (entry = h->list; entry; entry = entry->next)
    if (entry->digest == digest)
      return err;		/* already enabled */

  size = (sizeof (*entry) + digest->contextsize - sizeof (entry->context));
  /* And allocate a new list entry. */
  if (h->secure)
    entry = gcry_core_malloc_secure (ctx, size);
  else
    entry = gcry_core_malloc (ctx, size);
  if (!entry)
    err = gpg_err_code_from_errno (errno);
  else
    {
      entry->digest = digest;
      entry->next = h->list;
      entry->actual_struct_size = size;
      h->list = entry;

      assert (entry->digest->init || entry->cb.cb);

      /* And init this instance. */

      if (entry->digest->init)
	(*entry->digest->init) (ctx, &entry->context.c);
      else
	{
	  gcry_core_md_cb_init_t cb_data;

	  cb_data.c = &entry->context.c;
	  (*entry->cb.cb) (ctx, entry->cb.opaque,
			   GCRY_CORE_MD_CB_INIT, &cb_data);
	}
    }

  return err;
}


gcry_error_t
_gcry_core_md_enable (gcry_core_context_t ctx, gcry_core_md_hd_t hd,
		      gcry_core_md_spec_t algorithm)
{
  gcry_err_code_t err = md_enable (ctx, hd, algorithm);
  return gcry_core_error (err);
}

static gcry_err_code_t
md_copy (gcry_core_context_t ctx, gcry_core_md_hd_t ahd, gcry_core_md_hd_t * b_hd)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  struct gcry_md_context *a = ahd->ctx;
  struct gcry_md_context *b;
  GcryDigestEntry *ar, *br;
  gcry_core_md_hd_t bhd;
  size_t n;

  if (ahd->bufpos)
    md_write (ctx, ahd, NULL, 0);

  n = (char *) ahd->ctx - (char *) ahd;
  if (a->secure)
    bhd = gcry_core_malloc_secure (ctx, n + sizeof (struct gcry_md_context));
  else
    bhd = gcry_core_malloc (ctx, n + sizeof (struct gcry_md_context));

  if (!bhd)
    err = gpg_err_code_from_errno (errno);

  if (!err)
    {
      bhd->ctx = b = (struct gcry_md_context *) ((char *) bhd + n);
      /* No need to copy the buffer due to the write above. */
      assert (ahd->bufsize == (n - sizeof (struct gcry_md_handle) + 1));
      bhd->bufsize = ahd->bufsize;
      bhd->bufpos = 0;
      assert (!ahd->bufpos);
      memcpy (b, a, sizeof *a);
      b->list = NULL;
      b->debug = NULL;
      if (a->macpads)
	{
	  b->macpads = gcry_core_malloc_secure (ctx, 128);
	  if (!b->macpads)
	    {
	      md_close (ctx, bhd);
	      err = gpg_err_code_from_errno (errno);
	    }
	  else
	    memcpy (b->macpads, a->macpads, 128);
	}
    }

  /* Copy the complete list of algorithms.  The copied list is
     reversed, but that doesn't matter. */
  if (!err)
    for (ar = a->list; ar; ar = ar->next)
      {
	if (a->secure)
	  br = gcry_core_xmalloc_secure (ctx,
					 (sizeof *br
					  + ar->digest->contextsize
					  - sizeof (ar->context)));
	else
	  br = gcry_core_xmalloc (ctx,
				  (sizeof *br
				   + ar->digest->contextsize
				   - sizeof (ar->context)));
	memcpy (br, ar,
		sizeof (*br) + ar->digest->contextsize -
		sizeof (ar->context));
	br->next = b->list;
	b->list = br;
      }

  if (a->debug)
    md_start_debug (ctx, bhd, "unknown");

  if (!err)
    *b_hd = bhd;

  return err;
}

gcry_error_t
_gcry_core_md_copy (gcry_core_context_t ctx, gcry_core_md_hd_t * handle,
		    gcry_core_md_hd_t hd)
{
  gcry_err_code_t err = md_copy (ctx, hd, handle);
  if (err)
    *handle = NULL;
  return gcry_core_error (err);
}

/*
 * Reset all contexts and discard any buffered stuff.  This may be used
 * instead of a md_close(); md_open().
 */
void
_gcry_core_md_reset (gcry_core_context_t ctx, gcry_core_md_hd_t a)
{
  GcryDigestEntry *r;

  a->bufpos = a->ctx->finalized = 0;

  for (r = a->ctx->list; r; r = r->next)
    {
      memset (r->context.c, 0, r->digest->contextsize);

      assert (r->digest->init || r->cb.cb);
      if (r->digest->init)
	(*r->digest->init) (ctx, &r->context.c);
      else
	{
	  gcry_core_md_cb_init_t cb_data;

	  cb_data.c = &r->context.c;
	  (*r->cb.cb) (ctx, r->cb.opaque,
		       GCRY_CORE_MD_CB_INIT, &cb_data);
	}
    }
  if (a->ctx->macpads)
    md_write (ctx, a, a->ctx->macpads, 64);	/* inner pad */
}

static void
md_close (gcry_core_context_t ctx, gcry_core_md_hd_t a)
{
  GcryDigestEntry *r, *r2;

  if (!a)
    return;
  if (a->ctx->debug)
    md_stop_debug (ctx, a);
  for (r = a->ctx->list; r; r = r2)
    {
      r2 = r->next;
      wipememory (r, r->actual_struct_size);
      gcry_core_free (ctx, r);
    }

  if (a->ctx->macpads)
    {
      wipememory (a->ctx->macpads, 128);
      gcry_core_free (ctx, a->ctx->macpads);
    }

  wipememory (a, a->ctx->actual_handle_size);
  gcry_core_free (ctx, a);
}

void
_gcry_core_md_close (gcry_core_context_t ctx, gcry_core_md_hd_t hd)
{
  md_close (ctx, hd);
}

static void
md_write (gcry_core_context_t ctx, gcry_core_md_hd_t a, byte * inbuf, size_t inlen)
{
  GcryDigestEntry *r;

  if (a->ctx->debug)
    {
      if (a->bufpos && fwrite (a->buf, a->bufpos, 1, a->ctx->debug) != 1)
	BUG (ctx);
      if (inlen && fwrite (inbuf, inlen, 1, a->ctx->debug) != 1)
	BUG (ctx);
    }

  for (r = a->ctx->list; r; r = r->next)
    {
      gcry_core_md_cb_write_t cb_data;

      assert (r->digest->write || r->cb.cb);

      if (a->bufpos)
	{
	  if (r->digest->write)
	    (*r->digest->write) (ctx, &r->context.c, a->buf, a->bufpos);
	  else
	    {
	      cb_data.c = &r->context.c;
	      cb_data.buf = a->buf;
	      cb_data.nbytes = a->bufpos;
	      (*r->cb.cb) (ctx, r->cb.opaque,
			   GCRY_CORE_MD_CB_WRITE, &cb_data);
	    }
	}

      if (r->digest->write)
	(*r->digest->write) (ctx, &r->context.c, inbuf, inlen);
      else
	{
	  cb_data.c = &r->context.c;
	  cb_data.buf = inbuf;
	  cb_data.nbytes = inlen;
	  (*r->cb.cb) (ctx, r->cb.opaque,
		       GCRY_CORE_MD_CB_WRITE, &cb_data);
	}
    }
  a->bufpos = 0;
}

gcry_error_t
_gcry_core_md_write (gcry_core_context_t ctx,
		     gcry_core_md_hd_t hd, const void *inbuf, size_t inlen)
{
  md_write (ctx, hd, (unsigned char *) inbuf, inlen);
  /* FIXME: err codes.  */
  return 0;
}

static void
md_final (gcry_core_context_t ctx, gcry_core_md_hd_t a)
{
  GcryDigestEntry *r;

  if (a->ctx->finalized)
    return;

  if (a->bufpos)
    md_write (ctx, a, NULL, 0);

  for (r = a->ctx->list; r; r = r->next)
    {
      assert (r->digest->final || r->cb.cb);

      if (r->digest->final)
	(*r->digest->final) (ctx, &r->context.c);
      else
	{
	  gcry_core_md_cb_final_t cb_data;

	  cb_data.c = &r->context.c;
	  (*r->cb.cb) (ctx, r->cb.opaque,
		       GCRY_CORE_MD_CB_FINAL, &cb_data);
	}
    }

  a->ctx->finalized = 1;

  if (a->ctx->macpads)
    {
      /* Finish the hmac. */

      gcry_core_md_spec_t algo = md_get_algo (ctx, a, 0);
      byte *p = md_read (ctx, a, algo);
      size_t dlen = algo->mdlen;
      gcry_core_md_hd_t om;
      gcry_err_code_t err = md_open (ctx, &om, algo, a->ctx->secure, 0);

      if (err)
	BUG (ctx); // FIXME, moritz? _gcry_core_fatal_error (err, NULL);
      md_write (ctx, om, a->ctx->macpads + 64, 64);
      md_write (ctx, om, p, dlen);
      md_final (ctx, om);
      /* Replace our digest with the mac (they have the same size). */
      memcpy (p, md_read (ctx, om, algo), dlen);
      md_close (ctx, om);
    }
}

static gcry_err_code_t
prepare_macpads (gcry_core_context_t ctx, gcry_core_md_hd_t hd, const byte * key,
		 size_t keylen)
{
  int i;
  gcry_core_md_spec_t algo = md_get_algo (ctx, hd, 0);
  byte *helpkey = NULL;
  byte *ipad, *opad;

  if (!algo)
    return GPG_ERR_DIGEST_ALGO;	/* i.e. no algo enabled */

  if (keylen > 64)
    {
      helpkey = gcry_core_malloc_secure (ctx, algo->mdlen);
      if (!helpkey)
	return gpg_err_code_from_errno (errno);
      _gcry_core_md_hash_buffer (ctx, algo, helpkey, key, keylen);
      key = helpkey;
      keylen = algo->mdlen;
      assert (keylen <= 64);
    }

  memset (hd->ctx->macpads, 0, 128);
  ipad = hd->ctx->macpads;
  opad = hd->ctx->macpads + 64;
  memcpy (ipad, key, keylen);
  memcpy (opad, key, keylen);
  for (i = 0; i < 64; i++)
    {
      ipad[i] ^= 0x36;
      opad[i] ^= 0x5c;
    }
  gcry_core_free (ctx, helpkey);

  return GPG_ERR_NO_ERROR;
}

gcry_error_t
_gcry_core_md_final (gcry_core_context_t ctx, gcry_core_md_hd_t handle)
{
  /* FIXME, moritz?  */
  md_final (ctx, handle);
  return 0;
}

void
_gcry_core_md_debug_start (gcry_core_context_t ctx, gcry_core_md_hd_t handle,
			   const char *suffix)
{
  md_start_debug (ctx, handle, suffix);
}

void
_gcry_core_md_debug_stop (gcry_core_context_t ctx, gcry_core_md_hd_t handle)
{
  md_stop_debug (ctx, handle);
}

gcry_error_t
_gcry_core_md_setkey (gcry_core_context_t ctx,
		      gcry_core_md_hd_t hd, const void *key, size_t keylen)
{
  gcry_err_code_t rc = GPG_ERR_NO_ERROR;

  if (!hd->ctx->macpads)
    rc = GPG_ERR_CONFLICT;
  else
    {
      rc = prepare_macpads (ctx, hd, key, keylen);
      if (!rc)
	_gcry_core_md_reset (ctx, hd);
    }

  return gcry_core_error (rc);
}


/****************
 * if ALGO is null get the digest for the used algo (which should be only one)
 */
static byte *
md_read (gcry_core_context_t ctx, gcry_core_md_hd_t a, gcry_core_md_spec_t algo)
{
  GcryDigestEntry *r = a->ctx->list;

  if (!algo)
    {
      /* return the first algorithm */
      if (r && r->next)
	log_debug (ctx, "more than algorithm in md_read(0)\n");

      assert (r->digest->read || r->cb.cb);

      if (r->digest->read)
	return (*r->digest->read) (ctx, &r->context.c);
      else
	{
	  gcry_core_md_cb_read_t cb_data;
	  gcry_error_t err;

	  cb_data.c = &r->context.c;
	  cb_data.result = NULL;

	  err = (*r->cb.cb) (ctx, r->cb.opaque,
			     GCRY_CORE_MD_CB_READ, &cb_data);
	  return err ? NULL : *cb_data.result;
	}
    }
  else
    {
      gcry_core_md_cb_read_t cb_data;
      gcry_error_t err;

      for (r = a->ctx->list; r; r = r->next)
	if (r->digest == algo)
	  {
	    assert (r->digest->read || r->cb.cb);

	    if (r->digest->read)
	      return (*r->digest->read) (ctx, &r->context.c);
	    else
	      {
		cb_data.c = &r->context.c;
		cb_data.result = NULL;

		err = (*r->cb.cb) (ctx, r->cb.opaque,
				   GCRY_CORE_MD_CB_READ, &cb_data);
		return err ? NULL : *cb_data.result;
	      }
	  }
    }

  BUG (ctx);
  /* NOTREACHED */
  return NULL;
}

/*
 * Read out the complete digest, this function implictly finalizes
 * the hash.
 */
byte *
_gcry_core_md_read (gcry_core_context_t ctx, gcry_core_md_hd_t hd,
		    gcry_core_md_spec_t algo)
{
  _gcry_core_md_final (ctx, hd);
  return md_read (ctx, hd, algo);
}

/*
 * Shortcut function to hash a buffer with a given algo. The only
 * guaranteed supported algorithms are RIPE-MD160 and SHA-1. The
 * supplied digest buffer must be large enough to store the resulting
 * hash.  No error is returned, the function will abort on an invalid
 * algo.  DISABLED_ALGOS are ignored here.  */
gcry_error_t
_gcry_core_md_hash_buffer (gcry_core_context_t ctx, gcry_core_md_spec_t algo,
			   void *digest, const void *buffer, size_t length)
{
  gcry_error_t err;

  if (algo->hash)
    /* Use short-cut function. */
    err = (*algo->hash) (ctx, digest, buffer, length);
  else
    {
      /* Use generic implementation.  */

      gcry_core_md_hd_t handle;

      err = md_open (ctx, &handle, algo, 0, 0);
      if (err)
	goto out;
      md_write (ctx, handle, (byte *) buffer, length);
      md_final (ctx, handle);
      memcpy (digest, md_read (ctx, handle, algo), algo->mdlen);
      md_close (ctx, handle);
    }

 out:

  return err;
}

static gcry_core_md_spec_t
md_get_algo (gcry_core_context_t ctx, gcry_core_md_hd_t a, unsigned int nth)
{
  GcryDigestEntry *r = a->ctx->list;

  while (nth && r)
    {
      r = r->next;
      nth--;
    }

  return r ? r->digest : NULL;
}

gcry_core_md_spec_t
_gcry_core_md_get_algo (gcry_core_context_t ctx,
			gcry_core_md_hd_t hd, unsigned int nth)
{
  return md_get_algo (ctx, hd, nth);
}

static void
md_start_debug (gcry_core_context_t ctx, gcry_core_md_hd_t md, const char *suffix)
{
  static int idx = 0;
  char buf[50];

  if (md->ctx->debug)
    {
      log_debug (ctx, "Oops: md debug already started\n");
      return;
    }
  idx++;
  sprintf (buf, "dbgmd-%05d.%.10s", idx, suffix);
  md->ctx->debug = fopen (buf, "w");
  if (!md->ctx->debug)
    log_debug (ctx, "md debug: can't open %s\n", buf);
}

static void
md_stop_debug (gcry_core_context_t ctx, gcry_core_md_hd_t md)
{
  if (md->ctx->debug)
    {
      if (md->bufpos)
	md_write (ctx, md, NULL, 0);
      fclose (md->ctx->debug);
      md->ctx->debug = NULL;
    }
#ifdef HAVE_U64_TYPEDEF
  /* FIXME, necessary, why/  */
  {				/* a kludge to pull in the __muldi3 for Solaris */
    volatile u32 a = (u32) (ulong) md;
    volatile u64 b = 42;
    volatile u64 c;
    c = a * b;
  }
#endif
}

int
_gcry_core_md_is_secure (gcry_core_context_t ctx, gcry_core_md_hd_t a)
{
  return a->ctx->secure;
}


int
_gcry_core_md_is_enabled (gcry_core_context_t ctx, gcry_core_md_hd_t h,
			  gcry_core_md_spec_t algo)
{
  GcryDigestEntry *r;

  for (r = h->ctx->list; r; r = r->next)
    if (r->digest == algo)
      return 1;

  return 0;
}

static struct gcry_core_subsystem_md gcry_core_subsystem_md_struct =
  {
    _gcry_core_md_open,
    _gcry_core_md_set_cb,
    _gcry_core_md_close,
    _gcry_core_md_enable,
    _gcry_core_md_copy,
    _gcry_core_md_reset,
    _gcry_core_md_write,
    _gcry_core_md_read,
    _gcry_core_md_hash_buffer,
    _gcry_core_md_get_algo,
    _gcry_core_md_is_enabled,
    _gcry_core_md_is_secure,
    _gcry_core_md_setkey,
    _gcry_core_md_final,
    _gcry_core_md_debug_start,
    _gcry_core_md_debug_stop
  };

gcry_core_subsystem_md_t gcry_core_subsystem_md = &gcry_core_subsystem_md_struct;

/* EOF */
