/* memory.c - Memory management functions.
   Copyright (C) 2005 g10 Code GmbH

   This file is part of Libgcrypt.
 
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
 
   Libgcrypt is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU Lesser General Public
   License along with Libgcrypt; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <gcrypt-common-internal.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define MAGIC_NOR_BYTE 0x55
#define MAGIC_SEC_BYTE 0xcc
#define MAGIC_END_BYTE 0xaa

#if SIZEOF_UNSIGNED_LONG == 8
#define EXTRA_ALIGN 4
#else
#define EXTRA_ALIGN 0
#endif

int
_gcry_core_is_secure (gcry_core_context_t ctx, const void *p)
{
  assert (ctx->subsystems.secmem->is_secure);
  return (*ctx->subsystems.secmem->is_secure) (ctx, p);
}

void *
_gcry_core_malloc (gcry_core_context_t ctx, size_t n, int secure)
{
  size_t size;
  void *ret;
  char *p;

  if (ctx->flags & GCRY_CORE_FLAG_ENABLE_MEMORY_GUARD)
    size = n + EXTRA_ALIGN + 5;
  else
    size = n;

  if (secure && (! (ctx->flags & GCRY_CORE_FLAG_DISABLE_SECURE_MEMORY)))
    {
      assert (ctx->subsystems.secmem->malloc);
      p = (*ctx->subsystems.secmem->malloc) (ctx, size);
    }
  else
    {
      assert (ctx->handler.mem.alloc);
      p = (*ctx->handler.mem.alloc) (size);
    }

  if (p)
    {
      if (ctx->flags & GCRY_CORE_FLAG_ENABLE_MEMORY_GUARD)
	{
	  ((byte*)p)[EXTRA_ALIGN+0] = n;
	  ((byte*)p)[EXTRA_ALIGN+1] = n >> 8 ;
	  ((byte*)p)[EXTRA_ALIGN+2] = n >> 16 ;
	  ((byte*)p)[EXTRA_ALIGN+3] = MAGIC_NOR_BYTE;
	  p[4+EXTRA_ALIGN+n] = MAGIC_END_BYTE;
	  ret = p + EXTRA_ALIGN + 4;
	}
      else
	ret = p;
    }
  else
    ret = NULL;

  return ret;
}

void *
_gcry_core_calloc (gcry_core_context_t ctx, size_t n, size_t m, int secure)
{
  size_t bytes;
  void *p;

  bytes = n * m;
  if (m && (bytes / m != n))
    {
      errno = ENOMEM;
      return NULL;
    }

  p = _gcry_core_malloc (ctx, bytes, secure);
  if (p)
    memset (p, 0, bytes);

  return p;
}

void
_gcry_core_check_heap (gcry_core_context_t ctx, const void *a)
{
    if(ctx->flags & GCRY_CORE_FLAG_ENABLE_MEMORY_GUARD)
      {
	const byte *p = a;
	size_t len;

	if( !p )
	    return;

	if( !(p[-1] == MAGIC_NOR_BYTE || p[-1] == MAGIC_SEC_BYTE) )
	    _gcry_core_log_fatal(ctx, "memory at %p corrupted (underflow=%02x)\n", p, p[-1] );
	len  = p[-4];
	len |= p[-3] << 8;
	len |= p[-2] << 16;
	if( p[len] != MAGIC_END_BYTE )
	    _gcry_core_log_fatal(ctx, "memory at %p corrupted (overflow=%02x)\n", p, p[-1] );
      }
}

void
_gcry_core_free (gcry_core_context_t ctx, void *p)
{
  void *p_real;

  if (! p)
    return;

  if (ctx->flags & GCRY_CORE_FLAG_ENABLE_MEMORY_GUARD)
    {
      _gcry_core_check_heap (ctx, p);
      p_real = ((unsigned char *) p) - EXTRA_ALIGN - 4;
    }
  else
    p_real = p;

  if (_gcry_core_is_secure (ctx, p))
    {
      assert (ctx->subsystems.secmem->free);
      (*ctx->subsystems.secmem->free) (ctx, p_real);
    }
  else
    {
      assert (ctx->handler.mem.free);
      (*ctx->handler.mem.free) (p_real);
    }
}

void *
_gcry_core_realloc (gcry_core_context_t ctx, void *a, size_t n)
{
  void *ret;

  if (ctx->flags & GCRY_CORE_FLAG_ENABLE_MEMORY_GUARD)
    {
      unsigned char *p = a;
      int is_secure;
      size_t len;
      char *b;

      if (! a)
	return _gcry_core_malloc (ctx, n, 0);

	_gcry_core_check_heap (ctx, p);
	len  = p[-4];
	len |= p[-3] << 8;
	len |= p[-2] << 16;
	if( len >= n ) /* we don't shrink for now */
	    return a;

	is_secure = _gcry_core_is_secure (ctx, p);
	assert (is_secure == (p[-1] == MAGIC_SEC_BYTE));

	/* FIXME: this can be optimized (using a real realloc function
	   instead of simple malloc/free).  */
	b = _gcry_core_malloc (ctx, n, is_secure);
	if (!b)
	  return NULL;
	memcpy(b, a, len );
	memset(b+len, 0, n-len );
	_gcry_core_free (ctx, p);

	ret = b;
    }
  else
    {
      if (_gcry_core_is_secure (ctx, a))
	{
	  assert (ctx->subsystems.secmem->realloc);
	  ret = (*ctx->subsystems.secmem->realloc) (ctx, a, n);
	}
      else
	{
	  assert (ctx->handler.mem.realloc);
	  ret = (*ctx->handler.mem.realloc) (a, n);
	}
    }

  return ret;
}



void *
gcry_core_malloc (gcry_core_context_t ctx, size_t n)
{
  return _gcry_core_malloc (ctx, n, 0);
}

void *
gcry_core_xmalloc (gcry_core_context_t ctx, size_t n)
{
  void *p;

  while (!(p = _gcry_core_malloc(ctx, n, 0)))
    if ( (!ctx->handler.mem.no_mem)
	 || (! (*ctx->handler.mem.no_mem) (ctx->handler.mem.no_mem_opaque,
					   n, 0)))
      _gcry_core_fatal_error(ctx, gcry_core_err_code_from_errno (errno), NULL);

  return p;
}

void *
gcry_core_malloc_secure (gcry_core_context_t ctx, size_t n)
{
  return _gcry_core_malloc (ctx, n, 1);
}

void *
gcry_core_xmalloc_secure (gcry_core_context_t ctx, size_t n)
{
  void *p;

  while (!(p = _gcry_core_malloc(ctx, n, 1)))
    if ( (!ctx->handler.mem.no_mem)
	 || (! (*ctx->handler.mem.no_mem) (ctx->handler.mem.no_mem_opaque,
					   n, 0)))
      _gcry_core_fatal_error(ctx, gcry_core_err_code_from_errno (errno), NULL);

  return p;
}

void *
gcry_core_calloc (gcry_core_context_t ctx, size_t n, size_t m)
{
  return _gcry_core_calloc (ctx, n, m, 0);
}

void *
gcry_core_xcalloc (gcry_core_context_t ctx, size_t n, size_t m)
{
  void *p;

  while (!(p = _gcry_core_calloc(ctx, n, m, 0)))
    if ( (!ctx->handler.mem.no_mem)
	 || (! (*ctx->handler.mem.no_mem) (ctx->handler.mem.no_mem_opaque,
					   n, 0)))
      _gcry_core_fatal_error(ctx, gcry_core_err_code_from_errno (errno), NULL);

  return p;
}

void *
gcry_core_calloc_secure (gcry_core_context_t ctx, size_t n, size_t m)
{
  return _gcry_core_calloc (ctx, n, m, 1);
}

void *
gcry_core_xcalloc_secure (gcry_core_context_t ctx, size_t n, size_t m)
{
  void *p;

  while (!(p = _gcry_core_calloc(ctx, n, m, 1)))
    if ( (!ctx->handler.mem.no_mem)
	 || (! (*ctx->handler.mem.no_mem) (ctx->handler.mem.no_mem_opaque,
					   n, 0)))
      _gcry_core_fatal_error(ctx, gcry_core_err_code_from_errno (errno), NULL);

  return p;
}

void *
gcry_core_realloc (gcry_core_context_t ctx, void *p, size_t n)
{
  return _gcry_core_realloc (ctx, p, n);
}

void *
gcry_core_xrealloc (gcry_core_context_t ctx, void *a, size_t n)
{
  void *p;

  while (!(p = _gcry_core_realloc(ctx, a, n)))
    if ( (!ctx->handler.mem.no_mem)
	 || (! (*ctx->handler.mem.no_mem) (ctx->handler.mem.no_mem_opaque,
					   n, 0)))
      _gcry_core_fatal_error(ctx, gcry_core_err_code_from_errno (errno), NULL);

  return p;
}

void
gcry_core_free (gcry_core_context_t ctx, void *p)
{
  _gcry_core_free (ctx, p);
}

int
gcry_core_is_secure (gcry_core_context_t ctx, const void *p)
{
  return _gcry_core_is_secure (ctx, p);
}



char *
gcry_core_strdup (gcry_core_context_t ctx, const char *string)
{
  char *string_cp = NULL;
  size_t string_n = 0;

  string_n = strlen (string);

  if (gcry_core_is_secure (ctx, string))
    string_cp = gcry_core_malloc_secure (ctx, string_n + 1);
  else
    string_cp = gcry_core_malloc (ctx, string_n + 1);
  
  if (string_cp)
    strcpy (string_cp, string);

  return string_cp;
}

char *
gcry_core_xstrdup (gcry_core_context_t ctx, const char *string)
{
  char *p;

  while ( !(p = gcry_core_strdup (ctx, string)) ) 
    {
      int is_sec = !!gcry_core_is_secure (ctx, string);
      size_t n = strlen (string);

      if ( (!ctx->handler.mem.no_mem)
	   || (! (*ctx->handler.mem.no_mem) (ctx->handler.mem.no_mem_opaque,
					     n, 0)))
	_gcry_core_fatal_error (ctx,
			   gcry_core_err_code_from_errno (errno),
			   is_sec? _("out of core in secure memory"):NULL);
    }

  return p;
}

/* END. */
