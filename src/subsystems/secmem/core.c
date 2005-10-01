/* secmem/core.c - Memory allocation backed by a `secure' heap.
   Copyright (C) 1998, 1999, 2000, 2001, 2002,
                 2003, 2005 Free Software Foundation, Inc.

   This file is part of Libgcrypt.

   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   Libgcrypt is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <gcrypt-secmem-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <stddef.h>

#if defined(HAVE_MLOCK) || defined(HAVE_MMAP)
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#ifdef USE_CAPABILITIES
#include <sys/capability.h>
#endif
#endif

#include <gcrypt-ath-internal.h>



/* General definitions.  */

#if defined (MAP_ANON) && ! defined (MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif

#define DEFAULT_POOL_SIZE 16384
#define DEFAULT_PAGE_SIZE 4096

/* Convenient macros.  */
#define SECMEM_LOCK(ctx, secmem)   \
  _gcry_core_ath_mutex_lock   ((ctx), &(secmem)->lock)
#define SECMEM_UNLOCK(ctx, secmem) \
  _gcry_core_ath_mutex_unlock ((ctx), &(secmem)->lock)



/* The type used for a single `memory block'.  */
typedef struct memblock
{
  unsigned size;		/* Size of the memory available to the
				   user.  */
  int flags;			/* See below.  */
  PROPERLY_ALIGNED_TYPE aligned;
} memblock_t;

/* This flag specifies that the memory block is in use.  */
#define MB_FLAG_ACTIVE 1 << 0

/* The size of the memblock structure; this does not include the
   memory that is available to the user.  */
#define BLOCK_HEAD_SIZE \
  offsetof (memblock_t, aligned)

/* Convert an address into the according memory block structure.  */
#define ADDR_TO_BLOCK(addr) \
  (memblock_t *) ((char *) addr - BLOCK_HEAD_SIZE)

/* Check wether MB is a valid block.  */
#define BLOCK_VALID(secmem, mb) \
  (((char *) mb - (char *) secmem->pool) < secmem->pool_size)

/* This is the structure holding the internal state, which is stored
   in the library context.  */
typedef struct secmem_intern
{
  /* The pool of secure memory.  */
  void *pool;
  /* Size of POOL in bytes.  */
  size_t pool_size;
  /* True, if the memory pool is ready for use.  May be checked in
     an atexit function.  */
  volatile int pool_okay;
  /* True, if the memory pool is mmapped.  */
  volatile int pool_is_mmapped;
  int disable_secmem;
  int show_warning;
  int no_warning;
  int suspend_warning;
  /* Stats.  */
  unsigned int cur_alloced;
  unsigned int cur_blocks;
  /* Lock protecting accesses to the memory pool.  */
  gcry_core_ath_mutex_t lock;
} *secmem_intern_t;



static gcry_error_t
_gcry_secmem_prepare (gcry_core_context_t ctx, void **ptr)
{
  secmem_intern_t secmem;

  /* FIXME?  */
  secmem = gcry_core_xmalloc (ctx, sizeof (*secmem));
  memset (secmem, 0, sizeof (*secmem));
  _gcry_core_ath_mutex_init (ctx, &secmem->lock);

  *ptr = secmem;

  return 0;
}



/* Update the stats.  */
static void
stats_update (secmem_intern_t secmem, size_t add, size_t sub)
{
  if (add)
    {
      secmem->cur_alloced += add;
      secmem->cur_blocks++;
    }
  if (sub)
    {
      secmem->cur_alloced -= sub;
      secmem->cur_blocks--;
    }
}

/* Return the block following MB or NULL, if MB is the last block.  */
static memblock_t *
mb_get_next (secmem_intern_t secmem, memblock_t *mb)
{
  memblock_t *mb_next;

  mb_next = (memblock_t *) ((char *) mb + BLOCK_HEAD_SIZE + mb->size);
  
  if (! BLOCK_VALID (secmem,mb_next))
    mb_next = NULL;

  return mb_next;
}

/* Return the block preceeding MB or NULL, if MB is the first
   block.  */
static memblock_t *
mb_get_prev (secmem_intern_t secmem, memblock_t *mb)
{
  memblock_t *mb_prev, *mb_next;

  if (mb == secmem->pool)
    mb_prev = NULL;
  else
    {
      mb_prev = (memblock_t *) secmem->pool;
      while (1)
	{
	  mb_next = mb_get_next (secmem, mb_prev);
	  if (mb_next == mb)
	    break;
	  else
	    mb_prev = mb_next;
	}
    }

  return mb_prev;
}

/* If the preceeding block of MB and/or the following block of MB
   exist and are not active, merge them to form a bigger block.  */
static void
mb_merge (secmem_intern_t secmem, memblock_t *mb)
{
  memblock_t *mb_prev, *mb_next;

  mb_prev = mb_get_prev (secmem, mb);
  mb_next = mb_get_next (secmem, mb);

  if (mb_prev && (! (mb_prev->flags & MB_FLAG_ACTIVE)))
    {
      mb_prev->size += BLOCK_HEAD_SIZE + mb->size;
      mb = mb_prev;
    }
  if (mb_next && (! (mb_next->flags & MB_FLAG_ACTIVE)))
    mb->size += BLOCK_HEAD_SIZE + mb_next->size;
}

/* Return a new block, which can hold SIZE bytes.  */
static memblock_t *
mb_get_new (secmem_intern_t secmem, memblock_t *block, size_t size)
{
  memblock_t *mb, *mb_split;
  
  for (mb = block; BLOCK_VALID (secmem, mb); mb = mb_get_next (secmem, mb))
    if (! (mb->flags & MB_FLAG_ACTIVE) && mb->size >= size)
      {
	/* Found a free block.  */
	mb->flags |= MB_FLAG_ACTIVE;

	if (mb->size - size > BLOCK_HEAD_SIZE)
	  {
	    /* Split block.  */
	  
	    mb_split = (memblock_t *) (((char *) mb) + BLOCK_HEAD_SIZE + size);
	    mb_split->size = mb->size - size - BLOCK_HEAD_SIZE;
	    mb_split->flags = 0;

	    mb->size = size;

	    mb_merge (secmem, mb_split); /* FIXME? is this necessary? -moritz  */

	  }

	break;
      }

  if (! BLOCK_VALID (secmem, mb))
    mb = NULL;

  return mb;
}

/* Print a warning message.  */
static void
print_warn (gcry_core_context_t ctx, secmem_intern_t secmem)
{
  if (!secmem->no_warning)
    log_info (ctx, _("Warning: using insecure memory!\n"));
}

/* Lock the memory pages into core and drop privileges.  */
static void
lock_pool (gcry_core_context_t ctx, secmem_intern_t secmem, void *p, size_t n)
{
#if defined(USE_CAPABILITIES) && defined(HAVE_MLOCK)
  int err;

  cap_set_proc (cap_from_text ("cap_ipc_lock+ep"));
  err = mlock (p, n);
  if (err && errno)
    err = errno;
  cap_set_proc (cap_from_text ("cap_ipc_lock+p"));

  if (err)
    {
      if (errno != EPERM
#ifdef EAGAIN	/* OpenBSD returns this */
	  && errno != EAGAIN
#endif
#ifdef ENOSYS	/* Some SCOs return this (function not implemented) */
	  && errno != ENOSYS
#endif
#ifdef ENOMEM  /* Linux might return this. */
            && errno != ENOMEM
#endif
	  )
	log_error (ctx, "can't lock memory: %s\n", strerror (err));
      secmem->show_warning = 1;
    }

#elif defined(HAVE_MLOCK)
  uid_t uid;
  int err;

  uid = getuid ();

#ifdef HAVE_BROKEN_MLOCK
  /* Under HP/UX mlock segfaults if called by non-root.  Note, we have
     noch checked whether mlock does really work under AIX where we
     also detected a broken nlock.  Note further, that using plock ()
     is not a good idea under AIX. */ 
  if (uid)
    {
      errno = EPERM;
      err = errno;
    }
  else
    {
      err = mlock (p, n);
      if (err && errno)
	err = errno;
    }
#else /* !HAVE_BROKEN_MLOCK */
  err = mlock (p, n);
  if (err && errno)
    err = errno;
#endif /* !HAVE_BROKEN_MLOCK */

  if (uid && ! geteuid ())
    {
      /* check that we really dropped the privs.
       * Note: setuid(0) should always fail */
      if (setuid (uid) || getuid () != geteuid () || !setuid (0))
	log_fatal (ctx, "failed to reset uid: %s\n", strerror (errno));
    }

  if (err)
    {
      if (errno != EPERM
#ifdef EAGAIN	/* OpenBSD returns this. */
	  && errno != EAGAIN
#endif
#ifdef ENOSYS	/* Some SCOs return this (function not implemented). */
	  && errno != ENOSYS
#endif
#ifdef ENOMEM  /* Linux might return this. */
            && errno != ENOMEM
#endif
	  )
	log_error (ctx, "can't lock memory: %s\n", strerror (err));
      secmem->show_warning = 1;
    }

#elif defined ( __QNX__ )
  /* QNX does not page at all, so the whole secure memory stuff does
   * not make much sense.  However it is still of use because it
   * wipes out the memory on a free().
   * Therefore it is sufficient to suppress the warning
   */
#elif defined (HAVE_DOSISH_SYSTEM) || defined (__CYGWIN__)
    /* It does not make sense to print such a warning, given the fact that 
     * this whole Windows !@#$% and their user base are inherently insecure
     */
#elif defined (__riscos__)
    /* no virtual memory on RISC OS, so no pages are swapped to disc,
     * besides we don't have mmap, so we don't use it! ;-)
     * But don't complain, as explained above.
     */
#else
  log_info (ctx, "Please note that you don't have secure memory on this system\n");
#endif
}

/* Initialize POOL.  */
static void
init_pool (gcry_core_context_t ctx, secmem_intern_t secmem, size_t n)
{
  size_t pgsize;
  memblock_t *mb;

  secmem->pool_size = n;

  if (secmem->disable_secmem)
    log_bug (ctx, "secure memory is disabled");

#ifdef HAVE_GETPAGESIZE
  pgsize = getpagesize ();
#else
  pgsize = DEFAULT_PAGE_SIZE;
#endif

#if HAVE_MMAP
  secmem->pool_size = (secmem->pool_size + pgsize - 1) & ~(pgsize - 1);
#ifdef MAP_ANONYMOUS
  secmem->pool = mmap (0, secmem->pool_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else /* map /dev/zero instead */
  {
    int fd;

    fd = open ("/dev/zero", O_RDWR);
    if (fd == -1)
      {
	log_error (ctx, "can't open /dev/zero: %s\n", strerror (errno));
	secmem->pool = (void *) -1;
      }
    else
      {
	secmem->pool = mmap (0, pool_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
      }
  }
#endif
  if (secmem->pool == (void *) -1)
    log_info (ctx,
	      "can't mmap pool of %u bytes: %s - using malloc\n",
	      (unsigned) secmem->pool_size, strerror (errno));
  else
    {
      secmem->pool_is_mmapped = 1;
      secmem->pool_okay = 1;
    }

#endif
  if (!secmem->pool_okay)
    {
      secmem->pool = malloc (secmem->pool_size);
      if (!secmem->pool)
	log_fatal (ctx, "can't allocate memory pool of %u bytes\n",
		   (unsigned) secmem->pool_size);
      else
	secmem->pool_okay = 1;
    }

  /* Initialize first memory block.  */
  mb = (memblock_t *) secmem->pool;
  mb->size = secmem->pool_size;
  mb->flags = 0;
}

static void
_gcry_secmem_set_flags (gcry_core_context_t ctx, unsigned flags)
{
  secmem_intern_t secmem;
  int was_susp;

  secmem = ctx->secmem.intern;

  SECMEM_LOCK (ctx, secmem);

  was_susp = secmem->suspend_warning;
  secmem->no_warning = flags & GCRY_SECMEM_FLAG_NO_WARNING;
  secmem->suspend_warning = flags & GCRY_SECMEM_FLAG_SUSPEND_WARNING;

  /* and now issue the warning if it is not longer suspended */
  if (was_susp && !secmem->suspend_warning && secmem->show_warning)
    {
      secmem->show_warning = 0;
      print_warn (ctx, secmem);
    }

  SECMEM_UNLOCK (ctx, secmem);
}

static unsigned
_gcry_secmem_get_flags (gcry_core_context_t ctx)
{
  secmem_intern_t secmem;
  unsigned flags;

  secmem = ctx->secmem.intern;

  SECMEM_LOCK (ctx, secmem);

  flags = secmem->no_warning ? GCRY_SECMEM_FLAG_NO_WARNING : 0;
  flags |= secmem->suspend_warning ? GCRY_SECMEM_FLAG_SUSPEND_WARNING : 0;

  SECMEM_UNLOCK (ctx, secmem);

  return flags;
}

/* Initialize the secure memory system.  If running with the necessary
   privileges, the secure memory pool will be locked into the core in
   order to prevent page-outs of the data.  Furthermore allocated
   secure memory will be wiped out when released.  */
static void
_gcry_secmem_init (gcry_core_context_t ctx, size_t n)
{
  secmem_intern_t secmem;

  secmem = ctx->secmem.intern;

  SECMEM_LOCK (ctx, secmem);

  if (!n)
    {
#ifdef USE_CAPABILITIES
      /* drop all capabilities */
      cap_set_proc (cap_from_text ("all-eip"));

#elif !defined(HAVE_DOSISH_SYSTEM)
      uid_t uid;

      secmem->disable_secmem = 1;
      uid = getuid ();
      if (uid != geteuid ())
	{
	  if (setuid (uid) || getuid () != geteuid () || !setuid (0))
	    log_fatal (ctx, "failed to drop setuid\n");
	}
#endif
    }
  else
    {
      if (n < DEFAULT_POOL_SIZE)
	n = DEFAULT_POOL_SIZE;
      if (!secmem->pool_okay)
	{
	  init_pool (ctx, secmem, n);
	  lock_pool (ctx, secmem, secmem->pool, n);
	}
      else
	log_error (ctx, "Oops, secure memory pool already initialized\n");
    }

  SECMEM_UNLOCK (ctx, secmem);
}


static void *
_gcry_secmem_malloc_internal (gcry_core_context_t ctx, secmem_intern_t secmem, size_t size)
{
  memblock_t *mb;

  if (!secmem->pool_okay)
    {
      log_info (ctx,
		_("operation is not possible without initialized secure memory\n"));
      exit (2);
    }
  if (secmem->show_warning && !secmem->suspend_warning)
    {
      secmem->show_warning = 0;
      print_warn (ctx, secmem);
    }

  /* Blocks are always a multiple of 32. */
  size = ((size + 31) / 32) * 32;

  mb = mb_get_new (secmem, (memblock_t *) secmem->pool, size);
  if (mb)
    stats_update (secmem, size, 0);

  return mb ? &mb->aligned.c : NULL;
}

static void *
_gcry_secmem_malloc (gcry_core_context_t ctx, size_t size)
{
  secmem_intern_t secmem;
  void *p;

  secmem = ctx->secmem.intern;
  SECMEM_LOCK (ctx, secmem);
  p = _gcry_secmem_malloc_internal (ctx, secmem, size);
  SECMEM_UNLOCK (ctx, secmem);
  
  return p;
}

static void
_gcry_secmem_free_internal (gcry_core_context_t ctx, secmem_intern_t secmem, void *a)
{
  memblock_t *mb;
  int size;

  if (!a)
    return;

  mb = ADDR_TO_BLOCK (a);
  size = mb->size;

  /* This does not make much sense: probably this memory is held in the
   * cache. We do it anyway: */
#define MB_WIPE_OUT(byte) \
  memset ((memblock_t *) ((char *) mb + BLOCK_HEAD_SIZE), (byte), size);

  MB_WIPE_OUT (0xff);
  MB_WIPE_OUT (0xaa);
  MB_WIPE_OUT (0x55);
  MB_WIPE_OUT (0x00);

  stats_update (secmem, 0, size);

  mb->flags &= ~MB_FLAG_ACTIVE;

  /* Update stats.  */

  mb_merge (secmem, mb);
}

/* Wipe out and release memory.  */
static void
_gcry_secmem_free (gcry_core_context_t ctx, void *a)
{
  secmem_intern_t secmem;

  secmem = ctx->secmem.intern;
  SECMEM_LOCK (ctx, secmem);
  _gcry_secmem_free_internal (ctx, secmem, a);
  SECMEM_UNLOCK (ctx, secmem);
}

/* Realloc memory.  */
static void *
_gcry_secmem_realloc (gcry_core_context_t ctx, void *p, size_t newsize)
{
  secmem_intern_t secmem;
  memblock_t *mb;
  size_t size;
  void *a;

  secmem = ctx->secmem.intern;
  SECMEM_LOCK (ctx, secmem);

  mb = (memblock_t *) ((char *) p - ((size_t) &((memblock_t *) 0)->aligned.c));
  size = mb->size;
  if (newsize < size)
    {
      /* It is easier to not shrink the memory.  */
      a = p;
    }
  else
    {
      a = _gcry_secmem_malloc_internal (ctx, secmem, newsize);
      if (a)
	{
	  memcpy (a, p, size);
	  memset ((char *) a + size, 0, newsize - size); /* FIXME, necessary? -moritz  */
	  _gcry_secmem_free_internal (ctx, secmem, p);
	}
    }

  SECMEM_UNLOCK (ctx, secmem);

  return a;
}

static int
_gcry_private_is_secure (gcry_core_context_t ctx, const void *p)
{
  secmem_intern_t secmem;
  int ret = 0;

  secmem = ctx->secmem.intern;
  SECMEM_LOCK (ctx, secmem);

  if (secmem->pool_okay && BLOCK_VALID (secmem, ADDR_TO_BLOCK (p)))
    ret = 1;

  SECMEM_UNLOCK (ctx, secmem);

  return ret;
}


/****************
 * Warning:  This code might be called by an interrupt handler
 *	     and frankly, there should really be such a handler,
 *	     to make sure that the memory is wiped out.
 *	     We hope that the OS wipes out mlocked memory after
 *	     receiving a SIGKILL - it really should do so, otherwise
 *	     there is no chance to get the secure memory cleaned.
 */
static void
_gcry_secmem_term (gcry_core_context_t ctx)
{
  secmem_intern_t secmem;

  secmem = ctx->secmem.intern;

  if (!secmem->pool_okay)
    return;

  secmem = ctx->secmem.intern;

  wipememory2 (secmem->pool, 0xff, secmem->pool_size);
  wipememory2 (secmem->pool, 0xaa, secmem->pool_size);
  wipememory2 (secmem->pool, 0x55, secmem->pool_size);
  wipememory2 (secmem->pool, 0x00, secmem->pool_size);
#if HAVE_MMAP
  if (secmem->pool_is_mmapped)
    munmap (secmem->pool, secmem->pool_size);
#endif
  secmem->pool = NULL;
  secmem->pool_okay = 0;
  secmem->pool_size = 0;
}


static void
_gcry_secmem_dump_stats (gcry_core_context_t ctx)
{
#if 1
  secmem_intern_t secmem;

  secmem = ctx->secmem.intern;
  SECMEM_LOCK (ctx, secmem);

 if (secmem->pool_okay)
    log_info (ctx, "secmem usage: %u/%lu bytes in %u blocks\n",
	      secmem->cur_alloced, (unsigned long) secmem->pool_size,
	      secmem->cur_blocks);
  SECMEM_UNLOCK (ctx, secmem);
#else
  memblock_t *mb;
  int i;

  SECMEM_LOCK (ctx, secmem);

  for (i = 0, mb = (memblock_t *) pool;
       BLOCK_VALID (mb);
       mb = mb_get_next (mb), i++)
    log_info (ctx, "SECMEM: [%s] block: %i; size: %i\n",
	      (mb->flags & MB_FLAG_ACTIVE) ? "used" : "free",
	      i,
	      mb->size);
  SECMEM_UNLOCK (ctx, secmem);
#endif
}

static void
_gcry_secmem_finish (gcry_core_context_t ctx, void *ptr)
{
  if (ptr)
    {
      secmem_intern_t secmem = ptr;

      _gcry_core_ath_mutex_destroy (ctx, &secmem->lock);
      /* FIXME: Shall we overwrite secmem before releasing? */
      gcry_core_free (ctx, secmem);
    }
}

struct gcry_core_subsystem_secmem _gcry_subsystem_secmem =
  {
    _gcry_secmem_set_flags,
    _gcry_secmem_get_flags,
    _gcry_secmem_prepare,
    _gcry_secmem_finish,
    _gcry_secmem_init,
    _gcry_secmem_malloc,
    _gcry_secmem_free,
    _gcry_secmem_realloc,
    _gcry_private_is_secure,
    _gcry_secmem_term,
    _gcry_secmem_dump_stats
  };

gcry_core_subsystem_secmem_t gcry_core_subsystem_secmem = &_gcry_subsystem_secmem;
