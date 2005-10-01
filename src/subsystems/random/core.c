/* random.c  -	random number generator
 * Copyright (C) 1998, 2000, 2001, 2002, 2003,
 *               2004, 2005  Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
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

/****************
 * This random number generator is modelled after the one described in
 * Peter Gutmann's paper: "Software Generation of Practically Strong
 * Random Numbers". See also chapter 6 in his book "Cryptographic
 * Security Architecture", New York, 2004, ISBN 0-387-95387-6.
 */

#include <gcrypt-random-internal.h>
#include <gcrypt-ath-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#ifdef	HAVE_GETHRTIME
#include <sys/times.h>
#endif
#ifdef HAVE_GETTIMEOFDAY
#include <sys/times.h>
#endif
#ifdef HAVE_GETRUSAGE
#include <sys/resource.h>
#endif
#ifdef __MINGW32__
#include <process.h>
#endif

//#include "rmd.h"
//#include "random.h"
//#include "rand-internal.h"
//#include "cipher.h" /* only used for the rmd160_hash_buffer() prototype */

#include <rmd160.h>
#undef USE_SHA1
#include <sha1.h>

#ifndef RAND_MAX   /* for SunOS */
#define RAND_MAX 32767
#endif


#if SIZEOF_UNSIGNED_LONG == 8
#define ADD_VALUE 0xa5a5a5a5a5a5a5a5
#elif SIZEOF_UNSIGNED_LONG == 4
#define ADD_VALUE 0xa5a5a5a5
#else
#error weird size for an unsigned long
#endif

#define BLOCKLEN  64   /* hash this amount of bytes */
#define DIGESTLEN 20   /* into a digest of this length (rmd160) */
/* poolblocks is the number of digests which make up the pool
 * and poolsize must be a multiple of the digest length
 * to make the AND operations faster, the size should also be
 * a multiple of ulong
 */
#define POOLBLOCKS 30
#define POOLSIZE (POOLBLOCKS*DIGESTLEN)
#if (POOLSIZE % SIZEOF_UNSIGNED_LONG)
#error Please make sure that poolsize is a multiple of ulong
#endif
#define POOLWORDS (POOLSIZE / SIZEOF_UNSIGNED_LONG)

typedef struct random_intern
{
  int initialized;
  int is_initialized;
  char *rndpool;
  char *keypool;
  size_t pool_readpos;
  size_t pool_writepos;
  int pool_filled;
  int pool_balance;
  int just_mixed;
  int did_initial_extra_seeding;
  char *seed_file_name;
  int allow_seed_file_update;
  gcry_core_ath_mutex_t pool_lock;
  int pool_is_locked;
  gcry_core_ath_mutex_t nonce_buffer_lock;
  unsigned char failsafe_digest[DIGESTLEN];
  int failsafe_digest_valid;
  int fast_random_poll_initialized;
  unsigned char nonce_buffer[20+8];
  int nonce_buffer_initialized;
  gcry_core_random_source_gather_t fnc_gather;
  gcry_core_random_source_gather_fast_t fnc_gather_fast;
  int do_fast_random_poll_initialized;
  struct {
    ulong mixrnd;
    ulong mixkey;
    ulong slowpolls;
    ulong fastpolls;
    ulong getbytes1;
    ulong ngetbytes1;
    ulong getbytes2;
    ulong ngetbytes2;
    ulong addbytes;
    ulong naddbytes;
  } rndstats;
} *random_intern_t;

#define MASK_LEVEL(a) do { (a) &= 3; } while(0)

static byte *get_random_bytes(gcry_core_context_t ctx, random_intern_t randomctx,
			      size_t nbytes, int level, int secure );
static void read_pool(gcry_core_context_t ctx, random_intern_t randomctx,
		      byte *buffer, size_t length, int level );
static void add_randomness(gcry_core_context_t ctx,
			   const void *buffer, size_t length, int source );
static void random_poll(gcry_core_context_t ctx, random_intern_t randomctx);
static void do_fast_random_poll (gcry_core_context_t ctx, random_intern_t randomctx);
static void read_random_source(gcry_core_context_t ctx, random_intern_t randomctx,
			       int requester, size_t length, int level);



static gcry_error_t
random_init (gcry_core_context_t ctx, void **ptr)
{
  random_intern_t randomctx;

  /* FIXME?  */
  randomctx = gcry_core_xmalloc (ctx, sizeof (*randomctx));
  memset (randomctx, 0, sizeof (*randomctx));
  _gcry_core_ath_mutex_init (ctx, &randomctx->pool_lock);
  _gcry_core_ath_mutex_init (ctx, &randomctx->nonce_buffer_lock);

  *ptr = randomctx;

  return 0;
}

/* FIXME: init vs. prepare?  */
static gcry_error_t
_gcry_core_random_prepare (gcry_core_context_t ctx, void **ptr)
{
  return random_init (ctx, ptr);
}

static void
_gcry_core_random_finish (gcry_core_context_t ctx, void *ptr)
{
  /* FIXME, moritz: release random resources.  */
}





/* Note, we assume that this function is used before any concurrent
   access happens. */
static void
initialize_basics(gcry_core_context_t ctx, random_intern_t randomctx)
{
  int err;

  if (!randomctx->initialized)
    {
      randomctx->initialized = 1;
      err = _gcry_core_ath_mutex_init (ctx, &randomctx->pool_lock);
      if (err)
        log_fatal (ctx, "failed to create the pool lock: %s\n", strerror (err) );
      
      err = _gcry_core_ath_mutex_init (ctx, &randomctx->nonce_buffer_lock);
      if (err)
        log_fatal (ctx, "failed to create the nonce buffer lock: %s\n",
                   strerror (err) );
    }
}


static void
initialize(gcry_core_context_t ctx, random_intern_t randomctx)
{
  initialize_basics (ctx, randomctx);
  /* The data buffer is allocated somewhat larger, so that we can use
     this extra space (which is allocated in secure memory) as a
     temporary hash buffer */
  randomctx->rndpool = (ctx->flags & GCRY_CORE_FLAG_ENABLE_SECURE_RANDOM_ALLOCATION) ? gcry_core_xcalloc_secure(ctx,1,POOLSIZE+BLOCKLEN)
                         : gcry_core_xcalloc(ctx,1,POOLSIZE+BLOCKLEN);
  randomctx->keypool = (ctx->flags & GCRY_CORE_FLAG_ENABLE_SECURE_RANDOM_ALLOCATION) ? gcry_core_xcalloc_secure(ctx,1,POOLSIZE+BLOCKLEN)
                         : gcry_core_xcalloc(ctx,1,POOLSIZE+BLOCKLEN);
  randomctx->is_initialized = 1;
}


/* Initialize this random subsystem.  If FULL is false, this function
   merely calls the initialize and does not do anything more.  Doing
   this is not really required but when running in a threaded
   environment we might get a race condition otherwise. */
static void
_gcry_core_random_initialize (gcry_core_context_t ctx, int full)
{
  random_intern_t randomctx;

  randomctx = ctx->random.intern;
  if (!full)
    initialize_basics (ctx, randomctx);
  else if (!randomctx->is_initialized)
    initialize (ctx, randomctx);
}

static void
_gcry_core_random_dump_stats(gcry_core_context_t ctx)
{
  random_intern_t randomctx;

  randomctx = ctx->random.intern;

  log_info (ctx,
	    "random usage: poolsize=%d mixed=%lu polls=%lu/%lu added=%lu/%lu\n"
	    "              outmix=%lu getlvl1=%lu/%lu getlvl2=%lu/%lu\n",
	    POOLSIZE, randomctx->rndstats.mixrnd, randomctx->rndstats.slowpolls,
	    randomctx->rndstats.fastpolls, randomctx->rndstats.naddbytes,
	    randomctx->rndstats.addbytes, randomctx->rndstats.mixkey,
	    randomctx->rndstats.ngetbytes1, randomctx->rndstats.getbytes1,
	    randomctx->rndstats.ngetbytes2, randomctx->rndstats.getbytes2 );
}

/*
 * Return a pointer to a randomized buffer of LEVEL and NBYTES length.
 * Caller must free the buffer. 
 */
static byte *
get_random_bytes (gcry_core_context_t ctx, random_intern_t randomctx,
		  size_t nbytes, int level, int secure)
{
  byte *buf, *p;
  int err;

  /* First a hack toavoid the strong random using our regression test suite. */
  if ((ctx->flags & GCRY_CORE_FLAG_ENABLE_QUICK_RANDOM_GENERATION) && level > 1)
    level = 1;

  /* Make sure the requested level is in range. */
  MASK_LEVEL(level);

  /* Lock the pool. */
  err = _gcry_core_ath_mutex_lock (ctx, &randomctx->pool_lock);
  if (err)
    log_fatal (ctx, "failed to acquire the pool lock: %s\n", strerror (err));
  randomctx->pool_is_locked = 1;

  /* Keep some statistics. */
  if (level >= 2)
    {
      randomctx->rndstats.getbytes2 += nbytes;
      randomctx->rndstats.ngetbytes2++;
    }
  else
    {
      randomctx->rndstats.getbytes1 += nbytes;
      randomctx->rndstats.ngetbytes1++;
    }

  /* Allocate the return buffer. */
  buf = secure && (ctx->flags & GCRY_CORE_FLAG_ENABLE_SECURE_RANDOM_ALLOCATION) ? gcry_core_xmalloc_secure( ctx, nbytes )
                               : gcry_core_xmalloc( ctx, nbytes );

  /* Fill that buffer with random. */
  for (p = buf; nbytes > 0; )
    {
      size_t n;

      n = nbytes > POOLSIZE? POOLSIZE : nbytes;
      read_pool(ctx, randomctx, p, n, level );
      nbytes -= n;
      p += n;
    }

  /* Release the pool lock. */
  randomctx->pool_is_locked = 0;
  err = _gcry_core_ath_mutex_unlock (ctx, &randomctx->pool_lock);
  if (err)
    log_fatal (ctx, "failed to release the pool lock: %s\n", strerror (err));

  /* Return the buffer. */
  return buf;
}


/* Add BUFLEN bytes from BUF to the internal random pool.  QUALITY
   should be in the range of 0..100 to indicate the goodness of the
   entropy added, or -1 for goodness not known. 

   Note, that this function currently does nothing.
*/
static gcry_error_t
_gcry_core_random_add_bytes (gcry_core_context_t ctx,
			     const void * buf, size_t buflen, int quality)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;

  if (!buf || quality < -1 || quality > 100)
    err = GPG_ERR_INV_ARG;
  if (!buflen)
    return 0; /* Shortcut this dummy case. */
#if 0
  /* Before we actuall enable this code, we need to lock the pool,
     have a look at the quality and find a way to add them without
     disturbing the real entropy (we have estimated). */
  /*add_randomness( buf, buflen, 1 );*/
#endif
  return err;
}   
    
/* The public function to return random data of the quality LEVEL. */
static void *
_gcry_core_random_bytes(gcry_core_context_t ctx,
			size_t nbytes, enum gcry_random_level level )
{
  random_intern_t randomctx;

  randomctx = ctx->random.intern;
  if (!randomctx->is_initialized)
    initialize(ctx, randomctx);
  return get_random_bytes(ctx, randomctx, nbytes, level, 0 );
}

/* The public function to return random data of the quality LEVEL;
   this version of the function retrun the random a buffer allocated
   in secure memory. */
static void *
_gcry_core_random_bytes_secure(gcry_core_context_t ctx,
			       size_t nbytes, enum gcry_random_level level )
{
  random_intern_t randomctx;

  randomctx = ctx->random.intern;
  if (!randomctx->is_initialized)
    initialize(ctx, randomctx);
  return get_random_bytes(ctx, randomctx, nbytes, level, 1 );
}


/* Public function to fill the buffer with LENGTH bytes of
   cryptographically strong random bytes. level 0 is not very strong,
   1 is strong enough for most usage, 2 is good for key generation
   stuff but may be very slow.  */
static void
_gcry_core_random_randomize (gcry_core_context_t ctx,
			     byte *buffer, size_t length, enum gcry_random_level level)
{
  random_intern_t randomctx;
  byte *p;
  int err;

  randomctx = ctx->random.intern;

  /* Make sure we are initialized. */
  if (!randomctx->is_initialized)
    initialize (ctx, randomctx);

  /* Handle our hack used for regression tests of Libgcrypt. */
  if((ctx->flags & GCRY_CORE_FLAG_ENABLE_QUICK_RANDOM_GENERATION) && level > 1 )
    level = 1;

  /* Make sure the level is okay. */
  MASK_LEVEL(level);

  /* Acquire the pool lock. */
  err = _gcry_core_ath_mutex_lock (ctx, &randomctx->pool_lock);
  if (err)
    log_fatal (ctx, "failed to acquire the pool lock: %s\n", strerror (err));
  randomctx->pool_is_locked = 1;

  /* Update the statistics. */
  if (level >= 2)
    {
      randomctx->rndstats.getbytes2 += length;
      randomctx->rndstats.ngetbytes2++;
    }
  else
    {
      randomctx->rndstats.getbytes1 += length;
      randomctx->rndstats.ngetbytes1++;
    }

  /* Read the random into the provided buffer. */
  for (p = buffer; length > 0;)
    {
      size_t n;

      n = length > POOLSIZE? POOLSIZE : length;
      read_pool (ctx, randomctx,p, n, level);
      length -= n;
      p += n;
    }

  /* Release the pool lock. */
  randomctx->pool_is_locked = 0;
  err = _gcry_core_ath_mutex_unlock (ctx, &randomctx->pool_lock);
  if (err)
    log_fatal (ctx, "failed to release the pool lock: %s\n", strerror (err));

}




/*
   Mix the pool:

   |........blocks*20byte........|20byte|..44byte..|
   <..44byte..>           <20byte> 
        |                    |
        |                    +------+
        +---------------------------|----------+
                                    v          v
   |........blocks*20byte........|20byte|..44byte..|
                                 <.....64bytes.....>   
                                         |
      +----------------------------------+
     Hash
      v
   |.............................|20byte|..44byte..|
   <20byte><20byte><..44byte..>
      |                |
      |                +---------------------+
      +-----------------------------+        |
                                    v        v
   |.............................|20byte|..44byte..|
                                 <.....64byte......>
                                        |
              +-------------------------+
             Hash
              v
   |.............................|20byte|..44byte..|
   <20byte><20byte><..44byte..>

   and so on until we did this for all blocks. 

   To better protect against implementation errors in this code, we
   xor a digest of the entire pool into the pool before mixing.

   Note, that this function muts only be called with a locked pool.
 */
static void
mix_pool(gcry_core_context_t ctx, random_intern_t randomctx, byte *pool)
{
  char *hashbuf = pool + POOLSIZE;
  char *p, *pend;
  int i, n;
  RMD160_CONTEXT md;

#if DIGESTLEN != 20
#error must have a digest length of 20 for ripe-md-160
#endif

  assert (randomctx->pool_is_locked);
  _gcry_rmd160_init (ctx, &md );

  /* loop over the pool */
  pend = pool + POOLSIZE;
  memcpy(hashbuf, pend - DIGESTLEN, DIGESTLEN );
  memcpy(hashbuf+DIGESTLEN, pool, BLOCKLEN-DIGESTLEN);
  _gcry_rmd160_mixblock (ctx, &md, hashbuf);
  memcpy(pool, hashbuf, 20 );

  if (randomctx->failsafe_digest_valid && (char *)pool == randomctx->rndpool)
    {
      for (i=0; i < 20; i++)
        pool[i] ^= randomctx->failsafe_digest[i];
    }
  
  p = pool;
  for (n=1; n < POOLBLOCKS; n++)
    {
      memcpy (hashbuf, p, DIGESTLEN);

      p += DIGESTLEN;
      if (p+DIGESTLEN+BLOCKLEN < pend)
        memcpy (hashbuf+DIGESTLEN, p+DIGESTLEN, BLOCKLEN-DIGESTLEN);
      else 
        {
          char *pp = p + DIGESTLEN;
          
          for (i=DIGESTLEN; i < BLOCKLEN; i++ )
            {
              if ( pp >= pend )
                pp = pool;
              hashbuf[i] = *pp++;
	    }
	}
      
      _gcry_rmd160_mixblock(ctx, &md, hashbuf);
      memcpy(p, hashbuf, 20 );
    }

    /* Our hash implementation does only leave small parts (64 bytes)
       of the pool on the stack, so it is okay not to require secure
       memory here.  Before we use this pool, it will be copied to the
       help buffer anyway. */
    if ( (char*)pool == randomctx->rndpool)
      {
        _gcry_rmd160_hash_buffer (ctx, randomctx->failsafe_digest,
				  pool, POOLSIZE);
        randomctx->failsafe_digest_valid = 1;
      }

    _gcry_burn_stack (384); /* for the rmd160_mixblock(), rmd160_hash_buffer */
}


static void
_gcry_core_random_seed_file_set (gcry_core_context_t ctx, const char *name )
{
  random_intern_t randomctx;

  randomctx = ctx->random.intern;
  if (randomctx->seed_file_name)
    BUG (ctx);
  randomctx->seed_file_name = gcry_core_xstrdup (ctx, name);
}


/*
  Read in a seed form the random_seed file
  and return true if this was successful.
 */
static int
read_seed_file (gcry_core_context_t ctx, random_intern_t randomctx)
{
  int fd;
  struct stat sb;
  unsigned char buffer[POOLSIZE];
  int n;

  assert (randomctx->pool_is_locked);

  if (!randomctx->seed_file_name)
    return 0;
  
#ifdef HAVE_DOSISH_SYSTEM
  fd = open( randomctx->seed_file_name, O_RDONLY | O_BINARY );
#else
  fd = open( randomctx->seed_file_name, O_RDONLY );
#endif
  if( fd == -1 && errno == ENOENT)
    {
      randomctx->allow_seed_file_update = 1;
      return 0;
    }

  if (fd == -1 )
    {
      log_info(ctx, _("can't open `%s': %s\n"),
	       randomctx->seed_file_name, strerror(errno) );
      return 0;
    }
  if (fstat( fd, &sb ) )
    {
      log_info(ctx, _("can't stat `%s': %s\n"),
	       randomctx->seed_file_name, strerror(errno) );
      close(fd);
      return 0;
    }
  if (!S_ISREG(sb.st_mode) )
    {
      log_info(ctx, _("`%s' is not a regular file - ignored\n"),
	       randomctx->seed_file_name );
      close(fd);
      return 0;
    }
  if (!sb.st_size )
    {
      log_info(ctx, _("note: random_seed file is empty\n") );
      close(fd);
      randomctx->allow_seed_file_update = 1;
      return 0;
    }
  if (sb.st_size != POOLSIZE ) 
    {
      log_info(ctx, _("warning: invalid size of random_seed file - not used\n") );
      close(fd);
      return 0;
    }

  do
    {
      n = read( fd, buffer, POOLSIZE );
    } 
  while (n == -1 && errno == EINTR );

  if (n != POOLSIZE)
    {
      log_fatal(ctx, _("can't read `%s': %s\n"),
		randomctx->seed_file_name,strerror(errno) );
      close(fd);/*NOTREACHED*/
      return 0;
    }
  
  close(fd);

  add_randomness( ctx, buffer, POOLSIZE, 0 );
  /* add some minor entropy to the pool now (this will also force a mixing) */
  {	
    pid_t x = getpid();
    add_randomness( ctx, &x, sizeof(x), 0 );
  }
  {
    time_t x = time(NULL);
    add_randomness( ctx, &x, sizeof(x), 0 );
  }
  {	
    clock_t x = clock();
    add_randomness( ctx, &x, sizeof(x), 0 );
  }

  /* And read a few bytes from our entropy source.  By using a level
   * of 0 this will not block and might not return anything with some
   * entropy drivers, however the rndlinux driver will use
   * /dev/urandom and return some stuff - Do not read to much as we
   * want to be friendly to the scare system entropy resource. */
  read_random_source(ctx, randomctx, 0, 16, 0 );

  randomctx->allow_seed_file_update = 1;
  return 1;
}


static void
_gcry_core_random_seed_file_update(gcry_core_context_t ctx)
{
  random_intern_t randomctx;
  ulong *sp, *dp;
  int fd, i;
  int err;

  randomctx = ctx->random.intern;
  
  if ( !randomctx->seed_file_name || !randomctx->is_initialized || !randomctx->pool_filled )
    return;
  if ( !randomctx->allow_seed_file_update )
    {
      log_info(ctx, _("note: random_seed file not updated\n"));
      return;
    }

  err = _gcry_core_ath_mutex_lock (ctx, &randomctx->pool_lock);
  if (err)
    log_fatal (ctx, "failed to acquire the pool lock: %s\n", strerror (err));
  randomctx->pool_is_locked = 1;

  /* copy the entropy pool to a scratch pool and mix both of them */
  for (i=0,dp=(ulong*)randomctx->keypool, sp=(ulong*)randomctx->rndpool;
       i < POOLWORDS; i++, dp++, sp++ ) 
    {
      *dp = *sp + ADD_VALUE;
    }
  mix_pool(ctx, randomctx, randomctx->rndpool); randomctx->rndstats.mixrnd++;
  mix_pool(ctx, randomctx, randomctx->keypool); randomctx->rndstats.mixkey++;

#ifdef HAVE_DOSISH_SYSTEM
  fd = open (randomctx->seed_file_name, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,
             S_IRUSR|S_IWUSR );
#else
  fd = open (randomctx->seed_file_name, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR );
#endif

  if (fd == -1 )
    log_info (ctx, _("can't create `%s': %s\n"),
	      randomctx->seed_file_name, strerror(errno) );
  else 
    {
      do
        {
          i = write (fd, randomctx->keypool, POOLSIZE );
        } 
      while( i == -1 && errno == EINTR );
      if (i != POOLSIZE) 
        log_info (ctx, _("can't write `%s': %s\n"),
                  randomctx->seed_file_name, strerror(errno) );
      if (close(fd))
        log_info(ctx, _("can't close `%s': %s\n"),
                 randomctx->seed_file_name, strerror(errno) );
    }
  
  randomctx->pool_is_locked = 0;
  err = _gcry_core_ath_mutex_unlock (ctx, &randomctx->pool_lock);
  if (err)
    log_fatal (ctx, "failed to release the pool lock: %s\n", strerror (err));

}


/* Read random out of the pool. This function is the core of the
   public random fucntions.  Note that Level 0 is not anymore handeld
   special and in fact an alias for level 1. */
static void
read_pool (gcry_core_context_t ctx, random_intern_t randomctx,
	   byte *buffer, size_t length, int level)
{
  int i;
  unsigned long *sp, *dp;
  volatile pid_t my_pid; /* The volatile is there to make sure the
                            compiler does not optimize the code away
                            in case the getpid function is badly
                            attributed. */

 retry:
  /* Get our own pid, so that we can detect a fork. */
  my_pid = getpid ();

  assert (randomctx->pool_is_locked);

  /* Our code does not allow to extract more than POOLSIZE.  Better
     check it here. */
  if (length > POOLSIZE)
    {
      log_bug(ctx, "too many random bits requested\n");
    }

  if (!randomctx->pool_filled)
    {
      if (read_seed_file(ctx, randomctx) )
        randomctx->pool_filled = 1;
    }

  /* For level 2 quality (key generation) we always make sure that the
     pool has been seeded enough initially. */
  if (level == 2 && !randomctx->did_initial_extra_seeding)
    {
      size_t needed;

      randomctx->pool_balance = 0;
      needed = length - randomctx->pool_balance;
      if (needed < POOLSIZE/2)
        needed = POOLSIZE/2;
      else if( needed > POOLSIZE )
        BUG (ctx);
      read_random_source (ctx, randomctx, 3, needed, 2);
      randomctx->pool_balance += needed;
      randomctx->did_initial_extra_seeding = 1;
    }

  /* For level 2 make sure that there is enough random in the pool. */
  if (level == 2 && randomctx->pool_balance < length)
    {
      size_t needed;
      
      if (randomctx->pool_balance < 0)
        randomctx->pool_balance = 0;
      needed = length - randomctx->pool_balance;
      if (needed > POOLSIZE)
        BUG (ctx);
      read_random_source(ctx, randomctx, 3, needed, 2 );
      randomctx->pool_balance += needed;
    }

  /* make sure the pool is filled */
  while (!randomctx->pool_filled)
    random_poll(ctx, randomctx);

  /* Always do a fast random poll (we have to use the unlocked version). */
  do_fast_random_poll(ctx, randomctx);
  
  /* Mix the pid in so that we for sure won't deliver the same random
     after a fork. */
  {
    pid_t tmp_pid = my_pid;
    add_randomness (ctx, &tmp_pid, sizeof (tmp_pid), 0);
  }

  /* Mix the pool (if add_randomness() didn't it). */
  if (!randomctx->just_mixed)
    {
      mix_pool(ctx, randomctx, randomctx->rndpool);
      randomctx->rndstats.mixrnd++;
    }

  /* Create a new pool. */
  for(i=0,dp=(ulong*)randomctx->keypool, sp=(ulong*)randomctx->rndpool;
      i < POOLWORDS; i++, dp++, sp++ )
    *dp = *sp + ADD_VALUE;

  /* Mix both pools. */
  mix_pool(ctx, randomctx, randomctx->rndpool); randomctx->rndstats.mixrnd++;
  mix_pool(ctx, randomctx, randomctx->keypool); randomctx->rndstats.mixkey++;

  /* Read the required data.  We use a readpointer to read from a
     different position each time */
  while (length--)
    {
      *buffer++ = randomctx->keypool[randomctx->pool_readpos++];
      if (randomctx->pool_readpos >= POOLSIZE)
        randomctx->pool_readpos = 0;
      randomctx->pool_balance--;
    }
 
  if (randomctx->pool_balance < 0)
    randomctx->pool_balance = 0;

  /* Clear the keypool. */
  memset (randomctx->keypool, 0, POOLSIZE);

  /* We need to detect whether a fork has happened.  A fork might have
     an identical pool and thus the child and the parent could emit
     the very same random number.  Obviously this can only happen when
     running multi-threaded and the pool lock should even catch this.
     However things do get wrong and thus we better check and retry it
     here.  We assume that the thread library has no other fatal
     faults, though.
   */
  if ( getpid () != my_pid )
    {
      pid_t x = getpid();
      add_randomness (ctx,&x, sizeof(x), 0);
      randomctx->just_mixed = 0; /* Make sure it will get mixed. */
      goto retry;
    }
}


/*
 * Add LENGTH bytes of randomness from buffer to the pool.
 * source may be used to specify the randomness source.
 * Source is:
 *	0 - used ony for initialization
 *	1 - fast random poll function
 *	2 - normal poll function
 *	3 - used when level 2 random quality has been requested
 *	    to do an extra pool seed.
 */
static void
add_randomness(gcry_core_context_t ctx,
	       const void *buffer, size_t length, int source )
{
  random_intern_t randomctx;
  const byte *p = buffer;

  randomctx = ctx->random.intern;

  assert (randomctx->pool_is_locked);
  if (!randomctx->is_initialized)
    initialize (ctx, randomctx);
  randomctx->rndstats.addbytes += length;
  randomctx->rndstats.naddbytes++;
  while (length-- )
    {
      randomctx->rndpool[randomctx->pool_writepos++] ^= *p++;
      if (randomctx->pool_writepos >= POOLSIZE )
        {
          if (source > 1)
            randomctx->pool_filled = 1;
          randomctx->pool_writepos = 0;
          mix_pool(ctx, randomctx, randomctx->rndpool); randomctx->rndstats.mixrnd++;
          randomctx->just_mixed = !length;	/* FIXME: is this right?  -moritz */
	}
    }
}

static void
random_poll(gcry_core_context_t ctx, random_intern_t randomctx)
{
  randomctx->rndstats.slowpolls++;
  read_random_source (ctx, randomctx, 2, POOLSIZE/5, 1);
}

static gcry_core_random_source_gather_t
getfnc_gather_random (gcry_core_context_t ctx)
{
#if USE_RNDLINUX
  if (! (*gcry_core_random_source_dev->check) (ctx))
    return gcry_core_random_source_dev->gather;
#endif

#if USE_RNDEGD
  if (! (*gcry_core_random_source_egd->check) (ctx))
    return gcry_core_random_source_egd->gather;
#endif

#if USE_RNDUNIX
  if (! (*gcry_core_random_source_unix->check) (ctx))
    return gcry_core_random_source_unix->gather;
#endif

#if 0
  /* FIXME, moritz.  */
#if USE_RNDW32
  fnc = _gcry_rndw32_gather_random;
  return fnc;
#endif
#endif

  log_fatal (ctx, _("no entropy gathering module detected\n"));

  return NULL; /*NOTREACHED*/
}

static gcry_core_random_source_gather_fast_t
getfnc_fast_random_poll (void)
{
  /* FIXME, moritz?  */
#if USE_RNDW32
  return _gcry_rndw32_gather_random_fast;
#endif
  return NULL;
}

static void
do_fast_random_poll (gcry_core_context_t ctx, random_intern_t randomctx)
{
  assert (randomctx->pool_is_locked);

  randomctx->rndstats.fastpolls++;

  if (randomctx->do_fast_random_poll_initialized)
    {
      if (!randomctx->is_initialized)
	initialize (ctx, randomctx);
      randomctx->do_fast_random_poll_initialized = 1;
      randomctx->fnc_gather_fast = getfnc_fast_random_poll ();
    }

  if (randomctx->fnc_gather_fast)
    (*randomctx->fnc_gather_fast) (ctx, add_randomness, 1);

  /* Continue with the generic functions. */
#if HAVE_GETHRTIME
  {	
    hrtime_t tv;
    tv = gethrtime();
    add_randomness(ctx, &tv, sizeof(tv), 1 );
  }
#elif HAVE_GETTIMEOFDAY
  {	
    struct timeval tv;
    if( gettimeofday( &tv, NULL ) )
      BUG(ctx);
    add_randomness(ctx, &tv.tv_sec, sizeof(tv.tv_sec), 1 );
    add_randomness(ctx, &tv.tv_usec, sizeof(tv.tv_usec), 1 );
  }
#elif HAVE_CLOCK_GETTIME
  {	struct timespec tv;
  if( clock_gettime( CLOCK_REALTIME, &tv ) == -1 )
    BUG(ctx);
  add_randomness(ctx, &tv.tv_sec, sizeof(tv.tv_sec), 1 );
  add_randomness(ctx, &tv.tv_nsec, sizeof(tv.tv_nsec), 1 );
  }
#else /* use times */
# ifndef HAVE_DOSISH_SYSTEM
  {	struct tms buf;
  times( &buf );
  add_randomness(ctx, &buf, sizeof buf, 1 );
  }
# endif
#endif

#ifdef HAVE_GETRUSAGE
# ifdef RUSAGE_SELF
  {	
    struct rusage buf;
    /* QNX/Neutrino does return ENOSYS - so we just ignore it and
     * add whatever is in buf.  In a chroot environment it might not
     * work at all (i.e. because /proc/ is not accessible), so we better 
     * ugnore all error codes and hope for the best
     */
    getrusage (RUSAGE_SELF, &buf );
    add_randomness(ctx, &buf, sizeof buf, 1 );
    memset( &buf, 0, sizeof buf );
  }
# else /*!RUSAGE_SELF*/
#  ifdef __GCC__
#   warning There is no RUSAGE_SELF on this system
#  endif
# endif /*!RUSAGE_SELF*/
#endif /*HAVE_GETRUSAGE*/

  /* time and clock are availabe on all systems - so we better do it
     just in case one of the above functions didn't work */
  {
    time_t x = time(NULL);
    add_randomness(ctx, &x, sizeof(x), 1 );
  }
  {	
    clock_t x = clock();
    add_randomness(ctx, &x, sizeof(x), 1 );
  }
}


/* The fast random pool function as called at some places in
   libgcrypt.  This is merely a wrapper to make sure that this module
   is initalized and to look the pool.  Note, that this function is a
   NOP unless a random function has been used or _gcry_initialize (1)
   has been used.  We use this hack so that the internal use of this
   function in cipher_open and md_open won't start filling up the
   radnom pool, even if no random will be required by the process. */
static void
_gcry_core_random_fast_poll (gcry_core_context_t ctx)
{
  random_intern_t randomctx;
  int err;

  randomctx = ctx->random.intern;

  if (!randomctx->is_initialized)
    return;

  err = _gcry_core_ath_mutex_lock (ctx, &randomctx->pool_lock);
  if (err)
    log_fatal (ctx, "failed to acquire the pool lock: %s\n", strerror (err));
  randomctx->pool_is_locked = 1;

  do_fast_random_poll (ctx, randomctx);

  randomctx->pool_is_locked = 0;
  err = _gcry_core_ath_mutex_unlock (ctx, &randomctx->pool_lock);
  if (err)
    log_fatal (ctx, "failed to acquire the pool lock: %s\n", strerror (err));

}



static void
read_random_source(gcry_core_context_t ctx, random_intern_t randomctx,
		   int requester, size_t length, int level )
{
  if (!randomctx->fnc_gather)
    {
      if (!randomctx->is_initialized )
        initialize(ctx, randomctx);

      randomctx->fnc_gather = getfnc_gather_random (ctx);
      assert (randomctx->fnc_gather);

      if (!requester && !length && !level)
        return; /* Just the init was requested. */
    }

  if ((*randomctx->fnc_gather) (ctx, add_randomness,
				requester, length, level ) < 0)
    log_fatal (ctx, "No way to gather entropy for the RNG\n");
}

/* Create an unpredicable nonce of LENGTH bytes in BUFFER. */
static void
_gcry_core_random_create_nonce (gcry_core_context_t ctx, unsigned char *buffer, size_t length)
{
  random_intern_t randomctx;
  unsigned char *p;
  size_t n;
  int err;

  randomctx = ctx->random.intern;

  /* Make sure we are initialized. */
  if (!randomctx->is_initialized)
    initialize (ctx, randomctx);

  /* Acquire the nonce buffer lock. */
  err = _gcry_core_ath_mutex_lock (ctx, &randomctx->nonce_buffer_lock);
  if (err)
    log_fatal (ctx,
	       "failed to acquire the nonce buffer lock: %s\n",
               strerror (err));

  /* The first time intialize our buffer. */
  if (!randomctx->nonce_buffer_initialized)
    {
      pid_t apid = getpid ();
      time_t atime = time (NULL);

      if ((sizeof apid + sizeof atime) > sizeof randomctx->nonce_buffer)
        BUG (ctx);

      /* Initialize the first 20 bytes with a reasonable value so that
         a failure of gcry_randomize won't affect us too much.  Don't
         care about the uninitialized remaining bytes. */
      p = randomctx->nonce_buffer;
      memcpy (p, &apid, sizeof apid);
      p += sizeof apid;
      memcpy (p, &atime, sizeof atime); 

      /* Initialize the never changing private part of 64 bits. */
      _gcry_core_random_randomize (ctx,
				   randomctx->nonce_buffer+20, 8, GCRY_WEAK_RANDOM);

      randomctx->nonce_buffer_initialized = 1;
    }

  /* Create the nonce by hashing the entire buffer, returning the hash
     and updating the first 20 bytes of the buffer with this hash. */
  for (p = buffer; length > 0; length -= n, p += n)
    {
      _gcry_sha1_hash_buffer (ctx, randomctx->nonce_buffer,
                              randomctx->nonce_buffer, sizeof randomctx->nonce_buffer);
      n = length > 20? 20 : length;
      memcpy (p, randomctx->nonce_buffer, n);
    }


  /* Release the nonce buffer lock. */
  err = _gcry_core_ath_mutex_unlock (ctx, &randomctx->nonce_buffer_lock);
  if (err)
    log_fatal (ctx,
	       "failed to release the nonce buffer lock: %s\n",
               strerror (err));

}



struct gcry_core_subsystem_random _gcry_subsystem_random =
  {
    _gcry_core_random_prepare,
    _gcry_core_random_finish,
    _gcry_core_random_dump_stats,
    _gcry_core_random_add_bytes,
    _gcry_core_random_bytes,
    _gcry_core_random_bytes_secure,
    _gcry_core_random_randomize,
    _gcry_core_random_seed_file_set,
    _gcry_core_random_seed_file_update,
    _gcry_core_random_fast_poll,
    _gcry_core_random_create_nonce,
    _gcry_core_random_initialize,
  };

gcry_core_subsystem_random_t gcry_core_subsystem_random = &_gcry_subsystem_random;
