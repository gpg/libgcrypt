/* random-fips.c - FIPS style random number generator
 * Copyright (C) 2008  Free Software Foundation, Inc.
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
   The core of this deterministic random number generator is
   implemented according to the document "NIST-Recommended Random
   Number Generator Based on ANSI X9.31 Appendix A.2.4 Using the 3-Key
   Triple DES and AES Algorithms" (2005-01-31) and uses the AES
   variant.


 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif

#include "g10lib.h"
#include "random.h"
#include "rand-internal.h"
#include "ath.h"

/* This is the lock we use to serialize access to this RNG.  The extra
   integer variable is only used to check the locking state; that is,
   it is not meant to be thread-safe but merely as a failsafe feature
   to assert proper locking.  */
static ath_mutex_t fips_rng_lock = ATH_MUTEX_INITIALIZER;
static int fips_rng_is_locked;


/* The required size for the temporary buffer of the x931_aes_driver
   function and the buffer itself which will be allocated in secure
   memory.  This needs to be global variable for proper initialization
   and to allow shutting down the RNG without leaking memory.  May
   only be used while holding the FIPS_RNG_LOCK.

   This variable is also used to avoid duplicate initialization.  */
#define TEMPVALUE_FOR_X931_AES_DRIVER_SIZE 48
static unsigned char *tempvalue_for_x931_aes_driver;


/* The length of the key we use:  16 bytes (128 bit) for AES128.  */
#define X931_AES_KEYLEN  16
/* A global buffer used to communicate between the x931_generate_key
   and x931_generate_seed functions and the entropy_collect_cb
   function.  It may only be used by these functions. */
static unsigned char *entropy_collect_buffer;  /* Buffer.  */
static size_t entropy_collect_buffer_len;      /* Used length.  */
static size_t entropy_collect_buffer_size;     /* Allocated length.  */


/* This random context type is used to track properties of one random
   generator. Thee context are usually allocated in secure memory so
   that the seed value is well protected.  There are a couble of guard
   fields to help detecting applications accidently overwriting parts
   of the memory. */
struct rng_context
{
  unsigned char guard_0[1];

  /* The handle of the cipher used by the RNG.  If this one is not
     NULL a cipher handle along with a random key has been
     established.  */
  gcry_cipher_hd_t cipher_hd;

  /* If this flag is true, this context requires strong entropy;
     i.e. from /dev/random.  */
  int need_strong_entropy:1;

  /* If this flag is true, the SEED_V buffer below carries a valid
     seed.  */
  int is_seeded:1;

  /* The very first block generated is used to compare the result
     against the last result.  This flag indicates that such a block
     is available.  */
  int compare_value_valid:1;

  unsigned char guard_1[1];

  /* The buffer containing the seed value V.  */
  unsigned char seed_V[16];

  unsigned char guard_2[1];

  /* The last result from the x931_aes fucntion.  Only valid if
     compare_value_valid is set.  */
  unsigned char compare_value[16];

  unsigned char guard_3[1];

  /* We need to keep track of the process which did the initialization
     so that we can detect a fork.  The volatile modifier is required
     so that the compiler does not optimize it away in case the getpid
     function is badly attributed.  */ 
   pid_t key_init_pid;
   pid_t seed_init_pid;
};
typedef struct rng_context *rng_context_t;


/* The random context used for the nonce generator.  May only be used
   while holding the FIPS_RNG_LOCK.  */
static rng_context_t nonce_context;
/* The random context used for the standard random generator.  May
   only be used while holding the FIPS_RNG_LOCK.  */
static rng_context_t std_rng_context;
/* The random context used for the very strong random generator.  May
   only be used while holding the FIPS_RNG_LOCK.  */
static rng_context_t strong_rng_context;




/* --- Functions  --- */

/* Basic initialization is required to initialize mutexes and
   do a few checks on the implementation.  */
static void
basic_initialization (void)
{
  static int initialized;
  int my_errno;

  if (!initialized)
    return;
  initialized = 1;

  my_errno = ath_mutex_init (&fips_rng_lock);
  if (my_errno)
    log_fatal ("failed to create the RNG lock: %s\n", strerror (my_errno));
  fips_rng_is_locked = 0;
      
  /* Make sure that we are still using the values we have
     traditionally used for the random levels.  */
  gcry_assert (GCRY_WEAK_RANDOM == 0 
               && GCRY_STRONG_RANDOM == 1
               && GCRY_VERY_STRONG_RANDOM == 2);

}


/* Acquire the fips_rng_lock.  */
static void
lock_rng (void)
{
  int my_errno;

  my_errno = ath_mutex_lock (&fips_rng_lock);
  if (my_errno)
    log_fatal ("failed to acquire the RNG lock: %s\n", strerror (my_errno));
  fips_rng_is_locked = 1;
}


/* Release the fips_rng_lock.  */
static void
unlock_rng (void)
{
  int my_errno;

  fips_rng_is_locked = 0;
  my_errno = ath_mutex_unlock (&fips_rng_lock);
  if (my_errno)
    log_fatal ("failed to release the RNG lock: %s\n", strerror (my_errno));
}

static void
setup_guards (rng_context_t rng_ctx)
{
  /* Set the guards to some arbitrary values.  */
  rng_ctx->guard_0[0] = 17;
  rng_ctx->guard_1[0] = 42;
  rng_ctx->guard_2[0] = 137;
  rng_ctx->guard_3[0] = 252;
}

static void
check_guards (rng_context_t rng_ctx)
{
  if ( rng_ctx->guard_0[0] != 17
       || rng_ctx->guard_1[0] != 42
       || rng_ctx->guard_2[0] != 137
       || rng_ctx->guard_3[0] != 252 )
    log_fatal ("memory corruption detected in RNG context %p\n", rng_ctx);
}


/* Get the DT vector for use with the core PRNG function.  Buffer
   needs to be provided by the caller with a size of at least LENGTH
   bytes.  The 16 byte timestamp we construct is made up the real time
   and three counters:

   Buffer:       00112233445566778899AABBCCDDEEFF
                 !--+---!!-+-!!+!!--+---!!--+---!     
   seconds ---------/      |   |    |       |
   microseconds -----------/   |    |       |
   counter2 -------------------/    |       |
   counter1 ------------------------/       |
   counter0 --------------------------------/

   Counter 2 is just 12 bits wide and used to track fractions of
   milliseconds whereas counters 1 and 0 are combined to a free
   running 64 bit counter.  */
static void 
x931_get_dt (unsigned char *buffer, size_t length)
{
  gcry_assert (length == 16); /* This length is required for use with AES.  */
  gcry_assert (fips_rng_is_locked);

#if HAVE_GETTIMEOFDAY
  {
    static u32 last_sec, last_usec;
    static u32 counter1, counter0;
    static u16 counter2;
    
    unsigned int usec;
    struct timeval tv;

    if (!last_sec)
      {
        /* This is the very first time we are called: Set the counters
           to an not so easy predictable value to avoid always
           starting at 0.  Not really needed but it doesn't harm.  */
        counter1 = (u32)getpid ();
        counter0 = (u32)getppid ();
      }


    if (gettimeofday (&tv, NULL))
      log_fatal ("gettimeofday() failed: %s\n", strerror (errno));

    /* The microseconds part is always less than 1 millon (0x0f4240).
       Thus we don't care about the MSB and in addition shift it to
       the left by 4 bits.  */
    usec = tv.tv_usec;
    usec <<= 4;
    /* If we got the same time as by the last invocation, bump up
       counter2 and save the time for the next invocation.  */
    if (tv.tv_sec == last_sec && usec == last_usec)
      {
        counter2++;
        counter2 &= 0x0fff;
      }
    else
      {
        counter2 = 0;
        last_sec = tv.tv_sec;
        last_usec = usec;
      }
    /* Fill the buffer with the timestamp.  */
    buffer[0] = ((tv.tv_sec >> 24) & 0xff);
    buffer[1] = ((tv.tv_sec >> 16) & 0xff);
    buffer[2] = ((tv.tv_sec >> 8) & 0xff);
    buffer[3] = (tv.tv_sec & 0xff);
    buffer[4] = ((usec >> 16) & 0xff);
    buffer[5] = ((usec >> 8) & 0xff);
    buffer[6] = ((usec & 0xf0) | ((counter2 >> 8) & 0x0f));
    buffer[7] = (counter2 & 0xff);
    /* Add the free running counter.  */
    buffer[8]  = ((counter1 >> 24) & 0xff);
    buffer[9]  = ((counter1 >> 16) & 0xff);
    buffer[10] = ((counter1 >> 8) & 0xff); 
    buffer[11] = ((counter1) & 0xff);
    buffer[12] = ((counter0 >> 24) & 0xff);
    buffer[13] = ((counter0 >> 16) & 0xff);
    buffer[14] = ((counter0 >> 8) & 0xff); 
    buffer[15] = ((counter0) & 0xff);
    /* Bump up that counter.  */
    if (!++counter0)
      ++counter1;
  }
#else
  log_fatal ("gettimeofday() not available on this system\n");
#endif

  /* log_printhex ("x931_get_dt: ", buffer, 16); */
}


/* XOR the buffers A and B which are each of LENGTH bytes and store
   the result at R.  R needs to be provided by the caller with a size
   of at least LENGTH bytes.  */
static void
xor_buffer (unsigned char *r, 
            const unsigned char *a, const unsigned char *b, size_t length)
{
  for ( ; length; length--, a++, b++, r++)
    *r = (*a ^ *b);
}


/* Encrypt LENGTH bytes of INPUT to OUTPUT using KEY.  LENGTH
   needs to be 16. */
static void
encrypt_aes (gcry_cipher_hd_t key, 
             unsigned char *output, const unsigned char *input, size_t length)
{
  gpg_error_t err;

  gcry_assert (length == 16);

  err = gcry_cipher_encrypt (key, output, length, input, length);
  if (err)
    log_fatal ("AES encryption in RNG failed: %s\n", gcry_strerror (err));
}


/* The core ANSI X9.31, Appendix A.2.4 function using AES.  The caller
   needs to pass a 16 byte buffer for the result and the 16 byte seed
   value V.  The caller also needs to pass an appropriate KEY and make
   sure to pass a valid seed_V.  The caller also needs to provide two
   16 bytes buffer for intermediate results, they may be reused by the
   caller later.

   On return the result is stored at RESULT_R and the SEED_V is
   updated.  May only be used while holding the lock.  */
static void
x931_aes (unsigned char result_R[16], unsigned char seed_V[16],
          gcry_cipher_hd_t key,
          unsigned char intermediate_I[16], unsigned char temp_xor[16])
{
  unsigned char datetime_DT[16];

  /* Let ede*X(Y) represent the AES encryption of Y under the key *X.

     Let V be a 128-bit seed value which is also kept secret, and XOR
     be the exclusive-or operator. Let DT be a date/time vector which
     is updated on each iteration. I is a intermediate value. 

     I = ede*K(DT)  */
  x931_get_dt (datetime_DT, 16);
  encrypt_aes (key, intermediate_I, datetime_DT, 16);

  /* R = ede*K(I XOR V) */
  xor_buffer (temp_xor, intermediate_I, seed_V, 16);
  encrypt_aes (key, result_R, temp_xor, 16);

  /* V = ede*K(R XOR I).  */
  xor_buffer (temp_xor, result_R, intermediate_I, 16);
  encrypt_aes (key, seed_V, temp_xor, 16);

  /* Zero out temporary values.  */
  wipememory (intermediate_I, 16);
  wipememory (temp_xor, 16);
}


/* The high level driver to x931_aes.  This one does the required
   tests and calls the core function until the entire buffer has been
   filled.  OUTPUT is a caller provided buffer of LENGTH bytes to
   receive the random, RNG_CTX is the context of the RNG.  The context
   must be properly initialized.  Returns 0 on success. */
static int
x931_aes_driver (unsigned char *output, size_t length, rng_context_t rng_ctx)
{
  unsigned char *intermediate_I, *temp_buffer, *result_buffer;
  size_t nbytes;

  gcry_assert (fips_rng_is_locked);
  gcry_assert (rng_ctx->cipher_hd);
  gcry_assert (rng_ctx->is_seeded);

  gcry_assert (tempvalue_for_x931_aes_driver);
  gcry_assert (TEMPVALUE_FOR_X931_AES_DRIVER_SIZE == 48);
  intermediate_I = tempvalue_for_x931_aes_driver;
  temp_buffer    = tempvalue_for_x931_aes_driver + 16;
  result_buffer  = tempvalue_for_x931_aes_driver + 32;

  while (length)
    {
      /* Due to the design of the RNG, we always receive 16 bytes (128
         bit) of random even if we require less.  The extra bytes
         returned are not used.  Intheory we could save them for the
         next invocation, but that would make the control flow harder
         to read.  */
      nbytes = length < 16? length : 16;
      x931_aes (result_buffer, rng_ctx->seed_V, rng_ctx->cipher_hd,
                intermediate_I, temp_buffer);

      /* Do a basic check on the output to avoid a stuck generator.  */
      if (!rng_ctx->compare_value_valid)
        {
          /* First time used, only save the result.  */
          memcpy (rng_ctx->compare_value, result_buffer, 16);
          rng_ctx->compare_value_valid = 1;
          continue;
        }
      if (!memcmp (rng_ctx->compare_value, result_buffer, 16))
        {
          /* Ooops, we received the same 128 bit block - that should
             in theory never happen.  The FIPS requirement says that
             we need to put ourself into the error state in such
             case.  */
          fips_signal_error ("duplicate 128 bit block returned by RNG");
          return -1;
        }
      memcpy (rng_ctx->compare_value, result_buffer, 16);
      
      /* Append to outbut.  */
      memcpy (output, result_buffer, nbytes);
      wipememory (result_buffer, 16);
      output += nbytes;
      length -= nbytes;
    }

  return 0;
}


/* Callback for x931_generate_key. Note that this callback uses the
   global ENTROPY_COLLECT_BUFFER which has been setup by
   x931_generate_key.  ORIGIN is not used but required due to the
   emtropy gathering module. */
static void
entropy_collect_cb (const void *buffer, size_t length,
                    enum random_origins origin)
{
  const unsigned char *p = buffer;

  (void)origin;

  gcry_assert (fips_rng_is_locked);
  gcry_assert (entropy_collect_buffer);
  
  while (length--)
    {
      gcry_assert (entropy_collect_buffer_len < entropy_collect_buffer_size);
      entropy_collect_buffer[entropy_collect_buffer_len++] ^= *p++;
    }
}

/* Generate a key for use with x931_aes.  The function returns a
   handle to the cipher context readily prepared for ECB encryption.
   If VERY_STRONG is true the key is read from /dev/random, otherwise
   from /dev/urandom.  On error NULL is returned.  */
static gcry_cipher_hd_t
x931_generate_key (int very_strong)
{
  gcry_cipher_hd_t hd;
  gpg_error_t err;

  gcry_assert (fips_rng_is_locked);

  /* Allocate a cipher context.  */
  err = gcry_cipher_open (&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB,
                          GCRY_CIPHER_SECURE);
  if (err)
    {
      log_error ("error creating cipher context for RNG: %s\n",
                 gcry_strerror (err));
      return NULL;
    }

  /* Get a key from the entropy source.  */
#if USE_RNDLINUX
  gcry_assert (!entropy_collect_buffer);
  entropy_collect_buffer = gcry_xmalloc_secure (X931_AES_KEYLEN);
  entropy_collect_buffer_size = X931_AES_KEYLEN;
  entropy_collect_buffer_len = 0;
  if (_gcry_rndlinux_gather_random (entropy_collect_cb, 0, X931_AES_KEYLEN,
                                    (very_strong
                                     ? GCRY_VERY_STRONG_RANDOM
                                     : GCRY_STRONG_RANDOM)
                                    ) < 0
      || entropy_collect_buffer_len != entropy_collect_buffer_size)
    {
      gcry_free (entropy_collect_buffer);
      entropy_collect_buffer = NULL;
      gcry_cipher_close (hd);
      log_fatal ("error getting entropy data for the RNG key\n");
    }
#else
  log_fatal ("/dev/random support is not compiled in\n");
#endif

  /* Set the key and delete the buffer because the key is now part of
     the cipher context.  */
  err = gcry_cipher_setkey (hd, entropy_collect_buffer, X931_AES_KEYLEN);
  wipememory (entropy_collect_buffer, X931_AES_KEYLEN);
  gcry_free (entropy_collect_buffer);
  entropy_collect_buffer = NULL;
  if (err)
    {
      log_error ("error creating key for RNG: %s\n", gcry_strerror (err));
      gcry_cipher_close (hd);
      return NULL;
    }

  return hd;
}


/* Generate a key for use with x931_aes.  The function copies a seed
   of LENGTH bytes into SEED_BUFFER. LENGTH needs to by given as 16.  */
static void
x931_generate_seed (unsigned char *seed_buffer, size_t length, int very_strong)
{
  gcry_assert (fips_rng_is_locked);
  gcry_assert (length == 16);

  /* Get a seed from the entropy source.  */
#if USE_RNDLINUX
  gcry_assert (!entropy_collect_buffer);
  entropy_collect_buffer = gcry_xmalloc_secure (X931_AES_KEYLEN);
  entropy_collect_buffer_size = X931_AES_KEYLEN;
  entropy_collect_buffer_len = 0;
  if (_gcry_rndlinux_gather_random (entropy_collect_cb, 0, X931_AES_KEYLEN,
                                    (very_strong
                                     ? GCRY_VERY_STRONG_RANDOM
                                     : GCRY_STRONG_RANDOM)
                                    ) < 0
      || entropy_collect_buffer_len != entropy_collect_buffer_size)
    {
      gcry_free (entropy_collect_buffer);
      entropy_collect_buffer = NULL;
      log_fatal ("error getting entropy data for the RNG seed\n");
    }
#else
  log_fatal ("/dev/random support is not compiled in\n");
#endif
  gcry_free (entropy_collect_buffer);
  entropy_collect_buffer = NULL;
}


/* Core random function.  This is used for both nonce and random
   generator.  The actual RNG to be used depends on the random context
   RNG_CTX passed.  Note that this function is called with the RNG not
   yet locked.  */
static void
get_random (void *buffer, size_t length, rng_context_t rng_ctx)
{
  gcry_assert (buffer);
  gcry_assert (rng_ctx);

  lock_rng ();
  check_guards (rng_ctx);

  /* Initialize the cipher handle and thus setup the key if needed.  */
  if (!rng_ctx->cipher_hd)
    {
      rng_ctx->cipher_hd = x931_generate_key (rng_ctx->need_strong_entropy);
      if (!rng_ctx->cipher_hd)
        goto bailout;
      rng_ctx->key_init_pid = getpid ();
    }

  /* Initialize the seed value if needed.  */
  if (!rng_ctx->is_seeded)
    {
      x931_generate_seed (rng_ctx->seed_V, 16, rng_ctx->need_strong_entropy);
      rng_ctx->is_seeded = 1;
      rng_ctx->seed_init_pid = getpid ();
    }

  if (rng_ctx->key_init_pid != getpid ()
      || rng_ctx->seed_init_pid != getpid ())
    {
      /* We are in a child of us.  Because we have no way yet to do
         proper re-initialization (including self-checks etc), the
         only chance we have is to bail out.  Obviusly a fork/exec
         won't harm because the exec overwrites the old image. */
      fips_signal_error ("fork without proper re-initialization "
                         "detected in RNG");
      goto bailout;
    }

  if (x931_aes_driver (buffer, length, rng_ctx))
    goto bailout;

  check_guards (rng_ctx);
  unlock_rng ();
  return;

 bailout:
  unlock_rng ();
  log_fatal ("severe error getting random\n");
  /*NOTREACHED*/
}


/* Initialize this random subsystem.  If FULL is false, this function
   merely calls the basic initialization of the module and does not do
   anything more.  Doing this is not really required but when running
   in a threaded environment we might get a race condition
   otherwise. */
void
_gcry_rngfips_initialize (int full)
{
  basic_initialization ();
  if (!full)
    return;

  /* Allocate temporary buffers.  If that buffer already exists we
     know that we are already initialized.  */
  lock_rng ();
  if (!tempvalue_for_x931_aes_driver)
    {
      tempvalue_for_x931_aes_driver
        = gcry_xmalloc_secure (TEMPVALUE_FOR_X931_AES_DRIVER_SIZE);

      /* Allocate the random contexts.  Note that we do not need to use
         secure memory for the nonce context.  */
      nonce_context = gcry_xcalloc (1, sizeof *nonce_context);
      setup_guards (nonce_context);

      std_rng_context = gcry_xcalloc_secure (1, sizeof *std_rng_context);
      setup_guards (std_rng_context);
      
      strong_rng_context = gcry_xcalloc_secure (1, sizeof *strong_rng_context);
      strong_rng_context->need_strong_entropy = 1;
      setup_guards (strong_rng_context);
    }

  unlock_rng ();
}


void
_gcry_rngfips_dump_stats (void)
{
}


/* This function returns true if no real RNG is available or the
   quality of the RNG has been degraded for test purposes.  */
int
_gcry_rngfips_is_faked (void)
{
  return 0;  /* Faked random is not allowed.  */
}


/* Add BUFLEN bytes from BUF to the internal random pool.  QUALITY
   should be in the range of 0..100 to indicate the goodness of the
   entropy added, or -1 for goodness not known.  */
gcry_error_t
_gcry_rngfips_add_bytes (const void *buf, size_t buflen, int quality)
{
  return 0;
}   

    
/* Public function to fill the buffer with LENGTH bytes of
   cryptographically strong random bytes.  Level GCRY_WEAK_RANDOM is
   here mapped to GCRY_STRING_RANDOM, GCRY_STRONG_RANDOM is strong
   enough for most usage, GCRY_VERY_STRONG_RANDOM is good for key
   generation stuff but may be very slow.  */
void
_gcry_rngfips_randomize (void *buffer, size_t length,
                         enum gcry_random_level level)
{
  _gcry_rngfips_initialize (1);  /* Auto-initialize if needed.  */
  
  if (level == GCRY_VERY_STRONG_RANDOM)
    get_random (buffer, length, strong_rng_context);
  else
    get_random (buffer, length, std_rng_context);
}


/* Create an unpredicable nonce of LENGTH bytes in BUFFER. */
void
_gcry_rngfips_create_nonce (void *buffer, size_t length)
{
  _gcry_rngfips_initialize (1);  /* Auto-initialize if needed.  */

  get_random (buffer, length, nonce_context);
}

