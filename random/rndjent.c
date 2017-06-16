/* rndjent.c  - Driver for the jitterentropy module.
 * Copyright (C) 2017 g10 Code GmbH
 * Copyright (C) 2017 Bundesamt für Sicherheit in der Informationstechnik
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#include "types.h"
#include "g10lib.h"
#include "../cipher/bithelp.h"
#include "rand-internal.h"

/*
 * Decide whether we can support jent at compile time.
 */
#undef USE_JENT
#ifdef ENABLE_JENT_SUPPORT
# if defined (__i386__) || defined(__x86_64__)
#   define USE_JENT 1
# endif
#endif /*ENABLE_JENT_SUPPORT*/


#ifdef USE_JENT

/* When using the libgcrypt secure memory mechanism, all precautions
 * are taken to protect our state. If the user disables secmem during
 * runtime, it is his decision and we thus try not to overrule his
 * decision for less memory protection. */
#define JENT_CPU_JITTERENTROPY_SECURE_MEMORY 1
#define jent_zalloc(n) _gcry_calloc_secure (1, (n))



/*
 * Libgcrypt specific platform dependent functions.
 */


static void
jent_get_nstime(u64 *out)
{
  u32 t_eax, t_edx;

  asm volatile (".byte 0x0f,0x31\n\t"
                : "=a" (t_eax), "=d" (t_edx)
                );
  *out = (((u64)t_edx << 32) | t_eax);
}


static GPGRT_INLINE void
jent_zfree (void *ptr, unsigned int len)
{
  if (ptr)
    {
      wipememory (ptr, len);
      _gcry_free (ptr);
    }
}

static GPGRT_INLINE int
jent_fips_enabled(void)
{
  return fips_mode();
}


/*
 * We source include the actual jitter entropy code.  Note that the
 * included code has been slightly changed from the Linux kernel
 * version for namespace reasons.  We define MODULE so that the
 * EXPORT_SYMBOL macro will not be used.
 */
#undef CONFIG_CRYPTO_CPU_JITTERENTROPY_STAT
/* Uncomment the next line to build with statistics.  */
/* #define CONFIG_CRYPTO_CPU_JITTERENTROPY_STAT 1 */

#undef MODULE
#define MODULE 1

#ifndef HAVE_STDINT_H
# error This module needs stdint.h - try ./configure --disable-jent-support
#endif
#include "jitterentropy-base.c"


/* This is the lock we use to serialize access to this RNG.  The extra
 * integer variable is only used to check the locking state; that is,
 * it is not meant to be thread-safe but merely as a failsafe feature
 * to assert proper locking.  */
GPGRT_LOCK_DEFINE (jent_rng_lock);
static int jent_rng_is_locked;

/* This flag tracks whether the RNG has been initialized - either
 * with error or with success.  Protected by JENT_RNG_LOCK. */
static int jent_rng_is_initialized;

/* Our collector.  The RNG is in a working state if its value is not
 * NULL.  Protected by JENT_RNG_LOCK.  */
struct rand_data *jent_rng_collector;

/* The number of times the core entropy function has been called and
 * the number of random bytes retrieved.  */
static unsigned long jent_rng_totalcalls;
static unsigned long jent_rng_totalbytes;


/* Acquire the jent_rng_lock.  */
static void
lock_rng (void)
{
  gpg_err_code_t rc;

  rc = gpgrt_lock_lock (&jent_rng_lock);
  if (rc)
    log_fatal ("failed to acquire the Jent RNG lock: %s\n",
               gpg_strerror (rc));
  jent_rng_is_locked = 1;
}


/* Release the jent_rng_lock.  */
static void
unlock_rng (void)
{
  gpg_err_code_t rc;

  jent_rng_is_locked = 0;
  rc = gpgrt_lock_unlock (&jent_rng_lock);
  if (rc)
    log_fatal ("failed to release the Jent RNG lock: %s\n",
               gpg_strerror (rc));
}

#endif /* USE_JENT */


/*
 * The API used by the high level code.
 */

/* Read up to LENGTH bytes from a jitter RNG and return the number of
 * bytes actually read.  */
size_t
_gcry_rndjent_poll (void (*add)(const void*, size_t, enum random_origins),
                    enum random_origins origin, size_t length)
{
  size_t nbytes = 0;

  (void)add;
  (void)origin;

#ifdef USE_JENT
  if ((_gcry_get_hw_features () & HWF_INTEL_RDTSC))
    {
      lock_rng ();

      if (!jent_rng_is_initialized)
        {
          /* Auto-initialize.  */
          jent_rng_is_initialized = 1;
          jent_entropy_collector_free (jent_rng_collector);
          jent_rng_collector = NULL;
          if ( !(_gcry_random_read_conf () & RANDOM_CONF_DISABLE_JENT))
            {
              if (!jent_entropy_init ())
                jent_rng_collector = jent_entropy_collector_alloc (1, 0);
            }
        }

      if (jent_rng_collector)
        {
          /* We have a working JENT and it has not been disabled.  */
          char buffer[256];

          while (length)
            {
              int rc;
              size_t n = length < sizeof(buffer)? length : sizeof (buffer);

              jent_rng_totalcalls++;
              rc = jent_read_entropy (jent_rng_collector, buffer, n);
              if (rc < 0)
                break;
              (*add) (buffer, rc, origin);
              length -= rc;
              nbytes += rc;
              jent_rng_totalbytes += rc;
            }
          wipememory (buffer, sizeof buffer);
        }

      unlock_rng ();
    }
#endif

  return nbytes;
}


/* Log statistical informantion about the use of this module.  */
void
_gcry_rndjent_dump_stats (void)
{
  /* In theory we would need to lock the stats here.  However this
     function is usually called during cleanup and then we _might_ run
     into problems.  */

#ifdef USE_JENT
  if ((_gcry_get_hw_features () & HWF_INTEL_RDTSC))
    {

      log_info ("rndjent stat: collector=%p calls=%lu bytes=%lu\n",
                jent_rng_collector, jent_rng_totalcalls, jent_rng_totalbytes);

    }
#endif /*USE_JENT*/
}
