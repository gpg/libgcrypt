/*
 * Non-physical true random number generator based on timing jitter.
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2013
 *
 * License
 * =======
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef GCRYPT_JITTERENTROPY_BASE_USER_H
#define GCRYPT_JITTERENTROPY_BASE_USER_H

/*
 * This is Libgcrypt specific platform dependent code.  We use a
 * separate file because jitterentropy.h expects such a file.
 */

#ifndef USE_JENT
# error This file expects to be included from rndjent.c (via jitterentropy.h)
#endif
#ifndef HAVE_STDINT_H
# error This module needs stdint.h - try ./configure --disable-jent-support
#endif


/* When using the libgcrypt secure memory mechanism, all precautions
 * are taken to protect our state.  If the user disables secmem during
 * runtime, it is his decision and we thus try not to overrule his
 * decision for less memory protection.  */
#define JENT_CPU_JITTERENTROPY_SECURE_MEMORY 1
#define jent_zalloc(n) _gcry_calloc_secure (1, (n))


static void
jent_get_nstime(u64 *out)
{
#if USE_JENT == JENT_USES_RDTSC

  u32 t_eax, t_edx;

  asm volatile (".byte 0x0f,0x31\n\t"
                : "=a" (t_eax), "=d" (t_edx)
                );
  *out = (((u64)t_edx << 32) | t_eax);

#elif USE_JENT == JENT_USES_GETTIME

  struct timespec tv;
  u64 tmp;

  /* On Linux we could use CLOCK_MONOTONIC(_RAW), but with
   * CLOCK_REALTIME we get some nice extra entropy once in a while
   * from the NTP actions that we want to use as well... though, we do
   * not rely on that extra little entropy.  */
  if (!clock_gettime (CLOCK_REALTIME, &tv))
    {
      tmp = tv.tv_sec;
      tmp = tmp << 32;
      tmp = tmp | tv.tv_nsec;
    }
  else
    tmp = 0;
  *out = tmp;

#elif USE_JENT == JENT_USES_READ_REAL_TIME

  /* clock_gettime() on AIX returns a timer value that increments in
   * steps of 1000.  */
  u64 tmp = 0;

  timebasestruct_t aixtime;
  read_real_time (&aixtime, TIMEBASE_SZ);
  tmp = aixtime.tb_high;
  tmp = tmp << 32;
  tmp = tmp | aixtime.tb_low;
  *out = tmp;

#else
# error No clock available in jent_get_nstime
#endif
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


#endif /* GCRYPT_JITTERENTROPY_BASE_USER_H */
