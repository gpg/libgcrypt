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
  FIXME:  Explain


 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "g10lib.h"
#include "random.h"
#include "rand-internal.h"
#include "ath.h"





/* ---  Functions  --- */


/* Initialize this random subsystem.  If FULL is false, this function
   merely calls the basic initialization of the module and does not do
   anything more.  Doing this is not really required but when running
   in a threaded environment we might get a race condition
   otherwise. */
void
_gcry_rngfips_initialize (int full)
{
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
  BUG ();
}


/* Create an unpredicable nonce of LENGTH bytes in BUFFER. */
void
_gcry_rngfips_create_nonce (void *buffer, size_t length)
{
  /* No special nonce support here; divert to the standard random
     function.  */
  _gcry_rngfips_randomize (buffer, length, GCRY_WEAK_RANDOM);
}


