/* random-daemon.c  - Access to the external random daemon
 * Copyright (C) 2006  Free Software Foundation, Inc.
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

/*
   The functions here are used by random.c to divert calls to an
   external random number daemon.  The actual daemon we use is
   gcryptrnd.  Such a daemon is useful to keep a persistent pool in
   memory over invocations of a single application and to allow
   prioritizing access to the actual entropy sources.  The drawback is
   that we need to use IPC (i.e. unxi domain socket) to convey
   sensitive data.
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "g10lib.h"
#include "random.h"
#include "ath.h"


/* The lock taken while talking to the daemon.  */
static ath_mutex_t daemon_lock = ATH_MUTEX_INITIALIZER;



/* Initialize basics of this module. This should be viewed as a
   constroctur to prepare locking. */
void
_gcry_daemon_initialize_basics (void)
{
  static int initialized;
  int err;

  if (!initialized)
    {
      initialized = 1;
      err = ath_mutex_init (&daemon_lock);
      if (err)
        log_fatal ("failed to create the daemon lock: %s\n", strerror (err) );
    }
}

















/* Internal function to fill BUFFER with LENGTH bytes of random.  We
   support GCRY_STRONG_RANDOM and GCRY_VERY_STRONG_RANDOM here.
   Return 0 on success. */
int
_gcry_daemon_randomize (void *buffer, size_t length,
                        enum gcry_random_level level)
{
  return -1;
}

/* Internal function to return a pointer to a randomized buffer of
   LEVEL and NBYTES length.  Caller must free the buffer. With SECURE
   passed as TRUE, allocate the rwanom in secure memory - however note
   that the IPC mechanism might have not stored it there.  Return a
   pointer to a newly alloced memory or NULL if it failed.  */
void *
_gcry_daemon_get_random_bytes (size_t nbytes, int level, int secure)
{
  return NULL;
}


/* Internal function to fill BUFFER with NBYTES of data usable for a
   nonce.  Returns 0 on success. */
int
_gcry_daemon_create_nonce (void *buffer, size_t length)
{
  return -1;
}
