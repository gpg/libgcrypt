/* rndgetentropy.c  -  raw random number for OSes by getentropy function.
 * Copyright (C) 1998, 2001, 2002, 2003, 2007,
 *               2009  Free Software Foundation, Inc.
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
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "g10lib.h"
#include "rand-internal.h"

/* The function returns 0 on success or true on failure (in which case
 * the caller will signal a fatal error).  */
int
_gcry_rndgetentropy_gather_random (void (*add)(const void*, size_t,
                                               enum random_origins),
                                   enum random_origins origin,
                                   size_t length, int level)
{
  byte buffer[256];

  (void)level;

  if (!add)
    {
      /* Special mode to release resouces.  */
      _gcry_rndjent_fini ();
      return 0;
    }

  /* Enter the loop.  */
  while (length)
    {
      int ret;
      size_t nbytes;

      /* For a modern operating system, we use the new getentropy
       * function.  That call guarantees that the kernel's RNG has
       * been properly seeded before returning any data.  This is
       * different from /dev/urandom which may, due to its
       * non-blocking semantics, return data even if the kernel has
       * not been properly seeded.  And it differs from /dev/random by
       * never blocking once the kernel is seeded.  */
      do
        {
          nbytes = length < sizeof (buffer)? length : sizeof (buffer);
          _gcry_pre_syscall ();
          ret = getentropy (buffer, nbytes);
          _gcry_post_syscall ();
        }
      while (ret == -1 && errno == EINTR);

      if (ret == -1 && errno == ENOSYS)
        log_fatal ("getentropy is not supported: %s\n", strerror (errno));
      else
        { /* getentropy is supported.  Some sanity checks.  */
          if (ret == -1)
            log_fatal ("unexpected error from getentropy: %s\n",
                       strerror (errno));

          (*add) (buffer, nbytes, origin);
          length -= nbytes;
        }
    }
  wipememory (buffer, sizeof buffer);

  return 0; /* success */
}
