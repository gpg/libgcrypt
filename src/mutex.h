/* mutex.h -  Portable mutual exclusion, independent from any thread library.
 *      Copyright (C) 2002 g10 Code GmbH
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef MUTEX_H
#define MUTEX_H

/* Define MUTEX_FAKE before including the file to get stubs that don't
   provide any locking at all.  Define MUTEX_PTHREAD if you can link
   against the posix thread library.  */

#if defined(MUTEX_FAKE)

typedef char mutex_t;
#define mutex_init(x) (0)
#define mutex_destroy(x)
#define mutex_lock(x) (0)
#define mutex_unlock(x) (0)

#elif defined(MUTEX_PTHREAD)

#include <pthread.h>

#define mutex_t pthread_mutex_t
#define mutex_init(x) pthread_mutex_init (&(x), 0)
#define mutex_destroy(x) pthread_mutex_destroy(&(x))
#define mutex_lock(x) pthread_mutex_lock (&(x))
#define mutex_unlock(x) pthread_mutex_unlock (&(x))

#else

int _gcry_no_internal_locking (void);

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* The type of a mutex.  */
typedef int mutex_t[2];

inline static int
set_close_on_exec (int fd)
{
  int flags = fcntl (fd, F_GETFD, 0);
  if (flags == -1)
    return errno;
  flags |= FD_CLOEXEC;
  if (fcntl (fd, F_SETFD, flags) == -1)
    return errno;
  return 0;
}

/* Initialize the mutex variable MUTEX.  */
inline int
_gcry_mutex_init (mutex_t mutex)
{
  ssize_t amount;
  int err = 0;

  if  (_gcry_no_internal_locking())
    return 0;
  if (pipe (mutex))
    return errno;

  err = set_close_on_exec (mutex[0]);
  if (!err)
    err = set_close_on_exec (mutex[1]);
  if (!err)
    while ((amount = write (mutex[1], " ", 1)) < 0 && errno == EINTR)
      ;
  if (!err && amount != 1)
    err = errno;

  if (err)
    {
      close (mutex[0]);
      close (mutex[1]);
    }
  return err;
}

/* Destroy the mutex variable MUTEX.  */
inline void
_gcry_mutex_destroy (mutex_t mutex)
{
  if  (_gcry_no_internal_locking ())
    return;
  close (mutex[0]);
  close (mutex[1]);
}

/* Take the mutex variable MUTEX.  */
inline int
_gcry_mutex_lock (mutex_t mutex)
{
  char data;
  int amount;
  if  (_gcry_no_internal_locking ())
    return 0;

  while ((amount = read (mutex[0], &data, 1)) < 0 && errno == EINTR)
    ;
  return (amount != 1) ? errno : 0;
}

/* Release the mutex variable MUTEX.  */
inline int
_gcry_mutex_unlock (mutex_t mutex)
{
  int amount;
  if  (_gcry_no_internal_locking ())
    return 0;
  while ((amount = write (mutex[1], " ", 1)) < 0 && errno == EINTR)
    ;
  return (amount != 1) ? errno : 0;
}

#define mutex_init(x)    _gcry_mutex_init (x)
#define mutex_destroy(x) _gcry_mutex_destroy(x)
#define mutex_lock(x)    _gcry_mutex_lock (x)
#define mutex_unlock(x)  _gcry_mutex_unlock (x)


#endif	/* MUTEX_FAKE */
#endif	/* MUTEX_H */

