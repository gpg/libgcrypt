/* ath-pth.c - Pth module for self-adapting thread-safeness library
   Copyright (C) 2002, 2003 g10 Code GmbH

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>

#include <pth.h>

#include "ath.h"


/* The lock we take while checking for lazy lock initialization.  */
static pth_mutex_t check_init_lock = PTH_MUTEX_INIT;

/* Initialize the mutex *PRIV.  If JUST_CHECK is true, only do this if
   it is not already initialized.  */
static int
mutex_pth_init (ath_mutex_t *priv, int just_check)
{
  int err = 0;

  if (just_check)
    pth_mutex_acquire (&check_init_lock, 0, NULL);
  if (!*priv || !just_check)
    {
      pth_mutex_t *lock = malloc (sizeof (pth_mutex_t));
      if (!lock)
	err = ENOMEM;
      if (!err)
	{
	  err = pth_mutex_init (lock);
	  if (err == FALSE)
	    err = errno;
	  else
	    err = 0;

	  if (err)
	    free (lock);
	  else
	    *priv = (ath_mutex_t) lock;
	}
    }
  if (just_check)
    pth_mutex_release (&check_init_lock);
  return err;
}


void
ath_init (void)
{
  /* Nothing to do.  */
}


int
ath_mutex_init (ath_mutex_t *lock)
{
  return mutex_pth_init (lock, 0);
}


int
ath_mutex_destroy (ath_mutex_t *lock)
{
  int err = mutex_pth_init (lock, 1);
  if (!err)
    {
      /* GNU Pth has no destructor function.  */
      free (*lock);
    }
  return err;
}


int
ath_mutex_lock (ath_mutex_t *lock)
{
  int ret = mutex_pth_init (lock, 1);
  if (ret)
    return ret;

  ret = pth_mutex_acquire ((pth_mutex_t *) *lock, 0, NULL);
  return ret == FALSE ? errno : 0;
}


int
ath_mutex_unlock (ath_mutex_t *lock)
{
  int ret = mutex_pth_init (lock, 1);
  if (ret)
    return ret;

  ret = pth_mutex_release ((pth_mutex_t *) *lock);
  return ret == FALSE ? errno : 0;
}


ssize_t
ath_read (int fd, void *buf, size_t nbytes)
{
  return pth_read (fd, buf, nbytes);
}


ssize_t
ath_write (int fd, const void *buf, size_t nbytes)
{
  return pth_write (fd, buf, nbytes);
}


ssize_t
ath_select (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
	    struct timeval *timeout)
{
  return pth_select (nfd, rset, wset, eset, timeout);
}

 
ssize_t
ath_waitpid (pid_t pid, int *status, int options)
{
  return pth_waitpid (pid, status, options);
}


int
ath_accept (int s, struct sockaddr *addr, socklen_t *length_ptr)
{
  return pth_accept (s, addr, length_ptr);
}


int
ath_connect (int s, struct sockaddr *addr, socklen_t length)
{
  return pth_connect (s, addr, length);
}

int
ath_sendmsg (int s, const struct msghdr *msg, int flags)
{
  /* FIXME: GNU Pth is missing pth_sendmsg.  */
  return sendmsg (s, msg, flags);
}


int
ath_recvmsg (int s, struct msghdr *msg, int flags)
{
  /* FIXME: GNU Pth is missing pth_recvmsg.  */
  return recvmsg (s, msg, flags);
}

