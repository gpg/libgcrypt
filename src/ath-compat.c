/* ath-compat.c - Thread-safeness library.
   Copyright (C) 2002 g10 Code GmbH

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

#include <unistd.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#else
# include <sys/time.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>

#include "ath.h"

static struct ath_ops *ath_ops;

void
ath_init (void)
{
  if (0)
    ;
#ifdef HAVE_PTHREAD
  else if (!ath_ops)
    ath_ops = ath_pthread_available ();
#endif
#ifdef HAVE_PTH
  else if (!ath_ops)
    ath_ops = ath_pth_available ();
#endif
}


int
ath_mutex_init (ath_mutex_t *lock)
{
  if (!ath_ops)
    return 0;

  return ath_ops->mutex_init (lock, 0);
}


int
ath_mutex_destroy (ath_mutex_t *lock)
{
  int err;
  if (!ath_ops)
    return 0;
  err = ath_ops->mutex_init (lock, 1);
  if (!err)
    err = ath_ops->mutex_destroy (*lock);
  return err;
}


int
ath_mutex_lock (ath_mutex_t *lock)
{
  int err;

  if (!ath_ops)
    return 0;
  err = ath_ops->mutex_init (lock, 1);
  if (!err)
    err = ath_ops->mutex_lock (*lock);
  return err;
}


int
ath_mutex_unlock (ath_mutex_t *lock)
{
  int err;

  if (!ath_ops)
    return 0;
  err = ath_ops->mutex_init (lock, 1);
  if (!err)
    err = ath_ops->mutex_unlock (*lock);
  return err;
}


ssize_t
ath_read (int fd, void *buf, size_t nbytes)
{
  if (ath_ops && ath_ops->read)
    return ath_ops->read (fd, buf, nbytes);
  else
    return read (fd, buf, nbytes);
}


ssize_t
ath_write (int fd, const void *buf, size_t nbytes)
{
  if (ath_ops && ath_ops->write)
    return ath_ops->write (fd, buf, nbytes);
  else
    return write (fd, buf, nbytes);
}


ssize_t
ath_select (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
	    struct timeval *timeout)
{
  if (ath_ops && ath_ops->select)
    return ath_ops->select (nfd, rset, wset, eset, timeout);
  else
    return select (nfd, rset, wset, eset, timeout);
}

 
ssize_t
ath_waitpid (pid_t pid, int *status, int options)
{
  if (ath_ops && ath_ops->waitpid)
    return ath_ops->waitpid (pid, status, options);
  else
    return waitpid (pid, status, options);
}


int
ath_accept (int s, struct sockaddr *addr, socklen_t *length_ptr)
{
  if (ath_ops && ath_ops->accept)
    return ath_ops->accept (s, addr, length_ptr);
  else
    return accept (s, addr, length_ptr);
}


int
ath_connect (int s, struct sockaddr *addr, socklen_t length)
{
  if (ath_ops && ath_ops->connect)
    return ath_ops->connect (s, addr, length);
  else
    return connect (s, addr, length);
}


int
ath_sendmsg (int s, const struct msghdr *msg, int flags)
{
  if (ath_ops && ath_ops->sendmsg)
    return ath_ops->sendmsg (s, msg, flags);
  else
    return sendmsg (s, msg, flags);
}


int
ath_recvmsg (int s, struct msghdr *msg, int flags)
{
  if (ath_ops && ath_ops->recvmsg)
    return ath_ops->recvmsg (s, msg, flags);
  else
    return recvmsg (s, msg, flags);
}
