/* ath.c - Thread-safeness library.
   Copyright (C) 2002, 2003, 2004, 2005 g10 Code GmbH

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

#include <gcrypt-ath-internal.h>

#include <assert.h>
#include <unistd.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#else
# include <sys/time.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>



/* For the dummy interface.  */
#define MUTEX_UNLOCKED	((gcry_core_ath_mutex_t) 0)
#define MUTEX_LOCKED	((gcry_core_ath_mutex_t) 1)
#define MUTEX_DESTROYED	((gcry_core_ath_mutex_t) 2)



/* The lock we take while checking for lazy lock initialization.  */
static gcry_core_ath_mutex_t check_init_lock = ATH_MUTEX_INITIALIZER;

int
_gcry_core_ath_init (gcry_core_context_t ctx)
{
  int err = 0;

  if (ctx->handler.ath.ops_set)
    {
      if (ctx->handler.ath.init)
	/* FIXME: we should pass ctx to init function.  wonderful,
	   handler API break, would need wrappers in compat.  */
	err = (ctx->handler.ath.init) ();
      if (err)
	return err;
      err = (*ctx->handler.ath.mutex_init) (&check_init_lock);
    }
  return err;
}



static int
mutex_init (gcry_core_context_t ctx, gcry_core_ath_mutex_t *lock, int just_check)
{
  int err = 0;

  if (just_check)
    (*ctx->handler.ath.mutex_lock) (&check_init_lock);
  /* FIXME: line below - is this correct? better read the whole
     file.  */
  if (*lock == ATH_MUTEX_INITIALIZER || !just_check)
    err = (*ctx->handler.ath.mutex_init) (lock);
  if (just_check)
    (*ctx->handler.ath.mutex_unlock) (&check_init_lock);
  return err;
}


int
_gcry_core_ath_mutex_init (gcry_core_context_t ctx, gcry_core_ath_mutex_t *lock)
{
  if (ctx->handler.ath.ops_set)
    return mutex_init (ctx, lock, 0);

#ifndef NDEBUG
  *lock = MUTEX_UNLOCKED;
#endif
  return 0;
}


int
_gcry_core_ath_mutex_destroy (gcry_core_context_t ctx, gcry_core_ath_mutex_t *lock)
{
  if (ctx->handler.ath.ops_set)
    {
      int err = mutex_init (ctx, lock, 1);

      if (err)
	return err;

      if (ctx->handler.ath.mutex_destroy)
	return (*ctx->handler.ath.mutex_destroy) (lock);
      else
	return 0;
    }

#ifndef NDEBUG
  assert (*lock == MUTEX_UNLOCKED);

  *lock = MUTEX_DESTROYED;
#endif
  return 0;
}


int
_gcry_core_ath_mutex_lock (gcry_core_context_t ctx, gcry_core_ath_mutex_t *lock)
{
  if (ctx->handler.ath.ops_set)
    {
      int ret = mutex_init (ctx, lock, 1);
      if (ret)
	return ret;
      return (*ctx->handler.ath.mutex_lock) (lock);
    }

#ifndef NDEBUG
  assert (*lock == MUTEX_UNLOCKED);

  *lock = MUTEX_LOCKED;
#endif
  return 0;
}


int
_gcry_core_ath_mutex_unlock (gcry_core_context_t ctx, gcry_core_ath_mutex_t *lock)
{
  if (ctx->handler.ath.ops_set)
    {
      int ret = mutex_init (ctx, lock, 1);
      if (ret)
	return ret;
      return (*ctx->handler.ath.mutex_unlock) (lock);
    }

#ifndef NDEBUG
  assert (*lock == MUTEX_LOCKED);

  *lock = MUTEX_UNLOCKED;
#endif
  return 0;
}


ssize_t
_gcry_core_ath_read (gcry_core_context_t ctx, int fd, void *buf, size_t nbytes)
{
  if (ctx->handler.ath.ops_set && ctx->handler.ath.read)
    return (*ctx->handler.ath.read) (fd, buf, nbytes);
  else
    return read (fd, buf, nbytes);
}


ssize_t
_gcry_core_ath_write (gcry_core_context_t ctx, int fd, const void *buf, size_t nbytes)
{
  if (ctx->handler.ath.ops_set && ctx->handler.ath.write)
    return (*ctx->handler.ath.write) (fd, buf, nbytes);
  else
    return write (fd, buf, nbytes);
}


ssize_t
_gcry_core_ath_select (gcry_core_context_t ctx,
		       int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
		       struct timeval *timeout)
{
  if (ctx->handler.ath.ops_set && ctx->handler.ath.select)
    return (*ctx->handler.ath.select) (nfd, rset, wset, eset, timeout);
  else
    return select (nfd, rset, wset, eset, timeout);
}

 
ssize_t
_gcry_core_ath_waitpid (gcry_core_context_t ctx, pid_t pid, int *status, int options)
{
  if (ctx->handler.ath.ops_set && ctx->handler.ath.waitpid)
    return (*ctx->handler.ath.waitpid) (pid, status, options);
  else
    return waitpid (pid, status, options);
}


int
_gcry_core_ath_accept (gcry_core_context_t ctx,
		       int s, struct sockaddr *addr, socklen_t *length_ptr)
{
  if (ctx->handler.ath.ops_set && ctx->handler.ath.accept)
    return (*ctx->handler.ath.accept) (s, addr, length_ptr);
  else
    return accept (s, addr, length_ptr);
}


int
_gcry_core_ath_connect (gcry_core_context_t ctx,
	     int s, struct sockaddr *addr, socklen_t length)
{
  if (ctx->handler.ath.ops_set && ctx->handler.ath.connect)
    return (*ctx->handler.ath.connect) (s, addr, length);
  else
    return connect (s, addr, length);
}


int
_gcry_core_ath_sendmsg (gcry_core_context_t ctx,
	     int s, const struct msghdr *msg, int flags)
{
  if (ctx->handler.ath.ops_set && ctx->handler.ath.sendmsg)
    return (*ctx->handler.ath.sendmsg) (s, msg, flags);
  else
    return sendmsg (s, msg, flags);
}


int
_gcry_core_ath_recvmsg (gcry_core_context_t ctx,
	     int s, struct msghdr *msg, int flags)
{
  if (ctx->handler.ath.ops_set && ctx->handler.ath.recvmsg)
    return (*ctx->handler.ath.recvmsg) (s, msg, flags);
  else
    return recvmsg (s, msg, flags);
}

/* END. */
