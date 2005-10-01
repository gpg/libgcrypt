/* gcrypt-ath-common.h - Thread-safeness library, common definitions
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

#ifndef _GCRYPT_ATH_COMMON_H
#define _GCRYPT_ATH_COMMON_H

#ifdef _WIN32
#warning We need to replace these hacks by cleaner code.
typedef int ssize_t;
typedef int pid_t;
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

typedef struct gcry_core_handler_ath
{
  int (*init) (void);
  int (*mutex_init) (void **priv);
  int (*mutex_destroy) (void **priv);
  int (*mutex_lock) (void **priv);
  int (*mutex_unlock) (void **priv);
  ssize_t (*read) (int fd, void *buf, size_t nbytes);
  ssize_t (*write) (int fd, const void *buf, size_t nbytes);
  ssize_t (*select) (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
		     struct timeval *timeout);
  ssize_t (*waitpid) (pid_t pid, int *status, int options);
  int (*accept) (int s, struct sockaddr *addr, socklen_t *length_ptr);
  int (*connect) (int s, struct sockaddr *addr, socklen_t length);
  int (*sendmsg) (int s, const struct msghdr *msg, int flags);
  int (*recvmsg) (int s, struct msghdr *msg, int flags);
} *gcry_core_handler_ath_t;

#endif
