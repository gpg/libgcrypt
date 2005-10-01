/* gcrypt-ath-internal.h - Thread-safeness library, internal interface
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

#ifndef _GCRYPT_ATH_INTERNAL_H
#define _GCRYPT_ATH_INTERNAL_H

#include <gcrypt-common-internal.h>
#include <gcrypt-ath-common.h>



int _gcry_core_ath_init (gcry_core_context_t ctx);

/* Functions for mutual exclusion.  */
typedef void *gcry_core_ath_mutex_t;
#define ATH_MUTEX_INITIALIZER 0

int _gcry_core_ath_mutex_init (gcry_core_context_t ctx, gcry_core_ath_mutex_t *mutex);
int _gcry_core_ath_mutex_destroy (gcry_core_context_t ctx, gcry_core_ath_mutex_t *mutex);
int _gcry_core_ath_mutex_lock (gcry_core_context_t ctx, gcry_core_ath_mutex_t *mutex);
int _gcry_core_ath_mutex_unlock (gcry_core_context_t ctx, gcry_core_ath_mutex_t *mutex);


/* Replacement for the POSIX functions, which can be used to allow
   other (user-level) threads to run.  */
ssize_t _gcry_core_ath_read (gcry_core_context_t ctx,
			     int fd, void *buf, size_t nbytes);
ssize_t _gcry_core_ath_write (gcry_core_context_t ctx,
			      int fd, const void *buf, size_t nbytes);
ssize_t _gcry_core_ath_select (gcry_core_context_t ctx, int nfd,
			       fd_set *rset, fd_set *wset, fd_set *eset,
			       struct timeval *timeout);
ssize_t _gcry_core_ath_waitpid (gcry_core_context_t ctx,
				pid_t pid, int *status, int options);
int _gcry_core_ath_accept (gcry_core_context_t ctx,
			   int s, struct sockaddr *addr, socklen_t *length_ptr);
int _gcry_core_ath_connect (gcry_core_context_t ctx,
			    int s, struct sockaddr *addr, socklen_t length);
int _gcry_core_ath_sendmsg (gcry_core_context_t ctx,
			    int s, const struct msghdr *msg, int flags);
int _gcry_core_ath_recvmsg (gcry_core_context_t ctx,
			    int s, struct msghdr *msg, int flags);

#endif	/* _GCRY_ATH_INTERNAL_H */
