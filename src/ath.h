/* ath.h - interfaces for self-adapting thread-safeness library
 *      Copyright (C) 2002 g10 Code GmbH
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

#ifndef ATH_H
#define ATH_H

#include <sys/types.h>

#ifdef HAVE_DOSISH_SYSTEM
# include <windows.h> /* for fd_set */
# include <process.h> /* for pid_t */
  typedef unsigned int ssize_t;
#endif

/* Define ATH_EXT_SYM_PREFIX if you want to give all external symbols
   a prefix.  */
#define ATH_EXT_SYM_PREFIX _gcry_

#ifdef ATH_EXT_SYM_PREFIX
#define ATH_PREFIX1(x,y) x ## y
#define ATH_PREFIX2(x,y) ATH_PREFIX1(x,y)
#define ATH_PREFIX(x) ATH_PREFIX2(ATH_EXT_SYM_PREFIX,x)
#define ath_init ATH_PREFIX(ath_init)
#define ath_deinit ATH_PREFIX(ath_deinit)
#define ath_mutex_init ATH_PREFIX(ath_mutex_init)
#define ath_mutex_destroy ATH_PREFIX(ath_mutex_destroy)
#define ath_mutex_lock ATH_PREFIX(ath_mutex_lock)
#define ath_mutex_unlock ATH_PREFIX(ath_mutex_unlock)
#define ath_read ATH_PREFIX(ath_read)
#define ath_write ATH_PREFIX(ath_write)
#define ath_select ATH_PREFIX(ath_select)
#define ath_waitpid ATH_PREFIX(ath_waitpid)
#define ath_pthread_available ATH_PREFIX(ath_pthread_available)
#define ath_pth_available ATH_PREFIX(ath_pth_available)
#endif


typedef void *ath_mutex_t;
#define ATH_MUTEX_INITIALIZER 0;

/* Functions for mutual exclusion.  */
int ath_mutex_init (ath_mutex_t *mutex);
int ath_mutex_destroy (ath_mutex_t *mutex);
int ath_mutex_lock (ath_mutex_t *mutex);
int ath_mutex_unlock (ath_mutex_t *mutex);

/* Replacement for the POSIX functions, which can be used to allow
   other (user-level) threads to run.  */
ssize_t ath_read (int fd, void *buf, size_t nbytes);
ssize_t ath_write (int fd, const void *buf, size_t nbytes);
ssize_t ath_select (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
		    struct timeval *timeout);
ssize_t ath_waitpid (pid_t pid, int *status, int options);


struct ath_ops
{
  int (*mutex_init) (void **priv, int just_check);
  int (*mutex_destroy) (void *priv);
  int (*mutex_lock) (void *priv);
  int (*mutex_unlock) (void *priv);
  ssize_t (*read) (int fd, void *buf, size_t nbytes);
  ssize_t (*write) (int fd, const void *buf, size_t nbytes);
  ssize_t (*select) (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
		     struct timeval *timeout);
  ssize_t (*waitpid) (pid_t pid, int *status, int options);
};

/* Initialize the any-thread package.  */
void ath_init (void);
void ath_deinit (void);

/* Used by ath_pkg_init.  */
struct ath_ops *ath_pthread_available (void);
struct ath_ops *ath_pth_available (void);
struct ath_ops *ath_dummy_available (void);

#endif	/* ATH_H */
