/* ath-pth.c - Pth module for self-adapting thread-safeness library
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

#include <stdlib.h>
#include <errno.h>
#include <pth.h>

#include "ath.h"

#pragma weak pth_mutex_init
#pragma weak pth_mutex_acquire
#pragma weak pth_mutex_release
#pragma weak pth_read
#pragma weak pth_write
#pragma weak pth_select
#pragma weak pth_waitpid

/* The lock we take while checking for lazy lock initialization.  */
static pth_mutex_t check_init_lock = PTH_MUTEX_INIT;

/* Initialize the mutex *PRIV.  If JUST_CHECK is true, only do this if
   it is not already initialized.  */
static int
mutex_pth_init (void **priv, int just_check)
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
	    *priv = lock;
	}
    }
  if (just_check)
    pth_mutex_release (&check_init_lock);
  return err;
}


static int
mutex_pth_destroy (void *priv)
{
  free (priv);
  return 0;
}


static int
mutex_pth_lock (void *priv)
{
  int ret = pth_mutex_acquire ((pth_mutex_t *) priv, 0, NULL);
  return ret == FALSE ? errno : 0;
}


static int
mutex_pth_unlock (void *priv)
{
  int ret = pth_mutex_release ((pth_mutex_t *) priv);
  return ret == FALSE ? errno : 0;
}


static struct ath_ops ath_pth_ops =
  {
    mutex_pth_init,
    mutex_pth_destroy,
    mutex_pth_lock,
    mutex_pth_unlock,
    pth_read,
    pth_write,
    pth_select,
    pth_waitpid
  };


struct ath_ops *
ath_pth_available (void)
{
  if (pth_mutex_init && pth_mutex_acquire && pth_mutex_release
      && pth_read && pth_write && pth_select && pth_waitpid)
    return &ath_pth_ops;
  else
    return 0;
}
