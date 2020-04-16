/* mpih-const-time.c  -  Constant-time MPI helper functions
 *      Copyright (C) 2020  g10 Code GmbH
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
#include "mpi-internal.h"
#include "g10lib.h"

/*
 *  W = U when OP_ENABLED=1
 *  otherwise, W keeps old value
 */
void
_gcry_mpih_set_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
                     unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;
  mpi_limb_t x;

  for (i = 0; i < usize; i++)
    {
      x = mask & (wp[i] ^ up[i]);
      wp[i] = wp[i] ^ x;
    }
}


/*
 *  W = U + V when OP_ENABLED=1
 *  otherwise, W = U
 */
mpi_limb_t
_gcry_mpih_add_n_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_ptr_t vp,
                       mpi_size_t usize, unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t cy;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;

  cy = 0;
  for (i = 0; i < usize; i++)
    {
      mpi_limb_t x = up[i] + (vp[i] & mask);
      mpi_limb_t cy1 = x < up[i];
      mpi_limb_t cy2;

      x = x + cy;
      cy2 = x < cy;
      cy = cy1 | cy2;
      wp[i] = x;
    }

  return cy;
}


/*
 *  W = U - V when OP_ENABLED=1
 *  otherwise, W = U
 */
mpi_limb_t
_gcry_mpih_sub_n_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_ptr_t vp,
                       mpi_size_t usize, unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t cy;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;

  cy = 0;
  for (i = 0; i < usize; i++)
    {
      mpi_limb_t x = up[i] - (vp[i] & mask);
      mpi_limb_t cy1 = x > up[i];
      mpi_limb_t cy2;

      cy2 = x < cy;
      x = x - cy;
      cy = cy1 | cy2;
      wp[i] = x;
    }

  return cy;
}


/*
 *  Swap value of U and V when OP_ENABLED=1
 *  otherwise, no change
 */
void
_gcry_mpih_swap_cond (mpi_ptr_t up, mpi_ptr_t vp, mpi_size_t usize,
                      unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;

  for (i = 0; i < usize; i++)
    {
      mpi_limb_t x = mask & (up[i] ^ vp[i]);

      up[i] = up[i] ^ x;
      vp[i] = vp[i] ^ x;
    }
}


/*
 *  W = -U when OP_ENABLED=1
 *  otherwise, W = U
 */
void
_gcry_mpih_abs_cond (mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
                     unsigned long op_enable)
{
  mpi_size_t i;
  mpi_limb_t mask = ((mpi_limb_t)0) - op_enable;
  mpi_limb_t cy = op_enable;

  for (i = 0; i < usize; i++)
    {
      mpi_limb_t x = ~up[i] + cy;

      cy = (x < ~up[i]);
      wp[i] = up[i] ^ (mask & (x ^ up[i]));
    }
}
