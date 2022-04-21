/* bulkhelp.h  -  Some bulk processing helpers
 * Copyright (C) 2022 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
#ifndef GCRYPT_BULKHELP_H
#define GCRYPT_BULKHELP_H


#include "g10lib.h"
#include "cipher-internal.h"


#ifdef __x86_64__
/* Use u64 to store pointers for x32 support (assembly function assumes
 * 64-bit pointers). */
typedef u64 ocb_L_uintptr_t;
#else
typedef uintptr_t ocb_L_uintptr_t;
#endif


static inline ocb_L_uintptr_t *
bulk_ocb_prepare_L_pointers_array_blk32 (gcry_cipher_hd_t c,
                                         ocb_L_uintptr_t Ls[32], u64 blkn)
{
  unsigned int n = 32 - (blkn % 32);
  unsigned int i;

  for (i = 0; i < 32; i += 8)
    {
      Ls[(i + 0 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
      Ls[(i + 1 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[1];
      Ls[(i + 2 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
      Ls[(i + 3 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[2];
      Ls[(i + 4 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
      Ls[(i + 5 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[1];
      Ls[(i + 6 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
    }

  Ls[(7 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[3];
  Ls[(15 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[4];
  Ls[(23 + n) % 32] = (uintptr_t)(void *)c->u_mode.ocb.L[3];
  return &Ls[(31 + n) % 32];
}


static inline ocb_L_uintptr_t *
bulk_ocb_prepare_L_pointers_array_blk16 (gcry_cipher_hd_t c,
                                         ocb_L_uintptr_t Ls[16], u64 blkn)
{
  unsigned int n = 16 - (blkn % 16);
  unsigned int i;

  for (i = 0; i < 16; i += 8)
    {
      Ls[(i + 0 + n) % 16] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
      Ls[(i + 1 + n) % 16] = (uintptr_t)(void *)c->u_mode.ocb.L[1];
      Ls[(i + 2 + n) % 16] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
      Ls[(i + 3 + n) % 16] = (uintptr_t)(void *)c->u_mode.ocb.L[2];
      Ls[(i + 4 + n) % 16] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
      Ls[(i + 5 + n) % 16] = (uintptr_t)(void *)c->u_mode.ocb.L[1];
      Ls[(i + 6 + n) % 16] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
    }

  Ls[(7 + n) % 16] = (uintptr_t)(void *)c->u_mode.ocb.L[3];
  return &Ls[(15 + n) % 16];
}


static inline ocb_L_uintptr_t *
bulk_ocb_prepare_L_pointers_array_blk8 (gcry_cipher_hd_t c,
                                        ocb_L_uintptr_t Ls[8], u64 blkn)
{
  unsigned int n = 8 - (blkn % 8);

  Ls[(0 + n) % 8] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
  Ls[(1 + n) % 8] = (uintptr_t)(void *)c->u_mode.ocb.L[1];
  Ls[(2 + n) % 8] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
  Ls[(3 + n) % 8] = (uintptr_t)(void *)c->u_mode.ocb.L[2];
  Ls[(4 + n) % 8] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
  Ls[(5 + n) % 8] = (uintptr_t)(void *)c->u_mode.ocb.L[1];
  Ls[(6 + n) % 8] = (uintptr_t)(void *)c->u_mode.ocb.L[0];
  Ls[(7 + n) % 8] = (uintptr_t)(void *)c->u_mode.ocb.L[3];

  return &Ls[(7 + n) % 8];
}


#endif /*GCRYPT_BULKHELP_H*/
