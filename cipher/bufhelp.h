/* bufhelp.h  -  Some buffer manipulation helpers
 *	Copyright © 2012 Jussi Kivilinna <jussi.kivilinna@mbnet.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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
#ifndef G10_BUFHELP_H
#define G10_BUFHELP_H

#ifdef HAVE_STDINT_H
# include <stdint.h> /* uintptr_t */
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#else
/* In this case, uintptr_t is provided by config.h. */
#endif


#if defined(__i386__) || defined(__x86_64__)
/* These architechtures are able of unaligned memory accesses and can
   handle those fast.
 */
# define BUFHELP_FAST_UNALIGNED_ACCESS 1
#endif


/* Optimized function for buffer xoring */
static inline void
buf_xor(void *_dst, const void *_src1, const void *_src2, size_t len)
{
  byte *dst = _dst;
  const byte *src1 = _src1;
  const byte *src2 = _src2;
  uintptr_t *ldst;
  const uintptr_t *lsrc1, *lsrc2;
#ifndef BUFHELP_FAST_UNALIGNED_ACCESS
  const unsigned int longmask = sizeof(uintptr_t) - 1;

  /* Skip fast processing if alignment of buffers do not match.  */
  if ((((uintptr_t)dst ^ (uintptr_t)src1) |
       ((uintptr_t)dst ^ (uintptr_t)src2)) & longmask)
    goto do_bytes;

  /* Handle unaligned head.  */
  for (; len && ((uintptr_t)dst & longmask); len--)
      *dst++ = *src1++ ^ *src2++;
#endif

  ldst = (uintptr_t *)dst;
  lsrc1 = (const uintptr_t *)src1;
  lsrc2 = (const uintptr_t *)src2;

  for (; len >= sizeof(uintptr_t); len -= sizeof(uintptr_t))
    *ldst++ = *lsrc1++ ^ *lsrc2++;

  dst = (byte *)ldst;
  src1 = (const byte *)lsrc1;
  src2 = (const byte *)lsrc2;

#ifndef BUFHELP_FAST_UNALIGNED_ACCESS
do_bytes:
#endif
  /* Handle tail.  */
  for (; len; len--)
    *dst++ = *src1++ ^ *src2++;
}


/* Optimized function for buffer xoring with two destination buffers.  Used
   mainly by CFB mode encryption.  */
static inline void
buf_xor_2dst(void *_dst1, void *_dst2, const void *_src, size_t len)
{
  byte *dst1 = _dst1;
  byte *dst2 = _dst2;
  const byte *src = _src;
  uintptr_t *ldst1, *ldst2;
  const uintptr_t *lsrc;
#ifndef BUFHELP_FAST_UNALIGNED_ACCESS
  const unsigned int longmask = sizeof(uintptr_t) - 1;

  /* Skip fast processing if alignment of buffers do not match.  */
  if ((((uintptr_t)src ^ (uintptr_t)dst1) |
       ((uintptr_t)src ^ (uintptr_t)dst2)) & longmask)
    goto do_bytes;

  /* Handle unaligned head.  */
  for (; len && ((uintptr_t)src & longmask); len--)
    *dst1++ = (*dst2++ ^= *src++);
#endif

  ldst1 = (uintptr_t *)dst1;
  ldst2 = (uintptr_t *)dst2;
  lsrc = (const uintptr_t *)src;

  for (; len >= sizeof(uintptr_t); len -= sizeof(uintptr_t))
    *ldst1++ = (*ldst2++ ^= *lsrc++);

  dst1 = (byte *)ldst1;
  dst2 = (byte *)ldst2;
  src = (const byte *)lsrc;

#ifndef BUFHELP_FAST_UNALIGNED_ACCESS
do_bytes:
#endif
  /* Handle tail.  */
  for (; len; len--)
    *dst1++ = (*dst2++ ^= *src++);
}


/* Optimized function for combined buffer xoring and copying.  Used by mainly
   CFB mode decryption.  */
static inline void
buf_xor_n_copy(void *_dst_xor, void *_srcdst_cpy, const void *_src, size_t len)
{
  byte *dst_xor = _dst_xor;
  byte *srcdst_cpy = _srcdst_cpy;
  byte temp;
  const byte *src = _src;
  uintptr_t *ldst_xor, *lsrcdst_cpy;
  const uintptr_t *lsrc;
  uintptr_t ltemp;
#ifndef BUFHELP_FAST_UNALIGNED_ACCESS
  const unsigned int longmask = sizeof(uintptr_t) - 1;

  /* Skip fast processing if alignment of buffers do not match.  */
  if ((((uintptr_t)src ^ (uintptr_t)dst_xor) |
       ((uintptr_t)src ^ (uintptr_t)srcdst_cpy)) & longmask)
    goto do_bytes;

  /* Handle unaligned head.  */
  for (; len && ((uintptr_t)src & longmask); len--)
    {
      temp = *src++;
      *dst_xor++ = *srcdst_cpy ^ temp;
      *srcdst_cpy++ = temp;
    }
#endif

  ldst_xor = (uintptr_t *)dst_xor;
  lsrcdst_cpy = (uintptr_t *)srcdst_cpy;
  lsrc = (const uintptr_t *)src;

  for (; len >= sizeof(uintptr_t); len -= sizeof(uintptr_t))
    {
      ltemp = *lsrc++;
      *ldst_xor++ = *lsrcdst_cpy ^ ltemp;
      *lsrcdst_cpy++ = ltemp;
    }

  dst_xor = (byte *)ldst_xor;
  srcdst_cpy = (byte *)lsrcdst_cpy;
  src = (const byte *)lsrc;

#ifndef BUFHELP_FAST_UNALIGNED_ACCESS
do_bytes:
#endif
  /* Handle tail.  */
  for (; len; len--)
    {
      temp = *src++;
      *dst_xor++ = *srcdst_cpy ^ temp;
      *srcdst_cpy++ = temp;
    }
}

#endif /*G10_BITHELP_H*/
