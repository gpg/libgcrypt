/* cipher-ocb.c -  OCB cipher mode
 * Copyright (C) 2015, 2016 g10 Code GmbH
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *
 * OCB is covered by several patents but may be used freely by most
 * software.  See http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm .
 * In particular license 1 is suitable for Libgcrypt: See
 * http://web.cs.ucdavis.edu/~rogaway/ocb/license1.pdf for the full
 * license document; it basically says:
 *
 *   License 1 — License for Open-Source Software Implementations of OCB
 *               (Jan 9, 2013)
 *
 *   Under this license, you are authorized to make, use, and
 *   distribute open-source software implementations of OCB. This
 *   license terminates for you if you sue someone over their
 *   open-source software implementation of OCB claiming that you have
 *   a patent covering their implementation.
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "./cipher-internal.h"


/* Double the OCB_BLOCK_LEN sized block B in-place.  */
static inline void
double_block (unsigned char *b)
{
#if OCB_BLOCK_LEN != 16
  unsigned char b_0 = b[0];
  int i;

  for (i=0; i < OCB_BLOCK_LEN - 1; i++)
    b[i] = (b[i] << 1) | (b[i+1] >> 7);

  b[OCB_BLOCK_LEN-1] = (b[OCB_BLOCK_LEN-1] << 1) ^ ((b_0 >> 7) * 135);
#else
  /* This is the generic code for 16 byte blocks.  However it is not
     faster than the straight byte by byte implementation.  */
  u64 l_0, l, r;

  l = buf_get_be64 (b);
  r = buf_get_be64 (b + 8);

  l_0 = (int64_t)l >> 63;
  l = (l + l) ^ (r >> 63);
  r = (r + r) ^ (l_0 & 135);

  buf_put_be64 (b, l);
  buf_put_be64 (b+8, r);
#endif
}


/* Double the OCB_BLOCK_LEN sized block S and store it at D.  S and D
   may point to the same memory location but they may not overlap.  */
static void
double_block_cpy (unsigned char *d, const unsigned char *s)
{
  if (d != s)
    buf_cpy (d, s, OCB_BLOCK_LEN);
  double_block (d);
}


/* Copy NBYTES from buffer S starting at bit offset BITOFF to buffer D.  */
static void
bit_copy (unsigned char *d, const unsigned char *s,
          unsigned int bitoff, unsigned int nbytes)
{
  unsigned int shift;

  s += bitoff / 8;
  shift = bitoff % 8;
  if (shift)
    {
      for (; nbytes; nbytes--, d++, s++)
        *d = (s[0] << shift) | (s[1] >> (8 - shift));
    }
  else
    {
      for (; nbytes; nbytes--, d++, s++)
        *d = *s;
    }
}


/* Return the L-value for block N.  In most cases we use the table;
   only if the lower OCB_L_TABLE_SIZE bits of N are zero we need to
   compute it.  With a table size of 16 we need to this this only
   every 65536-th block.  L_TMP is a helper buffer of size
   OCB_BLOCK_LEN which is used to hold the computation if not taken
   from the table.  */
const unsigned char *
_gcry_cipher_ocb_get_l (gcry_cipher_hd_t c, unsigned char *l_tmp, u64 n)
{
  int ntz = _gcry_ctz64 (n);

  if (ntz < OCB_L_TABLE_SIZE)
    return c->u_mode.ocb.L[ntz];

  double_block_cpy (l_tmp, c->u_mode.ocb.L[OCB_L_TABLE_SIZE - 1]);
  for (ntz -= OCB_L_TABLE_SIZE; ntz; ntz--)
    double_block (l_tmp);

  return l_tmp;
}


/* Set the nonce for OCB.  This requires that the key has been set.
   Using it again resets start a new encryption cycle using the same
   key.  */
gcry_err_code_t
_gcry_cipher_ocb_set_nonce (gcry_cipher_hd_t c, const unsigned char *nonce,
                            size_t noncelen)
{
  unsigned char ktop[OCB_BLOCK_LEN];
  unsigned char stretch[OCB_BLOCK_LEN + 8];
  unsigned int bottom;
  int i;
  unsigned int burn = 0;
  unsigned int nburn;

  /* Check args.  */
  if (!c->marks.key)
    return GPG_ERR_INV_STATE;  /* Key must have been set first.  */
  switch (c->u_mode.ocb.taglen)
    {
    case 8:
    case 12:
    case 16:
      break;
    default:
      return GPG_ERR_BUG; /* Invalid tag length. */
    }

  if (c->spec->blocksize != OCB_BLOCK_LEN)
    return GPG_ERR_CIPHER_ALGO;
  if (!nonce)
    return GPG_ERR_INV_ARG;
  /* 120 bit is the allowed maximum.  In addition we impose a minimum
     of 64 bit.  */
  if (noncelen > (120/8) || noncelen < (64/8) || noncelen >= OCB_BLOCK_LEN)
    return GPG_ERR_INV_LENGTH;

  /* Set up the L table.  */
  /* L_star = E(zero_128) */
  memset (ktop, 0, OCB_BLOCK_LEN);
  nburn = c->spec->encrypt (&c->context.c, c->u_mode.ocb.L_star, ktop);
  burn = nburn > burn ? nburn : burn;
  /* L_dollar = double(L_star)  */
  double_block_cpy (c->u_mode.ocb.L_dollar, c->u_mode.ocb.L_star);
  /* L_0 = double(L_dollar), ...  */
  double_block_cpy (c->u_mode.ocb.L[0], c->u_mode.ocb.L_dollar);
  for (i = 1; i < OCB_L_TABLE_SIZE; i++)
    double_block_cpy (c->u_mode.ocb.L[i], c->u_mode.ocb.L[i-1]);

  /* Prepare the nonce.  */
  memset (ktop, 0, (OCB_BLOCK_LEN - noncelen));
  buf_cpy (ktop + (OCB_BLOCK_LEN - noncelen), nonce, noncelen);
  ktop[0] = ((c->u_mode.ocb.taglen * 8) % 128) << 1;
  ktop[OCB_BLOCK_LEN - noncelen - 1] |= 1;
  bottom = ktop[OCB_BLOCK_LEN - 1] & 0x3f;
  ktop[OCB_BLOCK_LEN - 1] &= 0xc0; /* Zero the bottom bits.  */
  nburn = c->spec->encrypt (&c->context.c, ktop, ktop);
  burn = nburn > burn ? nburn : burn;
  /* Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) */
  buf_cpy (stretch, ktop, OCB_BLOCK_LEN);
  buf_xor (stretch + OCB_BLOCK_LEN, ktop, ktop + 1, 8);
  /* Offset_0 = Stretch[1+bottom..128+bottom]
     (We use the IV field to store the offset) */
  bit_copy (c->u_iv.iv, stretch, bottom, OCB_BLOCK_LEN);
  c->marks.iv = 1;

  /* Checksum_0 = zeros(128)
     (We use the CTR field to store the checksum) */
  memset (c->u_ctr.ctr, 0, OCB_BLOCK_LEN);

  /* Clear AAD buffer.  */
  memset (c->u_mode.ocb.aad_offset, 0, OCB_BLOCK_LEN);
  memset (c->u_mode.ocb.aad_sum, 0, OCB_BLOCK_LEN);

  /* Setup other values.  */
  memset (c->lastiv, 0, sizeof(c->lastiv));
  c->unused = 0;
  c->marks.tag = 0;
  c->marks.finalize = 0;
  c->u_mode.ocb.data_nblocks = 0;
  c->u_mode.ocb.aad_nblocks = 0;
  c->u_mode.ocb.aad_nleftover = 0;
  c->u_mode.ocb.data_finalized = 0;
  c->u_mode.ocb.aad_finalized = 0;

  /* log_printhex ("L_*       ", c->u_mode.ocb.L_star, OCB_BLOCK_LEN); */
  /* log_printhex ("L_$       ", c->u_mode.ocb.L_dollar, OCB_BLOCK_LEN); */
  /* log_printhex ("L_0       ", c->u_mode.ocb.L[0], OCB_BLOCK_LEN); */
  /* log_printhex ("L_1       ", c->u_mode.ocb.L[1], OCB_BLOCK_LEN); */
  /* log_debug (   "bottom    : %u (decimal)\n", bottom); */
  /* log_printhex ("Ktop      ", ktop, OCB_BLOCK_LEN); */
  /* log_printhex ("Stretch   ", stretch, sizeof stretch); */
  /* log_printhex ("Offset_0  ", c->u_iv.iv, OCB_BLOCK_LEN); */

  /* Cleanup */
  wipememory (ktop, sizeof ktop);
  wipememory (stretch, sizeof stretch);
  if (burn > 0)
    _gcry_burn_stack (burn + 4*sizeof(void*));

  return 0;
}


/* Process additional authentication data.  This implementation allows
   to add additional authentication data at any time before the final
   gcry_cipher_gettag.  */
gcry_err_code_t
_gcry_cipher_ocb_authenticate (gcry_cipher_hd_t c, const unsigned char *abuf,
                               size_t abuflen)
{
  unsigned char l_tmp[OCB_BLOCK_LEN];

  /* Check that a nonce and thus a key has been set and that we have
     not yet computed the tag.  We also return an error if the aad has
     been finalized (i.e. a short block has been processed).  */
  if (!c->marks.iv || c->marks.tag || c->u_mode.ocb.aad_finalized)
    return GPG_ERR_INV_STATE;

  /* Check correct usage and arguments.  */
  if (c->spec->blocksize != OCB_BLOCK_LEN)
    return GPG_ERR_CIPHER_ALGO;

  /* Process remaining data from the last call first.  */
  if (c->u_mode.ocb.aad_nleftover)
    {
      for (; abuflen && c->u_mode.ocb.aad_nleftover < OCB_BLOCK_LEN;
           abuf++, abuflen--)
        c->u_mode.ocb.aad_leftover[c->u_mode.ocb.aad_nleftover++] = *abuf;

      if (c->u_mode.ocb.aad_nleftover == OCB_BLOCK_LEN)
        {
          c->u_mode.ocb.aad_nblocks++;

          /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
          buf_xor_1 (c->u_mode.ocb.aad_offset,
                     ocb_get_l (c, l_tmp, c->u_mode.ocb.aad_nblocks),
                     OCB_BLOCK_LEN);
          /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
          buf_xor (l_tmp, c->u_mode.ocb.aad_offset,
                   c->u_mode.ocb.aad_leftover, OCB_BLOCK_LEN);
          c->spec->encrypt (&c->context.c, l_tmp, l_tmp);
          buf_xor_1 (c->u_mode.ocb.aad_sum, l_tmp, OCB_BLOCK_LEN);

          c->u_mode.ocb.aad_nleftover = 0;
        }
    }

  if (!abuflen)
    return 0;

  /* Use a bulk method if available.  */
  if (abuflen >= OCB_BLOCK_LEN && c->bulk.ocb_auth)
    {
      size_t nblks;
      size_t nleft;
      size_t ndone;

      nblks = abuflen / OCB_BLOCK_LEN;
      nleft = c->bulk.ocb_auth (c, abuf, nblks);
      ndone = nblks - nleft;

      abuf += ndone * OCB_BLOCK_LEN;
      abuflen -= ndone * OCB_BLOCK_LEN;
      nblks = nleft;
    }

  /* Hash all full blocks.  */
  while (abuflen >= OCB_BLOCK_LEN)
    {
      c->u_mode.ocb.aad_nblocks++;

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      buf_xor_1 (c->u_mode.ocb.aad_offset,
                 ocb_get_l (c, l_tmp, c->u_mode.ocb.aad_nblocks),
                 OCB_BLOCK_LEN);
      /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
      buf_xor (l_tmp, c->u_mode.ocb.aad_offset, abuf, OCB_BLOCK_LEN);
      c->spec->encrypt (&c->context.c, l_tmp, l_tmp);
      buf_xor_1 (c->u_mode.ocb.aad_sum, l_tmp, OCB_BLOCK_LEN);

      abuf += OCB_BLOCK_LEN;
      abuflen -= OCB_BLOCK_LEN;
    }

  /* Store away the remaining data.  */
  for (; abuflen && c->u_mode.ocb.aad_nleftover < OCB_BLOCK_LEN;
       abuf++, abuflen--)
    c->u_mode.ocb.aad_leftover[c->u_mode.ocb.aad_nleftover++] = *abuf;
  gcry_assert (!abuflen);

  return 0;
}


/* Hash final partial AAD block.  */
static void
ocb_aad_finalize (gcry_cipher_hd_t c)
{
  unsigned char l_tmp[OCB_BLOCK_LEN];

  /* Check that a nonce and thus a key has been set and that we have
     not yet computed the tag.  We also skip this if the aad has been
     finalized.  */
  if (!c->marks.iv || c->marks.tag || c->u_mode.ocb.aad_finalized)
    return;
  if (c->spec->blocksize != OCB_BLOCK_LEN)
    return;  /* Ooops.  */

  /* Hash final partial block if any.  */
  if (c->u_mode.ocb.aad_nleftover)
    {
      /* Offset_* = Offset_m xor L_*  */
      buf_xor_1 (c->u_mode.ocb.aad_offset,
                 c->u_mode.ocb.L_star, OCB_BLOCK_LEN);
      /* CipherInput = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_*  */
      buf_cpy (l_tmp, c->u_mode.ocb.aad_leftover, c->u_mode.ocb.aad_nleftover);
      memset (l_tmp + c->u_mode.ocb.aad_nleftover, 0,
              OCB_BLOCK_LEN - c->u_mode.ocb.aad_nleftover);
      l_tmp[c->u_mode.ocb.aad_nleftover] = 0x80;
      buf_xor_1 (l_tmp, c->u_mode.ocb.aad_offset, OCB_BLOCK_LEN);
      /* Sum = Sum_m xor ENCIPHER(K, CipherInput)  */
      c->spec->encrypt (&c->context.c, l_tmp, l_tmp);
      buf_xor_1 (c->u_mode.ocb.aad_sum, l_tmp, OCB_BLOCK_LEN);

      c->u_mode.ocb.aad_nleftover = 0;
    }

  /* Mark AAD as finalized so that gcry_cipher_ocb_authenticate can
   * return an erro when called again.  */
  c->u_mode.ocb.aad_finalized = 1;
}



/* Checksumming for encrypt and decrypt.  */
static void
ocb_checksum (unsigned char *chksum, const unsigned char *plainbuf,
              size_t nblks)
{
  while (nblks > 0)
    {
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      buf_xor_1(chksum, plainbuf, OCB_BLOCK_LEN);

      plainbuf += OCB_BLOCK_LEN;
      nblks--;
    }
}


/* Common code for encrypt and decrypt.  */
static gcry_err_code_t
ocb_crypt (gcry_cipher_hd_t c, int encrypt,
           unsigned char *outbuf, size_t outbuflen,
           const unsigned char *inbuf, size_t inbuflen)
{
  unsigned char l_tmp[OCB_BLOCK_LEN];
  unsigned int burn = 0;
  unsigned int nburn;
  size_t nblks = inbuflen / OCB_BLOCK_LEN;

  /* Check that a nonce and thus a key has been set and that we are
     not yet in end of data state. */
  if (!c->marks.iv || c->u_mode.ocb.data_finalized)
    return GPG_ERR_INV_STATE;

  /* Check correct usage and arguments.  */
  if (c->spec->blocksize != OCB_BLOCK_LEN)
    return GPG_ERR_CIPHER_ALGO;
  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;
  if (c->marks.finalize)
    ; /* Allow arbitarty length. */
  else if ((inbuflen % OCB_BLOCK_LEN))
    return GPG_ERR_INV_LENGTH;  /* We support only full blocks for now.  */

  /* Use a bulk method if available.  */
  if (nblks && c->bulk.ocb_crypt)
    {
      size_t nleft;
      size_t ndone;

      nleft = c->bulk.ocb_crypt (c, outbuf, inbuf, nblks, encrypt);
      ndone = nblks - nleft;

      inbuf += ndone * OCB_BLOCK_LEN;
      outbuf += ndone * OCB_BLOCK_LEN;
      inbuflen -= ndone * OCB_BLOCK_LEN;
      outbuflen -= ndone * OCB_BLOCK_LEN;
      nblks = nleft;
    }

  if (nblks)
    {
      gcry_cipher_encrypt_t crypt_fn =
          encrypt ? c->spec->encrypt : c->spec->decrypt;

      if (encrypt)
        {
          /* Checksum_i = Checksum_{i-1} xor P_i  */
          ocb_checksum (c->u_ctr.ctr, inbuf, nblks);
        }

      /* Encrypt all full blocks.  */
      while (inbuflen >= OCB_BLOCK_LEN)
        {
          c->u_mode.ocb.data_nblocks++;

          /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
          buf_xor_1 (c->u_iv.iv,
                     ocb_get_l (c, l_tmp, c->u_mode.ocb.data_nblocks),
                     OCB_BLOCK_LEN);
          /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
          buf_xor (outbuf, c->u_iv.iv, inbuf, OCB_BLOCK_LEN);
          nburn = crypt_fn (&c->context.c, outbuf, outbuf);
          burn = nburn > burn ? nburn : burn;
          buf_xor_1 (outbuf, c->u_iv.iv, OCB_BLOCK_LEN);

          inbuf += OCB_BLOCK_LEN;
          inbuflen -= OCB_BLOCK_LEN;
          outbuf += OCB_BLOCK_LEN;
          outbuflen =- OCB_BLOCK_LEN;
        }

      if (!encrypt)
        {
          /* Checksum_i = Checksum_{i-1} xor P_i  */
          ocb_checksum (c->u_ctr.ctr, outbuf - nblks * OCB_BLOCK_LEN, nblks);
        }
    }

  /* Encrypt final partial block.  Note that we expect INBUFLEN to be
     shorter than OCB_BLOCK_LEN (see above).  */
  if (inbuflen)
    {
      unsigned char pad[OCB_BLOCK_LEN];

      /* Offset_* = Offset_m xor L_*  */
      buf_xor_1 (c->u_iv.iv, c->u_mode.ocb.L_star, OCB_BLOCK_LEN);
      /* Pad = ENCIPHER(K, Offset_*) */
      nburn = c->spec->encrypt (&c->context.c, pad, c->u_iv.iv);
      burn = nburn > burn ? nburn : burn;

      if (encrypt)
        {
          /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
          /* Note that INBUFLEN is less than OCB_BLOCK_LEN.  */
          buf_cpy (l_tmp, inbuf, inbuflen);
          memset (l_tmp + inbuflen, 0, OCB_BLOCK_LEN - inbuflen);
          l_tmp[inbuflen] = 0x80;
          buf_xor_1 (c->u_ctr.ctr, l_tmp, OCB_BLOCK_LEN);
          /* C_* = P_* xor Pad[1..bitlen(P_*)] */
          buf_xor (outbuf, inbuf, pad, inbuflen);
        }
      else
        {
          /* P_* = C_* xor Pad[1..bitlen(C_*)] */
          /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
          buf_cpy (l_tmp, pad, OCB_BLOCK_LEN);
          buf_cpy (l_tmp, inbuf, inbuflen);
          buf_xor_1 (l_tmp, pad, OCB_BLOCK_LEN);
          l_tmp[inbuflen] = 0x80;
          buf_cpy (outbuf, l_tmp, inbuflen);

          buf_xor_1 (c->u_ctr.ctr, l_tmp, OCB_BLOCK_LEN);
        }
    }

  /* Compute the tag if the finalize flag has been set.  */
  if (c->marks.finalize)
    {
      /* Tag = ENCIPHER(K, Checksum xor Offset xor L_$) xor HASH(K,A) */
      buf_xor (c->u_mode.ocb.tag, c->u_ctr.ctr, c->u_iv.iv, OCB_BLOCK_LEN);
      buf_xor_1 (c->u_mode.ocb.tag, c->u_mode.ocb.L_dollar, OCB_BLOCK_LEN);
      nburn = c->spec->encrypt (&c->context.c,
                                c->u_mode.ocb.tag, c->u_mode.ocb.tag);
      burn = nburn > burn ? nburn : burn;

      c->u_mode.ocb.data_finalized = 1;
      /* Note that the the final part of the tag computation is done
         by _gcry_cipher_ocb_get_tag.  */
    }

  if (burn > 0)
    _gcry_burn_stack (burn + 4*sizeof(void*));

  return 0;
}


/* Encrypt (INBUF,INBUFLEN) in OCB mode to OUTBUF.  OUTBUFLEN gives
   the allocated size of OUTBUF.  This function accepts only multiples
   of a full block unless gcry_cipher_final has been called in which
   case the next block may have any length.  */
gcry_err_code_t
_gcry_cipher_ocb_encrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, size_t outbuflen,
                          const unsigned char *inbuf, size_t inbuflen)

{
  return ocb_crypt (c, 1, outbuf, outbuflen, inbuf, inbuflen);
}


/* Decrypt (INBUF,INBUFLEN) in OCB mode to OUTBUF.  OUTBUFLEN gives
   the allocated size of OUTBUF.  This function accepts only multiples
   of a full block unless gcry_cipher_final has been called in which
   case the next block may have any length.  */
gcry_err_code_t
_gcry_cipher_ocb_decrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, size_t outbuflen,
                          const unsigned char *inbuf, size_t inbuflen)
{
  return ocb_crypt (c, 0, outbuf, outbuflen, inbuf, inbuflen);
}


/* Compute the tag.  The last data operation has already done some
   part of it.  To allow adding AAD even after having done all data,
   we finish the tag computation only here.  */
static void
compute_tag_if_needed (gcry_cipher_hd_t c)
{
  if (!c->marks.tag)
    {
      ocb_aad_finalize (c);
      buf_xor_1 (c->u_mode.ocb.tag, c->u_mode.ocb.aad_sum, OCB_BLOCK_LEN);
      c->marks.tag = 1;
    }
}


/* Copy the already computed tag to OUTTAG.  OUTTAGSIZE is the
   allocated size of OUTTAG; the function returns an error if that is
   too short to hold the tag.  */
gcry_err_code_t
_gcry_cipher_ocb_get_tag (gcry_cipher_hd_t c,
                          unsigned char *outtag, size_t outtagsize)
{
  if (c->u_mode.ocb.taglen > outtagsize)
    return GPG_ERR_BUFFER_TOO_SHORT;
  if (!c->u_mode.ocb.data_finalized)
    return GPG_ERR_INV_STATE; /* Data has not yet been finalized.  */

  compute_tag_if_needed (c);

  memcpy (outtag, c->u_mode.ocb.tag, c->u_mode.ocb.taglen);

  return 0;
}


/* Check that the tag (INTAG,TAGLEN) matches the computed tag for the
   handle C.  */
gcry_err_code_t
_gcry_cipher_ocb_check_tag (gcry_cipher_hd_t c, const unsigned char *intag,
			    size_t taglen)
{
  size_t n;

  if (!c->u_mode.ocb.data_finalized)
    return GPG_ERR_INV_STATE; /* Data has not yet been finalized.  */

  compute_tag_if_needed (c);

  n = c->u_mode.ocb.taglen;
  if (taglen < n)
    n = taglen;

  if (!buf_eq_const (intag, c->u_mode.ocb.tag, n)
      || c->u_mode.ocb.taglen != taglen)
    return GPG_ERR_CHECKSUM;

  return 0;
}
