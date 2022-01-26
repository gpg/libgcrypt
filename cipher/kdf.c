/* kdf.c  - Key Derivation Functions
 * Copyright (C) 1998, 2008, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
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
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "kdf-internal.h"


/* Transform a passphrase into a suitable key of length KEYSIZE and
   store this key in the caller provided buffer KEYBUFFER.  The caller
   must provide an HASHALGO, a valid ALGO and depending on that algo a
   SALT of 8 bytes and the number of ITERATIONS.  Code taken from
   gnupg/agent/protect.c:hash_passphrase.  */
static gpg_err_code_t
openpgp_s2k (const void *passphrase, size_t passphraselen,
             int algo, int hashalgo,
             const void *salt, size_t saltlen,
             unsigned long iterations,
             size_t keysize, void *keybuffer)
{
  gpg_err_code_t ec;
  gcry_md_hd_t md;
  char *key = keybuffer;
  int pass, i;
  int used = 0;
  int secmode;

  if ((algo == GCRY_KDF_SALTED_S2K || algo == GCRY_KDF_ITERSALTED_S2K)
      && (!salt || saltlen != 8))
    return GPG_ERR_INV_VALUE;

  secmode = _gcry_is_secure (passphrase) || _gcry_is_secure (keybuffer);

  ec = _gcry_md_open (&md, hashalgo, secmode? GCRY_MD_FLAG_SECURE : 0);
  if (ec)
    return ec;

  for (pass=0; used < keysize; pass++)
    {
      if (pass)
        {
          _gcry_md_reset (md);
          for (i=0; i < pass; i++) /* Preset the hash context.  */
            _gcry_md_putc (md, 0);
        }

      if (algo == GCRY_KDF_SALTED_S2K || algo == GCRY_KDF_ITERSALTED_S2K)
        {
          int len2 = passphraselen + 8;
          unsigned long count = len2;

          if (algo == GCRY_KDF_ITERSALTED_S2K)
            {
              count = iterations;
              if (count < len2)
                count = len2;
            }

          while (count > len2)
            {
              _gcry_md_write (md, salt, saltlen);
              _gcry_md_write (md, passphrase, passphraselen);
              count -= len2;
            }
          if (count < saltlen)
            _gcry_md_write (md, salt, count);
          else
            {
              _gcry_md_write (md, salt, saltlen);
              count -= saltlen;
              _gcry_md_write (md, passphrase, count);
            }
        }
      else
        _gcry_md_write (md, passphrase, passphraselen);

      _gcry_md_final (md);
      i = _gcry_md_get_algo_dlen (hashalgo);
      if (i > keysize - used)
        i = keysize - used;
      memcpy (key+used, _gcry_md_read (md, hashalgo), i);
      used += i;
    }
  _gcry_md_close (md);
  return 0;
}


/* Transform a passphrase into a suitable key of length KEYSIZE and
   store this key in the caller provided buffer KEYBUFFER.  The caller
   must provide PRFALGO which indicates the pseudorandom function to
   use: This shall be the algorithms id of a hash algorithm; it is
   used in HMAC mode.  SALT is a salt of length SALTLEN and ITERATIONS
   gives the number of iterations.  */
gpg_err_code_t
_gcry_kdf_pkdf2 (const void *passphrase, size_t passphraselen,
                 int hashalgo,
                 const void *salt, size_t saltlen,
                 unsigned long iterations,
                 size_t keysize, void *keybuffer)
{
  gpg_err_code_t ec;
  gcry_md_hd_t md;
  int secmode;
  unsigned long dklen = keysize;
  char *dk = keybuffer;
  unsigned int hlen;   /* Output length of the digest function.  */
  unsigned int l;      /* Rounded up number of blocks.  */
  unsigned int r;      /* Number of octets in the last block.  */
  char *sbuf;          /* Malloced buffer to concatenate salt and iter
                          as well as space to hold TBUF and UBUF.  */
  char *tbuf;          /* Buffer for T; ptr into SBUF, size is HLEN. */
  char *ubuf;          /* Buffer for U; ptr into SBUF, size is HLEN. */
  unsigned int lidx;   /* Current block number.  */
  unsigned long iter;  /* Current iteration number.  */
  unsigned int i;

  /* We allow for a saltlen of 0 here to support scrypt.  It is not
     clear whether rfc2898 allows for this this, thus we do a test on
     saltlen > 0 only in gcry_kdf_derive.  */
  if (!salt || !iterations || !dklen)
    return GPG_ERR_INV_VALUE;

  hlen = _gcry_md_get_algo_dlen (hashalgo);
  if (!hlen)
    return GPG_ERR_DIGEST_ALGO;

  secmode = _gcry_is_secure (passphrase) || _gcry_is_secure (keybuffer);

  /* Step 1 */
  /* If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
   * stop.  We use a stronger inequality but only if our type can hold
   * a larger value.  */

#if SIZEOF_UNSIGNED_LONG > 4
  if (dklen > 0xffffffffU)
    return GPG_ERR_INV_VALUE;
#endif


  /* Step 2 */
  l = ((dklen - 1)/ hlen) + 1;
  r = dklen - (l - 1) * hlen;

  /* Setup buffers and prepare a hash context.  */
  sbuf = (secmode
          ? xtrymalloc_secure (saltlen + 4 + hlen + hlen)
          : xtrymalloc (saltlen + 4 + hlen + hlen));
  if (!sbuf)
    return gpg_err_code_from_syserror ();
  tbuf = sbuf + saltlen + 4;
  ubuf = tbuf + hlen;

  ec = _gcry_md_open (&md, hashalgo, (GCRY_MD_FLAG_HMAC
                                      | (secmode?GCRY_MD_FLAG_SECURE:0)));
  if (ec)
    {
      xfree (sbuf);
      return ec;
    }

  ec = _gcry_md_setkey (md, passphrase, passphraselen);
  if (ec)
    {
      _gcry_md_close (md);
      xfree (sbuf);
      return ec;
    }

  /* Step 3 and 4. */
  memcpy (sbuf, salt, saltlen);
  for (lidx = 1; lidx <= l; lidx++)
    {
      for (iter = 0; iter < iterations; iter++)
        {
          _gcry_md_reset (md);
          if (!iter) /* Compute U_1:  */
            {
              sbuf[saltlen]     = (lidx >> 24);
              sbuf[saltlen + 1] = (lidx >> 16);
              sbuf[saltlen + 2] = (lidx >> 8);
              sbuf[saltlen + 3] = lidx;
              _gcry_md_write (md, sbuf, saltlen + 4);
              memcpy (ubuf, _gcry_md_read (md, 0), hlen);
              memcpy (tbuf, ubuf, hlen);
            }
          else /* Compute U_(2..c):  */
            {
              _gcry_md_write (md, ubuf, hlen);
              memcpy (ubuf, _gcry_md_read (md, 0), hlen);
              for (i=0; i < hlen; i++)
                tbuf[i] ^= ubuf[i];
            }
        }
      if (lidx == l)  /* Last block.  */
        memcpy (dk, tbuf, r);
      else
        {
          memcpy (dk, tbuf, hlen);
          dk += hlen;
        }
    }

  _gcry_md_close (md);
  xfree (sbuf);
  return 0;
}


/* Derive a key from a passphrase.  KEYSIZE gives the requested size
   of the keys in octets.  KEYBUFFER is a caller provided buffer
   filled on success with the derived key.  The input passphrase is
   taken from (PASSPHRASE,PASSPHRASELEN) which is an arbitrary memory
   buffer.  ALGO specifies the KDF algorithm to use; these are the
   constants GCRY_KDF_*.  SUBALGO specifies an algorithm used
   internally by the KDF algorithms; this is usually a hash algorithm
   but certain KDF algorithm may use it differently.  {SALT,SALTLEN}
   is a salt as needed by most KDF algorithms.  ITERATIONS is a
   positive integer parameter to most KDFs.  0 is returned on success,
   or an error code on failure.  */
gpg_err_code_t
_gcry_kdf_derive (const void *passphrase, size_t passphraselen,
                  int algo, int subalgo,
                  const void *salt, size_t saltlen,
                  unsigned long iterations,
                  size_t keysize, void *keybuffer)
{
  gpg_err_code_t ec;

  if (!passphrase)
    {
      ec = GPG_ERR_INV_DATA;
      goto leave;
    }

  if (!keybuffer || !keysize)
    {
      ec = GPG_ERR_INV_VALUE;
      goto leave;
    }


  switch (algo)
    {
    case GCRY_KDF_SIMPLE_S2K:
    case GCRY_KDF_SALTED_S2K:
    case GCRY_KDF_ITERSALTED_S2K:
      if (!passphraselen)
        ec = GPG_ERR_INV_DATA;
      else
        ec = openpgp_s2k (passphrase, passphraselen, algo, subalgo,
                          salt, saltlen, iterations, keysize, keybuffer);
      break;

    case GCRY_KDF_PBKDF1:
      ec = GPG_ERR_UNSUPPORTED_ALGORITHM;
      break;

    case GCRY_KDF_PBKDF2:
      if (!saltlen)
        ec = GPG_ERR_INV_VALUE;
      else
        ec = _gcry_kdf_pkdf2 (passphrase, passphraselen, subalgo,
                              salt, saltlen, iterations, keysize, keybuffer);
      break;

    case 41:
    case GCRY_KDF_SCRYPT:
#if USE_SCRYPT
      ec = _gcry_kdf_scrypt (passphrase, passphraselen, algo, subalgo,
                             salt, saltlen, iterations, keysize, keybuffer);
#else
      ec = GPG_ERR_UNSUPPORTED_ALGORITHM;
#endif /*USE_SCRYPT*/
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

 leave:
  return ec;
}

#include "bufhelp.h"

typedef struct argon2_context *argon2_ctx_t;

/* Per thread data for Argon2.  */
struct argon2_thread_data {
  argon2_ctx_t a;
  union {
    void *user_data;
    gpg_err_code_t ec;
  } u;

  unsigned int pass;
  unsigned int slice;
  unsigned int lane;
};

/* Argon2 context */
struct argon2_context {
  int algo;
  int hash_type;

  unsigned int outlen;
  unsigned int n_threads;

  const unsigned char *password;
  size_t passwordlen;

  const unsigned char *salt;
  size_t saltlen;

  const unsigned char *key;
  size_t keylen;

  const unsigned char *ad;
  size_t adlen;

  unsigned int m_cost;

  unsigned int passes;
  unsigned int memory_blocks;
  unsigned int segment_length;
  unsigned int lane_length;
  unsigned int lanes;

  unsigned int step;

  unsigned int r;
  unsigned int s;
  unsigned int l;
  unsigned int t;

  gcry_md_hd_t hd;
  unsigned char *block;
  struct argon2_thread_data *thread_data;

  unsigned char out[1];  /* In future, we may use flexible array member.  */
};

enum argon2_iterator_step {
  ARGON2_ITERATOR_STEP0,
  ARGON2_ITERATOR_STEP1,
  ARGON2_ITERATOR_STEP2,
  ARGON2_ITERATOR_STEP3,
  ARGON2_ITERATOR_STEP4
};

#define ARGON2_VERSION 0x13

static gpg_err_code_t
hash (gcry_md_hd_t hd, const unsigned char *input, unsigned int inputlen,
      unsigned char *output, unsigned int outputlen)
{
  gpg_err_code_t ec = 0;
  unsigned char buf[4];
  const unsigned char *digest;
  gcry_md_hd_t hd1;
  int algo;

  _gcry_md_reset (hd);

  if (outputlen < 64)
    {
      if (outputlen == 48)
        algo = GCRY_MD_BLAKE2B_384;
      else if (outputlen == 32)
        algo = GCRY_MD_BLAKE2B_256;
      else if (outputlen == 20)
        algo = GCRY_MD_BLAKE2B_160;
      else
        return GPG_ERR_NOT_IMPLEMENTED;

      ec = _gcry_md_open (&hd1, algo, 0);
      if (ec)
        return ec;

      buf_put_le32 (buf, outputlen);
      _gcry_md_write (hd1, buf, 4);
      _gcry_md_write (hd1, input, inputlen);
      digest = _gcry_md_read (hd1, algo);
      memcpy (output, digest, outputlen);
      _gcry_md_close (hd1);
    }
  else if (outputlen == 64)
    {
      buf_put_le32 (buf, outputlen);
      _gcry_md_write (hd, buf, 4);
      _gcry_md_write (hd, input, inputlen);
      digest = _gcry_md_read (hd, GCRY_MD_BLAKE2B_512);
      memcpy (output, digest, 64);
    }
  else
    {
      int i, r;
      unsigned int remained;
      unsigned char d[64];

      i = 0;
      r = outputlen/32;

      buf_put_le32 (buf, outputlen);
      _gcry_md_write (hd, buf, 4);
      _gcry_md_write (hd, input, inputlen);

      do
        {
          digest = _gcry_md_read (hd, GCRY_MD_BLAKE2B_512);
          memcpy (d, digest, 64);
          memcpy (output+i*32, digest, 32);
          i++;

          _gcry_md_reset (hd);
          _gcry_md_write (hd, d, 64);
        }
      while (i < r);

      remained = outputlen - 32*r;
      if (remained)
        {
          if (remained == 20)
            algo = GCRY_MD_BLAKE2B_160;
          else
            return GPG_ERR_NOT_IMPLEMENTED;

          ec = _gcry_md_open (&hd1, algo, 0);
          if (ec)
            return ec;

          _gcry_md_write (hd1, d, 64);
          digest = _gcry_md_read (hd1, algo);
          memcpy (output+r*32, digest, remained);
          _gcry_md_close (hd1);
        }
    }

  return 0;
}

static gpg_err_code_t
argon2_genh0_first_blocks (argon2_ctx_t a)
{
  gpg_err_code_t ec = 0;
  unsigned char h0_01_i[72];
  const unsigned char *digest;
  unsigned char buf[4];
  int i;

  buf_put_le32 (buf, a->lanes);
  _gcry_md_write (a->hd, buf, 4);

  buf_put_le32 (buf, a->outlen);
  _gcry_md_write (a->hd, buf, 4);

  buf_put_le32 (buf, a->m_cost);
  _gcry_md_write (a->hd, buf, 4);

  buf_put_le32 (buf, a->passes);
  _gcry_md_write (a->hd, buf, 4);

  buf_put_le32 (buf, ARGON2_VERSION);
  _gcry_md_write (a->hd, buf, 4);

  buf_put_le32 (buf, a->hash_type);
  _gcry_md_write (a->hd, buf, 4);

  buf_put_le32 (buf, a->passwordlen);
  _gcry_md_write (a->hd, buf, 4);
  _gcry_md_write (a->hd, a->password, a->passwordlen);

  buf_put_le32 (buf, a->saltlen);
  _gcry_md_write (a->hd, buf, 4);
  _gcry_md_write (a->hd, a->salt, a->saltlen);

  buf_put_le32 (buf, a->keylen);
  _gcry_md_write (a->hd, buf, 4);
  if (a->key)
    _gcry_md_write (a->hd, a->key, a->keylen);

  buf_put_le32 (buf, a->adlen);
  _gcry_md_write (a->hd, buf, 4);
  if (a->ad)
    _gcry_md_write (a->hd, a->ad, a->adlen);

  digest = _gcry_md_read (a->hd, GCRY_MD_BLAKE2B_512);

  memcpy (h0_01_i, digest, 64);

  for (i = 0; i < a->lanes; i++)
    {
      /*FIXME*/
      memset (h0_01_i+64, 0, 4);
      buf_put_le32 (h0_01_i+64+4, i);
      ec = hash (a->hd, h0_01_i, 72, a->block+1024*i, 1024);
      if (ec)
        break;

      buf_put_le32 (h0_01_i+64, 1);
      ec = hash (a->hd, h0_01_i, 72, a->block+1024*(i+a->lanes), 1024);
      if (ec)
        break;
    }

  return ec;
}

static gpg_err_code_t
argon2_init (argon2_ctx_t a, unsigned int parallelism,
             unsigned int m_cost, unsigned int t_cost)
{
  gpg_err_code_t ec = 0;
  unsigned int memory_blocks;
  unsigned int segment_length;
  gcry_md_hd_t hd;
  void *block;
  struct argon2_thread_data *thread_data;

  memory_blocks = m_cost;
  if (memory_blocks < 8 * parallelism)
    memory_blocks = 8 * parallelism;

  segment_length = memory_blocks / (parallelism * 4);
  memory_blocks = segment_length * parallelism * 4;

  a->passes = t_cost;
  a->memory_blocks = memory_blocks;
  a->segment_length = segment_length;
  a->lane_length = segment_length * 4;
  a->lanes = parallelism;

  a->r = a->s = a->l = a->t = 0;
  a->step = ARGON2_ITERATOR_STEP0;

  a->hd = NULL;
  a->block = NULL;
  a->thread_data = NULL;

  ec = _gcry_md_open (&hd, GCRY_MD_BLAKE2B_512, 0);
  if (ec)
    return ec;

  block = xtrymalloc (1024 * memory_blocks);
  if (!block)
    {
      ec = gpg_err_code_from_errno (errno);
      _gcry_md_close (hd);
      return ec;
    }
  memset (block, 0, 1024 * memory_blocks);

  thread_data = xtrymalloc (a->n_threads * sizeof (struct argon2_thread_data));
  if (!thread_data)
    {
      ec = gpg_err_code_from_errno (errno);
      xfree (block);
      _gcry_md_close (hd);
      return ec;
    }

  memset (thread_data, 0, a->n_threads * sizeof (struct argon2_thread_data));

  a->hd = hd;
  a->block = block;
  a->thread_data = thread_data;
  return 0;
}

static gpg_err_code_t
argon2_ctl (argon2_ctx_t a, int cmd, void *buffer, size_t buflen)
{
  gpg_err_code_t ec = GPG_ERR_NOT_IMPLEMENTED;

  (void)a;
  (void)cmd;
  (void)buffer;
  (void)buflen;
  return ec;
}

static gpg_err_code_t
argon2_iterator (argon2_ctx_t a, int *action_p,
                 struct gcry_kdf_pt_head **t_p)
{
  switch (a->step)
    {
    case ARGON2_ITERATOR_STEP0:
      argon2_genh0_first_blocks (a);
      /* continue */
      *action_p = 3;
      *t_p = NULL;
      a->step = ARGON2_ITERATOR_STEP1;
      return 0;

    case ARGON2_ITERATOR_STEP1:
      for (a->r = 0; a->r < a->passes; a->r++)
        for (a->s = 0; a->s < 4; a->s++)
          {
            struct argon2_thread_data *thread_data;

            for (a->l = 0; a->l < a->lanes; a->l++)
              {
                if (a->l >= a->n_threads)
                  {
                    /* Join a thread.  */
                    thread_data = &a->thread_data[a->t];
                    *action_p = 2;
                    *t_p = (struct gcry_kdf_pt_head *)thread_data;
                    a->step = ARGON2_ITERATOR_STEP2;
                    return 0;

                  case ARGON2_ITERATOR_STEP2:
                    thread_data = &a->thread_data[a->t];
                    if (thread_data->u.ec)
                      return thread_data->u.ec;
                  }

                /* Create a thread.  */
                thread_data = &a->thread_data[a->t];
                thread_data->a = a;
                thread_data->u.user_data = NULL;
                thread_data->pass = a->r;
                thread_data->slice = a->s;
                thread_data->lane = a->l;
                *action_p = 1;
                *t_p = (struct gcry_kdf_pt_head *)thread_data;
                a->step = ARGON2_ITERATOR_STEP3;
                return 0;

              case ARGON2_ITERATOR_STEP3:
                a->t = (a->t + 1) % a->n_threads;
              }

            for (a->l = a->lanes - a->n_threads; a->l < a->lanes; a->l++)
              {
                thread_data = &a->thread_data[a->t];

                /* Join a thread.  */
                *action_p = 2;
                *t_p = (struct gcry_kdf_pt_head *)thread_data;
                a->step = ARGON2_ITERATOR_STEP4;
                return 0;

              case ARGON2_ITERATOR_STEP4:
                thread_data = &a->thread_data[a->t];
                if (thread_data->u.ec)
                  return thread_data->u.ec;
                a->t = (a->t + 1) % a->n_threads;
              }
          }
    }

  *action_p = 0;
  *t_p = NULL;
  a->step = ARGON2_ITERATOR_STEP0;
  return 0;
}

static void
argon2_pseudo_rand_gen (argon2_ctx_t a, const struct argon2_thread_data *t,
                        u32 *random_index)
{
  (void)a;
  (void)t;
  (void)random_index;
}

static gpg_err_code_t
argon2_compute_segment (argon2_ctx_t a, const struct argon2_thread_data *t)
{
  gpg_err_code_t ec = 0;
  u32 *random_index = NULL;
  int i;
  int prev_offset, curr_offset;

  if (a->hash_type == GCRY_KDF_ARGON2I
      || (a->hash_type == GCRY_KDF_ARGON2ID && t->pass == 0 && t->slice < 2))
    {
      random_index = xtrymalloc (sizeof (u32)*a->segment_length);
      if (!random_index)
        return gpg_err_code_from_errno (errno);
      argon2_pseudo_rand_gen (a, t, random_index);
    }

  if (t->pass == 0 && t->slice == 0)
    i = 2;
  else
    i = 0;

  curr_offset = t->lane * a->lane_length + t->slice * a->segment_length + i;
  if ((curr_offset % a->lane_length))
    prev_offset = curr_offset - 1;
  else
    prev_offset = curr_offset + a->lane_length - 1;

  for (; i < a->segment_length; i++, curr_offset++, prev_offset++)
    {
      /* Not yet implemented.  */;
    }

  xfree (random_index);
  return ec;
}


static gpg_err_code_t
argon2_final (argon2_ctx_t a, size_t resultlen, void *result)
{
  gpg_err_code_t ec;
  int i, j;

  if (resultlen != a->outlen)
    return GPG_ERR_INV_VALUE;

  memset (a->block, 0, 1024);
  for (i = 0; i < a->lanes; i++)
    {
      unsigned char *p0;
      unsigned char *p1;  /*FIXME*/

      p0 = a->block;
      p1 = p0 + a->lane_length * i + (a->segment_length - 1)*1024;

      for (j = 0; j < 1024; j++)
        p0[j] ^= p1[j];
    }

  ec = hash (a->hd, a->block, 1024, result, a->outlen);
  return ec;
}

static void
argon2_close (argon2_ctx_t a)
{
  size_t n;

  n = offsetof (struct argon2_context, out) + a->outlen;

  if (a->hd)
    _gcry_md_close (a->hd);

  if (a->block)
    {
      wipememory (a->block, 1024 * a->memory_blocks);
      xfree (a->block);
    }

  if (a->thread_data)
    xfree (a->thread_data);

  wipememory (a, n);
  xfree (a);
}

static gpg_err_code_t
argon2_open (gcry_kdf_hd_t *hd, int subalgo,
             const unsigned long *param, unsigned int paramlen,
             const void *password, size_t passwordlen,
             const void *salt, size_t saltlen,
             const void *key, size_t keylen,
             const void *ad, size_t adlen)
{
  int hash_type;
  unsigned int taglen;
  unsigned int t_cost;
  unsigned int m_cost;
  unsigned int parallelism = 1;
  unsigned int n_threads = 1;
  argon2_ctx_t a;
  gpg_err_code_t ec;
  size_t n;

  if (subalgo != GCRY_KDF_ARGON2D
      && subalgo != GCRY_KDF_ARGON2I
      && subalgo != GCRY_KDF_ARGON2ID)
    return GPG_ERR_INV_VALUE;
  else
    hash_type = subalgo;

  /* param : [ tag_length, t_cost, m_cost, parallelism, n_threads ] */
  if (paramlen < 3 || paramlen > 5)
    return GPG_ERR_INV_VALUE;
  else
    {
      taglen = (unsigned int)param[0];
      t_cost = (unsigned int)param[1];
      m_cost = (unsigned int)param[2];
      if (paramlen == 4)
        parallelism = (unsigned int)param[3];
      if (paramlen == 5)
        {
          n_threads = (unsigned int)param[4];
          if (n_threads > parallelism)
            n_threads = parallelism;
        }

      if (!(taglen == 64 || taglen == 48
            || taglen % 32 == 0 || taglen % 32 == 20))
        /*
         * FIXME: To support arbitrary taglen, we need to expose
         * internal API of Blake2b.
         */
        return GPG_ERR_NOT_IMPLEMENTED;
    }

  n = offsetof (struct argon2_context, out) + taglen;
  a = xtrymalloc (n);
  if (!a)
    return gpg_err_code_from_errno (errno);

  a->algo = GCRY_KDF_ARGON2;
  a->hash_type = hash_type;

  a->outlen = taglen;
  a->n_threads = n_threads;

  a->password = password;
  a->passwordlen = passwordlen;
  a->salt = salt;
  a->saltlen = saltlen;
  a->key = key;
  a->keylen = keylen;
  a->ad = ad;
  a->adlen = adlen;

  a->block = NULL;
  a->thread_data = NULL;

  ec = argon2_init (a, parallelism, m_cost, t_cost);
  if (ec)
    {
      xfree (a);
      return ec;
    }

  *hd = (void *)a;
  return 0;
}


static gpg_err_code_t
balloon_open (gcry_kdf_hd_t *hd, int subalgo,
              const unsigned long *param, unsigned int paramlen,
              const void *passphrase, size_t passphraselen,
              const void *salt, size_t saltlen)
{
  /*
   * It should have space_cost and time_cost.
   * Optionally, for parallelised version, it has parallelism.
   */
  if (paramlen != 2 && paramlen != 3)
    return GPG_ERR_INV_VALUE;

  (void)param;
  (void)subalgo;
  (void)passphrase;
  (void)passphraselen;
  (void)salt;
  (void)saltlen;
  *hd = NULL;
  return GPG_ERR_NOT_IMPLEMENTED;
}


struct gcry_kdf_handle {
  int algo;
  /* And algo specific parts come.  */
};

gpg_err_code_t
_gcry_kdf_open (gcry_kdf_hd_t *hd, int algo, int subalgo,
                const unsigned long *param, unsigned int paramlen,
                const void *passphrase, size_t passphraselen,
                const void *salt, size_t saltlen,
                const void *key, size_t keylen,
                const void *ad, size_t adlen)
{
  gpg_err_code_t ec;

  switch (algo)
    {
    case GCRY_KDF_ARGON2:
      if (!passphraselen || !saltlen)
        ec = GPG_ERR_INV_VALUE;
      else
        ec = argon2_open (hd, subalgo, param, paramlen,
                          passphrase, passphraselen, salt, saltlen,
                          key, keylen, ad, adlen);
      break;

    case GCRY_KDF_BALLOON:
      if (!passphraselen || !saltlen)
        ec = GPG_ERR_INV_VALUE;
      else
        {
          (void)key;
          (void)keylen;
          (void)ad;
          (void)adlen;
          ec = balloon_open (hd, subalgo, param, paramlen,
                             passphrase, passphraselen, salt, saltlen);
        }
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

  return ec;
}

gpg_err_code_t
_gcry_kdf_ctl (gcry_kdf_hd_t h, int cmd, void *buffer, size_t buflen)
{
  gpg_err_code_t ec;

  switch (h->algo)
    {
    case GCRY_KDF_ARGON2:
      ec = argon2_ctl ((argon2_ctx_t)h, cmd, buffer, buflen);
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

  return ec;
}

gpg_err_code_t
_gcry_kdf_iterator (gcry_kdf_hd_t h, int *action_p,
                    struct gcry_kdf_pt_head **t_p)
{
  gpg_err_code_t ec;

  switch (h->algo)
    {
    case GCRY_KDF_ARGON2:
      ec = argon2_iterator ((argon2_ctx_t)h, action_p, t_p);
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

  return ec;
}

gpg_err_code_t
_gcry_kdf_compute_segment (gcry_kdf_hd_t h, const struct gcry_kdf_pt_head *t)
{
  gpg_err_code_t ec;

  switch (h->algo)
    {
    case GCRY_KDF_ARGON2:
      ec = argon2_compute_segment ((argon2_ctx_t)h,
                                   (const struct argon2_thread_data *)t);
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

  return ec;
}


gpg_err_code_t
_gcry_kdf_final (gcry_kdf_hd_t h, size_t resultlen, void *result)
{
  gpg_err_code_t ec;

  switch (h->algo)
    {
    case GCRY_KDF_ARGON2:
      ec = argon2_final ((argon2_ctx_t)h, resultlen, result);
      break;

    default:
      ec = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }

  return ec;
}

void
_gcry_kdf_close (gcry_kdf_hd_t h)
{
  switch (h->algo)
    {
    case GCRY_KDF_ARGON2:
      argon2_close ((argon2_ctx_t)h);
      break;

    default:
      break;
    }
}

/* Check one KDF call with ALGO and HASH_ALGO using the regular KDF
 * API. (passphrase,passphraselen) is the password to be derived,
 * (salt,saltlen) the salt for the key derivation,
 * iterations is the number of the kdf iterations,
 * and (expect,expectlen) the expected result. Returns NULL on
 * success or a string describing the failure.  */

static const char *
check_one (int algo, int hash_algo,
           const void *passphrase, size_t passphraselen,
           const void *salt, size_t saltlen,
           unsigned long iterations,
           const void *expect, size_t expectlen)
{
  unsigned char key[512]; /* hardcoded to avoid allocation */
  size_t keysize = expectlen;

  /* Skip test with shoter passphrase in FIPS mode.  */
  if (fips_mode () && passphraselen < 14)
    return NULL;

  if (keysize > sizeof(key))
    return "invalid tests data";

  if (_gcry_kdf_derive (passphrase, passphraselen, algo,
                        hash_algo, salt, saltlen, iterations,
                        keysize, key))
    return "gcry_kdf_derive failed";

  if (memcmp (key, expect, expectlen))
    return "does not match";

  return NULL;
}


static gpg_err_code_t
selftest_pbkdf2 (int extended, selftest_report_func_t report)
{
  static const struct {
    const char *desc;
    const char *p;   /* Passphrase.  */
    size_t plen;     /* Length of P. */
    const char *salt;
    size_t saltlen;
    int hashalgo;
    unsigned long c; /* Iterations.  */
    int dklen;       /* Requested key length.  */
    const char *dk;  /* Derived key.  */
    int disabled;
  } tv[] = {
#if USE_SHA1
#define NUM_TEST_VECTORS 9
    /* SHA1 test vectors are from RFC-6070.  */
    {
      "Basic PBKDF2 SHA1 #1",
      "password", 8,
      "salt", 4,
      GCRY_MD_SHA1,
      1,
      20,
      "\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9"
      "\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6"
    },
    {
      "Basic PBKDF2 SHA1 #2",
      "password", 8,
      "salt", 4,
      GCRY_MD_SHA1,
      2,
      20,
      "\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e"
      "\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57"
    },
    {
      "Basic PBKDF2 SHA1 #3",
      "password", 8,
      "salt", 4,
      GCRY_MD_SHA1,
      4096,
      20,
      "\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad"
      "\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1"
    },
    {
      "Basic PBKDF2 SHA1 #4",
      "password", 8,
      "salt", 4,
      GCRY_MD_SHA1,
      16777216,
      20,
      "\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94"
      "\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84",
      1 /* This test takes too long.  */
    },
    {
      "Basic PBKDF2 SHA1 #5",
      "passwordPASSWORDpassword", 24,
      "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
      GCRY_MD_SHA1,
      4096,
      25,
      "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8"
      "\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96"
      "\x4c\xf2\xf0\x70\x38"
    },
    {
      "Basic PBKDF2 SHA1 #6",
      "pass\0word", 9,
      "sa\0lt", 5,
      GCRY_MD_SHA1,
      4096,
      16,
      "\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37"
      "\xd7\xf0\x34\x25\xe0\xc3"
    },
    { /* empty password test, not in RFC-6070 */
      "Basic PBKDF2 SHA1 #7",
      "", 0,
      "salt", 4,
      GCRY_MD_SHA1,
      2,
      20,
      "\x13\x3a\x4c\xe8\x37\xb4\xd2\x52\x1e\xe2"
      "\xbf\x03\xe1\x1c\x71\xca\x79\x4e\x07\x97"
    },
#else
#define NUM_TEST_VECTORS 2
#endif
    {
      "Basic PBKDF2 SHA256",
      "password", 8,
      "salt", 4,
      GCRY_MD_SHA256,
      2,
      32,
      "\xae\x4d\x0c\x95\xaf\x6b\x46\xd3\x2d\x0a\xdf\xf9\x28\xf0\x6d\xd0"
      "\x2a\x30\x3f\x8e\xf3\xc2\x51\xdf\xd6\xe2\xd8\x5a\x95\x47\x4c\x43"
    },
    {
      "Extended PBKDF2 SHA256",
      "passwordPASSWORDpassword", 24,
      "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
      GCRY_MD_SHA256,
      4096,
      40,
      "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e\x84\xcf"
      "\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c\x4e\x2a\x1f\xb8\xdd\x53\xe1"
      "\xc6\x35\x51\x8c\x7d\xac\x47\xe9"
    },
    { NULL }
  };
  const char *what;
  const char *errtxt;
  int tvidx;

  for (tvidx=0; tv[tvidx].desc; tvidx++)
    {
      what = tv[tvidx].desc;
      if (tv[tvidx].disabled)
        continue;
      errtxt = check_one (GCRY_KDF_PBKDF2, tv[tvidx].hashalgo,
                          tv[tvidx].p, tv[tvidx].plen,
                          tv[tvidx].salt, tv[tvidx].saltlen,
                          tv[tvidx].c,
                          tv[tvidx].dk, tv[tvidx].dklen);
      if (errtxt)
        goto failed;
      if (tvidx >= NUM_TEST_VECTORS - 1 && !extended)
        break;
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("kdf", GCRY_KDF_PBKDF2, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}


/* Run the selftests for KDF with KDF algorithm ALGO with optional
   reporting function REPORT.  */
gpg_error_t
_gcry_kdf_selftest (int algo, int extended, selftest_report_func_t report)
{
  gcry_err_code_t ec = 0;

  if (algo == GCRY_KDF_PBKDF2)
    ec = selftest_pbkdf2 (extended, report);
  else
    {
      ec = GPG_ERR_UNSUPPORTED_ALGORITHM;
      if (report)
        report ("kdf", algo, "module", "algorithm not available");
    }
  return gpg_error (ec);
}
