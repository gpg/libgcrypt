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
