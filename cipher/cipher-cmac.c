/* cmac.c - CMAC, Cipher-based MAC.
 * Copyright (C) 2013,2018 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
#include <string.h>

#include "g10lib.h"
#include "cipher.h"
#include "cipher-internal.h"
#include "bufhelp.h"


#define set_burn(burn, nburn) do { \
  unsigned int __nburn = (nburn); \
  (burn) = (burn) > __nburn ? (burn) : __nburn; } while (0)


gcry_err_code_t
_gcry_cmac_write (gcry_cipher_hd_t c, gcry_cmac_context_t *ctx,
		  const byte * inbuf, size_t inlen)
{
  gcry_cipher_encrypt_t enc_fn = c->spec->encrypt;
  size_t blocksize_shift = _gcry_blocksize_shift(c);
  size_t blocksize = 1 << blocksize_shift;
  byte outbuf[MAX_BLOCKSIZE];
  unsigned int burn = 0;
  unsigned int nblocks;
  size_t n;

  if (ctx->tag)
    return GPG_ERR_INV_STATE;

  if (!inbuf)
    return GPG_ERR_INV_ARG;

  if (inlen == 0)
    return 0;

  /* Last block is needed for cmac_final.  */
  if (ctx->mac_unused + inlen <= blocksize)
    {
      buf_cpy (&ctx->macbuf[ctx->mac_unused], inbuf, inlen);
      ctx->mac_unused += inlen;
      inbuf += inlen;
      inlen -= inlen;

      return 0;
    }

  if (ctx->mac_unused)
    {
      n = inlen;
      if (n > blocksize - ctx->mac_unused)
	n = blocksize - ctx->mac_unused;

      buf_cpy (&ctx->macbuf[ctx->mac_unused], inbuf, n);
      ctx->mac_unused += n;
      inbuf += n;
      inlen -= n;

      cipher_block_xor (ctx->u_iv.iv, ctx->u_iv.iv, ctx->macbuf, blocksize);
      set_burn (burn, enc_fn (&c->context.c, ctx->u_iv.iv, ctx->u_iv.iv));

      ctx->mac_unused = 0;
    }

  if (c->bulk.cbc_enc && inlen > blocksize)
    {
      nblocks = inlen >> blocksize_shift;
      nblocks -= ((nblocks << blocksize_shift) == inlen);

      c->bulk.cbc_enc (&c->context.c, ctx->u_iv.iv, outbuf, inbuf, nblocks, 1);
      inbuf += nblocks << blocksize_shift;
      inlen -= nblocks << blocksize_shift;

      wipememory (outbuf, sizeof (outbuf));
    }
  else
    while (inlen > blocksize)
      {
        cipher_block_xor (ctx->u_iv.iv, ctx->u_iv.iv, inbuf, blocksize);
        set_burn (burn, enc_fn (&c->context.c, ctx->u_iv.iv, ctx->u_iv.iv));
        inlen -= blocksize;
        inbuf += blocksize;
      }

  /* Make sure that last block is passed to cmac_final.  */
  if (inlen == 0)
    BUG ();

  n = inlen;
  if (n > blocksize - ctx->mac_unused)
    n = blocksize - ctx->mac_unused;

  buf_cpy (&ctx->macbuf[ctx->mac_unused], inbuf, n);
  ctx->mac_unused += n;
  inbuf += n;
  inlen -= n;

  if (burn)
    _gcry_burn_stack (burn + 4 * sizeof (void *));

  return 0;
}


gcry_err_code_t
_gcry_cmac_generate_subkeys (gcry_cipher_hd_t c, gcry_cmac_context_t *ctx)
{
  const unsigned int blocksize = c->spec->blocksize;
  byte rb, carry, t, bi;
  unsigned int burn;
  int i, j;
  union
  {
    size_t _aligned;
    byte buf[MAX_BLOCKSIZE];
  } u;

  /* Tell compiler that we require a cipher with a 64bit or 128 bit block
   * length, to allow better optimization of this function.  */
  if (blocksize > 16 || blocksize < 8 || blocksize & (8 - 1))
    return GPG_ERR_INV_CIPHER_MODE;

  if (MAX_BLOCKSIZE < blocksize)
    BUG ();

  /* encrypt zero block */
  memset (u.buf, 0, blocksize);
  burn = c->spec->encrypt (&c->context.c, u.buf, u.buf);

  /* Currently supported blocksizes are 16 and 8. */
  rb = blocksize == 16 ? 0x87 : 0x1B /* blocksize == 8 */ ;

  for (j = 0; j < 2; j++)
    {
      /* Generate subkeys K1 and K2 */
      carry = 0;
      for (i = blocksize - 1; i >= 0; i--)
        {
          bi = u.buf[i];
          t = carry | (bi << 1);
          carry = bi >> 7;
          u.buf[i] = t & 0xff;
          ctx->subkeys[j][i] = u.buf[i];
        }
      u.buf[blocksize - 1] ^= carry ? rb : 0;
      ctx->subkeys[j][blocksize - 1] = u.buf[blocksize - 1];
    }

  wipememory (&u, sizeof (u));
  if (burn)
    _gcry_burn_stack (burn + 4 * sizeof (void *));

  return 0;
}


gcry_err_code_t
_gcry_cmac_final (gcry_cipher_hd_t c, gcry_cmac_context_t *ctx)
{
  const unsigned int blocksize = c->spec->blocksize;
  unsigned int count = ctx->mac_unused;
  unsigned int burn;
  byte *subkey;

  /* Tell compiler that we require a cipher with a 64bit or 128 bit block
   * length, to allow better optimization of this function.  */
  if (blocksize > 16 || blocksize < 8 || blocksize & (8 - 1))
    return GPG_ERR_INV_CIPHER_MODE;

  if (count == blocksize)
    subkey = ctx->subkeys[0];        /* K1 */
  else
    {
      subkey = ctx->subkeys[1];      /* K2 */
      ctx->macbuf[count++] = 0x80;
      while (count < blocksize)
        ctx->macbuf[count++] = 0;
    }

  cipher_block_xor (ctx->macbuf, ctx->macbuf, subkey, blocksize);

  cipher_block_xor (ctx->u_iv.iv, ctx->u_iv.iv, ctx->macbuf, blocksize);
  burn = c->spec->encrypt (&c->context.c, ctx->u_iv.iv, ctx->u_iv.iv);
  if (burn)
    _gcry_burn_stack (burn + 4 * sizeof (void *));

  ctx->mac_unused = 0;

  return 0;
}


static gcry_err_code_t
cmac_tag (gcry_cipher_hd_t c, gcry_cmac_context_t *ctx,
	  unsigned char *tag, size_t taglen, int check)
{
  gcry_err_code_t ret;

  if (!tag || taglen == 0 || taglen > c->spec->blocksize)
    return GPG_ERR_INV_ARG;

  if (!ctx->tag)
    {
      ret = _gcry_cmac_final (c, ctx);
      if (ret != 0)
	return ret;

      ctx->tag = 1;
    }

  if (!check)
    {
      memcpy (tag, ctx->u_iv.iv, taglen);
      return GPG_ERR_NO_ERROR;
    }
  else
    {
      return buf_eq_const (tag, ctx->u_iv.iv, taglen) ?
        GPG_ERR_NO_ERROR : GPG_ERR_CHECKSUM;
    }
}


void
_gcry_cmac_reset (gcry_cmac_context_t *ctx)
{
  char tmp_buf[sizeof(ctx->subkeys)];

  /* Only keep subkeys when reseting context. */

  buf_cpy (tmp_buf, ctx->subkeys, sizeof(ctx->subkeys));
  memset (ctx, 0, sizeof(*ctx));
  buf_cpy (ctx->subkeys, tmp_buf, sizeof(ctx->subkeys));
  wipememory (tmp_buf, sizeof(tmp_buf));
}


gcry_err_code_t
_gcry_cipher_cmac_authenticate (gcry_cipher_hd_t c,
                                const unsigned char *abuf, size_t abuflen)
{
  if (abuflen > 0 && !abuf)
    return GPG_ERR_INV_ARG;
  /* To support new blocksize, update cmac_generate_subkeys() then add new
     blocksize here. */
  if (c->spec->blocksize != 16 && c->spec->blocksize != 8)
    return GPG_ERR_INV_CIPHER_MODE;

  return _gcry_cmac_write (c, &c->u_mode.cmac, abuf, abuflen);
}


gcry_err_code_t
_gcry_cipher_cmac_get_tag (gcry_cipher_hd_t c,
                           unsigned char *outtag, size_t taglen)
{
  return cmac_tag (c, &c->u_mode.cmac, outtag, taglen, 0);
}


gcry_err_code_t
_gcry_cipher_cmac_check_tag (gcry_cipher_hd_t c,
                             const unsigned char *intag, size_t taglen)
{
  return cmac_tag (c, &c->u_mode.cmac, (unsigned char *) intag, taglen, 1);
}

gcry_err_code_t
_gcry_cipher_cmac_set_subkeys (gcry_cipher_hd_t c)
{
  return _gcry_cmac_generate_subkeys (c, &c->u_mode.cmac);
}

/* CMAC selftests.
 * Copyright (C) 2008 Free Software Foundation, Inc.
 * Copyright (C) 2019 Red Hat, Inc.
 */



/* Check one MAC with MAC ALGO using the regular MAC
 * API. (DATA,DATALEN) is the data to be MACed, (KEY,KEYLEN) the key
 * and (EXPECT,EXPECTLEN) the expected result.  If TRUNC is set, the
 * EXPECTLEN may be less than the digest length.  Returns NULL on
 * success or a string describing the failure.  */
static const char *
check_one (int algo,
           const void *data, size_t datalen,
           const void *key, size_t keylen,
           const void *expect, size_t expectlen)
{
  gcry_mac_hd_t hd;
  unsigned char mac[512]; /* hardcoded to avoid allocation */
  size_t macoutlen = expectlen;

/*   printf ("MAC algo %d\n", algo); */
  if (_gcry_mac_get_algo_maclen (algo) != expectlen ||
      expectlen > sizeof (mac))
    return "invalid tests data";
  if (_gcry_mac_open (&hd, algo, 0, NULL))
    return "gcry_mac_open failed";
  if (_gcry_mac_setkey (hd, key, keylen))
    {
      _gcry_mac_close (hd);
      return "gcry_md_setkey failed";
    }
  if (_gcry_mac_write (hd, data, datalen))
    {
      _gcry_mac_close (hd);
      return "gcry_mac_write failed";
    }
  if (_gcry_mac_read (hd, mac, &macoutlen))
    {
      _gcry_mac_close (hd);
      return "gcry_mac_read failed";
    }
  _gcry_mac_close (hd);
  if (macoutlen != expectlen || memcmp (mac, expect, expectlen))
    {
/*       int i; */

/*       fputs ("        {", stdout); */
/*       for (i=0; i < expectlen-1; i++) */
/*         { */
/*           if (i && !(i % 8)) */
/*             fputs ("\n         ", stdout); */
/*           printf (" 0x%02x,", mac[i]); */
/*         } */
/*       printf (" 0x%02x } },\n", mac[i]); */

      return "does not match";
    }
  return NULL;
}


static gpg_err_code_t
selftests_cmac_tdes (int extended, selftest_report_func_t report)
{
  const char *what;
  const char *errtxt;

  what = "Basic TDES";
  errtxt = check_one (GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57", 20,
        "\x8a\xa8\x3b\xf8\xcb\xda\x10\x62\x0b\xc1\xbf\x19\xfb\xb6\xcd\x58"
        "\xbc\x31\x3d\x4a\x37\x1c\xa8\xb5", 24,
        "\x74\x3d\xdb\xe0\xce\x2d\xc2\xed", 8);
  if (errtxt)
    goto failed;

  if (extended)
    {
      what = "Extended TDES #1";
      errtxt = check_one (GCRY_MAC_CMAC_3DES,
        "", 0,
        "\x8a\xa8\x3b\xf8\xcb\xda\x10\x62\x0b\xc1\xbf\x19\xfb\xb6\xcd\x58"
        "\xbc\x31\x3d\x4a\x37\x1c\xa8\xb5", 24,
        "\xb7\xa6\x88\xe1\x22\xff\xaf\x95", 8);
      if (errtxt)
        goto failed;

      what = "Extended TDES #2";
      errtxt = check_one (GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96", 8,
        "\x8a\xa8\x3b\xf8\xcb\xda\x10\x62\x0b\xc1\xbf\x19\xfb\xb6\xcd\x58"
        "\xbc\x31\x3d\x4a\x37\x1c\xa8\xb5", 24,
        "\x8e\x8f\x29\x31\x36\x28\x37\x97", 8);
      if (errtxt)
        goto failed;

      what = "Extended TDES #3";
      errtxt = check_one (GCRY_MAC_CMAC_3DES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51", 32,
        "\x8a\xa8\x3b\xf8\xcb\xda\x10\x62\x0b\xc1\xbf\x19\xfb\xb6\xcd\x58"
        "\xbc\x31\x3d\x4a\x37\x1c\xa8\xb5", 24,
        "\x33\xe6\xb1\x09\x24\x00\xea\xe5", 8);
      if (errtxt)
        goto failed;
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("cmac", GCRY_MAC_CMAC_3DES, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}



static gpg_err_code_t
selftests_cmac_aes (int extended, selftest_report_func_t report)
{
  const char *what;
  const char *errtxt;

  what = "Basic AES128";
  errtxt = check_one (GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11", 40,
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16,
        "\xdf\xa6\x67\x47\xde\x9a\xe6\x30\x30\xca\x32\x61\x14\x97\xc8\x27", 16);
  if (errtxt)
    goto failed;

  what = "Basic AES192";
  errtxt = check_one (GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11", 40,
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
        "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b", 24,
        "\x8a\x1d\xe5\xbe\x2e\xb3\x1a\xad\x08\x9a\x82\xe6\xee\x90\x8b\x0e", 16);
  if (errtxt)
    goto failed;

  what = "Basic AES256";
  errtxt = check_one (GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11", 40,
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32,
        "\xaa\xf3\xd8\xf1\xde\x56\x40\xc2\x32\xf5\xb1\x69\xb9\xc9\x11\xe6", 16);
  if (errtxt)
    goto failed;
  if (extended)
    {
      what = "Extended AES #1";
      errtxt = check_one (GCRY_MAC_CMAC_AES,
        "", 0,
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16,
        "\xbb\x1d\x69\x29\xe9\x59\x37\x28\x7f\xa3\x7d\x12\x9b\x75\x67\x46", 16);
      if (errtxt)
        goto failed;

      what = "Extended AES #2";
      errtxt = check_one (GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16,
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
        "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b", 24,
        "\x9e\x99\xa7\xbf\x31\xe7\x10\x90\x06\x62\xf6\x5e\x61\x7c\x51\x84", 16);
      if (errtxt)
        goto failed;

      what = "Extended AES #3";
      errtxt = check_one (GCRY_MAC_CMAC_AES,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
        "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10", 64,
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
        "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4", 32,
        "\xe1\x99\x21\x90\x54\x9f\x6e\xd5\x69\x6a\x2c\x05\x6c\x31\x54\x10", 16 );
      if (errtxt)
        goto failed;
    }

  return 0; /* Succeeded. */

 failed:
  if (report)
    report ("cmac", GCRY_MAC_CMAC_AES, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}


/* Run a full self-test for ALGO and return 0 on success.  */
static gpg_err_code_t
run_cmac_selftests (int algo, int extended, selftest_report_func_t report)
{
  gpg_err_code_t ec;

  switch (algo)
    {
    case GCRY_MAC_CMAC_3DES:
      ec = selftests_cmac_tdes (extended, report);
      break;
    case GCRY_MAC_CMAC_AES:
      ec = selftests_cmac_aes (extended, report);
      break;

    default:
      ec = GPG_ERR_MAC_ALGO;
      break;
    }
  return ec;
}




/* Run the selftests for CMAC with CMAC algorithm ALGO with optional
   reporting function REPORT.  */
gpg_error_t
_gcry_cmac_selftest (int algo, int extended, selftest_report_func_t report)
{
  gcry_err_code_t ec = 0;

  if (!_gcry_mac_algo_info( algo, GCRYCTL_TEST_ALGO, NULL, NULL ))
    {
      ec = run_cmac_selftests (algo, extended, report);
    }
  else
    {
      ec = GPG_ERR_MAC_ALGO;
      if (report)
        report ("mac", algo, "module", "algorithm not available");
    }
  return gpg_error (ec);
}
