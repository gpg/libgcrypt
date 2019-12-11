/* sm2.c - SM2 implementation
 * Copyright (C) 2019 Tianjia Zhang
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
#include <errno.h>

#include "g10lib.h"
#include "bithelp.h"
#include "mpi.h"
#include "cipher.h"
#include "context.h"
#include "ec-context.h"
#include "pubkey-internal.h"
#include "ecc-common.h"

#define MPI_NBYTES(m)   ((mpi_get_nbits(m) + 7) / 8)


static const char *sm2_names[] =
  {
    "sm2",
    "1.2.156.10197.1.301",
    NULL,
  };



/*********************************************
 **************  interface  ******************
 *********************************************/

static gcry_err_code_t
sm2_generate (const gcry_sexp_t genparms, gcry_sexp_t *r_skey)
{
  gpg_err_code_t rc;
  gcry_mpi_t Gx = NULL;
  gcry_mpi_t Gy = NULL;
  gcry_mpi_t Qx = NULL;
  gcry_mpi_t Qy = NULL;
  mpi_ec_t ec = NULL;
  gcry_sexp_t curve_info = NULL;
  gcry_sexp_t curve_flags = NULL;
  gcry_mpi_t base = NULL;
  gcry_mpi_t public = NULL;
  int flags = 0;

  rc = _gcry_mpi_ec_internal_new (&ec, &flags, "ecgen curve", genparms, NULL);
  if (rc)
    goto leave;

  rc = _gcry_ecc_nist_generate_key (ec, flags, &Qx, &Qy);
  if (rc)
    goto leave;

  /* Copy data to the result.  */
  Gx = mpi_new (0);
  Gy = mpi_new (0);
  if (_gcry_mpi_ec_get_affine (Gx, Gy, ec->G, ec))
    log_fatal ("ecgen: Failed to get affine coordinates for %s\n", "G");
  base = _gcry_ecc_ec2os (Gx, Gy, ec->p);

  if (!Qx)
    {
      Qx = mpi_new (0);
      Qy = mpi_new (0);
      if (_gcry_mpi_ec_get_affine (Qx, Qy, ec->Q, ec))
        log_fatal ("ecgen: Failed to get affine coordinates for %s\n", "Q");
    }
  public = _gcry_ecc_ec2os (Qx, Qy, ec->p);

  if (ec->name)
    {
      rc = sexp_build (&curve_info, NULL, "(curve %s)", ec->name);
      if (rc)
        goto leave;
    }

  if (flags & PUBKEY_FLAG_PARAM)
    {
      rc = sexp_build (&curve_flags, NULL, "(flags param)");
      if (rc)
        goto leave;
    }

  if ((flags & PUBKEY_FLAG_PARAM) && ec->name)
    rc = sexp_build (r_skey, NULL,
                     "(key-data"
                     " (public-key"
                     "  (sm2%S%S(p%m)(a%m)(b%m)(g%m)(n%m)(h%u)(q%m)))"
                     " (private-key"
                     "  (sm2%S%S(p%m)(a%m)(b%m)(g%m)(n%m)(h%u)(q%m)(d%m)))"
                     " )",
                     curve_info, curve_flags,
                     ec->p, ec->a, ec->b, base, ec->n, ec->h, public,
                     curve_info, curve_flags,
                     ec->p, ec->a, ec->b, base, ec->n, ec->h, public,
                     ec->d);
  else
    rc = sexp_build (r_skey, NULL,
                     "(key-data"
                     " (public-key"
                     "  (sm2%S%S(q%m)))"
                     " (private-key"
                     "  (sm2%S%S(q%m)(d%m)))"
                     " )",
                     curve_info, curve_flags, public,
                     curve_info, curve_flags, public, ec->d);
  if (rc)
    goto leave;

  if (DBG_CIPHER)
    {
      log_printmpi ("ecgen result  p", ec->p);
      log_printmpi ("ecgen result  a", ec->a);
      log_printmpi ("ecgen result  b", ec->b);
      log_printmpi ("ecgen result  G", base);
      log_printmpi ("ecgen result  n", ec->n);
      log_debug    ("ecgen result  h:+%02x\n", ec->h);
      log_printmpi ("ecgen result  Q", public);
      log_printmpi ("ecgen result  d", ec->d);
    }

 leave:
  mpi_free (public);
  mpi_free (base);
  mpi_free (Gx);
  mpi_free (Gy);
  mpi_free (Qx);
  mpi_free (Qy);
  _gcry_mpi_ec_free (ec);
  sexp_release (curve_flags);
  sexp_release (curve_info);
  return rc;
}


/* Key derivation function from X9.63/SECG */
static gcry_err_code_t
kdf_x9_63 (int algo, const void *in, size_t inlen, void *out, size_t outlen)
{
  gcry_err_code_t rc;
  gcry_md_hd_t hd;
  int mdlen;
  u32 counter = 1;
  u32 counter_be;
  unsigned char *dgst;
  unsigned char *pout = out;
  size_t rlen = outlen;
  size_t len;

  rc = _gcry_md_open (&hd, algo, 0);
  if (rc)
    return rc;

  mdlen = _gcry_md_get_algo_dlen (algo);

  while (rlen > 0)
    {
      counter_be = be_bswap32 (counter);   /* cpu_to_be32 */
      counter++;

      _gcry_md_write (hd, in, inlen);
      _gcry_md_write (hd, &counter_be, sizeof(counter_be));

      dgst = _gcry_md_read (hd, algo);
      if (dgst == NULL)
        {
          rc = GPG_ERR_DIGEST_ALGO;
          break;
        }

      len = mdlen < rlen ? mdlen : rlen;  /* min(mdlen, rlen) */
      memcpy (pout, dgst, len);
      rlen -= len;
      pout += len;

      _gcry_md_reset (hd);
    }

  _gcry_md_close (hd);
  return rc;
}


/* sm2_encrypt description:
 *   input:
 *     data[0] : octet string
 *   output: A new S-expression with the parameters:
 *     a: c1 : generated ephemeral public key (kG)
 *     b: c3 : Hash(x2 || IN || y2)
 *     c: c2 : cipher
 *
 * sm2_decrypt description:
 *   in contrast to encrypt
 */
static gcry_err_code_t
sm2_encrypt (gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
  gcry_err_code_t rc;
  struct pk_encoding_ctx ctx;
  gcry_mpi_t data = NULL;
  mpi_ec_t ec = NULL;
  int flags = 0;

  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_ENCRYPT,
                                   _gcry_ecc_get_nbits (keyparms));

  /* Extract the key. */
  rc = _gcry_mpi_ec_internal_new (&ec, &flags, "sm2_encrypt", keyparms, NULL);
  if (rc)
    goto leave;

  /* Extract the data. */
  rc = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (rc)
    goto leave;

  if (DBG_CIPHER)
    log_mpidump ("sm2_encrypt data", data);

  if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->Q)
    {
      rc = GPG_ERR_NO_OBJ;
      goto leave;
    }

  {
    const int algo = GCRY_MD_SM3;
    gcry_md_hd_t md = NULL;
    int mdlen;
    unsigned char *dgst;
    gcry_mpi_t k = NULL;
    mpi_point_struct kG, kP;
    gcry_mpi_t x1, y1;
    gcry_mpi_t x2, y2;
    gcry_mpi_t x2y2 = NULL;
    unsigned char *in = NULL;
    unsigned int inlen;
    unsigned char *raw;
    unsigned int rawlen;
    unsigned char *cipher = NULL;
    int i;

    point_init (&kG);
    point_init (&kP);
    x1 = mpi_new (0);
    y1 = mpi_new (0);
    x2 = mpi_new (0);
    y2 = mpi_new (0);

    in = _gcry_mpi_get_buffer (data, 0, &inlen, NULL);
    if (!in)
      {
        rc = gpg_err_code_from_syserror ();
        goto leave_main;
      }

    cipher = xtrymalloc (inlen);
    if (!cipher)
      {
        rc = gpg_err_code_from_syserror ();
        goto leave_main;
      }

    /* rand k in [1, n-1] */
    k = _gcry_dsa_gen_k (ec->n, GCRY_VERY_STRONG_RANDOM);

    /* [k]G = (x1, y1) */
    _gcry_mpi_ec_mul_point (&kG, k, ec->G, ec);
    if (_gcry_mpi_ec_get_affine (x1, y1, &kG, ec))
      {
        if (DBG_CIPHER)
          log_debug ("Bad check: kG can not be a Point at Infinity!\n");
        rc = GPG_ERR_INV_DATA;
        goto leave_main;
      }

    /* [k]P = (x2, y2) */
    _gcry_mpi_ec_mul_point (&kP, k, ec->Q, ec);
    if (_gcry_mpi_ec_get_affine (x2, y2, &kP, ec))
      {
        rc = GPG_ERR_INV_DATA;
        goto leave_main;
      }

    /* t = KDF(x2 || y2, klen) */
    x2y2 = _gcry_mpi_ec_ec2os (&kP, ec);
    raw = mpi_get_opaque (x2y2, &rawlen);
    rawlen = (rawlen + 7) / 8;


    /* skip the prefix '0x04' */
    raw += 1;
    rawlen -= 1;
    rc = kdf_x9_63 (algo, raw, rawlen, cipher, inlen);
    if (rc)
      goto leave_main;

    /* cipher = t xor in */
    for (i = 0; i < inlen; i++)
      cipher[i] ^= in[i];

    /* hash(x2 || IN || y2) */
    mdlen = _gcry_md_get_algo_dlen (algo);
    rc = _gcry_md_open (&md, algo, 0);
    if (rc)
      goto leave_main;
    _gcry_md_write (md, raw, MPI_NBYTES(x2));
    _gcry_md_write (md, in, inlen);
    _gcry_md_write (md, raw + MPI_NBYTES(x2), MPI_NBYTES(y2));
    dgst = _gcry_md_read (md, algo);
    if (dgst == NULL)
      {
        rc = GPG_ERR_DIGEST_ALGO;
        goto leave_main;
      }

    if (!rc)
      {
        gcry_mpi_t c1;
        gcry_mpi_t c3;
        gcry_mpi_t c2;

        c3 = mpi_new (0);
        c2 = mpi_new (0);

        c1 = _gcry_ecc_ec2os (x1, y1, ec->p);
        _gcry_mpi_set_opaque_copy (c3, dgst, mdlen * 8);
        _gcry_mpi_set_opaque_copy (c2, cipher, inlen * 8);

        rc = sexp_build (r_ciph, NULL, "(enc-val(sm2(a%M)(b%M)(c%M)))",
                         c1, c3, c2);

        mpi_free (c1);
        mpi_free (c3);
        mpi_free (c2);
      }

  leave_main:
    _gcry_md_close (md);
    mpi_free (x2y2);
    mpi_free (k);

    point_free (&kG);
    point_free (&kP);
    mpi_free (x1);
    mpi_free (y1);
    mpi_free (x2);
    mpi_free (y2);

    xfree (cipher);
    xfree (in);
  }

 leave:
  _gcry_mpi_release (data);
  _gcry_mpi_ec_free (ec);
  _gcry_pk_util_free_encoding_ctx (&ctx);
  if (DBG_CIPHER)
    log_debug ("sm2_encrypt    => %s\n", gpg_strerror (rc));
  return rc;
}


static gcry_err_code_t
sm2_decrypt (gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
  gcry_err_code_t rc;
  struct pk_encoding_ctx ctx;
  gcry_sexp_t l1 = NULL;
  gcry_mpi_t data_c1 = NULL;
  gcry_mpi_t data_c3 = NULL;
  gcry_mpi_t data_c2 = NULL;
  mpi_ec_t ec = NULL;
  int flags = 0;

  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_DECRYPT,
                                   _gcry_ecc_get_nbits (keyparms));

  /* extract the data */
  rc = _gcry_pk_util_preparse_encval (s_data, sm2_names, &l1, &ctx);
  if (rc)
    goto leave;
  if (ctx.encoding != PUBKEY_ENC_UNKNOWN)
    {
      rc = GPG_ERR_ENCODING_PROBLEM;
      goto leave;
    }

  rc = sexp_extract_param (l1, NULL, "/a/b/c", &data_c1, &data_c3, &data_c2, NULL);
  if (rc)
    goto leave;

  /* extract the key */
  rc = _gcry_mpi_ec_internal_new (&ec, &flags, "sm2_decrypt", keyparms, NULL);

  if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->d)
    {
      rc = GPG_ERR_NO_OBJ;
      goto leave;
    }

  {
    const int algo = GCRY_MD_SM3;
    gcry_md_hd_t md = NULL;
    int mdlen;
    unsigned char *dgst;
    mpi_point_struct c1;
    mpi_point_struct kP;
    gcry_mpi_t x2, y2;
    gcry_mpi_t x2y2 = NULL;
    unsigned char *in = NULL;
    unsigned int inlen;
    unsigned char *plain = NULL;
    unsigned char *raw;
    unsigned int rawlen;
    unsigned char *c3 = NULL;
    unsigned int c3_len;
    int i;

    point_init (&c1);
    point_init (&kP);
    x2 = mpi_new (0);
    y2 = mpi_new (0);

    in = mpi_get_opaque (data_c2, &inlen);
    inlen = (inlen + 7) / 8;
    plain = xtrymalloc (inlen);
    if (!plain)
      {
        rc = gpg_err_code_from_syserror ();
        goto leave_main;
      }

    rc = _gcry_ecc_os2ec (&c1, data_c1);
    if (rc)
      goto leave_main;

    if (!_gcry_mpi_ec_curve_point (&c1, ec))
      {
        rc = GPG_ERR_INV_DATA;
        goto leave_main;
      }

    /* [d]C1 = (x2, y2), C1 = [k]G */
    _gcry_mpi_ec_mul_point (&kP, ec->d, &c1, ec);
    if (_gcry_mpi_ec_get_affine (x2, y2, &kP, ec))
      {
        rc = GPG_ERR_INV_DATA;
        goto leave_main;
      }

    /* t = KDF(x2 || y2, inlen) */
    x2y2 = _gcry_mpi_ec_ec2os (&kP, ec);
    raw = mpi_get_opaque (x2y2, &rawlen);
    rawlen = (rawlen + 7) / 8;
    /* skip the prefix '0x04' */
    raw += 1;
    rawlen -= 1;
    rc = kdf_x9_63 (algo, raw, rawlen, plain, inlen);
    if (rc)
      goto leave_main;

    /* plain = C2 xor t */
    for (i = 0; i < inlen; i++)
      plain[i] ^= in[i];

    /* Hash(x2 || IN || y2) == C3 */
    mdlen = _gcry_md_get_algo_dlen (algo);
    rc = _gcry_md_open (&md, algo, 0);
    if (rc)
      goto leave_main;
    _gcry_md_write (md, raw, MPI_NBYTES(x2));
    _gcry_md_write (md, plain, inlen);
    _gcry_md_write (md, raw + MPI_NBYTES(x2), MPI_NBYTES(y2));
    dgst = _gcry_md_read (md, algo);
    if (dgst == NULL)
      {
        memset (plain, 0, inlen);
        rc = GPG_ERR_DIGEST_ALGO;
        goto leave_main;
      }
    c3 = mpi_get_opaque (data_c3, &c3_len);
    c3_len = (c3_len + 7) / 8;
    if (c3_len != mdlen || memcmp (dgst, c3, c3_len) != 0)
      {
        memset (plain, 0, inlen);
        rc = GPG_ERR_INV_DATA;
        goto leave_main;
      }

    if (!rc)
      {
        gcry_mpi_t r;

        r = mpi_new (inlen * 8);
        _gcry_mpi_set_buffer (r, plain, inlen, 0);

        rc = sexp_build (r_plain, NULL, "(value %m)", r);

        mpi_free (r);
      }

  leave_main:
    _gcry_md_close (md);
    mpi_free (x2y2);
    xfree (plain);

    point_free (&c1);
    point_free (&kP);
    mpi_free (x2);
    mpi_free (y2);
  }

 leave:
  _gcry_mpi_release (data_c1);
  _gcry_mpi_release (data_c3);
  _gcry_mpi_release (data_c2);
  _gcry_mpi_ec_free (ec);
  sexp_release (l1);
  _gcry_pk_util_free_encoding_ctx (&ctx);
  if (DBG_CIPHER)
    log_debug ("sm2_decrypt    => %s\n", gpg_strerror (rc));
  return rc;
}


static gcry_err_code_t
sm2_sign (gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
  gcry_err_code_t rc;
  struct pk_encoding_ctx ctx;
  gcry_mpi_t data = NULL;
  gcry_mpi_t hash = NULL;
  mpi_ec_t ec = NULL;
  int flags;

  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_SIGN, 0);

  /* Extract the data */
  rc = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (rc)
    goto leave;
  if (mpi_is_opaque(data))
    {
      const void *buf;
      unsigned int nbits;
      buf = mpi_get_opaque (data, &nbits);
      rc = _gcry_mpi_scan (&hash, GCRYMPI_FMT_USG, buf, (nbits + 7) / 8, NULL);
      if (rc)
        goto leave;
    }
  else
    hash = data;

  /* Extract the key */
  rc = _gcry_mpi_ec_internal_new (&ec, &flags, "sm2_sign", keyparms, NULL);
  if (rc)
    goto leave;
  if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->d)
    {
      rc = GPG_ERR_NO_OBJ;
      goto leave;
    }

  {
    gcry_mpi_t sig_r = NULL;
    gcry_mpi_t sig_s = NULL;
    gcry_mpi_t tmp = NULL;
    gcry_mpi_t k = NULL;
    gcry_mpi_t rk = NULL;
    mpi_point_struct kG;
    gcry_mpi_t x1;

    point_init (&kG);
    x1 = mpi_new (0);
    sig_r = mpi_new (0);
    sig_s = mpi_new (0);
    rk = mpi_new (0);
    tmp = mpi_new (0);

    for (;;)
      {
        /* rand k in [1, n-1] */
        k = _gcry_dsa_gen_k (ec->n, GCRY_VERY_STRONG_RANDOM);

        /* [k]G = (x1, y1) */
        _gcry_mpi_ec_mul_point (&kG, k, ec->G, ec);
        if (_gcry_mpi_ec_get_affine (x1, NULL, &kG, ec))
          {
            rc = GPG_ERR_INV_DATA;
            goto leave_main;
          }

        /* r = (e + x1) % n */
        mpi_addm (sig_r, hash, x1, ec->n);

        /* r != 0 && r + k != n */
        if (mpi_cmp_ui (sig_r, 0) == 0)
          continue;
        mpi_add (rk, sig_r, k);
        if (mpi_cmp (rk, ec->n) == 0)
          continue;

        /* s = ((d + 1)^-1 * (k - rd)) % n */
        mpi_addm (sig_s, ec->d, GCRYMPI_CONST_ONE, ec->n);
        mpi_invm (sig_s, sig_s, ec->n);
        mpi_mulm (tmp, sig_r, ec->d, ec->n);
        mpi_subm (tmp, k, tmp, ec->n);
        mpi_mulm (sig_s, sig_s, tmp, ec->n);

        break;
      }

    rc = sexp_build (r_sig, NULL, "(sig-val(sm2(r%M)(s%M)))", sig_r, sig_s);

  leave_main:
    point_free (&kG);
    mpi_free (x1);
    mpi_free (k);
    mpi_free (rk);
    mpi_free (sig_r);
    mpi_free (sig_s);
    mpi_free (tmp);
  }

 leave:
  _gcry_mpi_ec_free (ec);
  if (hash != data)
    mpi_free (hash);
  mpi_free (data);
  _gcry_pk_util_free_encoding_ctx (&ctx);
  if (DBG_CIPHER)
    log_debug ("sm2_sign      => %s\n", gpg_strerror (rc));
  return rc;
}


static gcry_err_code_t
sm2_verify (gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
  gcry_err_code_t rc;
  struct pk_encoding_ctx ctx;
  gcry_sexp_t l1 = NULL;
  gcry_mpi_t data = NULL;
  gcry_mpi_t hash = NULL;
  gcry_mpi_t sig_r = NULL;
  gcry_mpi_t sig_s = NULL;
  mpi_ec_t ec = NULL;
  int sigflags;
  int flags;

  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_VERIFY,
                                   _gcry_ecc_get_nbits (keyparms));

  /* Extract the data */
  rc = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (rc)
    goto leave;
  if (mpi_is_opaque (data))
    {
      const void *buf;
      unsigned int nbits;
      buf = mpi_get_opaque (data, &nbits);
      rc = _gcry_mpi_scan (&hash, GCRYMPI_FMT_USG, buf, (nbits + 7) / 8, NULL);
      if (rc)
        goto leave;
    }
  else
    hash = data;

  rc = _gcry_pk_util_preparse_sigval (s_sig, sm2_names, &l1, &sigflags);
  if (rc)
    goto leave;
  rc = sexp_extract_param (l1, NULL, "rs", &sig_r, &sig_s, NULL);
  if (rc)
    goto leave;

  /* Extract the key */
  rc = _gcry_mpi_ec_internal_new (&ec, &flags, "sm2_verify", keyparms, NULL);
  if (rc)
    goto leave;
  if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->Q)
    {
      rc = GPG_ERR_NO_OBJ;
      goto leave;
    }

  {
    gcry_mpi_t t = NULL;
    mpi_point_struct sG, tP;
    gcry_mpi_t x1, y1;

    point_init (&sG);
    point_init (&tP);
    x1 = mpi_new (0);
    y1 = mpi_new (0);
    t = mpi_new (0);

    /* r, s in [1, n-1] */
    if (mpi_cmp_ui (sig_r, 1) < 0 || mpi_cmp (sig_r, ec->n) > 0 ||
        mpi_cmp_ui (sig_s, 1) < 0 || mpi_cmp (sig_s, ec->n) > 0)
      {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave_main;
      }

    /* t = (r + s) % n, t == 0 */
    mpi_addm (t, sig_r, sig_s, ec->n);
    if (mpi_cmp_ui (t, 0) == 0)
      {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave_main;
      }

    /* sG + tP = (x1, y1) */
    _gcry_mpi_ec_mul_point (&sG, sig_s, ec->G, ec);
    _gcry_mpi_ec_mul_point (&tP, t, ec->Q, ec);
    _gcry_mpi_ec_add_points (&sG, &sG, &tP, ec);
    if (_gcry_mpi_ec_get_affine (x1, y1, &sG, ec))
      {
        rc = GPG_ERR_INV_DATA;
        goto leave_main;
      }

    /* R = (e + x1) % n */
    mpi_addm (t, hash, x1, ec->n);

    /* check R == r */
    if (mpi_cmp (t, sig_r))
      rc = GPG_ERR_BAD_SIGNATURE;
    else
      rc = 0;

  leave_main:
    point_free (&sG);
    point_free (&tP);
    mpi_free (x1);
    mpi_free (y1);
    mpi_free (t);
  }

 leave:
  _gcry_mpi_ec_free (ec);
  sexp_release (l1);
  if (hash != data)
    mpi_free (hash);
  mpi_free (data);
  _gcry_pk_util_free_encoding_ctx (&ctx);
  if (DBG_CIPHER)
    log_debug ("sm2_verify    => %s\n", rc ? gpg_strerror (rc) : "Good");
  return rc;
}


static const char *
selftest_genkey (gcry_sexp_t *pkey, gcry_sexp_t *skey)
{
  const char *errtxt;
  gpg_err_code_t err;
  gcry_sexp_t key_spec = NULL;
  gcry_sexp_t key = NULL;
  gcry_sexp_t pub_key = NULL;
  gcry_sexp_t sec_key = NULL;
  static const char genkey[] = "(genkey (sm2 (curve sm2p256v1)))";
  unsigned char keygrip[20];

  errtxt = "build key spec failed";
  err = sexp_sscan (&key_spec, NULL, genkey, strlen(genkey));
  if (err)
    goto leave;

  errtxt = "genkey failed";
  err = _gcry_pk_genkey (&key, key_spec);
  if (err)
    goto leave;

  errtxt = "encrypt signature validity failed";
  pub_key = _gcry_sexp_find_token (key, "public-key", 0);
  if (!pub_key)
    goto leave;
  sec_key = _gcry_sexp_find_token (key, "private-key", 0);
  if (!sec_key)
    goto leave;

  errtxt = "testkey failed";
  err = _gcry_pk_testkey (sec_key);
  if (err)
    goto leave;

  errtxt = "get keygrip failed";
  if (!_gcry_pk_get_keygrip (pub_key, keygrip))
    goto leave;

  *pkey = pub_key;
  *skey = sec_key;

  sexp_release (key_spec);
  sexp_release (key);
  return NULL;

 leave:
  sexp_release (key_spec);
  sexp_release (key);
  sexp_release (pub_key);
  sexp_release (sec_key);
  return errtxt;
}


#define SM2TEST_CURVE                                                      \
  "(p #8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3#)" \
  "(a #787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498#)" \
  "(b #63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A#)" \
  "(g #04"                                                                 \
  "    421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"   \
  "    0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2#)" \
  "(n #8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7#)" \
  "(h #0000000000000000000000000000000000000000000000000000000000000001#)"


static const char *
selftest_encrypt (void)
{
#define SM2TEST_PUBLIC_KEY                                                 \
  "(q #04"                                                                 \
  "    435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A"   \
  "    75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42#)"

  static const char secret_key[] =
    "(private-key"
    " (sm2"
    SM2TEST_CURVE
    SM2TEST_PUBLIC_KEY
    "  (d #1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0#)"
    "))";
  static const char public_key[] =
    "(public-key"
    " (sm2"
    SM2TEST_CURVE
    SM2TEST_PUBLIC_KEY
    "))";
#undef SM2TEST_PUBLIC_KEY

  static const char plain_text[] = "encryption standard";
  static const char plain_fmt[] =
    "(data\n"
    " (flags raw)\n"
    " (hash-algo %s)\n"
    " (value %m)\n"
    ")";

  const char *errtxt = NULL;
  gpg_err_code_t err;
  gcry_sexp_t skey = NULL;
  gcry_sexp_t pkey = NULL;
  gcry_mpi_t m = NULL;
  gcry_mpi_t calculated_m = NULL;
  gcry_sexp_t plain = NULL;
  gcry_sexp_t cipher = NULL;
  gcry_sexp_t result = NULL;
  gcry_sexp_t l1 = NULL;
  gcry_sexp_t l2 = NULL;
  gcry_sexp_t a = NULL;
  gcry_sexp_t b = NULL;
  gcry_sexp_t c = NULL;
  gcry_sexp_t value = NULL;
  unsigned int inlen;
  int cmp;

  errtxt = "build key failed";
  err = sexp_sscan (&skey, NULL, secret_key, strlen(secret_key));
  if (err)
    goto leave;
  err = sexp_sscan (&pkey, NULL, public_key, strlen(public_key));
  if (err)
    goto leave;

  inlen = strlen (plain_text);
  m = mpi_new (inlen * 8);
  _gcry_mpi_set_buffer (m, plain_text, inlen, 0);

  err = sexp_build (&plain, NULL, plain_fmt, "sm3", m);
  if (err)
   {
      errtxt = "build plain data failed";
      goto leave;
   }

  /* encrypt with pkey */
  err = _gcry_pk_encrypt (&cipher, plain, pkey);
  if (err)
    {
      errtxt = "encrypt failed";
      goto leave;
    }

  errtxt = "encrypt signature validity failed";
  l1 = _gcry_sexp_find_token (cipher, "enc-val", 0);
  if (!l1)
    goto leave;
  l2 = _gcry_sexp_find_token (l1, "sm2", 0);
  if (!l2)
    goto leave;
  a = _gcry_sexp_find_token (l1, "a", 0);
  if (!a)
    goto leave;
  b = _gcry_sexp_find_token (l1, "b", 0);
  if (!a)
    goto leave;
  c = _gcry_sexp_find_token (l1, "c", 0);
  if (!a)
    goto leave;

  /* decrypt with skey */
  err = _gcry_pk_decrypt (&result, cipher, skey);
  if (err)
    {
      errtxt = "decrypt failed";
      goto leave;
    }

  errtxt = "decrypt signature validity failed";
  value = _gcry_sexp_find_token (result, "value", 0);
  if (!value)
    goto leave;

  calculated_m = _gcry_sexp_nth_mpi (value, 1, GCRYMPI_FMT_USG);
  if (!calculated_m)
    goto leave;

  cmp = _gcry_mpi_cmp (m, calculated_m);
  if (cmp)
    {
      errtxt = "mismatch decrypt data";
      goto leave;
    }

  errtxt = NULL;

 leave:
  sexp_release (result);
  sexp_release (l1);
  sexp_release (l2);
  sexp_release (a);
  sexp_release (b);
  sexp_release (c);
  sexp_release (value);
  sexp_release (cipher);
  sexp_release (plain);
  sexp_release (skey);
  sexp_release (pkey);
  mpi_free (m);
  mpi_free (calculated_m);
  return errtxt;
}


static const char *
selftest_sign (void)
{
#define SM2TEST_PUBLIC_KEY                                                 \
  "(q #04"                                                                 \
  "    0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A"   \
  "    7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857#)"

  static const char secret_key[] =
    "(private-key"
    " (sm2"
    SM2TEST_CURVE
    SM2TEST_PUBLIC_KEY
    "  (d #128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263#)"
    "))";
  static const char public_key[] =
    "(public-key"
    " (sm2"
    SM2TEST_CURVE
    SM2TEST_PUBLIC_KEY
    "))";
#undef SM2TEST_PUBLIC_KEY

  static const char sample_data[] =
    "(data (flags raw)"
    " (hash sm3"
    " #B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76#))";
  static const char sample_data_bad[] =
    "(data (flags raw)"
    " (hash sm3"
    " #cd85698fecab7843e09bcde2289096872345bcbcdaa8870bbef23d8a110bcd9f#))";
  static const char signature_r[] =
    "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1";
  static const char signature_s[] =
    "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7";

  const char *errtxt = NULL;
  gcry_error_t err;
  gcry_sexp_t skey = NULL;
  gcry_sexp_t pkey = NULL;
  gcry_sexp_t data = NULL;
  gcry_sexp_t data_bad = NULL;
  gcry_sexp_t sig = NULL;
  gcry_sexp_t l1 = NULL;
  gcry_sexp_t l2 = NULL;
  gcry_sexp_t lr = NULL;
  gcry_sexp_t ls = NULL;
  gcry_mpi_t r = NULL;
  gcry_mpi_t s = NULL;

  errtxt = "build key failed";
  err = sexp_sscan (&skey, NULL, secret_key, strlen (secret_key));
  if (err)
    goto leave;
  err = sexp_sscan (&pkey, NULL, public_key, strlen (public_key));
  if (err)
    goto leave;

  errtxt = "build data failed";
  err = sexp_sscan (&data, NULL, sample_data, strlen (sample_data));
  if (err)
    goto leave;
  err = sexp_sscan (&data_bad, NULL, sample_data_bad, strlen (sample_data_bad));
  if (err)
    goto leave;
  /* TODO: r and s are only valid for fixed k in sm2test */
  err = _gcry_mpi_scan (&r, GCRYMPI_FMT_HEX, signature_r, 0, NULL);
  if (err)
    goto leave;
  err = _gcry_mpi_scan (&s, GCRYMPI_FMT_HEX, signature_s, 0, NULL);
  if (err)
    goto leave;

  /* sign with skey */
  errtxt = "signing failed";
  err = _gcry_pk_sign (&sig, data, skey);
  if (err)
    goto leave;

  /* check against known signature */
  errtxt = "signature validity failed";
  l1 = _gcry_sexp_find_token (sig, "sig-val", 0);
  if (!l1)
    goto leave;
  l2 = _gcry_sexp_find_token (l1, "sm2", 0);
  if (!l2)
    goto leave;
  lr = _gcry_sexp_find_token (l2, "r", 0);
  if (!r)
    goto leave;
  ls = _gcry_sexp_find_token (l2, "s", 0);
  if (!s)
    goto leave;

  /* verify with pkey */
  errtxt = "verify failed";
  err = _gcry_pk_verify (sig, data, pkey);
  if (err)
    goto leave;

  errtxt = "bad signature not detected";
  err = _gcry_pk_verify (sig, data_bad, pkey);
  if (gcry_err_code (err) != GPG_ERR_BAD_SIGNATURE)
    goto leave;

  errtxt = NULL;

 leave:
  sexp_release (skey);
  sexp_release (pkey);
  sexp_release (data);
  sexp_release (data_bad);
  sexp_release (sig);
  sexp_release (l1);
  sexp_release (l2);
  sexp_release (lr);
  sexp_release (ls);
  mpi_free (r);
  mpi_free (s);
  return errtxt;
}

#undef SM2TEST_CURVE


static gpg_err_code_t
run_selftests (int algo, int extended, selftest_report_func_t report)
{
  const char *what;
  const char *errtxt;
  gcry_sexp_t pkey = NULL;
  gcry_sexp_t skey = NULL;

  (void)extended;

  if (algo != GCRY_PK_SM2)
    return GPG_ERR_PUBKEY_ALGO;

  what = "genkey";
  errtxt = selftest_genkey (&pkey, &skey);
  if (errtxt)
    goto failed;

  what = "encrypt";
  errtxt = selftest_encrypt ();
  if (errtxt)
    goto failed;

  what = "sign";
  errtxt = selftest_sign ();
  if (errtxt)
    goto failed;

  return 0;

 failed:
  sexp_release (pkey);
  sexp_release (skey);
  if (report)
      report ("pubkey", GCRY_PK_SM2, what, errtxt);
  return GPG_ERR_SELFTEST_FAILED;
}




gcry_pk_spec_t _gcry_pubkey_spec_sm2 =
  {
    GCRY_PK_SM2, { 0, 1 },
    (GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR),
    "SM2", sm2_names,
    "pabgnhq", "pabgnhqd", "abc", "rs", "pabgnhq",
    sm2_generate,
    _gcry_ecc_check_secret_key,
    sm2_encrypt,
    sm2_decrypt,
    sm2_sign,
    sm2_verify,
    _gcry_ecc_get_nbits,
    run_selftests,
    _gcry_ecc_compute_keygrip,
    _gcry_ecc_get_curve,
    _gcry_ecc_get_param_sexp
  };
