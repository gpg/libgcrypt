/* pkey-internal.h  - Internal defs for pkey.c
 * Copyright (C) 2021 g10 Code GmbH
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 */

gcry_error_t _gcry_pkey_ed25519_sign (gcry_pkey_hd_t h,
                                      int num_in, const unsigned char *const in[],
                                      const size_t in_len[],
                                      int num_out, unsigned char *out[],
                                      size_t out_len[]);

gcry_error_t _gcry_pkey_ed25519_verify (gcry_pkey_hd_t h,
                                        int num_in, const unsigned char *const in[],
                                        const size_t in_len[]);

gcry_error_t _gcry_pkey_ed448_sign (gcry_pkey_hd_t h,
                                    int num_in, const unsigned char *const in[],
                                    const size_t in_len[],
                                    int num_out, unsigned char *out[],
                                    size_t out_len[]);

gcry_error_t _gcry_pkey_ed448_verify (gcry_pkey_hd_t h,
                                      int num_in, const unsigned char *const in[],
                                      const size_t in_len[]);

gcry_error_t _gcry_pkey_rsapss_sign (gcry_pkey_hd_t h,
                                     int num_in, const unsigned char *const in[],
                                     const size_t in_len[],
                                     int num_out, unsigned char *out[],
                                     size_t out_len[]);

gcry_error_t _gcry_pkey_rsapss_verify (gcry_pkey_hd_t h,
                                       int num_in, const unsigned char *const in[],
                                       const size_t in_len[]);

gcry_error_t _gcry_pkey_rsa15_sign (gcry_pkey_hd_t h,
                                    int num_in, const unsigned char *const in[],
                                    const size_t in_len[],
                                    int num_out, unsigned char *out[],
                                    size_t out_len[]);

gcry_error_t _gcry_pkey_rsa15_verify (gcry_pkey_hd_t h,
                                      int num_in, const unsigned char *const in[],
                                      const size_t in_len[]);

gcry_error_t _gcry_pkey_rsa931_sign (gcry_pkey_hd_t h,
                                     int num_in, const unsigned char *const in[],
                                     const size_t in_len[],
                                     int num_out, unsigned char *out[],
                                     size_t out_len[]);

gcry_error_t _gcry_pkey_rsa931_verify (gcry_pkey_hd_t h,
                                       int num_in, const unsigned char *const in[],
                                       const size_t in_len[]);

gcry_error_t _gcry_pkey_dsa_sign (gcry_pkey_hd_t h,
                                  int num_in, const unsigned char *const in[],
                                  const size_t in_len[],
                                  int num_out, unsigned char *out[],
                                  size_t out_len[]);

gcry_error_t _gcry_pkey_dsa_verify (gcry_pkey_hd_t h,
                                    int num_in, const unsigned char *const in[],
                                    const size_t in_len[]);

struct pkey_ecc {
  int curve;

  unsigned char *pk;
  size_t pk_len;

  unsigned char *sk;
  size_t sk_len;
};

struct pkey_rsa {
  int scheme;

  int md_algo;

  unsigned char *n;
  size_t n_len;

  unsigned char *e;
  size_t e_len;

  unsigned char *d;
  size_t d_len;
};

struct pkey_dsa {
  int md_algo;

  unsigned char *p;
  size_t p_len;

  unsigned char *q;
  size_t q_len;

  unsigned char *g;
  size_t g_len;

  unsigned char *x;             /* Private key.  */
  size_t x_len;

  unsigned char *y;             /* Public key.  */
  size_t y_len;
};

struct gcry_pkey_handle {
  int algo;
  unsigned int flags;

  union {
    struct pkey_ecc ecc;
    struct pkey_rsa rsa;
    struct pkey_dsa dsa;
  };
};
