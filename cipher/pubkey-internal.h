/* pubkey-internal.h  - Internal defs for pubkey.c
 * Copyright (C) 2013 g10 code GmbH
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

#ifndef GCRY_PUBKEY_INTERNAL_H
#define GCRY_PUBKEY_INTERNAL_H

/*-- rsa-common.h --*/
gpg_err_code_t
_gcry_rsa_pkcs1_encode_for_enc (gcry_mpi_t *r_result, unsigned int nbits,
                                const unsigned char *value, size_t valuelen,
                                const unsigned char *random_override,
                                size_t random_override_len);
gpg_err_code_t
_gcry_rsa_pkcs1_decode_for_enc (unsigned char **r_result, size_t *r_resultlen,
                                unsigned int nbits, gcry_mpi_t value);
gpg_err_code_t
_gcry_rsa_pkcs1_encode_for_sig (gcry_mpi_t *r_result, unsigned int nbits,
                                const unsigned char *value, size_t valuelen,
                                int algo);
gpg_err_code_t
_gcry_rsa_oaep_encode (gcry_mpi_t *r_result, unsigned int nbits, int algo,
                       const unsigned char *value, size_t valuelen,
                       const unsigned char *label, size_t labellen,
                       const void *random_override, size_t random_override_len);
gpg_err_code_t
_gcry_rsa_oaep_decode (unsigned char **r_result, size_t *r_resultlen,
                       unsigned int nbits, int algo,
                       gcry_mpi_t value,
                       const unsigned char *label, size_t labellen);
gpg_err_code_t
_gcry_rsa_pss_encode (gcry_mpi_t *r_result, unsigned int nbits, int algo,
                      const unsigned char *value, size_t valuelen, int saltlen,
                      const void *random_override, size_t random_override_len);
gpg_err_code_t
_gcry_rsa_pss_verify (gcry_mpi_t value, gcry_mpi_t encoded,
                      unsigned int nbits, int algo, size_t saltlen);



/*-- dsa-common.h --*/
gcry_mpi_t _gcry_dsa_gen_k (gcry_mpi_t q, int security_level);
gpg_err_code_t _gcry_dsa_gen_rfc6979_k (gcry_mpi_t *r_k,
                                        gcry_mpi_t dsa_q, gcry_mpi_t dsa_x,
                                        const unsigned char *h1,
                                        unsigned int h1len,
                                        int halgo,
                                        unsigned int extraloops);


/*-- ecc.c --*/
gpg_err_code_t _gcry_pk_ecc_get_sexp (gcry_sexp_t *r_sexp, int mode,
                                      mpi_ec_t ec);


#endif /*GCRY_PUBKEY_INTERNAL_H*/
