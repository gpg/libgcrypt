/* gcrypt-ac-glue.h - Integrate an asymmetric cipher into Libgcrypt.
   Copyright (C) 2003, Free Software Foundation, Inc.

   This file is part of Libgcrypt.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA.  */

#define _GCRY_AC_VAR_INIT(type, var, var_opaque) \
  type *var = (type *) var_opaque

#define GCRY_AC_VAR_INIT(identifier) \
 _GCRY_AC_VAR_INIT (identifier##_t, identifier, identifier##_opaque)

#define GCRY_AC_VAR_INIT_KEY_PUBLIC      GCRY_AC_VAR_INIT (key_public)
#define GCRY_AC_VAR_INIT_KEY_SECRET      GCRY_AC_VAR_INIT (key_secret)
#define GCRY_AC_VAR_INIT_DATA_ENCRYPTED  GCRY_AC_VAR_INIT (data_encrypted)
#define GCRY_AC_VAR_INIT_DATA_SIGNED     GCRY_AC_VAR_INIT (data_signed)

static gcry_err_code_t
ac_algorithm_generate (unsigned int nbits,
		       void *generate_spec,
		       void *key_secret_opaque,
		       void *key_public_opaque,
		       gcry_mpi_t **misc_data)
{
  GCRY_AC_VAR_INIT_KEY_PUBLIC;
  GCRY_AC_VAR_INIT_KEY_SECRET;
  return generate (key_secret, key_public, nbits, generate_spec, misc_data);
}

static gcry_err_code_t
ac_algorithm_key_secret_check (void *key_secret_opaque)
{
  GCRY_AC_VAR_INIT_KEY_SECRET;
  return key_secret_check (key_secret);
}

static gcry_err_code_t
ac_algorithm_get_nbits (void *key_public_opaque,
			void *key_secret_opaque,
			unsigned int *key_nbits)
{
  GCRY_AC_VAR_INIT_KEY_PUBLIC;
  GCRY_AC_VAR_INIT_KEY_SECRET;
  return get_nbits (key_public, key_secret, key_nbits);
}

static gcry_err_code_t
ac_algorithm_get_grip (void *key_public_opaque,
		       unsigned char *key_grip)
{
  GCRY_AC_VAR_INIT_KEY_PUBLIC;
  return get_grip (key_public, key_grip);
}

#ifdef GCRY_AC_INTERFACE_ENCRYPTION
static gcry_err_code_t
ac_algorithm_encrypt (gcry_mpi_t input,
		      void *key_public_opaque,
		      void *data_encrypted_opaque,
		      unsigned int flags)
{
  GCRY_AC_VAR_INIT_KEY_PUBLIC;
  GCRY_AC_VAR_INIT_DATA_ENCRYPTED;
  return encrypt (input, key_public, data_encrypted, flags);
}

static gcry_err_code_t
ac_algorithm_decrypt (void *data_encrypted_opaque,
		      void *key_secret_opaque,
		      gcry_mpi_t *data_decrypted,
		      unsigned int flags)
{
  GCRY_AC_VAR_INIT_KEY_SECRET;
  GCRY_AC_VAR_INIT_DATA_ENCRYPTED;
  return decrypt (data_encrypted, key_secret, data_decrypted, flags);
}
#endif

#ifdef GCRY_AC_INTERFACE_SIGNING
static gcry_err_code_t
ac_algorithm_sign (gcry_mpi_t input,
		   void *key_secret_opaque,
		   void *data_signed_opaque)
{
  GCRY_AC_VAR_INIT_KEY_SECRET;
  GCRY_AC_VAR_INIT_DATA_SIGNED;
  return sign (input, key_secret, data_signed);
}

static gcry_err_code_t
ac_algorithm_verify (gcry_mpi_t data,
		     void *key_public_opaque,
		     void *data_signed_opaque)
{
  GCRY_AC_VAR_INIT_KEY_PUBLIC;
  GCRY_AC_VAR_INIT_DATA_SIGNED;
  return verify (data, key_public, data_signed);
}
#endif

#ifdef GCRY_AC_ALIASES
static char *algorithm_aliases[] = { GCRY_AC_ALIASES, NULL };
#endif

#define _CONCAT(a, b) a ## b
#define _STR(a) #a
#define _STRINGIFY(a) _STR (a)

#define _GCRY_AC_SPEC_NAME(algorithm) _CONCAT (ac_spec_, algorithm)

gcry_ac_spec_t _GCRY_AC_SPEC_NAME (GCRY_AC_ALGORITHM) =
  {
    _STRINGIFY (GCRY_AC_ALGORITHM),
#ifdef GCRY_AC_ALIASES
    algorithm_aliases,
#else
    NULL,
#endif
    sizeof (key_public_t),
    sizeof (key_secret_t),
#ifdef GCRY_AC_INTERFACE_ENCRYPTION
    sizeof (data_encrypted_t),
#else
    0,
#endif
#ifdef GCRY_AC_INTERFACE_SIGNING
    sizeof (data_signed_t),
#else
    0,
#endif
    sizeof (spec_key_public) / sizeof (spec_key_public[0]),
    sizeof (spec_key_secret) / sizeof (spec_key_secret[0]),
#ifdef GCRY_AC_INTERFACE_ENCRYPTION
    sizeof (spec_data_encrypted) / sizeof (spec_data_encrypted[0]),
#else
    0,
#endif
#ifdef GCRY_AC_INTERFACE_SIGNING
    sizeof (spec_data_signed) / sizeof (spec_data_signed[0]),
#else
    0,
#endif
    spec_key_public,
    spec_key_secret,
#ifdef GCRY_AC_INTERFACE_ENCRYPTION
    spec_data_encrypted,
#else
    0,
#endif
#ifdef GCRY_AC_INTERFACE_SIGNING
    spec_data_signed,
#else
    0,
#endif
    ac_algorithm_generate,
    ac_algorithm_key_secret_check,
#ifdef GCRY_AC_INTERFACE_ENCRYPTION
    ac_algorithm_encrypt,
    ac_algorithm_decrypt,
#else
    NULL,
    NULL,
#endif
#ifdef GCRY_AC_INTERFACE_SIGNING
    ac_algorithm_sign,
    ac_algorithm_verify,
#else
    NULL,
    NULL,
#endif
    ac_algorithm_get_nbits,
    ac_algorithm_get_grip,
  };
