/* ac.c - Tests for the asymmetric cipher subsystem.
   Copyright (C) 2003 Free Software Foundation, Inc.

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

#include "test.h"

typedef struct test_context_ac
{
  int algorithm_id;
  gcry_ac_handle_t handle;
  gcry_ac_key_pair_t key_pair;
  gcry_ac_key_t key_secret;
  gcry_ac_key_t key_public;
  gcry_mpi_t mpi_plain;
  gcry_ac_data_t data_encrypted;
  gcry_mpi_t mpi_decrypted;
} *test_context_ac_t;

static char default_mpi_plain[] = "5B428AC13BE90CA12458CF";

static void
test_context_ac_init (const char *identifier, test_context_t *ctx)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_mpi_t mpi_plain = NULL;
  test_context_ac_t context = NULL;
  gcry_ac_handle_t handle = NULL;
  gcry_ac_id_t algorithm_id = 0;

  err = gcry_ac_name_to_id (identifier, &algorithm_id);
  test_assert_err (err);

  err = gcry_ac_open (&handle, algorithm_id, 0);
  test_assert_err (err);

  context = gcry_malloc (sizeof (*context));
  test_assert (context);

  err = gcry_mpi_scan (&mpi_plain, GCRYMPI_FMT_HEX, default_mpi_plain, 0, NULL);
  test_assert_err (err);

  context->algorithm_id = algorithm_id;
  context->handle = handle;
  context->key_pair = NULL;
  context->key_secret = NULL;
  context->key_public = NULL;
  context->mpi_plain = mpi_plain;
  context->data_encrypted = NULL;
  context->mpi_decrypted = NULL;

  *ctx = (test_context_t) context;
}

static void
test_context_ac_destroy (test_context_t ctx)
{
  test_context_ac_t context = (test_context_ac_t) ctx;

  gcry_ac_close (context->handle);
  if (context->key_pair)
    gcry_ac_key_pair_destroy (context->key_pair);
  if (context->mpi_plain)
    gcry_mpi_release (context->mpi_plain);
  if (context->mpi_decrypted)
    gcry_mpi_release (context->mpi_decrypted);
  if (context->data_encrypted)
    gcry_ac_data_destroy (context->data_encrypted);

  gcry_free (context);
}

static void
test_ac_identifiers_get (char ***identifiers, unsigned int *identifiers_n)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  char **identifiers_new = NULL;
  int *id_list = NULL;
  int id_list_n = 0;
  int i = 0;

  err = gcry_ac_list (&id_list, &id_list_n);
  test_assert_err (err);

  identifiers_new = gcry_malloc (sizeof (*identifiers_new) * id_list_n);
  test_assert (identifiers_new);

  for (i = 0; i < id_list_n; i++)
    {
      err = gcry_ac_id_to_name (id_list[i], (const char **) &identifiers_new[i]);
      test_assert (identifiers_new[i]);
    }

  if (id_list)
    gcry_free (id_list);

  *identifiers = identifiers_new;
  *identifiers_n = id_list_n;
}

static void
test_action_key_generate (test_context_t ctx, unsigned int flags)
{
  test_context_ac_t context = (test_context_ac_t) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_ac_key_pair_t key_pair = NULL;

  if (flags & TEST_ACTION_FLAG_RUN)
    {
      err = gcry_ac_key_pair_generate (context->handle, 1024, NULL, &key_pair, NULL);
      test_assert_err (err);
      context->key_secret = gcry_ac_key_pair_extract (key_pair, GCRY_AC_KEY_SECRET);
      test_assert (context->key_secret);
      context->key_public = gcry_ac_key_pair_extract (key_pair, GCRY_AC_KEY_PUBLIC);
      test_assert (context->key_public);
    }
}

static void
test_action_encrypt (test_context_t ctx, unsigned int flags)
{
  test_context_ac_t context = (test_context_ac_t) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;

  if (context->algorithm_id != GCRY_AC_DSA)
    {
      if (flags & TEST_ACTION_FLAG_RUN)
	{
	  err = gcry_ac_data_encrypt (context->handle, 0, context->key_public,
				      context->mpi_plain, &context->data_encrypted);
	  test_assert_err (err);
	}
      if (flags & TEST_ACTION_FLAG_DEALLOCATE)
	{
	  gcry_ac_data_destroy (context->data_encrypted);
	  context->data_encrypted = NULL;
	}
    }
}

static void
test_action_decrypt (test_context_t ctx, unsigned int flags)
{
  test_context_ac_t context = (test_context_ac_t) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;

  if (context->algorithm_id != GCRY_AC_DSA)
    {
      if (flags & TEST_ACTION_FLAG_RUN)
	{
	  err = gcry_ac_data_decrypt (context->handle, 0, context->key_secret,
				      &context->mpi_decrypted, context->data_encrypted);
	  test_assert_err (err);
	  
	  if (! (flags & TEST_ACTION_FLAG_BENCHMARK))
	    test_assert (! gcry_mpi_cmp (context->mpi_decrypted, context->mpi_plain));
	}
      
      if (flags & TEST_ACTION_FLAG_DEALLOCATE)
	{
	  gcry_mpi_release (context->mpi_decrypted);
	  context->mpi_decrypted = NULL;
	}
    }
}

test_action_t test_actions_ac[] =
  {
    { "key_generate",  test_action_key_generate,   2 },
    { "encrypt",       test_action_encrypt,      100 },
    { "decrypt",       test_action_decrypt,      100 }
  };

TEST_GROUP_DEFINE (MAPPING, ac);
