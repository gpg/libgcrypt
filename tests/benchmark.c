/* benchmark.c - Benchmarking for Libgcrypt
   Copyright (C) 2002, 2003 Free Software Foundation, Inc.
 
   This file is part of Libgcrypt.
  
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
  
   Libgcrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/times.h>
#include <gcrypt.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>



#define dim(array) (sizeof (array) / sizeof (*array))



/* Timestamp holders.  */
static clock_t timestamp_start, timestamp_stop;
static char *program_name;



typedef gcry_error_t (*benchmark_action_func_t) (void *context);
typedef gcry_error_t (*benchmark_func_t) (int argc, char **argv);
typedef const char *(*benchmark_help_get_t) (void);

typedef struct benchmark_action
{
  char *comment;
  benchmark_action_func_t func;
  void *context;
} benchmark_action_t;

typedef struct benchmark_function
{
  const char *identifier;
  benchmark_func_t func;
  benchmark_help_get_t help_get;
} benchmark_function_t;



static void
timer_start (void)
{
  struct tms tmp;

  times (&tmp);
  timestamp_start = tmp.tms_utime;
}

static void
timer_stop (void)
{
  struct tms tmp;

  times (&tmp);
  timestamp_stop = tmp.tms_utime;
}

static const char *
timer_delta (void)
{
  static char buf[50];

  sprintf (buf, "%5.0fms",
           (((double) (timestamp_stop - timestamp_start)) / CLOCKS_PER_SEC) * 10000000);
  
  return buf;
}

static gcry_error_t
timer_exec (benchmark_action_t action, const char **time_delta)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;

  timer_start ();
  err = (*action.func) (action.context);
  timer_stop ();
  *time_delta = timer_delta ();

  return err;
}



static gcry_error_t
benchmark_action_process (benchmark_action_t action, unsigned int index)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  const char *time_delta = NULL;

  err = timer_exec (action, &time_delta);
  printf ("\t#%i%s%s%s: \t%s%s%s%s\n",
	  index,
	  action.comment ? " (" : "",
	  action.comment ? action.comment : "",
	  action.comment ? ")" : "",
	  time_delta,
	  err ? " (" : "", err ? gcry_strerror (err) : "", err ? ")" : "");

  return err;
}    

static gcry_error_t
benchmark_actions_process (benchmark_action_t *actions, size_t actions_n)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; i < actions_n; i++)
    benchmark_action_process (actions[i], i);

  return err;
}



typedef struct benchmark_context_random
{
  char *buffer;
  size_t size;
  gcry_random_level_t random_level;
  unsigned int loop;
} benchmark_context_random_t;

static gcry_error_t
benchmark_random_randomize (void *ctx)
{
  benchmark_context_random_t *context = (benchmark_context_random_t *) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; i < context->loop; i++)
    gcry_randomize (context->buffer, context->size, context->random_level);

  return err;
}

static gcry_error_t
benchmark_random (int argc, char **argv)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  char buffer[128];
  benchmark_context_random_t context_randomize_100 = { buffer, sizeof (buffer),
						       GCRY_STRONG_RANDOM, 100 };
  benchmark_context_random_t context_randomize_8 = { buffer, 8,
						     GCRY_STRONG_RANDOM, 100 };
  benchmark_action_t actions[] =
    {
      { "128", benchmark_random_randomize, (void *) &context_randomize_100 },
      { "8", benchmark_random_randomize, (void *) &context_randomize_8 },
    };

  printf ("random\n");
  
  err = benchmark_actions_process (actions, dim (actions));

  return err;
}



typedef struct benchmark_context_md
{
  gcry_md_hd_t handle;
  char *buffer;
  size_t size;
  unsigned int loop;
} benchmark_context_md_t;

static gcry_error_t
benchmark_md_default (void *ctx)
{
  benchmark_context_md_t *context = (benchmark_context_md_t *) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  gcry_md_reset (context->handle);
  for (i = 0; i < context->loop; i++)
    gcry_md_write (context->handle, context->buffer, context->size);
  gcry_md_final (context->handle);

  return err;
}

static gcry_error_t
benchmark_md_one (const char *algorithm_name)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_md_hd_t handle = NULL;
  int algorithm_id = 0;
  unsigned int i = 0;
  char buffer[1000];
  benchmark_context_md_t context_0 = { NULL, buffer, sizeof (buffer), 1000 };
  benchmark_context_md_t context_1 = { NULL, buffer, sizeof (buffer) / 10, 10000 };
  benchmark_context_md_t context_2 = { NULL, "", 1, 1000000 };
  benchmark_action_t actions[] =
    {
      { "1000",    benchmark_md_default, (void *) &context_0 },
      { "10000",   benchmark_md_default, (void *) &context_1 },
      { "1000000", benchmark_md_default, (void *) &context_2 },
    };

  printf ("md: %s\n", algorithm_name);

  algorithm_id = gcry_md_map_name (algorithm_name);
  if (! algorithm_id)
    err = GPG_ERR_DIGEST_ALGO;

  if (! err)
    err = gcry_md_open (&handle, algorithm_id, 0);

  if (! err)
    {
      for (i = 0; i < sizeof (buffer); i++)
	buffer[i] = i & 0xFF;

      context_0.handle = handle;
      context_1.handle = handle;
      context_2.handle = handle;

      err = benchmark_actions_process (actions, dim (actions));
    }

  if (handle)
    gcry_md_close (handle);

  return err;
}

static gcry_error_t
benchmark_md (int argc, char **argv)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; (i < argc) && (! err); i++)
    err = benchmark_md_one (argv[i]);

  return err;
}

static const char *
benchmark_md_get_help (void)
{
  return "<algorithms>";
}



typedef struct benchmark_context_cipher
{
  gcry_cipher_hd_t handle;
  char *buffer;
  size_t buffer_length;
  char *buffer_out;
  unsigned int loop;
} benchmark_context_cipher_t;

static gcry_error_t
benchmark_cipher_one_encrypt (void *ctx)
{
  benchmark_context_cipher_t *context = (benchmark_context_cipher_t *) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; (i < context->loop) && (! err); i++)
    err = gcry_cipher_encrypt (context->handle,
			       context->buffer_out, context->buffer_length,
			       context->buffer, context->buffer_length);

  return err;
}

static gcry_error_t
benchmark_cipher_one_decrypt (void *ctx)
{
  benchmark_context_cipher_t *context = (benchmark_context_cipher_t *) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; (i < context->loop) && (! err); i++)
    err = gcry_cipher_decrypt (context->handle,
			       context->buffer_out, context->buffer_length,
			       context->buffer, context->buffer_length);

  return err;
}

static gcry_error_t
benchmark_cipher_one (const char *algorithm_name)
{
  char key[128], buffer[1000], buffer_out[1000];
  size_t buffer_length = sizeof (buffer);
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_cipher_hd_t handle = NULL;
  unsigned int block_length = 0;
  unsigned int key_length = 0;
  unsigned int mode_index = 0;
  int algorithm_id = 0;
  unsigned int i = 0;
  char comment[15];
  benchmark_context_cipher_t context = { NULL, buffer, 0, buffer_out, 0 };
  benchmark_action_t action = { comment, NULL, (void *) &context };
  struct
  {
    unsigned int mode;
    const char *name;
    int blocked;
  } modes[] =
    {
      { GCRY_CIPHER_MODE_ECB, "ECB", 1 },
      { GCRY_CIPHER_MODE_CBC, "CBC", 1 },
      { GCRY_CIPHER_MODE_CFB, "CFB", 0 },
      { GCRY_CIPHER_MODE_CTR, "CTR", 0 },
      { GCRY_CIPHER_MODE_STREAM, "STREAM", 0 },
    };

  printf ("cipher: %s\n", algorithm_name);

  algorithm_id = gcry_cipher_map_name (algorithm_name);
  if (! algorithm_id)
    err = GPG_ERR_CIPHER_ALGO;

  if (! err)
    {
      key_length = gcry_cipher_get_algo_keylen (algorithm_id);
      if (! key_length)
	err = GPG_ERR_CIPHER_ALGO;
      else
	{
	  assert (key_length <= sizeof (key));

	  for (i = 0; i < key_length; i++)
	    key[i] = i + (clock () & 0xFF);
	}
    }

  if (! err)
    {
      block_length = gcry_cipher_get_algo_blklen (algorithm_id);
      if (! block_length)
	err = GPG_ERR_CIPHER_ALGO;
    }

  for (mode_index = 0; (mode_index < dim (modes)) && (! err); mode_index++)
    {
      if (((block_length > 1) && (modes[mode_index].mode == GCRY_CIPHER_MODE_STREAM))
	  || ((block_length == 1) && modes[mode_index].mode != GCRY_CIPHER_MODE_STREAM))
	continue;

      for (i = 0; i < sizeof (buffer); i++)
        buffer[i] = i & 0xFF;

      err = gcry_cipher_open (&handle, algorithm_id, modes[mode_index].mode, 0);
      if (! err)
	err = gcry_cipher_setkey (handle, key, key_length);
      if (! err)
	if (modes[mode_index].blocked)
	  buffer_length = (buffer_length / block_length) * block_length;

      if (! err)
	{
	  context.handle = handle;
	  context.buffer_length = buffer_length;
	  context.loop = 1000;

	  action.func = benchmark_cipher_one_encrypt;
	  snprintf (action.comment, sizeof (action.comment), "%s-encrypt",
		    modes[mode_index].name);
	  err = benchmark_action_process (action, mode_index);

	  if (! err)
	    err = gcry_cipher_reset (handle);

	  if (! err)
	    {
	      action.func = benchmark_cipher_one_decrypt;
	      snprintf (action.comment, sizeof (action.comment), "%s-decrypt",
			modes[mode_index].name);
	      err = benchmark_action_process (action, mode_index);
	    }
	}
    }

  return err;
}

static gcry_error_t
benchmark_cipher (int argc, char **argv)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; (i < argc) && (! err); i++)
    err = benchmark_cipher_one (argv[i]);

  return err;
}

static const char *
benchmark_cipher_get_help (void)
{
  return "<algorithms>";
}



#define KEY_TYPE_PUBLIC (1 << 0)
#define KEY_TYPE_SECRET (1 << 1)

typedef struct key_spec
{
  const char *name;
  unsigned int flags;
  const char *mpi_string;
} key_spec_t;

static key_spec_t key_specs[] =
  {
    { "n", KEY_TYPE_PUBLIC | KEY_TYPE_SECRET,
      "e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251" },
    { "e", KEY_TYPE_PUBLIC | KEY_TYPE_SECRET,
      "010001" },
    { "d", KEY_TYPE_SECRET,
      "046129F2489D71579BE0A75FE029BD6CDB574EBF57EA8A5B0FDA942CAB943B11"
      "7D7BB95E5D28875E0F9FC5FCC06A72F6D502464DABDED78EF6B716177B83D5BD"
      "C543DC5D3FED932E59F5897E92E6F58A0F33424106A3B6FA2CBF877510E4AC21"
      "C3EE47851E97D12996222AC3566D4CCB0B83D164074ABF7DE655FC2446DA1781" },
    { "p", KEY_TYPE_SECRET,
      "00e861b700e17e8afe6837e7512e35b6ca11d0ae47d8b85161c67baf64377213"
      "fe52d772f2035b3ca830af41d8a4120e1c1c70d12cc22f00d28d31dd48a8d424f1" },
    { "q", KEY_TYPE_SECRET,
      "00f7a7ca5367c661f8e62df34f0d05c10c88e5492348dd7bddc942c9a8f369f9"
      "35a07785d2db805215ed786e4285df1658eed3ce84f469b81b50d358407b4ad361" },
    { "u", KEY_TYPE_SECRET,
      "304559a9ead56d2309d203811a641bb1a09626bc8eb36fffa23c968ec5bd891e"
      "ebbafc73ae666e01ba7c8990bae06cc2bbe10b75e69fcacb353a6473079d8e9b" },
    { NULL },
  };

static gcry_error_t
key_init (key_spec_t *key_specs, gcry_ac_key_type_t type, gcry_ac_key_t *key)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_ac_data_t key_data = NULL;
  gcry_ac_key_t key_new = NULL;
  gcry_mpi_t mpi = NULL;
  unsigned int i = 0;

  err = gcry_ac_data_new (&key_data);
  for (i = 0; key_specs[i].name && (! err); i++)
    {
      if (((type == GCRY_AC_KEY_PUBLIC) && (key_specs[i].flags & KEY_TYPE_PUBLIC))
	  || ((type == GCRY_AC_KEY_SECRET) && (key_specs[i].flags & KEY_TYPE_SECRET)))
	{
	  mpi = gcry_mpi_new (0);
	  err = gcry_mpi_scan (&mpi, GCRYMPI_FMT_HEX, key_specs[i].mpi_string, 0, NULL);

	  if (! err)
	    gcry_ac_data_set (key_data, GCRY_AC_FLAG_COPY | GCRY_AC_FLAG_DEALLOC,
			      key_specs[i].name, mpi);
	  if (mpi)
	    gcry_mpi_release (mpi);
	}
    }
  if (! err)
    err = gcry_ac_key_init (&key_new, NULL, type, key_data);

  if (key_data)
    gcry_ac_data_destroy (key_data);
  
  if (! err)
    *key = key_new;

  return err;
}

typedef struct benchmark_context_ac
{
  gcry_ac_handle_t handle;
  gcry_ac_scheme_t scheme;
  void *opts;
  gcry_ac_key_t key;
  unsigned char *m;
  size_t m_n;
  unsigned char **m2;
  size_t *m2_n;
  unsigned int loop;
} benchmark_context_ac_t;

static gcry_error_t
benchmark_ac_one_encrypt (void *ctx)
{
  benchmark_context_ac_t *context = (benchmark_context_ac_t *) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; (i < context->loop) && (! err); i++)
    err = gcry_ac_data_encrypt_scheme (context->handle, context->scheme, 0, context->opts,
				       context->key, context->m, context->m_n,
				       context->m2, context->m2_n);

  return err;
}

static gcry_error_t
benchmark_ac_one_decrypt (void *ctx)
{
  benchmark_context_ac_t *context = (benchmark_context_ac_t *) ctx;
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; (i < context->loop) && (! err); i++)
    err = gcry_ac_data_decrypt_scheme (context->handle, context->scheme, 0, context->opts,
				       context->key, context->m, context->m_n,
				       context->m2, context->m2_n);

  return err;
}
  
static gcry_error_t
benchmark_ac_one (const char *algorithm_name)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_ac_key_t key_public = NULL;
  gcry_ac_key_t key_secret = NULL;
  gcry_ac_handle_t handle = NULL;
  gcry_ac_id_t algorithm_id = 0;
  unsigned char *buffer_encrypted;
  size_t buffer_encrypted_n;
  unsigned char *buffer_decrypted;
  size_t buffer_decrypted_n;
  char comment[15];
  benchmark_context_ac_t context;
  benchmark_action_t action = { comment, NULL, (void *) &context };
  struct
  {
    gcry_ac_scheme_t scheme;
    void *opts;
    char *m;
    size_t m_n;
    unsigned int loop;
  } ac_specs[] =
    {
#define FILL(scheme, opts, m, loop) \
      { scheme, opts, m, sizeof (m), loop }
      FILL (GCRY_AC_ES_PKCS_V1_5, NULL, "One ring to rule them all", 100),
    };
  unsigned int i = 0;

  printf ("ac: %s\n", algorithm_name);

  err = gcry_ac_name_to_id (algorithm_name, &algorithm_id);
  if (! err)
    err = gcry_ac_open (&handle, algorithm_id, 0);
  if (! err)
    err = key_init (key_specs, GCRY_AC_KEY_PUBLIC, &key_public);
  if (! err)
    err = key_init (key_specs, GCRY_AC_KEY_SECRET, &key_secret);

  if (! err)
    {
      context.handle = handle;
	
      for (i = 0; (i < dim (ac_specs)) && (! err); i++)
	{
	  context.scheme = ac_specs[i].scheme;
	  context.opts = ac_specs[i].opts;
	  context.loop = ac_specs[i].loop;

	  if (! err)
	    {
	      context.m = ac_specs[i].m;
	      context.m_n = ac_specs[i].m_n;
	      context.m2 = &buffer_encrypted;
	      context.m2_n = &buffer_encrypted_n;
	      context.key = key_public;
	      action.func = benchmark_ac_one_encrypt;
	      snprintf (comment, sizeof (comment), "encrypt");

	      err = benchmark_action_process (action, i);
	    }

	  if (! err)
	    {
	      context.m = buffer_encrypted;
	      context.m_n = buffer_encrypted_n;
	      context.m2 = &buffer_decrypted;
	      context.m2_n = &buffer_decrypted_n;
	      context.key = key_secret;
	      action.func = benchmark_ac_one_decrypt;
	      snprintf (comment, sizeof (comment), "decrypt");

	      err = benchmark_action_process (action, i);
	    }
	
	  if (buffer_encrypted)
	    gcry_free (buffer_encrypted);
	  if (buffer_decrypted)
	    gcry_free (buffer_decrypted);
	}
    }

  if (key_public)
    gcry_ac_key_destroy (key_public);
  if (key_secret)
    gcry_ac_key_destroy (key_secret);
  if (handle)
    gcry_ac_close (handle);
  
  return err;
}

static gcry_error_t
benchmark_ac (int argc, char **argv)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int i = 0;

  for (i = 0; (i < argc) && (! err); i++)
    err = benchmark_ac_one (argv[i]);

  return err;
}

static const char *
benchmark_ac_get_help (void)
{
  return "<algorithms>";
}

#if 0
static void
do_powm ( const char *n_str, const char *e_str, const char *m_str)
{
  gcry_mpi_t e, n, msg, cip;
  gcry_error_t err;
  int i;

  err = gcry_mpi_scan (&n, GCRYMPI_FMT_HEX, n_str, 0, 0);
  if (err) BUG ();
  err = gcry_mpi_scan (&e, GCRYMPI_FMT_HEX, e_str, 0, 0);
  if (err) BUG ();
  err = gcry_mpi_scan (&msg, GCRYMPI_FMT_HEX, m_str, 0, 0);
  if (err) BUG ();

  cip = gcry_mpi_new (0);

  start_timer ();
  for (i=0; i < 1000; i++)
    gcry_mpi_powm (cip, msg, e, n);
  stop_timer ();
  printf (" %s", elapsed_time ()); fflush (stdout);
  /*    { */
  /*      char *buf; */

  /*      if (gcry_mpi_aprint (GCRYMPI_FMT_HEX, (void**)&buf, NULL, cip)) */
  /*        BUG (); */
  /*      printf ("result: %s\n", buf); */
  /*      gcry_free (buf); */
  /*    } */
  gcry_mpi_release (cip);
  gcry_mpi_release (msg);
  gcry_mpi_release (n);
  gcry_mpi_release (e);
}


static void
mpi_bench (void)
{
  printf ("%-10s", "powm"); fflush (stdout);

  do_powm (
	   "20A94417D4D5EF2B2DA99165C7DC87DADB3979B72961AF90D09D59BA24CB9A10166FDCCC9C659F2B9626EC23F3FA425F564A072BA941B03FA81767CC289E4",
           "29", 
	   "B870187A323F1ECD5B8A0B4249507335A1C4CE8394F38FD76B08C78A42C58F6EA136ACF90DFE8603697B1694A3D81114D6117AC1811979C51C4DD013D52F8"
           );
  do_powm (
           "20A94417D4D5EF2B2DA99165C7DC87DADB3979B72961AF90D09D59BA24CB9A10166FDCCC9C659F2B9626EC23F3FA425F564A072BA941B03FA81767CC289E41071F0246879A442658FBD18C1771571E7073EEEB2160BA0CBFB3404D627069A6CFBD53867AD2D9D40231648000787B5C84176B4336144644AE71A403CA40716",
           "29", 
           "B870187A323F1ECD5B8A0B4249507335A1C4CE8394F38FD76B08C78A42C58F6EA136ACF90DFE8603697B1694A3D81114D6117AC1811979C51C4DD013D52F8FC4EE4BB446B83E48ABED7DB81CBF5E81DE4759E8D68AC985846D999F96B0D8A80E5C69D272C766AB8A23B40D50A4FA889FBC2BD2624222D8EB297F4BAEF8593847"
           );
  do_powm (
           "20A94417D4D5EF2B2DA99165C7DC87DADB3979B72961AF90D09D59BA24CB9A10166FDCCC9C659F2B9626EC23F3FA425F564A072BA941B03FA81767CC289E41071F0246879A442658FBD18C1771571E7073EEEB2160BA0CBFB3404D627069A6CFBD53867AD2D9D40231648000787B5C84176B4336144644AE71A403CA4071620A94417D4D5EF2B2DA99165C7DC87DADB3979B72961AF90D09D59BA24CB9A10166FDCCC9C659F2B9626EC23F3FA425F564A072BA941B03FA81767CC289E41071F0246879A442658FBD18C1771571E7073EEEB2160BA0CBFB3404D627069A6CFBD53867AD2D9D40231648000787B5C84176B4336144644AE71A403CA40716",
           "29", 
           "B870187A323F1ECD5B8A0B4249507335A1C4CE8394F38FD76B08C78A42C58F6EA136ACF90DFE8603697B1694A3D81114D6117AC1811979C51C4DD013D52F8FC4EE4BB446B83E48ABED7DB81CBF5E81DE4759E8D68AC985846D999F96B0D8A80E5C69D272C766AB8A23B40D50A4FA889FBC2BD2624222D8EB297F4BAEF8593847B870187A323F1ECD5B8A0B4249507335A1C4CE8394F38FD76B08C78A42C58F6EA136ACF90DFE8603697B1694A3D81114D6117AC1811979C51C4DD013D52F8FC4EE4BB446B83E48ABED7DB81CBF5E81DE4759E8D68AC985846D999F96B0D8A80E5C69D272C766AB8A23B40D50A4FA889FBC2BD2624222D8EB297F4BAEF8593847"
           );

  putchar ('\n');


}
#endif



benchmark_function_t benchmark_functions[] =
  {
    { "random", benchmark_random, NULL },
    { "md", benchmark_md, benchmark_md_get_help },
    { "cipher", benchmark_cipher, benchmark_cipher_get_help },
    { "ac", benchmark_ac, benchmark_ac_get_help },
  };



void
print_version (void)
{
  printf ("Libgcrypt %s\n", gcry_check_version (NULL));
}

void
print_help (int status)
{
  unsigned int i = 0;

  if (status != EXIT_SUCCESS)
    fprintf (stderr, "Try `%s --help' or `%s -h' for more information.\n",
	     program_name, program_name);
  else
    {
      printf ("\
Usage: %s <category> [OPTIONS ...]\n\
Benchmark Libgcrypt\n\n",
	      program_name);

      fprintf (stderr, "Categories:\n");
      for (i = 0; i < dim (benchmark_functions); i++)
	fprintf (stderr, " %s%s%s\n",
		benchmark_functions[i].identifier,
		benchmark_functions[i].help_get
		? " "
		: "",
		benchmark_functions[i].help_get
		? (*benchmark_functions[i].help_get) ()
		: "");

      fprintf (stderr, "\n\
      --help                 display this help and exit\n\
      --version              output version information and exit\n\
\n\
Report bugs to %s.\n",
	     PACKAGE_BUGREPORT);
      exit (status);
    }
}

int
main (int argc, char **argv)
{
  const char *getopt_spec_short = "Vh";
  gcry_error_t err = GPG_ERR_NO_ERROR;
  const char *category = NULL;
  unsigned int i = 0;
  int c = 0;

  program_name = argv[0];

  opterr = 0;
  while ((c = getopt (argc, argv, getopt_spec_short)) != -1)
    switch (c)
      {
      case 'V':
	print_version ();
	return EXIT_SUCCESS;
	
      case 'h':
	print_help (EXIT_SUCCESS);
	return EXIT_SUCCESS;
      }

  if (optind < argc)
    for (i = 0; (i < dim (benchmark_functions)) && (! category); i++)
      if (! strcmp (argv[optind], benchmark_functions[i].identifier))
	{
	  category = argv[optind];
	  break;
	}

  if (category)
    {
      gcry_check_version (NULL);
      gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

      optind++;
      err = (*benchmark_functions[i].func) (argc - optind, argv + optind);
    }
  else
    print_help (EXIT_FAILURE);

  if (err)
    fprintf (stderr, "Error: %s\n", gcry_strerror (err));

  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
