/* pkbench.c - Pubkey menchmarking
 *	Copyright (C) 2004 Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <stdio.h>
#include <gcrypt.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

typedef struct context
{
  gcry_sexp_t key_secret;
  gcry_sexp_t key_public;
  gcry_sexp_t data;
  gcry_sexp_t data_encrypted;
  gcry_sexp_t data_signed;
} *context_t;

typedef int (*work_t) (context_t context, unsigned int final);

static void
benchmark (work_t worker, context_t context)
{
  clock_t timer_start, timer_stop;
  unsigned int loop = 10;
  unsigned int i = 0;
  struct tms timer;
  int ret = 0;

  times (&timer);
  timer_start = timer.tms_utime;
  for (i = 0; i < loop; i++)
    {
      ret = (*worker) (context, (i + 1) == loop);
      if (! ret)
	break;
    }
  times (&timer);
  timer_stop = timer.tms_utime;

  if (ret)
    printf ("%.0f ms\n",
	    (((double) ((timer_stop - timer_start) / loop)) / CLOCKS_PER_SEC)
	    * 10000000);
  else
    printf ("[skipped]\n");
}

static int
work_encrypt (context_t context, unsigned int final)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t data_encrypted = NULL;
  int ret = 1;

  err = gcry_pk_encrypt (&data_encrypted,
			 context->data, context->key_public);
  if (gpg_err_code (err) == GPG_ERR_NOT_IMPLEMENTED)
    {
      err = GPG_ERR_NO_ERROR;
      ret = 0;
    }
  else
    {
      assert (! err);

      if (final)
	context->data_encrypted = data_encrypted;
      else
	gcry_sexp_release (data_encrypted);
    }

  return ret;
}

static int
work_decrypt (context_t context, unsigned int final)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  int ret = 1;

  if (! context->data_encrypted)
    ret = 0;
  else
    {
      gcry_sexp_t data_decrypted = NULL;
      
      err = gcry_pk_decrypt (&data_decrypted,
			     context->data_encrypted,
			     context->key_secret);
      assert (! err);
      if (final)
	{
	  gcry_sexp_release (context->data_encrypted);
	  context->data_encrypted = NULL;
	}
      gcry_sexp_release (data_decrypted);
    }

  return ret;
}

static int
work_sign (context_t context, unsigned int final)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  gcry_sexp_t data_signed = NULL;
  int ret = 1;

  err = gcry_pk_sign (&data_signed,
		      context->data, context->key_secret);
  if (gpg_err_code (err) == GPG_ERR_NOT_IMPLEMENTED)
    {
      err = GPG_ERR_NO_ERROR;
      ret = 0;
    }
  else
    {
      assert (! err);

      if (final)
	context->data_signed = data_signed;
      else
	gcry_sexp_release (data_signed);
    }

  return ret;
}

static int
work_verify (context_t context, unsigned int final)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  int ret = 1;

  if (! context->data_signed)
    ret = 0;
  else
    {
      err = gcry_pk_verify (context->data_signed,
			    context->data,
			    context->key_public);
      assert (! err);
      if (final)
	{
	  gcry_sexp_release (context->data_signed);
	  context->data_signed = NULL;
	}
    }

  return ret;
}

static void
process_key_pair (context_t context)
{
  struct
  {
    work_t worker;
    const char *identifier;
  } worker_functions[] = { { work_encrypt, "encrypt" },
			   { work_decrypt, "decrypt" },
			   { work_sign,    "sign"    },
			   { work_verify,  "verify"  } };
  unsigned int i = 0;

  for (i = 0; i < (sizeof (worker_functions) / sizeof (*worker_functions)); i++)
    {
      printf ("%s: ", worker_functions[i].identifier);
      benchmark (worker_functions[i].worker, context);
    }
}

static void
context_init (context_t context, gcry_sexp_t key_secret, gcry_sexp_t key_public)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  unsigned int key_size = 0;
  gcry_mpi_t data = NULL;
  gcry_sexp_t data_sexp = NULL;

  key_size = gcry_pk_get_nbits (key_secret);
  assert (key_size);

  data = gcry_mpi_new (key_size);
  assert (data);

  gcry_mpi_randomize (data, key_size, GCRY_STRONG_RANDOM);
  gcry_mpi_clear_bit (data, key_size - 1);
  err = gcry_sexp_build (&data_sexp, NULL,
			 "(data (flags raw) (value %m))",
			 data);
  assert (! err);
  gcry_mpi_release (data);

  context->key_secret = key_secret;
  context->key_public = key_public;
  context->data = data_sexp;
  context->data_encrypted = NULL;
  context->data_signed = NULL;
}

static void
context_destroy (context_t context)
{
  gcry_sexp_release (context->key_secret);
  gcry_sexp_release (context->key_public);
  gcry_sexp_release (context->data);
}

static void
process_key_pair_file (const char *key_pair_file)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  void *key_pair_buffer = NULL;
  gcry_sexp_t key_pair_sexp = NULL;
  gcry_sexp_t key_secret_sexp = NULL;
  gcry_sexp_t key_public_sexp = NULL;
  struct context context = { NULL };
  struct stat statbuf;
  int key_pair_fd = -1;
  int ret = 0;

  ret = stat (key_pair_file, &statbuf);
  assert (! ret);

  key_pair_fd = open (key_pair_file, O_RDONLY);
  assert (key_pair_fd != -1);

  key_pair_buffer = mmap (NULL, statbuf.st_size, PROT_READ,
			  MAP_PRIVATE, key_pair_fd, 0);
  assert (key_pair_buffer != MAP_FAILED);

  err = gcry_sexp_sscan (&key_pair_sexp, NULL,
			 key_pair_buffer, statbuf.st_size);
  assert (! err);

  key_secret_sexp = gcry_sexp_find_token (key_pair_sexp, "private-key", 0);
  assert (key_secret_sexp);
  key_public_sexp = gcry_sexp_find_token (key_pair_sexp, "public-key", 0);
  assert (key_public_sexp);

  gcry_sexp_release (key_pair_sexp);
  ret = munmap (key_pair_buffer, statbuf.st_size);
  assert (! ret);
  ret = close (key_pair_fd);
  assert (! ret);

  context_init (&context, key_secret_sexp, key_public_sexp);

  printf ("Key file: %s\n", key_pair_file);
  process_key_pair (&context);
  printf ("\n");

  context_destroy (&context);
}

static const char *program_name = NULL;

static void
print_usage (int err)
{
  fprintf (err ? stderr : stdout,
	   "Usage: %s [--help ] [ --genkey <algorithm>,<size> ] <key files ...>\n\n",
	   program_name);
  exit (err);
}

static void
generate_key (const char *algorithm, const char *key_size)
{
  gcry_error_t err = GPG_ERR_NO_ERROR;
  size_t key_pair_buffer_size = 0;
  char *key_pair_buffer = NULL;
  gcry_sexp_t key_spec = NULL;
  gcry_sexp_t key_pair = NULL;

  err = gcry_sexp_build (&key_spec, NULL,
			 "(genkey (%s (nbits %s)))",
			 algorithm, key_size);
  assert (! err);

  err = gcry_pk_genkey (&key_pair, key_spec);
  assert (! err);

  key_pair_buffer_size = gcry_sexp_sprint (key_pair, GCRYSEXP_FMT_ADVANCED,
					   NULL, 0);
  key_pair_buffer = malloc (key_pair_buffer_size);
  assert (key_pair_buffer);

  gcry_sexp_sprint (key_pair, GCRYSEXP_FMT_ADVANCED,
		    key_pair_buffer, key_pair_buffer_size);

  printf ("%.*s", key_pair_buffer_size, key_pair_buffer);
}

int
main (int argc, char **argv)
{
  program_name = argc ? argv[0] : "";

  gcry_control (GCRYCTL_DISABLE_SECMEM);
  
  if (argv[1] && ((! strcmp (argv[1], "--help"))
		  || (! strcmp (argv[1], "-h"))))
    print_usage (0);
  else if (argv[1] && ((! strcmp (argv[1], "--genkey"))
		       || (! strcmp (argv[1], "-g"))))
    {
      char *algorithm = NULL;
      char *key_size = NULL;

      if (argv[2])
	{
	  algorithm = argv[2];
	  key_size = strchr (algorithm, ',');
	  if (key_size)
	    {
	      *key_size = 0;
	      key_size++;
	    }
	}

      if (algorithm && key_size)
	generate_key (algorithm, key_size);
      else
	print_usage (EXIT_FAILURE);
    }
  else
    {
      unsigned int i = 0;

      for (i = 1; (i < argc); i++)
	process_key_pair_file (argv[i]);
    }

  return EXIT_SUCCESS;
}
