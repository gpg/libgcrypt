/* pubkey.c - Public key encryption/decryption tests
 *	Copyright (C) 2003, 2005 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/wait.h>

#include "../src/compat/gcrypt.h"



#define DIM(a) (sizeof (a) / sizeof (*a))

static int verbose;

static void
die (const char *format, ...)
{
  va_list arg_ptr ;

  va_start( arg_ptr, format ) ;
  vfprintf (stderr, format, arg_ptr );
  va_end(arg_ptr);
  exit (1);
}



#if 0

static int
thread_init (void)
{
  return 0;
}

static int
thread_mutex_init (void **priv)
{
  *priv = NULL;
  return 0;
}

static int
thread_mutex_destroy (void **priv)
{
  return 0;
}

static int
thread_mutex_lock (void **priv)
{
  return 0;
}

static int
thread_mutex_unlock (void **priv)
{
  return 0;
}

static ssize_t
thread_read (int fd, void *buf, size_t nbytes)
{
  return read (fd, buf, nbytes);
}

static ssize_t
thread_write (int fd, const void *buf, size_t nbytes)
{
  return write (fd, buf, nbytes);
}

static ssize_t
thread_select (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
	       struct timeval *timeout)
{
  return select (nfd, rset, wset, eset, timeout);
}

static ssize_t
thread_waitpid (pid_t pid, int *status, int options)
{
  return waitpid (pid, status, options);
}

static int
thread_accept (int s, struct sockaddr *addr, socklen_t *length_ptr)
{
  return accept (s, addr, length_ptr);
}

static int
thread_connect (int s, struct sockaddr *addr, socklen_t length)
{
  return connect (s, addr, length);
}

static int
thread_sendmsg (int s, const struct msghdr *msg, int flags)
{
  return sendmsg (s, msg, flags);
}

static int
thread_recvmsg (int s, struct msghdr *msg, int flags)
{
  return recvmsg (s, msg, flags);
}

static struct gcry_thread_cbs thread_cbs =
  {
    GCRY_THREAD_OPTION_USER,
    thread_init, thread_mutex_init, thread_mutex_destroy, thread_mutex_lock,
    thread_mutex_unlock, thread_read, thread_write, thread_select,
    thread_waitpid, thread_accept, thread_connect, thread_sendmsg,
    thread_recvmsg
  };

static char *foo_pointer = "foo";

static void
progress (void *cb_data,
	  const char *what, int printchar, int current, int total)
{
  assert (cb_data == foo_pointer);
  fprintf (stderr, "[Progress: %s, %c, %i, %i]",
	   what, printchar, current, total);
}


static void
check_general_check_version (void)
{
  const char *s;

  s = gcry_check_version (NULL);
  assert (s);
  s = gcry_check_version (s);
  assert (s);
}

void
check_general_control (void)
{
  /* FIXME: there need to be extra tests for each gcry_control
     commands.  */
#if 0
  gcry_control (GCRYCTL_SET_THREAD_CBS, thread_cbs);
  gcry_control (GCRYCTL_DISABLE_SECMEM);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);
  gcry_control (GCRYCTL_SET_RANDOM_SEED_FILE, "/dev/null");
  gcry_control (GCRYCTL_UPDATE_RANDOM_SEED_FILE, "/dev/null");
  gcry_control (GCRYCTL_SET_VERBOSITY, 1); /* ? */
  gcry_control (GCRYCTL_SET_DEBUG_FLAGS, ~0);
  gcry_control (GCRYCTL_CLEAR_DEBUG_FLAGS, ~0);
  gcry_control (GCRYCTL_DISABLE_INTERNAL_LOCKING);
  /* ? */
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED_FINISHED);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P);
  gcry_control (GCRYCTL_INITIALIZATION_P);
  gcry_control (GCRYCTL_FAST_POLL);
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM);
  gcry_control (GCRYCTL_ENABLE_M_GUARD);
#endif
}

void
check_general_progress (void)
{
  gcry_set_progress_handler (progress, foo_pointer);
}

void
check_general_allocation_handler (void)
{
  gcry_set_allocation_handler (gcry_malloc, gcry_malloc_secure,
			       gcry_is_secure, gcry_realloc, gcry_free);
}

void
check_general (void)
{
  check_general_control ();
}

#endif



enum sexp_creation_mode
  {
    SEXP_NEW,
    SEXP_CREATE,
    SEXP_SSCAN
  };

static int sexp_formats[] =
  {
    /* FIXME!! */
    0
  };

/* This function handles:
 *   gcry_sexp_new()
 *   gcry_sexp_create()
 *   gcry_sexp_sscan()
 *   gcry_sexp_build() FIXME
 *   gcry_sexp_build_array() FIXME
 *   gcry_sexp_release().  */
static void
check_subsystem_sexp_CREATE (enum sexp_creation_mode mode)
{
  gcry_sexp_t sexp;
  gcry_error_t err;
  unsigned int i;
  size_t buffer_n;
  size_t erroff;
  void *buffer;
  size_t sexp_len_0;
  size_t sexp_len_1;
  char *sexp_s;
  int j;
  struct
  {
    const void *buffer;
    ssize_t buffer_n;
    int autodetect;
    gcry_err_code_t err;
    size_t erroff;
  } specs[] =
    {
      { "(foo (bar))", -1, 1, 0, -1 },
      { "(", -1, 1, GPG_ERR_SEXP_UNMATCHED_PAREN, -1 }
      /* FIXME: more entries needed.  */
    };

  for (i = 0; i < DIM (specs); i++)
    {
      if (specs[i].buffer_n == -1)
	buffer_n = strlen (specs[i].buffer);
      else
	buffer_n = specs[i].buffer_n;

      switch (mode)
	{
	case SEXP_NEW:
	  err = gcry_sexp_new (&sexp,
			       specs[i].buffer, buffer_n,
			       specs[i].autodetect);
	  break;

	case SEXP_CREATE:
	  buffer = gcry_xmalloc (buffer_n);
	  memcpy (buffer, specs[i].buffer, buffer_n);

	  err = gcry_sexp_create (&sexp,
				  buffer, buffer_n,
				  specs[i].autodetect,
				  gcry_free);
	  break;

	case SEXP_SSCAN:
	  err = gcry_sexp_sscan (&sexp, &erroff,
				 specs[i].buffer, buffer_n);

	  break;

	default:
	  err = 0;		/* Silence compiler.  */
	  break;
	}

      /* Verify that the error code is the expected one.  */
      assert (gcry_err_code (err) == specs[i].err);

      /* Verify that SEXP has been set to NULL in case of an
	 error.  */
      assert (((! err) && sexp) || (! sexp));

      if (mode == SEXP_SSCAN)
	assert ((specs[i].erroff == -1) || (specs[i].erroff == erroff));

      if (sexp)
	{
	  /* We got a new sexp object, therefore we can test some
	     other interfaces now (gcry_sexp_sprint(),
	     gcry_sexp_find_token(), gcry_sexp_length()).  */

	  for (j = 0; j < DIM (sexp_formats); j++)
	    {
	      sexp_len_0 = gcry_sexp_sprint (sexp, sexp_formats[j],
					     NULL, 0);
	      sexp_s = gcry_xmalloc (sexp_len_0);
	      assert (sexp_s);

	      sexp_len_1 = gcry_sexp_sprint (sexp, sexp_formats[j],
					     sexp_s, sexp_len_0);

	      /* Verify that return value of gcry_sexp_sprint() is the
		 same for the same sexp object.  */
	      //	      assert (sexp_len_1 == sexp_len_0);

	      /* FIXME: we should verify that the printed sexp looks
		 like expected.  */

	      /* FIXME: add test for find_token() and length().  */

	      gcry_free (sexp_s);
	    }
	}

      gcry_sexp_release (sexp);
    }
}



static void
check_subsystem_sexp (void)
{
  check_subsystem_sexp_CREATE (SEXP_CREATE);
  check_subsystem_sexp_CREATE (SEXP_NEW);
  check_subsystem_sexp_CREATE (SEXP_SSCAN);
}




#if 0
void
check_subsystem_pubkey_map_name (void)
{
  unsigned int i;
  struct
  {
    const char *name;
    int id;
  } specs[] =
    {
      { "BLOWFISH", },
      { "AES", },
      { "", 0},
      { NULL, 0 }
    };
  int id;

  for (i = 0; i < DIM (specs); i++)
    {
      id = gcry_pk_map_name (specs[i].name);
      assert (id == specs[i].id);
    }
}

void
check_subsystem_pubkey_get_keygrip (void)
{
  unsigned char buffer[20];
  unsigned char *ret;
  unsigned int i;
  gcry_sexp_t sexp;
  struct
  {
    gcry_sexp_t sexp;
    char *key;
    unsigned char grip[20];
  } specs[] =
    {
      { NULL,
	"(public-key"
	" (rsa"
	"  (n #00BDD6DB2341D74750899E5A5F99DE0D4B30ED43914A67B0A2F3A4D4C53A883482275A33F842A951DB8CEC7115A5412C8449669BA1178835FBB65F2FA3183E5E24EB7A8C5A01F257548AF5B8D1934FD799EBAE221DEE5428F2B7627A6E5ABF4D1E4E57CDB24A731C0C86E3ECD9B437CF666A02FC9C2B04331AEBB55EDE3D71ACEB#)"
	"  (e #010001#)))",
	foo },
      { NULL,
	"(private-key"
	" (rsa"
	"  (n #00BDD6DB2341D74750899E5A5F99DE0D4B30ED43914A67B0A2F3A4D4C53A883482275A33F842A951DB8CEC7115A5412C8449669BA1178835FBB65F2FA3183E5E24EB7A8C5A01F257548AF5B8D1934FD799EBAE221DEE5428F2B7627A6E5ABF4D1E4E57CDB24A731C0C86E3ECD9B437CF666A02FC9C2B04331AEBB55EDE3D71ACEB#)"
	"  (e #010001#)"
	"  (d #3BCB0AA6A63C4A4801B090C27FD242D9A605753CB3F4C8DBEA65C66680B319E6CCC24A902D5EEB5B7D9D9358BFFE3129517D3213A137D3D8FE6E28B0F417E0CAB12034D452CCC6531310F7040AAE7B84E02556918F91D2FD70488DA8B6D50CB8F22204C8A597E3512486CBA368635555B5DE102148266CF0B3C33676959ED731#)"
	"  (p #00D218452DF06198A78B4DA3B418B175318B1876EC923D6311A56AD2A729E00FB07E77E2FB004158613F176A184BE5AF2CC0AA111FCED7423EC126D718A3D2BE9F#)"
	"  (q #00E75195EAE9E3F8F117B73C90C5523BF844AD7F0E42B8E8906477060AA6B16876AE60A9794690FFE79AF124D88639992E2FEF80F62B049F04AFDA7A0ED1E20A35#)"
	"  (u #5B8579EC2A69BBE35C3F0992F5D8A42A7E3A6CBE1041A7FCB14A10BCEBB14AAED42128D3C291B88E6A6067DE0A441AF66860DB73CF7C069ADAAB0DC13721645E#)))",
	foo },
      { NULL,
	
	

    };
  

void
check_subsystem_util_mem (void)
{
  void *p;

  p = gcry_malloc (5000);
  if (p)
    log ("Warning: gcry_malloc (5000) return NULL");
  gcry_free (p);
}

void
check_subsystem_util (void)
{
  check_subsystem_util_mem ();
}



void
check_subsystem_mpi_new (void)
{
  gcry_mpi_t mpi;
  unsigned int i;
  struct
  {
    unsigned int nbits;
  } specs[] =
    {
      { 0 },
      { 1 },
      { 2 },
      { 3 },
      { 100 },
      { 200 },
      { 1000 },
      { 8000 },
      { 0 },
    };

  for (i = 0; i < DIM (specs); i++)
    {
      mpi = gcry_mpi_new (specs[i].nbits);
      assert (! ((! specs[i].nbits) && mpi));
      if (specs[i].nbits && (! mpi))
	die ("OOM for MPI of %u bits\n", specs[i].nbits);
      gcry_mpi_release (mpi);
    }
}

void
check_subsystem_mpi_copy (void)
{
  gcry_error_t err;
  unsigned int i;
  gcry_mpi_t a;
  gcry_mpi_t b;
  struct
  {
    const char *s;
  } specs[] =
    {
      { "001234567890BCDEF45A" }
      { "00" },
      { "0001" },
    };

  for (i = 0; i < DIM (specs); i++)
    {
      err = gcry_mpi_scan (&a, GCRYMPI_FMT_HEX, specs[i].s, 0, NULL);
      die ("error while scanning MPI: %s\n", gpg_strerror (err));
      b = gcry_mpi_copy (a);
      die ("MPI could not be copied\n");
      assert (! gcry_mpi_cmp (a, b));
      gcry_mpi_release (a);
      gcry_mpi_release (b);
    }
}

void
check_subsystem_mpi_set (void)
{
  gcry_error_t err;
  unsigned int i;
  gcry_mpi_t a;
  gcry_mpi_t b;
  gcry_mpi_t c;
  struct
  {
    int is_null;
    int is_zero;
    int set_ui;
    unsigned int n;
  } specs[] =
    {
      /* 0? */
      { 0, 0, 0, 1 },
      { 0, 1, 0, 1 },
      { 1, 0, 0, 100 },
      { 1, 0, 0, 200 },
      { 0, 0, 0, 300 },
      { 0, 1, 0, 400 },
      { 1, 0, 0, 1000 },
      { 1, 0, 0, 1000 },
      { 0, 0, 1, 1 },
      { 0, 1, 1, 1 },
      { 1, 0, 1, 100 },
      { 1, 0, 1, 200 },
      { 0, 0, 1, 300 },
      { 0, 1, 1, 400 },
      { 1, 0, 1, 1000 },
      { 1, 0, 1, 1000 }
    };
  

  for (i = 0; i < DIM (specs); i++)
    {
      if (specs[i].is_null)
	a = NULL;
      else
	{
	  a = gcry_mpi_new (0);
	  assert (a);
	  if (! specs[i].is_null)
	    gcry_mpi_randomize (a, specs[i].n, GCRY_RANDOM_WEAK);
	}

      if (! specs[i].set_ui)
	{
	  b = gcry_mpi_new (0);
	  assert (b);
	  gcry_mpi_randomize (b, specs[i].n, GCRY_RANDOM_WEAK);
	  
	  c = gcry_mpi_set (a, b);
	}
      else
	{
	  b = NULL;
	  c = gcry_mpi_set_ui (a, specs[i].n);
	}

      assert ((a == c) || (! a));

      if (specs[i].set_ui)
	assert (! gcry_mpi_cmp_ui (c, specs[i].n));
      else
	assert (! gcry_mpi_cmp (c, b));
      
      gcry_mpi_release (b);
      gcry_mpi_release (c);
    }
}

void
gcry_mpi_swap (gcry_mpi_t a, gcry_mpi_t b)
{

}


void
check_subsystem_mpi_prime (void)
{
  gcry_error_t err;

  err = gcry_prime_generate (&prime, 100);
}

void
check_subsystem_mpi (void)
{
  check_subsystem_mpi_prime ();
}



void
check_subsystem_cipher_encrypt_decrypt_0 (void)
{
  gcry_cipher_hd_t handle;
  gcry_error_t err;
  unsigned char *data_in;
  size_t data_in_n;
  unsigned char *data_out;
  size_t data_out_n;
  unsigned char *data_decrypted;
  size_t data_decrypted_n;
  unsigned int i_algorithms;
  unsigned int i_modes;
  size_t block_size;
  int algorithms[] =
    {
      GCRY_CIPHER_BLOWFISH,
      GCRY_CIPHER_AES
    }
  int modes[] = 
    {
      GCRY_CIPHER_MODE_ECB,
      GCRY_CIPHER_MODE_CFB,
      GCRY_CIPHER_MODE_CBC,
      GCRY_CIPHER_MODE_CTR
    };
  struct
  {
    unsigned char n;
  } specs[] =
    {
      { 0 },
      { 1 },
      { 100 },
      { 1000 },
    };
  unsigned char i_specs;
  unsigned int p;
  unsigned char *key;
  size_t key_size;

  for (i_algorithms = 0; i_algorithms < DIM (algorithms); i_algorithsm++)
    for (i_modes = 0; i_modes < DIM (modes); i_modes++)
      for (i_specs = 0; i_specs < DIM (specs); i_specs++)
	{
	  key_size = gcry_cipher_get_algo_keylen (algorithms[i_algorithms]);
	  assert (key_size);
	  key = gcry_xmalloc (key_size);
	  for (p = 0; p < key_size; p++)
	    key[p] = p & 0xFF;

	  block_size = gcry_cipher_get_algo_blklen (algorithms[i_algorithms]);
	  assert (block_size);
	  err = gcry_cipher_open (&handle, algorithms[i_algorithms],
				  modes[i_modes].mode, 0);
	  assert (! err);
	  if (specs[i_specs].n)
	    {
	      data_decrypted_n = data_out_n = data_in_n = block_size * specs[i_specs].n;
	      data_decrypted = gcry_xmalloc (data_decrypted_n);
	      data_out = gcry_xmalloc (data_out_n);
	      data_in = gcry_xmalloc (data_in_n);
	    }
	  else
	    {
	      data_out_n = data_in_n = 0;
	      data_out = data_in = NULL:
	    }

	  gcry_randomize (data_in, data_in_n, GCRY_WEAK_RANDOM);

	  err = gcry_cipher_setkey (handle, key, key_size);
	  assert (! err);

	  err = gcry_cipher_encrypt (handle,
				     data_out, data_out_n,
				     data_in, data_in_n);
	  assert (! err);
	  err = gcry_cipher_decrypt (handle,
				     data_decrypted, data_decrypted_n,
				     data_out, data_out_n);
	  assert (! err);

	  assert (! memcmp (data_in, data_decrypted, data_in));

	  gcry_cipher_close (handle);
	  gcry_free (data_in);
	  gcry_free (data_out);
	  gcry_free (data_decrypted);
	}
}
     
void
check_subsystem_cipher_encrypt_decrypt (void)
{
  check_subsystem_cipher_encrypt_decrypt_0 ();
}
      



void
check_subsystem_cipher (void)
{
}



void
check_subsystem_random_add_bytes (void)
{
  gcry_error_t err;
  unsigned int i;
  struct
  {
    const unsigned char *buffer;
    ssize_t length;
    int quality;
  } specs[] =
    {
      { NULL, 0, GCRY_WEAK_RANDOM },
      { "", 0, GCRY_STRONG_RANDOM },
      { "a", -1, GCRY_VERY_STRONG_RANDOM },
      { "foo                                       00                   1 bar", -1,
	GCRY_VERY_STRONG_RANDOM }
    };

  for (i = 0; i < DIM (specs); i++)
    {
      err = gcry_random_add_bytes (specs[i].buffer, specs[i].length,
				   specs[i].quality);
      assert (! err);
    }
}

void
check_subsystem_random_fast_random_poll (void)
{
  gcry_error_t err;
  unsigned int i;

  for (i = 0; i < 10; i++)
    {
      err = gcry_fast_random_poll ();
      assert (! err);
    }
}

void
check_subsystem_random_randomize (void)
{
  unsigned char *buffer;
  unsigned int i, j;
  struct
  {
    int size;
    int level;
  } specs[] =
    {
      { 100, GCRY_WEAK_RANDOM },
      { 90, GCRY_STRONG_RANDOM },
      { 50, GCRY_VERY_STRONG_RANDOM_RANDOM },
      { 0, GCRY_WEAK_RANDOM },
      { 0, GCRY_STRONG_RANDOM },
      { 0, GCRY_VERY_STRONG_RANDOM }
    };

  for (i = 0; i < DIM (specs); i++)
    {
      buffer = xmalloc (specs[i].size);
      memset (buffer, 0);
      gcry_randomize (buffer, specs[i].size, specs[i].level);
      for (j = 0; j < specs[i].size; j++)
	if (buffer[j])
	  break;
      assert (j < specs[i].size);
      xfree (buffer);
    }
}

void
check_subsystem_random_create_nonce (void)
{
  unsigned char buffer[1000];
  unsigned int i;
  struct
  {
    int length;
  } specs[i] =
    {
      { 0 },
      { 10 },
      { 200 },
      { 500 },
      { 1000 }
    };

  for (i = 0; i < DIM (specs); i++)
    gcry_create_nonce (buffer, specs[i].length);
}

void
check_subsystem_random (void)
{
  check_subsystem_random_add_bytes ();
  check_subsystem_random_fast_random_poll ();
  check_subsystem_random_randomize ();
}



void
check_subsystem_prime_generate (void)
{
  gcry_error_t err;
}

void
check_subsystem_prime_group_generator (void)
{
}

void
check_subsystem_prime_check (void)
{
}

void
check_subsystem_prime (void)
{
  check_subsystem_prime_generate ();
  check_subsystem_prime_group_generator ();
  check_subsystem_prime_check ();
}

#endif

void
check_run (void)
{
  check_subsystem_sexp ();
}

int
main (int argc, char **argv)
{
  int debug = 0;
  int i = 1;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

  for (; i > 0; i--)
    check_run ();
  
  return 0;
}
