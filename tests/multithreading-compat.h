#if defined HAVE_PTHREAD || defined HAVE_PTH

/* multithreading-compat.h - Test multithreading support
   Copyright (C) 2005 Free Software Foundation, Inc.
 
   This file is part of Libgcrypt.

   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   Libgcrypt is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "../src/compat/gcrypt.h"
#include "common.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>
#else
#ifdef HAVE_PTH
#include <pth.h>
#else
#error bug
#endif
#endif

/* FIXME, threading.  */

unsigned int test_startup_flags = (STARTUP_ENABLE_THREADING
				   | STARTUP_ENABLE_SECURE_MEMORY);



static int verbose;



/* Thread wrappers.  */

#ifdef HAVE_PTHREAD
void
create_thread (void *(*func) (void *arg), void *arg)
{
  pthread_t thread_id;
  int ret;

  ret = pthread_create (&thread_id, NULL, func, arg);
  assert (! ret);
  ret = pthread_detach (thread_id);
  assert (! ret);
}
static const char *threading = "pthread";
#else
#ifdef HAVE_PTH
void
create_thread (void *(*func) (void *arg), void *arg)
{
  pth_attr_t attr;
  pth_t thread_id;

  attr = pth_attr_new ();
  assert (attr);
  pth_attr_set(attr, PTH_ATTR_JOINABLE, FALSE);

  thread_id = pth_spawn (attr, func, arg);
  assert (thread_id);
}
static const char *threading = "pth";
#endif
#endif



static void *
test_secmem_thread_main (void *arg)
{
  unsigned int nloops = 8000;
  unsigned int size;
  unsigned int i;
  void *chunk;

  for (i = 0; i < nloops; i++)
    {
      size = rand () % 32;
      chunk = gcry_malloc_secure (size);
      assert (chunk);
      gcry_free (chunk);
    }

  return NULL;
}

static void
test_secmem (void)
{
  unsigned int nthreads = 20;
  unsigned int i;

  printf ("threads started:");
  for (i = 0; i < nthreads; i++)
    {
      create_thread (test_secmem_thread_main, NULL);
      printf (" %u", i);
    }
  printf ("\n");

  sleep (10);
}



/* Module stress testing.  */

static gcry_error_t
foo_setkey (void *c, const unsigned char *key, unsigned keylen)
{
  return 0;
}

#define FOO_BLOCKSIZE 16

static void
foo_encrypt (void *c, unsigned char *outbuf, const unsigned char *inbuf)
{
  int i;

  for (i = 0; i < FOO_BLOCKSIZE; i++)
    outbuf[i] = inbuf[i] + 13;
}

static void
foo_decrypt (void *c, unsigned char *outbuf, const unsigned char *inbuf)
{
  int i;

  for (i = 0; i < FOO_BLOCKSIZE; i++)
    outbuf[i] = inbuf[i] - 13;
}

static gcry_cipher_spec_t cipher_spec_foo =
  {
    "FOO", NULL, NULL, 16, 0, 0,
    foo_setkey, foo_encrypt, foo_decrypt,
    NULL, NULL,
  };


static void *
test_module_thread_main (void *arg)
{
  unsigned int nloops = 2000;
  gcry_error_t err;
  unsigned int i;
  int algorithm;
  gcry_module_t module;

  for (i = 0; i < nloops; i++)
    {
      err = gcry_cipher_register (&cipher_spec_foo, &algorithm, &module);
      assert (! err);

      gcry_cipher_unregister (module);
    }

  return NULL;
}

static void
test_module (void)
{
  unsigned int nthreads = 20;
  unsigned int i;

  printf ("threads started:");
  for (i = 0; i < nthreads; i++)
    {
      create_thread (test_module_thread_main, NULL);
      printf (" %u", i);
    }
  printf ("\n");

  sleep (10);
}




int
test_main (int argc, char **argv)
{
  int debug = 0;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    verbose = debug = 1;

  srand (time (NULL));

  printf ("testing threading (through %s)...\n\n", threading);

  printf ("testing secmem...\n");
  test_secmem ();
  printf ("testing module system...\n");
  test_module ();
  
  return 0;
}

#else

#include <stdio.h>

unsigned int test_startup_flags = 0;

int
test_main (int argc, char **argv)
{
  printf ("threading system not found, skipping this test...\n");
  return 0;
}

#endif
