#include <config.h>

#include "../src/compat/gcrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "common.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#else
#ifdef HAVE_PTH
#include <pth.h>
GCRY_THREAD_OPTION_PTH_IMPL;
#endif
#endif


extern unsigned int test_startup_flags;
int test_main (int argc, char **argv);

int
main (int argc, char **argv)
{
  gcry_error_t err;

  if (! (test_startup_flags & STARTUP_NEW_API_MODE))
    {
      if (test_startup_flags & STARTUP_ENABLE_THREADING)
	{
#ifdef HAVE_PTHREAD
	  err = gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread, 0);
#else
#ifdef HAVE_PTH
	  err = gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pth, 0);
#else
	  printf ("** WARNING: no threading library detected during configure run;\n"
		  "skipping multithreading test **\n");
	  exit (0);
#endif
#endif
	}

      if (test_startup_flags & STARTUP_ENABLE_SECURE_MEMORY)
	{
	  err = gcry_control (GCRYCTL_INIT_SECMEM, 16384);
	  assert (! err);
	}
      else
	{
	  err = gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	  assert (! err);
	}

      if (getenv ("GCRYPT_QUICK_RANDOM"))
	{
	  fprintf (stderr, "(enabling quick random number generation)\n");
	  err = gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	  assert (! err);
	}

      /* FIXME.  */
      gcry_check_version (NULL);
      gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

      //  if (!gcry_check_version (GCRYPT_VERSION))
      //    die ("version mismatch\n");
    }
  else
    /* FIXME.  */
    abort ();

  return test_main (argc, argv);
}
