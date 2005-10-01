/* global.c  -	global control functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003
 *               2004, 2005  Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <compat/gcrypt-internal.h>

#include <gcrypt-random-internal.h>
#include <gcrypt-secmem-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>

#include "secmem.h"
#include "ath.h"

/****************
 * flag bits: 0 : general cipher debug
 *	      1 : general MPI debug
 */
static int any_init_done;

static gcry_core_handler_alloc_t alloc_handler = malloc;
static gcry_core_handler_realloc_t realloc_handler = realloc;
static gcry_core_handler_free_t free_handler = free;
static gcry_core_handler_no_mem_t oom_handler;
static void *oom_handler_opaque;

static void
global_init (void)
{
  if (any_init_done)
    return;
  any_init_done = 1;

  _gcry_init ();
}

static const char*
parse_version_number( const char *s, int *number )
{
    int val = 0;

    if( *s == '0' && isdigit(s[1]) )
	return NULL; /* leading zeros are not allowed */
    for ( ; isdigit(*s); s++ ) {
	val *= 10;
	val += *s - '0';
    }
    *number = val;
    return val < 0? NULL : s;
}


static const char *
parse_version_string( const char *s, int *major, int *minor, int *micro )
{
    s = parse_version_number( s, major );
    if( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number( s, minor );
    if( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number( s, micro );
    if( !s )
	return NULL;
    return s; /* patchlevel */
}

/****************
 * Check that the the version of the library is at minimum the requested one
 * and return the version string; return NULL if the condition is not
 * satisfied.  If a NULL is passed to this function, no check is done,
 * but the version string is simply returned.
 */
const char *
gcry_check_version( const char *req_version )
{
    const char *ver = VERSION;
    int my_major, my_minor, my_micro;
    int rq_major, rq_minor, rq_micro;
    const char *my_plvl, *rq_plvl;

    global_init ();
    if ( !req_version )
	return ver;

    my_plvl = parse_version_string( ver, &my_major, &my_minor, &my_micro );
    if ( !my_plvl )
	return NULL;  /* very strange our own version is bogus */
    rq_plvl = parse_version_string( req_version, &rq_major, &rq_minor,
								&rq_micro );
    if ( !rq_plvl )
	return NULL;  /* req version string is invalid */

    if ( my_major > rq_major
	|| (my_major == rq_major && my_minor > rq_minor)
	|| (my_major == rq_major && my_minor == rq_minor
				 && my_micro > rq_micro)
	|| (my_major == rq_major && my_minor == rq_minor
				 && my_micro == rq_micro
				 && strcmp( my_plvl, rq_plvl ) >= 0) ) {
	return ver;
    }
    return NULL;
}

static unsigned int
convert_flags (unsigned int flags_compat)
{
  unsigned int flags;

  flags = 0;
  if (flags_compat & 1)
    flags |= (GCRY_CORE_FLAG_DEBUG_SYM_CIPHER
	      | GCRY_CORE_FLAG_DEBUG_ASYM_CIPHER
	      | GCRY_CORE_FLAG_DEBUG_HASH
	      | GCRY_CORE_FLAG_DEBUG_PRIME);
  if (flags_compat & 2)
    flags |= GCRY_CORE_FLAG_DEBUG_MPI;

  return flags;
}

gcry_error_t
gcry_control (enum gcry_ctl_cmds cmd, ...)
{
  gcry_error_t err = 0;
  static int init_finished = 0;
  va_list arg_ptr;
  
  _gcry_init_stage1_only ();

  va_start (arg_ptr, cmd);
  switch (cmd)
    {
    case GCRYCTL_ENABLE_M_GUARD:
      gcry_core_flags_set (context, GCRY_CORE_FLAG_ENABLE_MEMORY_GUARD);
      break;

    case GCRYCTL_ENABLE_QUICK_RANDOM:
      gcry_core_flags_set (context, GCRY_CORE_FLAG_ENABLE_QUICK_RANDOM_GENERATION);
      break;

    case GCRYCTL_DUMP_RANDOM_STATS:
      _gcry_init ();
      gcry_core_random_dump_stats (context);
      break;

    case GCRYCTL_DUMP_MEMORY_STATS:
      /*m_print_stats("[fixme: prefix]");*/
      break;

    case GCRYCTL_DUMP_SECMEM_STATS:
      _gcry_init ();
      gcry_core_secmem_dump_stats (context);
      break;

    case GCRYCTL_DROP_PRIVS:
      global_init ();
      gcry_core_secmem_init (context, 0);
      break;

    case GCRYCTL_DISABLE_SECMEM:
      global_init ();
      gcry_core_flags_set (context, GCRY_CORE_FLAG_DISABLE_SECURE_MEMORY);
      break;    

    case GCRYCTL_INIT_SECMEM:
      global_init ();
      gcry_core_secmem_init (context, va_arg (arg_ptr, unsigned int));
      break;

    case GCRYCTL_TERM_SECMEM:
      global_init ();
      gcry_core_secmem_term (context);
      break;

    case GCRYCTL_DISABLE_SECMEM_WARN:
      _gcry_init ();
      gcry_core_secmem_set_flags (context,
				  gcry_core_secmem_get_flags (context)
				  | GCRY_SECMEM_FLAG_NO_WARNING);
      break;

    case GCRYCTL_SUSPEND_SECMEM_WARN:
      _gcry_init ();
      gcry_core_secmem_set_flags (context,
				  gcry_core_secmem_get_flags (context)
				  | GCRY_SECMEM_FLAG_SUSPEND_WARNING);
      break;

    case GCRYCTL_RESUME_SECMEM_WARN:
      _gcry_init ();
      gcry_core_secmem_set_flags (context,
				  gcry_core_secmem_get_flags (context)
				  & ~GCRY_SECMEM_FLAG_SUSPEND_WARNING);
      break;

    case GCRYCTL_USE_SECURE_RNDPOOL:
      global_init ();
      gcry_core_flags_set (context,
			   GCRY_CORE_FLAG_ENABLE_SECURE_RANDOM_ALLOCATION);
      break;

    case GCRYCTL_SET_RANDOM_SEED_FILE:
      _gcry_init ();
      gcry_core_set_random_seed_file (context, va_arg (arg_ptr, const char *));
      break;

    case GCRYCTL_UPDATE_RANDOM_SEED_FILE:
      _gcry_init ();
      gcry_core_random_seed_file_update (context);
      break;

    case GCRYCTL_SET_VERBOSITY:
      _gcry_init ();
      gcry_core_set_verbosity (context, va_arg (arg_ptr, int));
      break;

    case GCRYCTL_SET_DEBUG_FLAGS:
      {
	unsigned int flags_compat = va_arg (arg_ptr, unsigned int);
	unsigned int flags;

	flags = convert_flags (flags_compat);
	gcry_core_debug_flags_set (context, flags);
      }
      break;

    case GCRYCTL_CLEAR_DEBUG_FLAGS:
      {
	unsigned int flags_compat = va_arg (arg_ptr, unsigned int);
	unsigned int flags;

	flags = convert_flags (flags_compat);
	gcry_core_debug_flags_clear (context, flags);
      }
      break;

    case GCRYCTL_DISABLE_INTERNAL_LOCKING:
      global_init ();
      /* I think this control command does not make sense anymore,
	 since Libgcrypt does not chose the threading system
	 automatically; if the user does not want locking, he can
	 simply skip the step of registering a threading system.  */
      break;

    case GCRYCTL_ANY_INITIALIZATION_P:
      if (any_init_done)
	err = gcry_error (GPG_ERR_GENERAL);
      break;

    case GCRYCTL_INITIALIZATION_FINISHED_P:
      if (init_finished)
	err = gcry_error (GPG_ERR_GENERAL);
      break;

    case GCRYCTL_INITIALIZATION_FINISHED:
      /* This is a hook which should be used by an application after
	 all initialization has been done and right before any threads
	 are started.  It is not really needed but the only way to be
	 really sure that all initialization for thread-safety has
	 been done. */
        if (! init_finished)
	  {
            global_init ();
              /* Do only a basic ranom initialization, i.e. inti the
               mutexes. */
	    gcry_core_random_initialize (context, 0);
            init_finished = 1;
	  }
        break;

    case GCRYCTL_SET_THREAD_CBS:
      assert (! _gcry_init_done_p ());
      err = ath_install (va_arg (arg_ptr, void *), any_init_done);
      break;

    case GCRYCTL_FAST_POLL:
      /* We need to do make sure that the random pool is really
         initialized so that the poll fucntion is not a NOP. */
      _gcry_init ();
      gcry_core_random_initialize (context, 1);
      gcry_core_random_fast_poll (context);
      break;

    case GCRYCTL_DISABLE_AUTO_PRNG_POOL_FILLING:
      gcry_core_flags_set (context,
			   GCRY_CORE_FLAG_DISABLE_AUTO_PRNG_POOL_FILLING);
      break;

    default:
      err = gcry_error (GPG_ERR_INV_OP);
    }

  va_end(arg_ptr);
  return err;
}

/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  */
const char *
gcry_strerror (gcry_error_t err)
{
  _gcry_init ();
  return gcry_core_strerror (err);
}

/* Return a pointer to a string containing a description of the error
   source in the error value ERR.  */
const char *
gcry_strsource (gcry_error_t err)
{
  _gcry_init ();
  return gcry_core_strsource (err);
}

/* Retrieve the error code for the system error ERR.  This returns
   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
   this).  */
gcry_err_code_t
gcry_err_code_from_errno (int err)
{
  _gcry_init ();
  return gcry_core_err_code_from_errno (err);
}


/* Retrieve the system error for the error code CODE.  This returns 0
   if CODE is not a system error code.  */
int
gcry_err_code_to_errno (gcry_err_code_t code)
{
  _gcry_init ();
  return gcry_core_err_code_to_errno (errno);
}

  
/* Return an error value with the error source SOURCE and the system
   error ERR.  */
gcry_error_t
gcry_err_make_from_errno (gpg_err_source_t source, int err)
{
  _gcry_init ();
  return gcry_core_err_make_from_errno (source, err);
}


/* Return an error value with the system error ERR.  */
gcry_err_code_t
gcry_error_from_errno (int err)
{
  _gcry_init ();
  return gcry_core_error_from_errno (err);
}

/****************
 * NOTE: All 5 functions should be set.  */
void
gcry_set_allocation_handler (gcry_handler_alloc_t alloc_func,
			     gcry_handler_alloc_t alloc_secure_func,
			     gcry_handler_secure_check_t secure_check_func,
			     gcry_handler_realloc_t realloc_func,
			     gcry_handler_free_t free_func)
{
  global_init ();

  alloc_handler = alloc_func;
  realloc_handler = realloc_func;
  free_handler = free_func;

  gcry_core_set_handler_mem (context,
			     alloc_func, realloc_func, free_func,
			     oom_handler, oom_handler_opaque);

  secmem_dummy_set_callbacks (context, alloc_secure_func, secure_check_func,
			      realloc_func, free_func);

  gcry_core_set_subsystem_secmem (context, secmem_dummy);
}


/****************
 * Set an optional handler which is called in case the xmalloc functions
 * ran out of memory.  This handler may do one of these things:
 *   o free some memory and return true, so that the xmalloc function
 *     tries again.
 *   o Do whatever it like and return false, so that the xmalloc functions
 *     use the default fatal error handler.
 *   o Terminate the program and don't return.
 *
 * The handler function is called with 3 arguments:  The opaque value set with
 * this function, the requested memory size, and a flag with these bits
 * currently defined:
 *	bit 0 set = secure memory has been requested.
 */
void
gcry_set_outofcore_handler (gcry_core_handler_no_mem_t cb, void *opaque)
{
  global_init ();

  oom_handler = cb;
  oom_handler_opaque = opaque;

  gcry_core_set_handler_mem (context,
			     alloc_handler, realloc_handler, free_handler,
			     cb, opaque);
}

void *
gcry_malloc (size_t n)
{
  _gcry_init ();

  return gcry_core_malloc (context, n);
}

void *
gcry_malloc_secure (size_t n)
{
  _gcry_init ();

  return gcry_core_malloc_secure (context, n);
}

int
gcry_is_secure (const void *a)
{
  _gcry_init ();

  return gcry_core_is_secure (context, a);
}

void
_gcry_check_heap( const void *a )
{
    /* FIXME: implement this*/
#if 0
    if( some_handler )
	some_handler(a)
    else
	_gcry_private_check_heap(a)
#endif
}

void *
gcry_realloc (void *a, size_t n)
{
  _gcry_init ();

  return gcry_core_realloc (context, a, n);
}

void
gcry_free( void *p )
{
  _gcry_init ();

  return gcry_core_free (context, p);
}

void *
gcry_calloc (size_t n, size_t m)
{
  _gcry_init ();

  return gcry_core_calloc (context, n, m);
}

void *
gcry_calloc_secure (size_t n, size_t m)
{
  _gcry_init ();

  return gcry_core_calloc_secure (context, n, m);
}

char *
gcry_strdup (const char *string)
{
  _gcry_init ();

  return gcry_core_strdup (context, string);
}


void *
gcry_xmalloc( size_t n )
{
  _gcry_init ();

  return gcry_core_xmalloc (context, n);
}

void *
gcry_xrealloc( void *a, size_t n )
{
  _gcry_init ();

  return gcry_core_xrealloc (context, a, n);
}

void *
gcry_xmalloc_secure( size_t n )
{
  _gcry_init ();

  return gcry_core_xmalloc_secure (context, n);
}

void *
gcry_xcalloc( size_t n, size_t m )
{
  _gcry_init ();

  return gcry_core_xcalloc (context, n, m);
}

void *
gcry_xcalloc_secure( size_t n, size_t m )
{
  _gcry_init ();

  return gcry_core_xcalloc_secure (context, n, m);
}

char *
gcry_xstrdup (const char *string)
{
  _gcry_init ();

  return gcry_core_xstrdup (context, string);
}


/* It is often useful to get some feedback of long running operations.
   This function may be used to register a handler for this. 
   The callback function CB is used as:

   void cb (void *opaque, const char *what, int printchar,
           int current, int total);

   Where WHAT is a string identifying the the type of the progress
   output, PRINTCHAR the character usually printed, CURRENT the amount
   of progress currently done and TOTAL the expected amount of
   progress.  A value of 0 for TOTAL indicates that there is no
   estimation available.

   Defined values for WHAT:

   "need_entropy"  X    0  number-of-bytes-required
            When running low on entropy
   "primegen"      '\n'  0 0
           Prime generated
                   '!'
           Need to refresh the prime pool
                   '<','>'
           Number of bits adjusted
                   '^'
           Looking for a generator
                   '.'
           Fermat tests on 10 candidates failed
                  ':'
           Restart with a new random value
                  '+'
           Rabin Miller test passed          
   "pk_elg"        '+','-','.','\n'   0  0
            Only used in debugging mode.
   "pk_dsa"       
            Only used in debugging mode.
*/
void
gcry_set_progress_handler (gcry_core_handler_progress_t progress,
			   void *opaque)
{
  _gcry_init ();

  gcry_core_set_handler_progress (context, progress, opaque);
}

/* Register a function used instead of the internal logging
   facility. */
void
gcry_set_log_handler (gcry_core_handler_log_t f, void *opaque)
{
  _gcry_init ();

  gcry_core_set_handler_log (context, f, opaque);
}

/* Register a function used instead of the internal fatal error
   handler. */
void
gcry_set_fatalerror_handler (gcry_core_handler_error_t fnc, void *opaque)
{
  _gcry_init ();
  gcry_core_set_handler_error (context, fnc, opaque);
}

/* Reserved for future use. */
void
gcry_set_gettext_handler (const char *(*f)(const char*))
{
  _gcry_init ();
  /* FIXME? */
}
