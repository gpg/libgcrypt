/* global.c  -	global control functions
 * Copyright (C) 1998,1999,2000,2001,2002,2003 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "stdmem.h" /* our own memory allocator */
#include "secmem.h" /* our own secmem allocator */
#include "ath.h"

/****************
 * flag bits: 0 : general cipher debug
 *	      1 : general MPI debug
 */
static unsigned int debug_flags;
static int last_ec; /* fixme: make thread safe */

static void *(*alloc_func)(size_t n) = NULL;
static void *(*alloc_secure_func)(size_t n) = NULL;
static int   (*is_secure_func)(const void*) = NULL;
static void *(*realloc_func)(void *p, size_t n) = NULL;
static void (*free_func)(void*) = NULL;
static int (*outofcore_handler)( void*, size_t, unsigned int ) = NULL;
static void *outofcore_handler_value = NULL;
static int no_secure_memory = 0;
static int any_init_done;

/* This is our handmade constructor.  It gets called by any function
   likely to be called at startup.  The suggested way for an
   application to make sure that this has been called is by using
   gcry_check_version. */
static void
global_init (void)
{
  if (any_init_done)
    return;
  any_init_done = 1;
  ath_init ();
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


int
gcry_control( enum gcry_ctl_cmds cmd, ... )
{
    static int init_finished = 0;
    va_list arg_ptr ;

    va_start( arg_ptr, cmd ) ;
    switch( cmd ) {
#if 0
      case GCRYCTL_NO_MEM_IS_FATAL:
	break;
      case GCRYCTL_SET_FATAL_FNC:
	break;
#endif

      case GCRYCTL_ENABLE_M_GUARD:
	_gcry_private_enable_m_guard();
	break;

      case GCRYCTL_ENABLE_QUICK_RANDOM:
        _gcry_quick_random_gen (1);
        break;

      case GCRYCTL_DUMP_RANDOM_STATS:
	_gcry_random_dump_stats();
	break;

      case GCRYCTL_DUMP_MEMORY_STATS:
	/*m_print_stats("[fixme: prefix]");*/
	break;

      case GCRYCTL_DUMP_SECMEM_STATS:
	_gcry_secmem_dump_stats();
	break;

      case GCRYCTL_DROP_PRIVS:
        global_init ();
	_gcry_secmem_init( 0 );
	break;

      case GCRYCTL_DISABLE_SECMEM:
        global_init ();
        no_secure_memory = 1;
        break;    

      case GCRYCTL_INIT_SECMEM:
        global_init ();
	_gcry_secmem_init( va_arg( arg_ptr, unsigned int ) );
	break;

      case GCRYCTL_TERM_SECMEM:
        global_init ();
	_gcry_secmem_term();
	break;

      case GCRYCTL_DISABLE_SECMEM_WARN:
	_gcry_secmem_set_flags( (_gcry_secmem_get_flags() | 1) );
	break;

      case GCRYCTL_SUSPEND_SECMEM_WARN:
	_gcry_secmem_set_flags( (_gcry_secmem_get_flags() | 2) );
	break;

      case GCRYCTL_RESUME_SECMEM_WARN:
	_gcry_secmem_set_flags( (_gcry_secmem_get_flags() & ~2) );
	break;

      case GCRYCTL_USE_SECURE_RNDPOOL:
        global_init ();
	_gcry_secure_random_alloc(); /* put random number into secure memory */
	break;

      case GCRYCTL_SET_VERBOSITY:
	_gcry_set_log_verbosity( va_arg( arg_ptr, int ) );
	break;

      case GCRYCTL_SET_DEBUG_FLAGS:
	debug_flags |= va_arg( arg_ptr, unsigned int );
	break;

      case GCRYCTL_CLEAR_DEBUG_FLAGS:
	debug_flags &= ~va_arg( arg_ptr, unsigned int );
	break;

      case GCRYCTL_DISABLE_INTERNAL_LOCKING:
        global_init ();
        /* We waste some bytes by doing it this way.  OTOH this
           function is not anymore required becuase it is done
           automagically. */
        ath_deinit ();
        break;

      case GCRYCTL_ANY_INITIALIZATION_P:
        va_end(arg_ptr);
        return any_init_done? 1 : 0;

      case GCRYCTL_INITIALIZATION_FINISHED_P:
        va_end(arg_ptr);
        return init_finished? 1 : 0;

      case GCRYCTL_INITIALIZATION_FINISHED:
        /* This is a hook which should be used by an application after
           all initialization has been done and right before any
           threads are started.  It is not really needed but the only
           way to be really sure that all initialization for
           thread-safety has been done. */
        if (!init_finished) {
            global_init ();
            _gcry_random_initialize ();
            init_finished = 1;
        }
        break;

      default:
	va_end(arg_ptr);
	return GCRYERR_INV_OP;
    }
    va_end(arg_ptr);
    return 0;
}

int
gcry_errno()
{
    return last_ec;
}

const char*
gcry_strerror( int ec )
{
    const char *s;
    static char buf[20];

    if( ec == -1 )
	ec = gcry_errno();
  #define X(n,a) case GCRYERR_##n : s = a; break;
    switch( ec ) {
      X(SUCCESS,        N_("no error"))
      X(GENERAL,        N_("general error"))

      X(INV_PK_ALGO,	N_("invalid public key algorithm"))
      X(INV_MD_ALGO,	N_("invalid hash algorithm"))
      X(BAD_PUBLIC_KEY ,N_("bad public key"))
      X(BAD_SECRET_KEY ,N_("bad secret key"))
      X(BAD_SIGNATURE , N_("bad signature"))

      X(INV_CIPHER_ALGO,N_("invalid cipher algorithm"))
      X(BAD_MPI,        N_("bad big integer"))
      X(WRONG_PK_ALGO,	N_("unusable public key algorithm"))
      X(WEAK_KEY,	N_("weak encryption key"))
      X(INV_KEYLEN,     N_("invalid key length"))
      X(INV_ARG,	N_("invalid argument"))
      X(SELFTEST,       N_("selftest failed"))

      X(INV_OP, 	N_("invalid operation code or ctl command"))
      X(NO_MEM, 	N_("out of core"))
      X(INTERNAL,	N_("internal error"))
      X(EOF,		N_("EOF"))
      X(INV_OBJ,	N_("an object is not valid"))
      X(TOO_SHORT,	N_("provided buffer too short"))
      X(TOO_LARGE,	N_("object is too large"))
      X(NO_OBJ,         N_("no object"))
      X(NOT_IMPL,       N_("not implemented"))
      X(CONFLICT,	N_("conflict"))
      X(INV_CIPHER_MODE,N_("invalid cipher mode"))
        X(INV_FLAG,     N_("invalid flag"))

        X(SEXP_INV_LEN_SPEC   ,N_("invalid length specification")) 
        X(SEXP_STRING_TOO_LONG,N_("string too long")) 
        X(SEXP_UNMATCHED_PAREN,N_("unmatched parenthesis")) 
        X(SEXP_NOT_CANONICAL  ,N_("not a canonical S-expression")) 
        X(SEXP_BAD_CHARACTER  ,N_("bad character")) 
        X(SEXP_BAD_QUOTATION  ,N_("invalid hex/octal value or bad quotation")) 
        X(SEXP_ZERO_PREFIX    ,N_("a length may not begin with zero")) 
        X(SEXP_NESTED_DH      ,N_("nested display hints")) 
        X(SEXP_UNMATCHED_DH   ,N_("unmatched display hint close")) 
        X(SEXP_UNEXPECTED_PUNC,N_("unexpected reserved punctuation")) 
        X(SEXP_BAD_HEX_CHAR,   N_("invalid hex character"))
        X(SEXP_ODD_HEX_NUMBERS,N_("odd number of hex characters"))
        X(SEXP_BAD_OCT_CHAR,   N_("invalid octal character"))

      default:
	sprintf( buf, "ec=%d", ec );
	s = buf;
    }
  #undef X
    return s;
}


int
_gcry_set_lasterr( int ec )
{
    if( ec )
	last_ec = ec == -1 ? GCRYERR_EOF : ec;
    return ec;
}



/****************
 * NOTE: All 5 functions should be set.  */
void
gcry_set_allocation_handler( void *(*new_alloc_func)(size_t n),
			     void *(*new_alloc_secure_func)(size_t n),
			     int (*new_is_secure_func)(const void*),
			     void *(*new_realloc_func)(void *p, size_t n),
			     void (*new_free_func)(void*) )
{
    global_init ();

    alloc_func	      = new_alloc_func;
    alloc_secure_func = new_alloc_secure_func;
    is_secure_func    = new_is_secure_func;
    realloc_func      = new_realloc_func;
    free_func	      = new_free_func;
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
gcry_set_outofcore_handler( int (*f)( void*, size_t, unsigned int ),
							void *value )
{
    global_init ();

    outofcore_handler = f;
    outofcore_handler_value = value;
}



void *
gcry_malloc( size_t n )
{
    if( alloc_func )
	return alloc_func( n ) ;
    return _gcry_private_malloc( n );
}

void *
gcry_malloc_secure( size_t n )
{
  if (no_secure_memory)
    return gcry_malloc (n);
  if (alloc_secure_func)
    return alloc_secure_func (n) ;
  return _gcry_private_malloc_secure (n);
}

int
gcry_is_secure( const void *a )
{
  if (no_secure_memory)
    return 0;
  if (is_secure_func)
    return is_secure_func (a) ;
  return _gcry_private_is_secure (a);
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
gcry_realloc( void *a, size_t n )
{
    /* FIXME: Make sure that the realloced memory is cleared out */

    if( realloc_func )
	return realloc_func( a, n ) ;
    return _gcry_private_realloc( a, n );
}

void
gcry_free( void *p )
{
    if( !p )
	return;

    if( free_func )
	free_func( p );
    else
	_gcry_private_free( p );
}

void *
gcry_calloc (size_t n, size_t m)
{
  size_t bytes;
  void *p;

  bytes = n * m; /* size_t is unsigned so the behavior on overflow is defined. */
  if (m && bytes / m != n) 
    {
      errno = ENOMEM;
      return NULL;
    }

  p = gcry_malloc (bytes);
  if (p)
    memset (p, 0, bytes);
  return p;
}

void *
gcry_calloc_secure (size_t n, size_t m)
{
  size_t bytes;
  void *p;

  bytes = n * m; /* size_t is unsigned so the behavior on overflow is defined. */
  if (m && bytes / m != n) 
    {
      errno = ENOMEM;
      return NULL;
    }
  
  p = gcry_malloc_secure (bytes);
  if (p)
    memset (p, 0, bytes);
  return p;
}


char *
gcry_strdup( const char *string )
{
    void *p = gcry_malloc( strlen(string)+1 );
    strcpy( p, string );
    return p;
}


void *
gcry_xmalloc( size_t n )
{
    void *p;

    while ( !(p = gcry_malloc( n )) ) {
	if( !outofcore_handler
	    || !outofcore_handler( outofcore_handler_value, n, 0 ) ) {
	    _gcry_fatal_error(GCRYERR_NO_MEM, NULL );
	}
    }
    return p;
}

void *
gcry_xrealloc( void *a, size_t n )
{
    void *p;

    while ( !(p = gcry_realloc( a, n )) ) {
	if( !outofcore_handler
	    || !outofcore_handler( outofcore_handler_value, n, 2 ) ) {
	    _gcry_fatal_error(GCRYERR_NO_MEM, NULL );
	}
    }
    return p;
}

void *
gcry_xmalloc_secure( size_t n )
{
    void *p;

    while ( !(p = gcry_malloc_secure( n )) ) {
	if( !outofcore_handler
	    || !outofcore_handler( outofcore_handler_value, n, 1 ) ) {
	    _gcry_fatal_error(GCRYERR_NO_MEM,
			     _("out of core in secure memory"));
	}
    }
    return p;
}

void *
gcry_xcalloc( size_t n, size_t m )
{
    void *p = gcry_xmalloc( n*m );
    memset( p, 0, n*m );
    return p;
}

void *
gcry_xcalloc_secure( size_t n, size_t m )
{
    void *p = gcry_xmalloc_secure( n* m );
    memset( p, 0, n*m );
    return p;
}

char *
gcry_xstrdup( const char *string )
{
    void *p = gcry_xmalloc( strlen(string)+1 );
    strcpy( p, string );
    return p;
}


int
_gcry_get_debug_flag( unsigned int mask )
{
    return debug_flags & mask;
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
gcry_set_progress_handler (void (*cb)(void *,const char*,int, int, int),
                           void *cb_data)
{
  _gcry_register_pk_dsa_progress (cb, cb_data);
  _gcry_register_pk_elg_progress (cb, cb_data);
  _gcry_register_primegen_progress (cb, cb_data);
  _gcry_register_random_progress (cb, cb_data);
}
