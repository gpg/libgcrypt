/* gcrypt-common-common.h - Common Libgcrypt definitions (public and internal)
   Copyright (C) 2005 g10 Code GmbH

   This file is part of Libgcrypt.
 
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
 
   Libgcrypt is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU Lesser General Public
   License along with Libgcrypt; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef _GCRYPT_COMMON_COMMON_H
#define _GCRYPT_COMMON_COMMON_H

#include <gpg-error.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <gcrypt-ath-common.h>



/* Wrappers for the libgpg-error library.  */

/* This type holds an error code.  */
typedef gpg_err_code_t gcry_err_code_t;

/* This type holds an error source identifier.  */
typedef gpg_err_source_t gcry_err_source_t;

/* This type combines an error code with an error source.  */
typedef gpg_error_t gcry_error_t;



/* This is the type holding a library context, which is required for
   all library functions.  */

struct gcry_core_context_t;
typedef struct gcry_context *gcry_core_context_t;



/* Logging.  */

/* Log levels used by the internal logging facility. */
typedef enum gcry_log_levels
  {
    GCRY_LOG_CONT   = 0,    /* continue the last log line */
    GCRY_LOG_INFO   = 10,
    GCRY_LOG_WARN   = 20,
    GCRY_LOG_ERROR  = 30,
    GCRY_LOG_FATAL  = 40,
    GCRY_LOG_BUG    = 50,
    GCRY_LOG_DEBUG  = 100
  }
gcry_logger_level_t;



/* Memory allocation.  */

void *gcry_core_malloc (gcry_core_context_t context, size_t n);
void *gcry_core_xmalloc (gcry_core_context_t context, size_t n);
void *gcry_core_malloc_secure (gcry_core_context_t context, size_t n);
void *gcry_core_xmalloc_secure (gcry_core_context_t context, size_t n);
void *gcry_core_calloc (gcry_core_context_t context, size_t n, size_t m);
void *gcry_core_xcalloc (gcry_core_context_t context, size_t n, size_t m);
void *gcry_core_calloc_secure (gcry_core_context_t context, size_t n, size_t m);
void *gcry_core_xcalloc_secure (gcry_core_context_t context, size_t n, size_t m);
void *gcry_core_realloc (gcry_core_context_t context, void *p, size_t n);
void *gcry_core_xrealloc (gcry_core_context_t context, void *p, size_t n);
void gcry_core_free (gcry_core_context_t context, void *p);
int gcry_core_is_secure (gcry_core_context_t context, const void *p);
char *gcry_core_strdup (gcry_core_context_t context, const char *string);
char *gcry_core_xstrdup (gcry_core_context_t context, const char *string);



typedef void (*gcry_core_handler_log_t) (void *, int, const char *, va_list);

/* Progress context.  */
typedef void (*gcry_core_handler_progress_t) (void *, const char *, int, int, int);

/* Memory handler.  */
typedef void *(*gcry_core_handler_alloc_t) (size_t n);
typedef void *(*gcry_core_handler_realloc_t) (void *p, size_t n);
typedef void (*gcry_core_handler_free_t) (void *p);
typedef int (*gcry_core_handler_no_mem_t) (void *, size_t, unsigned int);

/* Fatal error handler.  */

typedef void (*gcry_core_handler_error_t) (void *, int, const char *);



/* General library control flags.  */

#define GCRY_CORE_FLAG_DISABLE_AUTO_PRNG_POOL_FILLING  (1 << 0)
#define GCRY_CORE_FLAG_ENABLE_SECURE_RANDOM_ALLOCATION (1 << 1)
#define GCRY_CORE_FLAG_ENABLE_QUICK_RANDOM_GENERATION  (1 << 2)
#define GCRY_CORE_FLAG_ENABLE_MEMORY_GUARD             (1 << 3)
#define GCRY_CORE_FLAG_DISABLE_SECURE_MEMORY           (1 << 4)

/* Debug flags.  */

#define GCRY_CORE_FLAG_DEBUG_MPI         (1 << 0)
#define GCRY_CORE_FLAG_DEBUG_SYM_CIPHER  (1 << 1)
#define GCRY_CORE_FLAG_DEBUG_ASYM_CIPHER (1 << 2)
#define GCRY_CORE_FLAG_DEBUG_HASH        (1 << 3)
#define GCRY_CORE_FLAG_DEBUG_PRIME       (1 << 4)



/*
 * Context management functions.
 */

/* General.  */

size_t gcry_core_context_size (void);
void gcry_core_context_init (gcry_core_context_t ctx);
void gcry_core_context_prepare (gcry_core_context_t ctx);
void gcry_core_context_finish (gcry_core_context_t ctx);

void gcry_core_set_verbosity (gcry_core_context_t ctx, int level);

void gcry_core_flags_set (gcry_core_context_t ctx, unsigned int flags);
unsigned int gcry_core_flags_get (gcry_core_context_t ctx, unsigned int flags);
void gcry_core_flags_clear (gcry_core_context_t ctx, unsigned int flags);

void gcry_core_debug_flags_set (gcry_core_context_t ctx, unsigned int flags);
unsigned int gcry_core_debug_flags_get (gcry_core_context_t ctx, unsigned int flags);
void gcry_core_debug_flags_clear (gcry_core_context_t ctx, unsigned int flags);


/* Handler related.  */

void gcry_core_set_handler_mem (gcry_core_context_t ctx,
				gcry_core_handler_alloc_t func_alloc,
				gcry_core_handler_realloc_t func_realloc,
				gcry_core_handler_free_t func_free,
				gcry_core_handler_no_mem_t no_mem,
				void *no_mem_opaque);
void gcry_core_set_handler_progress (gcry_core_context_t ctx,
				     gcry_core_handler_progress_t progress,
				     void *opaque);
void gcry_core_set_handler_log (gcry_core_context_t ctx,
				gcry_core_handler_log_t logger, void *opaque);
void gcry_core_set_handler_error (gcry_core_context_t ctx,
				  gcry_core_handler_error_t err,
				  void *opaque);
void gcry_core_set_handler_ath (gcry_core_context_t ctx,
				gcry_core_handler_ath_t ath);

/* Default handlers.  */

void gcry_core_default_error_handler (void *opaque, int rc, const char *text);
void gcry_core_default_log_handler (void *opaque,
				    int level, const char *format, va_list ap);



/* We want to use gcc attributes when possible.  Warning: Don't use
   these macros in your programs: As indicated by the leading
   underscore they are subject to change without notice. */
#ifdef __GNUC__

#define _GCRY_GCC_VERSION (__GNUC__ * 10000 \
                             + __GNUC_MINOR__ * 100 \
                             + __GNUC_PATCHLEVEL__)

#if _GCRY_GCC_VERSION >= 30100
#define _GCRY_GCC_ATTR_DEPRECATED __attribute__ ((__deprecated__))
#endif

#if _GCRY_GCC_VERSION >= 29600
#define _GCRY_GCC_ATTR_PURE  __attribute__ ((__pure__))
#endif

#if _GCRY_GCC_VERSION >= 300200
#define _GCRY_GCC_ATTR_MALLOC  __attribute__ ((__malloc__))
#endif

#endif /*__GNUC__*/

#ifndef _GCRY_GCC_ATTR_DEPRECATED
#define _GCRY_GCC_ATTR_DEPRECATED
#endif
#ifndef _GCRY_GCC_ATTR_PURE
#define _GCRY_GCC_ATTR_PURE
#endif
#ifndef _GCRY_GCC_ATTR_MALLOC
#define _GCRY_GCC_ATTR_MALLOC
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
#define JNLIB_GCC_M_FUNCTION 1
#define JNLIB_GCC_A_NR 	     __attribute__ ((noreturn))
#define JNLIB_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
#define JNLIB_GCC_A_NR_PRINTF( f, a ) \
			    __attribute__ ((noreturn, format (printf,f,a)))
#define GCC_ATTR_NORETURN  __attribute__ ((__noreturn__))
#else
#define JNLIB_GCC_A_NR
#define JNLIB_GCC_A_PRINTF( f, a )
#define JNLIB_GCC_A_NR_PRINTF( f, a )
#define GCC_ATTR_NORETURN 
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96 )
#define GCC_ATTR_PURE  __attribute__ ((__pure__))
#else
#define GCC_ATTR_PURE
#endif

/* (The malloc attribute might be defined prior to 3.2 - I am just not sure) */
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 2 )
#define GCC_ATTR_MALLOC    __attribute__ ((__malloc__))
#else
#define GCC_ATTR_MALLOC
#endif

/* FIXME: above cleanup neccesary -moritz  */



#endif
