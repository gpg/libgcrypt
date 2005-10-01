/* gcrypt-common-internal.h - Common Libgcrypt defintions (internal)
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

#ifndef _GCRYPT_COMMON_INTERNAL_H
#define _GCRYPT_COMMON_INTERNAL_H

#include <config.h>
#include <sys/types.h>
#include <stddef.h>
#include <gpg-error.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>




/* Types. */

/* The AC_CHECK_SIZEOF() in configure fails for some machines.
 * we provide some fallback values here */
#if !SIZEOF_UNSIGNED_SHORT
#undef SIZEOF_UNSIGNED_SHORT
#define SIZEOF_UNSIGNED_SHORT 2
#endif
#if !SIZEOF_UNSIGNED_INT
#undef SIZEOF_UNSIGNED_INT
#define SIZEOF_UNSIGNED_INT 4
#endif
#if !SIZEOF_UNSIGNED_LONG
#undef SIZEOF_UNSIGNED_LONG
#define SIZEOF_UNSIGNED_LONG 4
#endif

#ifndef HAVE_BYTE_TYPEDEF
#undef byte	    /* maybe there is a macro with this name */
  typedef unsigned char byte;
#define HAVE_BYTE_TYPEDEF
#endif

#ifndef HAVE_USHORT_TYPEDEF
#undef ushort     /* maybe there is a macro with this name */
  typedef unsigned short ushort;
#define HAVE_USHORT_TYPEDEF
#endif

#ifndef HAVE_ULONG_TYPEDEF
#undef ulong	    /* maybe there is a macro with this name */
  typedef unsigned long ulong;
#define HAVE_ULONG_TYPEDEF
#endif

#ifndef HAVE_U16_TYPEDEF
#undef u16	    /* maybe there is a macro with this name */
#if SIZEOF_UNSIGNED_INT == 2
    typedef unsigned int   u16;
#elif SIZEOF_UNSIGNED_SHORT == 2
    typedef unsigned short u16;
#else
#error no typedef for u16
#endif
#define HAVE_U16_TYPEDEF
#endif

#ifndef HAVE_U32_TYPEDEF
#undef u32	    /* maybe there is a macro with this name */
#if SIZEOF_UNSIGNED_INT == 4
    typedef unsigned int u32;
#elif SIZEOF_UNSIGNED_LONG == 4
    typedef unsigned long u32;
#else
#error no typedef for u32
#endif
#define HAVE_U32_TYPEDEF
#endif

/****************
 * Warning: Some systems segfault when this u64 typedef and
 * the dummy code in cipher/md.c is not available.  Examples are
 * Solaris and IRIX.
 */
#ifndef HAVE_U64_TYPEDEF
#undef u64	    /* maybe there is a macro with this name */
#if SIZEOF_UNSIGNED_INT == 8
    typedef unsigned int u64;
#define U64_C(c) (c ## U)
#define HAVE_U64_TYPEDEF
#elif SIZEOF_UNSIGNED_LONG == 8
    typedef unsigned long u64;
#define U64_C(c) (c ## UL)
#define HAVE_U64_TYPEDEF
#elif SIZEOF_UNSIGNED_LONG_LONG == 8
    typedef unsigned long long u64;
#define U64_C(c) (c ## ULL)
#define HAVE_U64_TYPEDEF
#elif SIZEOF_UINT64_T == 8
    typedef uint64_t u64;
#define U64_C(c) (UINT64_C(c))
#define HAVE_U64_TYPEDEF
#endif
#endif

typedef union {
    int a;
    short b;
    char c[1];
    long d;
#ifdef HAVE_U64_TYPEDEF
    u64 e;
#endif
    float f;
    double g;
} PROPERLY_ALIGNED_TYPE;



/* FIXME, order, moritz?!!  */
#include <gcrypt-common-common.h>

#include <gcrypt-cipher-common.h>
#include <gcrypt-ac-common.h>
#include <gcrypt-random-common.h>
#include <gcrypt-md-common.h>
#include <gcrypt-secmem-common.h>
#include <gcrypt-mpi-common.h>
#include <gcrypt-prime-common.h>
#include <gcrypt-sexp-common.h>



/* The user can define GPG_ERR_SOURCE_DEFAULT before including this
   file to specify a default source for gpg_error.  */
#ifndef GCRY_ERR_SOURCE_DEFAULT
#define GCRY_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_USER_1
#endif

static GPG_ERR_INLINE gcry_error_t
gcry_core_error (gcry_err_code_t code)
{
  return gpg_err_make (GCRY_ERR_SOURCE_DEFAULT, code);
}

static GPG_ERR_INLINE gcry_err_code_t
gcry_core_err_code (gcry_error_t err)
{
  return gpg_err_code (err);
}


static GPG_ERR_INLINE gcry_err_source_t
gcry_core_err_source (gcry_error_t err)
{
  return gpg_err_source (err);
}

/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  */
const char *gcry_core_strerror (gcry_error_t err);

/* Return a pointer to a string containing a description of the error
   source in the error value ERR.  */
const char *gcry_core_strsource (gcry_error_t err);

/* Retrieve the error code for the system error ERR.  This returns
   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
   this).  */
gcry_err_code_t gcry_core_err_code_from_errno (int err);

/* Retrieve the system error for the error code CODE.  This returns 0
   if CODE is not a system error code.  */
int gcry_core_err_code_to_errno (gcry_err_code_t code);

/* Return an error value with the error source SOURCE and the system
   error ERR.  */
gcry_error_t gcry_core_err_make_from_errno (gcry_err_source_t source, int err);

/* Return an error value with the system error ERR.  */
gcry_err_code_t gcry_core_error_from_errno (int err);



#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define _(s) s



/* FIXME, order, moritz?  */

#ifdef JNLIB_GCC_M_FUNCTION
void _gcry_core_bug (gcry_core_context_t context,
		const char *file, int line, const char *func) GCC_ATTR_NORETURN;
#else
void _gcry_core_bug (gcry_core_context_t context,
		const char *file, int line);
#endif

void _gcry_core_fatal_error (gcry_core_context_t context,
			int rc, const char *text) JNLIB_GCC_A_NR;
void _gcry_core_log (gcry_core_context_t context,
		int level, const char *fmt, ...) JNLIB_GCC_A_PRINTF(3,4);
void _gcry_core_log_bug (gcry_core_context_t context,
		    const char *fmt, ...)   JNLIB_GCC_A_NR_PRINTF(2,3);
void _gcry_core_log_fatal (gcry_core_context_t context,
		      const char *fmt, ...) JNLIB_GCC_A_NR_PRINTF(2,3);
void _gcry_core_log_error (gcry_core_context_t context,
		      const char *fmt, ...) JNLIB_GCC_A_PRINTF(2,3);
void _gcry_core_log_info (gcry_core_context_t context,
		     const char *fmt, ...)  JNLIB_GCC_A_PRINTF(2,3);
void _gcry_core_log_debug (gcry_core_context_t context,
		      const char *fmt, ...) JNLIB_GCC_A_PRINTF(2,3);
void _gcry_core_log_printf (gcry_core_context_t context,
		       const char *fmt, ...) JNLIB_GCC_A_PRINTF(2,3);

#ifdef JNLIB_GCC_M_FUNCTION
#define BUG(ctx) _gcry_core_bug(ctx, __FILE__ , __LINE__, __FUNCTION__ )
#else
#define BUG(ctx) _gcry_core_bug(ctx, __FILE__ , __LINE__ )
#endif

#define log_hexdump _gcry_log_hexdump
#define log_bug     _gcry_core_log_bug
#define log_fatal   _gcry_core_log_fatal
#define log_error   _gcry_core_log_error
#define log_info    _gcry_core_log_info
#define log_debug   _gcry_core_log_debug
#define log_printf  _gcry_core_log_printf



/* FIXME, moritz.  */
void _gcry_core_progress (gcry_core_context_t ctx,
			  const char *a, int b, int c, int d);

/* Stack burning.  */
void _gcry_burn_stack (int bytes);

/* To avoid that a compiler optimizes certain memset calls away, these
   macros may be used instead. */
#define wipememory2(_ptr,_set,_len) do { \
              volatile char *_vptr=(volatile char *)(_ptr); \
              size_t _vlen=(_len); \
              while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } \
                  } while(0)
#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)

/* Digit predicates.  */

#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define octdigitp(p) (*(p) >= '0' && *(p) <= '7')
#define alphap(a)    (   (*(a) >= 'A' && *(a) <= 'Z')  \
                      || (*(a) >= 'a' && *(a) <= 'z'))
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))



struct gcry_context
{
  struct
  {
    gcry_core_subsystem_secmem_t secmem;
    gcry_core_subsystem_mpi_t mpi;
    gcry_core_subsystem_md_t md;
    gcry_core_subsystem_cipher_t cipher;
    gcry_core_subsystem_ac_t ac;
    gcry_core_subsystem_random_t random;
    gcry_core_subsystem_sexp_t sexp;
    gcry_core_subsystem_prime_t prime;
  } subsystems;

  struct
  {
    struct
    {
      gcry_core_handler_alloc_t alloc;
      gcry_core_handler_realloc_t realloc;
      gcry_core_handler_free_t free;
      gcry_core_handler_no_mem_t no_mem;
      void *no_mem_opaque;
    } mem;
    
    struct
    {
      gcry_core_handler_error_t error;
      void *opaque;
    } error;

    struct
    {
      gcry_core_handler_progress_t progress;
      void *opaque;
    } progress;

    struct
    {
      unsigned int ops_set;
      int (*init) (void);
      int (*mutex_init) (void **priv);
      int (*mutex_destroy) (void **priv);
      int (*mutex_lock) (void **priv);
      int (*mutex_unlock) (void **priv);
      ssize_t (*read) (int fd, void *buf, size_t nbytes);
      ssize_t (*write) (int fd, const void *buf, size_t nbytes);
      ssize_t (*select) (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
			 struct timeval *timeout);
      ssize_t (*waitpid) (pid_t pid, int *status, int options);
      int (*accept) (int s, struct sockaddr *addr, socklen_t *length_ptr);
      int (*connect) (int s, struct sockaddr *addr, socklen_t length);
      int (*sendmsg) (int s, const struct msghdr *msg, int flags);
      int (*recvmsg) (int s, struct msghdr *msg, int flags);
    } ath;

    struct
    {
      gcry_core_handler_log_t logger;
      void *opaque;
    } logger;

  } handler;

  unsigned int debug_flags;
  unsigned int flags;
  const char *random_seed_file;
  int verbosity_level;

  struct
  {
    void *intern;
  } random;

  struct
  {
    void *intern;
  } secmem;
  
  /* ...? */
};



/****************
 * Rotate the 32 bit unsigned integer X by N bits left/right
 */
#if defined(__GNUC__) && defined(__i386__)
static inline u32
rol( u32 x, int n)
{
	__asm__("roll %%cl,%0"
		:"=r" (x)
		:"0" (x),"c" (n));
	return x;
}
#else
#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

#if defined(__GNUC__) && defined(__i386__)
static inline u32
ror(u32 x, int n)
{
	__asm__("rorl %%cl,%0"
		:"=r" (x)
		:"0" (x),"c" (n));
	return x;
}
#else
#define ror(x,n) ( ((x) >> (n)) | ((x) << (32-(n))) )
#endif



#define GCRY_CORE_DEBUGGING_MPI(ctx) \
  gcry_core_debug_flags_get (ctx, GCRY_CORE_FLAG_DEBUG_MPI)
#define GCRY_CORE_DEBUGGING_SYM_CIPHER(ctx) \
  gcry_core_debug_flags_get (ctx, GCRY_CORE_FLAG_DEBUG_SYM_CIPHER)
#define GCRY_CORE_DEBUGGING_ASYM_CIPHER(ctx) \
  gcry_core_debug_flags_get (ctx, GCRY_CORE_FLAG_DEBUG_ASYM_CIPHER)
#define GCRY_CORE_DEBUGGING_HASH(ctx) \
  gcry_core_debug_flags_get (ctx, GCRY_CORE_FLAG_DEBUG_HASH)
#define GCRY_CORE_DEBUGGING_PRIME(ctx) \
  gcry_core_debug_flags_get (ctx, GCRY_CORE_FLAG_DEBUG_PRIME)

#endif
