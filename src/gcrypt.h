/* gcrypt.h -  GNU cryptographic library interface
 * Copyright (C) 1998,1999,2000,2001,2002,2003 Free Software Foundation, Inc.
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

#ifndef _GCRYPT_H
#define _GCRYPT_H

#include <stdarg.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens's auto-indent happy */
}
#endif
#endif

/* The version of this header should match the one of the library It
   should not be used by a program because gcry_check_version() should
   reurn the same version.  The purpose of this macro is to let
   autoconf (using the AM_PATH_GCRYPT macro) check that this header
   matches the installed library.  Note: Do not edit the next line as
   configure may fix the string here.  */
#define GCRYPT_VERSION "1.1.13-cvs"

/* Internal: We can't use the convenience macros for the multi
   precision integer functions when building this library. */
#ifdef _GCRYPT_IN_LIBGCRYPT
# ifndef GCRYPT_NO_MPI_MACROS
#   define GCRYPT_NO_MPI_MACROS 1
# endif
#endif

/* We want to use gcc attributes when possible.  Warning: Don't use
   these macros in your progranms: As indicated by the leading
   underscore they are subject to change without notice. */
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96 )
# define _GCRY_GCC_ATTR_PURE  __attribute__ ((__pure__))
#else
# define _GCRY_GCC_ATTR_PURE
#endif
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 2 )
# define _GCRY_GCC_ATTR_MALLOC  __attribute__ ((__malloc__))
#else
# define _GCRY_GCC_ATTR_MALLOC
#endif


/* The data object used to hold a multi precision integer.  GcryMPI is
   the preferred one. */
struct gcry_mpi;
typedef struct gcry_mpi *GCRY_MPI;
typedef struct gcry_mpi *GcryMPI;


/* Error handling etc. */

/* The error numbers used by Libgcrypt. */
/* FIXME: We should use the same values as they were used in GnuPG
   1.0.  gpg --status-fd may print some of these values. */
enum
  {
    GCRYERR_SUCCESS = 0,    /* "no error" (this is guaranteed to be 0) */
    GCRYERR_GENERAL = 1,    /* catch all the other errors code */
    
    GCRYERR_INV_PK_ALGO = 4,    /* invalid public key algorithm */
    GCRYERR_INV_MD_ALGO = 5,    /* invalid message digest algorithm */
    GCRYERR_BAD_PUBLIC_KEY = 6, /* Bad public key */
    GCRYERR_BAD_SECRET_KEY = 7, /* Bad secret key */
    GCRYERR_BAD_SIGNATURE = 8,	/* Bad signature */
    
    GCRYERR_INV_CIPHER_ALGO = 12, /* invalid cipher algorithm */
    GCRYERR_BAD_MPI = 30,         /* problem with an MPI's value*/
    GCRYERR_WRONG_PK_ALGO = 41,   /* wrong public key algorithm */
    GCRYERR_WEAK_KEY = 43,        /* weak encryption key */
    GCRYERR_INV_KEYLEN = 44,      /* invalid length of a key*/
    GCRYERR_INV_ARG = 45,         /* invalid argument */
    GCRYERR_SELFTEST = 50,	  /* selftest failed */

    /* error codes not used in GnuPG 1.0 */
    GCRYERR_INV_OP = 61,          /* invalid operation code or ctl command */
    GCRYERR_NO_MEM = 62,          /* out of core */
    GCRYERR_INTERNAL = 63,        /* internal error */
    GCRYERR_EOF = 64,	          /* (-1) is remapped to this value */
    GCRYERR_INV_OBJ = 65,         /* an object is not valid */
    GCRYERR_TOO_SHORT = 66,       /* provided buffer/object too short */
    GCRYERR_TOO_LARGE = 67,       /* object is too large */
    GCRYERR_NO_OBJ = 68,          /* Missing item in an object */
    GCRYERR_NOT_IMPL = 69,        /* Not implemented */
    GCRYERR_CONFLICT = 70,        /* conflicting use of functions/values */
    GCRYERR_INV_CIPHER_MODE = 71, /* invalid/unsupported cipher mode */ 
    GCRYERR_INV_FLAG = 72,        /* invalid flag */

    /* error codes pertaining to S-expressions */
    GCRYERR_SEXP_INV_LEN_SPEC    = 201,
    GCRYERR_SEXP_STRING_TOO_LONG = 202,
    GCRYERR_SEXP_UNMATCHED_PAREN = 203, 
    GCRYERR_SEXP_NOT_CANONICAL   = 204, 
    GCRYERR_SEXP_BAD_CHARACTER   = 205, 
    GCRYERR_SEXP_BAD_QUOTATION   = 206,/* or invalid hex or octal value */
    GCRYERR_SEXP_ZERO_PREFIX     = 207,/* first character of a length is 0 */
    GCRYERR_SEXP_NESTED_DH       = 208,/* nested display hints */
    GCRYERR_SEXP_UNMATCHED_DH    = 209,/* unmatched display hint */
    GCRYERR_SEXP_UNEXPECTED_PUNC = 210,/* unexpected reserved punctuation */
    GCRYERR_SEXP_BAD_HEX_CHAR    = 211,
    GCRYERR_SEXP_ODD_HEX_NUMBERS = 212,
    GCRYERR_SEXP_BAD_OCT_CHAR    = 213
  };

/* Check that the library fulfills the version requirement.  */
const char *gcry_check_version (const char *req_version);

/* Return the error number for the last failed function call. */
int gcry_errno(void) _GCRY_GCC_ATTR_PURE;

/* Map an error number to a string. */
const char *gcry_strerror (int ec);

/* Codes used with the gcry_control function. */
enum gcry_ctl_cmds 
  {
    GCRYCTL_SET_KEY  = 1,
    GCRYCTL_SET_IV   = 2,
    GCRYCTL_CFB_SYNC = 3,
    GCRYCTL_RESET    = 4,   /* e.g. for MDs */
    GCRYCTL_FINALIZE = 5,
    GCRYCTL_GET_KEYLEN = 6,
    GCRYCTL_GET_BLKLEN = 7,
    GCRYCTL_TEST_ALGO = 8,
    GCRYCTL_IS_SECURE = 9,
    GCRYCTL_GET_ASNOID = 10,
    GCRYCTL_ENABLE_ALGO = 11,
    GCRYCTL_DISABLE_ALGO = 12,
    GCRYCTL_DUMP_RANDOM_STATS = 13,
    GCRYCTL_DUMP_SECMEM_STATS = 14,
    GCRYCTL_GET_ALGO_NPKEY    = 15,
    GCRYCTL_GET_ALGO_NSKEY    = 16,
    GCRYCTL_GET_ALGO_NSIGN    = 17,
    GCRYCTL_GET_ALGO_NENCR    = 18,
    GCRYCTL_SET_VERBOSITY     = 19,
    GCRYCTL_SET_DEBUG_FLAGS   = 20,
    GCRYCTL_CLEAR_DEBUG_FLAGS = 21,
    GCRYCTL_USE_SECURE_RNDPOOL= 22,
    GCRYCTL_DUMP_MEMORY_STATS = 23,
    GCRYCTL_INIT_SECMEM       = 24,
    GCRYCTL_TERM_SECMEM       = 25,
    GCRYCTL_DISABLE_SECMEM_WARN = 27,
    GCRYCTL_SUSPEND_SECMEM_WARN = 28,
    GCRYCTL_RESUME_SECMEM_WARN	= 29,
    GCRYCTL_DROP_PRIVS		= 30,
    GCRYCTL_ENABLE_M_GUARD	= 31,
    GCRYCTL_START_DUMP		= 32,
    GCRYCTL_STOP_DUMP		= 33,
    GCRYCTL_GET_ALGO_USAGE      = 34,
    GCRYCTL_IS_ALGO_ENABLED     = 35,
    GCRYCTL_DISABLE_INTERNAL_LOCKING = 36,
    GCRYCTL_DISABLE_SECMEM      = 37,
    GCRYCTL_INITIALIZATION_FINISHED = 38,
    GCRYCTL_INITIALIZATION_FINISHED_P = 39,
    GCRYCTL_ANY_INITIALIZATION_P = 40,
    GCRYCTL_SET_CBC_CTS = 41,
    GCRYCTL_ENABLE_QUICK_RANDOM = 42
  };

/* Perform various operations defined by CMD. */
int gcry_control (enum gcry_ctl_cmds CMD, ...);



/* S-expression management. */ 

/* The object to represent an S-expression as used with the
   public key functions.  GcrySexp is the preferrred form. */
struct gcry_sexp;
typedef struct gcry_sexp *GCRY_SEXP;
typedef struct gcry_sexp *GcrySexp;  

/* The possible values for the S-expression format. */
enum gcry_sexp_format {
    GCRYSEXP_FMT_DEFAULT   = 0,
    GCRYSEXP_FMT_CANON	   = 1,
    GCRYSEXP_FMT_BASE64    = 2,
    GCRYSEXP_FMT_ADVANCED  = 3
};

/* Create an new S-expression object from BUFFER of size LENGTH and
   return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER
   is expected to be in canonized format */
int gcry_sexp_new (GcrySexp *retsexp, const void *buffer, size_t length,
                   int autodetect);

/* Same as gcry_sexp_new but allows to pass a FREEFNC which has the
   effect to transfer ownership of BUFFER to the created object. */
int gcry_sexp_create (GcrySexp *retsexp, void *buffer, size_t length,
                      int autodetect, void (*freefnc)(void*) );

/* Scan BUFFER and return a new S-expression object in RETSEXP.  This
   function expects a printf like string in BUFFER. */
int gcry_sexp_sscan (GcrySexp *retsexp, size_t *erroff,
                     const char *buffer, size_t length );

/* Same as gcry_sexp_sscan but expects a string in FORMAT and can thus
   only be used for certain encodings. */
int gcry_sexp_build (GcrySexp *retsexp, size_t *erroff,
                     const char *format, ... );

/* Release the S-expression object SEXP */
void gcry_sexp_release (GcrySexp sexp);

/* Calculate the length of an canonized S-expresion in BUFFER and
   check for a valid encoding. */
size_t gcry_sexp_canon_len (const unsigned char *buffer, size_t length, 
                            size_t *erroff, int *errcode);

/* Copies the S-expression object SEXP into BUFFER using the format
   specified in MODE. */
size_t gcry_sexp_sprint (GCRY_SEXP sexp, int mode, char *buffer,
                         size_t maxlength );

void	  gcry_sexp_dump( const GCRY_SEXP a );
GCRY_SEXP gcry_sexp_cons( const GCRY_SEXP a, const GCRY_SEXP b );
GCRY_SEXP gcry_sexp_alist( const GCRY_SEXP *array );
GCRY_SEXP gcry_sexp_vlist( const GCRY_SEXP a, ... );
GCRY_SEXP gcry_sexp_append( const GCRY_SEXP a, const GCRY_SEXP n );
GCRY_SEXP gcry_sexp_prepend( const GCRY_SEXP a, const GCRY_SEXP n );
GCRY_SEXP gcry_sexp_find_token( GCRY_SEXP list,
				  const char *tok, size_t toklen );
int	    gcry_sexp_length( const GCRY_SEXP list );
GCRY_SEXP   gcry_sexp_nth( const GCRY_SEXP list, int number );
GCRY_SEXP   gcry_sexp_car( const GCRY_SEXP list );
GCRY_SEXP   gcry_sexp_cdr( const GCRY_SEXP list );
GCRY_SEXP   gcry_sexp_cadr( const GCRY_SEXP list );
const char *gcry_sexp_nth_data( const GCRY_SEXP list, int number,
						      size_t *datalen );
GCRY_MPI    gcry_sexp_nth_mpi( GCRY_SEXP list, int number, int mpifmt );



/*******************************************
 *					   *
 *  multi precision integer functions	   *
 *					   *
 *******************************************/

/* Different formats of external big integer representation. */
enum gcry_mpi_format 
  {
    GCRYMPI_FMT_NONE= 0,
    GCRYMPI_FMT_STD = 1,    /* twos complement stored without length */
    GCRYMPI_FMT_PGP = 2,    /* As used by OpenPGP (only defined as unsigned)*/
    GCRYMPI_FMT_SSH = 3,    /* As used by SSH (same as 1 but with length)*/
    GCRYMPI_FMT_HEX = 4,    /* hex format */
    GCRYMPI_FMT_USG = 5     /* like STD but this is an unsigned one */
  };

/* Flags used for creating big integers.  */
enum gcry_mpi_flag 
  {
    GCRYMPI_FLAG_SECURE = 1,  /* Allocate the number in "secure" memory. */
    GCRYMPI_FLAG_OPAQUE = 2   /* The number is not a real one but just a
                               way to store some bytes.  This is
                               useful for encrypted big integers. */
  };


/* Allocate a new big integer object, initialize it with 0 and
   initially allocate memory for a number of at least NBITS. */
GcryMPI gcry_mpi_new (unsigned int nbits);

/* Same as gcry_mpi_new() but allocate in "secure" memory. */
GcryMPI gcry_mpi_snew (unsigned int nbits);

/* Release the number A and free all associated resources. */
void gcry_mpi_release (GcryMPI a);

/* Create a new number with the same value as A. */
GcryMPI gcry_mpi_copy (const GcryMPI a);

/* Store the big integer value U in W. */
GcryMPI gcry_mpi_set (GcryMPI w, const GcryMPI u);

/* Store the unsigned integer value U in W. */
GcryMPI gcry_mpi_set_ui (GcryMPI w, unsigned long u);

/* Swap the values of A and B. */
void gcry_mpi_swap (GcryMPI a, GcryMPI b);

/* Compare the big integer number U and V returning 0 for equality, a
   positive value for U > V and a negative for U < V. */
int gcry_mpi_cmp (const GcryMPI u, const GcryMPI v);

/* Compare the big integer number U with the unsigned integer V
   returning 0 for equality, a positive value for U > V and a negative
   for U < V. */
int gcry_mpi_cmp_ui (const GcryMPI u, unsigned long v);

/* Convert the external representation of an integer stored in BUFFER
   with a size of (*NBYTES) in a newly create MPI returned in RET_MPI.
   For certain formats a length is not required and may be passed as
   NULL.  After a successful operation NBYTES received the number of
   bytes actually scanned. */
int gcry_mpi_scan (GcryMPI *ret_mpi, enum gcry_mpi_format format,
                   const char *buffer, size_t *nbytes);

/* Convert the big integer A into the external representation
   described by FORMAT and store it in the provided BUFFER which has
   the size (*NBYTES).  NBYTES receives the actual length of the
   external representation. */
int gcry_mpi_print (enum gcry_mpi_format format,
                    char *buffer, size_t *nbytes, const GcryMPI a);

/* Convert the big integer A int the external representation desribed
   by FORMAT and store it in a newly allocated buffer which address
   will be put into BUFFER.  NBYTES receives the actual lengths of the
   external representation. */
int gcry_mpi_aprint (enum gcry_mpi_format format,
                     void **buffer, size_t *nbytes, const GcryMPI a);

/* W = U + V.  */
void gcry_mpi_add (GcryMPI w, GcryMPI u, GcryMPI v);

/* W = U + V.  V is an unsigned integer. */
void gcry_mpi_add_ui (GcryMPI w, GcryMPI u, unsigned long v);

/* W = U + V mod M. */
void gcry_mpi_addm (GcryMPI w, GcryMPI u, GcryMPI v, GcryMPI m);

/* W = U - V. */
void gcry_mpi_sub (GcryMPI w, GcryMPI u, GcryMPI v);

/* W = U - V.  V is an unsigned integer. */
void gcry_mpi_sub_ui (GcryMPI w, GcryMPI u, unsigned long v );

/* W = U - V mod M */
void gcry_mpi_subm (GcryMPI w, GcryMPI u, GcryMPI v, GcryMPI m);

/* W = U * V. */
void gcry_mpi_mul (GcryMPI w, GcryMPI u, GcryMPI v);

/* W = U * V.  V is an unsigned integer. */
void gcry_mpi_mul_ui (GcryMPI w, GcryMPI u, unsigned long v );

/* W = U * V mod M. */
void gcry_mpi_mulm (GcryMPI w, GcryMPI u, GcryMPI v, GcryMPI m);

/* W = U * (2 ^ CNT). */
void gcry_mpi_mul_2exp (GcryMPI w, GcryMPI u, unsigned long cnt);

/* Q = DIVIDEND / DIVISOR, R = DIVIDEND % DIVISOR,
   Q or R may be passed as NULL.  ROUND should be negative or 0. */
void gcry_mpi_div (GcryMPI q, GcryMPI r,
                   GcryMPI dividend, GcryMPI divisor, int round);

/* R = DIVIDEND % DIVISOR */
void gcry_mpi_mod (GcryMPI r, GcryMPI dividend, GcryMPI divisor);

/* W = B ^ E mod M. */
void gcry_mpi_powm (GcryMPI w,
                    const GcryMPI b, const GcryMPI e, const GcryMPI m);

/* Set G to the greatest common divisor of A and B.  
   Return true if the G is 1. */
int gcry_mpi_gcd (GcryMPI g, GcryMPI a, GcryMPI b);

/* Set X to the multiplicative inverse of A mod M.
   Return true if the value exists. */
int gcry_mpi_invm (GcryMPI x, GcryMPI a, GcryMPI m);


/* Return the number of bits required to represent A. */
unsigned int gcry_mpi_get_nbits (GcryMPI a);

/* Return true when bit number N (counting from 0) is set in A. */
int      gcry_mpi_test_bit (GcryMPI a, unsigned int n);

/* Set bit number N in A. */
void     gcry_mpi_set_bit (GcryMPI a, unsigned int n);

/* Clear bit number N in A. */
void     gcry_mpi_clear_bit (GcryMPI a, unsigned int n);

/* Set bit number N in A and clear all bits greater than N. */
void     gcry_mpi_set_highbit (GcryMPI a, unsigned int n);

/* Clear bit number N in A and all bits greater than N. */
void     gcry_mpi_clear_highbit (GcryMPI a, unsigned int n);

/* Shift the value of A by N bits to the right and store the result in X. */
void     gcry_mpi_rshift (GcryMPI x, GcryMPI a, unsigned int n);

/* Store NBITS of the value P points to in A and mark A as an opaque
   value. */
GcryMPI gcry_mpi_set_opaque (GcryMPI a, void *p, unsigned int nbits);

/* creturn a pointer to an opaque value stored in A and return its
   size in NBITS.  Note that the returned pointer is still owned by A
   and that the function should never be used for an non-opaque
   MPI. */
void *gcry_mpi_get_opaque (GcryMPI a, unsigned int *nbits);

/* Set the FLAG for the big integer A.  Currently only the flag
   GCRYMPI_FLAG_SECURE is allowed to convert A into an big intger
   stored in "secure" memory. */
void gcry_mpi_set_flag (GcryMPI a, enum gcry_mpi_flag flag);

/* Clear FLAG for the big integer A.  Note that this function is
   currently useless as no flags are allowed. */
void gcry_mpi_clear_flag (GcryMPI a, enum gcry_mpi_flag flag);

/* Return true when the FLAG is set for A. */
int gcry_mpi_get_flag (GcryMPI a, enum gcry_mpi_flag flag);

/* Unless the GCRYPT_NO_MPI_MACROS is used, provide a couple of
   convenience macors for the big integer functions. */
#ifndef GCRYPT_NO_MPI_MACROS
#define mpi_new(n)	    gcry_mpi_new( (n) )
#define mpi_secure_new( n ) gcry_mpi_snew( (n) )
#define mpi_release( a )    do { gcry_mpi_release( (a) ); \
				 (a) = NULL; } while(0)
#define mpi_copy( a )	    gcry_mpi_copy( (a) )
#define mpi_set( w, u)	    gcry_mpi_set( (w), (u) )
#define mpi_set_ui( w, u)   gcry_mpi_set_ui( (w), (u) )
#define mpi_cmp( u, v )     gcry_mpi_cmp( (u), (v) )
#define mpi_cmp_ui( u, v )  gcry_mpi_cmp_ui( (u), (v) )

#define mpi_add_ui(w,u,v)   gcry_mpi_add_ui((w),(u),(v))
#define mpi_add(w,u,v)      gcry_mpi_add ((w),(u),(v))
#define mpi_addm(w,u,v,m)   gcry_mpi_addm ((w),(u),(v),(m))
#define mpi_sub_ui(w,u,v)   gcry_mpi_sub_ui ((w),(u),(v))
#define mpi_sub(w,u,v)      gcry_mpi_sub ((w),(u),(v))
#define mpi_subm(w,u,v,m)   gcry_mpi_subm ((w),(u),(v),(m))
#define mpi_mul_ui(w,u,v)   gcry_mpi_mul_ui ((w),(u),(v))
#define mpi_mul_2exp(w,u,v) gcry_mpi_mul_2exp ((w),(u),(v))
#define mpi_mul(w,u,v)      gcry_mpi_mul ((w),(u),(v))
#define mpi_mulm(w,u,v,m)   gcry_mpi_mulm ((w),(u),(v),(m))
#define mpi_powm(w,b,e,m)   gcry_mpi_powm ( (w), (b), (e), (m) )
#define mpi_tdiv(q,r,a,m)   gcry_mpi_div ( (q), (r), (a), (m), 0)
#define mpi_fdiv(q,r,a,m)   gcry_mpi_div ( (q), (r), (a), (m), -1)
#define mpi_mod(r,a,m)      gcry_mpi_mod ((r), (a), (m))
#define mpi_gcd(g,a,b)      gcry_mpi_gcd ( (g), (a), (b) )
#define mpi_invm(g,a,b)     gcry_mpi_invm ( (g), (a), (b) )

#define mpi_get_nbits(a)       gcry_mpi_get_nbits ((a))
#define mpi_test_bit(a,b)      gcry_mpi_test_bit ((a),(b))
#define mpi_set_bit(a,b)       gcry_mpi_set_bit ((a),(b))
#define mpi_set_highbit(a,b)   gcry_mpi_set_highbit ((a),(b))
#define mpi_clear_bit(a,b)     gcry_mpi_clear_bit ((a),(b))
#define mpi_clear_highbit(a,b) gcry_mpi_clear_highbit ((a),(b))
#define mpi_rshift(a,b,c)      gcry_mpi_rshift ((a),(b),(c))

#define mpi_set_opaque(a,b,c) gcry_mpi_set_opaque( (a), (b), (c) )
#define mpi_get_opaque(a,b)   gcry_mpi_get_opaque( (a), (b) )
#endif /* GCRYPT_NO_MPI_MACROS */



/************************************
 *                                  *
 *   symmetric cipher functions     *
 *                                  *
 ************************************/

/* The data object used to hold a handle to an encryption opject.
   GcryCipherHd is the preferred one. */
struct gcry_cipher_handle;
typedef struct gcry_cipher_handle *GCRY_CIPHER_HD;
typedef struct gcry_cipher_handle *GcryCipherHd;

/* All symmetric encryption algorithms are identified by their IDs.
   More IDs may be registered at runtime. */
enum gcry_cipher_algos
  {
    GCRY_CIPHER_NONE	    = 0,
    GCRY_CIPHER_IDEA	    = 1,
    GCRY_CIPHER_3DES	    = 2,
    GCRY_CIPHER_CAST5	    = 3,
    GCRY_CIPHER_BLOWFISH    = 4,
    GCRY_CIPHER_SAFER_SK128 = 5,
    GCRY_CIPHER_DES_SK	    = 6,
    GCRY_CIPHER_AES         = 7,
    GCRY_CIPHER_AES192      = 8,
    GCRY_CIPHER_AES256      = 9,
    GCRY_CIPHER_TWOFISH     = 10,
    /* other cipher numbers are above 300 for OpenPGP reasons. */
    GCRY_CIPHER_ARCFOUR     = 301,  /* fully compatible with RSA's RC4 (tm). */
    GCRY_CIPHER_DES         = 302   /* Yes, this is single key 56 bit DES. */
  };

/* The Rijndael algorithm is basically AES, so provide some macros. */
#define GCRY_CIPHER_AES128      GCRY_CIPHER_AES    
#define GCRY_CIPHER_RIJNDAEL    GCRY_CIPHER_AES    
#define GCRY_CIPHER_RIJNDAEL128 GCRY_CIPHER_AES128 
#define GCRY_CIPHER_RIJNDAEL192 GCRY_CIPHER_AES192 
#define GCRY_CIPHER_RIJNDAEL256 GCRY_CIPHER_AES256 

/* The supported encryption modes.  NOte that not all of them are
   supported for each algorithm. */
enum gcry_cipher_modes 
  {
    GCRY_CIPHER_MODE_NONE   = 0,  /* Not yet specified. */
    GCRY_CIPHER_MODE_ECB    = 1,  /* Electronic codebook. */
    GCRY_CIPHER_MODE_CFB    = 2,  /* Cipher feedback. */
    GCRY_CIPHER_MODE_CBC    = 3,  /* Cipher block chaining. */
    GCRY_CIPHER_MODE_STREAM = 4,  /* Used with stream ciphers. */
    GCRY_CIPHER_MODE_OFB    = 5   /* Outer feedback. */
  };

/* Flags used with the open function. */ 
enum gcry_cipher_flags
  {
    GCRY_CIPHER_SECURE	    = 1,  /* Allocate in secure memory. */
    GCRY_CIPHER_ENABLE_SYNC = 2,  /* Enable CFB sync mode. */
    GCRY_CIPHER_CBC_CTS = 4       /* Enable CBC cipher text stealing (CTS). */
  };


/* Create a handle for algorithm ALGO to be used in MODE.  FLAGS may
   be given as an bitwise OR of the gcry_cipher_flags values. */
GcryCipherHd gcry_cipher_open (int algo, int mode, unsigned int flags);

/* Close the cioher handle H and release all resource. */
void gcry_cipher_close (GcryCipherHd h);

/* Perform various operations on the cipher object H. */
int gcry_cipher_ctl( GcryCipherHd h, int cmd, void *buffer, size_t buflen);

/* Retrieve various information about the cipher object H. */
int gcry_cipher_info( GcryCipherHd h, int what, void *buffer, size_t *nbytes);

/* Retrieve various information about the cipher algorithm ALGO. */
int gcry_cipher_algo_info (int algo, int what, void *buffer, size_t *nbytes);

/* Map the cipher algorithm id ALGO to a string representation of that
   algorithm name.  For unknown algorithms this functions returns an
   empty string. */
const char *gcry_cipher_algo_name (int algo) _GCRY_GCC_ATTR_PURE;

/* Map the algorithm name NAME to an cipher algorithm ID.  Return 0 if
   the algorithm name is not known. */
int gcry_cipher_map_name (const char *name) _GCRY_GCC_ATTR_PURE;

/* Given an ASN.1 object identifier in standard IETF dotted decimal
   format in STING, return the encryption mode associated with that
   OID or 0 if not known or applicable. */
int gcry_cipher_mode_from_oid (const char *string) _GCRY_GCC_ATTR_PURE;

/* Encrypt the plaintext of size INLEN in IN using the cipher handle H
   into the buffer OUT which has an allocated length of OUTSIZE.  For
   most algorithms it is possible to pass NULL for in and 0 for INLEN
   and do a in-place decryption of the data provided in OUT. */
int gcry_cipher_encrypt (GcryCipherHd h,
                         unsigned char *out, size_t outsize,
                         const unsigned char *in, size_t inlen);

/* The counterpart to gcry_cipher_encrypt. */
int gcry_cipher_decrypt (GcryCipherHd h,
                         unsigned char *out, size_t outsize,
                         const unsigned char *in, size_t inlen);

/* Set key K of length L for the cipher handle H. 
  (We have to cast away a const char* here - this catch-all ctl
  function was probably not the best choice) */
#define gcry_cipher_setkey(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_KEY, \
							 (char*)(k), (l) )

/* Set initialization vector K of length L for the cipher handle H. */
#define gcry_cipher_setiv(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_IV, \
							 (char*)(k), (l) )

/* Perform the the OppenPGP sync operation if this is enabled for the
   cipher handle H. */
#define gcry_cipher_sync(h)  gcry_cipher_ctl( (h), GCRYCTL_CFB_SYNC, \
								   NULL, 0 )

/* Enable or disable CTS in future calls to gcry_encrypt(). CBC mode only. */
#define gcry_cipher_cts(h,on)  gcry_cipher_ctl( (h), GCRYCTL_SET_CBC_CTS, \
								   NULL, on )

/* Retrieved the key length used with algorithm A. */
#define gcry_cipher_get_algo_keylen(a) \
	    gcry_cipher_algo_info( (a), GCRYCTL_GET_KEYLEN, NULL, NULL )

/* Retrieve the block length used with algorithm A. */
#define gcry_cipher_get_algo_blklen(a) \
	    gcry_cipher_algo_info( (a), GCRYCTL_GET_BLKLEN, NULL, NULL )

/* Return 0 if the algorithm A is available for use. */
#define gcry_cipher_test_algo(a) \
	    gcry_cipher_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )



/************************************
 *                                  *
 *    asymmetric cipher functions   *
 *                                  *
 ************************************/

/* The algorithms and their IDs we support. */
enum gcry_pk_algos 
  {
    GCRY_PK_RSA = 1,
    GCRY_PK_RSA_E = 2,	    /* deprecated */
    GCRY_PK_RSA_S = 3,	    /* deprecated */
    GCRY_PK_ELG_E = 16,     /* use only for OpenPGP */
    GCRY_PK_DSA   = 17,
    GCRY_PK_ELG   = 20
  };

/* Flags describing usage capabilities of a PK algorithm. */
#define GCRY_PK_USAGE_SIGN 1
#define GCRY_PK_USAGE_ENCR 2

/* Encrypt the DATA using the public key PKEY and store the result as
   a newly created S-expression at RESULT. */
int gcry_pk_encrypt (GcrySexp *result, GcrySexp data, GcrySexp pkey);

/* Decrypt the DATA using the private key SKEY and store the result as
   a newly created S-expression at RESULT. */
int gcry_pk_decrypt (GcrySexp *result, GcrySexp data, GcrySexp skey);

/* Sign the DATA using the private key SKEY and store the result as
   a newly created S-expression at RESULT. */
int gcry_pk_sign (GcrySexp *result, GcrySexp data, GcrySexp skey);

/* Check the signature SIGVAL on DATA using the public key PKEY. */
int gcry_pk_verify (GcrySexp sigval, GcrySexp data, GcrySexp pkey);

/* Check that KEY (either private or public) is sane. */
int gcry_pk_testkey (GcrySexp key);

/* Generate a new key pair according to the parameters given in
   S_PARMS.  The new key pair is returned in as an S-expression in
   R_KEY. */
int gcry_pk_genkey (GcrySexp *r_key, GcrySexp s_parms);

/* Catch all function for miscellaneous operations. */
int gcry_pk_ctl (int cmd, void *buffer, size_t buflen);

/* Retrieve information about the public key algorithm ALGO. */
int gcry_pk_algo_info (int algo, int what, void *buffer, size_t *nbytes);

/* Map the public key algorithm id ALGO to a string representation of the
   algorithm name.  For unknown algorithms this functions returns an
   empty string. */
const char *gcry_pk_algo_name (int algo) _GCRY_GCC_ATTR_PURE;

/* Map the algorithm NAME to a public key algorithm Id.  Return 0 if
   the algorithm name is not known. */
int gcry_pk_map_name (const char* name) _GCRY_GCC_ATTR_PURE;

/* Return what is commonly referred as the key length for the given
   public or private KEY.  */
unsigned int gcry_pk_get_nbits (GcrySexp key) _GCRY_GCC_ATTR_PURE;

/* Please note that keygrip is still experimental and should not be
   used without contacting the author. */
unsigned char *gcry_pk_get_keygrip (GcrySexp key, unsigned char *array);

/* Return 0 if the public key algorithm A is available for use. */
#define gcry_pk_test_algo(a) \
	    gcry_pk_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )



/************************************
 *                                  *
 *   cryptograhic hash functions    *
 *                                  *
 ************************************/

/* Algorithm IDs for the hash functions we know about. Not all of them
   are implemnted. */
enum gcry_md_algos
  {
    GCRY_MD_NONE    = 0,  
    GCRY_MD_MD5     = 1,
    GCRY_MD_SHA1    = 2,
    GCRY_MD_RMD160  = 3,
    GCRY_MD_MD2     = 5,
    GCRY_MD_TIGER   = 6,   /* TIGER/192. */
    GCRY_MD_HAVAL   = 7,   /* HAVAL, 5 pass, 160 bit. */
    GCRY_MD_SHA256  = 8,
    GCRY_MD_SHA384  = 9,
    GCRY_MD_SHA512  = 10,
    GCRY_MD_MD4     = 301,
    GCRY_MD_CRC32		= 302,
    GCRY_MD_CRC32_RFC1510	= 303,
    GCRY_MD_CRC24_RFC2440	= 304
  };

/* Flags used with the open function. */
enum gcry_md_flags
  {
    GCRY_MD_FLAG_SECURE = 1,  /* Allocate all buffers in "secure" memory */
    GCRY_MD_FLAG_HMAC	= 2   /* Make an HMAC out of this algorithm. */
  };


/* This object is used to hold a handle to an message digest object.
   GcryCipherHd is the preferred type. */
struct gcry_md_context;
struct gcry_md_handle 
  { /* This structure is private - only to be used by the gcry_md_  macros. */
    struct gcry_md_context *ctx;
    int  bufpos;
    int  bufsize;
    unsigned char buf[1];
  };
typedef struct gcry_md_handle *GCRY_MD_HD;
typedef struct gcry_md_handle *GcryMDHd;


/* Create a message digest object for algorithm ALGO.  FLAGS may be
   given as an bitwise OR of the gcry_md_flags values.  ALGO may be
   given as 0 if the algorithms to be used are later set using
   gcry_md_enable. */
GcryMDHd gcry_md_open (int algo, unsigned int flags);

/* Release the message digest object HD. */
void gcry_md_close (GcryMDHd hd);

/* Add the message digest algorithm ALGO to the digest object HD. */
int gcry_md_enable( GcryMDHd hd, int algo );

/* Create a new digest object as an exact copy of the object HD. */
GcryMDHd gcry_md_copy (GcryMDHd hd);

/* Reset the digest object HD to its initail state. */
void gcry_md_reset (GcryMDHd hd);

/* Perform various operations on the digets object HD. */
int gcry_md_ctl (GcryMDHd hd, int cmd, unsigned char *buffer, size_t buflen);

/* Pass LENGTH bytes of data in BUFFER to the digest object HD so that
   it can update the digest values.  This is the actual hash
   function. */
void gcry_md_write (GcryMDHd hd, const void *buffer, size_t length);

/* Read out the final digest from HD return the digest value for
   algorithm ALGO. */
unsigned char *gcry_md_read (GcryMDHd hd, int algo);

/* Convenience function to calculate the hash from the data in BUFFER
   of size LENGTH using the algorithm ALGO avoiding the creating of a
   hash object.  The hash is returned in the caller provided buffer
   DIGEST which must be large enough to hold the digest of the given
   algorithm. */
void gcry_md_hash_buffer (int algo, void *digest,
			  const void *buffer, size_t length);

/* Retrieve the algorithm used with HD.  This does not work reliable
   if more than one algorithm is enabled in HD. */
int gcry_md_get_algo (GcryMDHd hd);

/* Retrieved the length in bytes of the digest yielded by algorithm
   ALGO. */
unsigned int gcry_md_get_algo_dlen (int algo);

/* Retrieve various information about the object H. */
int gcry_md_info (GcryMDHd h, int what, void *buffer, size_t *nbytes);

/* Retrieve various information about the algorithm ALGO. */
int gcry_md_algo_info( int algo, int what, void *buffer, size_t *nbytes);

/* Map the digest algorithm id ALGO to a string representation of the
   algorithm name.  For unknown algorithms this functions returns an
   empty string. */
const char *gcry_md_algo_name (int algo) _GCRY_GCC_ATTR_PURE;

/* Map the algorithm NAME to a digest algorithm Id.  Return 0 if
   the algorithm name is not known. */
int gcry_md_map_name (const char* name) _GCRY_GCC_ATTR_PURE;

/* For use with the HMAC feature, the set MAC key to the KEY of
   KEYLEN. */
int gcry_md_setkey (GcryMDHd hd, const void *key, size_t keylen);

/* Update the hash(s) of H with the character C.  This is a buffered
   version of the gcry_md_write function. */
#define gcry_md_putc(h,c)  \
	    do {					  \
                GcryMDHd h__ = (h);                       \
		if( (h__)->bufpos == (h__)->bufsize )	  \
		    gcry_md_write( (h__), NULL, 0 );	  \
		(h__)->buf[(h__)->bufpos++] = (c) & 0xff; \
	    } while(0)

/* Finalize the digest calculation.  This is not really needed because
   gcry_md_read() does this implicitly. */
#define gcry_md_final(a) \
	    gcry_md_ctl ((a), GCRYCTL_FINALIZE, NULL, 0)

/* Return true when the digest object is allocated in "secure" memory. */
#define gcry_md_is_secure(a) \
	    gcry_md_info( (a), GCRYCTL_IS_SECURE, NULL, NULL )

/* Return 0 if the algorithm A is available for use. */
#define gcry_md_test_algo(a) \
	    gcry_md_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )

/* Return an DER encoded ASN.1 OID for the algorithm A in buffer B. N
   must point to size_t variable with the available size of buffer B.
   After return it will receive the actual size of the returned
   OID. */
#define gcry_md_get_asnoid(a,b,n) \
            gcry_md_algo_info((a), GCRYCTL_GET_ASNOID, (b), (n))

/* Enable debugging for digets object A; i.e. create files named
   dbgmd-<n>.<string> while hashing.  B is a string used as the suffix
   for the filename. */
#define gcry_md_start_debug(a,b) \
	    gcry_md_ctl( (a), GCRYCTL_START_DUMP, (b), 0 )

/* Disable the debugging of A. */
#define gcry_md_stop_debug(a,b) \
	    gcry_md_ctl( (a), GCRYCTL_STOP_DUMP, (b), 0 )



/************************************
 *                                  *
 *   random generating functions    *
 *                                  *
 ************************************/

/* The possible values for the random quality.  The rule of thumb is
   to use WEAK for random number which don't need to be
   cryptographically strong, STRONG for session keys and VERY_STRONG
   for key material. */
enum gcry_random_level
  {
    GCRY_WEAK_RANDOM = 0,
    GCRY_STRONG_RANDOM = 1,
    GCRY_VERY_STRONG_RANDOM = 2
  };


/* Fill BUFFER with LENGTH bytes of random, using random numbers of
   quality LEVEL. */
void gcry_randomize (unsigned char *buffer, size_t length,
		     enum gcry_random_level level);

/* Add the external random from BUFFER with LENGTH bytes into the
   pool. QUALITY should either be -1 for unknown or in the range of 0
   to 100 */
int gcry_random_add_bytes (const void *buffer, size_t length, int quality);

/* Return NBYTES of allocated random using a random numbers of quality
   LEVEL. */
void *gcry_random_bytes (size_t nbytes, enum gcry_random_level level)
                         _GCRY_GCC_ATTR_MALLOC;

/* Return NBYTES of allocated random using a random numbers of quality
   LEVEL.  The random numbers are created returned in "secure"
   memory. */
void *gcry_random_bytes_secure (size_t nbytes, enum gcry_random_level level)
                                _GCRY_GCC_ATTR_MALLOC;


/* Set the big inetger W to a random value of NBITS using a random
   generator with quality LEVEL. */
void gcry_mpi_randomize (GcryMPI w,
                         unsigned int nbits, enum gcry_random_level level);



/************************************
 *                                  *
 *     miscellaneous stuff          *
 *                                  *
 ************************************/

/* Log leveles used by the internal logging facility. */
enum gcry_log_levels 
  {
    GCRY_LOG_CONT   = 0,    /* continue the last log line */
    GCRY_LOG_INFO   = 10,
    GCRY_LOG_WARN   = 20,
    GCRY_LOG_ERROR  = 30,
    GCRY_LOG_FATAL  = 40,
    GCRY_LOG_BUG    = 50,
    GCRY_LOG_DEBUG  = 100
  };


/* Certain operations can provide progress information.  This function
   is used to register a handler for retrieving these information. */
void gcry_set_progress_handler (void (*cb)(void *,const char*,int, int, int),
                                void *cb_data);



/* Register a custom memory allocation functions. */
void gcry_set_allocation_handler (void *(*new_alloc_func)(size_t n),
				  void *(*new_alloc_secure_func)(size_t n),
				  int (*new_is_secure_func)(const void*),
				  void *(*new_realloc_func)(void *p, size_t n),
				  void (*new_free_func)(void*));

/* Register a function used instead of the internal out of memory
   handler. */
void gcry_set_outofcore_handler (int (*h)(void*, size_t, unsigned int),
                                 void *opaque );

/* Register a function used instead of the internal fatal error
   handler. */
void gcry_set_fatalerror_handler (void (*fnc)(void*,int, const char*),
                                  void *opaque);

/* Reserved for future use. */
void gcry_set_gettext_handler (const char *(*f)(const char*));

/* Regstier a function used instead of the internal logging
   facility. */
void gcry_set_log_handler (void (*f)(void*,int, const char*, va_list),
                           void *opaque);


/* Libgcrypt uses its own memory allocation.  It is important to use
   gcry_free () to release memory allocated by libgcrypt. */
void *gcry_malloc (size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_calloc (size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_malloc_secure (size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_calloc_secure (size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_realloc (void *a, size_t n);
char *gcry_strdup (const char *string) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xmalloc (size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xcalloc (size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xmalloc_secure (size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xcalloc_secure (size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xrealloc (void *a, size_t n);
char *gcry_xstrdup (const char * a) _GCRY_GCC_ATTR_MALLOC;
void  gcry_free (void *a);

/* Return true if A is allocated in "secure" memory. */
int gcry_is_secure (const void *a) _GCRY_GCC_ATTR_PURE;


#ifndef GCRYPT_NO_MPI_MACROS
# ifndef DID_MPI_TYPEDEF
    typedef struct gcry_mpi *MPI;
#   define DID_MPI_TYPEDEF
# endif
#endif /* GCRYPT_NO_MPI_MACROS */

#ifdef __cplusplus
}
#endif
#endif /* _GCRYPT_H */
