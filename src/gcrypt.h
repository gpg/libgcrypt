/* gcrypt.h -  GNU digital encryption library interface
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef _GCRYPT_H
#define _GCRYPT_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The version of this header should match the one of the library
 * It should not be used by a program because gcry_check_version()
 * should reurn the same version.  The purpose of this macro is to
 * let autoconf (using the AM_PATH_GCRYPT macro) check that this
 * header matches the installed library.
 * Note: Do not edit the next line as configure may fix the string here.
 */
#define GCRYPT_VERSION "1.1.6"


#ifndef HAVE_BYTE_TYPEDEF
# undef byte	   /* maybe there is a macro with this name */
  typedef unsigned char byte;
# define HAVE_BYTE_TYPEDEF
#endif

#ifdef _GCRYPT_IN_LIBGCRYPT
# ifndef GCRYPT_NO_MPI_MACROS
#   define GCRYPT_NO_MPI_MACROS 1
# endif
#endif

struct gcry_mpi;
typedef struct gcry_mpi *GCRY_MPI;

/*******************************************
 *					   *
 *  error handling etc. 		   *
 *					   *
 *******************************************/

/* FIXME: We should use the same values as they were used in GnuPG 1.0.
 *	  gpg --status-fd may print some of these values */
enum {
    GCRYERR_SUCCESS = 0,    /* "no error" */
    GCRYERR_GENERAL = 1,    /* catch all the other errors code */

    GCRYERR_INV_PK_ALGO = 4, /* invalid public key algorithm */
    GCRYERR_INV_MD_ALGO = 5, /* invalid message digest algorithm */
    GCRYERR_BAD_PUBLIC_KEY = 6, /* Bad public key */
    GCRYERR_BAD_SECRET_KEY = 7, /* Bad secret key */
    GCRYERR_BAD_SIGNATURE = 8,	/* Bad signature */

    GCRYERR_INV_CIPHER_ALGO = 12, /* invalid cipher algorithm */
    GCRYERR_BAD_MPI = 30,
    GCRYERR_WRONG_PK_ALGO = 41, /* wrong public key algorithm */
    GCRYERR_WEAK_KEY = 43,  /* weak encryption key */
    GCRYERR_INV_KEYLEN = 44,  /* invalid length of a key*/
    GCRYERR_INV_ARG = 45,    /* invalid argument */
    GCRYERR_SELFTEST = 50,	/* selftest failed */

    /* error codes not used in GnuPG 1.0 */
    GCRYERR_INV_OP = 61,     /* invalid operation code or ctl command */
    GCRYERR_NO_MEM = 62,     /* out of core */
    GCRYERR_INTERNAL = 63,   /* internal error */
    GCRYERR_EOF = 64,	     /* (-1) is remapped to this value */
    GCRYERR_INV_OBJ = 65,    /* an object is not valid */
    GCRYERR_TOO_SHORT = 66,  /* provided buffer too short */
    GCRYERR_TOO_LARGE = 67,  /* object is too large */
    GCRYERR_NO_OBJ = 68,     /* Missing item in an object */
    GCRYERR_NOT_IMPL = 69,   /* Not implemented */
    GCRYERR_CONFLICT = 70,
    GCRYERR_INV_CIPHER_MODE = 71
};

const char *gcry_check_version( const char *req_version );

int gcry_errno(void);
const char *gcry_strerror( int ec );

enum gcry_ctl_cmds {
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
    GCRYCTL_IS_ALGO_ENABLED     = 35
};

int gcry_control( enum gcry_ctl_cmds, ... );

enum gcry_random_level {
    GCRY_WEAK_RANDOM = 0,
    GCRY_STRONG_RANDOM = 1,
    GCRY_VERY_STRONG_RANDOM = 2
};


struct gcry_sexp;
typedef struct gcry_sexp *GCRY_SEXP;

enum gcry_sexp_format {
    GCRYSEXP_FMT_DEFAULT   = 0,
    GCRYSEXP_FMT_CANON	   = 1,
    GCRYSEXP_FMT_BASE64    = 2,
    GCRYSEXP_FMT_ADVANCED  = 3
};

void	  gcry_sexp_release( GCRY_SEXP sexp );
void	  gcry_sexp_dump( const GCRY_SEXP a );
GCRY_SEXP gcry_sexp_cons( const GCRY_SEXP a, const GCRY_SEXP b );
GCRY_SEXP gcry_sexp_alist( const GCRY_SEXP *array );
GCRY_SEXP gcry_sexp_vlist( const GCRY_SEXP a, ... );
GCRY_SEXP gcry_sexp_append( const GCRY_SEXP a, const GCRY_SEXP n );
GCRY_SEXP gcry_sexp_prepend( const GCRY_SEXP a, const GCRY_SEXP n );
int	  gcry_sexp_sscan( GCRY_SEXP *retsexp, size_t *erroff,
			   const char *buffer, size_t length );
int	  gcry_sexp_build( GCRY_SEXP *retsexp, size_t *erroff,
			   const char *format, ... );
size_t	  gcry_sexp_sprint( GCRY_SEXP sexp, int mode, char *buffer,
						size_t maxlength );
GCRY_SEXP   gcry_sexp_find_token( GCRY_SEXP list,
				  const char *tok, size_t toklen );
int	    gcry_sexp_length( const GCRY_SEXP list );
GCRY_SEXP   gcry_sexp_nth( const GCRY_SEXP list, int number );
GCRY_SEXP   gcry_sexp_car( const GCRY_SEXP list );
GCRY_SEXP   gcry_sexp_cdr( const GCRY_SEXP list );
GCRY_SEXP   gcry_sexp_cadr( const GCRY_SEXP list );
const char *gcry_sexp_nth_data( const GCRY_SEXP list, int number,
						      size_t *datalen );
GCRY_MPI    gcry_sexp_nth_mpi( GCRY_SEXP list, int number, int mpifmt );

size_t gcry_sexp_canon_len (const unsigned char *buffer, size_t length, 
                            size_t *erroff, int *errcode);


/*******************************************
 *					   *
 *  multi precision integer functions	   *
 *					   *
 *******************************************/

enum gcry_mpi_format {
    GCRYMPI_FMT_NONE= 0,
    GCRYMPI_FMT_STD = 1,    /* twos complement stored without length */
    GCRYMPI_FMT_PGP = 2,    /* As used by OpenPGP (only defined as unsigned)*/
    GCRYMPI_FMT_SSH = 3,    /* As used by SSH (same as 1 but with length)*/
    GCRYMPI_FMT_HEX = 4,    /* hex format */
    GCRYMPI_FMT_USG = 5     /* like STD but this is an unsigned one */
};


enum gcry_mpi_flag {
    GCRYMPI_FLAG_SECURE = 1,
    GCRYMPI_FLAG_OPAQUE = 2
};



GCRY_MPI gcry_mpi_new( unsigned int nbits );
GCRY_MPI gcry_mpi_snew( unsigned int nbits );
void	 gcry_mpi_release( GCRY_MPI a );
GCRY_MPI gcry_mpi_copy( const GCRY_MPI a );
GCRY_MPI gcry_mpi_set( GCRY_MPI w, const GCRY_MPI u );
GCRY_MPI gcry_mpi_set_ui( GCRY_MPI w, unsigned long u );
int	 gcry_mpi_cmp( const GCRY_MPI u, const GCRY_MPI v );
int	 gcry_mpi_cmp_ui( const GCRY_MPI u, unsigned long v );
void	 gcry_mpi_randomize( GCRY_MPI w,
			     unsigned int nbits, enum gcry_random_level level);
int	 gcry_mpi_scan( GCRY_MPI *ret_mpi, enum gcry_mpi_format format,
				       const char *buffer, size_t *nbytes );
int	 gcry_mpi_print( enum gcry_mpi_format format,
			 char *buffer, size_t *nbytes, const GCRY_MPI a );
int	 gcry_mpi_aprint( enum gcry_mpi_format format,
			  void **buffer, size_t *nbytes, const GCRY_MPI a );


void     gcry_mpi_add(GCRY_MPI w, GCRY_MPI u, GCRY_MPI v);
void     gcry_mpi_add_ui(GCRY_MPI w, GCRY_MPI u, unsigned long v );
void     gcry_mpi_addm(GCRY_MPI w, GCRY_MPI u, GCRY_MPI v, GCRY_MPI m);
void     gcry_mpi_sub( GCRY_MPI w, GCRY_MPI u, GCRY_MPI v);
void     gcry_mpi_sub_ui(GCRY_MPI w, GCRY_MPI u, unsigned long v );
void     gcry_mpi_subm( GCRY_MPI w, GCRY_MPI u, GCRY_MPI v, GCRY_MPI m);
void     gcry_mpi_mul_ui(GCRY_MPI w, GCRY_MPI u, unsigned long v );
void     gcry_mpi_mul_2exp( GCRY_MPI w, GCRY_MPI u, unsigned long cnt);
void     gcry_mpi_mul( GCRY_MPI w, GCRY_MPI u, GCRY_MPI v);
void     gcry_mpi_mulm( GCRY_MPI w, GCRY_MPI u, GCRY_MPI v, GCRY_MPI m);

void     gcry_mpi_powm( GCRY_MPI w,
                        const GCRY_MPI b, const GCRY_MPI e, const GCRY_MPI m );
int      gcry_mpi_gcd( GCRY_MPI g, GCRY_MPI a, GCRY_MPI b );

unsigned int gcry_mpi_get_nbits( GCRY_MPI a );

/* Please note that keygrip is still experimental and should not be
   used without contacting the author */
unsigned char *gcry_pk_get_keygrip (GCRY_SEXP key, unsigned char *array);

int      gcry_mpi_test_bit( GCRY_MPI a, unsigned int n );
void     gcry_mpi_set_bit( GCRY_MPI a, unsigned int n );
void     gcry_mpi_clear_bit( GCRY_MPI a, unsigned int n );
void     gcry_mpi_set_highbit( GCRY_MPI a, unsigned int n );
void     gcry_mpi_clear_highbit( GCRY_MPI a, unsigned int n );
void     gcry_mpi_rshift( GCRY_MPI x, GCRY_MPI a, unsigned int n );

GCRY_MPI gcry_mpi_set_opaque( GCRY_MPI a, void *p, unsigned int nbits );
void *   gcry_mpi_get_opaque( GCRY_MPI a, unsigned int *nbits );
void     gcry_mpi_set_flag( GCRY_MPI a, enum gcry_mpi_flag flag );
void     gcry_mpi_clear_flag( GCRY_MPI a, enum gcry_mpi_flag flag );
int      gcry_mpi_get_flag( GCRY_MPI a, enum gcry_mpi_flag flag );


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
#define mpi_powm(w,b,e,m)   gcry_mpi_powm( (w), (b), (e), (m) )
#define mpi_gcd(g,a,b)      gcry_mpi_gcd( (g), (a), (b) )

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

/********************************************
 *******  symmetric cipher functions  *******
 ********************************************/

struct gcry_cipher_handle;
typedef struct gcry_cipher_handle *GCRY_CIPHER_HD;

enum gcry_cipher_algos {
    GCRY_CIPHER_NONE	    = 0,
    GCRY_CIPHER_IDEA	    = 1,
    GCRY_CIPHER_3DES	    = 2,
    GCRY_CIPHER_CAST5	    = 3,
    GCRY_CIPHER_BLOWFISH    = 4,
    GCRY_CIPHER_SAFER_SK128 = 5,
    GCRY_CIPHER_DES_SK	    = 6,
    GCRY_CIPHER_RIJNDAEL    = 7,
    GCRY_CIPHER_RIJNDAEL192 = 8,
    GCRY_CIPHER_RIJNDAEL256 = 9,
    GCRY_CIPHER_TWOFISH     = 10,
    /* other cipher numbers are above 300 for OpenPGP reasons. */
    GCRY_CIPHER_ARCFOUR     = 301
};

#define GCRY_CIPHER_AES    GCRY_CIPHER_RIJNDAEL
#define GCRY_CIPHER_AES128 GCRY_CIPHER_RIJNDAEL
#define GCRY_CIPHER_AES192 GCRY_CIPHER_RIJNDAEL192
#define GCRY_CIPHER_AES256 GCRY_CIPHER_RIJNDAEL256

enum gcry_cipher_modes {
    GCRY_CIPHER_MODE_NONE   = 0,
    GCRY_CIPHER_MODE_ECB    = 1,
    GCRY_CIPHER_MODE_CFB    = 2,
    GCRY_CIPHER_MODE_CBC    = 3,
    GCRY_CIPHER_MODE_STREAM = 4, /* native stream mode of some the algorithms */
    GCRY_CIPHER_MODE_OFB    = 5
};

enum gcry_cipher_flags {
    GCRY_CIPHER_SECURE	    = 1,  /* allocate in secure memory */
    GCRY_CIPHER_ENABLE_SYNC = 2   /* enable CFB sync mode */
};


GCRY_CIPHER_HD gcry_cipher_open( int algo, int mode, unsigned flags);
void gcry_cipher_close( GCRY_CIPHER_HD h );
int  gcry_cipher_ctl( GCRY_CIPHER_HD h, int cmd, void *buffer, size_t buflen);
int gcry_cipher_info( GCRY_CIPHER_HD h, int what, void *buffer, size_t *nbytes);
int gcry_cipher_algo_info( int algo, int what, void *buffer, size_t *nbytes);
const char *gcry_cipher_algo_name( int algo );
int gcry_cipher_map_name( const char* name );
int gcry_cipher_mode_from_oid (const char *string);

int gcry_cipher_encrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				      const byte *in, size_t inlen );
int gcry_cipher_decrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
				      const byte *in, size_t inlen );


/* some handy macros */
/* We have to cast a way a const char* here - this catch-all ctl function
 * was probably not the best choice */
#define gcry_cipher_setkey(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_KEY, \
							 (char*)(k), (l) )
#define gcry_cipher_setiv(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_IV, \
							 (char*)(k), (l) )
#define gcry_cipher_sync(h)  gcry_cipher_ctl( (h), GCRYCTL_CFB_SYNC, \
								   NULL, 0 )

#define gcry_cipher_get_algo_keylen(a) \
	    gcry_cipher_algo_info( (a), GCRYCTL_GET_KEYLEN, NULL, NULL )
#define gcry_cipher_get_algo_blklen(a) \
	    gcry_cipher_algo_info( (a), GCRYCTL_GET_BLKLEN, NULL, NULL )
#define gcry_cipher_test_algo(a) \
	    gcry_cipher_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )


/*********************************************
 *******  asymmetric cipher functions  *******
 *********************************************/

enum gcry_pk_algos {
    GCRY_PK_RSA = 1,
    GCRY_PK_RSA_E = 2,	    /* use only for OpenPGP */
    GCRY_PK_RSA_S = 3,	    /* use only for OpenPGP */
    GCRY_PK_ELG_E = 16,     /* use only for OpenPGP */
    GCRY_PK_DSA   = 17,
    GCRY_PK_ELG   = 20
};

/* Flags describing usage capabilites/request of a PK algorithm */
#define GCRY_PK_USAGE_SIGN 1
#define GCRY_PK_USAGE_ENCR 2

int gcry_pk_encrypt( GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP pkey );
int gcry_pk_decrypt( GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP skey );
int gcry_pk_sign(    GCRY_SEXP *result, GCRY_SEXP data, GCRY_SEXP skey );
int gcry_pk_verify(  GCRY_SEXP sigval, GCRY_SEXP data, GCRY_SEXP pkey );
int gcry_pk_testkey( GCRY_SEXP key );
int gcry_pk_genkey(  GCRY_SEXP *r_key, GCRY_SEXP s_parms );

int gcry_pk_ctl( int cmd, void *buffer, size_t buflen);
int gcry_pk_algo_info( int algo, int what, void *buffer, size_t *nbytes);
const char *gcry_pk_algo_name( int algo );
int gcry_pk_map_name( const char* name );
unsigned int gcry_pk_get_nbits( GCRY_SEXP key );


#define gcry_pk_test_algo(a) \
	    gcry_pk_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )

/*********************************************
 *******  cryptograhic hash functions  *******
 *********************************************/

enum gcry_md_algos {
    GCRY_MD_NONE    = 0,
    GCRY_MD_MD5     = 1,
    GCRY_MD_SHA1    = 2,
    GCRY_MD_RMD160  = 3,
    GCRY_MD_TIGER   = 6
};

enum gcry_md_flags {
    GCRY_MD_FLAG_SECURE = 1,
    GCRY_MD_FLAG_HMAC	= 2
};


struct gcry_md_context;
struct gcry_md_handle {
    struct gcry_md_context *ctx;
    int  bufpos;
    int  bufsize;
    byte buf[1];
};
typedef struct gcry_md_handle *GCRY_MD_HD;


GCRY_MD_HD gcry_md_open( int algo, unsigned flags );
void gcry_md_close( GCRY_MD_HD hd );
int gcry_md_enable( GCRY_MD_HD hd, int algo );
GCRY_MD_HD gcry_md_copy( GCRY_MD_HD hd );
void gcry_md_reset( GCRY_MD_HD hd );
int gcry_md_ctl( GCRY_MD_HD hd, int cmd, byte *buffer, size_t buflen);
void gcry_md_write( GCRY_MD_HD hd, const byte *buffer, size_t length);
byte *gcry_md_read( GCRY_MD_HD hd, int algo );
void gcry_md_hash_buffer( int algo, char *digest,
			  const char *buffer, size_t length);
int gcry_md_get_algo( GCRY_MD_HD hd );
unsigned int gcry_md_get_algo_dlen( int algo );
/*??int gcry_md_get( GCRY_MD_HD hd, int algo, byte *buffer, int buflen );*/
int gcry_md_info( GCRY_MD_HD h, int what, void *buffer, size_t *nbytes);
int gcry_md_algo_info( int algo, int what, void *buffer, size_t *nbytes);
const char *gcry_md_algo_name( int algo );
int gcry_md_map_name( const char* name );
int gcry_md_setkey( GCRY_MD_HD hd, const char *key, size_t keylen );

#define gcry_md_putc(h,c)  \
	    do {					\
		if( (h)->bufpos == (h)->bufsize )	\
		    gcry_md_write( (h), NULL, 0 );	\
		(h)->buf[(h)->bufpos++] = (c) & 0xff;	\
	    } while(0)

#define gcry_md_final(a) \
	    gcry_md_ctl( (a), GCRYCTL_FINALIZE, NULL, 0 )

#define gcry_md_is_secure(a) \
	    gcry_md_info( (a), GCRYCTL_IS_SECURE, NULL, NULL )

#define gcry_md_test_algo(a) \
	    gcry_md_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )

#define gcry_md_start_debug(a,b) \
	    gcry_md_ctl( (a), GCRYCTL_START_DUMP, (b), 0 )
#define gcry_md_stop_debug(a,b) \
	    gcry_md_ctl( (a), GCRYCTL_STOP_DUMP, (b), 0 )


/*********************************************
 *******  random generating functions  *******
 *********************************************/
void gcry_randomize( byte *buffer, size_t length,
		     enum gcry_random_level level );
void *gcry_random_bytes( size_t nbytes, enum gcry_random_level level );
void *gcry_random_bytes_secure( size_t nbytes, enum gcry_random_level level );

/*****************************************
 *******  miscellaneous stuff	**********
 *****************************************/

enum gcry_log_levels {
    GCRY_LOG_CONT   = 0,    /* continue the last log line */
    GCRY_LOG_INFO   = 10,
    GCRY_LOG_WARN   = 20,
    GCRY_LOG_ERROR  = 30,
    GCRY_LOG_FATAL  = 40,
    GCRY_LOG_BUG    = 50,
    GCRY_LOG_DEBUG  = 100
};


/* Provide custom functions for special tasks of libgcrypt.
 */
void gcry_set_allocation_handler( void *(*new_alloc_func)(size_t n),
				  void *(*new_alloc_secure_func)(size_t n),
				  int (*new_is_secure_func)(const void*),
				  void *(*new_realloc_func)(void *p, size_t n),
				  void (*new_free_func)(void*) );
void gcry_set_outofcore_handler( int (*h)( void*, size_t, unsigned int ),
								void *opaque );
void gcry_set_fatalerror_handler( void (*fnc)(void*,int, const char*),
								void *opaque );
void gcry_set_gettext_handler( const char *(*f)(const char*) );
void gcry_set_log_handler( void (*f)(void*,int, const char*, va_list ),
							     void *opaque );


/* Access to the memory function of libgcrypt.
 * Especially the gcry_free() should be used for memory
 * allocated by gcry_ functions.
 */
void *gcry_malloc( size_t n );
void *gcry_calloc( size_t n, size_t m );
void *gcry_malloc_secure( size_t n );
void *gcry_calloc_secure( size_t n, size_t m );
void *gcry_realloc( void *a, size_t n );
void *gcry_xmalloc( size_t n );
void *gcry_xcalloc( size_t n, size_t m );
void *gcry_xmalloc_secure( size_t n );
void *gcry_xcalloc_secure( size_t n, size_t m );
void *gcry_xrealloc( void *a, size_t n );
char *gcry_xstrdup( const char * a);
void  gcry_free( void *a );
int   gcry_is_secure( const void *a );


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
