/* gcrypt.h -  GNU digital encryption library interface
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
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
#ifdef __cplusplus
extern "C" {
#endif


#ifndef HAVE_BYTE_TYPEDEF
  #undef byte	    /* maybe there is a macro with this name */
  typedef unsigned char byte;
  #define HAVE_BYTE_TYPEDEF
#endif

/*******************************************
 *					   *
 *  error handling etc. 		   *
 *					   *
 *******************************************/

enum {
    GCRYERR_SUCCESS = 0,    /* "no error" */
    GCRYERR_GENERAL = 1,    /* catch all the other errors code */
    GCRYERR_INV_OP = 2,     /* invalid operation code or ctl command */
    GCRYERR_NOMEM = 3,	    /* out of core */
    GCRYERR_INV_ALGO = 4,   /* invalid algorithm */
    GCRYERR_INV_ARG = 5,    /* invalid argument */
    GCRYERR_INTERNAL = 6,   /* internal error */
    GCRYERR_EOF = 7,	    /* (-1) is remapped to this value */
    GCRYERR_TOO_SHORT = 8,  /* provided buffer too short */
    GCRYERR_TOO_LARGE = 9,  /* object is too large */
    GCRYERR_INV_OBJ = 10,   /* an object is not valid */
};


int gcry_errno(void);
const char *gcry_strerror( int ec );

enum gcry_ctl_cmds {
    GCRYCTL_SET_KEY  = 1,
    GCRYCTL_SET_IV   = 2,
    GCRYCTL_CFB_SYNC = 3,
    GCRYCTL_RESET    = 4,   /* e.g. for MDs */
    GCRYCTL_FINALIZE = 5,
};

int gcry_control( enum gcry_ctl_cmds, ... );

enum gcry_random_level {
    GCRY_WEAK_RANDOM = 0,
    GCRY_STRONG_RANDOM = 1,
    GCRY_VERY_STRONG_RANDOM = 2
};

/*******************************************
 *					   *
 *  multi precision integer functions	   *
 *					   *
 *******************************************/

enum gcry_mpi_format {
    GCRYMPI_FMT_STD = 0,    /* As used by OpenPGP */
    GCRYMPI_FMT_SSH = 1,    /* As used by SSH */
    GCRYMPI_FMT_HEX = 2,    /* hex format */
};

struct gcry_mpi;
typedef struct gcry_mpi *GCRY_MPI;

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

void gcry_mpi_powm( GCRY_MPI w,
		    const GCRY_MPI b, const GCRY_MPI e, const GCRY_MPI m );


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

#define mpi_powm(w,b,e,m)   gcry_mpi_powm( (w), (b), (e), (m) )

#if 0
#define mpi_swap( a, b )    gcry_mpi_api( (a), (b) )
void g10m_add(MPI w, MPI u, MPI v);
void g10m_add_ui(MPI w, MPI u, unsigned long v );
void g10m_sub( MPI w, MPI u, MPI v);
void g10m_sub_ui(MPI w, MPI u, unsigned long v );

void g10m_mul_ui(MPI w, MPI u, unsigned long v );
void g10m_mul_2exp( MPI w, MPI u, unsigned long cnt);
void g10m_mul( MPI w, MPI u, MPI v);
void g10m_mulm( MPI w, MPI u, MPI v, MPI m);

void g10m_fdiv_q( MPI quot, MPI dividend, MPI divisor );

int  g10m_gcd( MPI g, MPI a, MPI b );
int  g10m_invm( MPI x, MPI u, MPI v );

unsigned g10m_get_nbits( MPI a );
unsigned g10m_get_size( MPI a );

void g10m_set_buffer( MPI a, const char *buffer, unsigned nbytes, int sign );
#endif

#endif /* GCRYPT_NO_MPI_MACROS */

/********************************************
 *******  symmetric cipher functions  *******
 ********************************************/

struct gcry_cipher_context;
typedef struct gcry_cipher_context *GCRY_CIPHER_HD;

enum gcry_cipher_algos {
    GCRY_CIPHER_NONE	    = 0,
    GCRY_CIPHER_IDEA	    = 1,
    GCRY_CIPHER_3DES	    = 2,
    GCRY_CIPHER_CAST5	    = 3,
    GCRY_CIPHER_BLOWFISH    = 4,
    GCRY_CIPHER_SAFER_SK128 = 5,
    GCRY_CIPHER_DES_SK	    = 6
};

enum gcry_cipher_modes {
    GCRY_CIPHER_MODE_NONE   = 0,
    GCRY_CIPHER_MODE_ECB    = 1,
    GCRY_CIPHER_MODE_CFB    = 2,
};

enum gcry_cipher_flags {
    GCRY_CIPHER_SECURE	    = 1,  /* allocate in secure memory */
    GCRY_CIPHER_ENABLE_SYNC = 2,  /* enable CFB sync mode */
};


#if 0 /* not yet done */
int gcry_string_to_cipher_algo( const char *string );
const char * gcry_cipher_algo_to_string( int algo );
int gcry_check_cipher_algo( int algo );
unsigned gcry_cipher_get_keylen( int algo );
unsigned gcry_cipher_get_blocksize( int algo );
#endif

GCRY_CIPHER_HD gcry_cipher_open( int algo, int mode, unsigned flags );
void gcry_cipher_close( GCRY_CIPHER_HD h );
int  gcry_cipher_ctl( GCRY_CIPHER_HD h, int cmd, byte *buffer, size_t buflen);

int gcry_cipher_encrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
					    byte *in, size_t inlen );
int gcry_cipher_decrypt( GCRY_CIPHER_HD h, byte *out, size_t outsize,
					    byte *in, size_t inlen );


/* some handy macros */
#define gcry_cipher_setkey(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_KEY, \
								  (k), (l) )
#define gcry_cipher_setiv(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_IV, \
								  (k), (l) )
#define gcry_cipher_sync(h)  gcry_cipher_ctl( (h), GCRYCTL_CFB_SYNC, \
								   NULL, 0 )


/*********************************************
 *******  asymmetric cipher functions  *******
 *********************************************/




/*********************************************
 *******  cryptograhic hash functions  *******
 *********************************************/

struct gcry_md_context;
typedef struct gcry_md_context *GCRY_MD_HD;

enum gcry_md_algos {
    GCRY_MD_NONE    = 0,
    GCRY_MD_MD5     = 1,
    GCRY_MD_SHA1    = 2,
    GCRY_MD_RMD160  = 3,
    GCRY_MD_TIGER   = 6
};

enum gcry_md_flags {
    GCRY_MD_FLAG_SECURE = 1
};


GCRY_MD_HD gcry_md_open( int algo, unsigned flags );
void gcry_md_close( GCRY_MD_HD hd );
void gcry_md_enable( GCRY_MD_HD hd, int algo );
GCRY_MD_HD gcry_md_copy( GCRY_MD_HD hd );
int gcry_md_ctl( GCRY_MD_HD hd, int cmd, byte *buffer, size_t buflen);
void gcry_md_write( GCRY_MD_HD hd, byte *inbuf, size_t inlen);
byte *gcry_md_read( GCRY_MD_HD hd, int algo );
int gcry_md_get( GCRY_MD_HD hd, int algo, byte *buffer, int buflen );


#define gcry_md_final( a )  gcry_md_ctl( (a), GCRYCTL_FINALIZE, NULL, 0 )


/*****************************************
 *******  miscellaneous functions  *******
 *****************************************/

#if 0
const char *g10m_revision_string(int mode);
const char *g10c_revision_string(int mode);
const char *g10u_revision_string(int mode);

MPI   g10c_generate_secret_prime( unsigned nbits );
char *g10c_get_random_bits( unsigned nbits, int level, int secure );


void *g10_malloc( size_t n );
void *g10_calloc( size_t n );
void *g10_malloc_secure( size_t n );
void *g10_calloc_secure( size_t n );
void *g10_realloc( void *a, size_t n );
void  g10_free( void *p );
char *g10_strdup( const char * a);

void g10_log_bug( const char *fmt, ... );
void g10_log_bug0( const char *, int );
void g10_log_fatal( const char *fmt, ... );
void g10_log_error( const char *fmt, ... );
void g10_log_info( const char *fmt, ... );
void g10_log_debug( const char *fmt, ... );
void g10_log_hexdump( const char *text, char *buf, size_t len );
void g10_log_mpidump( const char *text, MPI a );
#endif

/***************************
 *******  constants  *******
 **************************/
#if 0
#define CIPHER_ALGO_NONE	 0
#define CIPHER_ALGO_IDEA	 1
#define CIPHER_ALGO_3DES	 2
#define CIPHER_ALGO_CAST5	 3
#define CIPHER_ALGO_BLOWFISH	 4  /* blowfish 128 bit key */
#define CIPHER_ALGO_SAFER_SK128  5
#define CIPHER_ALGO_DES_SK	 6
#define CIPHER_ALGO_DUMMY      110  /* no encryption at all */

#define PUBKEY_ALGO_RSA        1
#define PUBKEY_ALGO_RSA_E      2     /* RSA encrypt only */
#define PUBKEY_ALGO_RSA_S      3     /* RSA sign only */
#define PUBKEY_ALGO_ELGAMAL_E 16     /* encrypt only ElGamal (but not for v3)*/
#define PUBKEY_ALGO_DSA       17
#define PUBKEY_ALGO_ELGAMAL   20     /* sign and encrypt elgamal */

#define DIGEST_ALGO_MD5       1
#define DIGEST_ALGO_SHA1      2
#define DIGEST_ALGO_RMD160    3
#define DIGEST_ALGO_TIGER     6

#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
		       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL || (a)==PUBKEY_ALGO_ELGAMAL_E)

#define G10ERR_GENERAL	       1
#define G10ERR_PUBKEY_ALGO     4
#define G10ERR_DIGEST_ALGO     5
#define G10ERR_BAD_PUBKEY      6
#define G10ERR_BAD_SECKEY      7
#define G10ERR_BAD_SIGN        8
#define G10ERR_CIPHER_ALGO    12
#define G10ERR_WRONG_SECKEY   18
#define G10ERR_UNSUPPORTED    19
#define G10ERR_NI_PUBKEY      27
#define G10ERR_NI_CIPHER      28
#define G10ERR_BAD_MPI	      30
#define G10ERR_WR_PUBKEY_ALGO 41
#endif

/***********************************************
 *					       *
 *   Some very handy macros		       *
 *					       *
 ***********************************************/
#ifndef GCRYPT_NO_MPI_MACROS

typedef struct gcry_mpi *MPI;


#endif /* GCRYPT_NO_MPI_MACROS */

#ifdef __cplusplus
}
#endif
#endif /* _GCRYPT_H */
