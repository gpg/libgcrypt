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

#define GPG_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_GCRYPT

/* Support for libgpg-error.  */
#ifdef USE_LIBGPG_ERROR
#include <gpg-error.h>
#else

/* Only use free slots, never change or reorder the existing
   entries.  */
typedef enum
  {
    GPG_ERR_SOURCE_GCRYPT = 1,

    /* This is one more than the largest allowed entry.  */
    GPG_ERR_SOURCE_DIM = 256
  } gpg_err_source_t;


/* The error code type gpg_err_code_t.  */

/* Only use free slots, never change or reorder the existing
   entries.  */
typedef enum
  {
    GPG_ERR_NO_ERROR = 0,		/* An error that is not an error.  */
    GPG_ERR_GENERAL = 1,
    GPG_ERR_UNKNOWN_PACKET = 2,
    GPG_ERR_UNKNOWN_VERSION = 3,	/* Unknown version (in packet).  */
    GPG_ERR_PUBKEY_ALGO	= 4,		/* Invalid public key algorithm.  */
    GPG_ERR_DIGEST_ALGO = 5,		/* Invalid digest algorithm.  */
    GPG_ERR_BAD_PUBKEY = 6,		/* Bad public key.  */
    GPG_ERR_BAD_SECKEY = 7,		/* Bad secret key.  */
    GPG_ERR_BAD_SIGNATURE = 8,		/* Bad signature.  */
    GPG_ERR_NO_PUBKEY = 9,		/* Public key not found.  */
    GPG_ERR_CHECKSUM = 10,		/* Checksum error.  */
    GPG_ERR_BAD_PASSPHRASE = 11,	/* Bad passphrase.  */
    GPG_ERR_CIPHER_ALGO = 12,		/* Invalid cipher algorithm.  */
    GPG_ERR_KEYRING_OPEN = 13,
    GPG_ERR_INV_PACKET = 14,
    GPG_ERR_INV_ARMOR = 15,
    GPG_ERR_NO_USER_ID = 16,
    GPG_ERR_NO_SECKEY = 17,		/* Secret key not available.  */
    GPG_ERR_WRONG_SECKEY = 18,		/* Wrong secret key used.  */
    GPG_ERR_BAD_KEY = 19,		/* Bad (session) key.  */
    GPG_ERR_COMPR_ALGO = 20,		/* Unknown compress algorithm.  */

    /* Codes 21 to 29 are free to be used.  */

    GPG_ERR_BAD_MPI = 30,		/* Problem with an MPI's value.  */
    GPG_ERR_INV_PASSPHRASE = 31,	/* Invalid passphrase.  */
    GPG_ERR_SIG_CLASS = 32,
    GPG_ERR_RESOURCE_LIMIT = 33,
    GPG_ERR_INV_KEYRING = 34,
    GPG_ERR_TRUSTDB = 35,		/* A problem with the trustdb.  */
    GPG_ERR_BAD_CERT = 36,		/* Bad certificate.  */
    GPG_ERR_INV_USER_ID = 37,
    GPG_ERR_UNEXPECTED = 38,
    GPG_ERR_TIME_CONFLICT = 39,
    GPG_ERR_KEYSERVER = 40,
    GPG_ERR_WRONG_PUBKEY_ALGO = 41,	/* Wrong public key algorithm.  */
    GPG_ERR_TRIBUTE_TO_D_A = 42,
    GPG_ERR_WEAK_KEY = 43,		/* Weak encryption key.  */
    GPG_ERR_INV_KEYLEN = 44,		/* Invalid length of a key.  */
    GPG_ERR_INV_ARG = 45,		/* Invalid argument.  */
    GPG_ERR_BAD_URI = 46,		/* Syntax error in URI.  */
    GPG_ERR_INV_URI = 47,		/* Unsupported scheme and similar.  */
    GPG_ERR_NETWORK = 48,		/* General network error.  */
    GPG_ERR_UNKNOWN_HOST = 49,
    GPG_ERR_SELFTEST_FAILED = 50,
    GPG_ERR_NOT_ENCRYPTED = 51,
    GPG_ERR_NOT_PROCESSED = 52,
    GPG_ERR_UNUSABLE_PUBKEY = 53,
    GPG_ERR_UNUSABLE_SECKEY = 54,
    GPG_ERR_INV_VALUE = 55,
    GPG_ERR_BAD_CERT_CHAIN = 56,
    GPG_ERR_MISSING_CERT = 57,
    GPG_ERR_NO_DATA = 58,
    GPG_ERR_BUG = 59,
    GPG_ERR_NOT_SUPPORTED = 60,
    GPG_ERR_INV_OP = 61,		/* Invalid operation code.  */
    GPG_ERR_TIMEOUT = 62,               /* Something timed out. */
    GPG_ERR_INTERNAL = 63,		/* Internal error.  */
    GPG_ERR_EOF_GCRYPT = 64,		/* Compatibility for gcrypt.  */
    GPG_ERR_INV_OBJ = 65,		/* An object is not valid.  */
    GPG_ERR_TOO_SHORT = 66,		/* Provided object is too short.  */
    GPG_ERR_TOO_LARGE = 67,		/* Provided object is too large.  */
    GPG_ERR_NO_OBJ = 68,		/* Missing item in an object.  */
    GPG_ERR_NOT_IMPLEMENTED = 69,	/* Not implemented.  */
    GPG_ERR_CONFLICT = 70,		/* Conflicting use.  */
    GPG_ERR_INV_CIPHER_MODE = 71,	/* Invalid cipher mode.  */ 
    GPG_ERR_INV_FLAG = 72,		/* Invalid flag.  */
    GPG_ERR_INV_HANDLE = 73,            /* Invalid handle.  */

    /* Code 74 is free to be used.  */

    GPG_ERR_INCOMPLETE_LINE = 75,
    GPG_ERR_INV_RESPONSE = 76,
    GPG_ERR_NO_AGENT = 77,
    GPG_ERR_AGENT = 78,
    GPG_ERR_INV_DATA = 79,
    GPG_ERR_ASSUAN_SERVER_FAULT = 80,
    GPG_ERR_ASSUAN = 81,		/* Catch all assuan error.  */
    GPG_ERR_INV_SESSION_KEY = 82,
    GPG_ERR_INV_SEXP = 83,
    GPG_ERR_UNSUPPORTED_ALGORITHM = 84,
    GPG_ERR_NO_PIN_ENTRY = 85,
    GPG_ERR_PIN_ENTRY = 86,
    GPG_ERR_BAD_PIN = 87,
    GPG_ERR_INV_NAME = 88,
    GPG_ERR_BAD_DATA = 89,
    GPG_ERR_INV_PARAMETER = 90,

    /* Code 91 is free to be used.  */

    GPG_ERR_NO_DIRMNGR = 92,
    GPG_ERR_DIRMNGR = 93,
    GPG_ERR_CERT_REVOKED = 94,
    GPG_ERR_NO_CRL_KNOWN = 95,
    GPG_ERR_CRL_TOO_OLD = 96,
    GPG_ERR_LINE_TOO_LONG = 97,
    GPG_ERR_NOT_TRUSTED = 98,
    GPG_ERR_CANCELED = 109,
    GPG_ERR_BAD_CA_CERT = 100,
    GPG_ERR_CERT_EXPIRED = 101,		/* Key signature expired.  */
    GPG_ERR_CERT_TOO_YOUNG = 102,
    GPG_ERR_UNSUPPORTED_CERT = 103,
    GPG_ERR_UNKNOWN_SEXP = 104,
    GPG_ERR_UNSUPPORTED_PROTECTION = 105,
    GPG_ERR_CORRUPTED_PROTECTION = 106,
    GPG_ERR_AMBIGUOUS_NAME = 107,
    GPG_ERR_CARD = 108,
    GPG_ERR_CARD_RESET = 109,
    GPG_ERR_CARD_REMOVED = 110,
    GPG_ERR_INV_CARD = 111,
    GPG_ERR_CARD_NOT_PRESENT = 112,
    GPG_ERR_NO_PKCS15_APP = 113,
    GPG_ERR_NOT_CONFIRMED = 114,
    GPG_ERR_CONFIGURATION = 115,
    GPG_ERR_NO_POLICY_MATCH = 116,
    GPG_ERR_INV_INDEX = 117,
    GPG_ERR_INV_ID = 118,
    GPG_ERR_NO_SCDAEMON = 119,
    GPG_ERR_SCDAEMON = 120,
    GPG_ERR_UNSUPPORTED_PROTOCOL = 121,
    GPG_ERR_BAD_PIN_METHOD = 122,
    GPG_ERR_CARD_NOT_INITIALIZED = 123,
    GPG_ERR_UNSUPPORTED_OPERATION = 124,
    GPG_ERR_WRONG_KEY_USAGE = 125,
    GPG_ERR_NOTHING_FOUND = 126,        /* Operation failed due to an
                                           unsuccessful find operation.  */
    GPG_ERR_WRONG_BLOB_TYPE = 127,      /* Keybox BLOB of wrong type.  */
    GPG_ERR_MISSING_VALUE = 128,        /* A required value is missing.  */

    /* 129 to 149 are free to be used.  */

    GPG_ERR_INV_ENGINE = 150,
    GPG_ERR_PUBKEY_NOT_TRUSTED = 151,
    GPG_ERR_DECRYPT_FAILED = 152,
    GPG_ERR_KEY_EXPIRED = 153,
    GPG_ERR_SIG_EXPIRED = 154,		/* Data signature expired.  */

    /* 155 to 200 are free to be used.  */

    /* Error codes pertaining to S-expressions.  */
    GPG_ERR_SEXP_INV_LEN_SPEC = 201,
    GPG_ERR_SEXP_STRING_TOO_LONG = 202,
    GPG_ERR_SEXP_UNMATCHED_PAREN = 203, 
    GPG_ERR_SEXP_NOT_CANONICAL = 204, 
    GPG_ERR_SEXP_BAD_CHARACTER = 205, 
    GPG_ERR_SEXP_BAD_QUOTATION = 206,	/* Or invalid hex or octal value.  */
    GPG_ERR_SEXP_ZERO_PREFIX = 207,	/* First character of length is 0.  */
    GPG_ERR_SEXP_NESTED_DH = 208,	/* Nested display hints.  */
    GPG_ERR_SEXP_UNMATCHED_DH = 209,	/* Unmatched display hint.  */
    GPG_ERR_SEXP_UNEXPECTED_PUNC = 210,	/* Unexpected reserved punctuation. */
    GPG_ERR_SEXP_BAD_HEX_CHAR = 211,
    GPG_ERR_SEXP_ODD_HEX_NUMBERS = 212,
    GPG_ERR_SEXP_BAD_OCT_CHAR = 213,

    /* 213 to 1023 are free to be used.  */

    /* For free use by non-GnuPG components.  */
    GPG_ERR_USER_1 = 1024,
    GPG_ERR_USER_2 = 1025,
    GPG_ERR_USER_3 = 1026,
    GPG_ERR_USER_4 = 1027,
    GPG_ERR_USER_5 = 1028,
    GPG_ERR_USER_6 = 1029,
    GPG_ERR_USER_7 = 1030,
    GPG_ERR_USER_8 = 1031,
    GPG_ERR_USER_9 = 1032,
    GPG_ERR_USER_10 = 1033,
    GPG_ERR_USER_11 = 1034,
    GPG_ERR_USER_12 = 1035,
    GPG_ERR_USER_13 = 1036,
    GPG_ERR_USER_14 = 1037,
    GPG_ERR_USER_15 = 1038,
    GPG_ERR_USER_16 = 1039,

    /* 1040 to 16381 are free to be used.  */

    GPG_ERR_UNKNOWN_ERRNO = 16382,
    GPG_ERR_EOF = 16383,		/* This was once a -1.  Pity.  */

    /* The following error codes are used to map system errors.  */
    GPG_ERR_E2BIG = 16384,
    GPG_ERR_EACCES = 16385,
    GPG_ERR_EADDRINUSE = 16386,
    GPG_ERR_EADDRNOTAVAIL = 16387,
    GPG_ERR_EADV = 16388,
    GPG_ERR_EAFNOSUPPORT = 16389,
    GPG_ERR_EAGAIN = 16390,
    GPG_ERR_EALREADY = 16391,
    GPG_ERR_EAUTH = 16392,
    GPG_ERR_EBACKGROUND = 16393,
    GPG_ERR_EBADE = 16394,
    GPG_ERR_EBADF = 16395,
    GPG_ERR_EBADFD = 16396,
    GPG_ERR_EBADMSG = 16397,
    GPG_ERR_EBADR = 16398,
    GPG_ERR_EBADRPC = 16399,
    GPG_ERR_EBADRQC = 16400,
    GPG_ERR_EBADSLT = 16401,
    GPG_ERR_EBFONT = 16402,
    GPG_ERR_EBUSY = 16403,
    GPG_ERR_ECANCELED = 16404,
    GPG_ERR_ECHILD = 16405,
    GPG_ERR_ECHRNG = 16406,
    GPG_ERR_ECOMM = 16407,
    GPG_ERR_ECONNABORTED = 16408,
    GPG_ERR_ECONNREFUSED = 16409,
    GPG_ERR_ECONNRESET = 16410,
    GPG_ERR_ED = 16411,
    GPG_ERR_EDEADLK = 16412,
    GPG_ERR_EDEADLOCK = 16413,
    GPG_ERR_EDESTADDRREQ = 16414,
    GPG_ERR_EDIED = 16415,
    GPG_ERR_EDOM = 16416,
    GPG_ERR_EDOTDOT = 16417,
    GPG_ERR_EDQUOT = 16418,
    GPG_ERR_EEXIST = 16419,
    GPG_ERR_EFAULT = 16420,
    GPG_ERR_EFBIG = 16421,
    GPG_ERR_EFTYPE = 16422,
    GPG_ERR_EGRATUITOUS = 16423,
    GPG_ERR_EGREGIOUS = 16424,
    GPG_ERR_EHOSTDOWN = 16425,
    GPG_ERR_EHOSTUNREACH = 16426,
    GPG_ERR_EIDRM = 16427,
    GPG_ERR_EIEIO = 16428,
    GPG_ERR_EILSEQ = 16429,
    GPG_ERR_EINPROGRESS = 16430,
    GPG_ERR_EINTR = 16431,
    GPG_ERR_EINVAL = 16432,
    GPG_ERR_EIO = 16433,
    GPG_ERR_EISCONN = 16434,
    GPG_ERR_EISDIR = 16435,
    GPG_ERR_EISNAM = 16436,
    GPG_ERR_EL2HLT = 16437,
    GPG_ERR_EL2NSYNC = 16438,
    GPG_ERR_EL3HLT = 16439,
    GPG_ERR_EL3RST = 16440,
    GPG_ERR_ELIBACC = 16441,
    GPG_ERR_ELIBBAD = 16442,
    GPG_ERR_ELIBEXEC = 16443,
    GPG_ERR_ELIBMAX = 16444,
    GPG_ERR_ELIBSCN = 16445,
    GPG_ERR_ELNRNG = 16446,
    GPG_ERR_ELOOP = 16447,
    GPG_ERR_EMEDIUMTYPE = 16448,
    GPG_ERR_EMFILE = 16449,
    GPG_ERR_EMLINK = 16450,
    GPG_ERR_EMSGSIZE = 16451,
    GPG_ERR_EMULTIHOP = 16452,
    GPG_ERR_ENAMETOOLONG = 16453,
    GPG_ERR_ENAVAIL = 16454,
    GPG_ERR_ENEEDAUTH = 16455,
    GPG_ERR_ENETDOWN = 16456,
    GPG_ERR_ENETRESET = 16457,
    GPG_ERR_ENETUNREACH = 16458,
    GPG_ERR_ENFILE = 16459,
    GPG_ERR_ENOANO = 16460,
    GPG_ERR_ENOBUFS = 16461,
    GPG_ERR_ENOCSI = 16462,
    GPG_ERR_ENODATA = 16463,
    GPG_ERR_ENODEV = 16464,
    GPG_ERR_ENOENT = 16465,
    GPG_ERR_ENOEXEC = 16466,
    GPG_ERR_ENOLCK = 16467,
    GPG_ERR_ENOLINK = 16468,
    GPG_ERR_ENOMEDIUM = 16469,
    GPG_ERR_ENOMEM = 16470,
    GPG_ERR_ENOMSG = 16471,
    GPG_ERR_ENONET = 16472,
    GPG_ERR_ENOPKG = 16473,
    GPG_ERR_ENOPROTOOPT = 16474,
    GPG_ERR_ENOSPC = 16475,
    GPG_ERR_ENOSR = 16476,
    GPG_ERR_ENOSTR = 16477,
    GPG_ERR_ENOSYS = 16478,
    GPG_ERR_ENOTBLK = 16479,
    GPG_ERR_ENOTCONN = 16480,
    GPG_ERR_ENOTDIR = 16481,
    GPG_ERR_ENOTEMPTY = 16482,
    GPG_ERR_ENOTNAM = 16483,
    GPG_ERR_ENOTSOCK = 16484,
    GPG_ERR_ENOTSUP = 16485,
    GPG_ERR_ENOTTY = 16486,
    GPG_ERR_ENOTUNIQ = 16487,
    GPG_ERR_ENXIO = 16488,
    GPG_ERR_EOPNOTSUPP = 16489,
    GPG_ERR_EOVERFLOW = 16490,
    GPG_ERR_EPERM = 16491,
    GPG_ERR_EPFNOSUPPORT = 16492,
    GPG_ERR_EPIPE = 16493,
    GPG_ERR_EPROCLIM = 16494,
    GPG_ERR_EPROCUNAVAIL = 16495,
    GPG_ERR_EPROGMISMATCH = 16496,
    GPG_ERR_EPROGUNAVAIL = 16497,
    GPG_ERR_EPROTO = 16498,
    GPG_ERR_EPROTONOSUPPORT = 16499,
    GPG_ERR_EPROTOTYPE = 16500,
    GPG_ERR_ERANGE = 16501,
    GPG_ERR_EREMCHG = 16502,
    GPG_ERR_EREMOTE = 16503,
    GPG_ERR_EREMOTEIO = 16504,
    GPG_ERR_ERESTART = 16505,
    GPG_ERR_EROFS = 16506,
    GPG_ERR_ERPCMISMATCH = 16507,
    GPG_ERR_ESHUTDOWN = 16508,
    GPG_ERR_ESOCKTNOSUPPORT = 16509,
    GPG_ERR_ESPIPE = 16510,
    GPG_ERR_ESRCH = 16511,
    GPG_ERR_ESRMNT = 16512,
    GPG_ERR_ESTALE = 16513,
    GPG_ERR_ESTRPIPE = 16514,
    GPG_ERR_ETIME = 16515,
    GPG_ERR_ETIMEDOUT = 16516,
    GPG_ERR_ETOOMANYREFS = 16517,
    GPG_ERR_ETXTBSY = 16518,
    GPG_ERR_EUCLEAN = 16519,
    GPG_ERR_EUNATCH = 16520,
    GPG_ERR_EUSERS = 16521,
    GPG_ERR_EWOULDBLOCK = 16522,
    GPG_ERR_EXDEV = 16523,
    GPG_ERR_EXFULL = 16524,

    /* 16525 to 32677 are free to be used for more system errors.  */

    /* This is one more than the largest allowed entry.  */
    GPG_ERR_CODE_DIM = 32768
  } gpg_err_code_t;


/* The error value type gpg_error_t.  */

/* We would really like to use bit-fields in a struct, but using
   structs as return values can cause binary compatibility issues, in
   particular if you want to do it effeciently (also see
   -freg-struct-return option to GCC).  */
typedef unsigned int gpg_error_t;

/* We use the lowest 16 bits of gpg_error_t for error codes.  The 17th
   bit indicates system errors.  */
#define GPG_ERR_CODE_MASK	(GPG_ERR_CODE_DIM - 1)
#define GPG_ERR_SYSTEM_ERROR	16384

/* Bits 18 to 24 are reserved.  */

/* We use the upper 8 bits of gpg_error_t for error sources.  */
#define GPG_ERR_SOURCE_MASK	(GPG_ERR_SOURCE_DIM - 1)
#define GPG_ERR_SOURCE_SHIFT	24


/* Constructor and accessor functions.  */

/* Construct an error value from an error code and source.  Within a
   subsystem, use gpg_error.  */
static __inline__ gpg_error_t
gpg_err_make (gpg_err_source_t source, gpg_err_code_t code)
{
  return code == GPG_ERR_NO_ERROR ? GPG_ERR_NO_ERROR
    : (((source & GPG_ERR_SOURCE_MASK) << GPG_ERR_SOURCE_SHIFT)
       | (code & GPG_ERR_CODE_MASK));
}


/* The user should define GPG_ERR_SOURCE_DEFAULT before including this
   file to specify a default source for gpg_error.  */
#ifndef GPG_ERR_SOURCE_DEFAULT
#define GPG_ERR_SOURCE_DEFAULT	GPG_ERR_SOURCE_UNKNOWN
#endif

static __inline__ gpg_error_t
gpg_error (gpg_err_code_t code)
{
  return gpg_err_make (GPG_ERR_SOURCE_DEFAULT, code);
}


/* Retrieve the error code from an error value.  */
static __inline__ gpg_err_code_t
gpg_err_code (gpg_error_t err)
{
  return err & GPG_ERR_CODE_MASK;
}


/* Retrieve the error source from an error value.  */
static __inline__ gpg_err_source_t
gpg_err_source (gpg_error_t err)
{
  return (err >> GPG_ERR_SOURCE_SHIFT) & GPG_ERR_SOURCE_MASK;
}


/* String functions.  */

/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  */
const char *gpg_strerror (gpg_error_t err);

/* Return a pointer to a string containing a description of the error
   source in the error value ERR.  */
const char *gpg_strsource (gpg_error_t err);


/* Mapping of system errors (errno).  */

/* Retrieve the error code for the system error ERR.  This returns
   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
   this).  */
gpg_err_code_t gpg_err_code_from_errno (int err);


/* Retrieve the system error for the error code CODE.  This returns 0
   if CODE is not a system error code.  */
int gpg_err_code_to_errno (gpg_err_code_t code);


/* Self-documenting convenience functions.  */

static __inline__ gpg_error_t
gpg_err_make_from_errno (gpg_err_source_t source, int err)
{
  return gpg_err_make (source, gpg_err_code_from_errno (err));
}


static __inline__ gpg_error_t
gpg_error_from_errno (int err)
{
  return gpg_error (gpg_err_code_from_errno (err));
}
#endif

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens's auto-indent happy */
}
#endif
#endif

/* The version of this header should match the one of the library It
   should not be used by a program because gcry_check_version() should
   return the same version.  The purpose of this macro is to let
   autoconf (using the AM_PATH_GCRYPT macro) check that this header
   matches the installed library.  Note: Do not edit the next line as
   configure may fix the string here.  */
#define GCRYPT_VERSION "1.1.13-cvs"

/* Internal: We can't use the convenience macros for the multi
   precision integer functions when building this library. */
#ifdef _GCRYPT_IN_LIBGCRYPT
#ifndef GCRYPT_NO_MPI_MACROS
#define GCRYPT_NO_MPI_MACROS 1
#endif
#endif

/* We want to use gcc attributes when possible.  Warning: Don't use
   these macros in your progranms: As indicated by the leading
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

#endif

#ifndef _GCRY_GCC_ATTR_DEPRECATED
#define _GCRY_GCC_ATTR_DEPRECATED
#endif
#ifndef _GCRY_GCC_ATTR_PURE
#define _GCRY_GCC_ATTR_PURE
#endif
#ifndef _GCRY_GCC_ATTR_MALLOC
#define _GCRY_GCC_ATTR_MALLOC
#endif

/* The data object used to hold a multi precision integer.  */
struct gcry_mpi;
typedef struct gcry_mpi *gcry_mpi_t;

typedef struct gcry_mpi *GCRY_MPI _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_mpi *GcryMPI _GCRY_GCC_ATTR_DEPRECATED;


/* The error numbers used by Libgcrypt.  */

/* These definitions provide some API compatibility.  */

#ifndef USE_LIBGPG_ERROR
/* FIXME!!!! */

#define gpg_strerror(x) gcry_strerror (x)

#endif


/* This is here for API compatibility.  */
enum
  {
    GCRYERR_SUCCESS = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_NO_ERROR & 0xFFFF),
    GCRYERR_GENERAL = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_GENERAL & 0xFFFF),
    GCRYERR_INV_PK_ALGO = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_PUBKEY_ALGO & 0xFFFF),
    GCRYERR_INV_MD_ALGO = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_DIGEST_ALGO & 0xFFFF),
    GCRYERR_BAD_PUBLIC_KEY = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_BAD_PUBKEY & 0xFFFF),
    GCRYERR_BAD_SECRET_KEY = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_BAD_SECKEY & 0xFFFF),
    GCRYERR_BAD_SIGNATURE = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_BAD_SIGNATURE & 0xFFFF),
    GCRYERR_INV_CIPHER_ALGO = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_CIPHER_ALGO & 0xFFFF),
    GCRYERR_BAD_MPI = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_BAD_MPI & 0xFFFF),
    GCRYERR_WRONG_PK_ALGO = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_WRONG_PUBKEY_ALGO & 0xFFFF),
    GCRYERR_WEAK_KEY = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_WEAK_KEY & 0xFFFF),
    GCRYERR_INV_KEYLEN = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_INV_KEYLEN & 0xFFFF),
    GCRYERR_INV_ARG = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_INV_ARG & 0xFFFF),
    GCRYERR_SELFTEST = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SELFTEST_FAILED & 0xFFFF),
    GCRYERR_INV_OP = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_INV_OP & 0xFFFF),

    GCRYERR_INTERNAL = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_INTERNAL & 0xFFFF),

    GCRYERR_INV_OBJ = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_INV_OBJ & 0xFFFF),
    GCRYERR_TOO_SHORT = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_TOO_SHORT & 0xFFFF),
    GCRYERR_TOO_LARGE = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_TOO_LARGE & 0xFFFF),
    GCRYERR_NO_OBJ = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_NO_OBJ & 0xFFFF),
    GCRYERR_NOT_IMPL = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_NOT_IMPLEMENTED & 0xFFFF),
    GCRYERR_CONFLICT = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_CONFLICT & 0xFFFF),
    GCRYERR_INV_CIPHER_MODE = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_INV_CIPHER_MODE & 0xFFFF),
    GCRYERR_INV_FLAG = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_INV_FLAG & 0xFFFF),
    GCRYERR_SEXP_INV_LEN_SPEC = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_INV_LEN_SPEC & 0xFFFF),
    GCRYERR_SEXP_STRING_TOO_LONG = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_STRING_TOO_LONG & 0xFFFF),
    GCRYERR_SEXP_UNMATCHED_PAREN = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_UNMATCHED_PAREN & 0xFFFF),
    GCRYERR_SEXP_NOT_CANONICAL = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_NOT_CANONICAL & 0xFFFF),
    GCRYERR_SEXP_BAD_CHARACTER = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_BAD_CHARACTER & 0xFFFF),
    GCRYERR_SEXP_BAD_QUOTATION = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_BAD_QUOTATION & 0xFFFF),
    GCRYERR_SEXP_ZERO_PREFIX = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_ZERO_PREFIX & 0xFFFF),
    GCRYERR_SEXP_NESTED_DH = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_NESTED_DH & 0xFFFF),
    GCRYERR_SEXP_UNMATCHED_DH = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_UNMATCHED_DH & 0xFFFF),
    GCRYERR_SEXP_UNEXPECTED_PUNC = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_UNEXPECTED_PUNC & 0xFFFF),
    GCRYERR_SEXP_BAD_HEX_CHAR = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_BAD_HEX_CHAR & 0xFFFF),
    GCRYERR_SEXP_ODD_HEX_NUMBERS = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_ODD_HEX_NUMBERS & 0xFFFF),
    GCRYERR_SEXP_BAD_OCT_CHAR = ((GPG_ERR_SOURCE_DEFAULT & 0xFF) << 24)
                          | (GPG_ERR_SEXP_BAD_OCT_CHAR & 0xFFFF),

  };

/* Check that the library fulfills the version requirement.  */
const char *gcry_check_version (const char *req_version);

/* Map an error number to a string. */
const char *gcry_strerror (gpg_error_t ec);

/* Codes for function dispatchers.  */

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
    GCRYCTL_SET_CBC_MAC = 42,
    GCRYCTL_SET_CTR = 43,
    GCRYCTL_ENABLE_QUICK_RANDOM = 44,
  };

/* Perform various operations defined by CMD. */
gpg_error_t gcry_control (enum gcry_ctl_cmds CMD, ...);



/* S-expression management. */ 

/* The object to represent an S-expression as used with the public key
   functions.  */
struct gcry_sexp;
typedef struct gcry_sexp *gcry_sexp_t;

typedef struct gcry_sexp *GCRY_SEXP _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_sexp *GcrySexp _GCRY_GCC_ATTR_DEPRECATED;

/* The possible values for the S-expression format. */
enum gcry_sexp_format
  {
    GCRYSEXP_FMT_DEFAULT   = 0,
    GCRYSEXP_FMT_CANON	   = 1,
    GCRYSEXP_FMT_BASE64    = 2,
    GCRYSEXP_FMT_ADVANCED  = 3
  };

/* Create an new S-expression object from BUFFER of size LENGTH and
   return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER
   is expected to be in canonized format.  */
gpg_error_t gcry_sexp_new (gcry_sexp_t *retsexp, const void *buffer, size_t length,
			   int autodetect);

 /* Same as gcry_sexp_new but allows to pass a FREEFNC which has the
   effect to transfer ownership of BUFFER to the created object.  */
gpg_error_t gcry_sexp_create (gcry_sexp_t *retsexp, void *buffer, size_t length,
			      int autodetect, void (*freefnc) (void *));

/* Scan BUFFER and return a new S-expression object in RETSEXP.  This
   function expects a printf like string in BUFFER.  */
gpg_error_t gcry_sexp_sscan (gcry_sexp_t *retsexp, size_t *erroff,
			     const char *buffer, size_t length);

/* Same as gcry_sexp_sscan but expects a string in FORMAT and can thus
   only be used for certain encodings.  */
gpg_error_t gcry_sexp_build (gcry_sexp_t *retsexp, size_t *erroff,
			     const char *format, ...);

/* Like gcry_sexp_build, but uses an array instead of variable
   function arguments.  */
gpg_error_t gcry_sexp_build_array (gcry_sexp_t *retsexp, size_t *erroff,
				   const char *format, void **arg_list);

/* Release the S-expression object SEXP */
void gcry_sexp_release (gcry_sexp_t sexp);

/* Calculate the length of an canonized S-expresion in BUFFER and
   check for a valid encoding. */
size_t gcry_sexp_canon_len (const unsigned char *buffer, size_t length, 
                            size_t *erroff, gpg_error_t *errcode);

/* Copies the S-expression object SEXP into BUFFER using the format
   specified in MODE.  */
size_t gcry_sexp_sprint (gcry_sexp_t sexp, int mode, char *buffer,
                         size_t maxlength);

/* Dumps the S-expression object A in a aformat suitable for debugging
   to Libgcrypt's logging stream.  */
void gcry_sexp_dump (const gcry_sexp_t a);


gcry_sexp_t gcry_sexp_cons (const gcry_sexp_t a, const gcry_sexp_t b);
gcry_sexp_t gcry_sexp_alist (const gcry_sexp_t *array);
gcry_sexp_t gcry_sexp_vlist (const gcry_sexp_t a, ...);
gcry_sexp_t gcry_sexp_append (const gcry_sexp_t a, const gcry_sexp_t n);
gcry_sexp_t gcry_sexp_prepend (const gcry_sexp_t a, const gcry_sexp_t n);

/* Scan the S-expression for a sublist with a type (the car of the
   list) matching the string TOKEN.  If TOKLEN is not 0, the token is
   assumed to be raw memory of this length.  The function returns a
   newly allocated S-expression consisting of the found sublist or
   `NULL' when not found.  */
gcry_sexp_t gcry_sexp_find_token (gcry_sexp_t list,
				const char *tok, size_t toklen);
/* Return the length of the LIST.  For a valid S-expression this
   should be at least 1.  */
int gcry_sexp_length (const gcry_sexp_t list);

/* Create and return a new S-expression from the element with index
   NUMBER in LIST.  Note that the first element has the index 0.  If
   there is no such element, `NULL' is returned.  */
gcry_sexp_t gcry_sexp_nth (const gcry_sexp_t list, int number);

/* Create and return a new S-expression from the first element in
   LIST; this called the "type" and should always exist and be a
   string. `NULL' is returned in case of a problem.  */
gcry_sexp_t gcry_sexp_car (const gcry_sexp_t list);

/* Create and return a new list form all elements except for the first
   one.  Note, that this function may return an invalid S-expression
   because it is not guaranteed, that the type exists and is a string.
   However, for parsing a complex S-expression it might be useful for
   intermediate lists.  Returns `NULL' on error.  */
gcry_sexp_t gcry_sexp_cdr (const gcry_sexp_t list);

gcry_sexp_t gcry_sexp_cadr (const gcry_sexp_t list);


/* This function is used to get data from a LIST.  A pointer to the
   actual data with index NUMBER is returned and the length of this
   data will be stored to DATALEN.  If there is no data at the given
   index or the index represents another list, `NULL' is returned.
   *Note:* The returned pointer is valid as long as LIST is not
   modified or released.  */
const char *gcry_sexp_nth_data (const gcry_sexp_t list, int number,
				size_t *datalen);

/* This function is used to get and convert data from a LIST. This
   data is assumed to be an MPI stored in the format described by
   MPIFMT and returned as a standard Libgcrypt MPI.  The caller must
   release this returned value using `gcry_mpi_release'.  If there is
   no data at the given index, the index represents a list or the
   value can't be converted to an MPI, `NULL' is returned.  */
gcry_mpi_t gcry_sexp_nth_mpi (gcry_sexp_t list, int number, int mpifmt);



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
gcry_mpi_t gcry_mpi_new (unsigned int nbits);

/* Same as gcry_mpi_new() but allocate in "secure" memory. */
gcry_mpi_t gcry_mpi_snew (unsigned int nbits);

/* Release the number A and free all associated resources. */
void gcry_mpi_release (gcry_mpi_t a);

/* Create a new number with the same value as A. */
gcry_mpi_t gcry_mpi_copy (const gcry_mpi_t a);

/* Store the big integer value U in W. */
gcry_mpi_t gcry_mpi_set (gcry_mpi_t w, const gcry_mpi_t u);

/* Store the unsigned integer value U in W. */
gcry_mpi_t gcry_mpi_set_ui (gcry_mpi_t w, unsigned long u);

/* Swap the values of A and B. */
void gcry_mpi_swap (gcry_mpi_t a, gcry_mpi_t b);

/* Compare the big integer number U and V returning 0 for equality, a
   positive value for U > V and a negative for U < V. */
int gcry_mpi_cmp (const gcry_mpi_t u, const gcry_mpi_t v);

/* Compare the big integer number U with the unsigned integer V
   returning 0 for equality, a positive value for U > V and a negative
   for U < V. */
int gcry_mpi_cmp_ui (const gcry_mpi_t u, unsigned long v);

/* Convert the external representation of an integer stored in BUFFER
   with a size of (*NBYTES) in a newly create MPI returned in RET_MPI.
   For certain formats a length is not required and may be passed as
   NULL.  After a successful operation NBYTES received the number of
   bytes actually scanned. */
gpg_error_t gcry_mpi_scan (gcry_mpi_t *ret_mpi, enum gcry_mpi_format format,
                   const char *buffer, size_t *nbytes);

/* Convert the big integer A into the external representation
   described by FORMAT and store it in the provided BUFFER which has
   the size (*NBYTES).  NBYTES receives the actual length of the
   external representation. */
gpg_error_t gcry_mpi_print (enum gcry_mpi_format format,
			    char *buffer, size_t *nbytes, const gcry_mpi_t a);

/* Convert the big integer A int the external representation desribed
   by FORMAT and store it in a newly allocated buffer which address
   will be put into BUFFER.  NBYTES receives the actual lengths of the
   external representation. */
gpg_error_t gcry_mpi_aprint (enum gcry_mpi_format format,
			     void **buffer, size_t *nbytes, const gcry_mpi_t a);

/* W = U + V.  */
void gcry_mpi_add (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);

/* W = U + V.  V is an unsigned integer. */
void gcry_mpi_add_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v);

/* W = U + V mod M. */
void gcry_mpi_addm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);

/* W = U - V. */
void gcry_mpi_sub (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);

/* W = U - V.  V is an unsigned integer. */
void gcry_mpi_sub_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v );

/* W = U - V mod M */
void gcry_mpi_subm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);

/* W = U * V. */
void gcry_mpi_mul (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);

/* W = U * V.  V is an unsigned integer. */
void gcry_mpi_mul_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v );

/* W = U * V mod M. */
void gcry_mpi_mulm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);

/* W = U * (2 ^ CNT). */
void gcry_mpi_mul_2exp (gcry_mpi_t w, gcry_mpi_t u, unsigned long cnt);

/* Q = DIVIDEND / DIVISOR, R = DIVIDEND % DIVISOR,
   Q or R may be passed as NULL.  ROUND should be negative or 0. */
void gcry_mpi_div (gcry_mpi_t q, gcry_mpi_t r,
                   gcry_mpi_t dividend, gcry_mpi_t divisor, int round);

/* R = DIVIDEND % DIVISOR */
void gcry_mpi_mod (gcry_mpi_t r, gcry_mpi_t dividend, gcry_mpi_t divisor);

/* W = B ^ E mod M. */
void gcry_mpi_powm (gcry_mpi_t w,
                    const gcry_mpi_t b, const gcry_mpi_t e, const gcry_mpi_t m);

/* Set G to the greatest common divisor of A and B.  
   Return true if the G is 1. */
int gcry_mpi_gcd (gcry_mpi_t g, gcry_mpi_t a, gcry_mpi_t b);

/* Set X to the multiplicative inverse of A mod M.
   Return true if the value exists. */
int gcry_mpi_invm (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t m);


/* Return the number of bits required to represent A. */
unsigned int gcry_mpi_get_nbits (gcry_mpi_t a);

/* Return true when bit number N (counting from 0) is set in A. */
int      gcry_mpi_test_bit (gcry_mpi_t a, unsigned int n);

/* Set bit number N in A. */
void     gcry_mpi_set_bit (gcry_mpi_t a, unsigned int n);

/* Clear bit number N in A. */
void     gcry_mpi_clear_bit (gcry_mpi_t a, unsigned int n);

/* Set bit number N in A and clear all bits greater than N. */
void     gcry_mpi_set_highbit (gcry_mpi_t a, unsigned int n);

/* Clear bit number N in A and all bits greater than N. */
void     gcry_mpi_clear_highbit (gcry_mpi_t a, unsigned int n);

/* Shift the value of A by N bits to the right and store the result in X. */
void     gcry_mpi_rshift (gcry_mpi_t x, gcry_mpi_t a, unsigned int n);

/* Store NBITS of the value P points to in A and mark A as an opaque
   value. */
gcry_mpi_t gcry_mpi_set_opaque (gcry_mpi_t a, void *p, unsigned int nbits);

/* Return a pointer to an opaque value stored in A and return its size
   in NBITS.  Note that the returned pointer is still owned by A and
   that the function should never be used for an non-opaque MPI. */
void *gcry_mpi_get_opaque (gcry_mpi_t a, unsigned int *nbits);

/* Set the FLAG for the big integer A.  Currently only the flag
   GCRYMPI_FLAG_SECURE is allowed to convert A into an big intger
   stored in "secure" memory. */
void gcry_mpi_set_flag (gcry_mpi_t a, enum gcry_mpi_flag flag);

/* Clear FLAG for the big integer A.  Note that this function is
   currently useless as no flags are allowed. */
void gcry_mpi_clear_flag (gcry_mpi_t a, enum gcry_mpi_flag flag);

/* Return true when the FLAG is set for A. */
int gcry_mpi_get_flag (gcry_mpi_t a, enum gcry_mpi_flag flag);

/* Unless the GCRYPT_NO_MPI_MACROS is used, provide a couple of
   convenience macors for the big integer functions. */
#ifndef GCRYPT_NO_MPI_MACROS
#define mpi_new(n)	    gcry_mpi_new( (n) )
#define mpi_secure_new( n ) gcry_mpi_snew( (n) )
#define mpi_release(a)      \
  do \
    { \
      gcry_mpi_release ((a)); \
      (a) = NULL; \
    } \
  while (0)

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

/* The data object used to hold a handle to an encryption object.  */
struct gcry_cipher_handle;
typedef struct gcry_cipher_handle *gcry_cipher_hd_t;

typedef struct gcry_cipher_handle *GCRY_CIPHER_HD _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_cipher_handle *GcryCipherHd _GCRY_GCC_ATTR_DEPRECATED;

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
    GCRY_CIPHER_DES         = 302,  /* Yes, this is single key 56 bit DES. */
    GCRY_CIPHER_SERPENT128  = 303,
    GCRY_CIPHER_SERPENT192  = 304,
    GCRY_CIPHER_SERPENT256  = 305,
  };

/* The Rijndael algorithm is basically AES, so provide some macros. */
#define GCRY_CIPHER_AES128      GCRY_CIPHER_AES    
#define GCRY_CIPHER_RIJNDAEL    GCRY_CIPHER_AES    
#define GCRY_CIPHER_RIJNDAEL128 GCRY_CIPHER_AES128 
#define GCRY_CIPHER_RIJNDAEL192 GCRY_CIPHER_AES192 
#define GCRY_CIPHER_RIJNDAEL256 GCRY_CIPHER_AES256 

/* The supported encryption modes.  Note that not all of them are
   supported for each algorithm. */
enum gcry_cipher_modes 
  {
    GCRY_CIPHER_MODE_NONE   = 0,  /* Not yet specified. */
    GCRY_CIPHER_MODE_ECB    = 1,  /* Electronic codebook. */
    GCRY_CIPHER_MODE_CFB    = 2,  /* Cipher feedback. */
    GCRY_CIPHER_MODE_CBC    = 3,  /* Cipher block chaining. */
    GCRY_CIPHER_MODE_STREAM = 4,  /* Used with stream ciphers. */
    GCRY_CIPHER_MODE_OFB    = 5,  /* Outer feedback. */
    GCRY_CIPHER_MODE_CTR    = 6   /* Counter. */
  };

/* Flags used with the open function. */ 
enum gcry_cipher_flags
  {
    GCRY_CIPHER_SECURE	    = 1,  /* Allocate in secure memory. */
    GCRY_CIPHER_ENABLE_SYNC = 2,  /* Enable CFB sync mode. */
    GCRY_CIPHER_CBC_CTS	    = 4,  /* Enable CBC cipher text stealing (CTS). */
    GCRY_CIPHER_CBC_MAC	    = 8   /* Enable CBC message auth. code (MAC). */
  };


/* Create a handle for algorithm ALGO to be used in MODE.  FLAGS may
   be given as an bitwise OR of the gcry_cipher_flags values. */
gpg_error_t gcry_cipher_open (gcry_cipher_hd_t *handle,
			      int algo, int mode, unsigned int flags);

/* Close the cioher handle H and release all resource. */
void gcry_cipher_close (gcry_cipher_hd_t h);

/* Perform various operations on the cipher object H. */
gpg_error_t gcry_cipher_ctl (gcry_cipher_hd_t h, int cmd, void *buffer,
			     size_t buflen);

/* Retrieve various information about the cipher object H. */
gpg_error_t gcry_cipher_info (gcry_cipher_hd_t h, int what, void *buffer,
			      size_t *nbytes);

/* Retrieve various information about the cipher algorithm ALGO. */
gpg_error_t gcry_cipher_algo_info (int algo, int what, void *buffer,
				   size_t *nbytes);

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
   and do a in-place decryption of the data provided in OUT.  */
gpg_error_t gcry_cipher_encrypt (gcry_cipher_hd_t h,
				 unsigned char *out, size_t outsize,
				 const unsigned char *in, size_t inlen);

/* The counterpart to gcry_cipher_encrypt.  */
gpg_error_t gcry_cipher_decrypt (gcry_cipher_hd_t h,
				 unsigned char *out, size_t outsize,
				 const unsigned char *in, size_t inlen);

/* Set key K of length L for the cipher handle H.  (We have to cast
   away a const char* here - this catch-all ctl function was probably
   not the best choice) */
#define gcry_cipher_setkey(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_KEY, \
							 (char*)(k), (l) )

/* Set initialization vector K of length L for the cipher handle H. */
#define gcry_cipher_setiv(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_IV, \
							 (char*)(k), (l) )

/* Reset the handle to the state after open.  */
#define gcry_cipher_reset(h)  gcry_cipher_ctl ((h), GCRYCTL_RESET, NULL, 0)

/* Perform the the OpenPGP sync operation if this is enabled for the
   cipher handle H. */
#define gcry_cipher_sync(h)  gcry_cipher_ctl( (h), GCRYCTL_CFB_SYNC, \
								   NULL, 0 )

/* Enable or disable CTS in future calls to gcry_encrypt(). CBC mode only. */
#define gcry_cipher_cts(h,on)  gcry_cipher_ctl( (h), GCRYCTL_SET_CBC_CTS, \
								   NULL, on )

/* Set counter for CTR mode.  (K,L) must denote a buffer of block size
   length, or (NULL,0) to set the CTR to the all-zero block. */
#define gcry_cipher_setctr(h,k,l)  gcry_cipher_ctl( (h), GCRYCTL_SET_CTR, \
						    (char*)(k), (l) )

/* Retrieved the key length used with algorithm A. */
#define gcry_cipher_get_algo_keylen(a, b) \
	    gcry_cipher_algo_info( (a), GCRYCTL_GET_KEYLEN, NULL, b)

/* Retrieve the block length used with algorithm A. */
#define gcry_cipher_get_algo_blklen(a, b) \
	    gcry_cipher_algo_info( (a), GCRYCTL_GET_BLKLEN, NULL, b)

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
gpg_error_t gcry_pk_encrypt (gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t pkey);

/* Decrypt the DATA using the private key SKEY and store the result as
   a newly created S-expression at RESULT. */
gpg_error_t gcry_pk_decrypt (gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t skey);

/* Sign the DATA using the private key SKEY and store the result as
   a newly created S-expression at RESULT. */
gpg_error_t gcry_pk_sign (gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t skey);

/* Check the signature SIGVAL on DATA using the public key PKEY. */
gpg_error_t gcry_pk_verify (gcry_sexp_t sigval, gcry_sexp_t data, gcry_sexp_t pkey);

/* Check that KEY (either private or public) is sane. */
gpg_error_t gcry_pk_testkey (gcry_sexp_t key);

/* Generate a new key pair according to the parameters given in
   S_PARMS.  The new key pair is returned in as an S-expression in
   R_KEY. */
gpg_error_t gcry_pk_genkey (gcry_sexp_t *r_key, gcry_sexp_t s_parms);

/* Catch all function for miscellaneous operations. */
gpg_error_t gcry_pk_ctl (int cmd, void *buffer, size_t buflen);

/* Retrieve information about the public key algorithm ALGO. */
gpg_error_t gcry_pk_algo_info (int algo, int what, void *buffer, size_t *nbytes);

/* Map the public key algorithm id ALGO to a string representation of the
   algorithm name.  For unknown algorithms this functions returns an
   empty string. */
const char *gcry_pk_algo_name (int algo) _GCRY_GCC_ATTR_PURE;

/* Map the algorithm NAME to a public key algorithm Id.  Return 0 if
   the algorithm name is not known. */
int gcry_pk_map_name (const char* name) _GCRY_GCC_ATTR_PURE;

/* Return what is commonly referred as the key length for the given
   public or private KEY.  */
unsigned int gcry_pk_get_nbits (gcry_sexp_t key) _GCRY_GCC_ATTR_PURE;

/* Please note that keygrip is still experimental and should not be
   used without contacting the author. */
unsigned char *gcry_pk_get_keygrip (gcry_sexp_t key, unsigned char *array);

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


/* This object is used to hold a handle to an message digest object.  */
struct gcry_md_context;
struct gcry_md_handle 
  { /* This structure is private - only to be used by the gcry_md_  macros. */
    struct gcry_md_context *ctx;
    int  bufpos;
    int  bufsize;
    unsigned char buf[1];
  };
typedef struct gcry_md_handle *gcry_md_hd_t;

typedef struct gcry_md_handle *GCRY_MD_HD _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_md_handle *GcryMDHd _GCRY_GCC_ATTR_DEPRECATED;


/* Create a message digest object for algorithm ALGO.  FLAGS may be
   given as an bitwise OR of the gcry_md_flags values.  ALGO may be
   given as 0 if the algorithms to be used are later set using
   gcry_md_enable. */
gpg_error_t gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags);

/* Release the message digest object HD. */
void gcry_md_close (gcry_md_hd_t hd);

/* Add the message digest algorithm ALGO to the digest object HD. */
gpg_error_t gcry_md_enable( gcry_md_hd_t hd, int algo );

/* Create a new digest object as an exact copy of the object HD. */
gpg_error_t gcry_md_copy (gcry_md_hd_t ahd, gcry_md_hd_t *bhd);

/* Reset the digest object HD to its initial state. */
void gcry_md_reset (gcry_md_hd_t hd);

/* Perform various operations on the digets object HD. */
gpg_error_t gcry_md_ctl (gcry_md_hd_t hd, int cmd, unsigned char *buffer,
			 size_t buflen);

/* Pass LENGTH bytes of data in BUFFER to the digest object HD so that
   it can update the digest values.  This is the actual hash
   function. */
void gcry_md_write (gcry_md_hd_t hd, const void *buffer, size_t length);

/* Read out the final digest from HD return the digest value for
   algorithm ALGO. */
unsigned char *gcry_md_read (gcry_md_hd_t hd, int algo);

/* Convenience function to calculate the hash from the data in BUFFER
   of size LENGTH using the algorithm ALGO avoiding the creating of a
   hash object.  The hash is returned in the caller provided buffer
   DIGEST which must be large enough to hold the digest of the given
   algorithm. */
void gcry_md_hash_buffer (int algo, void *digest,
			  const void *buffer, size_t length);

/* Retrieve the algorithm used with HD.  This does not work reliable
   if more than one algorithm is enabled in HD. */
gpg_error_t gcry_md_get_algo (gcry_md_hd_t hd, int *algo);

/* Retrieve the length in bytes of the digest yielded by algorithm
   ALGO. */
unsigned int gcry_md_get_algo_dlen (int algo);

/* Retrieve various information about the object H.  */
gpg_error_t gcry_md_info (gcry_md_hd_t h, int what, void *buffer,
			  size_t *nbytes);

/* Retrieve various information about the algorithm ALGO.  */
gpg_error_t gcry_md_algo_info (int algo, int what, void *buffer,
			       size_t *nbytes);

/* Map the digest algorithm id ALGO to a string representation of the
   algorithm name.  For unknown algorithms this functions returns an
   empty string. */
const char *gcry_md_algo_name (int algo) _GCRY_GCC_ATTR_PURE;

/* Map the algorithm NAME to a digest algorithm Id.  Return 0 if
   the algorithm name is not known. */
int gcry_md_map_name (const char* name) _GCRY_GCC_ATTR_PURE;

/* For use with the HMAC feature, the set MAC key to the KEY of
   KEYLEN. */
gpg_error_t gcry_md_setkey (gcry_md_hd_t hd, const void *key, size_t keylen);

/* Update the hash(s) of H with the character C.  This is a buffered
   version of the gcry_md_write function. */
#define gcry_md_putc(h,c)  \
	    do {					  \
                gcry_md_hd_t h__ = (h);                       \
		if( (h__)->bufpos == (h__)->bufsize )	  \
		    gcry_md_write( (h__), NULL, 0 );	  \
		(h__)->buf[(h__)->bufpos++] = (c) & 0xff; \
	    } while(0)

/* Finalize the digest calculation.  This is not really needed because
   gcry_md_read() does this implicitly. */
#define gcry_md_final(a) \
	    gcry_md_ctl ((a), GCRYCTL_FINALIZE, NULL, 0)

/* Return true when the digest object is allocated in "secure" memory. */
#define gcry_md_is_secure(a, b) \
	    gcry_md_info ((a), GCRYCTL_IS_SECURE, NULL, (b))

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
gpg_error_t gcry_random_add_bytes (const void *buffer, size_t length,
				   int quality);

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
void gcry_mpi_randomize (gcry_mpi_t w,
                         unsigned int nbits, enum gcry_random_level level);



/************************************
 *                                  *
 *     miscellaneous stuff          *
 *                                  *
 ************************************/

/* Log levels used by the internal logging facility. */
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

/* Register a function used instead of the internal logging
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

#if 0
/* FIXME.  */
#ifndef GCRYPT_NO_MPI_MACROS
#ifndef DID_MPI_TYPEDEF
    typedef struct gcry_mpi *MPI;
#define DID_MPI_TYPEDEF
#endif
#endif /* GCRYPT_NO_MPI_MACROS */
#endif

#if 0 /* keep Emacsens's auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif
#endif /* _GCRYPT_H */
