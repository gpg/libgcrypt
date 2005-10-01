#ifndef _GCRYPT_SEXP_COMMON_H
#define _GCRYPT_SEXP_COMMON_H

#include <gcrypt-mpi-common.h>

 /* The object to represent an S-expression as used with the public key
   functions.  */
struct gcry_core_sexp;
typedef struct gcry_core_sexp *gcry_core_sexp_t;

/* The possible values for the S-expression format. */
/* FIXMEx, moritz, shall these be improved?  */
typedef enum gcry_core_sexp_format
  {
    GCRYSEXP_FMT_DEFAULT   = 0,
    GCRYSEXP_FMT_CANON     = 1,
    GCRYSEXP_FMT_BASE64    = 2,
    GCRYSEXP_FMT_ADVANCED  = 3
  }
gcry_core_sexp_format_t;



typedef gcry_error_t (*gcry_subsystem_sexp_new_t) (gcry_core_context_t ctx,
						   gcry_core_sexp_t * retsexp,
						   const void *buffer, size_t length,
						   int autodetect);
typedef gcry_error_t (*gcry_subsystem_sexp_create_t) (gcry_core_context_t ctx,
						      gcry_core_sexp_t * retsexp,
						      void *buffer, size_t length,
						      int autodetect, void (*freefnc) (void *));
typedef gcry_error_t (*gcry_subsystem_sexp_sscan_t) (gcry_core_context_t ctx,
						     gcry_core_sexp_t * retsexp, size_t * erroff,
						     const char *buffer, size_t length);
typedef gcry_error_t (*gcry_subsystem_sexp_build_va_t) (gcry_core_context_t ctx,
							gcry_core_sexp_t * retsexp, size_t * erroff,
							const char *format, va_list ap);
typedef gcry_error_t (*gcry_subsystem_sexp_build_array_t) (gcry_core_context_t ctx,
							   gcry_core_sexp_t * retsexp,
							   size_t * erroff, const char *format,
							   void **arg_list);
typedef void (*gcry_subsystem_sexp_release_t) (gcry_core_context_t ctx, gcry_core_sexp_t sexp);
typedef size_t (*gcry_subsystem_sexp_canon_len_t) (gcry_core_context_t ctx,
						   const unsigned char *buffer, size_t length,
						   size_t * erroff, gcry_error_t * errcode);
typedef size_t (*gcry_subsystem_sexp_sprint_t) (gcry_core_context_t ctx,
						gcry_core_sexp_t sexp, int mode, char *buffer,
						size_t maxlength);
typedef void (*gcry_subsystem_sexp_dump_t) (gcry_core_context_t ctx, const gcry_core_sexp_t a);
typedef gcry_core_sexp_t (*gcry_subsystem_sexp_find_token_t) (gcry_core_context_t ctx,
							 gcry_core_sexp_t list,
							 const char *tok, size_t toklen);
typedef int (*gcry_subsystem_sexp_length_t) (gcry_core_context_t ctx, const gcry_core_sexp_t list);
typedef gcry_core_sexp_t (*gcry_subsystem_sexp_nth_t) (gcry_core_context_t ctx,
						  const gcry_core_sexp_t list, int number);
typedef gcry_core_sexp_t (*gcry_subsystem_sexp_car_t) (gcry_core_context_t ctx, const gcry_core_sexp_t list);
typedef gcry_core_sexp_t (*gcry_subsystem_sexp_cdr_t) (gcry_core_context_t ctx, const gcry_core_sexp_t list);
typedef gcry_core_sexp_t (*gcry_subsystem_sexp_cadr_t) (gcry_core_context_t ctx, const gcry_core_sexp_t list);
typedef const char *(*gcry_subsystem_sexp_nth_data_t) (gcry_core_context_t ctx,
						       const gcry_core_sexp_t list, int number,
						       size_t * datalen);
typedef gcry_core_mpi_t (*gcry_subsystem_sexp_nth_mpi_t) (gcry_core_context_t ctx, gcry_core_sexp_t list,
						     int number, int mpifmt);

/* Create an new S-expression object from BUFFER of size LENGTH and
   return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER
   is expected to be in canonized format.  */
gcry_error_t gcry_core_sexp_new (gcry_core_context_t ctx,
				 gcry_core_sexp_t * retsexp,
				 const void *buffer, size_t length,
				 int autodetect);

 /* Same as gcry_sexp_new but allows to pass a FREEFNC which has the
    effect to transfer ownership of BUFFER to the created object.  */
gcry_error_t gcry_core_sexp_create (gcry_core_context_t ctx,
				    gcry_core_sexp_t * retsexp,
				    void *buffer, size_t length,
				    int autodetect, void (*freefnc) (void *));

/* Scan BUFFER and return a new S-expression object in RETSEXP.  This
   function expects a printf like string in BUFFER.  */
gcry_error_t gcry_core_sexp_sscan (gcry_core_context_t ctx,
				   gcry_core_sexp_t * retsexp, size_t * erroff,
				   const char *buffer, size_t length);

/* Same as gcry_sexp_sscan but expects a string in FORMAT and can thus
   only be used for certain encodings.  */
gcry_error_t gcry_core_sexp_build (gcry_core_context_t ctx,
				   gcry_core_sexp_t * retsexp, size_t * erroff,
				   const char *format, ...);

gcry_error_t gcry_core_sexp_build_va (gcry_core_context_t ctx,
				      gcry_core_sexp_t * retsexp, size_t * erroff,
				      const char *format, va_list ap);

/* Like gcry_sexp_build, but uses an array instead of variable
   function arguments.  */
gcry_error_t gcry_core_sexp_build_array (gcry_core_context_t ctx,
					 gcry_core_sexp_t * retsexp,
					 size_t * erroff, const char *format,
					 void **arg_list);

/* Release the S-expression object SEXP */
void gcry_core_sexp_release (gcry_core_context_t ctx, gcry_core_sexp_t sexp);

/* Calculate the length of an canonized S-expresion in BUFFER and
   check for a valid encoding. */
size_t gcry_core_sexp_canon_len (gcry_core_context_t ctx,
				 const unsigned char *buffer, size_t length,
				 size_t * erroff, gcry_error_t * errcode);

/* Copies the S-expression object SEXP into BUFFER using the format
   specified in MODE.  */
size_t gcry_core_sexp_sprint (gcry_core_context_t ctx,
			      gcry_core_sexp_t sexp, int mode, char *buffer,
			      size_t maxlength);

/* Dumps the S-expression object A in a aformat suitable for debugging
   to Libgcrypt's logging stream.  */
void gcry_core_sexp_dump (gcry_core_context_t ctx, const gcry_core_sexp_t a);

/* Scan the S-expression for a sublist with a type (the car of the
   list) matching the string TOKEN.  If TOKLEN is not 0, the token is
   assumed to be raw memory of this length.  The function returns a
   newly allocated S-expression consisting of the found sublist or
   `NULL' when not found.  */
gcry_core_sexp_t gcry_core_sexp_find_token (gcry_core_context_t ctx,
				       gcry_core_sexp_t list,
				       const char *tok, size_t toklen);
/* Return the length of the LIST.  For a valid S-expression this
   should be at least 1.  */
int gcry_core_sexp_length (gcry_core_context_t ctx, const gcry_core_sexp_t list);

/* Create and return a new S-expression from the element with index
   NUMBER in LIST.  Note that the first element has the index 0.  If
   there is no such element, `NULL' is returned.  */
gcry_core_sexp_t gcry_core_sexp_nth (gcry_core_context_t ctx,
				const gcry_core_sexp_t list, int number);

/* Create and return a new S-expression from the first element in
   LIST; this called the "type" and should always exist and be a
   string. `NULL' is returned in case of a problem.  */
gcry_core_sexp_t gcry_core_sexp_car (gcry_core_context_t ctx, const gcry_core_sexp_t list);

/* Create and return a new list form all elements except for the first
   one.  Note, that this function may return an invalid S-expression
   because it is not guaranteed, that the type exists and is a string.
   However, for parsing a complex S-expression it might be useful for
   intermediate lists.  Returns `NULL' on error.  */
gcry_core_sexp_t gcry_core_sexp_cdr (gcry_core_context_t ctx, const gcry_core_sexp_t list);

gcry_core_sexp_t gcry_core_sexp_cadr (gcry_core_context_t ctx, const gcry_core_sexp_t list);


/* This function is used to get data from a LIST.  A pointer to the
   actual data with index NUMBER is returned and the length of this
   data will be stored to DATALEN.  If there is no data at the given
   index or the index represents another list, `NULL' is returned.
   *Note:* The returned pointer is valid as long as LIST is not
   modified or released.  */
const char *gcry_core_sexp_nth_data (gcry_core_context_t ctx,
				     const gcry_core_sexp_t list, int number,
				     size_t * datalen);

/* This function is used to get and convert data from a LIST. This
   data is assumed to be an MPI stored in the format described by
   MPIFMT and returned as a standard Libgcrypt MPI.  The caller must
   release this returned value using `gcry_mpi_release'.  If there is
   no data at the given index, the index represents a list or the
   value can't be converted to an MPI, `NULL' is returned.  */
gcry_core_mpi_t gcry_core_sexp_nth_mpi (gcry_core_context_t ctx, gcry_core_sexp_t list,
				   int number, int mpifmt);

typedef struct gcry_core_subsystem_sexp
{
  gcry_subsystem_sexp_new_t new;
  gcry_subsystem_sexp_create_t create;
  gcry_subsystem_sexp_sscan_t sscan;
  gcry_subsystem_sexp_build_va_t build_va;
  gcry_subsystem_sexp_build_array_t build_array;
  gcry_subsystem_sexp_release_t release;
  gcry_subsystem_sexp_canon_len_t canon_len;
  gcry_subsystem_sexp_sprint_t sprint;
  gcry_subsystem_sexp_dump_t dump;
  gcry_subsystem_sexp_find_token_t find_token;
  gcry_subsystem_sexp_length_t length;
  gcry_subsystem_sexp_nth_t nth;
  gcry_subsystem_sexp_car_t car;
  gcry_subsystem_sexp_cdr_t cdr;
  gcry_subsystem_sexp_cadr_t cadr;
  gcry_subsystem_sexp_nth_data_t nth_data;
  gcry_subsystem_sexp_nth_mpi_t nth_mpi;
} *gcry_core_subsystem_sexp_t;

extern gcry_core_subsystem_sexp_t gcry_core_subsystem_sexp;

void gcry_core_set_subsystem_sexp (gcry_core_context_t ctx, gcry_core_subsystem_sexp_t sexp);

#endif
