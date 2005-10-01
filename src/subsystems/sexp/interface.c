#include <gcrypt-sexp-internal.h>
#include <gcrypt-mpi-common.h>

#include <assert.h>

/* Create an new S-expression object from BUFFER of size LENGTH and
   return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER
   is expected to be in canonized format.  */
gcry_error_t
gcry_core_sexp_new (gcry_core_context_t ctx,
		    gcry_core_sexp_t * retsexp,
		    const void *buffer, size_t length,
		    int autodetect)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->new);
  return (*ctx->subsystems.sexp->new) (ctx, retsexp, buffer, length, autodetect);

}

 /* Same as gcry_sexp_new but allows to pass a FREEFNC which has the
    effect to transfer ownership of BUFFER to the created object.  */
gcry_error_t
gcry_core_sexp_create (gcry_core_context_t ctx,
		       gcry_core_sexp_t * retsexp,
		       void *buffer, size_t length,
		       int autodetect, void (*freefnc) (void *))
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->create);
  return (*ctx->subsystems.sexp->create) (ctx,
			      retsexp, buffer, length, autodetect, freefnc);
}

/* Scan BUFFER and return a new S-expression object in RETSEXP.  This
   function expects a printf like string in BUFFER.  */
gcry_error_t
gcry_core_sexp_sscan (gcry_core_context_t ctx,
		      gcry_core_sexp_t * retsexp, size_t * erroff,
		      const char *buffer, size_t length)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->sscan);
  return (*ctx->subsystems.sexp->sscan) (ctx, retsexp, erroff, buffer, length);
}


/* Same as gcry_sexp_sscan but expects a string in FORMAT and can thus
   only be used for certain encodings.  */
gcry_error_t
gcry_core_sexp_build (gcry_core_context_t ctx,
		      gcry_core_sexp_t * retsexp, size_t * erroff,
		      const char *format, ...)
{
  gcry_error_t err;
  va_list ap;

  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->build_va);
  va_start (ap, format);
  err = (*ctx->subsystems.sexp->build_va) (ctx, retsexp, erroff, format, ap);
  va_end (ap);

  return err;
}


gcry_error_t
gcry_core_sexp_build_va (gcry_core_context_t ctx,
			 gcry_core_sexp_t * retsexp, size_t * erroff,
			 const char *format, va_list ap)
{
  gcry_error_t err;

  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->build_va);
  err = (*ctx->subsystems.sexp->build_va) (ctx, retsexp, erroff, format, ap);

  return err;
}


/* Like gcry_sexp_build, but uses an array instead of variable
   function arguments.  */
gcry_error_t
gcry_core_sexp_build_array (gcry_core_context_t ctx,
			    gcry_core_sexp_t * retsexp,
			    size_t * erroff, const char *format,
			    void **arg_list)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->build_array);
  return (*ctx->subsystems.sexp->build_array) (ctx, retsexp, erroff, format, arg_list);
}


/* Release the S-expression object SEXP */
void
gcry_core_sexp_release (gcry_core_context_t ctx, gcry_core_sexp_t sexp)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->release);
  (*ctx->subsystems.sexp->release) (ctx, sexp);
}


/* Calculate the length of an canonized S-expresion in BUFFER and
   check for a valid encoding. */
size_t
gcry_core_sexp_canon_len (gcry_core_context_t ctx,
			  const unsigned char *buffer, size_t length,
			  size_t * erroff, gcry_error_t * errcode)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->canon_len);
  return (*ctx->subsystems.sexp->canon_len) (ctx, buffer, length, erroff, errcode);
}

/* Copies the S-expression object SEXP into BUFFER using the format
   specified in MODE.  */
size_t
gcry_core_sexp_sprint (gcry_core_context_t ctx,
		       gcry_core_sexp_t sexp, int mode, char *buffer,
		       size_t maxlength)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->sprint);
  return (*ctx->subsystems.sexp->sprint) (ctx, sexp, mode, buffer, maxlength);
}


/* Dumps the S-expression object A in a aformat suitable for debugging
   to Libgcrypt's logging stream.  */
void
gcry_core_sexp_dump (gcry_core_context_t ctx, const gcry_core_sexp_t a)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->dump);
  (*ctx->subsystems.sexp->dump) (ctx, a);
}

/* Scan the S-expression for a sublist with a type (the car of the
   list) matching the string TOKEN.  If TOKLEN is not 0, the token is
   assumed to be raw memory of this length.  The function returns a
   newly allocated S-expression consisting of the found sublist or
   `NULL' when not found.  */
gcry_core_sexp_t
gcry_core_sexp_find_token (gcry_core_context_t ctx,
			   gcry_core_sexp_t list,
			   const char *tok, size_t toklen)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->find_token);
  return (*ctx->subsystems.sexp->find_token) (ctx, list, tok, toklen);
}

/* Return the length of the LIST.  For a valid S-expression this
   should be at least 1.  */
int
gcry_core_sexp_length (gcry_core_context_t ctx, const gcry_core_sexp_t list)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->length);
  return (*ctx->subsystems.sexp->length) (ctx, list);
}

/* Create and return a new S-expression from the element with index
   NUMBER in LIST.  Note that the first element has the index 0.  If
   there is no such element, `NULL' is returned.  */
gcry_core_sexp_t
gcry_core_sexp_nth (gcry_core_context_t ctx,
		    const gcry_core_sexp_t list, int number)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->nth);
  return (*ctx->subsystems.sexp->nth) (ctx, list, number);
}

/* Create and return a new S-expression from the first element in
   LIST; this called the "type" and should always exist and be a
   string. `NULL' is returned in case of a problem.  */
gcry_core_sexp_t
gcry_core_sexp_car (gcry_core_context_t ctx, const gcry_core_sexp_t list)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->car);
  return (*ctx->subsystems.sexp->car) (ctx, list);
}

/* Create and return a new list form all elements except for the first
   one.  Note, that this function may return an invalid S-expression
   because it is not guaranteed, that the type exists and is a string.
   However, for parsing a complex S-expression it might be useful for
   intermediate lists.  Returns `NULL' on error.  */
gcry_core_sexp_t
gcry_core_sexp_cdr (gcry_core_context_t ctx, const gcry_core_sexp_t list)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->cdr);
  return (*ctx->subsystems.sexp->cdr) (ctx, list);
}

gcry_core_sexp_t
gcry_core_sexp_cadr (gcry_core_context_t ctx, const gcry_core_sexp_t list)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->cadr);
  return (*ctx->subsystems.sexp->cadr) (ctx, list);
}


/* This function is used to get data from a LIST.  A pointer to the
   actual data with index NUMBER is returned and the length of this
   data will be stored to DATALEN.  If there is no data at the given
   index or the index represents another list, `NULL' is returned.
   *Note:* The returned pointer is valid as long as LIST is not
   modified or released.  */
const char *
gcry_core_sexp_nth_data (gcry_core_context_t ctx,
			 const gcry_core_sexp_t list, int number,
			 size_t * datalen)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->nth_data);
  return (*ctx->subsystems.sexp->nth_data) (ctx, list, number, datalen);
}

/* This function is used to get and convert data from a LIST. This
   data is assumed to be an MPI stored in the format described by
   MPIFMT and returned as a standard Libgcrypt MPI.  The caller must
   release this returned value using `gcry_mpi_release'.  If there is
   no data at the given index, the index represents a list or the
   value can't be converted to an MPI, `NULL' is returned.  */
gcry_core_mpi_t
gcry_core_sexp_nth_mpi (gcry_core_context_t ctx, gcry_core_sexp_t list,
			int number, int mpifmt)
{
  assert (ctx->subsystems.sexp && ctx->subsystems.sexp->nth_mpi);
  return (*ctx->subsystems.sexp->nth_mpi) (ctx, list, number, mpifmt);
}
