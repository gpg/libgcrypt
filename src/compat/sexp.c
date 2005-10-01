#include <gcrypt-internal.h>

#include <gcrypt-sexp-internal.h>

gcry_error_t
gcry_sexp_new (gcry_sexp_t *retsexp,
	       const void *buffer, size_t length,
	       int autodetect)
{
  _gcry_init ();
  return gcry_core_sexp_new (context, retsexp, buffer, length, autodetect);
}

gcry_error_t
gcry_sexp_create (gcry_sexp_t *retsexp,
		  void *buffer, size_t length,
		  int autodetect, void (*freefnc) (void *))
{
  _gcry_init ();
  return gcry_core_sexp_create (context, retsexp, buffer, length,
				autodetect, freefnc);
}

gcry_error_t
gcry_sexp_sscan (gcry_sexp_t *retsexp, size_t *erroff,
		 const char *buffer, size_t length)
{
  _gcry_init ();
  return gcry_core_sexp_sscan (context, retsexp, erroff, buffer, length);
}

gcry_error_t
gcry_sexp_build (gcry_sexp_t *retsexp, size_t *erroff,
		 const char *format, ...)
{
  gcry_error_t err;
  va_list ap;

  _gcry_init ();
  va_start (ap, format);
  err = gcry_core_sexp_build_va (context, retsexp, erroff, format, ap);
  va_end (ap);

  return err;
}

gcry_error_t
gcry_sexp_build_array (gcry_sexp_t *retsexp, size_t *erroff,
		       const char *format, void **arg_list)
{
  _gcry_init ();
  return gcry_core_sexp_build_array (context, retsexp, erroff, format, arg_list);
}

void
gcry_sexp_release (gcry_sexp_t sexp)
{
  _gcry_init ();
  gcry_core_sexp_release (context, sexp);
}

size_t
gcry_sexp_canon_len (const unsigned char *buffer, size_t length, 
		     size_t *erroff, gcry_error_t *errcode)
{
  _gcry_init ();
  return gcry_core_sexp_canon_len (context, buffer, length, erroff, errcode);
}

size_t
gcry_sexp_sprint (gcry_sexp_t sexp, int mode, char *buffer,
		  size_t maxlength)
{
  _gcry_init ();
  return gcry_core_sexp_sprint (context, sexp, mode, buffer, maxlength);
}

void
gcry_sexp_dump (const gcry_sexp_t a)
{
  _gcry_init ();
  return gcry_core_sexp_dump (context, a);
}

gcry_sexp_t
gcry_sexp_cons (const gcry_sexp_t a, const gcry_sexp_t b)
{
  BUG (context);
  return NULL;
}

gcry_sexp_t
gcry_sexp_alist (const gcry_sexp_t *array)
{
  BUG (context);
  return NULL;
}

gcry_sexp_t
gcry_sexp_vlist (const gcry_sexp_t a, ...)
{
  BUG (context);
  return NULL;
}

gcry_sexp_t
gcry_sexp_append (const gcry_sexp_t a, const gcry_sexp_t n)
{
  BUG (context);
  return NULL;
}

gcry_sexp_t
gcry_sexp_prepend (const gcry_sexp_t a, const gcry_sexp_t n)
{
  BUG (context);
  return NULL;
}

gcry_sexp_t
gcry_sexp_find_token (gcry_sexp_t list,
		      const char *tok, size_t toklen)
{
  _gcry_init ();
  return gcry_core_sexp_find_token (context,list, tok, toklen);
}

int
gcry_sexp_length (const gcry_sexp_t list)
{
  _gcry_init ();
  return gcry_core_sexp_length (context, list);
}

gcry_sexp_t
gcry_sexp_nth (const gcry_sexp_t list, int number)
{
  _gcry_init ();
  return gcry_core_sexp_nth (context, list, number);
}

gcry_sexp_t
gcry_sexp_car (const gcry_sexp_t list)
{
  _gcry_init ();
  return gcry_core_sexp_car (context, list);
}

gcry_sexp_t
gcry_sexp_cdr (const gcry_sexp_t list)
{
  _gcry_init ();
  return gcry_core_sexp_cdr (context, list);
}

gcry_sexp_t
gcry_sexp_cadr (const gcry_sexp_t list)
{
  _gcry_init ();
  return gcry_core_sexp_cadr (context, list);
}

const char *
gcry_sexp_nth_data (const gcry_sexp_t list, int number,
		    size_t *datalen)
{
  _gcry_init ();
  return gcry_core_sexp_nth_data (context, list, number, datalen);
}

gcry_mpi_t
gcry_sexp_nth_mpi (gcry_sexp_t list, int number, int mpifmt)
{
  _gcry_init ();
  return gcry_core_sexp_nth_mpi (context, list, number, mpifmt);
}
