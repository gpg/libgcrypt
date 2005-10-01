#include <gcrypt-common-internal.h>

#include <stdlib.h>
#include <stdio.h>

#ifdef JNLIB_GCC_M_FUNCTION
void
_gcry_core_bug (gcry_core_context_t ctx,
	   const char *file, int line, const char *func)
     
{
  abort ();
}
#else
void _gcry_core_bug (gcry_core_context_t ctx,
		const char *file, int line)
{
  abort ();
}
#endif

void
gcry_core_default_error_handler (void *opaque, int rc, const char *text)
{
  FILE *fp = opaque;

  fprintf(fp, "\nFatal error: %s\n", text);

  abort ();
}

void
_gcry_core_fatal_error (gcry_core_context_t ctx, int rc, const char *text)
{
  if ( !text ) /* get a default text */
    text = gcry_core_strerror (rc);

  if (ctx->handler.error.error)
    (*ctx->handler.error.error) (ctx->handler.error.opaque, rc, text);

  abort ();
}

void
gcry_core_default_log_handler (void *opaque,
			       int level, const char *format, va_list ap)
{
  FILE *fp = opaque;

  switch (level)
    {
    case GCRY_LOG_CONT: break;
    case GCRY_LOG_INFO: break;
    case GCRY_LOG_WARN: break;
    case GCRY_LOG_ERROR: break;
    case GCRY_LOG_FATAL: fputs ("Fatal: ", fp); break;
    case GCRY_LOG_BUG: fputs ("Ohhhh jeeee: ", fp); break;
    case GCRY_LOG_DEBUG: fputs ("DBG: ", fp); break;
    default: fprintf (fp,"[Unknown log level %d]: ", level); break;
    }
  vfprintf (fp, format, ap);

  if (level == GCRY_LOG_FATAL)
    exit (2);
  else if (level == GCRY_LOG_BUG)
    abort ();
}

/****************
 * This is our log function which prints all log messages to stderr or
 * using the function defined with gcry_set_log_handler().
 */
static void
_gcry_core_logv( gcry_core_context_t ctx, int level, const char *fmt, va_list arg_ptr )
{
  if (ctx->handler.logger.logger)
    (*ctx->handler.logger.logger) (ctx->handler.logger.opaque,
				       level, fmt, arg_ptr);

}

void
_gcry_core_log (gcry_core_context_t ctx, int level, const char *fmt, ...)
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    _gcry_core_logv(ctx, level, fmt, arg_ptr );
    va_end(arg_ptr);
}

void
_gcry_core_log_bug (gcry_core_context_t ctx, const char *fmt, ...)
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    _gcry_core_logv(ctx, GCRY_LOG_BUG, fmt, arg_ptr );
    va_end(arg_ptr);
    abort(); /* never called, but it makes the compiler happy */
}

void
_gcry_core_log_fatal (gcry_core_context_t ctx, const char *fmt, ...)
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    _gcry_core_logv(ctx, GCRY_LOG_FATAL, fmt, arg_ptr );
    va_end(arg_ptr);
    abort(); /* never called, but it makes the compiler happy */
}

void
_gcry_core_log_error (gcry_core_context_t ctx, const char *fmt, ...)
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    _gcry_core_logv(ctx, GCRY_LOG_ERROR, fmt, arg_ptr );
    va_end(arg_ptr);
}

void
_gcry_core_log_info (gcry_core_context_t ctx, const char *fmt, ...)
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    _gcry_core_logv(ctx, GCRY_LOG_INFO, fmt, arg_ptr );
    va_end(arg_ptr);
}

void
_gcry_core_log_debug (gcry_core_context_t ctx, const char *fmt, ...)
{
    va_list arg_ptr ;

    va_start( arg_ptr, fmt ) ;
    _gcry_core_logv(ctx, GCRY_LOG_DEBUG, fmt, arg_ptr );
    va_end(arg_ptr);
}

void
_gcry_core_log_printf (gcry_core_context_t ctx, const char *fmt, ...)
{
  va_list arg_ptr;
  
  if (fmt) 
    {
      va_start( arg_ptr, fmt ) ;
      _gcry_core_logv (ctx, GCRY_LOG_CONT, fmt, arg_ptr);
      va_end(arg_ptr);
    }
}

/* FIXME, moritz.  */
void
_gcry_core_progress (gcry_core_context_t ctx,
		     const char *a, int b, int c, int d)
{
  if (ctx->handler.progress.progress)
    (*ctx->handler.progress.progress) (ctx->handler.progress.opaque,
				       a, b, c, d);
}
