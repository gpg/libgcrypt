/* error.c - Wrapper functions for libgpg-error.
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

#include <gcrypt-common-internal.h>

/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  */
const char *
gcry_core_strerror (gcry_error_t err)
{
  return gpg_strerror (err);
}

/* Return a pointer to a string containing a description of the error
   source in the error value ERR.  */
const char *
gcry_core_strsource (gcry_error_t err)
{
  return gpg_strsource (err);
}

/* Retrieve the error code for the system error ERR.  This returns
   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
   this).  */
gcry_err_code_t
gcry_core_err_code_from_errno (int err)
{
  return gpg_err_code_from_errno (err);
}


/* Retrieve the system error for the error code CODE.  This returns 0
   if CODE is not a system error code.  */
int
gcry_core_err_code_to_errno (gcry_err_code_t code)
{
  return gpg_err_code_from_errno (code);
}

  
/* Return an error value with the error source SOURCE and the system
   error ERR.  */
gcry_error_t
gcry_core_err_make_from_errno (gpg_err_source_t source, int err)
{
  return gpg_err_make_from_errno (source, err);
}


/* Return an error value with the system error ERR.  */
gcry_err_code_t
gcry_core_error_from_errno (int err)
{
  return gcry_core_error (gpg_err_code_from_errno (err));
}

/* END. */
