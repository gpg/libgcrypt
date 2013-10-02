/* gcrypt-module.h - GNU Cryptographic Library Interface
   Copyright (C) 2003, 2007 Free Software Foundation, Inc.

   This file is part of Libgcrypt.

   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   Libgcrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
   This file contains the necessary declarations/definitions for
   working with Libgcrypt modules.  Since 1.6 this is an internal
   interface and will eventually be merged into another header or
   entirely removed.
 */

#ifndef GCRYPT_MODULE_H
#define GCRYPT_MODULE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens's auto-indent happy */
}
#endif
#endif

/* The interfaces using the module system reserve a certain range of
   IDs for application use.  These IDs are not valid within Libgcrypt
   but Libgcrypt makes sure never to allocate such a module ID.  */
#define GCRY_MODULE_ID_USER      1024
#define GCRY_MODULE_ID_USER_LAST 4095


/* This type represents a `module'.  */
typedef struct gcry_module *gcry_module_t;


/* ********************** */


#if 0 /* keep Emacsens's auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif
#endif /*GCRYPT_MODULE_H*/
