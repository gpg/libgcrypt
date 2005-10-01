/* gcrypt-internal.h -  internal Libgcrypt interfaces
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
 *               2005  Free Software Foundation, Inc.
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

#ifndef _GCRYPT_INTERNAL_H
#define _GCRYPT_INTERNAL_H

#include <gcrypt-common-internal.h>
#include <gcrypt.h>



/*
 * Library initialization.
 */

/* Subsystem initializer functions.  */

gcry_error_t _gcry_cipher_init (void);
gcry_error_t _gcry_md_init (void);
gcry_error_t _gcry_ac_init (void);

/* This is the context used throughout Libgcrypt-compat for
   interaction with Libgcrypt-core.  */
extern gcry_core_context_t context;

extern void (*_gcry_init) (void);
void _gcry_init_stage1_only (void);
unsigned int _gcry_init_done_p (void);



/*
 * Module system interface (used by cipher.c/md.c/pubkey.c).
 */

/* Structure for each registered `module'.  */
struct gcry_module
{
  struct gcry_module *next;     /* List pointers.      */
  struct gcry_module **prevp;
  void *spec;			/* The acctual specs.  */
  int flags;			/* Associated flags.   */
  int counter;			/* Use counter.        */
  unsigned int mod_id;		/* ID of this module.  */
};

/* Flags for the `flags' member of gcry_module_t.  */
#define FLAG_MODULE_DISABLED 1 << 0

gcry_error_t _gcry_module_add (gcry_module_t *entries,
				 unsigned int id,
				 void *spec,
				 gcry_module_t *module);

typedef int (*gcry_module_lookup_t) (void *spec, const void *data);

/* Lookup a module specification by it's ID.  After a successfull
   lookup, the module has it's resource counter incremented.  */
gcry_module_t _gcry_module_lookup_id (gcry_module_t entries,
				       unsigned int id);

/* Internal function.  Lookup a module specification.  */
gcry_module_t _gcry_module_lookup (gcry_module_t entries, const void *data,
				    gcry_module_lookup_t func);

unsigned int _gcry_module_last_reference_p (gcry_module_t module);

/* Release a module.  In case the use-counter reaches zero, destroy
   the module.  */
void _gcry_module_release (gcry_module_t entry);

/* Add a reference to a module.  */
void _gcry_module_use (gcry_module_t module);

/* Return a list of module IDs.  */
gcry_error_t _gcry_module_list (gcry_module_t modules,
				  int *list, int *list_length);



/* Functions exporting functionality from the ac subsystem to the
   pubkey subsystem.  */

gcry_error_t _gcry_ac_id_to_name (gcry_ac_id_t algorithm_id,
				  const char **algorithm_name,
				  int try_alias);
gcry_error_t _gcry_ac_name_to_id (const char *name,
				  gcry_ac_id_t *algorithm_id);
gcry_error_t _gcry_ac_list (int *list, int *list_length);
gcry_error_t _gcry_ac_arg_list_from_data (gcry_ac_data_t data,
					  void ***arg_list);
gcry_error_t _gcry_ac_algorithm_disable (gcry_ac_handle_t handle);
void _gcry_ac_elements_amount_get (gcry_ac_handle_t handle,
				   unsigned int *elements_key_secret,
				   unsigned int *elements_key_public,
				   unsigned int *elements_encrypted,
				   unsigned int *elements_signed);
void _gcry_ac_info_get (gcry_ac_handle_t handle,
			unsigned int *algorithm_use_flags);

/* Message digest module access functions.  */

gcry_error_t _gcry_md_lookup_module_spec (int algo,
					  gcry_module_t *module,
					  gcry_core_md_spec_t *spec);
void _gcry_md_release_module (gcry_module_t module);



/*
 * Helper macros and declarations.
 */

/* replacements of missing functions (missing-string.c)*/
#ifndef HAVE_STPCPY
char *stpcpy (char *a, const char *b);
#endif
#ifndef HAVE_STRCASECMP
int strcasecmp (const char *a, const char *b) GCC_ATTR_PURE;
#endif

/* macros used to rename missing functions */
#ifndef HAVE_STRTOUL
#define strtoul(a,b,c)  ((unsigned long)strtol((a),(b),(c)))
#endif
#ifndef HAVE_MEMMOVE
#define memmove(d, s, n) bcopy((s), (d), (n))
#endif
#ifndef HAVE_STRICMP
#define stricmp(a,b)	 strcasecmp( (a), (b) )
#endif
#ifndef HAVE_ATEXIT
#define atexit(a)    (on_exit((a),0))
#endif
#ifndef HAVE_RAISE
#define raise(a) kill(getpid(), (a))
#endif

#endif

/* END. */
