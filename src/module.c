/* module.c - Module management for libgcrypt.
 * Copyright (C) 2003 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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

#include <assert.h>
#include <config.h>
#include <errno.h>
#include "g10lib.h"

/* Public function.  Add a module specification to the list ENTRIES.
   The new module has it's use-counter set to one.  */
gpg_err_code_t
_gcry_module_add (GcryModule **entries, void *spec,
		  GcryModule **module)
{
  gpg_err_code_t err = 0;
  GcryModule *entry;

  entry = gcry_malloc (sizeof (GcryModule));
  if (! entry)
    err = gpg_err_code_from_errno (errno);
  else
    {
      /* Fill new module entry.  */
      entry->flags = 0;
      entry->counter = 1;
      entry->spec = spec;

      /* Link it into the list.  */
      entry->next = *entries;
      entry->prevp = entries;
      if (*entries)
	(*entries)->prevp = &entry->next;
      *entries = entry;

      /* And give it to the caller.  */
      if (module)
	*module = entry;
    }
  return err;
}

/* Internal function.  Unlink CIPHER_ENTRY from the list of registered
   ciphers and destroy it.  */
static void
_gcry_module_drop (GcryModule *entry)
{
  *entry->prevp = entry->next;
  if (entry->next)
    entry->next->prevp = entry->prevp;

  gcry_free (entry);
}

/* Public function.  Lookup a module specification.  After a
   successfull lookup, the module has it's resource counter
   incremented.  FUNC is a function provided by the caller, which is
   responsible for identifying the wanted module.  */
GcryModule *
_gcry_module_lookup (GcryModule *entries, void *data,
		     GcryModuleLookup func)
{
  GcryModule *entry;

  for (entry = entries; entry; entry = entry->next)
    if ((*func) (entry->spec, data))
      {
	entry->counter++;
	break;
      }

  return entry;
}

/* Public function.  Release a module.  In case the use-counter
   reaches zero, destroy the module.  */
void
_gcry_module_release (GcryModule *module)
{
  if (! --module->counter)
    _gcry_module_drop (module);
}

/* Public function.  Add a reference to a module.  */
void
_gcry_module_use (GcryModule *module)
{
  ++module->counter;
}
