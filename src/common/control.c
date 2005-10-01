/* control.c - General library control functions.
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
#include <gcrypt-ath-internal.h>

#include <string.h>
#include <assert.h>

/* Return the size (in bytes) necessary for holding a context
   object.  */
size_t
gcry_core_context_size (void)
{
  return sizeof (struct gcry_context);
}

/* Initialize the newly allocated context object CTX.  */
void
gcry_core_context_init (gcry_core_context_t ctx)
{
  memset (ctx, 0, sizeof (struct gcry_context));
}

/* Prepare the context object CTX for use.  */
void
gcry_core_context_prepare (gcry_core_context_t ctx)
{
  gcry_error_t err;
  unsigned int i;
  struct
  {
    gcry_error_t (*prepare) (gcry_core_context_t context, void **ptr);
    void **ptr;
  } specs[] =
    {
      { ctx->subsystems.secmem->prepare, &ctx->secmem.intern },
      { ctx->subsystems.random->prepare, &ctx->random.intern },
    };

  /* Initialize ath.  */
  err = _gcry_core_ath_init (ctx);
  assert (! err);

  /* Initialize subsystems.  */
  for (i = 0; i < DIM (specs); i++)
    if (specs[i].prepare)
      {
	err = (*specs[i].prepare) (ctx, specs[i].ptr);
	assert (! err);
      }
}

/* Do cleanup work on the context object CTX.  */
void
gcry_core_context_finish (gcry_core_context_t ctx)
{
  unsigned int i;
  struct
  {
    void (*finish) (gcry_core_context_t c, void *ptr);
    void *ptr;
  } specs[] =
    {
      { ctx->subsystems.secmem->finish, ctx->secmem.intern },
      { ctx->subsystems.random->finish, ctx->random.intern }
    };

  for (i = 0; i < DIM (specs); i++)
    if (specs[i].finish)
      (*specs[i].finish) (ctx, specs[i].ptr);
}

/* Install the secmem subsystem specification SECMEM in CTX.  */
void
gcry_core_set_subsystem_secmem (gcry_core_context_t ctx, gcry_core_subsystem_secmem_t secmem)
{
  ctx->subsystems.secmem = secmem;
}

/* Install the mpi subsystem specification MPI in CTX.  */
void
gcry_core_set_subsystem_mpi (gcry_core_context_t ctx, gcry_core_subsystem_mpi_t mpi)
{
  ctx->subsystems.mpi = mpi;
}

/* Install the md subsystem specification MD in CTX.  */
void
gcry_core_set_subsystem_md (gcry_core_context_t ctx, gcry_core_subsystem_md_t md)
{
  ctx->subsystems.md = md;
}

/* Install the cipher subsystem specification CIPHER in CTX.  */
void
gcry_core_set_subsystem_cipher (gcry_core_context_t ctx, gcry_core_subsystem_cipher_t cipher)
{
  ctx->subsystems.cipher = cipher;
}

/* Install the ac subsystem specification AC in CTX.  */
void
gcry_core_set_subsystem_ac (gcry_core_context_t ctx, gcry_core_subsystem_ac_t ac)
{
  ctx->subsystems.ac = ac;
}

/* Install the random subsystem specification RANDOM in CTX.  */
void
gcry_core_set_subsystem_random (gcry_core_context_t ctx, gcry_core_subsystem_random_t random)
{
  ctx->subsystems.random = random;
}

/* Install the sexp subsystem specification SEXP in CTX.  */
void
gcry_core_set_subsystem_sexp (gcry_core_context_t ctx, gcry_core_subsystem_sexp_t sexp)
{
  ctx->subsystems.sexp = sexp;
}

/* Install the prime subsystem specification PRIME in CTX.  */
void
gcry_core_context_set_prime (gcry_core_context_t ctx, gcry_core_subsystem_prime_t prime)
{
  ctx->subsystems.prime = prime;
}



/* Set the debug flags FLAGS in the context object CTX.  */
void
gcry_core_debug_flags_set (gcry_core_context_t ctx, unsigned int flags)
{
  ctx->debug_flags |= flags;
}

/* Return the debug flags, which are set in the context object CTX and
   in FLAGS.  */
unsigned int
gcry_core_debug_flags_get (gcry_core_context_t ctx, unsigned int flags)
{
  return ctx->debug_flags & flags;
}

/* Clear the debug flags from the context object CTX which are set in
   FLAGS.  */
void
gcry_core_debug_flags_clear (gcry_core_context_t ctx, unsigned int flags)
{
  ctx->debug_flags &= ~flags;
}

/* Set the general flags FLAGS in the context object CTX.  */
void
gcry_core_flags_set (gcry_core_context_t ctx, unsigned int flags)
{
  ctx->flags |= flags;
}

/* Return the general flags, which are set in the context object CTX
   and in FLAGS.  */
unsigned int
gcry_core_flags_get (gcry_core_context_t ctx, unsigned int flags)
{
  return ctx->flags & flags;
}

/* Clear the general flags from the context object CTX which are set
   in FLAGS.  */
void
gcry_core_flags_clear (gcry_core_context_t ctx, unsigned int flags)
{
  ctx->flags &= ~flags;
}

/* FIXME: should this function be *here*?  */
void
gcry_core_set_random_seed_file (gcry_core_context_t ctx, const char *filename)
{
  assert (! ctx->random_seed_file);
  ctx->random_seed_file = gcry_core_xstrdup (ctx, filename);
}

/* Set the verbosity level of the context object CTX to LEVEL.  */
void
gcry_core_set_verbosity (gcry_core_context_t ctx, int level)
{
  ctx->verbosity_level = level;
}

/* Install the set of memory handler functions consisting of
   MEM_ALLOC, MEM_REALLOC, MEM_FREE and MEM_NO_MEM/MEM_NO_MEM_OPAQUE
   in the context object CTX.  */
void
gcry_core_set_handler_mem (gcry_core_context_t ctx,
			   gcry_core_handler_alloc_t mem_alloc,
			   gcry_core_handler_realloc_t mem_realloc,
			   gcry_core_handler_free_t mem_free,
			   gcry_core_handler_no_mem_t mem_no_mem,
			   void *mem_no_mem_opaque)
{
  ctx->handler.mem.alloc = mem_alloc;
  ctx->handler.mem.realloc = mem_realloc;
  ctx->handler.mem.free = mem_free;
  ctx->handler.mem.no_mem = mem_no_mem;
  ctx->handler.mem.no_mem_opaque = mem_no_mem_opaque;
}

/* Install the progress handler PROGRESS in the context object CTX
   using OPAQUE as opaque argument for the handler function.  */
void
gcry_core_set_handler_progress (gcry_core_context_t ctx,
				gcry_core_handler_progress_t progress,
				void *opaque)
{
  ctx->handler.progress.progress = progress;
  ctx->handler.progress.opaque = opaque;
}

/* Install the error handler ERR in the context object CTX using
   OPAQUE as opaque argument for the handler function.  */
void
gcry_core_set_handler_error (gcry_core_context_t ctx,
			     gcry_core_handler_error_t err,
			     void *opaque)
{
  ctx->handler.error.error = err;
  ctx->handler.error.opaque = opaque;
}

/* Install the logging handler logger in the context object CTX using
   OPAQUE as opaque argument for the handler function.  */
void
gcry_core_set_handler_log (gcry_core_context_t ctx,
			   gcry_core_handler_log_t logger,
			   void *opaque)
{
  ctx->handler.logger.logger = logger;
  ctx->handler.logger.opaque = opaque;
}

void
gcry_core_set_handler_ath (gcry_core_context_t ctx, gcry_core_handler_ath_t ath)
{
  assert (ctx->handler.ath.ops_set == 0);
  assert (ath->mutex_init && ath->mutex_lock && ath->mutex_unlock);

  ctx->handler.ath.ops_set = 1;
  ctx->handler.ath.init = ath->init;
  ctx->handler.ath.mutex_init = ath->mutex_init;
  ctx->handler.ath.mutex_destroy = ath->mutex_destroy;
  ctx->handler.ath.mutex_lock = ath->mutex_lock;
  ctx->handler.ath.mutex_unlock = ath->mutex_unlock;
  ctx->handler.ath.read = ath->read;
  ctx->handler.ath.write = ath->write;
  ctx->handler.ath.select = ath->select;
  ctx->handler.ath.waitpid = ath->waitpid;
  ctx->handler.ath.accept = ath->accept;
  ctx->handler.ath.connect = ath->connect;
  ctx->handler.ath.sendmsg = ath->sendmsg;
  ctx->handler.ath.recvmsg = ath->recvmsg;
}

/* END. */
