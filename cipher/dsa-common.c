/* dsa-common.c - Common code for DSA
 * Copyright (C) 1998, 1999 Free Software Foundation, Inc.
 * Copyright (C) 2013  g10 Code GmbH
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "pubkey-internal.h"


/*
 * Generate a random secret exponent K less than Q.
 * Note that ECDSA uses this code also to generate D.
 */
gcry_mpi_t
_gcry_dsa_gen_k (gcry_mpi_t q, int security_level)
{
  gcry_mpi_t k        = mpi_alloc_secure (mpi_get_nlimbs (q));
  unsigned int nbits  = mpi_get_nbits (q);
  unsigned int nbytes = (nbits+7)/8;
  char *rndbuf = NULL;

  /* To learn why we don't use mpi_mod to get the requested bit size,
     read the paper: "The Insecurity of the Digital Signature
     Algorithm with Partially Known Nonces" by Nguyen and Shparlinski.
     Journal of Cryptology, New York. Vol 15, nr 3 (2003)  */

  if (DBG_CIPHER)
    log_debug ("choosing a random k of %u bits at seclevel %d\n",
               nbits, security_level);
  for (;;)
    {
      if ( !rndbuf || nbits < 32 )
        {
          gcry_free (rndbuf);
          rndbuf = gcry_random_bytes_secure (nbytes, security_level);
	}
      else
        { /* Change only some of the higher bits.  We could improve
	     this by directly requesting more memory at the first call
	     to get_random_bytes() and use these extra bytes here.
	     However the required management code is more complex and
	     thus we better use this simple method.  */
          char *pp = gcry_random_bytes_secure (4, security_level);
          memcpy (rndbuf, pp, 4);
          gcry_free (pp);
	}
      _gcry_mpi_set_buffer (k, rndbuf, nbytes, 0);

      /* Make sure we have the requested number of bits.  This code
         looks a bit funny but it is easy to understand if you
         consider that mpi_set_highbit clears all higher bits.  We
         don't have a clear_highbit, thus we first set the high bit
         and then clear it again.  */
      if (mpi_test_bit (k, nbits-1))
        mpi_set_highbit (k, nbits-1);
      else
        {
          mpi_set_highbit (k, nbits-1);
          mpi_clear_bit (k, nbits-1);
	}

      if (!(mpi_cmp (k, q) < 0))    /* check: k < q */
        {
          if (DBG_CIPHER)
            log_debug ("\tk too large - again");
          continue; /* no  */
        }
      if (!(mpi_cmp_ui (k, 0) > 0)) /* check: k > 0 */
        {
          if (DBG_CIPHER)
            log_debug ("\tk is zero - again");
          continue; /* no */
        }
      break;	/* okay */
    }
  gcry_free (rndbuf);

  return k;
}
