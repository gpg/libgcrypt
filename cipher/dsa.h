/* dsa.h  -  DSA signature scheme
 *	Copyright (C) 1998, 2001, 2002 Free Software Foundation, Inc.
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
#ifndef G10_DSA_H
#define G10_DSA_H

int _gcry_dsa_generate( int algo, unsigned int nbits, unsigned long dummy,
                        MPI *skey, MPI **retfactors );
int _gcry_dsa_check_secret_key( int algo, MPI *skey );
int _gcry_dsa_sign( int algo, MPI *resarr, MPI data, MPI *skey );
int _gcry_dsa_verify( int algo, MPI hash, MPI *data, MPI *pkey,
		    int (*cmp)(void *, MPI), void *opaquev );
unsigned _gcry_dsa_get_nbits( int algo, MPI *pkey );
const char *_gcry_dsa_get_info( int algo, int *npkey, int *nskey,
				    int *nenc, int *nsig, int *use );

#endif /*G10_DSA_H*/
