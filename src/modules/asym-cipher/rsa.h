/* rsa.h - interface for RSA module
   Copyright (C) 2005 Free Software Foundation, Inc.
 
   This file is part of Libgcrypt.

   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   Libgcrypt is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef RSA_H
#define RSA_H

/* The caller of gcry_ac_key_pair_generate can provide one of these
   structures in order to influence the key generation process in an
   algorithm-specific way.  */
typedef struct gcry_core_ac_key_spec_rsa
{
  unsigned long int e;
} gcry_core_ac_key_spec_rsa_t;

extern gcry_core_ac_spec_t gcry_core_ac_rsa;

#endif

/* END. */
