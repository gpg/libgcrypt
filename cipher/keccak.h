/* keccak.h  -  internal keccak-related functionality
 * Copyright (C) 2023 MTG AG
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "gcrypt.h"


#define DOES_MULT_OVERFL_SIZE_T(a, b) (a != 0 && ((size_t) (a*b))/a != b)

gpg_err_code_t _gcry_cshake_add_input(void* context,
                        enum gcry_ctl_cmds addin_type,
                        const void *v,
                        size_t v_len);
