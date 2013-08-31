/* hwfeatures.c - Detect hardware features.
 * Copyright (C) 2007, 2011  Free Software Foundation, Inc.
 * Copyright (C) 2012  g10 Code GmbH
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
#include <stdarg.h>
#include <unistd.h>

#include "g10lib.h"
#include "hwf-common.h"


/* A bit vector describing the hardware features currently
   available. */
static unsigned int hw_features;


/* Return a bit vector describing the available hardware features.
   The HWF_ constants are used to test for them. */
unsigned int
_gcry_get_hw_features (void)
{
  return hw_features;
}


/* Detect the available hardware features.  This function is called
   once right at startup and we assume that no other threads are
   running.  */
void
_gcry_detect_hw_features (unsigned int disabled_features)
{
  hw_features = 0;

  if (fips_mode ())
    return; /* Hardware support is not to be evaluated.  */

#if defined (HAVE_CPU_ARCH_X86)
  {
    hw_features = _gcry_hwf_detect_x86 ();
  }
#endif /* HAVE_CPU_ARCH_X86 */
#if defined (HAVE_CPU_ARCH_ARM)
  {
    hw_features = _gcry_hwf_detect_arm ();
  }
#endif /* HAVE_CPU_ARCH_ARM */

  hw_features &= ~disabled_features;
}
