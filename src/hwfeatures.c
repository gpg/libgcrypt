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


/* A table to map hardware features to a string.  */
static struct
{
  unsigned int flag;
  const char *desc;
} hwflist[] =
  {
    { HWF_PADLOCK_RNG, "padlock-rng" },
    { HWF_PADLOCK_AES, "padlock-aes" },
    { HWF_PADLOCK_SHA, "padlock-sha" },
    { HWF_PADLOCK_MMUL,"padlock-mmul"},
    { HWF_INTEL_PCLMUL,"intel-pclmul" },
    { HWF_INTEL_AESNI, "intel-aesni" },
    { HWF_INTEL_RDRAND,"intel-rdrand" },
    { HWF_INTEL_AVX,   "intel-avx" },
    { HWF_INTEL_AVX2,  "intel-avx2" },
    { HWF_ARM_NEON,    "arm-neon" }
  };

/* A bit vector with the hardware features which shall not be used.
   This variable must be set prior to any initialization.  */
static unsigned int disabled_hw_features;

/* A bit vector describing the hardware features currently
   available. */
static unsigned int hw_features;


/* Disable a feature by name.  This function must be called *before*
   _gcry_detect_hw_features is called.  */
gpg_err_code_t
_gcry_disable_hw_feature (const char *name)
{
  int i;

  for (i=0; i < DIM (hwflist); i++)
    if (!strcmp (hwflist[i].desc, name))
      {
        disabled_hw_features |= hwflist[i].flag;
        return 0;
      }
  return GPG_ERR_INV_NAME;
}


/* Return a bit vector describing the available hardware features.
   The HWF_ constants are used to test for them. */
unsigned int
_gcry_get_hw_features (void)
{
  return hw_features;
}


/* Enumerate all features.  The caller is expected to start with an
   IDX of 0 and then increment IDX until NULL is returned.  */
const char *
_gcry_enum_hw_features (int idx, unsigned int *r_feature)
{
  if (idx < 0 || idx >= DIM (hwflist))
    return NULL;
  if (r_feature)
    *r_feature = hwflist[idx].flag;
  return hwflist[idx].desc;
}


/* Detect the available hardware features.  This function is called
   once right at startup and we assume that no other threads are
   running.  */
void
_gcry_detect_hw_features (void)
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

  hw_features &= ~disabled_hw_features;
}
