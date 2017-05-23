/*
 * Non-physical true random number generator based on timing jitter.
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2013
 *
 * License
 * =======
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _JITTERENTROPY_BASE_X86_H
#define _JITTERENTROPY_BASE_X86_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <config.h>
#include "g10lib.h"

typedef uint64_t __u64;

#define RdTSC __asm _emit 0x0f __asm _emit 0x31

static void jent_get_nstime(__u64 *out)
{
	__u64 ret = 0;
	_asm {
		RdTSC
		mov DWORD PTR ret, eax
		mov DWORD PTR[ret + 4], edx
	}
	*out = ret;
}

static inline void *jent_zalloc(size_t len)
{
	void *tmp = NULL;

	/* When using the libgcrypt secure memory mechanism, all precautions
	 * are taken to protect our state. If the user disables secmem during
	 * runtime, it is his decision and we thus try not to overrule his
	 * decision for less memory protection. */
#define CONFIG_CRYPTO_CPU_JITTERENTROPY_SECURE_MEMORY
	tmp = gcry_xmalloc_secure(len);
	if(NULL != tmp)
		memset(tmp, 0, len);
	return tmp;
}

static inline void jent_zfree(void *ptr, unsigned int len)
{
	memset(ptr, 0, len);
	gcry_free(ptr);
}

static inline int jent_fips_enabled(void)
{
        return fips_mode();
}

/* --- helpers needed in user space -- */

/* note: these helper functions are shamelessly stolen from the kernel :-) */

static inline __u64 rol64(__u64 word, unsigned int shift)
{
	return (word << shift) | (word >> (64 - shift));
}


#endif /* _JITTERENTROPY_BASE_X86_H */
