/* asm-common-amd64.h  -  Common macros for AMD64 assembly
 *
 * Copyright (C) 2018 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#ifndef GCRY_ASM_COMMON_AMD64_H
#define GCRY_ASM_COMMON_AMD64_H

#include <config.h>

#ifdef HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS
# define ELF(...) __VA_ARGS__
#else
# define ELF(...) /*_*/
#endif

#ifdef __PIC__
#  define rRIP (%rip)
#else
#  define rRIP
#endif

#ifdef __PIC__
#  define RIP %rip
#else
#  define RIP
#endif

#if defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS) || !defined(__PIC__)
#  define GET_EXTERN_POINTER(name, reg) movabsq $name, reg
#else
#  ifdef __code_model_large__
#    define GET_EXTERN_POINTER(name, reg) \
	       pushq %r15; \
	       pushq %r14; \
	    1: leaq 1b(%rip), reg; \
	       movabsq $_GLOBAL_OFFSET_TABLE_-1b, %r14; \
	       movabsq $name@GOT, %r15; \
	       addq %r14, reg; \
	       popq %r14; \
	       movq (reg, %r15), reg; \
	       popq %r15;
#  else
#    define GET_EXTERN_POINTER(name, reg) movq name@GOTPCREL(%rip), reg
#  endif
#endif

#ifdef HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS
# define ENTER_SYSV_FUNC_PARAMS_0_4 \
	pushq %rdi; \
	pushq %rsi; \
	movq %rcx, %rdi; \
	movq %rdx, %rsi; \
	movq %r8, %rdx; \
	movq %r9, %rcx; \

# define ENTER_SYSV_FUNC_PARAMS_5 \
	ENTER_SYSV_FUNC_PARAMS_0_4; \
	movq 0x38(%rsp), %r8;

# define ENTER_SYSV_FUNC_PARAMS_6 \
	ENTER_SYSV_FUNC_PARAMS_5; \
	movq 0x40(%rsp), %r9;

# define EXIT_SYSV_FUNC \
	popq %rsi; \
	popq %rdi;
#else
# define ENTER_SYSV_FUNC_PARAMS_0_4
# define ENTER_SYSV_FUNC_PARAMS_5
# define ENTER_SYSV_FUNC_PARAMS_6
# define EXIT_SYSV_FUNC
#endif

#endif /* GCRY_ASM_COMMON_AMD64_H */
