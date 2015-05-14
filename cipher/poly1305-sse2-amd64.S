/* poly1305-sse2-amd64.S  -  AMD64/SSE2 implementation of Poly1305
 *
 * Copyright (C) 2014 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

/*
 * Based on public domain implementation by Andrew Moon at
 *  https://github.com/floodyberry/poly1305-opt
 */

#include <config.h>

#if defined(__x86_64__) && (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))

#ifdef HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS
# define ELF(...) __VA_ARGS__
#else
# define ELF(...) /*_*/
#endif


.text


.align 8
.globl _gcry_poly1305_amd64_sse2_init_ext
ELF(.type  _gcry_poly1305_amd64_sse2_init_ext,@function;)
_gcry_poly1305_amd64_sse2_init_ext:
.Lpoly1305_init_ext_x86_local:
	xor %edx, %edx
	pushq %r12
	pushq %r13
	pushq %r14
	movq %rdx, %r10
	movq $-1, %rcx
	testq %r10, %r10
	pxor %xmm0, %xmm0
	movq $0xfffffc0ffff, %r9
	movdqa %xmm0, (%rdi)
	cmove %rcx, %r10
	movdqa %xmm0, 16(%rdi)
	movq $0xffc0fffffff, %rcx
	movdqa %xmm0, 32(%rdi)
	movdqa %xmm0, 48(%rdi)
	movdqa %xmm0, 64(%rdi)
	movq 8(%rsi), %r11
	movq %r11, %r8
	movq (%rsi), %r12
	andq %r12, %rcx
	shrq $44, %r12
	shlq $20, %r8
	shrq $24, %r11
	orq %r8, %r12
	movq $0xffffffc0f, %r8
	andq %r9, %r12
	andq %r8, %r11
	movl %ecx, %r8d
	andl $67108863, %r8d
	movq %rcx, %r9
	movl %r8d, 84(%rdi)
	movq %r12, %r8
	shrq $26, %r9
	shlq $18, %r8
	orq %r8, %r9
	movq %r12, %r8
	shrq $8, %r8
	andl $67108863, %r9d
	andl $67108863, %r8d
	movl %r9d, 92(%rdi)
	movq %r12, %r9
	movl %r8d, 100(%rdi)
	movq %r11, %r8
	shrq $34, %r9
	shlq $10, %r8
	orq %r8, %r9
	movq %r11, %r8
	shrq $16, %r8
	andl $67108863, %r9d
	movl %r9d, 108(%rdi)
	cmpq $16, %r10
	movl %r8d, 116(%rdi)
	movl 16(%rsi), %r8d
	movl %r8d, 124(%rdi)
	movl 20(%rsi), %r8d
	movl %r8d, 132(%rdi)
	movl 24(%rsi), %r8d
	movl %r8d, 140(%rdi)
	movl 28(%rsi), %esi
	movl %esi, 148(%rdi)
	jbe .Lpoly1305_init_ext_sse2_done
	lea (%r11,%r11,4), %r14
	shlq $2, %r14
	lea (%r12,%r12), %rax
	mulq %r14
	movq %rax, %r13
	movq %rcx, %rax
	movq %rdx, %r8
	mulq %rcx
	addq %rax, %r13
	lea (%rcx,%rcx), %rax
	movq %r13, %r9
	adcq %rdx, %r8
	mulq %r12
	shlq $20, %r8
	movq %rax, %rsi
	shrq $44, %r9
	movq %r11, %rax
	orq %r9, %r8
	movq %rdx, %r9
	mulq %r14
	addq %rax, %rsi
	movq %rcx, %rax
	adcq %rdx, %r9
	addq %r11, %r11
	mulq %r11
	addq %rsi, %r8
	movq %rax, %r11
	movq %r12, %rax
	movq %rdx, %rcx
	adcq $0, %r9
	mulq %r12
	addq %rax, %r11
	movq %r8, %rsi
	adcq %rdx, %rcx
	shlq $20, %r9
	shrq $44, %rsi
	orq %rsi, %r9
	movq $0xfffffffffff, %rsi
	addq %r11, %r9
	movq %r9, %r12
	adcq $0, %rcx
	andq %rsi, %r13
	shlq $22, %rcx
	andq %rsi, %r8
	shrq $42, %r12
	orq %r12, %rcx
	movq %rsi, %r12
	lea (%rcx,%rcx,4), %rcx
	addq %rcx, %r13
	movq %rsi, %rcx
	andq %r13, %rcx
	shrq $44, %r13
	movq %rcx, %r14
	addq %r13, %r8
	movq $0x3ffffffffff, %r13
	andq %r8, %r12
	andq %r13, %r9
	shrq $44, %r8
	movq %r12, %r11
	addq %r8, %r9
	movq %r12, %rax
	movq %r9, %r13
	movl %ecx, %r8d
	shrq $26, %r14
	andl $67108863, %r8d
	shlq $18, %r11
	shrq $34, %rax
	orq %r11, %r14
	shlq $10, %r13
	movq %r12, %r11
	orq %r13, %rax
	movq %r9, %r13
	shrq $8, %r11
	shrq $16, %r13
	andl $67108863, %r14d
	andl $67108863, %r11d
	andl $67108863, %eax
	movl %r8d, 88(%rdi)
	cmpq $64, %r10
	movl %r8d, 80(%rdi)
	movl %r14d, 104(%rdi)
	movl %r14d, 96(%rdi)
	movl %r11d, 120(%rdi)
	movl %r11d, 112(%rdi)
	movl %eax, 136(%rdi)
	movl %eax, 128(%rdi)
	movl %r13d, 152(%rdi)
	movl %r13d, 144(%rdi)
	jbe .Lpoly1305_init_ext_sse2_done
	lea (%r9,%r9,4), %r14
	shlq $2, %r14
	lea (%r12,%r12), %rax
	mulq %r14
	movq %rax, %r8
	movq %rcx, %rax
	movq %rdx, %r10
	mulq %rcx
	addq %rax, %r8
	lea (%rcx,%rcx), %rax
	movq %r8, %r11
	adcq %rdx, %r10
	andq %rsi, %r8
	mulq %r12
	shlq $20, %r10
	movq %rax, %r13
	shrq $44, %r11
	movq %r9, %rax
	orq %r11, %r10
	movq %rdx, %r11
	mulq %r14
	addq %rax, %r13
	movq %rcx, %rax
	adcq %rdx, %r11
	addq %r9, %r9
	mulq %r9
	addq %r13, %r10
	movq %rax, %r9
	movq %r12, %rax
	movq %rdx, %rcx
	adcq $0, %r11
	mulq %r12
	addq %rax, %r9
	movq %r10, %r13
	adcq %rdx, %rcx
	andq %rsi, %r10
	shlq $20, %r11
	shrq $44, %r13
	orq %r13, %r11
	addq %r9, %r11
	movq %rsi, %r9
	movq %r11, %r12
	adcq $0, %rcx
	shlq $22, %rcx
	shrq $42, %r12
	orq %r12, %rcx
	lea (%rcx,%rcx,4), %rcx
	addq %rcx, %r8
	andq %r8, %r9
	shrq $44, %r8
	movl %r9d, %eax
	addq %r8, %r10
	movq $0x3ffffffffff, %r8
	andq %r10, %rsi
	andq %r8, %r11
	shrq $44, %r10
	movq %rsi, %r8
	addq %r10, %r11
	andl $67108863, %eax
	shrq $26, %r9
	movq %r11, %r10
	shlq $18, %r8
	shlq $10, %r10
	orq %r8, %r9
	movq %rsi, %r8
	shrq $34, %rsi
	andl $67108863, %r9d
	shrq $8, %r8
	orq %r10, %rsi
	shrq $16, %r11
	andl $67108863, %r8d
	andl $67108863, %esi
	movl %eax, 168(%rdi)
	movl %eax, 160(%rdi)
	movl %r9d, 184(%rdi)
	movl %r9d, 176(%rdi)
	movl %r8d, 200(%rdi)
	movl %r8d, 192(%rdi)
	movl %esi, 216(%rdi)
	movl %esi, 208(%rdi)
	movl %r11d, 232(%rdi)
	movl %r11d, 224(%rdi)
.Lpoly1305_init_ext_sse2_done:
	movq $0, 240(%rdi)
	popq %r14
	popq %r13
	popq %r12
	ret
ELF(.size _gcry_poly1305_amd64_sse2_init_ext,.-_gcry_poly1305_amd64_sse2_init_ext;)


.align 8
.globl _gcry_poly1305_amd64_sse2_finish_ext
ELF(.type  _gcry_poly1305_amd64_sse2_finish_ext,@function;)
_gcry_poly1305_amd64_sse2_finish_ext:
.Lpoly1305_finish_ext_x86_local:
	pushq %rbp
	movq %rsp, %rbp
	subq $64, %rsp
	andq $~63, %rsp
	movq %rdx, 32(%rsp)
	movq %rcx, 40(%rsp)
	andq %rdx, %rdx
	jz .Lpoly1305_finish_x86_no_leftover
	pxor %xmm0, %xmm0
	movdqa %xmm0, 0+0(%rsp)
	movdqa %xmm0, 16+0(%rsp)
	leaq 0(%rsp), %r8
	testq $16, %rdx
	jz .Lpoly1305_finish_x86_skip16
	movdqu 0(%rsi), %xmm0
	movdqa %xmm0, 0(%r8)
	addq $16, %rsi
	addq $16, %r8
.Lpoly1305_finish_x86_skip16:
	testq $8, %rdx
	jz .Lpoly1305_finish_x86_skip8
	movq 0(%rsi), %rax
	movq %rax, 0(%r8)
	addq $8, %rsi
	addq $8, %r8
.Lpoly1305_finish_x86_skip8:
	testq $4, %rdx
	jz .Lpoly1305_finish_x86_skip4
	movl 0(%rsi), %eax
	movl %eax, 0(%r8)
	addq $4, %rsi
	addq $4, %r8
.Lpoly1305_finish_x86_skip4:
	testq $2, %rdx
	jz .Lpoly1305_finish_x86_skip2
	movw 0(%rsi), %ax
	movw %ax, 0(%r8)
	addq $2, %rsi
	addq $2, %r8
.Lpoly1305_finish_x86_skip2:
	testq $1, %rdx
	jz .Lpoly1305_finish_x86_skip1
	movb 0(%rsi), %al
	movb %al, 0(%r8)
	addq $1, %r8
.Lpoly1305_finish_x86_skip1:
	cmpq $16, %rdx
	je .Lpoly1305_finish_x86_is16
	movb $1, 0(%r8)
.Lpoly1305_finish_x86_is16:
	movq $4, %rax
	jae .Lpoly1305_finish_x86_16andover
	movq $8, %rax
.Lpoly1305_finish_x86_16andover:
	orq %rax, 240(%rdi)
	leaq 0(%rsp), %rsi
	movq $32, %rdx
	callq .Lpoly1305_blocks_x86_local
.Lpoly1305_finish_x86_no_leftover:
	testq $1, 240(%rdi)
	jz .Lpoly1305_finish_x86_not_started
	movq 32(%rsp), %rdx
	andq %rdx, %rdx
	jz .Lpoly1305_finish_x86_r2r
	cmpq $16, %rdx
	jg .Lpoly1305_finish_x86_r2r
	xorl %r10d, %r10d
	movl 84(%rdi), %eax
	movl 92(%rdi), %ecx
	movl 100(%rdi), %edx
	movl 108(%rdi), %r8d
	movl 116(%rdi), %r9d
	movl %eax, 80(%rdi)
	movl $1, 8+80(%rdi)
	movl %ecx, 96(%rdi)
	movl %r10d, 8+96(%rdi)
	movl %edx, 112(%rdi)
	movl %r10d, 8+112(%rdi)
	movl %r8d, 128(%rdi)
	movl %r10d, 8+128(%rdi)
	movl %r9d, 144(%rdi)
	movl %r10d, 8+144(%rdi)
	jmp .Lpoly1305_finish_x86_combine
.Lpoly1305_finish_x86_r2r:
	movl 84(%rdi), %eax
	movl 92(%rdi), %ecx
	movl 100(%rdi), %edx
	movl 108(%rdi), %r8d
	movl 116(%rdi), %r9d
	movl %eax, 8+80(%rdi)
	movl %ecx, 8+96(%rdi)
	movl %edx, 8+112(%rdi)
	movl %r8d, 8+128(%rdi)
	movl %r9d, 8+144(%rdi)
.Lpoly1305_finish_x86_combine:
	xorq %rsi, %rsi
	movq $32, %rdx
	callq .Lpoly1305_blocks_x86_local
.Lpoly1305_finish_x86_not_started:
	movq 0(%rdi), %r8
	movq 8(%rdi), %r9
	movq %r9, %r10
	movq 16(%rdi), %r11
	shlq $44, %r9
	shrq $20, %r10
	shlq $24, %r11
	orq %r9, %r8
	orq %r11, %r10
	pxor %xmm0, %xmm0
	movl 124(%rdi), %eax
	movl 132(%rdi), %ecx
	movl 140(%rdi), %edx
	movl 148(%rdi), %esi
	movq 40(%rsp), %r11
	shlq $32, %rcx
	shlq $32, %rsi
	orq %rcx, %rax
	orq %rsi, %rdx
	addq %r8, %rax
	adcq %r10, %rdx
	movq %rax, 0(%r11)
	movq %rdx, 8(%r11)
	movq %rbp, %rax
	subq %rsp, %rax
	movq %rbp, %rsp
	movdqa %xmm0, 0(%rdi)
	movdqa %xmm0, 16(%rdi)
	movdqa %xmm0, 32(%rdi)
	movdqa %xmm0, 48(%rdi)
	movdqa %xmm0, 64(%rdi)
	movdqa %xmm0, 80(%rdi)
	movdqa %xmm0, 96(%rdi)
	movdqa %xmm0, 112(%rdi)
	movdqa %xmm0, 128(%rdi)
	movdqa %xmm0, 144(%rdi)
	movdqa %xmm0, 160(%rdi)
	movdqa %xmm0, 176(%rdi)
	movdqa %xmm0, 192(%rdi)
	movdqa %xmm0, 208(%rdi)
	movdqa %xmm0, 224(%rdi)
	popq %rbp
	addq $8, %rax
	ret
ELF(.size _gcry_poly1305_amd64_sse2_finish_ext,.-_gcry_poly1305_amd64_sse2_finish_ext;)


.align 8
.globl _gcry_poly1305_amd64_sse2_blocks
ELF(.type  _gcry_poly1305_amd64_sse2_blocks,@function;)
_gcry_poly1305_amd64_sse2_blocks:
.Lpoly1305_blocks_x86_local:
	pushq %rbp
	movq %rsp, %rbp
	pushq %rbx
	andq $-64, %rsp
	subq $328, %rsp
	movq 240(%rdi), %rax
	movl $(1<<24), %r8d
	movl $((1<<26)-1), %r9d
	movd %r8, %xmm0
	movd %r9, %xmm5
	pshufd $0x44, %xmm0, %xmm0
	pshufd $0x44, %xmm5, %xmm5
	testb $4, %al
	je .Lpoly1305_blocks_x86_3
	psrldq $8, %xmm0
.Lpoly1305_blocks_x86_3:
	testb $8, %al
	je .Lpoly1305_blocks_x86_4
	pxor %xmm0, %xmm0
.Lpoly1305_blocks_x86_4:
	movdqa %xmm0, 168(%rsp)
	testb $1, %al
	jne .Lpoly1305_blocks_x86_5
	movq 16(%rsi), %xmm0
	movdqa %xmm5, %xmm7
	movdqa %xmm5, %xmm10
	movq (%rsi), %xmm6
	orq $1, %rax
	subq $32, %rdx
	movq 8(%rsi), %xmm1
	punpcklqdq %xmm0, %xmm6
	movq 24(%rsi), %xmm0
	pand %xmm6, %xmm7
	movdqa %xmm6, %xmm9
	psrlq $52, %xmm6
	addq $32, %rsi
	punpcklqdq %xmm0, %xmm1
	movdqa %xmm1, %xmm0
	psrlq $26, %xmm9
	psllq $12, %xmm0
	movq %rax, 240(%rdi)
	pand %xmm5, %xmm9
	por %xmm0, %xmm6
	psrlq $40, %xmm1
	pand %xmm6, %xmm10
	por 168(%rsp), %xmm1
	psrlq $26, %xmm6
	pand %xmm5, %xmm6
.Lpoly1305_blocks_x86_6:
	movdqa 80(%rdi), %xmm13
	cmpq $63, %rdx
	movl $(5), %r8d
	movd %r8, %xmm14
	pshufd $0x44, %xmm14, %xmm14
	movdqa 96(%rdi), %xmm15
	movdqa %xmm13, -8(%rsp)
	movdqa 112(%rdi), %xmm0
	movdqa %xmm14, 136(%rsp)
	movdqa 128(%rdi), %xmm3
	movdqa %xmm15, 312(%rsp)
	pmuludq %xmm14, %xmm15
	movdqa 144(%rdi), %xmm13
	movdqa %xmm0, 232(%rsp)
	pmuludq %xmm14, %xmm0
	movdqa %xmm3, 152(%rsp)
	pmuludq %xmm14, %xmm3
	movdqa %xmm13, 56(%rsp)
	pmuludq %xmm14, %xmm13
	movdqa %xmm15, 40(%rsp)
	movdqa %xmm0, -24(%rsp)
	movdqa %xmm3, -40(%rsp)
	movdqa %xmm13, -56(%rsp)
	jbe .Lpoly1305_blocks_x86_7
	movdqa 192(%rdi), %xmm15
	leaq 32(%rsi), %rax
	movq %rdx, %rcx
	movdqa 176(%rdi), %xmm14
	movdqa %xmm15, %xmm2
	movdqa 208(%rdi), %xmm0
	movdqa %xmm15, 216(%rsp)
	movdqa %xmm14, 296(%rsp)
	movdqa 224(%rdi), %xmm3
	pmuludq 136(%rsp), %xmm14
	movdqa -24(%rsp), %xmm13
	movdqa %xmm14, 8(%rsp)
	pmuludq 136(%rsp), %xmm2
	movdqa -40(%rsp), %xmm14
	movdqa %xmm0, 120(%rsp)
	pmuludq 136(%rsp), %xmm0
	movdqa %xmm3, 24(%rsp)
	movdqa 160(%rdi), %xmm12
	movdqa %xmm0, %xmm8
	movdqa -56(%rsp), %xmm15
	movdqa %xmm13, 88(%rsp)
	pmuludq 136(%rsp), %xmm3
	movdqa %xmm2, 104(%rsp)
	movdqa %xmm0, %xmm13
	movdqa -8(%rsp), %xmm11
	movdqa %xmm3, 280(%rsp)
	movdqa %xmm2, %xmm3
	movdqa %xmm0, 200(%rsp)
	movdqa %xmm14, 184(%rsp)
	movdqa %xmm15, 264(%rsp)
	jmp .Lpoly1305_blocks_x86_8
.p2align 6,,63
.Lpoly1305_blocks_x86_13:
	movdqa 200(%rsp), %xmm13
	movdqa %xmm3, %xmm6
	movdqa 200(%rsp), %xmm8
	movdqa 104(%rsp), %xmm3
.Lpoly1305_blocks_x86_8:
	movdqa 8(%rsp), %xmm4
	pmuludq %xmm6, %xmm3
	subq $64, %rcx
	pmuludq %xmm10, %xmm8
	movdqa 104(%rsp), %xmm2
	movdqa 200(%rsp), %xmm0
	pmuludq %xmm1, %xmm4
	movdqa 280(%rsp), %xmm15
	pmuludq %xmm6, %xmm13
	movdqa 280(%rsp), %xmm14
	pmuludq %xmm1, %xmm0
	paddq %xmm3, %xmm4
	pmuludq %xmm1, %xmm2
	movdqa 280(%rsp), %xmm3
	paddq %xmm8, %xmm4
	pmuludq %xmm9, %xmm15
	movdqa 280(%rsp), %xmm8
	pmuludq %xmm10, %xmm14
	pmuludq %xmm6, %xmm8
	paddq %xmm13, %xmm2
	movdqa %xmm6, %xmm13
	pmuludq %xmm1, %xmm3
	paddq %xmm15, %xmm4
	movdqa 296(%rsp), %xmm15
	pmuludq %xmm12, %xmm13
	paddq %xmm14, %xmm2
	movdqa %xmm7, %xmm14
	paddq %xmm8, %xmm0
	pmuludq %xmm12, %xmm14
	movdqa %xmm9, %xmm8
	pmuludq 296(%rsp), %xmm6
	pmuludq %xmm12, %xmm8
	movdqa %xmm6, 248(%rsp)
	pmuludq %xmm10, %xmm15
	movq -16(%rax), %xmm6
	paddq %xmm13, %xmm3
	movdqa %xmm10, %xmm13
	paddq %xmm14, %xmm4
	movq -8(%rax), %xmm14
	paddq %xmm8, %xmm2
	movq -32(%rax), %xmm8
	pmuludq %xmm12, %xmm13
	paddq %xmm15, %xmm3
	pmuludq %xmm12, %xmm1
	movdqa 216(%rsp), %xmm15
	pmuludq 216(%rsp), %xmm10
	punpcklqdq %xmm6, %xmm8
	movq -24(%rax), %xmm6
	pmuludq %xmm9, %xmm15
	paddq %xmm13, %xmm0
	movdqa 296(%rsp), %xmm13
	paddq 248(%rsp), %xmm1
	punpcklqdq %xmm14, %xmm6
	movdqa 296(%rsp), %xmm14
	pmuludq %xmm9, %xmm13
	pmuludq 120(%rsp), %xmm9
	movdqa %xmm15, 72(%rsp)
	paddq %xmm10, %xmm1
	movdqa 216(%rsp), %xmm15
	pmuludq %xmm7, %xmm14
	movdqa %xmm6, %xmm10
	paddq %xmm9, %xmm1
	pmuludq %xmm7, %xmm15
	paddq %xmm13, %xmm0
	paddq 72(%rsp), %xmm3
	movdqa 120(%rsp), %xmm13
	psllq $12, %xmm10
	paddq %xmm14, %xmm2
	movdqa %xmm5, %xmm14
	pand %xmm8, %xmm14
	pmuludq %xmm7, %xmm13
	paddq %xmm15, %xmm0
	movdqa %xmm14, 248(%rsp)
	movdqa %xmm8, %xmm14
	psrlq $52, %xmm8
	movdqu (%rax), %xmm9
	por %xmm10, %xmm8
	pmuludq 24(%rsp), %xmm7
	movdqu 16(%rax), %xmm10
	paddq %xmm13, %xmm3
	pxor %xmm13, %xmm13
	movdqa %xmm9, %xmm15
	paddq %xmm7, %xmm1
	movdqa %xmm6, %xmm7
	movdqa %xmm10, -72(%rsp)
	punpckldq %xmm10, %xmm15
	movdqa %xmm15, %xmm10
	punpckldq %xmm13, %xmm10
	punpckhdq -72(%rsp), %xmm9
	psrlq $40, %xmm6
	movdqa %xmm10, 72(%rsp)
	movdqa %xmm9, %xmm10
	punpckhdq %xmm13, %xmm9
	psllq $18, %xmm9
	paddq 72(%rsp), %xmm4
	addq $64, %rax
	paddq %xmm9, %xmm3
	movdqa 40(%rsp), %xmm9
	cmpq $63, %rcx
	punpckhdq %xmm13, %xmm15
	psllq $6, %xmm15
	punpckldq %xmm13, %xmm10
	paddq %xmm15, %xmm2
	psllq $12, %xmm10
	por 168(%rsp), %xmm6
	pmuludq %xmm6, %xmm9
	movdqa 88(%rsp), %xmm15
	paddq %xmm10, %xmm0
	movdqa 88(%rsp), %xmm13
	psrlq $14, %xmm7
	pand %xmm5, %xmm8
	movdqa 184(%rsp), %xmm10
	pand %xmm5, %xmm7
	pmuludq %xmm7, %xmm15
	paddq %xmm9, %xmm4
	pmuludq %xmm6, %xmm13
	movdqa 184(%rsp), %xmm9
	paddq 168(%rsp), %xmm1
	pmuludq %xmm7, %xmm10
	pmuludq %xmm6, %xmm9
	paddq %xmm15, %xmm4
	movdqa 184(%rsp), %xmm15
	paddq %xmm13, %xmm2
	psrlq $26, %xmm14
	movdqa 264(%rsp), %xmm13
	paddq %xmm10, %xmm2
	pmuludq %xmm8, %xmm15
	pand %xmm5, %xmm14
	paddq %xmm9, %xmm0
	pmuludq %xmm6, %xmm13
	movdqa 264(%rsp), %xmm9
	movdqa 264(%rsp), %xmm10
	pmuludq %xmm11, %xmm6
	pmuludq %xmm8, %xmm9
	paddq %xmm15, %xmm4
	movdqa 264(%rsp), %xmm15
	pmuludq %xmm14, %xmm10
	paddq %xmm13, %xmm3
	movdqa %xmm7, %xmm13
	pmuludq %xmm7, %xmm15
	paddq %xmm6, %xmm1
	movdqa 312(%rsp), %xmm6
	paddq %xmm9, %xmm2
	pmuludq %xmm11, %xmm13
	movdqa 248(%rsp), %xmm9
	paddq %xmm10, %xmm4
	pmuludq %xmm8, %xmm6
	pmuludq 312(%rsp), %xmm7
	paddq %xmm15, %xmm0
	movdqa %xmm9, %xmm10
	movdqa %xmm14, %xmm15
	pmuludq %xmm11, %xmm10
	paddq %xmm13, %xmm3
	movdqa %xmm8, %xmm13
	pmuludq %xmm11, %xmm13
	paddq %xmm6, %xmm3
	paddq %xmm7, %xmm1
	movdqa 232(%rsp), %xmm6
	pmuludq %xmm11, %xmm15
	pmuludq 232(%rsp), %xmm8
	paddq %xmm10, %xmm4
	paddq %xmm8, %xmm1
	movdqa 312(%rsp), %xmm10
	paddq %xmm13, %xmm0
	pmuludq %xmm14, %xmm6
	movdqa 312(%rsp), %xmm13
	pmuludq %xmm9, %xmm10
	paddq %xmm15, %xmm2
	movdqa 232(%rsp), %xmm7
	pmuludq %xmm14, %xmm13
	pmuludq 152(%rsp), %xmm14
	paddq %xmm14, %xmm1
	pmuludq %xmm9, %xmm7
	paddq %xmm6, %xmm3
	paddq %xmm10, %xmm2
	movdqa 152(%rsp), %xmm10
	paddq %xmm13, %xmm0
	pmuludq %xmm9, %xmm10
	paddq %xmm7, %xmm0
	movdqa %xmm4, %xmm7
	psrlq $26, %xmm7
	pmuludq 56(%rsp), %xmm9
	pand %xmm5, %xmm4
	paddq %xmm7, %xmm2
	paddq %xmm9, %xmm1
	paddq %xmm10, %xmm3
	movdqa %xmm2, %xmm7
	movdqa %xmm2, %xmm9
	movdqa %xmm3, %xmm6
	psrlq $26, %xmm7
	pand %xmm5, %xmm3
	psrlq $26, %xmm6
	paddq %xmm7, %xmm0
	pand %xmm5, %xmm9
	paddq %xmm6, %xmm1
	movdqa %xmm0, %xmm10
	movdqa %xmm1, %xmm6
	pand %xmm5, %xmm10
	pand %xmm5, %xmm1
	psrlq $26, %xmm6
	pmuludq 136(%rsp), %xmm6
	paddq %xmm6, %xmm4
	movdqa %xmm0, %xmm6
	psrlq $26, %xmm6
	movdqa %xmm4, %xmm2
	movdqa %xmm4, %xmm7
	paddq %xmm6, %xmm3
	psrlq $26, %xmm2
	pand %xmm5, %xmm7
	movdqa %xmm3, %xmm0
	paddq %xmm2, %xmm9
	pand %xmm5, %xmm3
	psrlq $26, %xmm0
	paddq %xmm0, %xmm1
	ja .Lpoly1305_blocks_x86_13
	leaq -64(%rdx), %rax
	movdqa %xmm3, %xmm6
	andl $63, %edx
	andq $-64, %rax
	leaq 64(%rsi,%rax), %rsi
.Lpoly1305_blocks_x86_7:
	cmpq $31, %rdx
	jbe .Lpoly1305_blocks_x86_9
	movdqa -24(%rsp), %xmm13
	movdqa %xmm6, %xmm0
	movdqa %xmm6, %xmm3
	movdqa 40(%rsp), %xmm11
	movdqa %xmm1, %xmm12
	testq %rsi, %rsi
	movdqa -40(%rsp), %xmm2
	pmuludq %xmm13, %xmm0
	movdqa %xmm1, %xmm8
	pmuludq %xmm1, %xmm11
	movdqa %xmm10, %xmm4
	movdqa %xmm1, %xmm14
	pmuludq %xmm2, %xmm3
	movdqa %xmm6, %xmm15
	pmuludq %xmm1, %xmm13
	movdqa %xmm7, %xmm1
	pmuludq %xmm2, %xmm12
	paddq %xmm0, %xmm11
	movdqa -56(%rsp), %xmm0
	pmuludq %xmm10, %xmm2
	paddq %xmm3, %xmm13
	pmuludq %xmm0, %xmm4
	movdqa %xmm9, %xmm3
	pmuludq %xmm0, %xmm3
	paddq %xmm2, %xmm11
	pmuludq %xmm0, %xmm8
	movdqa %xmm6, %xmm2
	pmuludq %xmm0, %xmm2
	movdqa -8(%rsp), %xmm0
	paddq %xmm4, %xmm13
	movdqa 312(%rsp), %xmm4
	paddq %xmm3, %xmm11
	pmuludq 312(%rsp), %xmm6
	movdqa 312(%rsp), %xmm3
	pmuludq %xmm0, %xmm1
	paddq %xmm2, %xmm12
	pmuludq %xmm0, %xmm15
	movdqa %xmm9, %xmm2
	pmuludq %xmm0, %xmm2
	pmuludq %xmm7, %xmm3
	paddq %xmm1, %xmm11
	movdqa 232(%rsp), %xmm1
	pmuludq %xmm0, %xmm14
	paddq %xmm15, %xmm8
	pmuludq %xmm10, %xmm0
	paddq %xmm2, %xmm13
	movdqa 312(%rsp), %xmm2
	pmuludq %xmm10, %xmm4
	paddq %xmm3, %xmm13
	movdqa 152(%rsp), %xmm3
	pmuludq %xmm9, %xmm2
	paddq %xmm6, %xmm14
	pmuludq 232(%rsp), %xmm10
	paddq %xmm0, %xmm12
	pmuludq %xmm9, %xmm1
	paddq %xmm10, %xmm14
	movdqa 232(%rsp), %xmm0
	pmuludq %xmm7, %xmm3
	paddq %xmm4, %xmm8
	pmuludq 152(%rsp), %xmm9
	paddq %xmm2, %xmm12
	paddq %xmm9, %xmm14
	pmuludq %xmm7, %xmm0
	paddq %xmm1, %xmm8
	pmuludq 56(%rsp), %xmm7
	paddq %xmm3, %xmm8
	paddq %xmm7, %xmm14
	paddq %xmm0, %xmm12
	je .Lpoly1305_blocks_x86_10
	movdqu (%rsi), %xmm1
	pxor %xmm0, %xmm0
	paddq 168(%rsp), %xmm14
	movdqu 16(%rsi), %xmm2
	movdqa %xmm1, %xmm3
	punpckldq %xmm2, %xmm3
	punpckhdq %xmm2, %xmm1
	movdqa %xmm3, %xmm4
	movdqa %xmm1, %xmm2
	punpckldq %xmm0, %xmm4
	punpckhdq %xmm0, %xmm3
	punpckhdq %xmm0, %xmm1
	punpckldq %xmm0, %xmm2
	movdqa %xmm2, %xmm0
	psllq $6, %xmm3
	paddq %xmm4, %xmm11
	psllq $12, %xmm0
	paddq %xmm3, %xmm13
	psllq $18, %xmm1
	paddq %xmm0, %xmm12
	paddq %xmm1, %xmm8
.Lpoly1305_blocks_x86_10:
	movdqa %xmm11, %xmm9
	movdqa %xmm8, %xmm1
	movdqa %xmm11, %xmm7
	psrlq $26, %xmm9
	movdqa %xmm8, %xmm6
	pand %xmm5, %xmm7
	paddq %xmm13, %xmm9
	psrlq $26, %xmm1
	pand %xmm5, %xmm6
	movdqa %xmm9, %xmm10
	paddq %xmm14, %xmm1
	pand %xmm5, %xmm9
	psrlq $26, %xmm10
	movdqa %xmm1, %xmm0
	pand %xmm5, %xmm1
	paddq %xmm12, %xmm10
	psrlq $26, %xmm0
	pmuludq 136(%rsp), %xmm0
	movdqa %xmm10, %xmm2
	paddq %xmm0, %xmm7
	psrlq $26, %xmm2
	movdqa %xmm7, %xmm0
	pand %xmm5, %xmm10
	paddq %xmm2, %xmm6
	psrlq $26, %xmm0
	pand %xmm5, %xmm7
	movdqa %xmm6, %xmm2
	paddq %xmm0, %xmm9
	pand %xmm5, %xmm6
	psrlq $26, %xmm2
	paddq %xmm2, %xmm1
.Lpoly1305_blocks_x86_9:
	testq %rsi, %rsi
	je .Lpoly1305_blocks_x86_11
	movdqa %xmm7, 0(%rdi)
	movdqa %xmm9, 16(%rdi)
	movdqa %xmm10, 32(%rdi)
	movdqa %xmm6, 48(%rdi)
	movdqa %xmm1, 64(%rdi)
	movq -8(%rbp), %rbx
	leave
	ret
.Lpoly1305_blocks_x86_5:
	movdqa 0(%rdi), %xmm7
	movdqa 16(%rdi), %xmm9
	movdqa 32(%rdi), %xmm10
	movdqa 48(%rdi), %xmm6
	movdqa 64(%rdi), %xmm1
	jmp .Lpoly1305_blocks_x86_6
.Lpoly1305_blocks_x86_11:
	movdqa %xmm7, %xmm0
	movdqa %xmm9, %xmm2
	movdqa %xmm6, %xmm3
	psrldq $8, %xmm0
	movabsq $4398046511103, %rbx
	paddq %xmm0, %xmm7
	psrldq $8, %xmm2
	movdqa %xmm10, %xmm0
	movd %xmm7, %edx
	paddq %xmm2, %xmm9
	psrldq $8, %xmm0
	movl %edx, %ecx
	movd %xmm9, %eax
	paddq %xmm0, %xmm10
	shrl $26, %ecx
	psrldq $8, %xmm3
	movdqa %xmm1, %xmm0
	addl %ecx, %eax
	movd %xmm10, %ecx
	paddq %xmm3, %xmm6
	movl %eax, %r9d
	shrl $26, %eax
	psrldq $8, %xmm0
	addl %ecx, %eax
	movd %xmm6, %ecx
	paddq %xmm0, %xmm1
	movl %eax, %esi
	andl $67108863, %r9d
	movd %xmm1, %r10d
	shrl $26, %esi
	andl $67108863, %eax
	andl $67108863, %edx
	addl %ecx, %esi
	salq $8, %rax
	movl %r9d, %ecx
	shrl $18, %r9d
	movl %esi, %r8d
	shrl $26, %esi
	andl $67108863, %r8d
	addl %r10d, %esi
	orq %r9, %rax
	salq $16, %rsi
	movq %r8, %r9
	shrl $10, %r8d
	salq $26, %rcx
	orq %r8, %rsi
	salq $34, %r9
	orq %rdx, %rcx
	movq %rsi, %r8
	shrq $42, %rsi
	movabsq $17592186044415, %rdx
	orq %r9, %rax
	andq %rbx, %r8
	leaq (%rsi,%rsi,4), %rsi
	andq %rdx, %rcx
	andq %rdx, %rax
	movabsq $-4398046511104, %r10
	addq %rsi, %rcx
	movq %rcx, %rsi
	shrq $44, %rcx
	addq %rcx, %rax
	andq %rdx, %rsi
	movq %rax, %rcx
	shrq $44, %rax
	addq %r8, %rax
	andq %rdx, %rcx
	andq %rax, %rbx
	shrq $42, %rax
	leaq (%rsi,%rax,4), %rsi
	addq %rbx, %r10
	addq %rax, %rsi
	movq %rsi, %r8
	shrq $44, %rsi
	andq %rdx, %r8
	addq %rcx, %rsi
	leaq 5(%r8), %r9
	movq %r9, %r11
	andq %rdx, %r9
	shrq $44, %r11
	addq %rsi, %r11
	movq %r11, %rax
	andq %r11, %rdx
	shrq $44, %rax
	addq %rax, %r10
	movq %r10, %rax
	shrq $63, %rax
	subq $1, %rax
	movq %rax, %rcx
	andq %rax, %r9
	andq %rax, %rdx
	notq %rcx
	andq %r10, %rax
	andq %rcx, %r8
	andq %rcx, %rsi
	andq %rbx, %rcx
	orq %r9, %r8
	orq %rdx, %rsi
	orq %rax, %rcx
	movq %r8, 0(%rdi)
	movq %rsi, 8(%rdi)
	movq %rcx, 16(%rdi)
	movq -8(%rbp), %rbx
	movq %rbp, %rax
	subq %rsp, %rax
	pxor %xmm15, %xmm15
	pxor %xmm7, %xmm7
	pxor %xmm14, %xmm14
	pxor %xmm6, %xmm6
	pxor %xmm13, %xmm13
	pxor %xmm5, %xmm5
	pxor %xmm12, %xmm12
	pxor %xmm4, %xmm4
	leave
	addq $8, %rax
	pxor %xmm11, %xmm11
	pxor %xmm3, %xmm3
	pxor %xmm10, %xmm10
	pxor %xmm2, %xmm2
	pxor %xmm9, %xmm9
	pxor %xmm1, %xmm1
	pxor %xmm8, %xmm8
	pxor %xmm0, %xmm0
	ret
ELF(.size _gcry_poly1305_amd64_sse2_blocks,.-_gcry_poly1305_amd64_sse2_blocks;)

#endif
