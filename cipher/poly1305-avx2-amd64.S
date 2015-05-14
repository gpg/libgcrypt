/* poly1305-avx2-amd64.S  -  AMD64/AVX2 implementation of Poly1305
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
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS)) && \
    defined(ENABLE_AVX2_SUPPORT)

#ifdef HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS
# define ELF(...) __VA_ARGS__
#else
# define ELF(...) /*_*/
#endif


.text


.align 8
.globl _gcry_poly1305_amd64_avx2_init_ext
ELF(.type  _gcry_poly1305_amd64_avx2_init_ext,@function;)
_gcry_poly1305_amd64_avx2_init_ext:
.Lpoly1305_init_ext_avx2_local:
	xor %edx, %edx
	vzeroupper
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	pushq %rbx
	movq %rdx, %rcx
	vpxor %ymm0, %ymm0, %ymm0
	movq $-1, %r8
	testq %rcx, %rcx
	vmovdqu %ymm0, (%rdi)
	vmovdqu %ymm0, 32(%rdi)
	vmovdqu %ymm0, 64(%rdi)
	vmovdqu %ymm0, 96(%rdi)
	vmovdqu %ymm0, 128(%rdi)
	movq 8(%rsi), %r9
	cmove %r8, %rcx
	movq $0xffc0fffffff, %r8
	movq %r9, %r13
	movq (%rsi), %r10
	andq %r10, %r8
	shrq $44, %r10
	movq %r8, %r14
	shlq $20, %r13
	orq %r13, %r10
	movq $0xfffffc0ffff, %r13
	shrq $24, %r9
	andq %r13, %r10
	movq $0xffffffc0f, %r13
	andq %r13, %r9
	movl %r8d, %r13d
	andl $67108863, %r13d
	movl %r13d, 164(%rdi)
	movq %r10, %r13
	shrq $26, %r14
	shlq $18, %r13
	orq %r13, %r14
	movq %r10, %r13
	shrq $8, %r13
	andl $67108863, %r14d
	andl $67108863, %r13d
	movl %r14d, 172(%rdi)
	movq %r10, %r14
	movl %r13d, 180(%rdi)
	movq %r9, %r13
	shrq $34, %r14
	shlq $10, %r13
	orq %r13, %r14
	movq %r9, %r13
	shrq $16, %r13
	andl $67108863, %r14d
	movl %r14d, 188(%rdi)
	movl %r13d, 196(%rdi)
	cmpq $16, %rcx
	jbe .Lpoly1305_init_ext_avx2_continue
	lea (%r9,%r9,4), %r11
	shlq $2, %r11
	lea (%r10,%r10), %rax
	mulq %r11
	movq %rax, %r13
	movq %r8, %rax
	movq %rdx, %r14
	mulq %r8
	addq %rax, %r13
	lea (%r8,%r8), %rax
	movq %r13, %r12
	adcq %rdx, %r14
	mulq %r10
	shlq $20, %r14
	movq %rax, %r15
	shrq $44, %r12
	movq %r11, %rax
	orq %r12, %r14
	movq %rdx, %r12
	mulq %r9
	addq %rax, %r15
	movq %r8, %rax
	adcq %rdx, %r12
	addq %r15, %r14
	lea (%r9,%r9), %r15
	movq %r14, %rbx
	adcq $0, %r12
	mulq %r15
	shlq $20, %r12
	movq %rdx, %r11
	shrq $44, %rbx
	orq %rbx, %r12
	movq %rax, %rbx
	movq %r10, %rax
	mulq %r10
	addq %rax, %rbx
	adcq %rdx, %r11
	addq %rbx, %r12
	movq $0xfffffffffff, %rbx
	movq %r12, %r15
	adcq $0, %r11
	andq %rbx, %r13
	shlq $22, %r11
	andq %rbx, %r14
	shrq $42, %r15
	orq %r15, %r11
	lea (%r11,%r11,4), %r11
	addq %r11, %r13
	movq %rbx, %r11
	andq %r13, %r11
	shrq $44, %r13
	movq %r11, %r15
	addq %r13, %r14
	movq $0x3ffffffffff, %r13
	andq %r14, %rbx
	andq %r13, %r12
	movq %rbx, %r13
	shrq $26, %r15
	shlq $18, %r13
	orq %r13, %r15
	movq %rbx, %r13
	shrq $44, %r14
	shrq $8, %r13
	addq %r14, %r12
	movl %r11d, %r14d
	andl $67108863, %r15d
	andl $67108863, %r14d
	andl $67108863, %r13d
	movl %r14d, 204(%rdi)
	movq %rbx, %r14
	movl %r13d, 220(%rdi)
	movq %r12, %r13
	shrq $34, %r14
	shlq $10, %r13
	orq %r13, %r14
	movq %r12, %r13
	shrq $16, %r13
	andl $67108863, %r14d
	movl %r15d, 212(%rdi)
	movl %r14d, 228(%rdi)
	movl %r13d, 236(%rdi)
	cmpq $32, %rcx
	jbe .Lpoly1305_init_ext_avx2_continue
	movq %r9, %rax
	lea (%rbx,%rbx,4), %r14
	shlq $2, %r14
	mulq %r14
	movq %rdi, -32(%rsp)
	lea (%r12,%r12,4), %rdi
	shlq $2, %rdi
	movq %rax, %r14
	movq %r10, %rax
	movq %rdx, %r15
	mulq %rdi
	movq %rax, %r13
	movq %r11, %rax
	movq %rcx, -16(%rsp)
	movq %rdx, %rcx
	mulq %r8
	addq %rax, %r13
	movq %rdi, %rax
	movq %rsi, -24(%rsp)
	adcq %rdx, %rcx
	addq %r13, %r14
	adcq %rcx, %r15
	movq %r14, %rcx
	mulq %r9
	shlq $20, %r15
	movq %rax, %r13
	shrq $44, %rcx
	movq %r11, %rax
	orq %rcx, %r15
	movq %rdx, %rcx
	mulq %r10
	movq %rax, %rsi
	movq %rbx, %rax
	movq %rdx, %rdi
	mulq %r8
	addq %rax, %rsi
	movq %r11, %rax
	adcq %rdx, %rdi
	addq %rsi, %r13
	adcq %rdi, %rcx
	addq %r13, %r15
	movq %r15, %rdi
	adcq $0, %rcx
	mulq %r9
	shlq $20, %rcx
	movq %rdx, %rsi
	shrq $44, %rdi
	orq %rdi, %rcx
	movq %rax, %rdi
	movq %rbx, %rax
	mulq %r10
	movq %rax, %r9
	movq %r8, %rax
	movq %rdx, %r10
	movq $0xfffffffffff, %r8
	mulq %r12
	addq %rax, %r9
	adcq %rdx, %r10
	andq %r8, %r14
	addq %r9, %rdi
	adcq %r10, %rsi
	andq %r8, %r15
	addq %rdi, %rcx
	movq $0x3ffffffffff, %rdi
	movq %rcx, %r10
	adcq $0, %rsi
	andq %rdi, %rcx
	shlq $22, %rsi
	shrq $42, %r10
	orq %r10, %rsi
	movq -32(%rsp), %rdi
	lea (%rsi,%rsi,4), %r9
	movq %r8, %rsi
	addq %r9, %r14
	andq %r14, %rsi
	shrq $44, %r14
	addq %r14, %r15
	andq %r15, %r8
	shrq $44, %r15
	movq %r8, %r14
	addq %r15, %rcx
	movl %esi, %r15d
	movq %rcx, %r10
	movq %r8, %r9
	shrq $26, %rsi
	andl $67108863, %r15d
	shlq $18, %r14
	shrq $34, %r8
	orq %r14, %rsi
	shlq $10, %r10
	shrq $8, %r9
	orq %r10, %r8
	shrq $16, %rcx
	andl $67108863, %esi
	movl %esi, 252(%rdi)
	andl $67108863, %r9d
	movl %ecx, 276(%rdi)
	andl $67108863, %r8d
	movl %r15d, 244(%rdi)
	movl %r9d, 260(%rdi)
	movl %r8d, 268(%rdi)
	movq -16(%rsp), %rcx
	movq -24(%rsp), %rsi
.Lpoly1305_init_ext_avx2_continue:
	movl 16(%rsi), %r8d
	movl %r8d, 284(%rdi)
	movl 20(%rsi), %r9d
	movl %r9d, 292(%rdi)
	movl 24(%rsi), %r10d
	movl %r10d, 300(%rdi)
	movl 28(%rsi), %esi
	movl %esi, 308(%rdi)
	cmpq $48, %rcx
	jbe .Lpoly1305_init_ext_avx2_done
	lea (%r12,%r12,4), %r9
	shlq $2, %r9
	lea (%rbx,%rbx), %rax
	mulq %r9
	movq %rax, %rsi
	movq %r11, %rax
	movq %rdx, %r8
	mulq %r11
	addq %rax, %rsi
	lea (%r11,%r11), %rax
	movq %rsi, %r10
	adcq %rdx, %r8
	mulq %rbx
	movq %rax, %r13
	movq %r12, %rax
	movq %rdx, %rcx
	addq %r12, %r12
	mulq %r9
	addq %rax, %r13
	movq %r11, %rax
	movq $0xfffffffffff, %r9
	adcq %rdx, %rcx
	andq %r9, %rsi
	mulq %r12
	shlq $20, %r8
	movq %rax, %r11
	shrq $44, %r10
	movq %rbx, %rax
	orq %r10, %r8
	movq %rdx, %r12
	mulq %rbx
	addq %r13, %r8
	movq %r8, %r14
	adcq $0, %rcx
	andq %r9, %r8
	addq %rax, %r11
	adcq %rdx, %r12
	shlq $20, %rcx
	shrq $44, %r14
	orq %r14, %rcx
	addq %r11, %rcx
	movq %rcx, %rbx
	adcq $0, %r12
	shlq $22, %r12
	shrq $42, %rbx
	orq %rbx, %r12
	movq %r9, %rbx
	lea (%r12,%r12,4), %r15
	addq %r15, %rsi
	andq %rsi, %rbx
	shrq $44, %rsi
	movl %ebx, %r11d
	addq %rsi, %r8
	movq $0x3ffffffffff, %rsi
	andq %r8, %r9
	andq %rsi, %rcx
	shrq $44, %r8
	movq %r9, %rax
	addq %r8, %rcx
	movq %r9, %r8
	movq %rcx, %r10
	andl $67108863, %r11d
	shrq $26, %rbx
	shlq $18, %r8
	shrq $34, %r9
	orq %r8, %rbx
	shlq $10, %r10
	shrq $8, %rax
	orq %r10, %r9
	shrq $16, %rcx
	andl $67108863, %ebx
	andl $67108863, %eax
	andl $67108863, %r9d
	movl %r11d, 184(%rdi)
	movl %r11d, 176(%rdi)
	movl %r11d, 168(%rdi)
	movl %r11d, 160(%rdi)
	movl %ebx, 216(%rdi)
	movl %ebx, 208(%rdi)
	movl %ebx, 200(%rdi)
	movl %ebx, 192(%rdi)
	movl %eax, 248(%rdi)
	movl %eax, 240(%rdi)
	movl %eax, 232(%rdi)
	movl %eax, 224(%rdi)
	movl %r9d, 280(%rdi)
	movl %r9d, 272(%rdi)
	movl %r9d, 264(%rdi)
	movl %r9d, 256(%rdi)
	movl %ecx, 312(%rdi)
	movl %ecx, 304(%rdi)
	movl %ecx, 296(%rdi)
	movl %ecx, 288(%rdi)
.Lpoly1305_init_ext_avx2_done:
	movq $0, 320(%rdi)
	vzeroall
	popq %rbx
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	ret
ELF(.size _gcry_poly1305_amd64_avx2_init_ext,.-_gcry_poly1305_amd64_avx2_init_ext;)


.align 8
.globl _gcry_poly1305_amd64_avx2_blocks
ELF(.type  _gcry_poly1305_amd64_avx2_blocks,@function;)
_gcry_poly1305_amd64_avx2_blocks:
.Lpoly1305_blocks_avx2_local:
	vzeroupper
	pushq %rbp
	movq %rsp, %rbp
	pushq %rbx
	andq $-64, %rsp
	subq $200, %rsp
	movl $((1<<26)-1), %r8d
	movl $(5), %r9d
	movl $((1<<24)), %r10d
	vmovd %r8d, %xmm0
	vmovd %r9d, %xmm8
	vmovd %r10d, %xmm7
	vpbroadcastq %xmm0, %ymm0
	vpbroadcastq %xmm8, %ymm8
	vpbroadcastq %xmm7, %ymm7
	vmovdqa %ymm7, 168(%rsp)
	movq 320(%rdi), %rax
	testb $60, %al
	je .Lpoly1305_blocks_avx2_9
	vmovdqa 168(%rsp), %ymm7
	vpsrldq $8, %ymm7, %ymm1
	vmovdqa %ymm1, 168(%rsp)
	testb $4, %al
	je .Lpoly1305_blocks_avx2_10
	vpermq $192, %ymm1, %ymm7
	vmovdqa %ymm7, 168(%rsp)
.Lpoly1305_blocks_avx2_10:
	testb $8, %al
	je .Lpoly1305_blocks_avx2_11
	vpermq $240, 168(%rsp), %ymm7
	vmovdqa %ymm7, 168(%rsp)
.Lpoly1305_blocks_avx2_11:
	testb $16, %al
	je .Lpoly1305_blocks_avx2_12
	vpermq $252, 168(%rsp), %ymm6
	vmovdqa %ymm6, 168(%rsp)
.Lpoly1305_blocks_avx2_12:
	testb $32, %al
	je .Lpoly1305_blocks_avx2_9
	vpxor %xmm6, %xmm6, %xmm6
	vmovdqa %ymm6, 168(%rsp)
.Lpoly1305_blocks_avx2_9:
	testb $1, %al
	jne .Lpoly1305_blocks_avx2_13
	vmovdqu (%rsi), %ymm3
	vmovdqu 32(%rsi), %ymm1
	vpunpcklqdq %ymm1, %ymm3, %ymm2
	vpunpckhqdq %ymm1, %ymm3, %ymm1
	vpermq $216, %ymm2, %ymm2
	vpermq $216, %ymm1, %ymm1
	vpand %ymm2, %ymm0, %ymm5
	vpsrlq $26, %ymm2, %ymm4
	vpand %ymm4, %ymm0, %ymm4
	vpsllq $12, %ymm1, %ymm3
	vpsrlq $52, %ymm2, %ymm2
	vpor %ymm3, %ymm2, %ymm2
	vpand %ymm2, %ymm0, %ymm3
	vpsrlq $26, %ymm2, %ymm2
	vpand %ymm2, %ymm0, %ymm2
	vpsrlq $40, %ymm1, %ymm1
	vpor 168(%rsp), %ymm1, %ymm1
	addq $64, %rsi
	subq $64, %rdx
	orq $1, 320(%rdi)
	jmp .Lpoly1305_blocks_avx2_14
.Lpoly1305_blocks_avx2_13:
	vmovdqa (%rdi), %ymm5
	vmovdqa 32(%rdi), %ymm4
	vmovdqa 64(%rdi), %ymm3
	vmovdqa 96(%rdi), %ymm2
	vmovdqa 128(%rdi), %ymm1
.Lpoly1305_blocks_avx2_14:
	cmpq $63, %rdx
	jbe .Lpoly1305_blocks_avx2_15
	vmovdqa 160(%rdi), %ymm6
	vmovdqa %ymm8, 136(%rsp)
	vmovdqa 192(%rdi), %ymm7
	vpmuludq %ymm8, %ymm7, %ymm11
	vmovdqa %ymm11, 104(%rsp)
	vmovdqa 224(%rdi), %ymm11
	vmovdqa %ymm11, 72(%rsp)
	vpmuludq %ymm11, %ymm8, %ymm11
	vmovdqa %ymm11, 40(%rsp)
	vmovdqa 256(%rdi), %ymm11
	vmovdqa %ymm11, 8(%rsp)
	vpmuludq %ymm11, %ymm8, %ymm11
	vmovdqa %ymm11, -24(%rsp)
	vmovdqa 288(%rdi), %ymm13
	vmovdqa %ymm13, -56(%rsp)
	vpmuludq %ymm13, %ymm8, %ymm13
	vmovdqa %ymm13, -88(%rsp)
.Lpoly1305_blocks_avx2_16:
	vpmuludq 104(%rsp), %ymm1, %ymm14
	vmovdqa 40(%rsp), %ymm13
	vpmuludq %ymm13, %ymm2, %ymm8
	vpmuludq %ymm13, %ymm1, %ymm13
	vmovdqa -24(%rsp), %ymm9
	vpmuludq %ymm9, %ymm2, %ymm10
	vpmuludq %ymm9, %ymm1, %ymm11
	vpaddq %ymm8, %ymm14, %ymm14
	vpmuludq %ymm9, %ymm3, %ymm8
	vmovdqa -88(%rsp), %ymm12
	vpmuludq %ymm12, %ymm1, %ymm9
	vpaddq %ymm10, %ymm13, %ymm13
	vpmuludq %ymm12, %ymm4, %ymm15
	vmovdqa %ymm12, %ymm10
	vpmuludq %ymm12, %ymm3, %ymm12
	vpaddq %ymm8, %ymm14, %ymm14
	vpmuludq %ymm10, %ymm2, %ymm10
	vpmuludq %ymm6, %ymm2, %ymm8
	vpaddq %ymm15, %ymm14, %ymm14
	vpmuludq %ymm6, %ymm1, %ymm1
	vpaddq %ymm12, %ymm13, %ymm13
	vpmuludq %ymm6, %ymm5, %ymm15
	vpaddq %ymm10, %ymm11, %ymm11
	vpmuludq %ymm6, %ymm4, %ymm12
	vpaddq %ymm8, %ymm9, %ymm9
	vpmuludq %ymm6, %ymm3, %ymm10
	vpmuludq %ymm7, %ymm3, %ymm8
	vpaddq %ymm15, %ymm14, %ymm14
	vpmuludq %ymm7, %ymm2, %ymm2
	vpaddq %ymm12, %ymm13, %ymm12
	vpmuludq %ymm7, %ymm5, %ymm15
	vpaddq %ymm10, %ymm11, %ymm10
	vpmuludq %ymm7, %ymm4, %ymm13
	vpaddq %ymm8, %ymm9, %ymm8
	vmovdqa 72(%rsp), %ymm9
	vpmuludq %ymm9, %ymm4, %ymm11
	vpaddq %ymm2, %ymm1, %ymm1
	vpmuludq %ymm9, %ymm3, %ymm3
	vpaddq %ymm15, %ymm12, %ymm12
	vpmuludq %ymm9, %ymm5, %ymm15
	vpaddq %ymm13, %ymm10, %ymm10
	vmovdqa 8(%rsp), %ymm2
	vpmuludq %ymm2, %ymm5, %ymm9
	vpaddq %ymm11, %ymm8, %ymm8
	vpmuludq %ymm2, %ymm4, %ymm4
	vpaddq %ymm3, %ymm1, %ymm1
	vpmuludq -56(%rsp), %ymm5, %ymm5
	vpaddq %ymm15, %ymm10, %ymm10
	vpaddq %ymm9, %ymm8, %ymm8
	vpaddq %ymm4, %ymm1, %ymm1
	vpaddq %ymm5, %ymm1, %ymm5
	vmovdqu (%rsi), %ymm3
	vmovdqu 32(%rsi), %ymm2
	vperm2i128 $32, %ymm2, %ymm3, %ymm1
	vperm2i128 $49, %ymm2, %ymm3, %ymm2
	vpunpckldq %ymm2, %ymm1, %ymm15
	vpunpckhdq %ymm2, %ymm1, %ymm2
	vpxor %xmm4, %xmm4, %xmm4
	vpunpckldq %ymm4, %ymm15, %ymm1
	vpunpckhdq %ymm4, %ymm15, %ymm15
	vpunpckldq %ymm4, %ymm2, %ymm3
	vpunpckhdq %ymm4, %ymm2, %ymm2
	vpsllq $6, %ymm15, %ymm15
	vpsllq $12, %ymm3, %ymm3
	vpsllq $18, %ymm2, %ymm2
	vpaddq %ymm1, %ymm14, %ymm14
	vpaddq %ymm15, %ymm12, %ymm12
	vpaddq %ymm3, %ymm10, %ymm10
	vpaddq %ymm2, %ymm8, %ymm8
	vpaddq 168(%rsp), %ymm5, %ymm5
	addq $64, %rsi
	vpsrlq $26, %ymm14, %ymm4
	vpsrlq $26, %ymm8, %ymm2
	vpand %ymm0, %ymm14, %ymm14
	vpand %ymm0, %ymm8, %ymm8
	vpaddq %ymm4, %ymm12, %ymm12
	vpaddq %ymm2, %ymm5, %ymm5
	vpsrlq $26, %ymm12, %ymm3
	vpsrlq $26, %ymm5, %ymm9
	vpand %ymm0, %ymm12, %ymm12
	vpand %ymm0, %ymm5, %ymm11
	vpaddq %ymm3, %ymm10, %ymm3
	vpmuludq 136(%rsp), %ymm9, %ymm9
	vpaddq %ymm9, %ymm14, %ymm14
	vpsrlq $26, %ymm3, %ymm2
	vpsrlq $26, %ymm14, %ymm4
	vpand %ymm0, %ymm3, %ymm3
	vpand %ymm0, %ymm14, %ymm5
	vpaddq %ymm2, %ymm8, %ymm2
	vpaddq %ymm4, %ymm12, %ymm4
	vpsrlq $26, %ymm2, %ymm1
	vpand %ymm0, %ymm2, %ymm2
	vpaddq %ymm1, %ymm11, %ymm1
	subq $64, %rdx
	cmpq $63, %rdx
	ja .Lpoly1305_blocks_avx2_16
.Lpoly1305_blocks_avx2_15:
	testb $64, 320(%rdi)
	jne .Lpoly1305_blocks_avx2_17
	vmovdqa %ymm5, (%rdi)
	vmovdqa %ymm4, 32(%rdi)
	vmovdqa %ymm3, 64(%rdi)
	vmovdqa %ymm2, 96(%rdi)
	vmovdqa %ymm1, 128(%rdi)
	jmp .Lpoly1305_blocks_avx2_8
.Lpoly1305_blocks_avx2_17:
	vpermq $245, %ymm5, %ymm0
	vpaddq %ymm0, %ymm5, %ymm5
	vpermq $245, %ymm4, %ymm0
	vpaddq %ymm0, %ymm4, %ymm4
	vpermq $245, %ymm3, %ymm0
	vpaddq %ymm0, %ymm3, %ymm3
	vpermq $245, %ymm2, %ymm0
	vpaddq %ymm0, %ymm2, %ymm2
	vpermq $245, %ymm1, %ymm0
	vpaddq %ymm0, %ymm1, %ymm1
	vpermq $170, %ymm5, %ymm0
	vpaddq %ymm0, %ymm5, %ymm5
	vpermq $170, %ymm4, %ymm0
	vpaddq %ymm0, %ymm4, %ymm4
	vpermq $170, %ymm3, %ymm0
	vpaddq %ymm0, %ymm3, %ymm3
	vpermq $170, %ymm2, %ymm0
	vpaddq %ymm0, %ymm2, %ymm2
	vpermq $170, %ymm1, %ymm0
	vpaddq %ymm0, %ymm1, %ymm1
	vmovd %xmm5, %eax
	vmovd %xmm4, %edx
	movl %eax, %ecx
	shrl $26, %ecx
	addl %edx, %ecx
	movl %ecx, %edx
	andl $67108863, %edx
	vmovd %xmm3, %esi
	shrl $26, %ecx
	movl %ecx, %r11d
	addl %esi, %r11d
	vmovd %xmm2, %ecx
	movl %r11d, %r10d
	shrl $26, %r10d
	addl %ecx, %r10d
	movl %r10d, %r9d
	andl $67108863, %r9d
	vmovd %xmm1, %r8d
	movl %edx, %esi
	salq $26, %rsi
	andl $67108863, %eax
	orq %rax, %rsi
	movabsq $17592186044415, %rax
	andq %rax, %rsi
	andl $67108863, %r11d
	salq $8, %r11
	shrl $18, %edx
	movl %edx, %edx
	orq %r11, %rdx
	movq %r9, %rcx
	salq $34, %rcx
	orq %rcx, %rdx
	andq %rax, %rdx
	shrl $26, %r10d
	addl %r10d, %r8d
	salq $16, %r8
	shrl $10, %r9d
	movl %r9d, %r9d
	orq %r9, %r8
	movabsq $4398046511103, %r10
	movq %r8, %r9
	andq %r10, %r9
	shrq $42, %r8
	leaq (%r8,%r8,4), %rcx
	addq %rcx, %rsi
	movq %rsi, %r8
	andq %rax, %r8
	movq %rsi, %rcx
	shrq $44, %rcx
	addq %rdx, %rcx
	movq %rcx, %rsi
	andq %rax, %rsi
	shrq $44, %rcx
	movq %rcx, %rdx
	addq %r9, %rdx
	andq %rdx, %r10
	shrq $42, %rdx
	leaq (%r8,%rdx,4), %rcx
	leaq (%rcx,%rdx), %rdx
	movq %rdx, %rbx
	andq %rax, %rbx
	shrq $44, %rdx
	movq %rdx, %r11
	addq %rsi, %r11
	leaq 5(%rbx), %r9
	movq %r9, %r8
	shrq $44, %r8
	addq %r11, %r8
	movabsq $-4398046511104, %rsi
	addq %r10, %rsi
	movq %r8, %rdx
	shrq $44, %rdx
	addq %rdx, %rsi
	movq %rsi, %rdx
	shrq $63, %rdx
	subq $1, %rdx
	movq %rdx, %rcx
	notq %rcx
	andq %rcx, %rbx
	andq %rcx, %r11
	andq %r10, %rcx
	andq %rax, %r9
	andq %rdx, %r9
	orq %r9, %rbx
	movq %rbx, (%rdi)
	andq %r8, %rax
	andq %rdx, %rax
	orq %rax, %r11
	movq %r11, 8(%rdi)
	andq %rsi, %rdx
	orq %rcx, %rdx
	movq %rdx, 16(%rdi)
.Lpoly1305_blocks_avx2_8:
	movq -8(%rbp), %rbx
	vzeroall
	movq %rbp, %rax
	subq %rsp, %rax
	leave
	addq $8, %rax
	ret
ELF(.size _gcry_poly1305_amd64_avx2_blocks,.-_gcry_poly1305_amd64_avx2_blocks;)


.align 8
.globl _gcry_poly1305_amd64_avx2_finish_ext
ELF(.type  _gcry_poly1305_amd64_avx2_finish_ext,@function;)
_gcry_poly1305_amd64_avx2_finish_ext:
.Lpoly1305_finish_ext_avx2_local:
	vzeroupper
	pushq %rbp
	movq %rsp, %rbp
	pushq %r13
	pushq %r12
	pushq %rbx
	andq $-64, %rsp
	subq $64, %rsp
	movq %rdi, %rbx
	movq %rdx, %r13
	movq %rcx, %r12
	testq %rdx, %rdx
	je .Lpoly1305_finish_ext_avx2_22
	vpxor %xmm0, %xmm0, %xmm0
	vmovdqa %ymm0, (%rsp)
	vmovdqa %ymm0, 32(%rsp)
	movq %rsp, %rax
	subq %rsp, %rsi
	testb $32, %dl
	je .Lpoly1305_finish_ext_avx2_23
	vmovdqu (%rsp,%rsi), %ymm0
	vmovdqa %ymm0, (%rsp)
	leaq 32(%rsp), %rax
.Lpoly1305_finish_ext_avx2_23:
	testb $16, %r13b
	je .Lpoly1305_finish_ext_avx2_24
	vmovdqu (%rax,%rsi), %xmm0
	vmovdqa %xmm0, (%rax)
	addq $16, %rax
.Lpoly1305_finish_ext_avx2_24:
	testb $8, %r13b
	je .Lpoly1305_finish_ext_avx2_25
	movq (%rax,%rsi), %rdx
	movq %rdx, (%rax)
	addq $8, %rax
.Lpoly1305_finish_ext_avx2_25:
	testb $4, %r13b
	je .Lpoly1305_finish_ext_avx2_26
	movl (%rax,%rsi), %edx
	movl %edx, (%rax)
	addq $4, %rax
.Lpoly1305_finish_ext_avx2_26:
	testb $2, %r13b
	je .Lpoly1305_finish_ext_avx2_27
	movzwl (%rax,%rsi), %edx
	movw %dx, (%rax)
	addq $2, %rax
.Lpoly1305_finish_ext_avx2_27:
	testb $1, %r13b
	je .Lpoly1305_finish_ext_avx2_28
	movzbl (%rax,%rsi), %edx
	movb %dl, (%rax)
.Lpoly1305_finish_ext_avx2_28:
	testb $15, %r13b
	je .Lpoly1305_finish_ext_avx2_29
	movb $1, (%rsp,%r13)
.Lpoly1305_finish_ext_avx2_29:
	cmpq $47, %r13
	jbe .Lpoly1305_finish_ext_avx2_30
	orq $4, 320(%rbx)
	jmp .Lpoly1305_finish_ext_avx2_31
.Lpoly1305_finish_ext_avx2_30:
	cmpq $31, %r13
	jbe .Lpoly1305_finish_ext_avx2_32
	orq $8, 320(%rbx)
	jmp .Lpoly1305_finish_ext_avx2_31
.Lpoly1305_finish_ext_avx2_32:
	cmpq $15, %r13
	jbe .Lpoly1305_finish_ext_avx2_33
	orq $16, 320(%rbx)
	jmp .Lpoly1305_finish_ext_avx2_31
.Lpoly1305_finish_ext_avx2_33:
	orq $32, 320(%rbx)
.Lpoly1305_finish_ext_avx2_31:
	testb $1, 320(%rbx)
	je .Lpoly1305_finish_ext_avx2_34
	cmpq $32, %r13
	ja .Lpoly1305_finish_ext_avx2_34
	cmpq $17, %r13
	sbbq %rsi, %rsi
	notq %rsi
	addq $2, %rsi
	cmpq $17, %r13
	sbbq %rax, %rax
	movq %rbx, %rdx
	addq $23, %rax
	leaq (%rbx,%rax,8), %rax
	movl $0, %ecx
.Lpoly1305_finish_ext_avx2_37:
	movl 244(%rdx), %edi
	movl %edi, (%rax)
	movl 252(%rdx), %edi
	movl %edi, 32(%rax)
	movl 260(%rdx), %edi
	movl %edi, 64(%rax)
	movl 268(%rdx), %edi
	movl %edi, 96(%rax)
	movl 276(%rdx), %edi
	movl %edi, 128(%rax)
	addq $1, %rcx
	subq $40, %rdx
	addq $8, %rax
	cmpq %rcx, %rsi
	ja .Lpoly1305_finish_ext_avx2_37
.Lpoly1305_finish_ext_avx2_34:
	movl $64, %edx
	movq %rsp, %rsi
	movq %rbx, %rdi
	call .Lpoly1305_blocks_avx2_local
.Lpoly1305_finish_ext_avx2_22:
	movq 320(%rbx), %r8
	testb $1, %r8b
	je .Lpoly1305_finish_ext_avx2_38
	leaq -1(%r13), %rax
	cmpq $47, %rax
	ja .Lpoly1305_finish_ext_avx2_46
	cmpq $32, %r13
	ja .Lpoly1305_finish_ext_avx2_47
	cmpq $17, %r13
	sbbq %r9, %r9
	addq $2, %r9
	movl $0, %edi
	cmpq $17, %r13
	sbbq %rax, %rax
	notq %rax
	andl $5, %eax
	jmp .Lpoly1305_finish_ext_avx2_39
.Lpoly1305_finish_ext_avx2_41:
	movl (%rdx), %esi
	movl %esi, (%rax)
	movl 8(%rdx), %esi
	movl %esi, 32(%rax)
	movl 16(%rdx), %esi
	movl %esi, 64(%rax)
	movl 24(%rdx), %esi
	movl %esi, 96(%rax)
	movl 32(%rdx), %esi
	movl %esi, 128(%rax)
	addq $1, %rcx
	subq $40, %rdx
	addq $8, %rax
	movq %rcx, %rsi
	subq %rdi, %rsi
	cmpq %rsi, %r9
	ja .Lpoly1305_finish_ext_avx2_41
	cmpq $3, %rcx
	ja .Lpoly1305_finish_ext_avx2_42
	leaq 160(%rbx,%rcx,8), %rax
.Lpoly1305_finish_ext_avx2_43:
	movl $1, (%rax)
	movl $0, 32(%rax)
	movl $0, 64(%rax)
	movl $0, 96(%rax)
	movl $0, 128(%rax)
	addq $1, %rcx
	addq $8, %rax
	cmpq $4, %rcx
	jne .Lpoly1305_finish_ext_avx2_43
.Lpoly1305_finish_ext_avx2_42:
	orq $96, %r8
	movq %r8, 320(%rbx)
	vpxor %ymm0, %ymm0, %ymm0
	vmovdqa %ymm0, (%rsp)
	vmovdqa %ymm0, 32(%rsp)
	movl $64, %edx
	movq %rsp, %rsi
	movq %rbx, %rdi
	call .Lpoly1305_blocks_avx2_local
.Lpoly1305_finish_ext_avx2_38:
	movq 8(%rbx), %rax
	movq %rax, %rdx
	salq $44, %rdx
	orq (%rbx), %rdx
	shrq $20, %rax
	movl $24, %edi
	shlx %rdi, 16(%rbx), %rcx
	orq %rcx, %rax
	movl 292(%rbx), %ecx
	salq $32, %rcx
	movl 284(%rbx), %esi
	orq %rsi, %rcx
	movl 308(%rbx), %esi
	salq $32, %rsi
	movl 300(%rbx), %edi
	orq %rdi, %rsi
	addq %rcx, %rdx
	adcq %rsi, %rax
	movq %rdx, (%r12)
	movq %rax, 8(%r12)
	vpxor %xmm0, %xmm0, %xmm0
	vmovdqu %ymm0, (%rbx)
	vmovdqu %ymm0, 32(%rbx)
	vmovdqu %ymm0, 64(%rbx)
	vmovdqu %ymm0, 96(%rbx)
	vmovdqu %ymm0, 128(%rbx)
	vmovdqu %ymm0, 160(%rbx)
	vmovdqu %ymm0, 192(%rbx)
	vmovdqu %ymm0, 224(%rbx)
	jmp .Lpoly1305_finish_ext_avx2_49
.Lpoly1305_finish_ext_avx2_46:
	movl $3, %r9d
	movl $1, %edi
	movl $10, %eax
	jmp .Lpoly1305_finish_ext_avx2_39
.Lpoly1305_finish_ext_avx2_47:
	movl $3, %r9d
	movl $0, %edi
	movl $10, %eax
.Lpoly1305_finish_ext_avx2_39:
	leaq 164(%rbx,%rax,8), %rdx
	leaq 160(%rbx,%rdi,8), %rax
	movq %rdi, %rcx
	jmp .Lpoly1305_finish_ext_avx2_41
.Lpoly1305_finish_ext_avx2_49:
	movq %rbp, %rax
	subq %rsp, %rax
	leaq -24(%rbp), %rsp
	vzeroall
	popq %rbx
	popq %r12
	popq %r13
	popq %rbp
	addq $(8*5), %rax
ret
ELF(.size _gcry_poly1305_amd64_avx2_finish_ext,.-_gcry_poly1305_amd64_avx2_finish_ext;)

#endif
