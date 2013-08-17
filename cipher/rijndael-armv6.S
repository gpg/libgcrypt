/* rijndael-armv6.S  -  ARM assembly implementation of AES cipher
 *
 * Copyright © 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#if defined(HAVE_ARM_ARCH_V6) && defined(__ARMEL__)
#ifdef HAVE_COMPATIBLE_GCC_ARM_PLATFORM_AS

.text

.syntax unified
.arm

/* register macros */
#define CTX	%r0
#define RTAB	%lr
#define RMASK	%ip

#define RA	%r4
#define RB	%r5
#define RC	%r6
#define RD	%r7

#define RNA	%r8
#define RNB	%r9
#define RNC	%r10
#define RND	%r11

#define RT0	%r1
#define RT1	%r2
#define RT2	%r3

/* helper macros */
#define ldr_unaligned_le(rout, rsrc, offs, rtmp) \
	ldrb rout, [rsrc, #((offs) + 0)]; \
	ldrb rtmp, [rsrc, #((offs) + 1)]; \
	orr rout, rout, rtmp, lsl #8; \
	ldrb rtmp, [rsrc, #((offs) + 2)]; \
	orr rout, rout, rtmp, lsl #16; \
	ldrb rtmp, [rsrc, #((offs) + 3)]; \
	orr rout, rout, rtmp, lsl #24;

#define str_unaligned_le(rin, rdst, offs, rtmp0, rtmp1) \
	mov rtmp0, rin, lsr #8; \
	strb rin, [rdst, #((offs) + 0)]; \
	mov rtmp1, rin, lsr #16; \
	strb rtmp0, [rdst, #((offs) + 1)]; \
	mov rtmp0, rin, lsr #24; \
	strb rtmp1, [rdst, #((offs) + 2)]; \
	strb rtmp0, [rdst, #((offs) + 3)];

/***********************************************************************
 * ARM assembly implementation of the AES cipher
 ***********************************************************************/
#define preload_first_key(round, ra) \
	ldr ra, [CTX, #(((round) * 16) + 0 * 4)];

#define dummy(round, ra) /* nothing */

#define addroundkey(ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_key) \
	ldm CTX, {rna, rnb, rnc, rnd}; \
	eor ra, rna; \
	eor rb, rnb; \
	eor rc, rnc; \
	preload_key(1, rna); \
	eor rd, rnd;

#define do_encround(next_r, ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_key) \
	ldr rnb, [CTX, #(((next_r) * 16) + 1 * 4)]; \
	\
	and RT0, RMASK, ra, lsl#3; \
	ldr rnc, [CTX, #(((next_r) * 16) + 2 * 4)]; \
	and RT1, RMASK, ra, lsr#(8 - 3); \
	ldr rnd, [CTX, #(((next_r) * 16) + 3 * 4)]; \
	and RT2, RMASK, ra, lsr#(16 - 3); \
	ldr RT0, [RTAB, RT0]; \
	and ra,  RMASK, ra, lsr#(24 - 3); \
	\
	ldr RT1, [RTAB, RT1]; \
	eor rna, rna, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rd, lsl#3; \
	ldr ra,  [RTAB, ra]; \
	\
	eor rnd, rnd, RT1, ror #24; \
	and RT1, RMASK, rd, lsr#(8 - 3); \
	eor rnc, rnc, RT2, ror #16; \
	and RT2, RMASK, rd, lsr#(16 - 3); \
	eor rnb, rnb, ra, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rd,  RMASK, rd, lsr#(24 - 3); \
	\
	ldr RT1, [RTAB, RT1]; \
	eor rnd, rnd, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rc, lsl#3; \
	ldr rd,  [RTAB, rd]; \
	\
	eor rnc, rnc, RT1, ror #24; \
	and RT1, RMASK, rc, lsr#(8 - 3); \
	eor rnb, rnb, RT2, ror #16; \
	and RT2, RMASK, rc, lsr#(16 - 3); \
	eor rna, rna, rd, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rc,  RMASK, rc, lsr#(24 - 3); \
	\
	ldr RT1, [RTAB, RT1]; \
	eor rnc, rnc, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rb, lsl#3; \
	ldr rc,  [RTAB, rc]; \
	\
	eor rnb, rnb, RT1, ror #24; \
	and RT1, RMASK, rb, lsr#(8 - 3); \
	eor rna, rna, RT2, ror #16; \
	and RT2, RMASK, rb, lsr#(16 - 3); \
	eor rnd, rnd, rc, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rb,  RMASK, rb, lsr#(24 - 3); \
	\
	ldr RT1, [RTAB, RT1]; \
	eor rnb, rnb, RT0; \
	ldr RT2, [RTAB, RT2]; \
	eor rna, rna, RT1, ror #24; \
	ldr rb,  [RTAB, rb]; \
	\
	eor rnd, rnd, RT2, ror #16; \
	preload_key((next_r) + 1, ra); \
	eor rnc, rnc, rb, ror #8;

#define do_lastencround(ra, rb, rc, rd, rna, rnb, rnc, rnd) \
	and RT0, RMASK, ra, lsl#3; \
	and RT1, RMASK, ra, lsr#(8 - 3); \
	and RT2, RMASK, ra, lsr#(16 - 3); \
	ldr rna, [RTAB, RT0]; \
	and ra,  RMASK, ra, lsr#(24 - 3); \
	ldr rnd, [RTAB, RT1]; \
	and RT0, RMASK, rd, lsl#3; \
	ldr rnc, [RTAB, RT2]; \
	mov rnd, rnd, ror #24; \
	ldr rnb, [RTAB, ra]; \
	and RT1, RMASK, rd, lsr#(8 - 3); \
	mov rnc, rnc, ror #16; \
	and RT2, RMASK, rd, lsr#(16 - 3); \
	mov rnb, rnb, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rd,  RMASK, rd, lsr#(24 - 3); \
	ldr RT1, [RTAB, RT1]; \
	\
	orr rnd, rnd, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rc, lsl#3; \
	ldr rd,  [RTAB, rd]; \
	orr rnc, rnc, RT1, ror #24; \
	and RT1, RMASK, rc, lsr#(8 - 3); \
	orr rnb, rnb, RT2, ror #16; \
	and RT2, RMASK, rc, lsr#(16 - 3); \
	orr rna, rna, rd, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rc,  RMASK, rc, lsr#(24 - 3); \
	ldr RT1, [RTAB, RT1]; \
	\
	orr rnc, rnc, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rb, lsl#3; \
	ldr rc,  [RTAB, rc]; \
	orr rnb, rnb, RT1, ror #24; \
	and RT1, RMASK, rb, lsr#(8 - 3); \
	orr rna, rna, RT2, ror #16; \
	ldr RT0, [RTAB, RT0]; \
	and RT2, RMASK, rb, lsr#(16 - 3); \
	ldr RT1, [RTAB, RT1]; \
	orr rnd, rnd, rc, ror #8; \
	ldr RT2, [RTAB, RT2]; \
	and rb,  RMASK, rb, lsr#(24 - 3); \
	ldr rb,  [RTAB, rb]; \
	\
	orr rnb, rnb, RT0; \
	orr rna, rna, RT1, ror #24; \
	orr rnd, rnd, RT2, ror #16; \
	orr rnc, rnc, rb, ror #8;

#define firstencround(round, ra, rb, rc, rd, rna, rnb, rnc, rnd) \
	addroundkey(ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_first_key); \
	do_encround((round) + 1, ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_first_key);

#define encround(round, ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_key) \
	do_encround((round) + 1, ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_key);

#define lastencround(round, ra, rb, rc, rd, rna, rnb, rnc, rnd) \
	add CTX, #(((round) + 1) * 16); \
	add RTAB, #4; \
	do_lastencround(ra, rb, rc, rd, rna, rnb, rnc, rnd); \
	addroundkey(rna, rnb, rnc, rnd, ra, rb, rc, rd, dummy);

.align 3
.global _gcry_aes_armv6_encrypt_block
.type   _gcry_aes_armv6_encrypt_block,%function;

_gcry_aes_armv6_encrypt_block:
	/* input:
	 *	%r0: keysched, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: number of rounds.. 10, 12 or 14
	 */
	push {%r4-%r11, %ip, %lr};

	/* read input block */
#ifndef __ARM_FEATURE_UNALIGNED
	/* test if src is unaligned */
	tst	%r2, #3;
	beq	1f;

	/* unaligned load */
	ldr_unaligned_le(RA, %r2, 0, RNA);
	ldr_unaligned_le(RB, %r2, 4, RNB);
	ldr_unaligned_le(RC, %r2, 8, RNA);
	ldr_unaligned_le(RD, %r2, 12, RNB);
	b	2f;
.ltorg
1:
#endif
	/* aligned load */
	ldm	%r2, {RA, RB, RC, RD};
#ifndef __ARMEL__
	rev	RA, RA;
	rev	RB, RB;
	rev	RC, RC;
	rev	RD, RD;
#endif
2:
	sub	%sp, #16;

	ldr	RTAB, =.LtableE0;

	str	%r1, [%sp, #4];		/* dst */
	mov	RMASK, #0xff;
	str	%r3, [%sp, #8];		/* nrounds */
	mov	RMASK, RMASK, lsl#3;	/* byte mask */

	firstencround(0, RA, RB, RC, RD, RNA, RNB, RNC, RND);
	encround(1, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	encround(2, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	encround(3, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	encround(4, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	encround(5, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	encround(6, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	encround(7, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);

	ldr	RT0, [%sp, #8];		/* nrounds */
	cmp	RT0, #12;
	bge	.Lenc_not_128;

	encround(8, RA, RB, RC, RD, RNA, RNB, RNC, RND, dummy);
	lastencround(9, RNA, RNB, RNC, RND, RA, RB, RC, RD);

.Lenc_done:
	ldr	RT0, [%sp, #4];		/* dst */
	add	%sp, #16;

	/* store output block */
#ifndef __ARM_FEATURE_UNALIGNED
	/* test if dst is unaligned */
	tst	RT0, #3;
	beq	1f;

	/* unaligned store */
	str_unaligned_le(RA, RT0, 0, RNA, RNB);
	str_unaligned_le(RB, RT0, 4, RNA, RNB);
	str_unaligned_le(RC, RT0, 8, RNA, RNB);
	str_unaligned_le(RD, RT0, 12, RNA, RNB);
	b	2f;
.ltorg
1:
#endif
	/* aligned store */
#ifndef __ARMEL__
	rev	RA, RA;
	rev	RB, RB;
	rev	RC, RC;
	rev	RD, RD;
#endif
	/* write output block */
	stm	RT0, {RA, RB, RC, RD};
2:
	pop {%r4-%r11, %ip, %pc};

.ltorg
.Lenc_not_128:
	beq .Lenc_192

	encround(8, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	encround(9, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	encround(10, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	encround(11, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	encround(12, RA, RB, RC, RD, RNA, RNB, RNC, RND, dummy);
	lastencround(13, RNA, RNB, RNC, RND, RA, RB, RC, RD);

	b .Lenc_done;

.ltorg
.Lenc_192:
	encround(8, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	encround(9, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	encround(10, RA, RB, RC, RD, RNA, RNB, RNC, RND, dummy);
	lastencround(11, RNA, RNB, RNC, RND, RA, RB, RC, RD);

	b .Lenc_done;
.size _gcry_aes_armv6_encrypt_block,.-_gcry_aes_armv6_encrypt_block;

#define addroundkey_dec(round, ra, rb, rc, rd, rna, rnb, rnc, rnd) \
	ldr rna, [CTX, #(((round) * 16) + 0 * 4)]; \
	ldr rnb, [CTX, #(((round) * 16) + 1 * 4)]; \
	eor ra, rna; \
	ldr rnc, [CTX, #(((round) * 16) + 2 * 4)]; \
	eor rb, rnb; \
	ldr rnd, [CTX, #(((round) * 16) + 3 * 4)]; \
	eor rc, rnc; \
	preload_first_key((round) - 1, rna); \
	eor rd, rnd;

#define do_decround(next_r, ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_key) \
	ldr rnb, [CTX, #(((next_r) * 16) + 1 * 4)]; \
	\
	and RT0, RMASK, ra, lsl#3; \
	ldr rnc, [CTX, #(((next_r) * 16) + 2 * 4)]; \
	and RT1, RMASK, ra, lsr#(8 - 3); \
	ldr rnd, [CTX, #(((next_r) * 16) + 3 * 4)]; \
	and RT2, RMASK, ra, lsr#(16 - 3); \
	ldr RT0, [RTAB, RT0]; \
	and ra,  RMASK, ra, lsr#(24 - 3); \
	\
	ldr RT1, [RTAB, RT1]; \
	eor rna, rna, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rb, lsl#3; \
	ldr ra,  [RTAB, ra]; \
	\
	eor rnb, rnb, RT1, ror #24; \
	and RT1, RMASK, rb, lsr#(8 - 3); \
	eor rnc, rnc, RT2, ror #16; \
	and RT2, RMASK, rb, lsr#(16 - 3); \
	eor rnd, rnd, ra, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rb,  RMASK, rb, lsr#(24 - 3); \
	\
	ldr RT1, [RTAB, RT1]; \
	eor rnb, rnb, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rc, lsl#3; \
	ldr rb,  [RTAB, rb]; \
	\
	eor rnc, rnc, RT1, ror #24; \
	and RT1, RMASK, rc, lsr#(8 - 3); \
	eor rnd, rnd, RT2, ror #16; \
	and RT2, RMASK, rc, lsr#(16 - 3); \
	eor rna, rna, rb, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rc,  RMASK, rc, lsr#(24 - 3); \
	\
	ldr RT1, [RTAB, RT1]; \
	eor rnc, rnc, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rd, lsl#3; \
	ldr rc,  [RTAB, rc]; \
	\
	eor rnd, rnd, RT1, ror #24; \
	and RT1, RMASK, rd, lsr#(8 - 3); \
	eor rna, rna, RT2, ror #16; \
	and RT2, RMASK, rd, lsr#(16 - 3); \
	eor rnb, rnb, rc, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rd,  RMASK, rd, lsr#(24 - 3); \
	\
	ldr RT1, [RTAB, RT1]; \
	eor rnd, rnd, RT0; \
	ldr RT2, [RTAB, RT2]; \
	eor rna, rna, RT1, ror #24; \
	ldr rd,  [RTAB, rd]; \
	\
	eor rnb, rnb, RT2, ror #16; \
	preload_key((next_r) - 1, ra); \
	eor rnc, rnc, rd, ror #8;

#define do_lastdecround(ra, rb, rc, rd, rna, rnb, rnc, rnd) \
	and RT0, RMASK, ra, lsl#3; \
	and RT1, RMASK, ra, lsr#(8 - 3); \
	and RT2, RMASK, ra, lsr#(16 - 3); \
	ldr rna, [RTAB, RT0]; \
	and ra,  RMASK, ra, lsr#(24 - 3); \
	ldr rnb, [RTAB, RT1]; \
	and RT0, RMASK, rb, lsl#3; \
	ldr rnc, [RTAB, RT2]; \
	mov rnb, rnb, ror #24; \
	ldr rnd, [RTAB, ra]; \
	and RT1, RMASK, rb, lsr#(8 - 3); \
	mov rnc, rnc, ror #16; \
	and RT2, RMASK, rb, lsr#(16 - 3); \
	mov rnd, rnd, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rb,  RMASK, rb, lsr#(24 - 3); \
	ldr RT1, [RTAB, RT1]; \
	\
	orr rnb, rnb, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rc, lsl#3; \
	ldr rb,  [RTAB, rb]; \
	orr rnc, rnc, RT1, ror #24; \
	and RT1, RMASK, rc, lsr#(8 - 3); \
	orr rnd, rnd, RT2, ror #16; \
	and RT2, RMASK, rc, lsr#(16 - 3); \
	orr rna, rna, rb, ror #8; \
	ldr RT0, [RTAB, RT0]; \
	and rc,  RMASK, rc, lsr#(24 - 3); \
	ldr RT1, [RTAB, RT1]; \
	\
	orr rnc, rnc, RT0; \
	ldr RT2, [RTAB, RT2]; \
	and RT0, RMASK, rd, lsl#3; \
	ldr rc,  [RTAB, rc]; \
	orr rnd, rnd, RT1, ror #24; \
	and RT1, RMASK, rd, lsr#(8 - 3); \
	orr rna, rna, RT2, ror #16; \
	ldr RT0, [RTAB, RT0]; \
	and RT2, RMASK, rd, lsr#(16 - 3); \
	ldr RT1, [RTAB, RT1]; \
	orr rnb, rnb, rc, ror #8; \
	ldr RT2, [RTAB, RT2]; \
	and rd,  RMASK, rd, lsr#(24 - 3); \
	ldr rd,  [RTAB, rd]; \
	\
	orr rnd, rnd, RT0; \
	orr rna, rna, RT1, ror #24; \
	orr rnb, rnb, RT2, ror #16; \
	orr rnc, rnc, rd, ror #8;

#define firstdecround(round, ra, rb, rc, rd, rna, rnb, rnc, rnd) \
	addroundkey_dec(((round) + 1), ra, rb, rc, rd, rna, rnb, rnc, rnd); \
	do_decround(round, ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_first_key);

#define decround(round, ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_key) \
	do_decround(round, ra, rb, rc, rd, rna, rnb, rnc, rnd, preload_key);

#define lastdecround(round, ra, rb, rc, rd, rna, rnb, rnc, rnd) \
	add RTAB, #4; \
	do_lastdecround(ra, rb, rc, rd, rna, rnb, rnc, rnd); \
	addroundkey(rna, rnb, rnc, rnd, ra, rb, rc, rd, dummy);

.align 3
.global _gcry_aes_armv6_decrypt_block
.type   _gcry_aes_armv6_decrypt_block,%function;

_gcry_aes_armv6_decrypt_block:
	/* input:
	 *	%r0: keysched, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: number of rounds.. 10, 12 or 14
	 */
	push {%r4-%r11, %ip, %lr};

	/* read input block */
#ifndef __ARM_FEATURE_UNALIGNED
	/* test if src is unaligned */
	tst	%r2, #3;
	beq	1f;

	/* unaligned load */
	ldr_unaligned_le(RA, %r2, 0, RNA);
	ldr_unaligned_le(RB, %r2, 4, RNB);
	ldr_unaligned_le(RC, %r2, 8, RNA);
	ldr_unaligned_le(RD, %r2, 12, RNB);
	b	2f;
.ltorg
1:
#endif
	/* aligned load */
	ldm	%r2, {RA, RB, RC, RD};
#ifndef __ARMEL__
	rev	RA, RA;
	rev	RB, RB;
	rev	RC, RC;
	rev	RD, RD;
#endif
2:
	sub	%sp, #16;

	ldr	RTAB, =.LtableD0;

	mov	RMASK, #0xff;
	str	%r1, [%sp, #4];		/* dst */
	mov	RMASK, RMASK, lsl#3;	/* byte mask */

	cmp	%r3, #12;
	bge	.Ldec_256;

	firstdecround(9, RA, RB, RC, RD, RNA, RNB, RNC, RND);
.Ldec_tail:
	decround(8, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	decround(7, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	decround(6, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	decround(5, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	decround(4, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	decround(3, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	decround(2, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	decround(1, RA, RB, RC, RD, RNA, RNB, RNC, RND, dummy);
	lastdecround(0, RNA, RNB, RNC, RND, RA, RB, RC, RD);

	ldr	RT0, [%sp, #4];		/* dst */
	add	%sp, #16;

	/* store output block */
#ifndef __ARM_FEATURE_UNALIGNED
	/* test if dst is unaligned */
	tst	RT0, #3;
	beq	1f;

	/* unaligned store */
	str_unaligned_le(RA, RT0, 0, RNA, RNB);
	str_unaligned_le(RB, RT0, 4, RNA, RNB);
	str_unaligned_le(RC, RT0, 8, RNA, RNB);
	str_unaligned_le(RD, RT0, 12, RNA, RNB);
	b	2f;
.ltorg
1:
#endif
	/* aligned store */
#ifndef __ARMEL__
	rev	RA, RA;
	rev	RB, RB;
	rev	RC, RC;
	rev	RD, RD;
#endif
	/* write output block */
	stm	RT0, {RA, RB, RC, RD};
2:
	pop {%r4-%r11, %ip, %pc};

.ltorg
.Ldec_256:
	beq .Ldec_192;

	firstdecround(13, RA, RB, RC, RD, RNA, RNB, RNC, RND);
	decround(12, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	decround(11, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);
	decround(10, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	decround(9, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);

	b .Ldec_tail;

.ltorg
.Ldec_192:
	firstdecround(11, RA, RB, RC, RD, RNA, RNB, RNC, RND);
	decround(10, RNA, RNB, RNC, RND, RA, RB, RC, RD, preload_first_key);
	decround(9, RA, RB, RC, RD, RNA, RNB, RNC, RND, preload_first_key);

	b .Ldec_tail;
.size _gcry_aes_armv6_encrypt_block,.-_gcry_aes_armv6_encrypt_block;

.data

/* Encryption tables */
.align 5
.type .LtableE0, %object
.type .LtableEs0, %object
.LtableE0:
.long 0xa56363c6
.LtableEs0:
.long             0x00000063, 0x847c7cf8, 0x0000007c
.long 0x997777ee, 0x00000077, 0x8d7b7bf6, 0x0000007b
.long 0x0df2f2ff, 0x000000f2, 0xbd6b6bd6, 0x0000006b
.long 0xb16f6fde, 0x0000006f, 0x54c5c591, 0x000000c5
.long 0x50303060, 0x00000030, 0x03010102, 0x00000001
.long 0xa96767ce, 0x00000067, 0x7d2b2b56, 0x0000002b
.long 0x19fefee7, 0x000000fe, 0x62d7d7b5, 0x000000d7
.long 0xe6abab4d, 0x000000ab, 0x9a7676ec, 0x00000076
.long 0x45caca8f, 0x000000ca, 0x9d82821f, 0x00000082
.long 0x40c9c989, 0x000000c9, 0x877d7dfa, 0x0000007d
.long 0x15fafaef, 0x000000fa, 0xeb5959b2, 0x00000059
.long 0xc947478e, 0x00000047, 0x0bf0f0fb, 0x000000f0
.long 0xecadad41, 0x000000ad, 0x67d4d4b3, 0x000000d4
.long 0xfda2a25f, 0x000000a2, 0xeaafaf45, 0x000000af
.long 0xbf9c9c23, 0x0000009c, 0xf7a4a453, 0x000000a4
.long 0x967272e4, 0x00000072, 0x5bc0c09b, 0x000000c0
.long 0xc2b7b775, 0x000000b7, 0x1cfdfde1, 0x000000fd
.long 0xae93933d, 0x00000093, 0x6a26264c, 0x00000026
.long 0x5a36366c, 0x00000036, 0x413f3f7e, 0x0000003f
.long 0x02f7f7f5, 0x000000f7, 0x4fcccc83, 0x000000cc
.long 0x5c343468, 0x00000034, 0xf4a5a551, 0x000000a5
.long 0x34e5e5d1, 0x000000e5, 0x08f1f1f9, 0x000000f1
.long 0x937171e2, 0x00000071, 0x73d8d8ab, 0x000000d8
.long 0x53313162, 0x00000031, 0x3f15152a, 0x00000015
.long 0x0c040408, 0x00000004, 0x52c7c795, 0x000000c7
.long 0x65232346, 0x00000023, 0x5ec3c39d, 0x000000c3
.long 0x28181830, 0x00000018, 0xa1969637, 0x00000096
.long 0x0f05050a, 0x00000005, 0xb59a9a2f, 0x0000009a
.long 0x0907070e, 0x00000007, 0x36121224, 0x00000012
.long 0x9b80801b, 0x00000080, 0x3de2e2df, 0x000000e2
.long 0x26ebebcd, 0x000000eb, 0x6927274e, 0x00000027
.long 0xcdb2b27f, 0x000000b2, 0x9f7575ea, 0x00000075
.long 0x1b090912, 0x00000009, 0x9e83831d, 0x00000083
.long 0x742c2c58, 0x0000002c, 0x2e1a1a34, 0x0000001a
.long 0x2d1b1b36, 0x0000001b, 0xb26e6edc, 0x0000006e
.long 0xee5a5ab4, 0x0000005a, 0xfba0a05b, 0x000000a0
.long 0xf65252a4, 0x00000052, 0x4d3b3b76, 0x0000003b
.long 0x61d6d6b7, 0x000000d6, 0xceb3b37d, 0x000000b3
.long 0x7b292952, 0x00000029, 0x3ee3e3dd, 0x000000e3
.long 0x712f2f5e, 0x0000002f, 0x97848413, 0x00000084
.long 0xf55353a6, 0x00000053, 0x68d1d1b9, 0x000000d1
.long 0x00000000, 0x00000000, 0x2cededc1, 0x000000ed
.long 0x60202040, 0x00000020, 0x1ffcfce3, 0x000000fc
.long 0xc8b1b179, 0x000000b1, 0xed5b5bb6, 0x0000005b
.long 0xbe6a6ad4, 0x0000006a, 0x46cbcb8d, 0x000000cb
.long 0xd9bebe67, 0x000000be, 0x4b393972, 0x00000039
.long 0xde4a4a94, 0x0000004a, 0xd44c4c98, 0x0000004c
.long 0xe85858b0, 0x00000058, 0x4acfcf85, 0x000000cf
.long 0x6bd0d0bb, 0x000000d0, 0x2aefefc5, 0x000000ef
.long 0xe5aaaa4f, 0x000000aa, 0x16fbfbed, 0x000000fb
.long 0xc5434386, 0x00000043, 0xd74d4d9a, 0x0000004d
.long 0x55333366, 0x00000033, 0x94858511, 0x00000085
.long 0xcf45458a, 0x00000045, 0x10f9f9e9, 0x000000f9
.long 0x06020204, 0x00000002, 0x817f7ffe, 0x0000007f
.long 0xf05050a0, 0x00000050, 0x443c3c78, 0x0000003c
.long 0xba9f9f25, 0x0000009f, 0xe3a8a84b, 0x000000a8
.long 0xf35151a2, 0x00000051, 0xfea3a35d, 0x000000a3
.long 0xc0404080, 0x00000040, 0x8a8f8f05, 0x0000008f
.long 0xad92923f, 0x00000092, 0xbc9d9d21, 0x0000009d
.long 0x48383870, 0x00000038, 0x04f5f5f1, 0x000000f5
.long 0xdfbcbc63, 0x000000bc, 0xc1b6b677, 0x000000b6
.long 0x75dadaaf, 0x000000da, 0x63212142, 0x00000021
.long 0x30101020, 0x00000010, 0x1affffe5, 0x000000ff
.long 0x0ef3f3fd, 0x000000f3, 0x6dd2d2bf, 0x000000d2
.long 0x4ccdcd81, 0x000000cd, 0x140c0c18, 0x0000000c
.long 0x35131326, 0x00000013, 0x2fececc3, 0x000000ec
.long 0xe15f5fbe, 0x0000005f, 0xa2979735, 0x00000097
.long 0xcc444488, 0x00000044, 0x3917172e, 0x00000017
.long 0x57c4c493, 0x000000c4, 0xf2a7a755, 0x000000a7
.long 0x827e7efc, 0x0000007e, 0x473d3d7a, 0x0000003d
.long 0xac6464c8, 0x00000064, 0xe75d5dba, 0x0000005d
.long 0x2b191932, 0x00000019, 0x957373e6, 0x00000073
.long 0xa06060c0, 0x00000060, 0x98818119, 0x00000081
.long 0xd14f4f9e, 0x0000004f, 0x7fdcdca3, 0x000000dc
.long 0x66222244, 0x00000022, 0x7e2a2a54, 0x0000002a
.long 0xab90903b, 0x00000090, 0x8388880b, 0x00000088
.long 0xca46468c, 0x00000046, 0x29eeeec7, 0x000000ee
.long 0xd3b8b86b, 0x000000b8, 0x3c141428, 0x00000014
.long 0x79dedea7, 0x000000de, 0xe25e5ebc, 0x0000005e
.long 0x1d0b0b16, 0x0000000b, 0x76dbdbad, 0x000000db
.long 0x3be0e0db, 0x000000e0, 0x56323264, 0x00000032
.long 0x4e3a3a74, 0x0000003a, 0x1e0a0a14, 0x0000000a
.long 0xdb494992, 0x00000049, 0x0a06060c, 0x00000006
.long 0x6c242448, 0x00000024, 0xe45c5cb8, 0x0000005c
.long 0x5dc2c29f, 0x000000c2, 0x6ed3d3bd, 0x000000d3
.long 0xefacac43, 0x000000ac, 0xa66262c4, 0x00000062
.long 0xa8919139, 0x00000091, 0xa4959531, 0x00000095
.long 0x37e4e4d3, 0x000000e4, 0x8b7979f2, 0x00000079
.long 0x32e7e7d5, 0x000000e7, 0x43c8c88b, 0x000000c8
.long 0x5937376e, 0x00000037, 0xb76d6dda, 0x0000006d
.long 0x8c8d8d01, 0x0000008d, 0x64d5d5b1, 0x000000d5
.long 0xd24e4e9c, 0x0000004e, 0xe0a9a949, 0x000000a9
.long 0xb46c6cd8, 0x0000006c, 0xfa5656ac, 0x00000056
.long 0x07f4f4f3, 0x000000f4, 0x25eaeacf, 0x000000ea
.long 0xaf6565ca, 0x00000065, 0x8e7a7af4, 0x0000007a
.long 0xe9aeae47, 0x000000ae, 0x18080810, 0x00000008
.long 0xd5baba6f, 0x000000ba, 0x887878f0, 0x00000078
.long 0x6f25254a, 0x00000025, 0x722e2e5c, 0x0000002e
.long 0x241c1c38, 0x0000001c, 0xf1a6a657, 0x000000a6
.long 0xc7b4b473, 0x000000b4, 0x51c6c697, 0x000000c6
.long 0x23e8e8cb, 0x000000e8, 0x7cdddda1, 0x000000dd
.long 0x9c7474e8, 0x00000074, 0x211f1f3e, 0x0000001f
.long 0xdd4b4b96, 0x0000004b, 0xdcbdbd61, 0x000000bd
.long 0x868b8b0d, 0x0000008b, 0x858a8a0f, 0x0000008a
.long 0x907070e0, 0x00000070, 0x423e3e7c, 0x0000003e
.long 0xc4b5b571, 0x000000b5, 0xaa6666cc, 0x00000066
.long 0xd8484890, 0x00000048, 0x05030306, 0x00000003
.long 0x01f6f6f7, 0x000000f6, 0x120e0e1c, 0x0000000e
.long 0xa36161c2, 0x00000061, 0x5f35356a, 0x00000035
.long 0xf95757ae, 0x00000057, 0xd0b9b969, 0x000000b9
.long 0x91868617, 0x00000086, 0x58c1c199, 0x000000c1
.long 0x271d1d3a, 0x0000001d, 0xb99e9e27, 0x0000009e
.long 0x38e1e1d9, 0x000000e1, 0x13f8f8eb, 0x000000f8
.long 0xb398982b, 0x00000098, 0x33111122, 0x00000011
.long 0xbb6969d2, 0x00000069, 0x70d9d9a9, 0x000000d9
.long 0x898e8e07, 0x0000008e, 0xa7949433, 0x00000094
.long 0xb69b9b2d, 0x0000009b, 0x221e1e3c, 0x0000001e
.long 0x92878715, 0x00000087, 0x20e9e9c9, 0x000000e9
.long 0x49cece87, 0x000000ce, 0xff5555aa, 0x00000055
.long 0x78282850, 0x00000028, 0x7adfdfa5, 0x000000df
.long 0x8f8c8c03, 0x0000008c, 0xf8a1a159, 0x000000a1
.long 0x80898909, 0x00000089, 0x170d0d1a, 0x0000000d
.long 0xdabfbf65, 0x000000bf, 0x31e6e6d7, 0x000000e6
.long 0xc6424284, 0x00000042, 0xb86868d0, 0x00000068
.long 0xc3414182, 0x00000041, 0xb0999929, 0x00000099
.long 0x772d2d5a, 0x0000002d, 0x110f0f1e, 0x0000000f
.long 0xcbb0b07b, 0x000000b0, 0xfc5454a8, 0x00000054
.long 0xd6bbbb6d, 0x000000bb, 0x3a16162c, 0x00000016

/* Decryption tables */
.align 5
.type .LtableD0, %object
.type .LtableDs0, %object
.LtableD0:
.long 0x50a7f451
.LtableDs0:
.long             0x00000052, 0x5365417e, 0x00000009
.long 0xc3a4171a, 0x0000006a, 0x965e273a, 0x000000d5
.long 0xcb6bab3b, 0x00000030, 0xf1459d1f, 0x00000036
.long 0xab58faac, 0x000000a5, 0x9303e34b, 0x00000038
.long 0x55fa3020, 0x000000bf, 0xf66d76ad, 0x00000040
.long 0x9176cc88, 0x000000a3, 0x254c02f5, 0x0000009e
.long 0xfcd7e54f, 0x00000081, 0xd7cb2ac5, 0x000000f3
.long 0x80443526, 0x000000d7, 0x8fa362b5, 0x000000fb
.long 0x495ab1de, 0x0000007c, 0x671bba25, 0x000000e3
.long 0x980eea45, 0x00000039, 0xe1c0fe5d, 0x00000082
.long 0x02752fc3, 0x0000009b, 0x12f04c81, 0x0000002f
.long 0xa397468d, 0x000000ff, 0xc6f9d36b, 0x00000087
.long 0xe75f8f03, 0x00000034, 0x959c9215, 0x0000008e
.long 0xeb7a6dbf, 0x00000043, 0xda595295, 0x00000044
.long 0x2d83bed4, 0x000000c4, 0xd3217458, 0x000000de
.long 0x2969e049, 0x000000e9, 0x44c8c98e, 0x000000cb
.long 0x6a89c275, 0x00000054, 0x78798ef4, 0x0000007b
.long 0x6b3e5899, 0x00000094, 0xdd71b927, 0x00000032
.long 0xb64fe1be, 0x000000a6, 0x17ad88f0, 0x000000c2
.long 0x66ac20c9, 0x00000023, 0xb43ace7d, 0x0000003d
.long 0x184adf63, 0x000000ee, 0x82311ae5, 0x0000004c
.long 0x60335197, 0x00000095, 0x457f5362, 0x0000000b
.long 0xe07764b1, 0x00000042, 0x84ae6bbb, 0x000000fa
.long 0x1ca081fe, 0x000000c3, 0x942b08f9, 0x0000004e
.long 0x58684870, 0x00000008, 0x19fd458f, 0x0000002e
.long 0x876cde94, 0x000000a1, 0xb7f87b52, 0x00000066
.long 0x23d373ab, 0x00000028, 0xe2024b72, 0x000000d9
.long 0x578f1fe3, 0x00000024, 0x2aab5566, 0x000000b2
.long 0x0728ebb2, 0x00000076, 0x03c2b52f, 0x0000005b
.long 0x9a7bc586, 0x000000a2, 0xa50837d3, 0x00000049
.long 0xf2872830, 0x0000006d, 0xb2a5bf23, 0x0000008b
.long 0xba6a0302, 0x000000d1, 0x5c8216ed, 0x00000025
.long 0x2b1ccf8a, 0x00000072, 0x92b479a7, 0x000000f8
.long 0xf0f207f3, 0x000000f6, 0xa1e2694e, 0x00000064
.long 0xcdf4da65, 0x00000086, 0xd5be0506, 0x00000068
.long 0x1f6234d1, 0x00000098, 0x8afea6c4, 0x00000016
.long 0x9d532e34, 0x000000d4, 0xa055f3a2, 0x000000a4
.long 0x32e18a05, 0x0000005c, 0x75ebf6a4, 0x000000cc
.long 0x39ec830b, 0x0000005d, 0xaaef6040, 0x00000065
.long 0x069f715e, 0x000000b6, 0x51106ebd, 0x00000092
.long 0xf98a213e, 0x0000006c, 0x3d06dd96, 0x00000070
.long 0xae053edd, 0x00000048, 0x46bde64d, 0x00000050
.long 0xb58d5491, 0x000000fd, 0x055dc471, 0x000000ed
.long 0x6fd40604, 0x000000b9, 0xff155060, 0x000000da
.long 0x24fb9819, 0x0000005e, 0x97e9bdd6, 0x00000015
.long 0xcc434089, 0x00000046, 0x779ed967, 0x00000057
.long 0xbd42e8b0, 0x000000a7, 0x888b8907, 0x0000008d
.long 0x385b19e7, 0x0000009d, 0xdbeec879, 0x00000084
.long 0x470a7ca1, 0x00000090, 0xe90f427c, 0x000000d8
.long 0xc91e84f8, 0x000000ab, 0x00000000, 0x00000000
.long 0x83868009, 0x0000008c, 0x48ed2b32, 0x000000bc
.long 0xac70111e, 0x000000d3, 0x4e725a6c, 0x0000000a
.long 0xfbff0efd, 0x000000f7, 0x5638850f, 0x000000e4
.long 0x1ed5ae3d, 0x00000058, 0x27392d36, 0x00000005
.long 0x64d90f0a, 0x000000b8, 0x21a65c68, 0x000000b3
.long 0xd1545b9b, 0x00000045, 0x3a2e3624, 0x00000006
.long 0xb1670a0c, 0x000000d0, 0x0fe75793, 0x0000002c
.long 0xd296eeb4, 0x0000001e, 0x9e919b1b, 0x0000008f
.long 0x4fc5c080, 0x000000ca, 0xa220dc61, 0x0000003f
.long 0x694b775a, 0x0000000f, 0x161a121c, 0x00000002
.long 0x0aba93e2, 0x000000c1, 0xe52aa0c0, 0x000000af
.long 0x43e0223c, 0x000000bd, 0x1d171b12, 0x00000003
.long 0x0b0d090e, 0x00000001, 0xadc78bf2, 0x00000013
.long 0xb9a8b62d, 0x0000008a, 0xc8a91e14, 0x0000006b
.long 0x8519f157, 0x0000003a, 0x4c0775af, 0x00000091
.long 0xbbdd99ee, 0x00000011, 0xfd607fa3, 0x00000041
.long 0x9f2601f7, 0x0000004f, 0xbcf5725c, 0x00000067
.long 0xc53b6644, 0x000000dc, 0x347efb5b, 0x000000ea
.long 0x7629438b, 0x00000097, 0xdcc623cb, 0x000000f2
.long 0x68fcedb6, 0x000000cf, 0x63f1e4b8, 0x000000ce
.long 0xcadc31d7, 0x000000f0, 0x10856342, 0x000000b4
.long 0x40229713, 0x000000e6, 0x2011c684, 0x00000073
.long 0x7d244a85, 0x00000096, 0xf83dbbd2, 0x000000ac
.long 0x1132f9ae, 0x00000074, 0x6da129c7, 0x00000022
.long 0x4b2f9e1d, 0x000000e7, 0xf330b2dc, 0x000000ad
.long 0xec52860d, 0x00000035, 0xd0e3c177, 0x00000085
.long 0x6c16b32b, 0x000000e2, 0x99b970a9, 0x000000f9
.long 0xfa489411, 0x00000037, 0x2264e947, 0x000000e8
.long 0xc48cfca8, 0x0000001c, 0x1a3ff0a0, 0x00000075
.long 0xd82c7d56, 0x000000df, 0xef903322, 0x0000006e
.long 0xc74e4987, 0x00000047, 0xc1d138d9, 0x000000f1
.long 0xfea2ca8c, 0x0000001a, 0x360bd498, 0x00000071
.long 0xcf81f5a6, 0x0000001d, 0x28de7aa5, 0x00000029
.long 0x268eb7da, 0x000000c5, 0xa4bfad3f, 0x00000089
.long 0xe49d3a2c, 0x0000006f, 0x0d927850, 0x000000b7
.long 0x9bcc5f6a, 0x00000062, 0x62467e54, 0x0000000e
.long 0xc2138df6, 0x000000aa, 0xe8b8d890, 0x00000018
.long 0x5ef7392e, 0x000000be, 0xf5afc382, 0x0000001b
.long 0xbe805d9f, 0x000000fc, 0x7c93d069, 0x00000056
.long 0xa92dd56f, 0x0000003e, 0xb31225cf, 0x0000004b
.long 0x3b99acc8, 0x000000c6, 0xa77d1810, 0x000000d2
.long 0x6e639ce8, 0x00000079, 0x7bbb3bdb, 0x00000020
.long 0x097826cd, 0x0000009a, 0xf418596e, 0x000000db
.long 0x01b79aec, 0x000000c0, 0xa89a4f83, 0x000000fe
.long 0x656e95e6, 0x00000078, 0x7ee6ffaa, 0x000000cd
.long 0x08cfbc21, 0x0000005a, 0xe6e815ef, 0x000000f4
.long 0xd99be7ba, 0x0000001f, 0xce366f4a, 0x000000dd
.long 0xd4099fea, 0x000000a8, 0xd67cb029, 0x00000033
.long 0xafb2a431, 0x00000088, 0x31233f2a, 0x00000007
.long 0x3094a5c6, 0x000000c7, 0xc066a235, 0x00000031
.long 0x37bc4e74, 0x000000b1, 0xa6ca82fc, 0x00000012
.long 0xb0d090e0, 0x00000010, 0x15d8a733, 0x00000059
.long 0x4a9804f1, 0x00000027, 0xf7daec41, 0x00000080
.long 0x0e50cd7f, 0x000000ec, 0x2ff69117, 0x0000005f
.long 0x8dd64d76, 0x00000060, 0x4db0ef43, 0x00000051
.long 0x544daacc, 0x0000007f, 0xdf0496e4, 0x000000a9
.long 0xe3b5d19e, 0x00000019, 0x1b886a4c, 0x000000b5
.long 0xb81f2cc1, 0x0000004a, 0x7f516546, 0x0000000d
.long 0x04ea5e9d, 0x0000002d, 0x5d358c01, 0x000000e5
.long 0x737487fa, 0x0000007a, 0x2e410bfb, 0x0000009f
.long 0x5a1d67b3, 0x00000093, 0x52d2db92, 0x000000c9
.long 0x335610e9, 0x0000009c, 0x1347d66d, 0x000000ef
.long 0x8c61d79a, 0x000000a0, 0x7a0ca137, 0x000000e0
.long 0x8e14f859, 0x0000003b, 0x893c13eb, 0x0000004d
.long 0xee27a9ce, 0x000000ae, 0x35c961b7, 0x0000002a
.long 0xede51ce1, 0x000000f5, 0x3cb1477a, 0x000000b0
.long 0x59dfd29c, 0x000000c8, 0x3f73f255, 0x000000eb
.long 0x79ce1418, 0x000000bb, 0xbf37c773, 0x0000003c
.long 0xeacdf753, 0x00000083, 0x5baafd5f, 0x00000053
.long 0x146f3ddf, 0x00000099, 0x86db4478, 0x00000061
.long 0x81f3afca, 0x00000017, 0x3ec468b9, 0x0000002b
.long 0x2c342438, 0x00000004, 0x5f40a3c2, 0x0000007e
.long 0x72c31d16, 0x000000ba, 0x0c25e2bc, 0x00000077
.long 0x8b493c28, 0x000000d6, 0x41950dff, 0x00000026
.long 0x7101a839, 0x000000e1, 0xdeb30c08, 0x00000069
.long 0x9ce4b4d8, 0x00000014, 0x90c15664, 0x00000063
.long 0x6184cb7b, 0x00000055, 0x70b632d5, 0x00000021
.long 0x745c6c48, 0x0000000c, 0x4257b8d0, 0x0000007d

#endif /*HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS*/
#endif /*__ARM_ARCH >= 6*/
