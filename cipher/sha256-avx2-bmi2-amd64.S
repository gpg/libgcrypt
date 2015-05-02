/*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Copyright (c) 2012, Intel Corporation
;
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are
; met:
;
; * Redistributions of source code must retain the above copyright
;   notice, this list of conditions and the following disclaimer.
;
; * Redistributions in binary form must reproduce the above copyright
;   notice, this list of conditions and the following disclaimer in the
;   documentation and/or other materials provided with the
;   distribution.
;
; * Neither the name of the Intel Corporation nor the names of its
;   contributors may be used to endorse or promote products derived from
;   this software without specific prior written permission.
;
;
; THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY
; EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
; PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR
; CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
; EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
; PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
; PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
; LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; This code is described in an Intel White-Paper:
; "Fast SHA-256 Implementations on Intel Architecture Processors"
;
; To find it, surf to http://www.intel.com/p/en_US/embedded
; and search for that title.
; The paper is expected to be released roughly at the end of April, 2012
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; This code schedules 2 blocks at a time, with 4 lanes per block
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
*/
/*
 * Conversion to GAS assembly and integration to libgcrypt
 *  by Jussi Kivilinna <jussi.kivilinna@iki.fi>
 */

#ifdef __x86_64
#include <config.h>
#if (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
     defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS)) && \
    defined(HAVE_INTEL_SYNTAX_PLATFORM_AS) && \
    defined(HAVE_GCC_INLINE_ASM_AVX2) && defined(HAVE_GCC_INLINE_ASM_BMI2) && \
    defined(USE_SHA256)

#ifdef __PIC__
#  define ADD_RIP +rip
#else
#  define ADD_RIP
#endif

#ifdef HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS
# define ELF(...) __VA_ARGS__
#else
# define ELF(...) /*_*/
#endif

.intel_syntax noprefix

#define	VMOVDQ vmovdqu /* ; assume buffers not aligned  */

/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Define Macros */

/*  addm [mem], reg */
/*  Add reg to mem using reg-mem add and store */
.macro addm p1 p2
	add	\p2, \p1
	mov	\p1, \p2
.endm

/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

X0 = ymm4
X1 = ymm5
X2 = ymm6
X3 = ymm7

/*  XMM versions of above */
XWORD0 = xmm4
XWORD1 = xmm5
XWORD2 = xmm6
XWORD3 = xmm7

XTMP0 = ymm0
XTMP1 = ymm1
XTMP2 = ymm2
XTMP3 = ymm3
XTMP4 = ymm8
XFER =  ymm9
XTMP5 = ymm11

SHUF_00BA = ymm10 /*  shuffle xBxA -> 00BA */
SHUF_DC00 = ymm12 /*  shuffle xDxC -> DC00 */
BYTE_FLIP_MASK = ymm13

X_BYTE_FLIP_MASK = xmm13 /*  XMM version of BYTE_FLIP_MASK */

NUM_BLKS = rdx	/*  3rd arg */
CTX =	rsi   	/*  2nd arg */
INP =	rdi	/*  1st arg */
c =	ecx
d =	r8d
e =	edx	/*  clobbers NUM_BLKS */
y3 =	edi	/*  clobbers INP */

TBL =	rbp
SRND =	CTX	/*  SRND is same register as CTX */

a =	eax
b =	ebx
f =	r9d
g =	r10d
h =	r11d
old_h =	r11d

T1 = r12d
y0 = r13d
y1 = r14d
y2 = r15d


_XFER_SIZE	= 2*64*4	/*  2 blocks, 64 rounds, 4 bytes/round */
_XMM_SAVE_SIZE  = 0
_INP_END_SIZE	= 8
_INP_SIZE	= 8
_CTX_SIZE	= 8
_RSP_SIZE	= 8

_XFER		= 0
_XMM_SAVE	= _XFER     + _XFER_SIZE
_INP_END	= _XMM_SAVE + _XMM_SAVE_SIZE
_INP 		= _INP_END  + _INP_END_SIZE
_CTX		= _INP      + _INP_SIZE
_RSP		= _CTX      + _CTX_SIZE
STACK_SIZE	= _RSP      + _RSP_SIZE

/*  rotate_Xs */
/*  Rotate values of symbols X0...X3 */
.macro rotate_Xs
X_ = X0
X0 = X1
X1 = X2
X2 = X3
X3 = X_
.endm

/*  ROTATE_ARGS */
/*  Rotate values of symbols a...h */
.macro ROTATE_ARGS
old_h = h
TMP_ = h
h = g
g = f
f = e
e = d
d = c
c = b
b = a
a = TMP_
.endm

.macro FOUR_ROUNDS_AND_SCHED XFER
/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 0 ;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	mov	y3, a		/*  y3 = a                                ; MAJA	 */
	rorx	y0, e, 25	/*  y0 = e >> 25				; S1A */
	rorx	y1, e, 11	/*  y1 = e >> 11				; S1B */

	add	h, [\XFER+0*4]		/*  h = k + w + h         ; --	 */
	or	y3, c		/*  y3 = a|c                              ; MAJA	 */
		vpalignr	XTMP0, X3, X2, 4	/*  XTMP0 = W[-7] */
	mov	y2, f		/*  y2 = f                                ; CH	 */
	rorx	T1, a, 13	/*  T1 = a >> 13				; S0B */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11)		; S1 */
	xor	y2, g		/*  y2 = f^g                              ; CH	 */
		vpaddd	XTMP0, XTMP0, X0	/*  XTMP0 = W[-7] + W[-16]; y1 = (e >> 6)					; S1 */
	rorx	y1, e, 6	/*  y1 = (e >> 6)				; S1 */

	and	y2, e		/*  y2 = (f^g)&e                          ; CH	 */
	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11) ^ (e>>6)	; S1 */
	rorx	y1, a, 22	/*  y1 = a >> 22				; S0A */
	add	d, h		/*  d = k + w + h + d                     ; --	 */

	and	y3, b		/*  y3 = (a|c)&b                          ; MAJA	 */
		vpalignr	XTMP1, X1, X0, 4	/*  XTMP1 = W[-15] */
	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13)		; S0 */
	rorx	T1, a, 2	/*  T1 = (a >> 2)				; S0 */

	xor	y2, g		/*  y2 = CH = ((f^g)&e)^g                 ; CH	 */
		vpsrld	XTMP2, XTMP1, 7
	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13) ^ (a>>2)	; S0 */
	mov	T1, a		/*  T1 = a                                ; MAJB	 */
	and	T1, c		/*  T1 = a&c                              ; MAJB	 */

	add	y2, y0		/*  y2 = S1 + CH                          ; --	 */
		vpslld	XTMP3, XTMP1, (32-7)
	or	y3, T1		/*  y3 = MAJ = (a|c)&b)|(a&c)             ; MAJ	 */
	add	h, y1		/*  h = k + w + h + S0                    ; --	 */

	add	d, y2		/*  d = k + w + h + d + S1 + CH = d + t1  ; --	 */
		vpor	XTMP3, XTMP3, XTMP2	/*  XTMP3 = W[-15] ror 7 */

		vpsrld	XTMP2, XTMP1,18
	add	h, y2		/*  h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */
	lea	h, [h + y3]	/*  h = t1 + S0 + MAJ                     ; --	 */


ROTATE_ARGS

/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 1 ;;;;;;;;;;;;;;;;;;;;;;;;;;;; */


	mov	y3, a		/*  y3 = a                                ; MAJA	 */
	rorx	y0, e, 25	/*  y0 = e >> 25				; S1A */
	rorx	y1, e, 11	/*  y1 = e >> 11				; S1B */
	add	h, [\XFER+1*4]		/*  h = k + w + h         ; --	 */
	or	y3, c		/*  y3 = a|c                              ; MAJA	 */


		vpsrld	XTMP4, XTMP1, 3	/*  XTMP4 = W[-15] >> 3 */
	mov	y2, f		/*  y2 = f                                ; CH	 */
	rorx	T1, a, 13	/*  T1 = a >> 13				; S0B */
	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11)		; S1 */
	xor	y2, g		/*  y2 = f^g                              ; CH	 */


	rorx	y1, e, 6	/*  y1 = (e >> 6)				; S1 */
	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11) ^ (e>>6)	; S1 */
	rorx	y1, a, 22	/*  y1 = a >> 22				; S0A */
	and	y2, e		/*  y2 = (f^g)&e                          ; CH	 */
	add	d, h		/*  d = k + w + h + d                     ; --	 */

		vpslld	XTMP1, XTMP1, (32-18)
	and	y3, b		/*  y3 = (a|c)&b                          ; MAJA	 */
	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13)		; S0 */

		vpxor	XTMP3, XTMP3, XTMP1
	rorx	T1, a, 2	/*  T1 = (a >> 2)				; S0 */
	xor	y2, g		/*  y2 = CH = ((f^g)&e)^g                 ; CH	 */

		vpxor	XTMP3, XTMP3, XTMP2	/*  XTMP3 = W[-15] ror 7 ^ W[-15] ror 18 */
	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13) ^ (a>>2)	; S0 */
	mov	T1, a		/*  T1 = a                                ; MAJB	 */
	and	T1, c		/*  T1 = a&c                              ; MAJB	 */
	add	y2, y0		/*  y2 = S1 + CH                          ; --	 */

		vpxor	XTMP1, XTMP3, XTMP4	/*  XTMP1 = s0 */
		vpshufd	XTMP2, X3, 0b11111010	/*  XTMP2 = W[-2] {BBAA} */
	or	y3, T1		/*  y3 = MAJ = (a|c)&b)|(a&c)             ; MAJ	 */
	add	h, y1		/*  h = k + w + h + S0                    ; --	 */

		vpaddd	XTMP0, XTMP0, XTMP1	/*  XTMP0 = W[-16] + W[-7] + s0 */
	add	d, y2		/*  d = k + w + h + d + S1 + CH = d + t1  ; --	 */
	add	h, y2		/*  h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */
	lea	h, [h + y3]	/*  h = t1 + S0 + MAJ                     ; --	 */

		vpsrld	XTMP4, XTMP2, 10	/*  XTMP4 = W[-2] >> 10 {BBAA} */


ROTATE_ARGS

/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 2 ;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	mov	y3, a		/*  y3 = a                                ; MAJA	 */
	rorx	y0, e, 25	/*  y0 = e >> 25				; S1A */
	add	h, [\XFER+2*4]		/*  h = k + w + h         ; --	 */

		vpsrlq	XTMP3, XTMP2, 19	/*  XTMP3 = W[-2] ror 19 {xBxA} */
	rorx	y1, e, 11	/*  y1 = e >> 11				; S1B */
	or	y3, c		/*  y3 = a|c                              ; MAJA	 */
	mov	y2, f		/*  y2 = f                                ; CH	 */
	xor	y2, g		/*  y2 = f^g                              ; CH	 */

	rorx	T1, a, 13	/*  T1 = a >> 13				; S0B */
	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11)		; S1 */
		vpsrlq	XTMP2, XTMP2, 17	/*  XTMP2 = W[-2] ror 17 {xBxA} */
	and	y2, e		/*  y2 = (f^g)&e                          ; CH	 */

	rorx	y1, e, 6	/*  y1 = (e >> 6)				; S1 */
		vpxor	XTMP2, XTMP2, XTMP3
	add	d, h		/*  d = k + w + h + d                     ; --	 */
	and	y3, b		/*  y3 = (a|c)&b                          ; MAJA	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11) ^ (e>>6)	; S1 */
	rorx	y1, a, 22	/*  y1 = a >> 22				; S0A */
		vpxor	XTMP4, XTMP4, XTMP2	/*  XTMP4 = s1 {xBxA} */
	xor	y2, g		/*  y2 = CH = ((f^g)&e)^g                 ; CH	 */

		vpshufb	XTMP4, XTMP4, SHUF_00BA	/*  XTMP4 = s1 {00BA} */
	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13)		; S0 */
	rorx	T1, a, 2	/*  T1 = (a >> 2)				; S0 */
		vpaddd	XTMP0, XTMP0, XTMP4	/*  XTMP0 = {..., ..., W[1], W[0]} */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13) ^ (a>>2)	; S0 */
	mov	T1, a		/*  T1 = a                                ; MAJB	 */
	and	T1, c		/*  T1 = a&c                              ; MAJB	 */
	add	y2, y0		/*  y2 = S1 + CH                          ; --	 */
		vpshufd	XTMP2, XTMP0, 0b1010000	/*  XTMP2 = W[-2] {DDCC} */

	or	y3, T1		/*  y3 = MAJ = (a|c)&b)|(a&c)             ; MAJ	 */
	add	h, y1		/*  h = k + w + h + S0                    ; --	 */
	add	d, y2		/*  d = k + w + h + d + S1 + CH = d + t1  ; --	 */
	add	h, y2		/*  h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */

	lea	h, [h + y3]	/*  h = t1 + S0 + MAJ                     ; --	 */


ROTATE_ARGS

/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 3 ;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	mov	y3, a		/*  y3 = a                                ; MAJA	 */
	rorx	y0, e, 25	/*  y0 = e >> 25				; S1A */
	rorx	y1, e, 11	/*  y1 = e >> 11				; S1B */
	add	h, [\XFER+3*4]		/*  h = k + w + h         ; --	 */
	or	y3, c		/*  y3 = a|c                              ; MAJA	 */


		vpsrld	XTMP5, XTMP2,   10	/*  XTMP5 = W[-2] >> 10 {DDCC} */
	mov	y2, f		/*  y2 = f                                ; CH	 */
	rorx	T1, a, 13	/*  T1 = a >> 13				; S0B */
	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11)		; S1 */
	xor	y2, g		/*  y2 = f^g                              ; CH	 */


		vpsrlq	XTMP3, XTMP2, 19	/*  XTMP3 = W[-2] ror 19 {xDxC} */
	rorx	y1, e, 6	/*  y1 = (e >> 6)				; S1 */
	and	y2, e		/*  y2 = (f^g)&e                          ; CH	 */
	add	d, h		/*  d = k + w + h + d                     ; --	 */
	and	y3, b		/*  y3 = (a|c)&b                          ; MAJA	 */

		vpsrlq	XTMP2, XTMP2, 17	/*  XTMP2 = W[-2] ror 17 {xDxC} */
	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11) ^ (e>>6)	; S1 */
	xor	y2, g		/*  y2 = CH = ((f^g)&e)^g                 ; CH	 */

		vpxor	XTMP2, XTMP2, XTMP3
	rorx	y1, a, 22	/*  y1 = a >> 22				; S0A */
	add	y2, y0		/*  y2 = S1 + CH                          ; --	 */

		vpxor	XTMP5, XTMP5, XTMP2	/*  XTMP5 = s1 {xDxC} */
	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13)		; S0 */
	add	d, y2		/*  d = k + w + h + d + S1 + CH = d + t1  ; --	 */

	rorx	T1, a, 2	/*  T1 = (a >> 2)				; S0 */
		vpshufb	XTMP5, XTMP5, SHUF_DC00	/*  XTMP5 = s1 {DC00} */

		vpaddd	X0, XTMP5, XTMP0	/*  X0 = {W[3], W[2], W[1], W[0]} */
	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13) ^ (a>>2)	; S0 */
	mov	T1, a		/*  T1 = a                                ; MAJB	 */
	and	T1, c		/*  T1 = a&c                              ; MAJB	 */
	or	y3, T1		/*  y3 = MAJ = (a|c)&b)|(a&c)             ; MAJ	 */

	add	h, y1		/*  h = k + w + h + S0                    ; --	 */
	add	h, y2		/*  h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */
	lea	h, [h + y3]	/*  h = t1 + S0 + MAJ                     ; --	 */

ROTATE_ARGS
rotate_Xs
.endm

.macro DO_4ROUNDS XFER
/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 0 ;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	mov	y2, f		/*  y2 = f                                ; CH	 */
	rorx	y0, e, 25	/*  y0 = e >> 25				; S1A */
	rorx	y1, e, 11	/*  y1 = e >> 11				; S1B */
	xor	y2, g		/*  y2 = f^g                              ; CH	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11)		; S1 */
	rorx	y1, e, 6	/*  y1 = (e >> 6)				; S1 */
	and	y2, e		/*  y2 = (f^g)&e                          ; CH	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11) ^ (e>>6)	; S1 */
	rorx	T1, a, 13	/*  T1 = a >> 13				; S0B */
	xor	y2, g		/*  y2 = CH = ((f^g)&e)^g                 ; CH	 */
	rorx	y1, a, 22	/*  y1 = a >> 22				; S0A */
	mov	y3, a		/*  y3 = a                                ; MAJA	 */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13)		; S0 */
	rorx	T1, a, 2	/*  T1 = (a >> 2)				; S0 */
	add	h, [\XFER + 4*0]		/*  h = k + w + h ; --	 */
	or	y3, c		/*  y3 = a|c                              ; MAJA	 */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13) ^ (a>>2)	; S0 */
	mov	T1, a		/*  T1 = a                                ; MAJB	 */
	and	y3, b		/*  y3 = (a|c)&b                          ; MAJA	 */
	and	T1, c		/*  T1 = a&c                              ; MAJB	 */
	add	y2, y0		/*  y2 = S1 + CH                          ; --	 */


	add	d, h		/*  d = k + w + h + d                     ; --	 */
	or	y3, T1		/*  y3 = MAJ = (a|c)&b)|(a&c)             ; MAJ	 */
	add	h, y1		/*  h = k + w + h + S0                    ; --	 */

	add	d, y2		/*  d = k + w + h + d + S1 + CH = d + t1  ; --	 */


	/* add	h, y2		; h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */

	/* lea	h, [h + y3]	; h = t1 + S0 + MAJ                     ; --	 */

	ROTATE_ARGS

/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 1 ;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	add	old_h, y2	/*  h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */
	mov	y2, f		/*  y2 = f                                ; CH	 */
	rorx	y0, e, 25	/*  y0 = e >> 25				; S1A */
	rorx	y1, e, 11	/*  y1 = e >> 11				; S1B */
	xor	y2, g		/*  y2 = f^g                              ; CH	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11)		; S1 */
	rorx	y1, e, 6	/*  y1 = (e >> 6)				; S1 */
	and	y2, e		/*  y2 = (f^g)&e                          ; CH	 */
	add	old_h, y3	/*  h = t1 + S0 + MAJ                     ; --	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11) ^ (e>>6)	; S1 */
	rorx	T1, a, 13	/*  T1 = a >> 13				; S0B */
	xor	y2, g		/*  y2 = CH = ((f^g)&e)^g                 ; CH	 */
	rorx	y1, a, 22	/*  y1 = a >> 22				; S0A */
	mov	y3, a		/*  y3 = a                                ; MAJA	 */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13)		; S0 */
	rorx	T1, a, 2	/*  T1 = (a >> 2)				; S0 */
	add	h, [\XFER + 4*1]		/*  h = k + w + h ; --	 */
	or	y3, c		/*  y3 = a|c                              ; MAJA	 */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13) ^ (a>>2)	; S0 */
	mov	T1, a		/*  T1 = a                                ; MAJB	 */
	and	y3, b		/*  y3 = (a|c)&b                          ; MAJA	 */
	and	T1, c		/*  T1 = a&c                              ; MAJB	 */
	add	y2, y0		/*  y2 = S1 + CH                          ; --	 */


	add	d, h		/*  d = k + w + h + d                     ; --	 */
	or	y3, T1		/*  y3 = MAJ = (a|c)&b)|(a&c)             ; MAJ	 */
	add	h, y1		/*  h = k + w + h + S0                    ; --	 */

	add	d, y2		/*  d = k + w + h + d + S1 + CH = d + t1  ; --	 */


	/* add	h, y2		; h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */

	/* lea	h, [h + y3]	; h = t1 + S0 + MAJ                     ; --	 */

	ROTATE_ARGS

/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 2 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	add	old_h, y2	/*  h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */
	mov	y2, f		/*  y2 = f                                ; CH	 */
	rorx	y0, e, 25	/*  y0 = e >> 25				; S1A */
	rorx	y1, e, 11	/*  y1 = e >> 11				; S1B */
	xor	y2, g		/*  y2 = f^g                              ; CH	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11)		; S1 */
	rorx	y1, e, 6	/*  y1 = (e >> 6)				; S1 */
	and	y2, e		/*  y2 = (f^g)&e                          ; CH	 */
	add	old_h, y3	/*  h = t1 + S0 + MAJ                     ; --	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11) ^ (e>>6)	; S1 */
	rorx	T1, a, 13	/*  T1 = a >> 13				; S0B */
	xor	y2, g		/*  y2 = CH = ((f^g)&e)^g                 ; CH	 */
	rorx	y1, a, 22	/*  y1 = a >> 22				; S0A */
	mov	y3, a		/*  y3 = a                                ; MAJA	 */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13)		; S0 */
	rorx	T1, a, 2	/*  T1 = (a >> 2)				; S0 */
	add	h, [\XFER + 4*2]		/*  h = k + w + h ; --	 */
	or	y3, c		/*  y3 = a|c                              ; MAJA	 */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13) ^ (a>>2)	; S0 */
	mov	T1, a		/*  T1 = a                                ; MAJB	 */
	and	y3, b		/*  y3 = (a|c)&b                          ; MAJA	 */
	and	T1, c		/*  T1 = a&c                              ; MAJB	 */
	add	y2, y0		/*  y2 = S1 + CH                          ; --	 */


	add	d, h		/*  d = k + w + h + d                     ; --	 */
	or	y3, T1		/*  y3 = MAJ = (a|c)&b)|(a&c)             ; MAJ	 */
	add	h, y1		/*  h = k + w + h + S0                    ; --	 */

	add	d, y2		/*  d = k + w + h + d + S1 + CH = d + t1  ; --	 */


	/* add	h, y2		; h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */

	/* lea	h, [h + y3]	; h = t1 + S0 + MAJ                     ; --	 */

	ROTATE_ARGS

/* ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 3 ;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	add	old_h, y2	/*  h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */
	mov	y2, f		/*  y2 = f                                ; CH	 */
	rorx	y0, e, 25	/*  y0 = e >> 25				; S1A */
	rorx	y1, e, 11	/*  y1 = e >> 11				; S1B */
	xor	y2, g		/*  y2 = f^g                              ; CH	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11)		; S1 */
	rorx	y1, e, 6	/*  y1 = (e >> 6)				; S1 */
	and	y2, e		/*  y2 = (f^g)&e                          ; CH	 */
	add	old_h, y3	/*  h = t1 + S0 + MAJ                     ; --	 */

	xor	y0, y1		/*  y0 = (e>>25) ^ (e>>11) ^ (e>>6)	; S1 */
	rorx	T1, a, 13	/*  T1 = a >> 13				; S0B */
	xor	y2, g		/*  y2 = CH = ((f^g)&e)^g                 ; CH	 */
	rorx	y1, a, 22	/*  y1 = a >> 22				; S0A */
	mov	y3, a		/*  y3 = a                                ; MAJA	 */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13)		; S0 */
	rorx	T1, a, 2	/*  T1 = (a >> 2)				; S0 */
	add	h, [\XFER + 4*3]		/*  h = k + w + h ; --	 */
	or	y3, c		/*  y3 = a|c                              ; MAJA	 */

	xor	y1, T1		/*  y1 = (a>>22) ^ (a>>13) ^ (a>>2)	; S0 */
	mov	T1, a		/*  T1 = a                                ; MAJB	 */
	and	y3, b		/*  y3 = (a|c)&b                          ; MAJA	 */
	and	T1, c		/*  T1 = a&c                              ; MAJB	 */
	add	y2, y0		/*  y2 = S1 + CH                          ; --	 */


	add	d, h		/*  d = k + w + h + d                     ; --	 */
	or	y3, T1		/*  y3 = MAJ = (a|c)&b)|(a&c)             ; MAJ	 */
	add	h, y1		/*  h = k + w + h + S0                    ; --	 */

	add	d, y2		/*  d = k + w + h + d + S1 + CH = d + t1  ; --	 */


	add	h, y2		/*  h = k + w + h + S0 + S1 + CH = t1 + S0; --	 */

	lea	h, [h + y3]	/*  h = t1 + S0 + MAJ                     ; --	 */

	ROTATE_ARGS
.endm

/*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha256_rorx(void *input_data, UINT32 digest[8], UINT64 num_blks)
;; arg 1 : pointer to input data
;; arg 2 : pointer to digest
;; arg 3 : Num blocks
*/
.text
.globl _gcry_sha256_transform_amd64_avx2
ELF(.type _gcry_sha256_transform_amd64_avx2,@function)
.align 32
_gcry_sha256_transform_amd64_avx2:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15

	vzeroupper

	mov	rax, rsp
	sub	rsp, STACK_SIZE
	and	rsp, -32
	mov	[rsp + _RSP], rax

	shl	NUM_BLKS, 6	/*  convert to bytes */
	jz	.Ldone_hash
	lea	NUM_BLKS, [NUM_BLKS + INP - 64] /*  pointer to last block */
	mov	[rsp + _INP_END], NUM_BLKS

	cmp	INP, NUM_BLKS
	je	.Lonly_one_block

	/* ; load initial digest */
	mov	a,[4*0 + CTX]
	mov	b,[4*1 + CTX]
	mov	c,[4*2 + CTX]
	mov	d,[4*3 + CTX]
	mov	e,[4*4 + CTX]
	mov	f,[4*5 + CTX]
	mov	g,[4*6 + CTX]
	mov	h,[4*7 + CTX]

	vmovdqa	BYTE_FLIP_MASK, [.LPSHUFFLE_BYTE_FLIP_MASK ADD_RIP]
	vmovdqa	SHUF_00BA, [.L_SHUF_00BA ADD_RIP]
	vmovdqa	SHUF_DC00, [.L_SHUF_DC00 ADD_RIP]

	mov	[rsp + _CTX], CTX

.Loop0:
	lea	TBL, [.LK256 ADD_RIP]

	/* ; Load first 16 dwords from two blocks */
	VMOVDQ	XTMP0, [INP + 0*32]
	VMOVDQ	XTMP1, [INP + 1*32]
	VMOVDQ	XTMP2, [INP + 2*32]
	VMOVDQ	XTMP3, [INP + 3*32]

	/* ; byte swap data */
	vpshufb	XTMP0, XTMP0, BYTE_FLIP_MASK
	vpshufb	XTMP1, XTMP1, BYTE_FLIP_MASK
	vpshufb	XTMP2, XTMP2, BYTE_FLIP_MASK
	vpshufb	XTMP3, XTMP3, BYTE_FLIP_MASK

	/* ; transpose data into high/low halves */
	vperm2i128	X0, XTMP0, XTMP2, 0x20
	vperm2i128	X1, XTMP0, XTMP2, 0x31
	vperm2i128	X2, XTMP1, XTMP3, 0x20
	vperm2i128	X3, XTMP1, XTMP3, 0x31

.Last_block_enter:
	add	INP, 64
	mov	[rsp + _INP], INP

	/* ; schedule 48 input dwords, by doing 3 rounds of 12 each */
	xor	SRND, SRND

.align 16
.Loop1:
	vpaddd	XFER, X0, [TBL + SRND + 0*32]
	vmovdqa [rsp + _XFER + SRND + 0*32], XFER
	FOUR_ROUNDS_AND_SCHED	rsp + _XFER + SRND + 0*32

	vpaddd	XFER, X0, [TBL + SRND + 1*32]
	vmovdqa [rsp + _XFER + SRND + 1*32], XFER
	FOUR_ROUNDS_AND_SCHED	rsp + _XFER + SRND + 1*32

	vpaddd	XFER, X0, [TBL + SRND + 2*32]
	vmovdqa [rsp + _XFER + SRND + 2*32], XFER
	FOUR_ROUNDS_AND_SCHED	rsp + _XFER + SRND + 2*32

	vpaddd	XFER, X0, [TBL + SRND + 3*32]
	vmovdqa [rsp + _XFER + SRND + 3*32], XFER
	FOUR_ROUNDS_AND_SCHED	rsp + _XFER + SRND + 3*32

	add	SRND, 4*32
	cmp	SRND, 3 * 4*32
	jb	.Loop1

.Loop2:
	/* ; Do last 16 rounds with no scheduling */
	vpaddd	XFER, X0, [TBL + SRND + 0*32]
	vmovdqa [rsp + _XFER + SRND + 0*32], XFER
	DO_4ROUNDS	rsp + _XFER + SRND + 0*32
	vpaddd	XFER, X1, [TBL + SRND + 1*32]
	vmovdqa [rsp + _XFER + SRND + 1*32], XFER
	DO_4ROUNDS	rsp + _XFER + SRND + 1*32
	add	SRND, 2*32

	vmovdqa	X0, X2
	vmovdqa	X1, X3

	cmp	SRND, 4 * 4*32
	jb	.Loop2

	mov	CTX, [rsp + _CTX]
	mov	INP, [rsp + _INP]

	addm	[4*0 + CTX],a
	addm	[4*1 + CTX],b
	addm	[4*2 + CTX],c
	addm	[4*3 + CTX],d
	addm	[4*4 + CTX],e
	addm	[4*5 + CTX],f
	addm	[4*6 + CTX],g
	addm	[4*7 + CTX],h

	cmp	INP, [rsp + _INP_END]
	ja	.Ldone_hash

	/* ;;; Do second block using previously scheduled results */
	xor	SRND, SRND
.align 16
.Loop3:
	DO_4ROUNDS	rsp + _XFER + SRND + 0*32 + 16
	DO_4ROUNDS	rsp + _XFER + SRND + 1*32 + 16
	add	SRND, 2*32
	cmp	SRND, 4 * 4*32
	jb .Loop3

	mov	CTX, [rsp + _CTX]
	mov	INP, [rsp + _INP]
	add	INP, 64

	addm	[4*0 + CTX],a
	addm	[4*1 + CTX],b
	addm	[4*2 + CTX],c
	addm	[4*3 + CTX],d
	addm	[4*4 + CTX],e
	addm	[4*5 + CTX],f
	addm	[4*6 + CTX],g
	addm	[4*7 + CTX],h

	cmp	INP, [rsp + _INP_END]
	jb	.Loop0
	ja	.Ldone_hash

.Ldo_last_block:
	/* ;;; do last block */
	lea	TBL, [.LK256 ADD_RIP]

	VMOVDQ	XWORD0, [INP + 0*16]
	VMOVDQ	XWORD1, [INP + 1*16]
	VMOVDQ	XWORD2, [INP + 2*16]
	VMOVDQ	XWORD3, [INP + 3*16]

	vpshufb	XWORD0, XWORD0, X_BYTE_FLIP_MASK
	vpshufb	XWORD1, XWORD1, X_BYTE_FLIP_MASK
	vpshufb	XWORD2, XWORD2, X_BYTE_FLIP_MASK
	vpshufb	XWORD3, XWORD3, X_BYTE_FLIP_MASK

	jmp	.Last_block_enter

.Lonly_one_block:

	/* ; load initial digest */
	mov	a,[4*0 + CTX]
	mov	b,[4*1 + CTX]
	mov	c,[4*2 + CTX]
	mov	d,[4*3 + CTX]
	mov	e,[4*4 + CTX]
	mov	f,[4*5 + CTX]
	mov	g,[4*6 + CTX]
	mov	h,[4*7 + CTX]

	vmovdqa	BYTE_FLIP_MASK, [.LPSHUFFLE_BYTE_FLIP_MASK ADD_RIP]
	vmovdqa	SHUF_00BA, [.L_SHUF_00BA ADD_RIP]
	vmovdqa	SHUF_DC00, [.L_SHUF_DC00 ADD_RIP]

	mov	[rsp + _CTX], CTX
	jmp	.Ldo_last_block

.Ldone_hash:
	mov	rsp, [rsp + _RSP]

	vzeroall

	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx

	/* stack burn depth */
	mov	eax, STACK_SIZE + 6*8 + 31

	ret

.data
.align 64
.LK256:
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

.LPSHUFFLE_BYTE_FLIP_MASK:
	.octa 0x0c0d0e0f08090a0b0405060700010203,0x0c0d0e0f08090a0b0405060700010203

/*  shuffle xBxA -> 00BA */
.L_SHUF_00BA:
	.octa 0xFFFFFFFFFFFFFFFF0b0a090803020100,0xFFFFFFFFFFFFFFFF0b0a090803020100

/*  shuffle xDxC -> DC00 */
.L_SHUF_DC00:
	.octa 0x0b0a090803020100FFFFFFFFFFFFFFFF,0x0b0a090803020100FFFFFFFFFFFFFFFF

#endif
#endif
