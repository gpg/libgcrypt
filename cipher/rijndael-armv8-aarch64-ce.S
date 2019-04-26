/* rijndael-armv8-aarch64-ce.S - ARMv8/CE accelerated AES
 * Copyright (C) 2016 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#include "asm-common-aarch64.h"

#if defined(__AARCH64EL__) && \
    defined(HAVE_COMPATIBLE_GCC_AARCH64_PLATFORM_AS) && \
    defined(HAVE_GCC_INLINE_ASM_AARCH64_CRYPTO)

.cpu generic+simd+crypto

.text


/* Register macros */

#define vk0 v17
#define vk1 v18
#define vk2 v19
#define vk3 v20
#define vk4 v21
#define vk5 v22
#define vk6 v23
#define vk7 v24
#define vk8 v25
#define vk9 v26
#define vk10 v27
#define vk11 v28
#define vk12 v29
#define vk13 v30
#define vk14 v31


/* AES macros */

#define aes_preload_keys(keysched, nrounds) \
	cmp nrounds, #12; \
	ld1 {vk0.16b-vk3.16b}, [keysched], #64; \
	ld1 {vk4.16b-vk7.16b}, [keysched], #64; \
	ld1 {vk8.16b-vk10.16b}, [keysched], #48; \
	b.lo 1f; \
	ld1 {vk11.16b-vk12.16b}, [keysched], #32; \
	b.eq 1f; \
	ld1 {vk13.16b-vk14.16b}, [keysched]; \
1:	;

#define do_aes_one128(ed, mcimc, vo, vb) \
	aes##ed    vb.16b, vk0.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk1.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk2.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk3.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk4.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk5.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk6.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk7.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk8.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk9.16b; \
	eor        vo.16b, vb.16b, vk10.16b;

#define do_aes_one192(ed, mcimc, vo, vb) \
	aes##ed    vb.16b, vk0.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk1.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk2.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk3.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk4.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk5.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk6.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk7.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk8.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk9.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk10.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk11.16b; \
	eor        vo.16b, vb.16b, vk12.16b;

#define do_aes_one256(ed, mcimc, vo, vb) \
	aes##ed    vb.16b, vk0.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk1.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk2.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk3.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk4.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk5.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk6.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk7.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk8.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk9.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk10.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk11.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk12.16b; \
	aes##mcimc vb.16b, vb.16b; \
	aes##ed    vb.16b, vk13.16b; \
	eor        vo.16b, vb.16b, vk14.16b;

#define aes_round_4(ed, mcimc, b0, b1, b2, b3, key) \
	aes##ed    b0.16b, key.16b; \
	aes##mcimc b0.16b, b0.16b; \
	  aes##ed    b1.16b, key.16b; \
	  aes##mcimc b1.16b, b1.16b; \
	    aes##ed    b2.16b, key.16b; \
	    aes##mcimc b2.16b, b2.16b; \
	      aes##ed    b3.16b, key.16b; \
	      aes##mcimc b3.16b, b3.16b;

#define aes_lastround_4(ed, b0, b1, b2, b3, key1, key2) \
	aes##ed    b0.16b, key1.16b; \
	eor        b0.16b, b0.16b, key2.16b; \
	  aes##ed    b1.16b, key1.16b; \
	  eor        b1.16b, b1.16b, key2.16b; \
	    aes##ed    b2.16b, key1.16b; \
	    eor        b2.16b, b2.16b, key2.16b; \
	      aes##ed    b3.16b, key1.16b; \
	      eor        b3.16b, b3.16b, key2.16b;

#define do_aes_4_128(ed, mcimc, b0, b1, b2, b3) \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk0); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk1); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk2); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk3); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk4); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk5); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk6); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk7); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk8); \
	aes_lastround_4(ed, b0, b1, b2, b3, vk9, vk10);

#define do_aes_4_192(ed, mcimc, b0, b1, b2, b3) \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk0); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk1); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk2); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk3); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk4); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk5); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk6); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk7); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk8); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk9); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk10); \
	aes_lastround_4(ed, b0, b1, b2, b3, vk11, vk12);

#define do_aes_4_256(ed, mcimc, b0, b1, b2, b3) \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk0); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk1); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk2); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk3); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk4); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk5); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk6); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk7); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk8); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk9); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk10); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk11); \
	aes_round_4(ed, mcimc, b0, b1, b2, b3, vk12); \
	aes_lastround_4(ed, b0, b1, b2, b3, vk13, vk14);


/* Other functional macros */

#define CLEAR_REG(reg) eor reg.16b, reg.16b, reg.16b;

#define aes_clear_keys(nrounds) \
	cmp nrounds, #12; \
	CLEAR_REG(vk0); \
	CLEAR_REG(vk1); \
	CLEAR_REG(vk2); \
	CLEAR_REG(vk3); \
	CLEAR_REG(vk4); \
	CLEAR_REG(vk5); \
	CLEAR_REG(vk6); \
	CLEAR_REG(vk7); \
	CLEAR_REG(vk9); \
	CLEAR_REG(vk8); \
	CLEAR_REG(vk10); \
	b.lo 1f; \
	CLEAR_REG(vk11); \
	CLEAR_REG(vk12); \
	b.eq 1f; \
	CLEAR_REG(vk13); \
	CLEAR_REG(vk14); \
1:	;


/*
 * unsigned int _gcry_aes_enc_armv8_ce(void *keysched, byte *dst,
 *                                     const byte *src,
 *                                     unsigned int nrounds);
 */
.align 3
.globl _gcry_aes_enc_armv8_ce
ELF(.type  _gcry_aes_enc_armv8_ce,%function;)
_gcry_aes_enc_armv8_ce:
  /* input:
   *    x0: keysched
   *    x1: dst
   *    x2: src
   *    w3: nrounds
   */
  CFI_STARTPROC();

  aes_preload_keys(x0, w3);

  ld1 {v0.16b}, [x2]

  b.hi .Lenc1_256
  b.eq .Lenc1_192

.Lenc1_128:
  do_aes_one128(e, mc, v0, v0);

.Lenc1_tail:
  CLEAR_REG(vk0)
  CLEAR_REG(vk1)
  CLEAR_REG(vk2)
  CLEAR_REG(vk3)
  CLEAR_REG(vk4)
  CLEAR_REG(vk5)
  CLEAR_REG(vk6)
  CLEAR_REG(vk7)
  CLEAR_REG(vk8)
  CLEAR_REG(vk9)
  CLEAR_REG(vk10)
  st1 {v0.16b}, [x1]
  CLEAR_REG(v0)

  mov x0, #0
  ret

.Lenc1_192:
  do_aes_one192(e, mc, v0, v0);

  CLEAR_REG(vk11)
  CLEAR_REG(vk12)
  b .Lenc1_tail

.Lenc1_256:
  do_aes_one256(e, mc, v0, v0);

  CLEAR_REG(vk11)
  CLEAR_REG(vk12)
  CLEAR_REG(vk13)
  CLEAR_REG(vk14)
  b .Lenc1_tail
  CFI_ENDPROC();
ELF(.size _gcry_aes_enc_armv8_ce,.-_gcry_aes_enc_armv8_ce;)


/*
 * unsigned int _gcry_aes_dec_armv8_ce(void *keysched, byte *dst,
 *                                     const byte *src,
 *                                     unsigned int nrounds);
 */
.align 3
.globl _gcry_aes_dec_armv8_ce
ELF(.type  _gcry_aes_dec_armv8_ce,%function;)
_gcry_aes_dec_armv8_ce:
  /* input:
   *    x0: keysched
   *    x1: dst
   *    x2: src
   *    w3: nrounds
   */
  CFI_STARTPROC();

  aes_preload_keys(x0, w3);

  ld1 {v0.16b}, [x2]

  b.hi .Ldec1_256
  b.eq .Ldec1_192

.Ldec1_128:
  do_aes_one128(d, imc, v0, v0);

.Ldec1_tail:
  CLEAR_REG(vk0)
  CLEAR_REG(vk1)
  CLEAR_REG(vk2)
  CLEAR_REG(vk3)
  CLEAR_REG(vk4)
  CLEAR_REG(vk5)
  CLEAR_REG(vk6)
  CLEAR_REG(vk7)
  CLEAR_REG(vk8)
  CLEAR_REG(vk9)
  CLEAR_REG(vk10)
  st1 {v0.16b}, [x1]
  CLEAR_REG(v0)

  mov x0, #0
  ret

.Ldec1_192:
  do_aes_one192(d, imc, v0, v0);

  CLEAR_REG(vk11)
  CLEAR_REG(vk12)
  b .Ldec1_tail

.Ldec1_256:
  do_aes_one256(d, imc, v0, v0);

  CLEAR_REG(vk11)
  CLEAR_REG(vk12)
  CLEAR_REG(vk13)
  CLEAR_REG(vk14)
  b .Ldec1_tail
  CFI_ENDPROC();
ELF(.size _gcry_aes_dec_armv8_ce,.-_gcry_aes_dec_armv8_ce;)


/*
 * void _gcry_aes_cbc_enc_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *iv, size_t nblocks,
 *                                  int cbc_mac, unsigned int nrounds);
 */

.align 3
.globl _gcry_aes_cbc_enc_armv8_ce
ELF(.type  _gcry_aes_cbc_enc_armv8_ce,%function;)
_gcry_aes_cbc_enc_armv8_ce:
  /* input:
   *    x0: keysched
   *    x1: outbuf
   *    x2: inbuf
   *    x3: iv
   *    x4: nblocks
   *    w5: cbc_mac
   *    w6: nrounds
   */
  CFI_STARTPROC();

  cbz x4, .Lcbc_enc_skip

  cmp w5, #0
  ld1 {v1.16b}, [x3] /* load IV */
  cset x5, eq

  aes_preload_keys(x0, w6);
  lsl x5, x5, #4

  b.eq .Lcbc_enc_loop192
  b.hi .Lcbc_enc_loop256

#define CBC_ENC(bits) \
  .Lcbc_enc_loop##bits: \
    ld1 {v0.16b}, [x2], #16; /* load plaintext */ \
    eor v1.16b, v0.16b, v1.16b; \
    sub x4, x4, #1; \
    \
    do_aes_one##bits(e, mc, v1, v1); \
    \
    st1 {v1.16b}, [x1], x5; /* store ciphertext */ \
    \
    cbnz x4, .Lcbc_enc_loop##bits; \
    b .Lcbc_enc_done;

  CBC_ENC(128)
  CBC_ENC(192)
  CBC_ENC(256)

#undef CBC_ENC

.Lcbc_enc_done:
  aes_clear_keys(w6)

  st1 {v1.16b}, [x3] /* store IV */

  CLEAR_REG(v1)
  CLEAR_REG(v0)

.Lcbc_enc_skip:
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_cbc_enc_armv8_ce,.-_gcry_aes_cbc_enc_armv8_ce;)

/*
 * void _gcry_aes_cbc_dec_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *iv, unsigned int nrounds);
 */

.align 3
.globl _gcry_aes_cbc_dec_armv8_ce
ELF(.type  _gcry_aes_cbc_dec_armv8_ce,%function;)
_gcry_aes_cbc_dec_armv8_ce:
  /* input:
   *    x0: keysched
   *    x1: outbuf
   *    x2: inbuf
   *    x3: iv
   *    x4: nblocks
   *    w5: nrounds
   */
  CFI_STARTPROC();

  cbz x4, .Lcbc_dec_skip

  ld1 {v0.16b}, [x3] /* load IV */

  aes_preload_keys(x0, w5);

  b.eq .Lcbc_dec_entry_192
  b.hi .Lcbc_dec_entry_256

#define CBC_DEC(bits) \
  .Lcbc_dec_entry_##bits: \
    cmp x4, #4; \
    b.lo .Lcbc_dec_loop_##bits; \
    \
  .Lcbc_dec_loop4_##bits: \
    \
    ld1 {v1.16b-v4.16b}, [x2], #64; /* load ciphertext */ \
    sub x4, x4, #4; \
    mov v5.16b, v1.16b; \
    mov v6.16b, v2.16b; \
    mov v7.16b, v3.16b; \
    mov v16.16b, v4.16b; \
    cmp x4, #4; \
    \
    do_aes_4_##bits(d, imc, v1, v2, v3, v4); \
    \
    eor v1.16b, v1.16b, v0.16b; \
    eor v2.16b, v2.16b, v5.16b; \
    st1 {v1.16b-v2.16b}, [x1], #32; /* store plaintext */ \
    eor v3.16b, v3.16b, v6.16b; \
    eor v4.16b, v4.16b, v7.16b; \
    mov v0.16b, v16.16b; /* next IV */ \
    st1 {v3.16b-v4.16b}, [x1], #32; /* store plaintext */ \
    \
    b.hs .Lcbc_dec_loop4_##bits; \
    CLEAR_REG(v3); \
    CLEAR_REG(v4); \
    CLEAR_REG(v5); \
    CLEAR_REG(v6); \
    CLEAR_REG(v7); \
    CLEAR_REG(v16); \
    cbz x4, .Lcbc_dec_done; \
    \
  .Lcbc_dec_loop_##bits: \
    ld1 {v1.16b}, [x2], #16; /* load ciphertext */ \
    sub x4, x4, #1; \
    mov v2.16b, v1.16b; \
    \
    do_aes_one##bits(d, imc, v1, v1); \
    \
    eor v1.16b, v1.16b, v0.16b; \
    mov v0.16b, v2.16b; \
    st1 {v1.16b}, [x1], #16; /* store plaintext */ \
    \
    cbnz x4, .Lcbc_dec_loop_##bits; \
    b .Lcbc_dec_done;

  CBC_DEC(128)
  CBC_DEC(192)
  CBC_DEC(256)

#undef CBC_DEC

.Lcbc_dec_done:
  aes_clear_keys(w5)

  st1 {v0.16b}, [x3] /* store IV */

  CLEAR_REG(v0)
  CLEAR_REG(v1)
  CLEAR_REG(v2)

.Lcbc_dec_skip:
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_cbc_dec_armv8_ce,.-_gcry_aes_cbc_dec_armv8_ce;)


/*
 * void _gcry_aes_ctr_enc_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *iv, unsigned int nrounds);
 */

.align 3
.globl _gcry_aes_ctr_enc_armv8_ce
ELF(.type  _gcry_aes_ctr_enc_armv8_ce,%function;)
_gcry_aes_ctr_enc_armv8_ce:
  /* input:
   *    r0: keysched
   *    r1: outbuf
   *    r2: inbuf
   *    r3: iv
   *    x4: nblocks
   *    w5: nrounds
   */
  CFI_STARTPROC();

  cbz x4, .Lctr_enc_skip

  mov x6, #1
  movi v16.16b, #0
  mov v16.D[1], x6

  /* load IV */
  ldp x9, x10, [x3]
  ld1 {v0.16b}, [x3]
  rev x9, x9
  rev x10, x10

  aes_preload_keys(x0, w5);

  b.eq .Lctr_enc_entry_192
  b.hi .Lctr_enc_entry_256

#define CTR_ENC(bits) \
  .Lctr_enc_entry_##bits: \
    cmp x4, #4; \
    b.lo .Lctr_enc_loop_##bits; \
    \
  .Lctr_enc_loop4_##bits: \
    cmp x10, #0xfffffffffffffffc; \
    sub x4, x4, #4; \
    b.lo .Lctr_enc_loop4_##bits##_nocarry; \
    \
    adds x10, x10, #1; \
    mov v1.16b, v0.16b; \
    adc x9, x9, xzr; \
    mov v2.D[1], x10; \
    mov v2.D[0], x9; \
    \
    adds x10, x10, #1; \
    rev64 v2.16b, v2.16b; \
    adc x9, x9, xzr; \
    mov v3.D[1], x10; \
    mov v3.D[0], x9; \
    \
    adds x10, x10, #1; \
    rev64 v3.16b, v3.16b; \
    adc x9, x9, xzr; \
    mov v4.D[1], x10; \
    mov v4.D[0], x9; \
    \
    adds x10, x10, #1; \
    rev64 v4.16b, v4.16b; \
    adc x9, x9, xzr; \
    mov v0.D[1], x10; \
    mov v0.D[0], x9; \
    rev64 v0.16b, v0.16b; \
    \
    b .Lctr_enc_loop4_##bits##_store_ctr; \
    \
  .Lctr_enc_loop4_##bits##_nocarry: \
    \
    add v3.2d, v16.2d, v16.2d; /* 2 */ \
    rev64 v6.16b, v0.16b; \
    add x10, x10, #4; \
    add v4.2d, v3.2d, v16.2d;  /* 3 */ \
    add v0.2d, v3.2d, v3.2d;   /* 4 */ \
    rev64 v1.16b, v6.16b; \
    add v2.2d, v6.2d, v16.2d; \
    add v3.2d, v6.2d, v3.2d; \
    add v4.2d, v6.2d, v4.2d; \
    add v0.2d, v6.2d, v0.2d; \
    rev64 v2.16b, v2.16b; \
    rev64 v3.16b, v3.16b; \
    rev64 v0.16b, v0.16b; \
    rev64 v4.16b, v4.16b; \
    \
  .Lctr_enc_loop4_##bits##_store_ctr: \
    \
    st1 {v0.16b}, [x3]; \
    cmp x4, #4; \
    ld1 {v5.16b-v7.16b}, [x2], #48; /* preload ciphertext */ \
    \
    do_aes_4_##bits(e, mc, v1, v2, v3, v4); \
    \
    eor v1.16b, v1.16b, v5.16b; \
    ld1 {v5.16b}, [x2], #16; /* load ciphertext */ \
    eor v2.16b, v2.16b, v6.16b; \
    eor v3.16b, v3.16b, v7.16b; \
    eor v4.16b, v4.16b, v5.16b; \
    st1 {v1.16b-v4.16b}, [x1], #64; /* store plaintext */ \
    \
    b.hs .Lctr_enc_loop4_##bits; \
    CLEAR_REG(v3); \
    CLEAR_REG(v4); \
    CLEAR_REG(v5); \
    CLEAR_REG(v6); \
    CLEAR_REG(v7); \
    cbz x4, .Lctr_enc_done; \
    \
  .Lctr_enc_loop_##bits: \
    \
    adds x10, x10, #1; \
    mov v1.16b, v0.16b; \
    adc x9, x9, xzr; \
    mov v0.D[1], x10; \
    mov v0.D[0], x9; \
    sub x4, x4, #1; \
    ld1 {v2.16b}, [x2], #16; /* load ciphertext */ \
    rev64 v0.16b, v0.16b; \
    \
    do_aes_one##bits(e, mc, v1, v1); \
    \
    eor v1.16b, v2.16b, v1.16b; \
    st1 {v1.16b}, [x1], #16; /* store plaintext */ \
    \
    cbnz x4, .Lctr_enc_loop_##bits; \
    b .Lctr_enc_done;

  CTR_ENC(128)
  CTR_ENC(192)
  CTR_ENC(256)

#undef CTR_ENC

.Lctr_enc_done:
  aes_clear_keys(w5)

  st1 {v0.16b}, [x3] /* store IV */

  CLEAR_REG(v0)
  CLEAR_REG(v1)
  CLEAR_REG(v2)

.Lctr_enc_skip:
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_ctr_enc_armv8_ce,.-_gcry_aes_ctr_enc_armv8_ce;)


/*
 * void _gcry_aes_cfb_enc_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *iv, unsigned int nrounds);
 */

.align 3
.globl _gcry_aes_cfb_enc_armv8_ce
ELF(.type  _gcry_aes_cfb_enc_armv8_ce,%function;)
_gcry_aes_cfb_enc_armv8_ce:
  /* input:
   *    r0: keysched
   *    r1: outbuf
   *    r2: inbuf
   *    r3: iv
   *    x4: nblocks
   *    w5: nrounds
   */
  CFI_STARTPROC();

  cbz x4, .Lcfb_enc_skip

  /* load IV */
  ld1 {v0.16b}, [x3]

  aes_preload_keys(x0, w5);

  b.eq .Lcfb_enc_entry_192
  b.hi .Lcfb_enc_entry_256

#define CFB_ENC(bits) \
  .Lcfb_enc_entry_##bits: \
  .Lcfb_enc_loop_##bits: \
    ld1 {v1.16b}, [x2], #16; /* load plaintext */ \
    sub x4, x4, #1; \
    \
    do_aes_one##bits(e, mc, v0, v0); \
    \
    eor v0.16b, v1.16b, v0.16b; \
    st1 {v0.16b}, [x1], #16; /* store ciphertext */ \
    \
    cbnz x4, .Lcfb_enc_loop_##bits; \
    b .Lcfb_enc_done;

  CFB_ENC(128)
  CFB_ENC(192)
  CFB_ENC(256)

#undef CFB_ENC

.Lcfb_enc_done:
  aes_clear_keys(w5)

  st1 {v0.16b}, [x3] /* store IV */

  CLEAR_REG(v0)
  CLEAR_REG(v1)

.Lcfb_enc_skip:
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_cfb_enc_armv8_ce,.-_gcry_aes_cfb_enc_armv8_ce;)


/*
 * void _gcry_aes_cfb_dec_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *iv, unsigned int nrounds);
 */

.align 3
.globl _gcry_aes_cfb_dec_armv8_ce
ELF(.type  _gcry_aes_cfb_dec_armv8_ce,%function;)
_gcry_aes_cfb_dec_armv8_ce:
  /* input:
   *    r0: keysched
   *    r1: outbuf
   *    r2: inbuf
   *    r3: iv
   *    x4: nblocks
   *    w5: nrounds
   */
  CFI_STARTPROC();

  cbz x4, .Lcfb_dec_skip

  /* load IV */
  ld1 {v0.16b}, [x3]

  aes_preload_keys(x0, w5);

  b.eq .Lcfb_dec_entry_192
  b.hi .Lcfb_dec_entry_256

#define CFB_DEC(bits) \
  .Lcfb_dec_entry_##bits: \
    cmp x4, #4; \
    b.lo .Lcfb_dec_loop_##bits; \
    \
  .Lcfb_dec_loop4_##bits: \
    \
    ld1 {v2.16b-v4.16b}, [x2], #48; /* load ciphertext */ \
    mov v1.16b, v0.16b; \
    sub x4, x4, #4; \
    cmp x4, #4; \
    mov v5.16b, v2.16b; \
    mov v6.16b, v3.16b; \
    mov v7.16b, v4.16b; \
    ld1 {v0.16b}, [x2], #16; /* load next IV / ciphertext */ \
    \
    do_aes_4_##bits(e, mc, v1, v2, v3, v4); \
    \
    eor v1.16b, v1.16b, v5.16b; \
    eor v2.16b, v2.16b, v6.16b; \
    eor v3.16b, v3.16b, v7.16b; \
    eor v4.16b, v4.16b, v0.16b; \
    st1 {v1.16b-v4.16b}, [x1], #64; /* store plaintext */ \
    \
    b.hs .Lcfb_dec_loop4_##bits; \
    CLEAR_REG(v3); \
    CLEAR_REG(v4); \
    CLEAR_REG(v5); \
    CLEAR_REG(v6); \
    CLEAR_REG(v7); \
    cbz x4, .Lcfb_dec_done; \
    \
  .Lcfb_dec_loop_##bits: \
    \
    ld1 {v1.16b}, [x2], #16; /* load ciphertext */ \
    \
    sub x4, x4, #1; \
    \
    do_aes_one##bits(e, mc, v0, v0); \
    \
    eor v2.16b, v1.16b, v0.16b; \
    mov v0.16b, v1.16b; \
    st1 {v2.16b}, [x1], #16; /* store plaintext */ \
    \
    cbnz x4, .Lcfb_dec_loop_##bits; \
    b .Lcfb_dec_done;

  CFB_DEC(128)
  CFB_DEC(192)
  CFB_DEC(256)

#undef CFB_DEC

.Lcfb_dec_done:
  aes_clear_keys(w5)

  st1 {v0.16b}, [x3] /* store IV */

  CLEAR_REG(v0)
  CLEAR_REG(v1)
  CLEAR_REG(v2)

.Lcfb_dec_skip:
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_cfb_dec_armv8_ce,.-_gcry_aes_cfb_dec_armv8_ce;)


/*
 * void _gcry_aes_ocb_enc_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *offset,
 *                                  unsigned char *checksum,
 *                                  unsigned char *L_table,
 *                                  size_t nblocks,
 *                                  unsigned int nrounds,
 *                                  unsigned int blkn);
 */

.align 3
.globl _gcry_aes_ocb_enc_armv8_ce
ELF(.type  _gcry_aes_ocb_enc_armv8_ce,%function;)
_gcry_aes_ocb_enc_armv8_ce:
  /* input:
   *    x0: keysched
   *    x1: outbuf
   *    x2: inbuf
   *    x3: offset
   *    x4: checksum
   *    x5: Ltable
   *    x6: nblocks (0 < nblocks <= 32)
   *    w7: nrounds
   *    %st+0: blkn => w12
   */
  CFI_STARTPROC();

  ldr w12, [sp]
  ld1 {v0.16b}, [x3] /* load offset */
  ld1 {v16.16b}, [x4] /* load checksum */

  aes_preload_keys(x0, w7);

  b.eq .Locb_enc_entry_192
  b.hi .Locb_enc_entry_256

#define OCB_ENC(bits, ...) \
  .Locb_enc_entry_##bits: \
    cmp x6, #4; \
    add x12, x12, #1; \
    b.lo .Locb_enc_loop_##bits; \
    \
  .Locb_enc_loop4_##bits: \
    \
    /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */ \
    /* Checksum_i = Checksum_{i-1} xor P_i  */ \
    /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */ \
    \
    add w9, w12, #1; \
    add w10, w12, #2; \
    add w11, w12, #3; \
    rbit w8, w12; \
    add w12, w12, #4; \
    rbit w9, w9; \
    rbit w10, w10; \
    rbit w11, w11; \
    clz w8, w8; /* ntz(i+0) */ \
    clz w9, w9; /* ntz(i+1) */ \
    clz w10, w10; /* ntz(i+2) */ \
    clz w11, w11; /* ntz(i+3) */ \
    add x8, x5, x8, lsl #4; \
    ld1 {v1.16b-v4.16b}, [x2], #64;   /* load P_i+<0-3> */ \
    add x9, x5, x9, lsl #4; \
    add x10, x5, x10, lsl #4; \
    add x11, x5, x11, lsl #4; \
    \
    sub x6, x6, #4; \
    \
    ld1 {v5.16b}, [x8];               /* load L_{ntz(i+0)} */ \
    eor v16.16b, v16.16b, v1.16b;     /* Checksum_i+0 */ \
    ld1 {v6.16b}, [x9];               /* load L_{ntz(i+1)} */ \
    eor v16.16b, v16.16b, v2.16b;     /* Checksum_i+1 */ \
    ld1 {v7.16b}, [x10];              /* load L_{ntz(i+2)} */ \
    eor v16.16b, v16.16b, v3.16b;     /* Checksum_i+2 */ \
    eor v5.16b, v5.16b, v0.16b;       /* Offset_i+0 */ \
    ld1 {v0.16b}, [x11];              /* load L_{ntz(i+3)} */ \
    eor v16.16b, v16.16b, v4.16b;     /* Checksum_i+3 */ \
    eor v6.16b, v6.16b, v5.16b;       /* Offset_i+1 */ \
    eor v1.16b, v1.16b, v5.16b;       /* P_i+0 xor Offset_i+0 */ \
    eor v7.16b, v7.16b, v6.16b;       /* Offset_i+2 */ \
    eor v2.16b, v2.16b, v6.16b;       /* P_i+1 xor Offset_i+1 */ \
    eor v0.16b, v0.16b, v7.16b;       /* Offset_i+3 */ \
    cmp x6, #4; \
    eor v3.16b, v3.16b, v7.16b;       /* P_i+2 xor Offset_i+2 */ \
    eor v4.16b, v4.16b, v0.16b;       /* P_i+3 xor Offset_i+3 */ \
    \
    do_aes_4_##bits(e, mc, v1, v2, v3, v4); \
    \
    eor v1.16b, v1.16b, v5.16b;       /* xor Offset_i+0 */ \
    eor v2.16b, v2.16b, v6.16b;       /* xor Offset_i+1 */ \
    eor v3.16b, v3.16b, v7.16b;       /* xor Offset_i+2 */ \
    eor v4.16b, v4.16b, v0.16b;       /* xor Offset_i+3 */ \
    st1 {v1.16b-v4.16b}, [x1], #64; \
    \
    b.hs .Locb_enc_loop4_##bits; \
    CLEAR_REG(v3); \
    CLEAR_REG(v4); \
    CLEAR_REG(v5); \
    CLEAR_REG(v6); \
    CLEAR_REG(v7); \
    cbz x6, .Locb_enc_done; \
    \
  .Locb_enc_loop_##bits: \
    \
    /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */ \
    /* Checksum_i = Checksum_{i-1} xor P_i  */ \
    /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */ \
    \
    rbit x8, x12; \
    add x12, x12, #1; \
    clz x8, x8; /* ntz(i) */ \
    add x8, x5, x8, lsl #4; \
    \
    ld1 {v1.16b}, [x2], #16; /* load plaintext */ \
    ld1 {v2.16b}, [x8]; /* load L_{ntz(i)} */ \
    sub x6, x6, #1; \
    eor v0.16b, v0.16b, v2.16b; \
    eor v16.16b, v16.16b, v1.16b; \
    eor v1.16b, v1.16b, v0.16b; \
    \
    do_aes_one##bits(e, mc, v1, v1); \
    \
    eor v1.16b, v1.16b, v0.16b; \
    st1 {v1.16b}, [x1], #16; /* store ciphertext */ \
    \
    cbnz x6, .Locb_enc_loop_##bits; \
    b .Locb_enc_done;

  OCB_ENC(128)
  OCB_ENC(192)
  OCB_ENC(256)

#undef OCB_ENC

.Locb_enc_done:
  aes_clear_keys(w7)

  st1 {v16.16b}, [x4] /* store checksum */
  st1 {v0.16b}, [x3] /* store offset */

  CLEAR_REG(v0)
  CLEAR_REG(v1)
  CLEAR_REG(v2)
  CLEAR_REG(v16)

  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_ocb_enc_armv8_ce,.-_gcry_aes_ocb_enc_armv8_ce;)


/*
 * void _gcry_aes_ocb_dec_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *offset,
 *                                  unsigned char *checksum,
 *                                  unsigned char *L_table,
 *                                  size_t nblocks,
 *                                  unsigned int nrounds,
 *                                  unsigned int blkn);
 */

.align 3
.globl _gcry_aes_ocb_dec_armv8_ce
ELF(.type  _gcry_aes_ocb_dec_armv8_ce,%function;)
_gcry_aes_ocb_dec_armv8_ce:
  /* input:
   *    x0: keysched
   *    x1: outbuf
   *    x2: inbuf
   *    x3: offset
   *    x4: checksum
   *    x5: Ltable
   *    x6: nblocks (0 < nblocks <= 32)
   *    w7: nrounds
   *    %st+0: blkn => w12
   */
  CFI_STARTPROC();

  ldr w12, [sp]
  ld1 {v0.16b}, [x3] /* load offset */
  ld1 {v16.16b}, [x4] /* load checksum */

  aes_preload_keys(x0, w7);

  b.eq .Locb_dec_entry_192
  b.hi .Locb_dec_entry_256

#define OCB_DEC(bits) \
  .Locb_dec_entry_##bits: \
    cmp x6, #4; \
    add w12, w12, #1; \
    b.lo .Locb_dec_loop_##bits; \
    \
  .Locb_dec_loop4_##bits: \
    \
    /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */ \
    /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */ \
    /* Checksum_i = Checksum_{i-1} xor P_i  */ \
    \
    add w9, w12, #1; \
    add w10, w12, #2; \
    add w11, w12, #3; \
    rbit w8, w12; \
    add w12, w12, #4; \
    rbit w9, w9; \
    rbit w10, w10; \
    rbit w11, w11; \
    clz w8, w8; /* ntz(i+0) */ \
    clz w9, w9; /* ntz(i+1) */ \
    clz w10, w10; /* ntz(i+2) */ \
    clz w11, w11; /* ntz(i+3) */ \
    add x8, x5, x8, lsl #4; \
    ld1 {v1.16b-v4.16b}, [x2], #64;   /* load C_i+<0-3> */ \
    add x9, x5, x9, lsl #4; \
    add x10, x5, x10, lsl #4; \
    add x11, x5, x11, lsl #4; \
    \
    sub x6, x6, #4; \
    \
    ld1 {v5.16b}, [x8];               /* load L_{ntz(i+0)} */ \
    ld1 {v6.16b}, [x9];               /* load L_{ntz(i+1)} */ \
    ld1 {v7.16b}, [x10];              /* load L_{ntz(i+2)} */ \
    eor v5.16b, v5.16b, v0.16b;       /* Offset_i+0 */ \
    ld1 {v0.16b}, [x11];              /* load L_{ntz(i+3)} */ \
    eor v6.16b, v6.16b, v5.16b;       /* Offset_i+1 */ \
    eor v1.16b, v1.16b, v5.16b;       /* C_i+0 xor Offset_i+0 */ \
    eor v7.16b, v7.16b, v6.16b;       /* Offset_i+2 */ \
    eor v2.16b, v2.16b, v6.16b;       /* C_i+1 xor Offset_i+1 */ \
    eor v0.16b, v0.16b, v7.16b;       /* Offset_i+3 */ \
    cmp x6, #4; \
    eor v3.16b, v3.16b, v7.16b;       /* C_i+2 xor Offset_i+2 */ \
    eor v4.16b, v4.16b, v0.16b;       /* C_i+3 xor Offset_i+3 */ \
    \
    do_aes_4_##bits(d, imc, v1, v2, v3, v4); \
    \
    eor v1.16b, v1.16b, v5.16b;       /* xor Offset_i+0 */ \
    eor v2.16b, v2.16b, v6.16b;       /* xor Offset_i+1 */ \
    eor v16.16b, v16.16b, v1.16b;     /* Checksum_i+0 */ \
    eor v3.16b, v3.16b, v7.16b;       /* xor Offset_i+2 */ \
    eor v16.16b, v16.16b, v2.16b;     /* Checksum_i+1 */ \
    eor v4.16b, v4.16b, v0.16b;       /* xor Offset_i+3 */ \
    eor v16.16b, v16.16b, v3.16b;     /* Checksum_i+2 */ \
    eor v16.16b, v16.16b, v4.16b;     /* Checksum_i+3 */ \
    st1 {v1.16b-v4.16b}, [x1], #64; \
    \
    b.hs .Locb_dec_loop4_##bits; \
    CLEAR_REG(v3); \
    CLEAR_REG(v4); \
    CLEAR_REG(v5); \
    CLEAR_REG(v6); \
    CLEAR_REG(v7); \
    cbz x6, .Locb_dec_done; \
    \
  .Locb_dec_loop_##bits: \
    \
    /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */ \
    /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */ \
    /* Checksum_i = Checksum_{i-1} xor P_i  */ \
    \
    rbit w8, w12; \
    add w12, w12, #1; \
    clz w8, w8; /* ntz(i) */ \
    add x8, x5, x8, lsl #4; \
    \
    ld1 {v1.16b}, [x2], #16; /* load ciphertext */ \
    ld1 {v2.16b}, [x8]; /* load L_{ntz(i)} */ \
    sub x6, x6, #1; \
    eor v0.16b, v0.16b, v2.16b; \
    eor v1.16b, v1.16b, v0.16b; \
    \
    do_aes_one##bits(d, imc, v1, v1) \
    \
    eor v1.16b, v1.16b, v0.16b; \
    st1 {v1.16b}, [x1], #16; /* store plaintext */ \
    eor v16.16b, v16.16b, v1.16b; \
    \
    cbnz x6, .Locb_dec_loop_##bits; \
    b .Locb_dec_done;

  OCB_DEC(128)
  OCB_DEC(192)
  OCB_DEC(256)

#undef OCB_DEC

.Locb_dec_done:
  aes_clear_keys(w7)

  st1 {v16.16b}, [x4] /* store checksum */
  st1 {v0.16b}, [x3] /* store offset */

  CLEAR_REG(v0)
  CLEAR_REG(v1)
  CLEAR_REG(v2)
  CLEAR_REG(v16)

  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_ocb_dec_armv8_ce,.-_gcry_aes_ocb_dec_armv8_ce;)


/*
 * void _gcry_aes_ocb_auth_armv8_ce (const void *keysched,
 *                                   const unsigned char *abuf,
 *                                   unsigned char *offset,
 *                                   unsigned char *checksum,
 *                                   unsigned char *L_table,
 *                                   size_t nblocks,
 *                                   unsigned int nrounds,
 *                                   unsigned int blkn);
 */

.align 3
.globl _gcry_aes_ocb_auth_armv8_ce
ELF(.type  _gcry_aes_ocb_auth_armv8_ce,%function;)
_gcry_aes_ocb_auth_armv8_ce:
  /* input:
   *    x0: keysched
   *    x1: abuf
   *    x2: offset => x3
   *    x3: checksum => x4
   *    x4: Ltable => x5
   *    x5: nblocks => x6  (0 < nblocks <= 32)
   *    w6: nrounds => w7
   *    w7: blkn => w12
   */
  CFI_STARTPROC();

  mov w12, w7
  mov w7, w6
  mov x6, x5
  mov x5, x4
  mov x4, x3
  mov x3, x2

  aes_preload_keys(x0, w7);

  ld1 {v0.16b}, [x3] /* load offset */
  ld1 {v16.16b}, [x4] /* load checksum */

  beq .Locb_auth_entry_192
  bhi .Locb_auth_entry_256

#define OCB_AUTH(bits) \
  .Locb_auth_entry_##bits: \
    cmp x6, #4; \
    add w12, w12, #1; \
    b.lo .Locb_auth_loop_##bits; \
    \
  .Locb_auth_loop4_##bits: \
    \
    /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */ \
    /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */ \
    \
    add w9, w12, #1; \
    add w10, w12, #2; \
    add w11, w12, #3; \
    rbit w8, w12; \
    add w12, w12, #4; \
    rbit w9, w9; \
    rbit w10, w10; \
    rbit w11, w11; \
    clz w8, w8; /* ntz(i+0) */ \
    clz w9, w9; /* ntz(i+1) */ \
    clz w10, w10; /* ntz(i+2) */ \
    clz w11, w11; /* ntz(i+3) */ \
    add x8, x5, x8, lsl #4; \
    ld1 {v1.16b-v4.16b}, [x1], #64;   /* load A_i+<0-3> */ \
    add x9, x5, x9, lsl #4; \
    add x10, x5, x10, lsl #4; \
    add x11, x5, x11, lsl #4; \
    \
    sub x6, x6, #4; \
    \
    ld1 {v5.16b}, [x8];               /* load L_{ntz(i+0)} */ \
    ld1 {v6.16b}, [x9];               /* load L_{ntz(i+1)} */ \
    ld1 {v7.16b}, [x10];              /* load L_{ntz(i+2)} */ \
    eor v5.16b, v5.16b, v0.16b;       /* Offset_i+0 */ \
    ld1 {v0.16b}, [x11];              /* load L_{ntz(i+3)} */ \
    eor v6.16b, v6.16b, v5.16b;       /* Offset_i+1 */ \
    eor v1.16b, v1.16b, v5.16b;       /* A_i+0 xor Offset_i+0 */ \
    eor v7.16b, v7.16b, v6.16b;       /* Offset_i+2 */ \
    eor v2.16b, v2.16b, v6.16b;       /* A_i+1 xor Offset_i+1 */ \
    eor v0.16b, v0.16b, v7.16b;       /* Offset_i+3 */ \
    cmp x6, #4; \
    eor v3.16b, v3.16b, v7.16b;       /* A_i+2 xor Offset_i+2 */ \
    eor v4.16b, v4.16b, v0.16b;       /* A_i+3 xor Offset_i+3 */ \
    \
    do_aes_4_##bits(e, mc, v1, v2, v3, v4); \
    \
    eor v1.16b, v1.16b, v2.16b; \
    eor v16.16b, v16.16b, v3.16b; \
    eor v1.16b, v1.16b, v4.16b; \
    eor v16.16b, v16.16b, v1.16b; \
    \
    b.hs .Locb_auth_loop4_##bits; \
    CLEAR_REG(v3); \
    CLEAR_REG(v4); \
    CLEAR_REG(v5); \
    CLEAR_REG(v6); \
    CLEAR_REG(v7); \
    cbz x6, .Locb_auth_done; \
    \
  .Locb_auth_loop_##bits: \
    \
    /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */ \
    /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */ \
    \
    rbit w8, w12; \
    add w12, w12, #1; \
    clz w8, w8; /* ntz(i) */ \
    add x8, x5, x8, lsl #4; \
    \
    ld1 {v1.16b}, [x1], #16; /* load aadtext */ \
    ld1 {v2.16b}, [x8]; /* load L_{ntz(i)} */ \
    sub x6, x6, #1; \
    eor v0.16b, v0.16b, v2.16b; \
    eor v1.16b, v1.16b, v0.16b; \
    \
    do_aes_one##bits(e, mc, v1, v1) \
    \
    eor v16.16b, v16.16b, v1.16b; \
    \
    cbnz x6, .Locb_auth_loop_##bits; \
    b .Locb_auth_done;

  OCB_AUTH(128)
  OCB_AUTH(192)
  OCB_AUTH(256)

#undef OCB_AUTH

.Locb_auth_done:
  aes_clear_keys(w7)

  st1 {v16.16b}, [x4] /* store checksum */
  st1 {v0.16b}, [x3] /* store offset */

  CLEAR_REG(v0)
  CLEAR_REG(v1)
  CLEAR_REG(v2)
  CLEAR_REG(v16)

  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_ocb_auth_armv8_ce,.-_gcry_aes_ocb_auth_armv8_ce;)


/*
 * void _gcry_aes_xts_enc_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *tweak,
 *                                  size_t nblocks,
 *                                  unsigned int nrounds);
 */

.align 3
.globl _gcry_aes_xts_enc_armv8_ce
ELF(.type  _gcry_aes_xts_enc_armv8_ce,%function;)
_gcry_aes_xts_enc_armv8_ce:
  /* input:
   *    r0: keysched
   *    r1: outbuf
   *    r2: inbuf
   *    r3: tweak
   *    x4: nblocks
   *    w5: nrounds
   */
  CFI_STARTPROC();

  cbz x4, .Lxts_enc_skip

  /* load tweak */
  ld1 {v0.16b}, [x3]

  /* load gfmul mask */
  mov x6, #0x87
  mov x7, #0x01
  mov v16.D[0], x6
  mov v16.D[1], x7

  aes_preload_keys(x0, w5);

  b.eq .Lxts_enc_entry_192
  b.hi .Lxts_enc_entry_256

#define XTS_ENC(bits) \
  .Lxts_enc_entry_##bits: \
    cmp x4, #4; \
    b.lo .Lxts_enc_loop_##bits; \
    \
  .Lxts_enc_loop4_##bits: \
    \
    ext v4.16b, v0.16b, v0.16b, #8; \
    \
    sshr v2.2d, v4.2d, #63; \
    add v5.2d, v0.2d, v0.2d; \
    and v2.16b, v2.16b, v16.16b; \
    add v4.2d, v4.2d, v4.2d; \
    eor v5.16b, v5.16b, v2.16b; \
    \
    sshr v2.2d, v4.2d, #63; \
    add v6.2d, v5.2d, v5.2d; \
    and v2.16b, v2.16b, v16.16b; \
    add v4.2d, v4.2d, v4.2d; \
    eor v6.16b, v6.16b, v2.16b; \
    \
    sshr v2.2d, v4.2d, #63; \
    add v7.2d, v6.2d, v6.2d; \
    and v2.16b, v2.16b, v16.16b; \
    add v4.2d, v4.2d, v4.2d; \
    eor v7.16b, v7.16b, v2.16b; \
    \
    sshr v2.2d, v4.2d, #63; \
    add v3.2d, v7.2d, v7.2d; \
    and v2.16b, v2.16b, v16.16b; \
    add v4.2d, v4.2d, v4.2d; \
    eor v3.16b, v3.16b, v2.16b; \
    ld1 {v1.16b-v2.16b}, [x2], #32; /* load plaintext */ \
    st1 {v3.16b}, [x3]; \
    sub x4, x4, #4; \
    eor v1.16b, v1.16b, v0.16b; \
    \
    ld1 {v3.16b-v4.16b}, [x2], #32; /* load plaintext */ \
    cmp x4, #4; \
    eor v2.16b, v2.16b, v5.16b; \
    eor v3.16b, v3.16b, v6.16b; \
    eor v4.16b, v4.16b, v7.16b; \
    \
    do_aes_4_##bits(e, mc, v1, v2, v3, v4); \
    \
    eor v1.16b, v1.16b, v0.16b; \
    ld1 {v0.16b}, [x3]; \
    eor v2.16b, v2.16b, v5.16b; \
    eor v3.16b, v3.16b, v6.16b; \
    eor v4.16b, v4.16b, v7.16b; \
    st1 {v1.16b-v4.16b}, [x1], #64; /* store plaintext */ \
    \
    b.hs .Lxts_enc_loop4_##bits; \
    CLEAR_REG(v3); \
    CLEAR_REG(v4); \
    CLEAR_REG(v5); \
    CLEAR_REG(v6); \
    CLEAR_REG(v7); \
    cbz x4, .Lxts_enc_done; \
    \
  .Lxts_enc_loop_##bits: \
    \
    ld1 {v1.16b}, [x2], #16; /* load plaintext */ \
    ext v3.16b, v0.16b, v0.16b, #8; \
    mov v2.16b, v0.16b; \
    sshr v3.2d, v3.2d, #63; \
    add v0.2d, v0.2d, v0.2d; \
    and v3.16b, v3.16b, v16.16b; \
    eor v1.16b, v1.16b, v2.16b; \
    eor v0.16b, v0.16b, v3.16b; \
    sub x4, x4, #1; \
    \
    do_aes_one##bits(e, mc, v1, v1); \
    \
    eor v1.16b, v1.16b, v2.16b; \
    st1 {v1.16b}, [x1], #16; /* store ciphertext */ \
    \
    cbnz x4, .Lxts_enc_loop_##bits; \
    b .Lxts_enc_done;

  XTS_ENC(128)
  XTS_ENC(192)
  XTS_ENC(256)

#undef XTS_ENC

.Lxts_enc_done:
  aes_clear_keys(w5)

  st1 {v0.16b}, [x3] /* store tweak */

  CLEAR_REG(v0)
  CLEAR_REG(v1)
  CLEAR_REG(v2)

.Lxts_enc_skip:
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_xts_enc_armv8_ce,.-_gcry_aes_xts_enc_armv8_ce;)


/*
 * void _gcry_aes_xts_dec_armv8_ce (const void *keysched,
 *                                  unsigned char *outbuf,
 *                                  const unsigned char *inbuf,
 *                                  unsigned char *tweak,
 *                                  size_t nblocks,
 *                                  unsigned int nrounds);
 */

.align 3
.globl _gcry_aes_xts_dec_armv8_ce
ELF(.type  _gcry_aes_xts_dec_armv8_ce,%function;)
_gcry_aes_xts_dec_armv8_ce:
  /* input:
   *    r0: keysched
   *    r1: outbuf
   *    r2: inbuf
   *    r3: tweak
   *    x4: nblocks
   *    w5: nrounds
   */
  CFI_STARTPROC();

  cbz x4, .Lxts_dec_skip

  /* load tweak */
  ld1 {v0.16b}, [x3]

  /* load gfmul mask */
  mov x6, #0x87
  mov x7, #0x01
  mov v16.D[0], x6
  mov v16.D[1], x7

  aes_preload_keys(x0, w5);

  b.eq .Lxts_dec_entry_192
  b.hi .Lxts_dec_entry_256

#define XTS_DEC(bits) \
  .Lxts_dec_entry_##bits: \
    cmp x4, #4; \
    b.lo .Lxts_dec_loop_##bits; \
    \
  .Lxts_dec_loop4_##bits: \
    \
    ext v4.16b, v0.16b, v0.16b, #8; \
    \
    sshr v2.2d, v4.2d, #63; \
    add v5.2d, v0.2d, v0.2d; \
    and v2.16b, v2.16b, v16.16b; \
    add v4.2d, v4.2d, v4.2d; \
    eor v5.16b, v5.16b, v2.16b; \
    \
    sshr v2.2d, v4.2d, #63; \
    add v6.2d, v5.2d, v5.2d; \
    and v2.16b, v2.16b, v16.16b; \
    add v4.2d, v4.2d, v4.2d; \
    eor v6.16b, v6.16b, v2.16b; \
    \
    sshr v2.2d, v4.2d, #63; \
    add v7.2d, v6.2d, v6.2d; \
    and v2.16b, v2.16b, v16.16b; \
    add v4.2d, v4.2d, v4.2d; \
    eor v7.16b, v7.16b, v2.16b; \
    \
    sshr v2.2d, v4.2d, #63; \
    add v3.2d, v7.2d, v7.2d; \
    and v2.16b, v2.16b, v16.16b; \
    add v4.2d, v4.2d, v4.2d; \
    eor v3.16b, v3.16b, v2.16b; \
    ld1 {v1.16b-v2.16b}, [x2], #32; /* load plaintext */ \
    st1 {v3.16b}, [x3]; \
    sub x4, x4, #4; \
    eor v1.16b, v1.16b, v0.16b; \
    \
    ld1 {v3.16b-v4.16b}, [x2], #32; /* load plaintext */ \
    cmp x4, #4; \
    eor v2.16b, v2.16b, v5.16b; \
    eor v3.16b, v3.16b, v6.16b; \
    eor v4.16b, v4.16b, v7.16b; \
    \
    do_aes_4_##bits(d, imc, v1, v2, v3, v4); \
    \
    eor v1.16b, v1.16b, v0.16b; \
    ld1 {v0.16b}, [x3]; \
    eor v2.16b, v2.16b, v5.16b; \
    eor v3.16b, v3.16b, v6.16b; \
    eor v4.16b, v4.16b, v7.16b; \
    st1 {v1.16b-v4.16b}, [x1], #64; /* store plaintext */ \
    \
    b.hs .Lxts_dec_loop4_##bits; \
    CLEAR_REG(v3); \
    CLEAR_REG(v4); \
    CLEAR_REG(v5); \
    CLEAR_REG(v6); \
    CLEAR_REG(v7); \
    cbz x4, .Lxts_dec_done; \
    \
  .Lxts_dec_loop_##bits: \
    \
    ld1 {v1.16b}, [x2], #16; /* load plaintext */ \
    ext v3.16b, v0.16b, v0.16b, #8; \
    mov v2.16b, v0.16b; \
    sshr v3.2d, v3.2d, #63; \
    add v0.2d, v0.2d, v0.2d; \
    and v3.16b, v3.16b, v16.16b; \
    eor v1.16b, v1.16b, v2.16b; \
    eor v0.16b, v0.16b, v3.16b; \
    sub x4, x4, #1; \
    \
    do_aes_one##bits(d, imc, v1, v1); \
    \
    eor v1.16b, v1.16b, v2.16b; \
    st1 {v1.16b}, [x1], #16; /* store ciphertext */ \
    \
    cbnz x4, .Lxts_dec_loop_##bits; \
    b .Lxts_dec_done;

  XTS_DEC(128)
  XTS_DEC(192)
  XTS_DEC(256)

#undef XTS_DEC

.Lxts_dec_done:
  aes_clear_keys(w5)

  st1 {v0.16b}, [x3] /* store tweak */

  CLEAR_REG(v0)
  CLEAR_REG(v1)
  CLEAR_REG(v2)

.Lxts_dec_skip:
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_xts_dec_armv8_ce,.-_gcry_aes_xts_dec_armv8_ce;)


/*
 * u32 _gcry_aes_sbox4_armv8_ce(u32 in4b);
 */
.align 3
.globl _gcry_aes_sbox4_armv8_ce
ELF(.type  _gcry_aes_sbox4_armv8_ce,%function;)
_gcry_aes_sbox4_armv8_ce:
  /* See "Gouvêa, C. P. L. & López, J. Implementing GCM on ARMv8. Topics in
   * Cryptology — CT-RSA 2015" for details.
   */
  CFI_STARTPROC();
  movi v0.16b, #0x52
  movi v1.16b, #0
  mov v0.S[0], w0
  aese v0.16b, v1.16b
  addv s0, v0.4s
  mov w0, v0.S[0]
  CLEAR_REG(v0)
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_sbox4_armv8_ce,.-_gcry_aes_sbox4_armv8_ce;)


/*
 * void _gcry_aes_invmixcol_armv8_ce(void *dst, const void *src);
 */
.align 3
.globl _gcry_aes_invmixcol_armv8_ce
ELF(.type  _gcry_aes_invmixcol_armv8_ce,%function;)
_gcry_aes_invmixcol_armv8_ce:
  CFI_STARTPROC();
  ld1 {v0.16b}, [x1]
  aesimc v0.16b, v0.16b
  st1 {v0.16b}, [x0]
  CLEAR_REG(v0)
  ret
  CFI_ENDPROC();
ELF(.size _gcry_aes_invmixcol_armv8_ce,.-_gcry_aes_invmixcol_armv8_ce;)

#endif
