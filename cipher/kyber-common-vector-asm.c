// shuffle.inc
asm ("
.macro shuffle8 r0,r1,r2,r3
vperm2i128	$0x20,%ymm\r1,%ymm\r0,%ymm\r2
vperm2i128	$0x31,%ymm\r1,%ymm\r0,%ymm\r3
.endm

.macro shuffle4 r0,r1,r2,r3
vpunpcklqdq	%ymm\r1,%ymm\r0,%ymm\r2
vpunpckhqdq	%ymm\r1,%ymm\r0,%ymm\r3
.endm

.macro shuffle2 r0,r1,r2,r3
#vpsllq		$32,%ymm\r1,%ymm\r2
vmovsldup	%ymm\r1,%ymm\r2
vpblendd	$0xAA,%ymm\r2,%ymm\r0,%ymm\r2
vpsrlq		$32,%ymm\r0,%ymm\r0
#vmovshdup	%ymm\r0,%ymm\r0
vpblendd	$0xAA,%ymm\r1,%ymm\r0,%ymm\r3
.endm

.macro shuffle1 r0,r1,r2,r3
vpslld		$16,%ymm\r1,%ymm\r2
vpblendw	$0xAA,%ymm\r2,%ymm\r0,%ymm\r2
vpsrld		$16,%ymm\r0,%ymm\r0
vpblendw	$0xAA,%ymm\r1,%ymm\r0,%ymm\r3
.endm
");

// ntt.S
asm ("
.macro mul rh0,rh1,rh2,rh3,zl0=15,zl1=15,zh0=2,zh1=2
vpmullw		%ymm\zl0,%ymm\rh0,%ymm12
vpmullw		%ymm\zl0,%ymm\rh1,%ymm13

vpmullw		%ymm\zl1,%ymm\rh2,%ymm14
vpmullw		%ymm\zl1,%ymm\rh3,%ymm15

vpmulhw		%ymm\zh0,%ymm\rh0,%ymm\rh0
vpmulhw		%ymm\zh0,%ymm\rh1,%ymm\rh1

vpmulhw		%ymm\zh1,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm\zh1,%ymm\rh3,%ymm\rh3
.endm

.macro reduce
vpmulhw		%ymm0,%ymm12,%ymm12
vpmulhw		%ymm0,%ymm13,%ymm13

vpmulhw		%ymm0,%ymm14,%ymm14
vpmulhw		%ymm0,%ymm15,%ymm15
.endm

.macro update rln,rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3
vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rln
vpsubw		%ymm\rh0,%ymm\rl0,%ymm\rh0
vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl0

vpsubw		%ymm\rh1,%ymm\rl1,%ymm\rh1
vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl1
vpsubw		%ymm\rh2,%ymm\rl2,%ymm\rh2

vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl2
vpsubw		%ymm\rh3,%ymm\rl3,%ymm\rh3

vpsubw		%ymm12,%ymm\rln,%ymm\rln
vpaddw		%ymm12,%ymm\rh0,%ymm\rh0
vpsubw		%ymm13,%ymm\rl0,%ymm\rl0

vpaddw		%ymm13,%ymm\rh1,%ymm\rh1
vpsubw		%ymm14,%ymm\rl1,%ymm\rl1
vpaddw		%ymm14,%ymm\rh2,%ymm\rh2

vpsubw		%ymm15,%ymm\rl2,%ymm\rl2
vpaddw		%ymm15,%ymm\rh3,%ymm\rh3
.endm

.macro level0 off
vpbroadcastq	(_ZETAS_EXP+0)*2(%rsi),%ymm15
vmovdqa		(64*\off+128)*2(%rdi),%ymm8
vmovdqa		(64*\off+144)*2(%rdi),%ymm9
vmovdqa		(64*\off+160)*2(%rdi),%ymm10
vmovdqa		(64*\off+176)*2(%rdi),%ymm11
vpbroadcastq	(_ZETAS_EXP+4)*2(%rsi),%ymm2

mul		8,9,10,11

vmovdqa		(64*\off+  0)*2(%rdi),%ymm4
vmovdqa		(64*\off+ 16)*2(%rdi),%ymm5
vmovdqa		(64*\off+ 32)*2(%rdi),%ymm6
vmovdqa		(64*\off+ 48)*2(%rdi),%ymm7

reduce
update		3,4,5,6,7,8,9,10,11

vmovdqa		%ymm3,(64*\off+  0)*2(%rdi)
vmovdqa		%ymm4,(64*\off+ 16)*2(%rdi)
vmovdqa		%ymm5,(64*\off+ 32)*2(%rdi)
vmovdqa		%ymm6,(64*\off+ 48)*2(%rdi)
vmovdqa		%ymm8,(64*\off+128)*2(%rdi)
vmovdqa		%ymm9,(64*\off+144)*2(%rdi)
vmovdqa		%ymm10,(64*\off+160)*2(%rdi)
vmovdqa		%ymm11,(64*\off+176)*2(%rdi)
.endm

.macro levels1t6 off
/* level 1 */
vmovdqa		(_ZETAS_EXP+224*\off+16)*2(%rsi),%ymm15
vmovdqa		(128*\off+ 64)*2(%rdi),%ymm8
vmovdqa		(128*\off+ 80)*2(%rdi),%ymm9
vmovdqa		(128*\off+ 96)*2(%rdi),%ymm10
vmovdqa		(128*\off+112)*2(%rdi),%ymm11
vmovdqa		(_ZETAS_EXP+224*\off+32)*2(%rsi),%ymm2

mul		8,9,10,11

vmovdqa		(128*\off+  0)*2(%rdi),%ymm4
vmovdqa	 	(128*\off+ 16)*2(%rdi),%ymm5
vmovdqa		(128*\off+ 32)*2(%rdi),%ymm6
vmovdqa		(128*\off+ 48)*2(%rdi),%ymm7

reduce
update		3,4,5,6,7,8,9,10,11

/* level 2 */
shuffle8	5,10,7,10
shuffle8	6,11,5,11

vmovdqa		(_ZETAS_EXP+224*\off+48)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+64)*2(%rsi),%ymm2

mul		7,10,5,11

shuffle8	3,8,6,8
shuffle8	4,9,3,9

reduce
update		4,6,8,3,9,7,10,5,11

/* level 3 */
shuffle4	8,5,9,5
shuffle4	3,11,8,11

vmovdqa		(_ZETAS_EXP+224*\off+80)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+96)*2(%rsi),%ymm2

mul		9,5,8,11

shuffle4	4,7,3,7
shuffle4	6,10,4,10

reduce
update		6,3,7,4,10,9,5,8,11

/* level 4 */
shuffle2	7,8,10,8
shuffle2	4,11,7,11

vmovdqa		(_ZETAS_EXP+224*\off+112)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+128)*2(%rsi),%ymm2

mul		10,8,7,11

shuffle2	6,9,4,9
shuffle2	3,5,6,5

reduce
update		3,4,9,6,5,10,8,7,11

/* level 5 */
shuffle1	9,7,5,7
shuffle1	6,11,9,11

vmovdqa		(_ZETAS_EXP+224*\off+144)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+160)*2(%rsi),%ymm2

mul		5,7,9,11

shuffle1	3,10,6,10
shuffle1	4,8,3,8

reduce
update		4,6,10,3,8,5,7,9,11

/* level 6 */
vmovdqa		(_ZETAS_EXP+224*\off+176)*2(%rsi),%ymm14
vmovdqa		(_ZETAS_EXP+224*\off+208)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+192)*2(%rsi),%ymm8
vmovdqa		(_ZETAS_EXP+224*\off+224)*2(%rsi),%ymm2

mul		10,3,9,11,14,15,8,2

reduce
update		8,4,6,5,7,10,3,9,11

vmovdqa		%ymm8,(128*\off+  0)*2(%rdi)
vmovdqa		%ymm4,(128*\off+ 16)*2(%rdi)
vmovdqa		%ymm10,(128*\off+ 32)*2(%rdi)
vmovdqa		%ymm3,(128*\off+ 48)*2(%rdi)
vmovdqa		%ymm6,(128*\off+ 64)*2(%rdi)
vmovdqa		%ymm5,(128*\off+ 80)*2(%rdi)
vmovdqa		%ymm9,(128*\off+ 96)*2(%rdi)
vmovdqa		%ymm11,(128*\off+112)*2(%rdi)
.endm

.text
.global cdecl(ntt_avx)
cdecl(ntt_avx):
vmovdqa		_16XQ*2(%rsi),%ymm0

level0		0
level0		1

levels1t6	0
levels1t6	1

ret
");

// fq.inc
asm ("
.macro red16 r,rs=0,x=12
vpmulhw         %ymm1,%ymm\r,%ymm\x
.if \rs
vpmulhrsw	%ymm\rs,%ymm\x,%ymm\x
.else
vpsraw          $10,%ymm\x,%ymm\x
.endif
vpmullw         %ymm0,%ymm\x,%ymm\x
vpsubw          %ymm\x,%ymm\r,%ymm\r
.endm

.macro csubq r,x=12
vpsubw		%ymm0,%ymm\r,%ymm\r
vpsraw		$15,%ymm\r,%ymm\x
vpand		%ymm0,%ymm\x,%ymm\x
vpaddw		%ymm\x,%ymm\r,%ymm\r
.endm

.macro caddq r,x=12
vpsraw		$15,%ymm\r,%ymm\x
vpand		%ymm0,%ymm\x,%ymm\x
vpaddw		%ymm\x,%ymm\r,%ymm\r
.endm

.macro fqmulprecomp al,ah,b,x=12
vpmullw		%ymm\al,%ymm\b,%ymm\x
vpmulhw		%ymm\ah,%ymm\b,%ymm\b
vpmulhw		%ymm0,%ymm\x,%ymm\x
vpsubw		%ymm\x,%ymm\b,%ymm\b
.endm
");

// invntt.S
asm ("
.macro butterfly rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3,zl0=2,zl1=2,zh0=3,zh1=3
vpsubw		%ymm\rl0,%ymm\rh0,%ymm12
vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rl0
vpsubw		%ymm\rl1,%ymm\rh1,%ymm13

vpmullw		%ymm\zl0,%ymm12,%ymm\rh0
vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl1
vpsubw		%ymm\rl2,%ymm\rh2,%ymm14

vpmullw		%ymm\zl0,%ymm13,%ymm\rh1
vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl2
vpsubw		%ymm\rl3,%ymm\rh3,%ymm15

vpmullw		%ymm\zl1,%ymm14,%ymm\rh2
vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl3
vpmullw		%ymm\zl1,%ymm15,%ymm\rh3

vpmulhw		%ymm\zh0,%ymm12,%ymm12
vpmulhw		%ymm\zh0,%ymm13,%ymm13

vpmulhw		%ymm\zh1,%ymm14,%ymm14
vpmulhw		%ymm\zh1,%ymm15,%ymm15

vpmulhw		%ymm0,%ymm\rh0,%ymm\rh0

vpmulhw		%ymm0,%ymm\rh1,%ymm\rh1

vpmulhw		%ymm0,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm0,%ymm\rh3,%ymm\rh3

#

#

vpsubw		%ymm\rh0,%ymm12,%ymm\rh0

vpsubw		%ymm\rh1,%ymm13,%ymm\rh1

vpsubw		%ymm\rh2,%ymm14,%ymm\rh2
vpsubw		%ymm\rh3,%ymm15,%ymm\rh3
.endm

.macro intt_levels0t5 off
/* level 0 */
vmovdqa		_16XFLO*2(%rsi),%ymm2
vmovdqa		_16XFHI*2(%rsi),%ymm3

vmovdqa         (128*\off+  0)*2(%rdi),%ymm4
vmovdqa         (128*\off+ 32)*2(%rdi),%ymm6
vmovdqa         (128*\off+ 16)*2(%rdi),%ymm5
vmovdqa         (128*\off+ 48)*2(%rdi),%ymm7

fqmulprecomp	2,3,4
fqmulprecomp	2,3,6
fqmulprecomp	2,3,5
fqmulprecomp	2,3,7

vmovdqa         (128*\off+ 64)*2(%rdi),%ymm8
vmovdqa         (128*\off+ 96)*2(%rdi),%ymm10
vmovdqa         (128*\off+ 80)*2(%rdi),%ymm9
vmovdqa         (128*\off+112)*2(%rdi),%ymm11

fqmulprecomp	2,3,8
fqmulprecomp	2,3,10
fqmulprecomp	2,3,9
fqmulprecomp	2,3,11

vpermq		$0x4E,(_ZETAS_EXP+(1-\off)*224+208)*2(%rsi),%ymm15
vpermq		$0x4E,(_ZETAS_EXP+(1-\off)*224+176)*2(%rsi),%ymm1
vpermq		$0x4E,(_ZETAS_EXP+(1-\off)*224+224)*2(%rsi),%ymm2
vpermq		$0x4E,(_ZETAS_EXP+(1-\off)*224+192)*2(%rsi),%ymm3
vmovdqa		_REVIDXB*2(%rsi),%ymm12
vpshufb		%ymm12,%ymm15,%ymm15
vpshufb		%ymm12,%ymm1,%ymm1
vpshufb		%ymm12,%ymm2,%ymm2
vpshufb		%ymm12,%ymm3,%ymm3

butterfly	4,5,8,9,6,7,10,11,15,1,2,3

/* level 1 */
vpermq		$0x4E,(_ZETAS_EXP+(1-\off)*224+144)*2(%rsi),%ymm2
vpermq		$0x4E,(_ZETAS_EXP+(1-\off)*224+160)*2(%rsi),%ymm3
vmovdqa		_REVIDXB*2(%rsi),%ymm1
vpshufb		%ymm1,%ymm2,%ymm2
vpshufb		%ymm1,%ymm3,%ymm3

butterfly	4,5,6,7,8,9,10,11,2,2,3,3

shuffle1	4,5,3,5
shuffle1	6,7,4,7
shuffle1	8,9,6,9
shuffle1	10,11,8,11

/* level 2 */
vmovdqa		_REVIDXD*2(%rsi),%ymm12
vpermd		(_ZETAS_EXP+(1-\off)*224+112)*2(%rsi),%ymm12,%ymm2
vpermd		(_ZETAS_EXP+(1-\off)*224+128)*2(%rsi),%ymm12,%ymm10

butterfly	3,4,6,8,5,7,9,11,2,2,10,10

vmovdqa		_16XV*2(%rsi),%ymm1
red16		3

shuffle2	3,4,10,4
shuffle2	6,8,3,8
shuffle2	5,7,6,7
shuffle2	9,11,5,11

/* level 3 */
vpermq		$0x1B,(_ZETAS_EXP+(1-\off)*224+80)*2(%rsi),%ymm2
vpermq		$0x1B,(_ZETAS_EXP+(1-\off)*224+96)*2(%rsi),%ymm9

butterfly	10,3,6,5,4,8,7,11,2,2,9,9

shuffle4	10,3,9,3
shuffle4	6,5,10,5
shuffle4	4,8,6,8
shuffle4	7,11,4,11

/* level 4 */
vpermq		$0x4E,(_ZETAS_EXP+(1-\off)*224+48)*2(%rsi),%ymm2
vpermq		$0x4E,(_ZETAS_EXP+(1-\off)*224+64)*2(%rsi),%ymm7

butterfly	9,10,6,4,3,5,8,11,2,2,7,7

red16		9

shuffle8	9,10,7,10
shuffle8	6,4,9,4
shuffle8	3,5,6,5
shuffle8	8,11,3,11

/* level 5 */
vmovdqa		(_ZETAS_EXP+(1-\off)*224+16)*2(%rsi),%ymm2
vmovdqa		(_ZETAS_EXP+(1-\off)*224+32)*2(%rsi),%ymm8

butterfly	7,9,6,3,10,4,5,11,2,2,8,8

vmovdqa         %ymm7,(128*\off+  0)*2(%rdi)
vmovdqa         %ymm9,(128*\off+ 16)*2(%rdi)
vmovdqa         %ymm6,(128*\off+ 32)*2(%rdi)
vmovdqa         %ymm3,(128*\off+ 48)*2(%rdi)
vmovdqa         %ymm10,(128*\off+ 64)*2(%rdi)
vmovdqa         %ymm4,(128*\off+ 80)*2(%rdi)
vmovdqa         %ymm5,(128*\off+ 96)*2(%rdi)
vmovdqa         %ymm11,(128*\off+112)*2(%rdi)
.endm

.macro intt_level6 off
/* level 6 */
vmovdqa         (64*\off+  0)*2(%rdi),%ymm4
vmovdqa         (64*\off+128)*2(%rdi),%ymm8
vmovdqa         (64*\off+ 16)*2(%rdi),%ymm5
vmovdqa         (64*\off+144)*2(%rdi),%ymm9
vpbroadcastq	(_ZETAS_EXP+0)*2(%rsi),%ymm2

vmovdqa         (64*\off+ 32)*2(%rdi),%ymm6
vmovdqa         (64*\off+160)*2(%rdi),%ymm10
vmovdqa         (64*\off+ 48)*2(%rdi),%ymm7
vmovdqa         (64*\off+176)*2(%rdi),%ymm11
vpbroadcastq	(_ZETAS_EXP+4)*2(%rsi),%ymm3

butterfly	4,5,6,7,8,9,10,11

.if \off == 0
red16		4
.endif

vmovdqa		%ymm4,(64*\off+  0)*2(%rdi)
vmovdqa		%ymm5,(64*\off+ 16)*2(%rdi)
vmovdqa		%ymm6,(64*\off+ 32)*2(%rdi)
vmovdqa		%ymm7,(64*\off+ 48)*2(%rdi)
vmovdqa		%ymm8,(64*\off+128)*2(%rdi)
vmovdqa		%ymm9,(64*\off+144)*2(%rdi)
vmovdqa		%ymm10,(64*\off+160)*2(%rdi)
vmovdqa		%ymm11,(64*\off+176)*2(%rdi)
.endm

.text
.global cdecl(invntt_avx)
cdecl(invntt_avx):
vmovdqa         _16XQ*2(%rsi),%ymm0

intt_levels0t5	0
intt_levels0t5	1

intt_level6	0
intt_level6	1
ret
");

// shuffle.S
asm ("
.text
nttunpack128_avx:
#load
vmovdqa		(%rdi),%ymm4
vmovdqa		32(%rdi),%ymm5
vmovdqa		64(%rdi),%ymm6
vmovdqa		96(%rdi),%ymm7
vmovdqa		128(%rdi),%ymm8
vmovdqa		160(%rdi),%ymm9
vmovdqa		192(%rdi),%ymm10
vmovdqa		224(%rdi),%ymm11

shuffle8	4,8,3,8
shuffle8	5,9,4,9
shuffle8	6,10,5,10
shuffle8	7,11,6,11

shuffle4	3,5,7,5
shuffle4	8,10,3,10
shuffle4	4,6,8,6
shuffle4	9,11,4,11

shuffle2	7,8,9,8
shuffle2	5,6,7,6
shuffle2	3,4,5,4
shuffle2	10,11,3,11

shuffle1	9,5,10,5
shuffle1	8,4,9,4
shuffle1	7,3,8,3
shuffle1	6,11,7,11

#store
vmovdqa		%ymm10,(%rdi)
vmovdqa		%ymm5,32(%rdi)
vmovdqa		%ymm9,64(%rdi)
vmovdqa		%ymm4,96(%rdi)
vmovdqa		%ymm8,128(%rdi)
vmovdqa		%ymm3,160(%rdi)
vmovdqa		%ymm7,192(%rdi)
vmovdqa		%ymm11,224(%rdi)

ret

.global cdecl(nttunpack_avx)
cdecl(nttunpack_avx):
call		nttunpack128_avx
add		$256,%rdi
call		nttunpack128_avx
ret

ntttobytes128_avx:
#load
vmovdqa		(%rsi),%ymm5
vmovdqa		32(%rsi),%ymm6
vmovdqa		64(%rsi),%ymm7
vmovdqa		96(%rsi),%ymm8
vmovdqa		128(%rsi),%ymm9
vmovdqa		160(%rsi),%ymm10
vmovdqa		192(%rsi),%ymm11
vmovdqa		224(%rsi),%ymm12

#csubq
csubq		5,13
csubq		6,13
csubq		7,13
csubq		8,13
csubq		9,13
csubq		10,13
csubq		11,13
csubq		12,13

#bitpack
vpsllw		$12,%ymm6,%ymm4
vpor		%ymm4,%ymm5,%ymm4

vpsrlw		$4,%ymm6,%ymm5
vpsllw		$8,%ymm7,%ymm6
vpor		%ymm5,%ymm6,%ymm5

vpsrlw		$8,%ymm7,%ymm6
vpsllw		$4,%ymm8,%ymm7
vpor		%ymm6,%ymm7,%ymm6

vpsllw		$12,%ymm10,%ymm7
vpor		%ymm7,%ymm9,%ymm7

vpsrlw		$4,%ymm10,%ymm8
vpsllw		$8,%ymm11,%ymm9
vpor		%ymm8,%ymm9,%ymm8

vpsrlw		$8,%ymm11,%ymm9
vpsllw		$4,%ymm12,%ymm10
vpor		%ymm9,%ymm10,%ymm9

shuffle1	4,5,3,5
shuffle1	6,7,4,7
shuffle1	8,9,6,9

shuffle2	3,4,8,4
shuffle2	6,5,3,5
shuffle2	7,9,6,9

shuffle4	8,3,7,3
shuffle4	6,4,8,4
shuffle4	5,9,6,9

shuffle8	7,8,5,8
shuffle8	6,3,7,3
shuffle8	4,9,6,9

#store
vmovdqu		%ymm5,(%rdi)
vmovdqu		%ymm7,32(%rdi)
vmovdqu		%ymm6,64(%rdi)
vmovdqu		%ymm8,96(%rdi)
vmovdqu		%ymm3,128(%rdi)
vmovdqu		%ymm9,160(%rdi)

ret

.global cdecl(ntttobytes_avx)
cdecl(ntttobytes_avx):
#consts
vmovdqa		_16XQ*2(%rdx),%ymm0
call		ntttobytes128_avx
add		$256,%rsi
add		$192,%rdi
call		ntttobytes128_avx
ret

nttfrombytes128_avx:
#load
vmovdqu		(%rsi),%ymm4
vmovdqu		32(%rsi),%ymm5
vmovdqu		64(%rsi),%ymm6
vmovdqu		96(%rsi),%ymm7
vmovdqu		128(%rsi),%ymm8
vmovdqu		160(%rsi),%ymm9

shuffle8	4,7,3,7
shuffle8	5,8,4,8
shuffle8	6,9,5,9

shuffle4	3,8,6,8
shuffle4	7,5,3,5
shuffle4	4,9,7,9

shuffle2	6,5,4,5
shuffle2	8,7,6,7
shuffle2	3,9,8,9

shuffle1	4,7,10,7
shuffle1	5,8,4,8
shuffle1	6,9,5,9

#bitunpack
vpsrlw		$12,%ymm10,%ymm11
vpsllw		$4,%ymm7,%ymm12
vpor		%ymm11,%ymm12,%ymm11
vpand		%ymm0,%ymm10,%ymm10
vpand		%ymm0,%ymm11,%ymm11

vpsrlw		$8,%ymm7,%ymm12
vpsllw		$8,%ymm4,%ymm13
vpor		%ymm12,%ymm13,%ymm12
vpand		%ymm0,%ymm12,%ymm12

vpsrlw		$4,%ymm4,%ymm13
vpand		%ymm0,%ymm13,%ymm13

vpsrlw		$12,%ymm8,%ymm14
vpsllw		$4,%ymm5,%ymm15
vpor		%ymm14,%ymm15,%ymm14
vpand		%ymm0,%ymm8,%ymm8
vpand		%ymm0,%ymm14,%ymm14

vpsrlw		$8,%ymm5,%ymm15
vpsllw		$8,%ymm9,%ymm1
vpor		%ymm15,%ymm1,%ymm15
vpand		%ymm0,%ymm15,%ymm15

vpsrlw		$4,%ymm9,%ymm1
vpand		%ymm0,%ymm1,%ymm1

#store
vmovdqa		%ymm10,(%rdi)
vmovdqa		%ymm11,32(%rdi)
vmovdqa		%ymm12,64(%rdi)
vmovdqa		%ymm13,96(%rdi)
vmovdqa		%ymm8,128(%rdi)
vmovdqa		%ymm14,160(%rdi)
vmovdqa		%ymm15,192(%rdi)
vmovdqa		%ymm1,224(%rdi)

ret

.global cdecl(nttfrombytes_avx)
cdecl(nttfrombytes_avx):
#consts
vmovdqa		_16XMASK*2(%rdx),%ymm0
call		nttfrombytes128_avx
add		$256,%rdi
add		$192,%rsi
call		nttfrombytes128_avx
ret
");

// basemul.S
asm ("
.macro schoolbook off
vmovdqa		_16XQINV*2(%rcx),%ymm0
vmovdqa		(64*\off+ 0)*2(%rsi),%ymm1		# a0
vmovdqa		(64*\off+16)*2(%rsi),%ymm2		# b0
vmovdqa		(64*\off+32)*2(%rsi),%ymm3		# a1
vmovdqa		(64*\off+48)*2(%rsi),%ymm4		# b1

vpmullw		%ymm0,%ymm1,%ymm9			# a0.lo
vpmullw		%ymm0,%ymm2,%ymm10			# b0.lo
vpmullw		%ymm0,%ymm3,%ymm11			# a1.lo
vpmullw		%ymm0,%ymm4,%ymm12			# b1.lo

vmovdqa		(64*\off+ 0)*2(%rdx),%ymm5		# c0
vmovdqa		(64*\off+16)*2(%rdx),%ymm6		# d0

vpmulhw		%ymm5,%ymm1,%ymm13			# a0c0.hi
vpmulhw		%ymm6,%ymm1,%ymm1			# a0d0.hi
vpmulhw		%ymm5,%ymm2,%ymm14			# b0c0.hi
vpmulhw		%ymm6,%ymm2,%ymm2			# b0d0.hi

vmovdqa		(64*\off+32)*2(%rdx),%ymm7		# c1
vmovdqa		(64*\off+48)*2(%rdx),%ymm8		# d1

vpmulhw		%ymm7,%ymm3,%ymm15			# a1c1.hi
vpmulhw		%ymm8,%ymm3,%ymm3			# a1d1.hi
vpmulhw		%ymm7,%ymm4,%ymm0			# b1c1.hi
vpmulhw		%ymm8,%ymm4,%ymm4			# b1d1.hi

vmovdqa		%ymm13,(%rsp)

vpmullw		%ymm5,%ymm9,%ymm13			# a0c0.lo
vpmullw		%ymm6,%ymm9,%ymm9			# a0d0.lo
vpmullw		%ymm5,%ymm10,%ymm5			# b0c0.lo
vpmullw		%ymm6,%ymm10,%ymm10			# b0d0.lo

vpmullw		%ymm7,%ymm11,%ymm6			# a1c1.lo
vpmullw		%ymm8,%ymm11,%ymm11			# a1d1.lo
vpmullw		%ymm7,%ymm12,%ymm7			# b1c1.lo
vpmullw		%ymm8,%ymm12,%ymm12			# b1d1.lo

vmovdqa		_16XQ*2(%rcx),%ymm8
vpmulhw		%ymm8,%ymm13,%ymm13
vpmulhw		%ymm8,%ymm9,%ymm9
vpmulhw		%ymm8,%ymm5,%ymm5
vpmulhw		%ymm8,%ymm10,%ymm10
vpmulhw		%ymm8,%ymm6,%ymm6
vpmulhw		%ymm8,%ymm11,%ymm11
vpmulhw		%ymm8,%ymm7,%ymm7
vpmulhw		%ymm8,%ymm12,%ymm12

vpsubw		(%rsp),%ymm13,%ymm13			# -a0c0
vpsubw		%ymm9,%ymm1,%ymm9			# a0d0
vpsubw		%ymm5,%ymm14,%ymm5			# b0c0
vpsubw		%ymm10,%ymm2,%ymm10			# b0d0

vpsubw		%ymm6,%ymm15,%ymm6			# a1c1
vpsubw		%ymm11,%ymm3,%ymm11			# a1d1
vpsubw		%ymm7,%ymm0,%ymm7			# b1c1
vpsubw		%ymm12,%ymm4,%ymm12			# b1d1

vmovdqa		(%r9),%ymm0
vmovdqa		32(%r9),%ymm1
vpmullw		%ymm0,%ymm10,%ymm2
vpmullw		%ymm0,%ymm12,%ymm3
vpmulhw		%ymm1,%ymm10,%ymm10
vpmulhw		%ymm1,%ymm12,%ymm12
vpmulhw		%ymm8,%ymm2,%ymm2
vpmulhw		%ymm8,%ymm3,%ymm3
vpsubw		%ymm2,%ymm10,%ymm10			# rb0d0
vpsubw		%ymm3,%ymm12,%ymm12			# rb1d1

vpaddw		%ymm5,%ymm9,%ymm9
vpaddw		%ymm7,%ymm11,%ymm11
vpsubw		%ymm13,%ymm10,%ymm13
vpsubw		%ymm12,%ymm6,%ymm6

vmovdqa		%ymm13,(64*\off+ 0)*2(%rdi)
vmovdqa		%ymm9,(64*\off+16)*2(%rdi)
vmovdqa		%ymm6,(64*\off+32)*2(%rdi)
vmovdqa		%ymm11,(64*\off+48)*2(%rdi)
.endm

.text
cdecl(basemul_avx):
mov		%rsp,%r8
and		$-32,%rsp
sub		$32,%rsp

lea		(_ZETAS_EXP+176)*2(%rcx),%r9
schoolbook	0

add		$32*2,%r9
schoolbook	1

add		$192*2,%r9
schoolbook	2

add		$32*2,%r9
schoolbook	3

mov		%r8,%rsp
ret
");
