/* kyber-common-vector.c - the Kyber key encapsulation mechanism
 *                         (common vector part)
 * Copyright (C) 2026 g10 Code GmbH
 *
 * This file was modified for use by Libgcrypt.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * You can also use this file under the same licence of original code.
 * SPDX-License-Identifier: CC0 OR Apache-2.0
 *
 */
/*
  Original code from:

  Repository: https://github.com/pq-crystals/kyber.git
  Branch: standard
  Commit: d5b791c0c601b543233daccbae2845c6197a9e77

  Licence:
  Public Domain (https://creativecommons.org/share-your-work/public-domain/cc0/);
  or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).

  Authors:
        Joppe Bos
        Léo Ducas
        Eike Kiltz
        Tancrède Lepoint
        Vadim Lyubashevsky
        John Schanck
        Peter Schwabe
        Gregor Seiler
        Damien Stehlé

  Kyber Home: https://www.pq-crystals.org/kyber/
 */
/*
 * From original code, following modification was made.
 *
 * - C++ style comments are changed to C-style.
 *
 * - Assembler implementation (*.S files) are converted to asm statements.
 *
 * - poly_ntt calls reduce_avx (so that we can share indcpa_keypair_derand).
 */
#include <stdint.h>
#include <immintrin.h>

/*************** kyber/avx2/consts.c */
#define Q KYBER_Q
#define MONT -1044 /* 2^16 mod q */
#define QINV -3327 /* q^-1 mod 2^16 */
#define V 20159 /* floor(2^26/q + 0.5) */
#define FHI 1441 /* mont^2/128 */
#define FLO -10079 /* qinv*FHI */
#define MONTSQHI 1353 /* mont^2 */
#define MONTSQLO 20553 /* qinv*MONTSQHI */
#define MASK 4095
#define SHIFT 32

static const qdata_t qdata = {{
#define _16XQ 0
  Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q, Q,

#define _16XQINV 16
  QINV, QINV, QINV, QINV, QINV, QINV, QINV, QINV,
  QINV, QINV, QINV, QINV, QINV, QINV, QINV, QINV,

#define _16XV 32
  V, V, V, V, V, V, V, V, V, V, V, V, V, V, V, V,

#define _16XFLO 48
  FLO, FLO, FLO, FLO, FLO, FLO, FLO, FLO,
  FLO, FLO, FLO, FLO, FLO, FLO, FLO, FLO,

#define _16XFHI 64
  FHI, FHI, FHI, FHI, FHI, FHI, FHI, FHI,
  FHI, FHI, FHI, FHI, FHI, FHI, FHI, FHI,

#define _16XMONTSQLO 80
  MONTSQLO, MONTSQLO, MONTSQLO, MONTSQLO,
  MONTSQLO, MONTSQLO, MONTSQLO, MONTSQLO,
  MONTSQLO, MONTSQLO, MONTSQLO, MONTSQLO,
  MONTSQLO, MONTSQLO, MONTSQLO, MONTSQLO,

#define _16XMONTSQHI 96
  MONTSQHI, MONTSQHI, MONTSQHI, MONTSQHI,
  MONTSQHI, MONTSQHI, MONTSQHI, MONTSQHI,
  MONTSQHI, MONTSQHI, MONTSQHI, MONTSQHI,
  MONTSQHI, MONTSQHI, MONTSQHI, MONTSQHI,

#define _16XMASK 112
  MASK, MASK, MASK, MASK, MASK, MASK, MASK, MASK,
  MASK, MASK, MASK, MASK, MASK, MASK, MASK, MASK,

#define _REVIDXB 128
  3854, 3340, 2826, 2312, 1798, 1284, 770, 256,
  3854, 3340, 2826, 2312, 1798, 1284, 770, 256,

#define _REVIDXD 144
  7, 0, 6, 0, 5, 0, 4, 0, 3, 0, 2, 0, 1, 0, 0, 0,

#define _ZETAS_EXP 160
   31498,  31498,  31498,  31498,   -758,   -758,   -758,   -758,
    5237,   5237,   5237,   5237,   1397,   1397,   1397,   1397,
   14745,  14745,  14745,  14745,  14745,  14745,  14745,  14745,
   14745,  14745,  14745,  14745,  14745,  14745,  14745,  14745,
    -359,   -359,   -359,   -359,   -359,   -359,   -359,   -359,
    -359,   -359,   -359,   -359,   -359,   -359,   -359,   -359,
   13525,  13525,  13525,  13525,  13525,  13525,  13525,  13525,
  -12402, -12402, -12402, -12402, -12402, -12402, -12402, -12402,
    1493,   1493,   1493,   1493,   1493,   1493,   1493,   1493,
    1422,   1422,   1422,   1422,   1422,   1422,   1422,   1422,
  -20907, -20907, -20907, -20907,  27758,  27758,  27758,  27758,
   -3799,  -3799,  -3799,  -3799, -15690, -15690, -15690, -15690,
    -171,   -171,   -171,   -171,    622,    622,    622,    622,
    1577,   1577,   1577,   1577,    182,    182,    182,    182,
   -5827,  -5827,  17363,  17363, -26360, -26360, -29057, -29057,
    5571,   5571,  -1102,  -1102,  21438,  21438, -26242, -26242,
     573,    573,  -1325,  -1325,    264,    264,    383,    383,
    -829,   -829,   1458,   1458,  -1602,  -1602,   -130,   -130,
   -5689,  -6516,   1496,  30967, -23565,  20179,  20710,  25080,
  -12796,  26616,  16064, -12442,   9134,   -650, -25986,  27837,
    1223,    652,   -552,   1015,  -1293,   1491,   -282,  -1544,
     516,     -8,   -320,   -666,  -1618,  -1162,    126,   1469,
    -335, -11477, -32227,  20494, -27738,    945, -14883,   6182,
   32010,  10631,  29175, -28762, -18486,  17560, -14430,  -5276,
   -1103,    555,  -1251,   1550,    422,    177,   -291,   1574,
    -246,   1159,   -777,   -602,  -1590,   -872,    418,   -156,
   11182,  13387, -14233, -21655,  13131,  -4587,  23092,   5493,
  -32502,  30317, -18741,  12639,  20100,  18525,  19529, -12619,
     430,    843,    871,    105,    587,   -235,   -460,   1653,
     778,   -147,   1483,   1119,    644,    349,    329,    -75,
     787,    787,    787,    787,    787,    787,    787,    787,
     787,    787,    787,    787,    787,    787,    787,    787,
   -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  -1517,
   -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  -1517,  -1517,
   28191,  28191,  28191,  28191,  28191,  28191,  28191,  28191,
  -16694, -16694, -16694, -16694, -16694, -16694, -16694, -16694,
     287,    287,    287,    287,    287,    287,    287,    287,
     202,    202,    202,    202,    202,    202,    202,    202,
   10690,  10690,  10690,  10690,   1358,   1358,   1358,   1358,
  -11202, -11202, -11202, -11202,  31164,  31164,  31164,  31164,
     962,    962,    962,    962,  -1202,  -1202,  -1202,  -1202,
   -1474,  -1474,  -1474,  -1474,   1468,   1468,   1468,   1468,
  -28073, -28073,  24313,  24313, -10532, -10532,   8800,   8800,
   18426,  18426,   8859,   8859,  26675,  26675, -16163, -16163,
    -681,   -681,   1017,   1017,    732,    732,    608,    608,
   -1542,  -1542,    411,    411,   -205,   -205,  -1571,  -1571,
   19883, -28250, -15887,  -8898, -28309,   9075, -30199,  18249,
   13426,  14017, -29156, -12757,  16832,   4311, -24155, -17915,
    -853,    -90,   -271,    830,    107,  -1421,   -247,   -951,
    -398,    961,  -1508,   -725,    448,  -1065,    677,  -1275,
  -31183,  25435,  -7382,  24391, -20927,  10946,  24214,  16989,
   10335,  -7934, -22502,  10906,  31636,  28644,  23998, -17422,
     817,    603,   1322,  -1465,  -1215,   1218,   -874,  -1187,
   -1185,  -1278,  -1510,   -870,   -108,    996,    958,   1522,
   20297,   2146,  15355, -32384,  -6280, -14903, -11044,  14469,
  -21498, -20198,  23210, -17442, -23860, -20257,   7756,  23132,
    1097,    610,  -1285,    384,   -136,  -1335,    220,  -1659,
   -1530,    794,   -854,    478,   -308,    991,  -1460,   1628,

#define _16XSHIFT 624
  SHIFT, SHIFT, SHIFT, SHIFT, SHIFT, SHIFT, SHIFT, SHIFT,
  SHIFT, SHIFT, SHIFT, SHIFT, SHIFT, SHIFT, SHIFT, SHIFT
}};

/*************** kyber/avx2/fips202x4.h */
typedef struct {
  __m256i s[25];
} keccakx4_state;

/*************** kyber/avx2/keccak4x/KeccakP-SIMD256-config.h */
#define KeccakP1600times4_implementation_config "AVX2, all rounds unrolled"
#define KeccakP1600times4_fullUnrolling
#define KeccakP1600times4_useAVX2

/*************** kyber/avx2/keccak4x/KeccakP-1600-times4-SIMD256.c */
/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

typedef unsigned long long int UINT64;
typedef __m256i V256;

    #define ANDnu256(a, b)          _mm256_andnot_si256(a, b)
    #define CONST256(a)             _mm256_load_si256((const V256 *)&(a))
    #define CONST256_64(a)          (V256)_mm256_broadcast_sd((const double*)(&a))
    #define LOAD256(a)              _mm256_load_si256((const V256 *)&(a))
    #define LOAD256u(a)             _mm256_loadu_si256((const V256 *)&(a))
    #define LOAD4_64(a, b, c, d)    _mm256_set_epi64x((UINT64)(a), (UINT64)(b), (UINT64)(c), (UINT64)(d))
    #define ROL64in256(d, a, o)     d = _mm256_or_si256(_mm256_slli_epi64(a, o), _mm256_srli_epi64(a, 64-(o)))
    #define ROL64in256_8(d, a)      d = _mm256_shuffle_epi8(a, CONST256(rho8))
    #define ROL64in256_56(d, a)     d = _mm256_shuffle_epi8(a, CONST256(rho56))
static const UINT64 rho8[4] = {0x0605040302010007, 0x0E0D0C0B0A09080F, 0x1615141312111017, 0x1E1D1C1B1A19181F};
static const UINT64 rho56[4] = {0x0007060504030201, 0x080F0E0D0C0B0A09, 0x1017161514131211, 0x181F1E1D1C1B1A19};
    #define STORE256(a, b)          _mm256_store_si256((V256 *)&(a), b)
    #define STORE256u(a, b)         _mm256_storeu_si256((V256 *)&(a), b)
    #define STORE2_128(ah, al, v)   _mm256_storeu2_m128d((V128*)&(ah), (V128*)&(al), v)
    #define XOR256(a, b)            _mm256_xor_si256(a, b)
    #define XOReq256(a, b)          a = _mm256_xor_si256(a, b)
    #define UNPACKL( a, b )         _mm256_unpacklo_epi64((a), (b))
    #define UNPACKH( a, b )         _mm256_unpackhi_epi64((a), (b))
    #define PERM128( a, b, c )      (V256)_mm256_permute2f128_ps((__m256)(a), (__m256)(b), c)
    #define SHUFFLE64( a, b, c )    (V256)_mm256_shuffle_pd((__m256d)(a), (__m256d)(b), c)

    #define UNINTLEAVE()            lanesL01 = UNPACKL( lanes0, lanes1 ),                   \
                                    lanesH01 = UNPACKH( lanes0, lanes1 ),                   \
                                    lanesL23 = UNPACKL( lanes2, lanes3 ),                   \
                                    lanesH23 = UNPACKH( lanes2, lanes3 ),                   \
                                    lanes0 = PERM128( lanesL01, lanesL23, 0x20 ),           \
                                    lanes2 = PERM128( lanesL01, lanesL23, 0x31 ),           \
                                    lanes1 = PERM128( lanesH01, lanesH23, 0x20 ),           \
                                    lanes3 = PERM128( lanesH01, lanesH23, 0x31 )

    #define INTLEAVE()              lanesL01 = PERM128( lanes0, lanes2, 0x20 ),             \
                                    lanesH01 = PERM128( lanes1, lanes3, 0x20 ),             \
                                    lanesL23 = PERM128( lanes0, lanes2, 0x31 ),             \
                                    lanesH23 = PERM128( lanes1, lanes3, 0x31 ),             \
                                    lanes0 = SHUFFLE64( lanesL01, lanesH01, 0x00 ),         \
                                    lanes1 = SHUFFLE64( lanesL01, lanesH01, 0x0F ),         \
                                    lanes2 = SHUFFLE64( lanesL23, lanesH23, 0x00 ),         \
                                    lanes3 = SHUFFLE64( lanesL23, lanesH23, 0x0F )

#define declareABCDE \
    V256 Aba, Abe, Abi, Abo, Abu; \
    V256 Aga, Age, Agi, Ago, Agu; \
    V256 Aka, Ake, Aki, Ako, Aku; \
    V256 Ama, Ame, Ami, Amo, Amu; \
    V256 Asa, Ase, Asi, Aso, Asu; \
    V256 Bba, Bbe, Bbi, Bbo, Bbu; \
    V256 Bga, Bge, Bgi, Bgo, Bgu; \
    V256 Bka, Bke, Bki, Bko, Bku; \
    V256 Bma, Bme, Bmi, Bmo, Bmu; \
    V256 Bsa, Bse, Bsi, Bso, Bsu; \
    V256 Ca, Ce, Ci, Co, Cu; \
    V256 Ca1, Ce1, Ci1, Co1, Cu1; \
    V256 Da, De, Di, Do, Du; \
    V256 Eba, Ebe, Ebi, Ebo, Ebu; \
    V256 Ega, Ege, Egi, Ego, Egu; \
    V256 Eka, Eke, Eki, Eko, Eku; \
    V256 Ema, Eme, Emi, Emo, Emu; \
    V256 Esa, Ese, Esi, Eso, Esu; \

static __attribute__ ((aligned(32))) const UINT64 KeccakF1600RoundConstants[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL};

#define copyFromState(X, state) \
    X##ba = LOAD256(state[ 0]); \
    X##be = LOAD256(state[ 1]); \
    X##bi = LOAD256(state[ 2]); \
    X##bo = LOAD256(state[ 3]); \
    X##bu = LOAD256(state[ 4]); \
    X##ga = LOAD256(state[ 5]); \
    X##ge = LOAD256(state[ 6]); \
    X##gi = LOAD256(state[ 7]); \
    X##go = LOAD256(state[ 8]); \
    X##gu = LOAD256(state[ 9]); \
    X##ka = LOAD256(state[10]); \
    X##ke = LOAD256(state[11]); \
    X##ki = LOAD256(state[12]); \
    X##ko = LOAD256(state[13]); \
    X##ku = LOAD256(state[14]); \
    X##ma = LOAD256(state[15]); \
    X##me = LOAD256(state[16]); \
    X##mi = LOAD256(state[17]); \
    X##mo = LOAD256(state[18]); \
    X##mu = LOAD256(state[19]); \
    X##sa = LOAD256(state[20]); \
    X##se = LOAD256(state[21]); \
    X##si = LOAD256(state[22]); \
    X##so = LOAD256(state[23]); \
    X##su = LOAD256(state[24]); \

#define copyToState(state, X) \
    STORE256(state[ 0], X##ba); \
    STORE256(state[ 1], X##be); \
    STORE256(state[ 2], X##bi); \
    STORE256(state[ 3], X##bo); \
    STORE256(state[ 4], X##bu); \
    STORE256(state[ 5], X##ga); \
    STORE256(state[ 6], X##ge); \
    STORE256(state[ 7], X##gi); \
    STORE256(state[ 8], X##go); \
    STORE256(state[ 9], X##gu); \
    STORE256(state[10], X##ka); \
    STORE256(state[11], X##ke); \
    STORE256(state[12], X##ki); \
    STORE256(state[13], X##ko); \
    STORE256(state[14], X##ku); \
    STORE256(state[15], X##ma); \
    STORE256(state[16], X##me); \
    STORE256(state[17], X##mi); \
    STORE256(state[18], X##mo); \
    STORE256(state[19], X##mu); \
    STORE256(state[20], X##sa); \
    STORE256(state[21], X##se); \
    STORE256(state[22], X##si); \
    STORE256(state[23], X##so); \
    STORE256(state[24], X##su); \

#define prepareTheta \
    Ca = XOR256(Aba, XOR256(Aga, XOR256(Aka, XOR256(Ama, Asa)))); \
    Ce = XOR256(Abe, XOR256(Age, XOR256(Ake, XOR256(Ame, Ase)))); \
    Ci = XOR256(Abi, XOR256(Agi, XOR256(Aki, XOR256(Ami, Asi)))); \
    Co = XOR256(Abo, XOR256(Ago, XOR256(Ako, XOR256(Amo, Aso)))); \
    Cu = XOR256(Abu, XOR256(Agu, XOR256(Aku, XOR256(Amu, Asu)))); \

/* --- Theta Rho Pi Chi Iota Prepare-theta */
/* --- 64-bit lanes mapped to 64-bit words */
#define thetaRhoPiChiIotaPrepareTheta(i, A, E) \
    ROL64in256(Ce1, Ce, 1); \
    Da = XOR256(Cu, Ce1); \
    ROL64in256(Ci1, Ci, 1); \
    De = XOR256(Ca, Ci1); \
    ROL64in256(Co1, Co, 1); \
    Di = XOR256(Ce, Co1); \
    ROL64in256(Cu1, Cu, 1); \
    Do = XOR256(Ci, Cu1); \
    ROL64in256(Ca1, Ca, 1); \
    Du = XOR256(Co, Ca1); \
\
    XOReq256(A##ba, Da); \
    Bba = A##ba; \
    XOReq256(A##ge, De); \
    ROL64in256(Bbe, A##ge, 44); \
    XOReq256(A##ki, Di); \
    ROL64in256(Bbi, A##ki, 43); \
    E##ba = XOR256(Bba, ANDnu256(Bbe, Bbi)); \
    XOReq256(E##ba, CONST256_64(KeccakF1600RoundConstants[i])); \
    Ca = E##ba; \
    XOReq256(A##mo, Do); \
    ROL64in256(Bbo, A##mo, 21); \
    E##be = XOR256(Bbe, ANDnu256(Bbi, Bbo)); \
    Ce = E##be; \
    XOReq256(A##su, Du); \
    ROL64in256(Bbu, A##su, 14); \
    E##bi = XOR256(Bbi, ANDnu256(Bbo, Bbu)); \
    Ci = E##bi; \
    E##bo = XOR256(Bbo, ANDnu256(Bbu, Bba)); \
    Co = E##bo; \
    E##bu = XOR256(Bbu, ANDnu256(Bba, Bbe)); \
    Cu = E##bu; \
\
    XOReq256(A##bo, Do); \
    ROL64in256(Bga, A##bo, 28); \
    XOReq256(A##gu, Du); \
    ROL64in256(Bge, A##gu, 20); \
    XOReq256(A##ka, Da); \
    ROL64in256(Bgi, A##ka, 3); \
    E##ga = XOR256(Bga, ANDnu256(Bge, Bgi)); \
    XOReq256(Ca, E##ga); \
    XOReq256(A##me, De); \
    ROL64in256(Bgo, A##me, 45); \
    E##ge = XOR256(Bge, ANDnu256(Bgi, Bgo)); \
    XOReq256(Ce, E##ge); \
    XOReq256(A##si, Di); \
    ROL64in256(Bgu, A##si, 61); \
    E##gi = XOR256(Bgi, ANDnu256(Bgo, Bgu)); \
    XOReq256(Ci, E##gi); \
    E##go = XOR256(Bgo, ANDnu256(Bgu, Bga)); \
    XOReq256(Co, E##go); \
    E##gu = XOR256(Bgu, ANDnu256(Bga, Bge)); \
    XOReq256(Cu, E##gu); \
\
    XOReq256(A##be, De); \
    ROL64in256(Bka, A##be, 1); \
    XOReq256(A##gi, Di); \
    ROL64in256(Bke, A##gi, 6); \
    XOReq256(A##ko, Do); \
    ROL64in256(Bki, A##ko, 25); \
    E##ka = XOR256(Bka, ANDnu256(Bke, Bki)); \
    XOReq256(Ca, E##ka); \
    XOReq256(A##mu, Du); \
    ROL64in256_8(Bko, A##mu); \
    E##ke = XOR256(Bke, ANDnu256(Bki, Bko)); \
    XOReq256(Ce, E##ke); \
    XOReq256(A##sa, Da); \
    ROL64in256(Bku, A##sa, 18); \
    E##ki = XOR256(Bki, ANDnu256(Bko, Bku)); \
    XOReq256(Ci, E##ki); \
    E##ko = XOR256(Bko, ANDnu256(Bku, Bka)); \
    XOReq256(Co, E##ko); \
    E##ku = XOR256(Bku, ANDnu256(Bka, Bke)); \
    XOReq256(Cu, E##ku); \
\
    XOReq256(A##bu, Du); \
    ROL64in256(Bma, A##bu, 27); \
    XOReq256(A##ga, Da); \
    ROL64in256(Bme, A##ga, 36); \
    XOReq256(A##ke, De); \
    ROL64in256(Bmi, A##ke, 10); \
    E##ma = XOR256(Bma, ANDnu256(Bme, Bmi)); \
    XOReq256(Ca, E##ma); \
    XOReq256(A##mi, Di); \
    ROL64in256(Bmo, A##mi, 15); \
    E##me = XOR256(Bme, ANDnu256(Bmi, Bmo)); \
    XOReq256(Ce, E##me); \
    XOReq256(A##so, Do); \
    ROL64in256_56(Bmu, A##so); \
    E##mi = XOR256(Bmi, ANDnu256(Bmo, Bmu)); \
    XOReq256(Ci, E##mi); \
    E##mo = XOR256(Bmo, ANDnu256(Bmu, Bma)); \
    XOReq256(Co, E##mo); \
    E##mu = XOR256(Bmu, ANDnu256(Bma, Bme)); \
    XOReq256(Cu, E##mu); \
\
    XOReq256(A##bi, Di); \
    ROL64in256(Bsa, A##bi, 62); \
    XOReq256(A##go, Do); \
    ROL64in256(Bse, A##go, 55); \
    XOReq256(A##ku, Du); \
    ROL64in256(Bsi, A##ku, 39); \
    E##sa = XOR256(Bsa, ANDnu256(Bse, Bsi)); \
    XOReq256(Ca, E##sa); \
    XOReq256(A##ma, Da); \
    ROL64in256(Bso, A##ma, 41); \
    E##se = XOR256(Bse, ANDnu256(Bsi, Bso)); \
    XOReq256(Ce, E##se); \
    XOReq256(A##se, De); \
    ROL64in256(Bsu, A##se, 2); \
    E##si = XOR256(Bsi, ANDnu256(Bso, Bsu)); \
    XOReq256(Ci, E##si); \
    E##so = XOR256(Bso, ANDnu256(Bsu, Bsa)); \
    XOReq256(Co, E##so); \
    E##su = XOR256(Bsu, ANDnu256(Bsa, Bse)); \
    XOReq256(Cu, E##su); \
\

/* --- Theta Rho Pi Chi Iota */
/* --- 64-bit lanes mapped to 64-bit words */
#define thetaRhoPiChiIota(i, A, E) \
    ROL64in256(Ce1, Ce, 1); \
    Da = XOR256(Cu, Ce1); \
    ROL64in256(Ci1, Ci, 1); \
    De = XOR256(Ca, Ci1); \
    ROL64in256(Co1, Co, 1); \
    Di = XOR256(Ce, Co1); \
    ROL64in256(Cu1, Cu, 1); \
    Do = XOR256(Ci, Cu1); \
    ROL64in256(Ca1, Ca, 1); \
    Du = XOR256(Co, Ca1); \
\
    XOReq256(A##ba, Da); \
    Bba = A##ba; \
    XOReq256(A##ge, De); \
    ROL64in256(Bbe, A##ge, 44); \
    XOReq256(A##ki, Di); \
    ROL64in256(Bbi, A##ki, 43); \
    E##ba = XOR256(Bba, ANDnu256(Bbe, Bbi)); \
    XOReq256(E##ba, CONST256_64(KeccakF1600RoundConstants[i])); \
    XOReq256(A##mo, Do); \
    ROL64in256(Bbo, A##mo, 21); \
    E##be = XOR256(Bbe, ANDnu256(Bbi, Bbo)); \
    XOReq256(A##su, Du); \
    ROL64in256(Bbu, A##su, 14); \
    E##bi = XOR256(Bbi, ANDnu256(Bbo, Bbu)); \
    E##bo = XOR256(Bbo, ANDnu256(Bbu, Bba)); \
    E##bu = XOR256(Bbu, ANDnu256(Bba, Bbe)); \
\
    XOReq256(A##bo, Do); \
    ROL64in256(Bga, A##bo, 28); \
    XOReq256(A##gu, Du); \
    ROL64in256(Bge, A##gu, 20); \
    XOReq256(A##ka, Da); \
    ROL64in256(Bgi, A##ka, 3); \
    E##ga = XOR256(Bga, ANDnu256(Bge, Bgi)); \
    XOReq256(A##me, De); \
    ROL64in256(Bgo, A##me, 45); \
    E##ge = XOR256(Bge, ANDnu256(Bgi, Bgo)); \
    XOReq256(A##si, Di); \
    ROL64in256(Bgu, A##si, 61); \
    E##gi = XOR256(Bgi, ANDnu256(Bgo, Bgu)); \
    E##go = XOR256(Bgo, ANDnu256(Bgu, Bga)); \
    E##gu = XOR256(Bgu, ANDnu256(Bga, Bge)); \
\
    XOReq256(A##be, De); \
    ROL64in256(Bka, A##be, 1); \
    XOReq256(A##gi, Di); \
    ROL64in256(Bke, A##gi, 6); \
    XOReq256(A##ko, Do); \
    ROL64in256(Bki, A##ko, 25); \
    E##ka = XOR256(Bka, ANDnu256(Bke, Bki)); \
    XOReq256(A##mu, Du); \
    ROL64in256_8(Bko, A##mu); \
    E##ke = XOR256(Bke, ANDnu256(Bki, Bko)); \
    XOReq256(A##sa, Da); \
    ROL64in256(Bku, A##sa, 18); \
    E##ki = XOR256(Bki, ANDnu256(Bko, Bku)); \
    E##ko = XOR256(Bko, ANDnu256(Bku, Bka)); \
    E##ku = XOR256(Bku, ANDnu256(Bka, Bke)); \
\
    XOReq256(A##bu, Du); \
    ROL64in256(Bma, A##bu, 27); \
    XOReq256(A##ga, Da); \
    ROL64in256(Bme, A##ga, 36); \
    XOReq256(A##ke, De); \
    ROL64in256(Bmi, A##ke, 10); \
    E##ma = XOR256(Bma, ANDnu256(Bme, Bmi)); \
    XOReq256(A##mi, Di); \
    ROL64in256(Bmo, A##mi, 15); \
    E##me = XOR256(Bme, ANDnu256(Bmi, Bmo)); \
    XOReq256(A##so, Do); \
    ROL64in256_56(Bmu, A##so); \
    E##mi = XOR256(Bmi, ANDnu256(Bmo, Bmu)); \
    E##mo = XOR256(Bmo, ANDnu256(Bmu, Bma)); \
    E##mu = XOR256(Bmu, ANDnu256(Bma, Bme)); \
\
    XOReq256(A##bi, Di); \
    ROL64in256(Bsa, A##bi, 62); \
    XOReq256(A##go, Do); \
    ROL64in256(Bse, A##go, 55); \
    XOReq256(A##ku, Du); \
    ROL64in256(Bsi, A##ku, 39); \
    E##sa = XOR256(Bsa, ANDnu256(Bse, Bsi)); \
    XOReq256(A##ma, Da); \
    ROL64in256(Bso, A##ma, 41); \
    E##se = XOR256(Bse, ANDnu256(Bsi, Bso)); \
    XOReq256(A##se, De); \
    ROL64in256(Bsu, A##se, 2); \
    E##si = XOR256(Bsi, ANDnu256(Bso, Bsu)); \
    E##so = XOR256(Bso, ANDnu256(Bsu, Bsa)); \
    E##su = XOR256(Bsu, ANDnu256(Bsa, Bse)); \
\

/*************** kyber/avx2/keccak4x/KeccakP-1600-unrolling.macros */
#define rounds24 \
    prepareTheta \
    thetaRhoPiChiIotaPrepareTheta( 0, A, E) \
    thetaRhoPiChiIotaPrepareTheta( 1, E, A) \
    thetaRhoPiChiIotaPrepareTheta( 2, A, E) \
    thetaRhoPiChiIotaPrepareTheta( 3, E, A) \
    thetaRhoPiChiIotaPrepareTheta( 4, A, E) \
    thetaRhoPiChiIotaPrepareTheta( 5, E, A) \
    thetaRhoPiChiIotaPrepareTheta( 6, A, E) \
    thetaRhoPiChiIotaPrepareTheta( 7, E, A) \
    thetaRhoPiChiIotaPrepareTheta( 8, A, E) \
    thetaRhoPiChiIotaPrepareTheta( 9, E, A) \
    thetaRhoPiChiIotaPrepareTheta(10, A, E) \
    thetaRhoPiChiIotaPrepareTheta(11, E, A) \
    thetaRhoPiChiIotaPrepareTheta(12, A, E) \
    thetaRhoPiChiIotaPrepareTheta(13, E, A) \
    thetaRhoPiChiIotaPrepareTheta(14, A, E) \
    thetaRhoPiChiIotaPrepareTheta(15, E, A) \
    thetaRhoPiChiIotaPrepareTheta(16, A, E) \
    thetaRhoPiChiIotaPrepareTheta(17, E, A) \
    thetaRhoPiChiIotaPrepareTheta(18, A, E) \
    thetaRhoPiChiIotaPrepareTheta(19, E, A) \
    thetaRhoPiChiIotaPrepareTheta(20, A, E) \
    thetaRhoPiChiIotaPrepareTheta(21, E, A) \
    thetaRhoPiChiIotaPrepareTheta(22, A, E) \
    thetaRhoPiChiIota(23, E, A) \


#define KeccakF1600_StatePermute4x KeccakP1600times4_PermuteAll_24rounds
static void KeccakF1600_StatePermute4x(__m256i *states)
{
    V256 *statesAsLanes = (V256 *)states;
    declareABCDE
    #ifndef KeccakP1600times4_fullUnrolling
    unsigned int i;
    #endif

    copyFromState(A, statesAsLanes)
    rounds24
    copyToState(statesAsLanes, A)
}

/*************** kyber/avx2/fips202x4.c */
static void keccakx4_absorb_once(__m256i s[25],
                                 unsigned int r,
                                 const uint8_t *in0,
                                 const uint8_t *in1,
                                 const uint8_t *in2,
                                 const uint8_t *in3,
                                 size_t inlen,
                                 uint8_t p)
{
  size_t i;
  uint64_t pos = 0;
  __m256i t, idx;

  for(i = 0; i < 25; ++i)
    s[i] = _mm256_setzero_si256();

  idx = _mm256_set_epi64x((long long)in3, (long long)in2, (long long)in1, (long long)in0);
  while(inlen >= r) {
    for(i = 0; i < r/8; ++i) {
      t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
      s[i] = _mm256_xor_si256(s[i], t);
      pos += 8;
    }
    inlen -= r;

    KeccakF1600_StatePermute4x(s);
  }

  for(i = 0; i < inlen/8; ++i) {
    t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
    s[i] = _mm256_xor_si256(s[i], t);
    pos += 8;
  }
  inlen -= 8*i;

  if(inlen) {
    t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
    idx = _mm256_set1_epi64x((1ULL << (8*inlen)) - 1);
    t = _mm256_and_si256(t, idx);
    s[i] = _mm256_xor_si256(s[i], t);
  }

  t = _mm256_set1_epi64x((uint64_t)p << 8*inlen);
  s[i] = _mm256_xor_si256(s[i], t);
  t = _mm256_set1_epi64x(1ULL << 63);
  s[r/8 - 1] = _mm256_xor_si256(s[r/8 - 1], t);
}

static void keccakx4_squeezeblocks(uint8_t *out0,
                                   uint8_t *out1,
                                   uint8_t *out2,
                                   uint8_t *out3,
                                   size_t nblocks,
                                   unsigned int r,
                                   __m256i s[25])
{
  unsigned int i;
  __m128d t;

  while(nblocks > 0) {
    KeccakF1600_StatePermute4x(s);
    for(i=0; i < r/8; ++i) {
      t = _mm_castsi128_pd(_mm256_castsi256_si128(s[i]));
      _mm_storel_pd((__attribute__((__may_alias__)) double *)&out0[8*i], t);
      _mm_storeh_pd((__attribute__((__may_alias__)) double *)&out1[8*i], t);
      t = _mm_castsi128_pd(_mm256_extracti128_si256(s[i],1));
      _mm_storel_pd((__attribute__((__may_alias__)) double *)&out2[8*i], t);
      _mm_storeh_pd((__attribute__((__may_alias__)) double *)&out3[8*i], t);
    }

    out0 += r;
    out1 += r;
    out2 += r;
    out3 += r;
    --nblocks;
  }
}

void shake128x4_absorb_once(keccakx4_state *state,
                            const uint8_t *in0,
                            const uint8_t *in1,
                            const uint8_t *in2,
                            const uint8_t *in3,
                            size_t inlen)
{
  keccakx4_absorb_once(state->s, SHAKE128_RATE, in0, in1, in2, in3, inlen, 0x1F);
}

void shake128x4_squeezeblocks(uint8_t *out0,
                              uint8_t *out1,
                              uint8_t *out2,
                              uint8_t *out3,
                              size_t nblocks,
                              keccakx4_state *state)
{
  keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks, SHAKE128_RATE, state->s);
}

static
void shake256x4_absorb_once(keccakx4_state *state,
                            const uint8_t *in0,
                            const uint8_t *in1,
                            const uint8_t *in2,
                            const uint8_t *in3,
                            size_t inlen)
{
  keccakx4_absorb_once(state->s, SHAKE256_RATE, in0, in1, in2, in3, inlen, 0x1F);
}

static
void shake256x4_squeezeblocks(uint8_t *out0,
                              uint8_t *out1,
                              uint8_t *out2,
                              uint8_t *out3,
                              size_t nblocks,
                              keccakx4_state *state)
{
  keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks, SHAKE256_RATE, state->s);
}

/*************** kyber/avx2/cbd.c */
/*************************************************
* Name:        cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const __m256i *buf: pointer to aligned input byte array
**************************************************/
static void cbd2(poly * restrict r, const __m256i buf[2*KYBER_N/128])
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i mask55 = _mm256_set1_epi32(0x55555555);
  const __m256i mask33 = _mm256_set1_epi32(0x33333333);
  const __m256i mask03 = _mm256_set1_epi32(0x03030303);
  const __m256i mask0F = _mm256_set1_epi32(0x0F0F0F0F);

  for(i = 0; i < KYBER_N/64; i++) {
    f0 = _mm256_load_si256(&buf[i]);

    f1 = _mm256_srli_epi16(f0, 1);
    f0 = _mm256_and_si256(mask55, f0);
    f1 = _mm256_and_si256(mask55, f1);
    f0 = _mm256_add_epi8(f0, f1);

    f1 = _mm256_srli_epi16(f0, 2);
    f0 = _mm256_and_si256(mask33, f0);
    f1 = _mm256_and_si256(mask33, f1);
    f0 = _mm256_add_epi8(f0, mask33);
    f0 = _mm256_sub_epi8(f0, f1);

    f1 = _mm256_srli_epi16(f0, 4);
    f0 = _mm256_and_si256(mask0F, f0);
    f1 = _mm256_and_si256(mask0F, f1);
    f0 = _mm256_sub_epi8(f0, mask03);
    f1 = _mm256_sub_epi8(f1, mask03);

    f2 = _mm256_unpacklo_epi8(f0, f1);
    f3 = _mm256_unpackhi_epi8(f0, f1);

    f0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f2));
    f1 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f2,1));
    f2 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f3));
    f3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f3,1));

    _mm256_store_si256(&r->vec[4*i+0], f0);
    _mm256_store_si256(&r->vec[4*i+1], f2);
    _mm256_store_si256(&r->vec[4*i+2], f1);
    _mm256_store_si256(&r->vec[4*i+3], f3);
  }
}

#if !defined(KYBER_K) || KYBER_K == 2
/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3
*              This function is only needed for Kyber-512
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const __m256i *buf: pointer to aligned input byte array
**************************************************/
static void cbd3(poly * restrict r, const uint8_t buf[3*KYBER_N/4+8])
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i mask249 = _mm256_set1_epi32(0x249249);
  const __m256i mask6DB = _mm256_set1_epi32(0x6DB6DB);
  const __m256i mask07 = _mm256_set1_epi32(7);
  const __m256i mask70 = _mm256_set1_epi32(7 << 16);
  const __m256i mask3 = _mm256_set1_epi16(3);
  const __m256i shufbidx = _mm256_set_epi8(-1,15,14,13,-1,12,11,10,-1, 9, 8, 7,-1, 6, 5, 4,
                                           -1,11,10, 9,-1, 8, 7, 6,-1, 5, 4, 3,-1, 2, 1, 0);

  for(i = 0; i < KYBER_N/32; i++) {
    f0 = _mm256_loadu_si256((__m256i *)&buf[24*i]);
    f0 = _mm256_permute4x64_epi64(f0,0x94);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);

    f1 = _mm256_srli_epi32(f0,1);
    f2 = _mm256_srli_epi32(f0,2);
    f0 = _mm256_and_si256(mask249,f0);
    f1 = _mm256_and_si256(mask249,f1);
    f2 = _mm256_and_si256(mask249,f2);
    f0 = _mm256_add_epi32(f0,f1);
    f0 = _mm256_add_epi32(f0,f2);

    f1 = _mm256_srli_epi32(f0,3);
    f0 = _mm256_add_epi32(f0,mask6DB);
    f0 = _mm256_sub_epi32(f0,f1);

    f1 = _mm256_slli_epi32(f0,10);
    f2 = _mm256_srli_epi32(f0,12);
    f3 = _mm256_srli_epi32(f0, 2);
    f0 = _mm256_and_si256(f0,mask07);
    f1 = _mm256_and_si256(f1,mask70);
    f2 = _mm256_and_si256(f2,mask07);
    f3 = _mm256_and_si256(f3,mask70);
    f0 = _mm256_add_epi16(f0,f1);
    f1 = _mm256_add_epi16(f2,f3);
    f0 = _mm256_sub_epi16(f0,mask3);
    f1 = _mm256_sub_epi16(f1,mask3);

    f2 = _mm256_unpacklo_epi32(f0,f1);
    f3 = _mm256_unpackhi_epi32(f0,f1);

    f0 = _mm256_permute2x128_si256(f2,f3,0x20);
    f1 = _mm256_permute2x128_si256(f2,f3,0x31);

    _mm256_store_si256(&r->vec[2*i+0], f0);
    _mm256_store_si256(&r->vec[2*i+1], f1);
  }
}
#endif

/*************** kyber/avx2/poly.c */
/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial.
*              The coefficients of the input polynomial are assumed to
*              lie in the invertal [0,q], i.e. the polynomial must be reduced
*              by poly_reduce().
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (of length KYBER_POLYCOMPRESSEDBYTES)
*              - const poly *a: pointer to input polynomial
**************************************************/
#if !defined(KYBER_K) || KYBER_K == 2 || KYBER_K == 3
void poly_compress_128(uint8_t r[128], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV/16]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 9);
  const __m256i mask = _mm256_set1_epi16(15);
  const __m256i shift2 = _mm256_set1_epi16((16 << 8) + 1);
  const __m256i permdidx = _mm256_set_epi32(7,3,6,2,5,1,4,0);

  for(i=0;i<KYBER_N/64;i++) {
    f0 = _mm256_load_si256(&a->vec[4*i+0]);
    f1 = _mm256_load_si256(&a->vec[4*i+1]);
    f2 = _mm256_load_si256(&a->vec[4*i+2]);
    f3 = _mm256_load_si256(&a->vec[4*i+3]);
    f0 = _mm256_mulhi_epi16(f0,v);
    f1 = _mm256_mulhi_epi16(f1,v);
    f2 = _mm256_mulhi_epi16(f2,v);
    f3 = _mm256_mulhi_epi16(f3,v);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f1 = _mm256_mulhrs_epi16(f1,shift1);
    f2 = _mm256_mulhrs_epi16(f2,shift1);
    f3 = _mm256_mulhrs_epi16(f3,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f1 = _mm256_and_si256(f1,mask);
    f2 = _mm256_and_si256(f2,mask);
    f3 = _mm256_and_si256(f3,mask);
    f0 = _mm256_packus_epi16(f0,f1);
    f2 = _mm256_packus_epi16(f2,f3);
    f0 = _mm256_maddubs_epi16(f0,shift2);
    f2 = _mm256_maddubs_epi16(f2,shift2);
    f0 = _mm256_packus_epi16(f0,f2);
    f0 = _mm256_permutevar8x32_epi32(f0,permdidx);
    _mm256_storeu_si256((__m256i *)&r[32*i],f0);
  }
}
#endif
#if !defined(KYBER_K) || KYBER_K == 4
void poly_compress_160(uint8_t r[160], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV/16]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 10);
  const __m256i mask = _mm256_set1_epi16(31);
  const __m256i shift2 = _mm256_set1_epi16((32 << 8) + 1);
  const __m256i shift3 = _mm256_set1_epi32((1024 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12);
  const __m256i shufbidx = _mm256_set_epi8( 8,-1,-1,-1,-1,-1, 4, 3, 2, 1, 0,-1,12,11,10, 9,
                                           -1,12,11,10, 9, 8,-1,-1,-1,-1,-1 ,4, 3, 2, 1, 0);

  for(i=0;i<KYBER_N/32;i++) {
    f0 = _mm256_load_si256(&a->vec[2*i+0]);
    f1 = _mm256_load_si256(&a->vec[2*i+1]);
    f0 = _mm256_mulhi_epi16(f0,v);
    f1 = _mm256_mulhi_epi16(f1,v);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f1 = _mm256_mulhrs_epi16(f1,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f1 = _mm256_and_si256(f1,mask);
    f0 = _mm256_packus_epi16(f0,f1);
    f0 = _mm256_maddubs_epi16(f0,shift2);	// a0 a1 a2 a3 b0 b1 b2 b3 a4 a5 a6 a7 b4 b5 b6 b7
    f0 = _mm256_madd_epi16(f0,shift3);		// a0 a1 b0 b1 a2 a3 b2 b3
    f0 = _mm256_sllv_epi32(f0,sllvdidx);
    f0 = _mm256_srlv_epi64(f0,sllvdidx);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0,1);
    t0 = _mm_blendv_epi8(t0,t1,_mm256_castsi256_si128(shufbidx));
    _mm_storeu_si128((__m128i *)&r[20*i+ 0],t0);
    memcpy(&r[20*i+16],&t1,4);
  }
}
#endif

#if !defined(KYBER_K) || KYBER_K == 2 || KYBER_K == 3
void poly_decompress_128(poly * restrict r, const uint8_t a[128])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ/16]);
  const __m256i shufbidx = _mm256_set_epi8(7,7,7,7,6,6,6,6,5,5,5,5,4,4,4,4,
                                           3,3,3,3,2,2,2,2,1,1,1,1,0,0,0,0);
  const __m256i mask = _mm256_set1_epi32(0x00F0000F);
  const __m256i shift = _mm256_set1_epi32((128 << 16) + 2048);

  for(i=0;i<KYBER_N/16;i++) {
    t = _mm_loadl_epi64((__m128i *)&a[8*i]);
    f = _mm256_broadcastsi128_si256(t);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mullo_epi16(f,shift);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}
#endif
#if !defined(KYBER_K) || KYBER_K == 4
void poly_decompress_160(poly * restrict r, const uint8_t a[160])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  int16_t ti;
  const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ/16]);
  const __m256i shufbidx = _mm256_set_epi8(9,9,9,8,8,8,8,7,7,6,6,6,6,5,5,5,
                                           4,4,4,3,3,3,3,2,2,1,1,1,1,0,0,0);
  const __m256i mask = _mm256_set_epi16(248,1984,62,496,3968,124,992,31,
                                        248,1984,62,496,3968,124,992,31);
  const __m256i shift = _mm256_set_epi16(128,16,512,64,8,256,32,1024,
                                         128,16,512,64,8,256,32,1024);

  for(i=0;i<KYBER_N/16;i++) {
    t = _mm_loadl_epi64((__m128i *)&a[10*i+0]);
    memcpy(&ti,&a[10*i+8],2);
    t = _mm_insert_epi16(t,ti,4);
    f = _mm256_broadcastsi128_si256(t);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mullo_epi16(f,shift);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}
#endif

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial in NTT representation.
*              The coefficients of the input polynomial are assumed to
*              lie in the invertal [0,q], i.e. the polynomial must be reduced
*              by poly_reduce(). The coefficients are orderd as output by
*              poly_ntt(); the serialized output coefficients are in bitreversed
*              order.
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYBYTES bytes)
*              - poly *a: pointer to input polynomial
**************************************************/
void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a)
{
  ntttobytes_avx(r, a->vec, qdata.vec);
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of KYBER_POLYBYTES bytes)
**************************************************/
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES])
{
  nttfrombytes_avx(r->vec, a, qdata.vec);
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void poly_frommsg(poly * restrict r, const uint8_t msg[KYBER_INDCPA_MSGBYTES])
{
#if (KYBER_INDCPA_MSGBYTES != 32)
#error "KYBER_INDCPA_MSGBYTES must be equal to 32!"
#endif
  __m256i f, g0, g1, g2, g3, h0, h1, h2, h3;
  const __m256i shift = _mm256_broadcastsi128_si256(_mm_set_epi32(0,1,2,3));
  const __m256i idx = _mm256_broadcastsi128_si256(_mm_set_epi8(15,14,11,10,7,6,3,2,13,12,9,8,5,4,1,0));
  const __m256i hqs = _mm256_set1_epi16((KYBER_Q+1)/2);

#define FROMMSG64(i)						\
  g3 = _mm256_shuffle_epi32(f,0x55*i);				\
  g3 = _mm256_sllv_epi32(g3,shift);				\
  g3 = _mm256_shuffle_epi8(g3,idx);				\
  g0 = _mm256_slli_epi16(g3,12);				\
  g1 = _mm256_slli_epi16(g3,8);					\
  g2 = _mm256_slli_epi16(g3,4);					\
  g0 = _mm256_srai_epi16(g0,15);				\
  g1 = _mm256_srai_epi16(g1,15);				\
  g2 = _mm256_srai_epi16(g2,15);				\
  g3 = _mm256_srai_epi16(g3,15);				\
  g0 = _mm256_and_si256(g0,hqs);  /* 19 18 17 16  3  2  1  0 */	\
  g1 = _mm256_and_si256(g1,hqs);  /* 23 22 21 20  7  6  5  4 */	\
  g2 = _mm256_and_si256(g2,hqs);  /* 27 26 25 24 11 10  9  8 */	\
  g3 = _mm256_and_si256(g3,hqs);  /* 31 30 29 28 15 14 13 12 */	\
  h0 = _mm256_unpacklo_epi64(g0,g1);				\
  h2 = _mm256_unpackhi_epi64(g0,g1);				\
  h1 = _mm256_unpacklo_epi64(g2,g3);				\
  h3 = _mm256_unpackhi_epi64(g2,g3);				\
  g0 = _mm256_permute2x128_si256(h0,h1,0x20);			\
  g2 = _mm256_permute2x128_si256(h0,h1,0x31);			\
  g1 = _mm256_permute2x128_si256(h2,h3,0x20);			\
  g3 = _mm256_permute2x128_si256(h2,h3,0x31);			\
  _mm256_store_si256(&r->vec[0+2*i+0],g0);	\
  _mm256_store_si256(&r->vec[0+2*i+1],g1);	\
  _mm256_store_si256(&r->vec[8+2*i+0],g2);	\
  _mm256_store_si256(&r->vec[8+2*i+1],g3)

  f = _mm256_loadu_si256((__m256i *)msg);
  FROMMSG64(0);
  FROMMSG64(1);
  FROMMSG64(2);
  FROMMSG64(3);
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message.
*              The coefficients of the input polynomial are assumed to
*              lie in the invertal [0,q], i.e. the polynomial must be reduced
*              by poly_reduce().
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - poly *a: pointer to input polynomial
**************************************************/
void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly * restrict a)
{
  unsigned int i;
  uint32_t small;
  __m256i f0, f1, g0, g1;
  const __m256i hq = _mm256_set1_epi16((KYBER_Q - 1)/2);
  const __m256i hhq = _mm256_set1_epi16((KYBER_Q - 1)/4);

  for(i=0;i<KYBER_N/32;i++) {
    f0 = _mm256_load_si256(&a->vec[2*i+0]);
    f1 = _mm256_load_si256(&a->vec[2*i+1]);
    f0 = _mm256_sub_epi16(hq, f0);
    f1 = _mm256_sub_epi16(hq, f1);
    g0 = _mm256_srai_epi16(f0, 15);
    g1 = _mm256_srai_epi16(f1, 15);
    f0 = _mm256_xor_si256(f0, g0);
    f1 = _mm256_xor_si256(f1, g1);
    f0 = _mm256_sub_epi16(f0, hhq);
    f1 = _mm256_sub_epi16(f1, hhq);
    f0 = _mm256_packs_epi16(f0, f1);
    f0 = _mm256_permute4x64_epi64(f0, 0xD8);
    small = _mm256_movemask_epi8(f0);
    memcpy(&msg[4*i], &small, 4);
  }
}

/*************************************************
* Name:        poly_getnoise_eta1
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA1
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce: one-byte input nonce
**************************************************/
#if !defined(KYBER_K) || KYBER_K == 2
void poly_getnoise_eta1_2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  ALIGNED_UINT8(KYBER_ETA1_2*KYBER_N/4+32) buf; /* +32 bytes as required by poly_cbd_eta1 */
  prf(buf.coeffs, KYBER_ETA1_2*KYBER_N/4, seed, nonce);
  cbd3(r, (const uint8_t *)buf.vec);
}
#endif
#if !defined(KYBER_K) || KYBER_K == 3 || KYBER_K == 4
void poly_getnoise_eta1_3_4(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  ALIGNED_UINT8(KYBER_ETA1_3_4*KYBER_N/4+32) buf; /* +32 bytes as required by poly_cbd_eta1 */
  prf(buf.coeffs, KYBER_ETA1_3_4*KYBER_N/4, seed, nonce);
  cbd2(r, buf.vec);
}
#endif

/*************************************************
* Name:        poly_getnoise_eta2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA2
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce: one-byte input nonce
**************************************************/
void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  ALIGNED_UINT8(KYBER_ETA2*KYBER_N/4) buf;
  prf(buf.coeffs, KYBER_ETA2*KYBER_N/4, seed, nonce);
  cbd2(r, buf.vec);
}

#ifndef KYBER_90S
#if !defined(KYBER_K) || KYBER_K == 2
#define NOISE_NBLOCKS_2 ((KYBER_ETA1_2*KYBER_N/4+SHAKE256_RATE-1)/SHAKE256_RATE)
void poly_getnoise_eta1_4x_2(poly *r0,
                           poly *r1,
                           poly *r2,
                           poly *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3)
{
  ALIGNED_UINT8(NOISE_NBLOCKS_2*SHAKE256_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  buf[0].coeffs[32] = nonce0;
  buf[1].coeffs[32] = nonce1;
  buf[2].coeffs[32] = nonce2;
  buf[3].coeffs[32] = nonce3;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 33);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, NOISE_NBLOCKS_2, &state);

  cbd3(r0, (const uint8_t *)buf[0].vec);
  cbd3(r1, (const uint8_t *)buf[1].vec);
  cbd3(r2, (const uint8_t *)buf[2].vec);
  cbd3(r3, (const uint8_t *)buf[3].vec);
}
#endif
#if !defined(KYBER_K) || KYBER_K == 3 || KYBER_K == 4
#define NOISE_NBLOCKS_3_4 ((KYBER_ETA1_3_4*KYBER_N/4+SHAKE256_RATE-1)/SHAKE256_RATE)
void poly_getnoise_eta1_4x_3_4(poly *r0,
                           poly *r1,
                           poly *r2,
                           poly *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3)
{
  ALIGNED_UINT8(NOISE_NBLOCKS_3_4*SHAKE256_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  buf[0].coeffs[32] = nonce0;
  buf[1].coeffs[32] = nonce1;
  buf[2].coeffs[32] = nonce2;
  buf[3].coeffs[32] = nonce3;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 33);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, NOISE_NBLOCKS_3_4, &state);

  cbd2(r0, buf[0].vec);
  cbd2(r1, buf[1].vec);
  cbd2(r2, buf[2].vec);
  cbd2(r3, buf[3].vec);
}
#endif

#if !defined(KYBER_K) || KYBER_K == 2
void poly_getnoise_eta1122_4x(poly *r0,
                              poly *r1,
                              poly *r2,
                              poly *r3,
                              const uint8_t seed[32],
                              uint8_t nonce0,
                              uint8_t nonce1,
                              uint8_t nonce2,
                              uint8_t nonce3)
{
  ALIGNED_UINT8(NOISE_NBLOCKS_2*SHAKE256_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  buf[0].coeffs[32] = nonce0;
  buf[1].coeffs[32] = nonce1;
  buf[2].coeffs[32] = nonce2;
  buf[3].coeffs[32] = nonce3;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 33);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, NOISE_NBLOCKS_2, &state);

  cbd3(r0, (const uint8_t *)buf[0].vec);
  cbd3(r1, (const uint8_t *)buf[1].vec);
  cbd2(r2, buf[2].vec);
  cbd2(r3, buf[3].vec);
}
#endif
#endif

/*************************************************
* Name:        poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place.
*              Input coefficients assumed to be in normal order,
*              output coefficients are in special order that is natural
*              for the vectorization. Input coefficients are assumed to be
*              bounded by q in absolute value.
*
* Arguments:   - poly *r: pointer to in/output polynomial
**************************************************/
void poly_ntt(poly *r)
{
  ntt_avx(r->vec, qdata.vec);
  reduce_avx(r->vec, qdata.vec);
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              Input coefficients assumed to be in special order from vectorized
*              forward ntt, output in normal order. Input coefficients can be
*              arbitrary 16-bit integers, output coefficients are bounded by 14870
*              in absolute value.
*
* Arguments:   - poly *a: pointer to in/output polynomial
**************************************************/
void poly_invntt_tomont(poly *r)
{
  invntt_avx(r->vec, qdata.vec);
}

static
void poly_nttunpack(poly *r)
{
  nttunpack_avx(r->vec, qdata.vec);
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain.
*              One of the input polynomials needs to have coefficients
*              bounded by q, the other polynomial can have arbitrary
*              coefficients. Output coefficients are bounded by 6656.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
  basemul_avx(r->vec, a->vec, b->vec, qdata.vec);
}

/*************************************************
* Name:        poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_tomont(poly *r)
{
  tomont_avx(r->vec, qdata.vec);
}

/*************************************************
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_reduce(poly *r)
{
  reduce_avx(r->vec, qdata.vec);
}

/*************************************************
* Name:        poly_add
*
* Description: Add two polynomials. No modular reduction
*              is performed.
*
* Arguments: - poly *r: pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_add(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  __m256i f0, f1;

  for(i=0;i<KYBER_N/16;i++) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_load_si256(&b->vec[i]);
    f0 = _mm256_add_epi16(f0, f1);
    _mm256_store_si256(&r->vec[i], f0);
  }
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials. No modular reduction
*              is performed.
*
* Arguments: - poly *r: pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_sub(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  __m256i f0, f1;

  for(i=0;i<KYBER_N/16;i++) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_load_si256(&b->vec[i]);
    f0 = _mm256_sub_epi16(f0, f1);
    _mm256_store_si256(&r->vec[i], f0);
  }
}

/*************** kyber/avx2/polyvec.c */
#if !defined(KYBER_K) || KYBER_K == 2 || KYBER_K == 3
static void poly_compress10(uint8_t r[320], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV/16]);
  const __m256i v8 = _mm256_slli_epi16(v,3);
  const __m256i off = _mm256_set1_epi16(15);
  const __m256i shift1 = _mm256_set1_epi16(1 << 12);
  const __m256i mask = _mm256_set1_epi16(1023);
  const __m256i shift2 = _mm256_set1_epi64x((1024LL << 48) + (1LL << 32) + (1024 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12);
  const __m256i shufbidx = _mm256_set_epi8( 8, 4, 3, 2, 1, 0,-1,-1,-1,-1,-1,-1,12,11,10, 9,
                                           -1,-1,-1,-1,-1,-1,12,11,10, 9, 8, 4, 3, 2, 1, 0);

  for(i=0;i<KYBER_N/16;i++) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_mullo_epi16(f0,v8);
    f2 = _mm256_add_epi16(f0,off);
    f0 = _mm256_slli_epi16(f0,3);
    f0 = _mm256_mulhi_epi16(f0,v);
    f2 = _mm256_sub_epi16(f1,f2);
    f1 = _mm256_andnot_si256(f1,f2);
    f1 = _mm256_srli_epi16(f1,15);
    f0 = _mm256_sub_epi16(f0,f1);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f0 = _mm256_madd_epi16(f0,shift2);
    f0 = _mm256_sllv_epi32(f0,sllvdidx);
    f0 = _mm256_srli_epi64(f0,12);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0,1);
    t0 = _mm_blend_epi16(t0,t1,0xE0);
    _mm_storeu_si128((__m128i *)&r[20*i+ 0],t0);
    memcpy(&r[20*i+16],&t1,4);
  }
}

static void poly_decompress10(poly * restrict r, const uint8_t a[320+12])
{
  unsigned int i;
  __m256i f;
  const __m256i q = _mm256_set1_epi32((KYBER_Q << 16) + 4*KYBER_Q);
  const __m256i shufbidx = _mm256_set_epi8(11,10,10, 9, 9, 8, 8, 7,
                                            6, 5, 5, 4, 4, 3, 3, 2,
                                            9, 8, 8, 7, 7, 6, 6, 5,
                                            4, 3, 3, 2, 2, 1, 1, 0);
  const __m256i sllvdidx = _mm256_set1_epi64x(4);
  const __m256i mask = _mm256_set1_epi32((32736 << 16) + 8184);

  for(i=0;i<KYBER_N/16;i++) {
    f = _mm256_loadu_si256((__m256i *)&a[20*i]);
    f = _mm256_permute4x64_epi64(f,0x94);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_sllv_epi32(f,sllvdidx);
    f = _mm256_srli_epi16(f,1);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}
#endif
#if !defined(KYBER_K) || KYBER_K == 4
static void poly_compress11(uint8_t r[352+2], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV/16]);
  const __m256i v8 = _mm256_slli_epi16(v,3);
  const __m256i off = _mm256_set1_epi16(36);
  const __m256i shift1 = _mm256_set1_epi16(1 << 13);
  const __m256i mask = _mm256_set1_epi16(2047);
  const __m256i shift2 = _mm256_set1_epi64x((2048LL << 48) + (1LL << 32) + (2048 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(10);
  const __m256i srlvqidx = _mm256_set_epi64x(30,10,30,10);
  const __m256i shufbidx = _mm256_set_epi8( 4, 3, 2, 1, 0, 0,-1,-1,-1,-1,10, 9, 8, 7, 6, 5,
                                           -1,-1,-1,-1,-1,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

  for(i=0;i<KYBER_N/16;i++) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_mullo_epi16(f0,v8);
    f2 = _mm256_add_epi16(f0,off);
    f0 = _mm256_slli_epi16(f0,3);
    f0 = _mm256_mulhi_epi16(f0,v);
    f2 = _mm256_sub_epi16(f1,f2);
    f1 = _mm256_andnot_si256(f1,f2);
    f1 = _mm256_srli_epi16(f1,15);
    f0 = _mm256_sub_epi16(f0,f1);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f0 = _mm256_madd_epi16(f0,shift2);
    f0 = _mm256_sllv_epi32(f0,sllvdidx);
    f1 = _mm256_bsrli_epi128(f0,8);
    f0 = _mm256_srlv_epi64(f0,srlvqidx);
    f1 = _mm256_slli_epi64(f1,34);
    f0 = _mm256_add_epi64(f0,f1);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0,1);
    t0 = _mm_blendv_epi8(t0,t1,_mm256_castsi256_si128(shufbidx));
    _mm_storeu_si128((__m128i *)&r[22*i+ 0],t0);
    _mm_storel_epi64((__m128i *)&r[22*i+16],t1);
  }
}

static void poly_decompress11(poly * restrict r, const uint8_t a[352+10])
{
  unsigned int i;
  __m256i f;
  const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ/16]);
  const __m256i shufbidx = _mm256_set_epi8(13,12,12,11,10, 9, 9, 8,
                                            8, 7, 6, 5, 5, 4, 4, 3,
                                           10, 9, 9, 8, 7, 6, 6, 5,
                                            5, 4, 3, 2, 2, 1, 1, 0);
  const __m256i srlvdidx = _mm256_set_epi32(0,0,1,0,0,0,1,0);
  const __m256i srlvqidx = _mm256_set_epi64x(2,0,2,0);
  const __m256i shift = _mm256_set_epi16(4,32,1,8,32,1,4,32,4,32,1,8,32,1,4,32);
  const __m256i mask = _mm256_set1_epi16(32752);

  for(i=0;i<KYBER_N/16;i++) {
    f = _mm256_loadu_si256((__m256i *)&a[22*i]);
    f = _mm256_permute4x64_epi64(f,0x94);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_srlv_epi32(f,srlvdidx);
    f = _mm256_srlv_epi64(f,srlvqidx);
    f = _mm256_mullo_epi16(f,shift);
    f = _mm256_srli_epi16(f,1);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}
#endif

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - polyvec *a: pointer to input vector of polynomials
**************************************************/
#if !defined(KYBER_K) || KYBER_K == 2
void polyvec_compress_2(uint8_t r[2*320+2], const polyvec_2 *a)
{
  unsigned int i;

  for(i=0;i<2;i++)
    poly_compress10(&r[320*i],&a->vec[i]);
}
#endif
#if !defined(KYBER_K) || KYBER_K == 3
void polyvec_compress_3(uint8_t r[3*320+2], const polyvec_3 *a)
{
  unsigned int i;

  for(i=0;i<3;i++)
    poly_compress10(&r[320*i],&a->vec[i]);
}
#endif
#if !defined(KYBER_K) || KYBER_K == 4
void polyvec_compress_4(uint8_t r[4*352+2], const polyvec_4 *a)
{
  unsigned int i;

  for(i=0;i<4;i++)
    poly_compress11(&r[352*i],&a->vec[i]);
}
#endif

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r: pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
#if !defined(KYBER_K) || KYBER_K == 2
void polyvec_decompress_2(polyvec_2 *r, const uint8_t a[2*320+12])
{
  unsigned int i;

  for(i=0;i<2;i++)
    poly_decompress10(&r->vec[i],&a[320*i]);
}
#endif
#if !defined(KYBER_K) || KYBER_K == 3
void polyvec_decompress_3(polyvec_3 *r, const uint8_t a[3*320+12])
{
  unsigned int i;

  for(i=0;i<3;i++)
    poly_decompress10(&r->vec[i],&a[320*i]);
}
#endif
#if !defined(KYBER_K) || KYBER_K == 4
void polyvec_decompress_4(polyvec_4 *r, const uint8_t a[4*352+12])
{
  unsigned int i;

  for(i=0;i<4;i++)
    poly_decompress11(&r->vec[i],&a[352*i]);
}
#endif

/*************** kyber/avx2/rejsample.c */
#define REJ_UNIFORM_AVX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
#define REJ_UNIFORM_AVX_BUFLEN (REJ_UNIFORM_AVX_NBLOCKS*XOF_BLOCKBYTES)

static const uint8_t idx[256][8] = {
  {-1, -1, -1, -1, -1, -1, -1, -1},
  { 0, -1, -1, -1, -1, -1, -1, -1},
  { 2, -1, -1, -1, -1, -1, -1, -1},
  { 0,  2, -1, -1, -1, -1, -1, -1},
  { 4, -1, -1, -1, -1, -1, -1, -1},
  { 0,  4, -1, -1, -1, -1, -1, -1},
  { 2,  4, -1, -1, -1, -1, -1, -1},
  { 0,  2,  4, -1, -1, -1, -1, -1},
  { 6, -1, -1, -1, -1, -1, -1, -1},
  { 0,  6, -1, -1, -1, -1, -1, -1},
  { 2,  6, -1, -1, -1, -1, -1, -1},
  { 0,  2,  6, -1, -1, -1, -1, -1},
  { 4,  6, -1, -1, -1, -1, -1, -1},
  { 0,  4,  6, -1, -1, -1, -1, -1},
  { 2,  4,  6, -1, -1, -1, -1, -1},
  { 0,  2,  4,  6, -1, -1, -1, -1},
  { 8, -1, -1, -1, -1, -1, -1, -1},
  { 0,  8, -1, -1, -1, -1, -1, -1},
  { 2,  8, -1, -1, -1, -1, -1, -1},
  { 0,  2,  8, -1, -1, -1, -1, -1},
  { 4,  8, -1, -1, -1, -1, -1, -1},
  { 0,  4,  8, -1, -1, -1, -1, -1},
  { 2,  4,  8, -1, -1, -1, -1, -1},
  { 0,  2,  4,  8, -1, -1, -1, -1},
  { 6,  8, -1, -1, -1, -1, -1, -1},
  { 0,  6,  8, -1, -1, -1, -1, -1},
  { 2,  6,  8, -1, -1, -1, -1, -1},
  { 0,  2,  6,  8, -1, -1, -1, -1},
  { 4,  6,  8, -1, -1, -1, -1, -1},
  { 0,  4,  6,  8, -1, -1, -1, -1},
  { 2,  4,  6,  8, -1, -1, -1, -1},
  { 0,  2,  4,  6,  8, -1, -1, -1},
  {10, -1, -1, -1, -1, -1, -1, -1},
  { 0, 10, -1, -1, -1, -1, -1, -1},
  { 2, 10, -1, -1, -1, -1, -1, -1},
  { 0,  2, 10, -1, -1, -1, -1, -1},
  { 4, 10, -1, -1, -1, -1, -1, -1},
  { 0,  4, 10, -1, -1, -1, -1, -1},
  { 2,  4, 10, -1, -1, -1, -1, -1},
  { 0,  2,  4, 10, -1, -1, -1, -1},
  { 6, 10, -1, -1, -1, -1, -1, -1},
  { 0,  6, 10, -1, -1, -1, -1, -1},
  { 2,  6, 10, -1, -1, -1, -1, -1},
  { 0,  2,  6, 10, -1, -1, -1, -1},
  { 4,  6, 10, -1, -1, -1, -1, -1},
  { 0,  4,  6, 10, -1, -1, -1, -1},
  { 2,  4,  6, 10, -1, -1, -1, -1},
  { 0,  2,  4,  6, 10, -1, -1, -1},
  { 8, 10, -1, -1, -1, -1, -1, -1},
  { 0,  8, 10, -1, -1, -1, -1, -1},
  { 2,  8, 10, -1, -1, -1, -1, -1},
  { 0,  2,  8, 10, -1, -1, -1, -1},
  { 4,  8, 10, -1, -1, -1, -1, -1},
  { 0,  4,  8, 10, -1, -1, -1, -1},
  { 2,  4,  8, 10, -1, -1, -1, -1},
  { 0,  2,  4,  8, 10, -1, -1, -1},
  { 6,  8, 10, -1, -1, -1, -1, -1},
  { 0,  6,  8, 10, -1, -1, -1, -1},
  { 2,  6,  8, 10, -1, -1, -1, -1},
  { 0,  2,  6,  8, 10, -1, -1, -1},
  { 4,  6,  8, 10, -1, -1, -1, -1},
  { 0,  4,  6,  8, 10, -1, -1, -1},
  { 2,  4,  6,  8, 10, -1, -1, -1},
  { 0,  2,  4,  6,  8, 10, -1, -1},
  {12, -1, -1, -1, -1, -1, -1, -1},
  { 0, 12, -1, -1, -1, -1, -1, -1},
  { 2, 12, -1, -1, -1, -1, -1, -1},
  { 0,  2, 12, -1, -1, -1, -1, -1},
  { 4, 12, -1, -1, -1, -1, -1, -1},
  { 0,  4, 12, -1, -1, -1, -1, -1},
  { 2,  4, 12, -1, -1, -1, -1, -1},
  { 0,  2,  4, 12, -1, -1, -1, -1},
  { 6, 12, -1, -1, -1, -1, -1, -1},
  { 0,  6, 12, -1, -1, -1, -1, -1},
  { 2,  6, 12, -1, -1, -1, -1, -1},
  { 0,  2,  6, 12, -1, -1, -1, -1},
  { 4,  6, 12, -1, -1, -1, -1, -1},
  { 0,  4,  6, 12, -1, -1, -1, -1},
  { 2,  4,  6, 12, -1, -1, -1, -1},
  { 0,  2,  4,  6, 12, -1, -1, -1},
  { 8, 12, -1, -1, -1, -1, -1, -1},
  { 0,  8, 12, -1, -1, -1, -1, -1},
  { 2,  8, 12, -1, -1, -1, -1, -1},
  { 0,  2,  8, 12, -1, -1, -1, -1},
  { 4,  8, 12, -1, -1, -1, -1, -1},
  { 0,  4,  8, 12, -1, -1, -1, -1},
  { 2,  4,  8, 12, -1, -1, -1, -1},
  { 0,  2,  4,  8, 12, -1, -1, -1},
  { 6,  8, 12, -1, -1, -1, -1, -1},
  { 0,  6,  8, 12, -1, -1, -1, -1},
  { 2,  6,  8, 12, -1, -1, -1, -1},
  { 0,  2,  6,  8, 12, -1, -1, -1},
  { 4,  6,  8, 12, -1, -1, -1, -1},
  { 0,  4,  6,  8, 12, -1, -1, -1},
  { 2,  4,  6,  8, 12, -1, -1, -1},
  { 0,  2,  4,  6,  8, 12, -1, -1},
  {10, 12, -1, -1, -1, -1, -1, -1},
  { 0, 10, 12, -1, -1, -1, -1, -1},
  { 2, 10, 12, -1, -1, -1, -1, -1},
  { 0,  2, 10, 12, -1, -1, -1, -1},
  { 4, 10, 12, -1, -1, -1, -1, -1},
  { 0,  4, 10, 12, -1, -1, -1, -1},
  { 2,  4, 10, 12, -1, -1, -1, -1},
  { 0,  2,  4, 10, 12, -1, -1, -1},
  { 6, 10, 12, -1, -1, -1, -1, -1},
  { 0,  6, 10, 12, -1, -1, -1, -1},
  { 2,  6, 10, 12, -1, -1, -1, -1},
  { 0,  2,  6, 10, 12, -1, -1, -1},
  { 4,  6, 10, 12, -1, -1, -1, -1},
  { 0,  4,  6, 10, 12, -1, -1, -1},
  { 2,  4,  6, 10, 12, -1, -1, -1},
  { 0,  2,  4,  6, 10, 12, -1, -1},
  { 8, 10, 12, -1, -1, -1, -1, -1},
  { 0,  8, 10, 12, -1, -1, -1, -1},
  { 2,  8, 10, 12, -1, -1, -1, -1},
  { 0,  2,  8, 10, 12, -1, -1, -1},
  { 4,  8, 10, 12, -1, -1, -1, -1},
  { 0,  4,  8, 10, 12, -1, -1, -1},
  { 2,  4,  8, 10, 12, -1, -1, -1},
  { 0,  2,  4,  8, 10, 12, -1, -1},
  { 6,  8, 10, 12, -1, -1, -1, -1},
  { 0,  6,  8, 10, 12, -1, -1, -1},
  { 2,  6,  8, 10, 12, -1, -1, -1},
  { 0,  2,  6,  8, 10, 12, -1, -1},
  { 4,  6,  8, 10, 12, -1, -1, -1},
  { 0,  4,  6,  8, 10, 12, -1, -1},
  { 2,  4,  6,  8, 10, 12, -1, -1},
  { 0,  2,  4,  6,  8, 10, 12, -1},
  {14, -1, -1, -1, -1, -1, -1, -1},
  { 0, 14, -1, -1, -1, -1, -1, -1},
  { 2, 14, -1, -1, -1, -1, -1, -1},
  { 0,  2, 14, -1, -1, -1, -1, -1},
  { 4, 14, -1, -1, -1, -1, -1, -1},
  { 0,  4, 14, -1, -1, -1, -1, -1},
  { 2,  4, 14, -1, -1, -1, -1, -1},
  { 0,  2,  4, 14, -1, -1, -1, -1},
  { 6, 14, -1, -1, -1, -1, -1, -1},
  { 0,  6, 14, -1, -1, -1, -1, -1},
  { 2,  6, 14, -1, -1, -1, -1, -1},
  { 0,  2,  6, 14, -1, -1, -1, -1},
  { 4,  6, 14, -1, -1, -1, -1, -1},
  { 0,  4,  6, 14, -1, -1, -1, -1},
  { 2,  4,  6, 14, -1, -1, -1, -1},
  { 0,  2,  4,  6, 14, -1, -1, -1},
  { 8, 14, -1, -1, -1, -1, -1, -1},
  { 0,  8, 14, -1, -1, -1, -1, -1},
  { 2,  8, 14, -1, -1, -1, -1, -1},
  { 0,  2,  8, 14, -1, -1, -1, -1},
  { 4,  8, 14, -1, -1, -1, -1, -1},
  { 0,  4,  8, 14, -1, -1, -1, -1},
  { 2,  4,  8, 14, -1, -1, -1, -1},
  { 0,  2,  4,  8, 14, -1, -1, -1},
  { 6,  8, 14, -1, -1, -1, -1, -1},
  { 0,  6,  8, 14, -1, -1, -1, -1},
  { 2,  6,  8, 14, -1, -1, -1, -1},
  { 0,  2,  6,  8, 14, -1, -1, -1},
  { 4,  6,  8, 14, -1, -1, -1, -1},
  { 0,  4,  6,  8, 14, -1, -1, -1},
  { 2,  4,  6,  8, 14, -1, -1, -1},
  { 0,  2,  4,  6,  8, 14, -1, -1},
  {10, 14, -1, -1, -1, -1, -1, -1},
  { 0, 10, 14, -1, -1, -1, -1, -1},
  { 2, 10, 14, -1, -1, -1, -1, -1},
  { 0,  2, 10, 14, -1, -1, -1, -1},
  { 4, 10, 14, -1, -1, -1, -1, -1},
  { 0,  4, 10, 14, -1, -1, -1, -1},
  { 2,  4, 10, 14, -1, -1, -1, -1},
  { 0,  2,  4, 10, 14, -1, -1, -1},
  { 6, 10, 14, -1, -1, -1, -1, -1},
  { 0,  6, 10, 14, -1, -1, -1, -1},
  { 2,  6, 10, 14, -1, -1, -1, -1},
  { 0,  2,  6, 10, 14, -1, -1, -1},
  { 4,  6, 10, 14, -1, -1, -1, -1},
  { 0,  4,  6, 10, 14, -1, -1, -1},
  { 2,  4,  6, 10, 14, -1, -1, -1},
  { 0,  2,  4,  6, 10, 14, -1, -1},
  { 8, 10, 14, -1, -1, -1, -1, -1},
  { 0,  8, 10, 14, -1, -1, -1, -1},
  { 2,  8, 10, 14, -1, -1, -1, -1},
  { 0,  2,  8, 10, 14, -1, -1, -1},
  { 4,  8, 10, 14, -1, -1, -1, -1},
  { 0,  4,  8, 10, 14, -1, -1, -1},
  { 2,  4,  8, 10, 14, -1, -1, -1},
  { 0,  2,  4,  8, 10, 14, -1, -1},
  { 6,  8, 10, 14, -1, -1, -1, -1},
  { 0,  6,  8, 10, 14, -1, -1, -1},
  { 2,  6,  8, 10, 14, -1, -1, -1},
  { 0,  2,  6,  8, 10, 14, -1, -1},
  { 4,  6,  8, 10, 14, -1, -1, -1},
  { 0,  4,  6,  8, 10, 14, -1, -1},
  { 2,  4,  6,  8, 10, 14, -1, -1},
  { 0,  2,  4,  6,  8, 10, 14, -1},
  {12, 14, -1, -1, -1, -1, -1, -1},
  { 0, 12, 14, -1, -1, -1, -1, -1},
  { 2, 12, 14, -1, -1, -1, -1, -1},
  { 0,  2, 12, 14, -1, -1, -1, -1},
  { 4, 12, 14, -1, -1, -1, -1, -1},
  { 0,  4, 12, 14, -1, -1, -1, -1},
  { 2,  4, 12, 14, -1, -1, -1, -1},
  { 0,  2,  4, 12, 14, -1, -1, -1},
  { 6, 12, 14, -1, -1, -1, -1, -1},
  { 0,  6, 12, 14, -1, -1, -1, -1},
  { 2,  6, 12, 14, -1, -1, -1, -1},
  { 0,  2,  6, 12, 14, -1, -1, -1},
  { 4,  6, 12, 14, -1, -1, -1, -1},
  { 0,  4,  6, 12, 14, -1, -1, -1},
  { 2,  4,  6, 12, 14, -1, -1, -1},
  { 0,  2,  4,  6, 12, 14, -1, -1},
  { 8, 12, 14, -1, -1, -1, -1, -1},
  { 0,  8, 12, 14, -1, -1, -1, -1},
  { 2,  8, 12, 14, -1, -1, -1, -1},
  { 0,  2,  8, 12, 14, -1, -1, -1},
  { 4,  8, 12, 14, -1, -1, -1, -1},
  { 0,  4,  8, 12, 14, -1, -1, -1},
  { 2,  4,  8, 12, 14, -1, -1, -1},
  { 0,  2,  4,  8, 12, 14, -1, -1},
  { 6,  8, 12, 14, -1, -1, -1, -1},
  { 0,  6,  8, 12, 14, -1, -1, -1},
  { 2,  6,  8, 12, 14, -1, -1, -1},
  { 0,  2,  6,  8, 12, 14, -1, -1},
  { 4,  6,  8, 12, 14, -1, -1, -1},
  { 0,  4,  6,  8, 12, 14, -1, -1},
  { 2,  4,  6,  8, 12, 14, -1, -1},
  { 0,  2,  4,  6,  8, 12, 14, -1},
  {10, 12, 14, -1, -1, -1, -1, -1},
  { 0, 10, 12, 14, -1, -1, -1, -1},
  { 2, 10, 12, 14, -1, -1, -1, -1},
  { 0,  2, 10, 12, 14, -1, -1, -1},
  { 4, 10, 12, 14, -1, -1, -1, -1},
  { 0,  4, 10, 12, 14, -1, -1, -1},
  { 2,  4, 10, 12, 14, -1, -1, -1},
  { 0,  2,  4, 10, 12, 14, -1, -1},
  { 6, 10, 12, 14, -1, -1, -1, -1},
  { 0,  6, 10, 12, 14, -1, -1, -1},
  { 2,  6, 10, 12, 14, -1, -1, -1},
  { 0,  2,  6, 10, 12, 14, -1, -1},
  { 4,  6, 10, 12, 14, -1, -1, -1},
  { 0,  4,  6, 10, 12, 14, -1, -1},
  { 2,  4,  6, 10, 12, 14, -1, -1},
  { 0,  2,  4,  6, 10, 12, 14, -1},
  { 8, 10, 12, 14, -1, -1, -1, -1},
  { 0,  8, 10, 12, 14, -1, -1, -1},
  { 2,  8, 10, 12, 14, -1, -1, -1},
  { 0,  2,  8, 10, 12, 14, -1, -1},
  { 4,  8, 10, 12, 14, -1, -1, -1},
  { 0,  4,  8, 10, 12, 14, -1, -1},
  { 2,  4,  8, 10, 12, 14, -1, -1},
  { 0,  2,  4,  8, 10, 12, 14, -1},
  { 6,  8, 10, 12, 14, -1, -1, -1},
  { 0,  6,  8, 10, 12, 14, -1, -1},
  { 2,  6,  8, 10, 12, 14, -1, -1},
  { 0,  2,  6,  8, 10, 12, 14, -1},
  { 4,  6,  8, 10, 12, 14, -1, -1},
  { 0,  4,  6,  8, 10, 12, 14, -1},
  { 2,  4,  6,  8, 10, 12, 14, -1},
  { 0,  2,  4,  6,  8, 10, 12, 14}
};
#define _mm256_cmpge_epu16(a, b) _mm256_cmpeq_epi16(_mm256_max_epu16(a, b), a)
#define _mm_cmpge_epu16(a, b) _mm_cmpeq_epi16(_mm_max_epu16(a, b), a)

static
unsigned int rej_uniform_avx(int16_t * restrict r, const uint8_t *buf)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;
  uint32_t good;
#ifdef BMI
  uint64_t idx0, idx1, idx2, idx3;
#endif
  const __m256i bound  = _mm256_load_si256(&qdata.vec[_16XQ/16]);
  const __m256i ones   = _mm256_set1_epi8(1);
  const __m256i mask  = _mm256_set1_epi16(0xFFF);
  const __m256i idx8  = _mm256_set_epi8(15,14,14,13,12,11,11,10,
                                         9, 8, 8, 7, 6, 5, 5, 4,
                                        11,10,10, 9, 8, 7, 7, 6,
                                         5, 4, 4, 3, 2, 1, 1, 0);
  __m256i f0, f1, g0, g1, g2, g3;
  __m128i f, t, pilo, pihi;

  ctr = pos = 0;
  while(ctr <= KYBER_N - 32 && pos <= REJ_UNIFORM_AVX_BUFLEN - 56) {
    f0 = _mm256_loadu_si256((__m256i *)&buf[pos]);
    f1 = _mm256_loadu_si256((__m256i *)&buf[pos+24]);
    f0 = _mm256_permute4x64_epi64(f0, 0x94);
    f1 = _mm256_permute4x64_epi64(f1, 0x94);
    f0 = _mm256_shuffle_epi8(f0, idx8);
    f1 = _mm256_shuffle_epi8(f1, idx8);
    g0 = _mm256_srli_epi16(f0, 4);
    g1 = _mm256_srli_epi16(f1, 4);
    f0 = _mm256_blend_epi16(f0, g0, 0xAA);
    f1 = _mm256_blend_epi16(f1, g1, 0xAA);
    f0 = _mm256_and_si256(f0, mask);
    f1 = _mm256_and_si256(f1, mask);
    pos += 48;

    g0 = _mm256_cmpgt_epi16(bound, f0);
    g1 = _mm256_cmpgt_epi16(bound, f1);

    g0 = _mm256_packs_epi16(g0, g1);
    good = _mm256_movemask_epi8(g0);

#ifdef BMI
    idx0 = _pdep_u64(good >>  0, 0x0101010101010101);
    idx1 = _pdep_u64(good >>  8, 0x0101010101010101);
    idx2 = _pdep_u64(good >> 16, 0x0101010101010101);
    idx3 = _pdep_u64(good >> 24, 0x0101010101010101);
    idx0 = (idx0 << 8) - idx0;
    idx0  = _pext_u64(0x0E0C0A0806040200, idx0);
    idx1 = (idx1 << 8) - idx1;
    idx1  = _pext_u64(0x0E0C0A0806040200, idx1);
    idx2 = (idx2 << 8) - idx2;
    idx2  = _pext_u64(0x0E0C0A0806040200, idx2);
    idx3 = (idx3 << 8) - idx3;
    idx3  = _pext_u64(0x0E0C0A0806040200, idx3);

    g0 = _mm256_castsi128_si256(_mm_cvtsi64_si128(idx0));
    g1 = _mm256_castsi128_si256(_mm_cvtsi64_si128(idx1));
    g0 = _mm256_inserti128_si256(g0, _mm_cvtsi64_si128(idx2), 1);
    g1 = _mm256_inserti128_si256(g1, _mm_cvtsi64_si128(idx3), 1);
#else
    g0 = _mm256_castsi128_si256(_mm_loadl_epi64((__m128i *)&idx[(good >>  0) & 0xFF]));
    g1 = _mm256_castsi128_si256(_mm_loadl_epi64((__m128i *)&idx[(good >>  8) & 0xFF]));
    g0 = _mm256_inserti128_si256(g0, _mm_loadl_epi64((__m128i *)&idx[(good >> 16) & 0xFF]), 1);
    g1 = _mm256_inserti128_si256(g1, _mm_loadl_epi64((__m128i *)&idx[(good >> 24) & 0xFF]), 1);
#endif

    g2 = _mm256_add_epi8(g0, ones);
    g3 = _mm256_add_epi8(g1, ones);
    g0 = _mm256_unpacklo_epi8(g0, g2);
    g1 = _mm256_unpacklo_epi8(g1, g3);

    f0 = _mm256_shuffle_epi8(f0, g0);
    f1 = _mm256_shuffle_epi8(f1, g1);

    _mm_storeu_si128((__m128i *)&r[ctr], _mm256_castsi256_si128(f0));
    ctr += _mm_popcnt_u32((good >>  0) & 0xFF);
    _mm_storeu_si128((__m128i *)&r[ctr], _mm256_extracti128_si256(f0, 1));
    ctr += _mm_popcnt_u32((good >> 16) & 0xFF);
    _mm_storeu_si128((__m128i *)&r[ctr], _mm256_castsi256_si128(f1));
    ctr += _mm_popcnt_u32((good >>  8) & 0xFF);
    _mm_storeu_si128((__m128i *)&r[ctr], _mm256_extracti128_si256(f1, 1));
    ctr += _mm_popcnt_u32((good >> 24) & 0xFF);
  }

  while(ctr <= KYBER_N - 8 && pos <= REJ_UNIFORM_AVX_BUFLEN - 16) {
    f = _mm_loadu_si128((__m128i *)&buf[pos]);
    f = _mm_shuffle_epi8(f, _mm256_castsi256_si128(idx8));
    t = _mm_srli_epi16(f, 4);
    f = _mm_blend_epi16(f, t, 0xAA);
    f = _mm_and_si128(f, _mm256_castsi256_si128(mask));
    pos += 12;

    t = _mm_cmpgt_epi16(_mm256_castsi256_si128(bound), f);
    good = _mm_movemask_epi8(t);

#ifdef BMI
    good &= 0x5555;
    idx0 = _pdep_u64(good, 0x1111111111111111);
    idx0 = (idx0 << 8) - idx0;
    idx0 = _pext_u64(0x0E0C0A0806040200, idx0);
    pilo = _mm_cvtsi64_si128(idx0);
#else
    good = _pext_u32(good, 0x5555);
    pilo = _mm_loadl_epi64((__m128i *)&idx[good]);
#endif

    pihi = _mm_add_epi8(pilo, _mm256_castsi256_si128(ones));
    pilo = _mm_unpacklo_epi8(pilo, pihi);
    f = _mm_shuffle_epi8(f, pilo);
    _mm_storeu_si128((__m128i *)&r[ctr], f);
    ctr += _mm_popcnt_u32(good);
  }

  while(ctr < KYBER_N && pos <= REJ_UNIFORM_AVX_BUFLEN - 3) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4));
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(val1 < KYBER_Q && ctr < KYBER_N)
      r[ctr++] = val1;
  }

  return ctr;
}

/*************** kyber/avx2/indcpa.c */
/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#if !defined(KYBER_K) || KYBER_K == 2
static
void gen_matrix_2(polyvec_2 *a, const uint8_t seed[32], int transposed)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 1;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 1;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[1].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[1].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[1].vec[0].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[1].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[0].vec[0]);
  poly_nttunpack(&a[0].vec[1]);
  poly_nttunpack(&a[1].vec[0]);
  poly_nttunpack(&a[1].vec[1]);
}
#endif

#if !defined(KYBER_K) || KYBER_K == 3
static
void gen_matrix_3(polyvec_3 *a, const uint8_t seed[32], int transposed)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;
  xof_state state1x;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 2;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 0;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 2;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 0;
    buf[3].coeffs[33] = 1;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[0].vec[2].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[1].vec[0].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[0].vec[2].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[0].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[0].vec[0]);
  poly_nttunpack(&a[0].vec[1]);
  poly_nttunpack(&a[0].vec[2]);
  poly_nttunpack(&a[1].vec[0]);

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 1;
    buf[0].coeffs[33] = 1;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 2;
    buf[2].coeffs[32] = 2;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 2;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 1;
    buf[0].coeffs[33] = 1;
    buf[1].coeffs[32] = 2;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 2;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 2;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[1].vec[1].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[1].vec[2].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[2].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[2].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[1].vec[1].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[1].vec[2].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[2].vec[0].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[2].vec[1].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[1].vec[1]);
  poly_nttunpack(&a[1].vec[2]);
  poly_nttunpack(&a[2].vec[0]);
  poly_nttunpack(&a[2].vec[1]);

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  xof_init(&state1x);
  xof_absorb(&state1x, buf[0].coeffs, 2, 2);
  xof_squeezeblocks(buf[0].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state1x);
  ctr0 = rej_uniform_avx(a[2].vec[2].coeffs, buf[0].coeffs);
  while(ctr0 < KYBER_N) {
    xof_squeezeblocks(buf[0].coeffs, 1, &state1x);
    ctr0 += rej_uniform(a[2].vec[2].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
  }
  xof_close (&state1x);

  poly_nttunpack(&a[2].vec[2]);
}
#endif

#if !defined(KYBER_K) || KYBER_K == 3
static
void gen_matrix_4(polyvec_4 *a, const uint8_t seed[32], int transposed)
{
  unsigned int i, ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  for(i=0;i<4;i++) {
    f = _mm256_loadu_si256((__m256i *)seed);
    _mm256_store_si256(buf[0].vec, f);
    _mm256_store_si256(buf[1].vec, f);
    _mm256_store_si256(buf[2].vec, f);
    _mm256_store_si256(buf[3].vec, f);

    if(transposed) {
      buf[0].coeffs[32] = i;
      buf[0].coeffs[33] = 0;
      buf[1].coeffs[32] = i;
      buf[1].coeffs[33] = 1;
      buf[2].coeffs[32] = i;
      buf[2].coeffs[33] = 2;
      buf[3].coeffs[32] = i;
      buf[3].coeffs[33] = 3;
    }
    else {
      buf[0].coeffs[32] = 0;
      buf[0].coeffs[33] = i;
      buf[1].coeffs[32] = 1;
      buf[1].coeffs[33] = i;
      buf[2].coeffs[32] = 2;
      buf[2].coeffs[33] = i;
      buf[3].coeffs[32] = 3;
      buf[3].coeffs[33] = i;
    }

    shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

    ctr0 = rej_uniform_avx(a[i].vec[0].coeffs, buf[0].coeffs);
    ctr1 = rej_uniform_avx(a[i].vec[1].coeffs, buf[1].coeffs);
    ctr2 = rej_uniform_avx(a[i].vec[2].coeffs, buf[2].coeffs);
    ctr3 = rej_uniform_avx(a[i].vec[3].coeffs, buf[3].coeffs);

    while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
      shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

      ctr0 += rej_uniform(a[i].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
      ctr1 += rej_uniform(a[i].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
      ctr2 += rej_uniform(a[i].vec[2].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
      ctr3 += rej_uniform(a[i].vec[3].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
    }

    poly_nttunpack(&a[i].vec[0]);
    poly_nttunpack(&a[i].vec[1]);
    poly_nttunpack(&a[i].vec[2]);
    poly_nttunpack(&a[i].vec[3]);
  }
}
#endif

/*************** kyber/avx2/consts.h */
asm (""
".equ _16XQ,            0\n"
".equ _16XQINV,        16\n"
".equ _16XV,           32\n"
".equ _16XFLO,         48\n"
".equ _16XFHI,         64\n"
".equ _16XMONTSQLO,    80\n"
".equ _16XMONTSQHI,    96\n"
".equ _16XMASK,       112\n"
".equ _REVIDXB,       128\n"
".equ _REVIDXD,       144\n"
".equ _ZETAS_EXP,     160\n"
".equ	_16XSHIFT,     624\n"
);

/*************** kyber/avx2/shuffle.inc */
asm (""
".macro shuffle8 r0,r1,r2,r3\n"
"vperm2i128	$0x20,%ymm\\r1,%ymm\\r0,%ymm\\r2\n"
"vperm2i128	$0x31,%ymm\\r1,%ymm\\r0,%ymm\\r3\n"
".endm\n"
"\n"
".macro shuffle4 r0,r1,r2,r3\n"
"vpunpcklqdq	%ymm\\r1,%ymm\\r0,%ymm\\r2\n"
"vpunpckhqdq	%ymm\\r1,%ymm\\r0,%ymm\\r3\n"
".endm\n"
"\n"
".macro shuffle2 r0,r1,r2,r3\n"
"#vpsllq		$32,%ymm\\r1,%ymm\\r2\n"
"vmovsldup	%ymm\\r1,%ymm\\r2\n"
"vpblendd	$0xAA,%ymm\\r2,%ymm\\r0,%ymm\\r2\n"
"vpsrlq		$32,%ymm\\r0,%ymm\\r0\n"
"#vmovshdup	%ymm\\r0,%ymm\\r0\n"
"vpblendd	$0xAA,%ymm\\r1,%ymm\\r0,%ymm\\r3\n"
".endm\n"
"\n"
".macro shuffle1 r0,r1,r2,r3\n"
"vpslld		$16,%ymm\\r1,%ymm\\r2\n"
"vpblendw	$0xAA,%ymm\\r2,%ymm\\r0,%ymm\\r2\n"
"vpsrld		$16,%ymm\\r0,%ymm\\r0\n"
"vpblendw	$0xAA,%ymm\\r1,%ymm\\r0,%ymm\\r3\n"
".endm\n"
);

/*************** kyber/avx2/ntt.S */
asm (""
".macro mul rh0,rh1,rh2,rh3,zl0=15,zl1=15,zh0=2,zh1=2\n"
"vpmullw		%ymm\\zl0,%ymm\\rh0,%ymm12\n"
"vpmullw		%ymm\\zl0,%ymm\\rh1,%ymm13\n"
"\n"
"vpmullw		%ymm\\zl1,%ymm\\rh2,%ymm14\n"
"vpmullw		%ymm\\zl1,%ymm\\rh3,%ymm15\n"
"\n"
"vpmulhw		%ymm\\zh0,%ymm\\rh0,%ymm\\rh0\n"
"vpmulhw		%ymm\\zh0,%ymm\\rh1,%ymm\\rh1\n"
"\n"
"vpmulhw		%ymm\\zh1,%ymm\\rh2,%ymm\\rh2\n"
"vpmulhw		%ymm\\zh1,%ymm\\rh3,%ymm\\rh3\n"
".endm\n"
"\n"
".macro reduce\n"
"vpmulhw		%ymm0,%ymm12,%ymm12\n"
"vpmulhw		%ymm0,%ymm13,%ymm13\n"
"\n"
"vpmulhw		%ymm0,%ymm14,%ymm14\n"
"vpmulhw		%ymm0,%ymm15,%ymm15\n"
".endm\n"
"\n"
".macro update rln,rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3\n"
"vpaddw		%ymm\\rh0,%ymm\\rl0,%ymm\\rln\n"
"vpsubw		%ymm\\rh0,%ymm\\rl0,%ymm\\rh0\n"
"vpaddw		%ymm\\rh1,%ymm\\rl1,%ymm\\rl0\n"
"\n"
"vpsubw		%ymm\\rh1,%ymm\\rl1,%ymm\\rh1\n"
"vpaddw		%ymm\\rh2,%ymm\\rl2,%ymm\\rl1\n"
"vpsubw		%ymm\\rh2,%ymm\\rl2,%ymm\\rh2\n"
"\n"
"vpaddw		%ymm\\rh3,%ymm\\rl3,%ymm\\rl2\n"
"vpsubw		%ymm\\rh3,%ymm\\rl3,%ymm\\rh3\n"
"\n"
"vpsubw		%ymm12,%ymm\\rln,%ymm\\rln\n"
"vpaddw		%ymm12,%ymm\\rh0,%ymm\\rh0\n"
"vpsubw		%ymm13,%ymm\\rl0,%ymm\\rl0\n"
"\n"
"vpaddw		%ymm13,%ymm\\rh1,%ymm\\rh1\n"
"vpsubw		%ymm14,%ymm\\rl1,%ymm\\rl1\n"
"vpaddw		%ymm14,%ymm\\rh2,%ymm\\rh2\n"
"\n"
"vpsubw		%ymm15,%ymm\\rl2,%ymm\\rl2\n"
"vpaddw		%ymm15,%ymm\\rh3,%ymm\\rh3\n"
".endm\n"
"\n"
".macro level0 off\n"
"vpbroadcastq	(_ZETAS_EXP+0)*2(%rsi),%ymm15\n"
"vmovdqa		(64*\\off+128)*2(%rdi),%ymm8\n"
"vmovdqa		(64*\\off+144)*2(%rdi),%ymm9\n"
"vmovdqa		(64*\\off+160)*2(%rdi),%ymm10\n"
"vmovdqa		(64*\\off+176)*2(%rdi),%ymm11\n"
"vpbroadcastq	(_ZETAS_EXP+4)*2(%rsi),%ymm2\n"
"\n"
"mul		8,9,10,11\n"
"\n"
"vmovdqa		(64*\\off+  0)*2(%rdi),%ymm4\n"
"vmovdqa		(64*\\off+ 16)*2(%rdi),%ymm5\n"
"vmovdqa		(64*\\off+ 32)*2(%rdi),%ymm6\n"
"vmovdqa		(64*\\off+ 48)*2(%rdi),%ymm7\n"
"\n"
"reduce\n"
"update		3,4,5,6,7,8,9,10,11\n"
"\n"
"vmovdqa		%ymm3,(64*\\off+  0)*2(%rdi)\n"
"vmovdqa		%ymm4,(64*\\off+ 16)*2(%rdi)\n"
"vmovdqa		%ymm5,(64*\\off+ 32)*2(%rdi)\n"
"vmovdqa		%ymm6,(64*\\off+ 48)*2(%rdi)\n"
"vmovdqa		%ymm8,(64*\\off+128)*2(%rdi)\n"
"vmovdqa		%ymm9,(64*\\off+144)*2(%rdi)\n"
"vmovdqa		%ymm10,(64*\\off+160)*2(%rdi)\n"
"vmovdqa		%ymm11,(64*\\off+176)*2(%rdi)\n"
".endm\n"
"\n"
".macro levels1t6 off\n"
/* level 1 */
"vmovdqa		(_ZETAS_EXP+224*\\off+16)*2(%rsi),%ymm15\n"
"vmovdqa		(128*\\off+ 64)*2(%rdi),%ymm8\n"
"vmovdqa		(128*\\off+ 80)*2(%rdi),%ymm9\n"
"vmovdqa		(128*\\off+ 96)*2(%rdi),%ymm10\n"
"vmovdqa		(128*\\off+112)*2(%rdi),%ymm11\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+32)*2(%rsi),%ymm2\n"
"\n"
"mul		8,9,10,11\n"
"\n"
"vmovdqa		(128*\\off+  0)*2(%rdi),%ymm4\n"
"vmovdqa	 	(128*\\off+ 16)*2(%rdi),%ymm5\n"
"vmovdqa		(128*\\off+ 32)*2(%rdi),%ymm6\n"
"vmovdqa		(128*\\off+ 48)*2(%rdi),%ymm7\n"
"\n"
"reduce\n"
"update		3,4,5,6,7,8,9,10,11\n"
"\n"
/* level 2 */
"shuffle8	5,10,7,10\n"
"shuffle8	6,11,5,11\n"
"\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+48)*2(%rsi),%ymm15\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+64)*2(%rsi),%ymm2\n"
"\n"
"mul		7,10,5,11\n"
"\n"
"shuffle8	3,8,6,8\n"
"shuffle8	4,9,3,9\n"
"\n"
"reduce\n"
"update		4,6,8,3,9,7,10,5,11\n"
"\n"
/* level 3 */
"shuffle4	8,5,9,5\n"
"shuffle4	3,11,8,11\n"
"\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+80)*2(%rsi),%ymm15\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+96)*2(%rsi),%ymm2\n"
"\n"
"mul		9,5,8,11\n"
"\n"
"shuffle4	4,7,3,7\n"
"shuffle4	6,10,4,10\n"
"\n"
"reduce\n"
"update		6,3,7,4,10,9,5,8,11\n"
"\n"
/* level 4 */
"shuffle2	7,8,10,8\n"
"shuffle2	4,11,7,11\n"
"\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+112)*2(%rsi),%ymm15\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+128)*2(%rsi),%ymm2\n"
"\n"
"mul		10,8,7,11\n"
"\n"
"shuffle2	6,9,4,9\n"
"shuffle2	3,5,6,5\n"
"\n"
"reduce\n"
"update		3,4,9,6,5,10,8,7,11\n"
"\n"
/* level 5 */
"shuffle1	9,7,5,7\n"
"shuffle1	6,11,9,11\n"
"\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+144)*2(%rsi),%ymm15\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+160)*2(%rsi),%ymm2\n"
"\n"
"mul		5,7,9,11\n"
"\n"
"shuffle1	3,10,6,10\n"
"shuffle1	4,8,3,8\n"
"\n"
"reduce\n"
"update		4,6,10,3,8,5,7,9,11\n"
"\n"
/* level 6 */
"vmovdqa		(_ZETAS_EXP+224*\\off+176)*2(%rsi),%ymm14\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+208)*2(%rsi),%ymm15\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+192)*2(%rsi),%ymm8\n"
"vmovdqa		(_ZETAS_EXP+224*\\off+224)*2(%rsi),%ymm2\n"
"\n"
"mul		10,3,9,11,14,15,8,2\n"
"\n"
"reduce\n"
"update		8,4,6,5,7,10,3,9,11\n"
"\n"
"vmovdqa		%ymm8,(128*\\off+  0)*2(%rdi)\n"
"vmovdqa		%ymm4,(128*\\off+ 16)*2(%rdi)\n"
"vmovdqa		%ymm10,(128*\\off+ 32)*2(%rdi)\n"
"vmovdqa		%ymm3,(128*\\off+ 48)*2(%rdi)\n"
"vmovdqa		%ymm6,(128*\\off+ 64)*2(%rdi)\n"
"vmovdqa		%ymm5,(128*\\off+ 80)*2(%rdi)\n"
"vmovdqa		%ymm9,(128*\\off+ 96)*2(%rdi)\n"
"vmovdqa		%ymm11,(128*\\off+112)*2(%rdi)\n"
".endm\n"
"\n"
".text\n"
"ntt_avx:\n"
"vmovdqa		_16XQ*2(%rsi),%ymm0\n"
"\n"
"level0		0\n"
"level0		1\n"
"\n"
"levels1t6	0\n"
"levels1t6	1\n"
"\n"
"ret\n"
);

/*************** kyber/avx2/fq.inc */
asm (""
".macro red16 r,rs=0,x=12\n"
"vpmulhw         %ymm1,%ymm\\r,%ymm\\x\n"
".if \\rs\n"
"vpmulhrsw	%ymm\\rs,%ymm\\x,%ymm\\x\n"
".else\n"
"vpsraw          $10,%ymm\\x,%ymm\\x\n"
".endif\n"
"vpmullw         %ymm0,%ymm\\x,%ymm\\x\n"
"vpsubw          %ymm\\x,%ymm\\r,%ymm\\r\n"
".endm\n"
"\n"
".macro csubq r,x=12\n"
"vpsubw		%ymm0,%ymm\\r,%ymm\\r\n"
"vpsraw		$15,%ymm\\r,%ymm\\x\n"
"vpand		%ymm0,%ymm\\x,%ymm\\x\n"
"vpaddw		%ymm\\x,%ymm\\r,%ymm\\r\n"
".endm\n"
"\n"
".macro caddq r,x=12\n"
"vpsraw		$15,%ymm\\r,%ymm\\x\n"
"vpand		%ymm0,%ymm\\x,%ymm\\x\n"
"vpaddw		%ymm\\x,%ymm\\r,%ymm\\r\n"
".endm\n"
"\n"
".macro fqmulprecomp al,ah,b,x=12\n"
"vpmullw		%ymm\\al,%ymm\\b,%ymm\\x\n"
"vpmulhw		%ymm\\ah,%ymm\\b,%ymm\\b\n"
"vpmulhw		%ymm0,%ymm\\x,%ymm\\x\n"
"vpsubw		%ymm\\x,%ymm\\b,%ymm\\b\n"
".endm\n"
);

/*************** kyber/avx2/fq.S */
asm (""
".text\n"
"reduce128_avx:\n"
"#load\n"
"vmovdqa		(%rdi),%ymm2\n"
"vmovdqa		32(%rdi),%ymm3\n"
"vmovdqa		64(%rdi),%ymm4\n"
"vmovdqa		96(%rdi),%ymm5\n"
"vmovdqa		128(%rdi),%ymm6\n"
"vmovdqa		160(%rdi),%ymm7\n"
"vmovdqa		192(%rdi),%ymm8\n"
"vmovdqa		224(%rdi),%ymm9\n"
"\n"
"red16		2\n"
"red16		3\n"
"red16		4\n"
"red16		5\n"
"red16		6\n"
"red16		7\n"
"red16		8\n"
"red16		9\n"
"\n"
"#store\n"
"vmovdqa		%ymm2,(%rdi)\n"
"vmovdqa		%ymm3,32(%rdi)\n"
"vmovdqa		%ymm4,64(%rdi)\n"
"vmovdqa		%ymm5,96(%rdi)\n"
"vmovdqa		%ymm6,128(%rdi)\n"
"vmovdqa		%ymm7,160(%rdi)\n"
"vmovdqa		%ymm8,192(%rdi)\n"
"vmovdqa		%ymm9,224(%rdi)\n"
"\n"
"ret\n"
"\n"
"reduce_avx:\n"
"#consts\n"
"vmovdqa		_16XQ*2(%rsi),%ymm0\n"
"vmovdqa		_16XV*2(%rsi),%ymm1\n"
"call		reduce128_avx\n"
"add		$256,%rdi\n"
"call		reduce128_avx\n"
"ret\n"
"\n"
"tomont128_avx:\n"
"#load\n"
"vmovdqa		(%rdi),%ymm3\n"
"vmovdqa		32(%rdi),%ymm4\n"
"vmovdqa		64(%rdi),%ymm5\n"
"vmovdqa		96(%rdi),%ymm6\n"
"vmovdqa		128(%rdi),%ymm7\n"
"vmovdqa		160(%rdi),%ymm8\n"
"vmovdqa		192(%rdi),%ymm9\n"
"vmovdqa		224(%rdi),%ymm10\n"
"\n"
"fqmulprecomp	1,2,3,11\n"
"fqmulprecomp	1,2,4,12\n"
"fqmulprecomp	1,2,5,13\n"
"fqmulprecomp	1,2,6,14\n"
"fqmulprecomp	1,2,7,15\n"
"fqmulprecomp	1,2,8,11\n"
"fqmulprecomp	1,2,9,12\n"
"fqmulprecomp	1,2,10,13\n"
"\n"
"#store\n"
"vmovdqa		%ymm3,(%rdi)\n"
"vmovdqa		%ymm4,32(%rdi)\n"
"vmovdqa		%ymm5,64(%rdi)\n"
"vmovdqa		%ymm6,96(%rdi)\n"
"vmovdqa		%ymm7,128(%rdi)\n"
"vmovdqa		%ymm8,160(%rdi)\n"
"vmovdqa		%ymm9,192(%rdi)\n"
"vmovdqa		%ymm10,224(%rdi)\n"
"\n"
"ret\n"
"\n"
"tomont_avx:\n"
"#consts\n"
"vmovdqa		_16XQ*2(%rsi),%ymm0\n"
"vmovdqa		_16XMONTSQLO*2(%rsi),%ymm1\n"
"vmovdqa		_16XMONTSQHI*2(%rsi),%ymm2\n"
"call		tomont128_avx\n"
"add		$256,%rdi\n"
"call		tomont128_avx\n"
"ret\n"
);

/*************** kyber/avx2/invntt.S */
asm (""
".macro butterfly rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3,zl0=2,zl1=2,zh0=3,zh1=3\n"
"vpsubw		%ymm\\rl0,%ymm\\rh0,%ymm12\n"
"vpaddw		%ymm\\rh0,%ymm\\rl0,%ymm\\rl0\n"
"vpsubw		%ymm\\rl1,%ymm\\rh1,%ymm13\n"
"\n"
"vpmullw		%ymm\\zl0,%ymm12,%ymm\\rh0\n"
"vpaddw		%ymm\\rh1,%ymm\\rl1,%ymm\\rl1\n"
"vpsubw		%ymm\\rl2,%ymm\\rh2,%ymm14\n"
"\n"
"vpmullw		%ymm\\zl0,%ymm13,%ymm\\rh1\n"
"vpaddw		%ymm\\rh2,%ymm\\rl2,%ymm\\rl2\n"
"vpsubw		%ymm\\rl3,%ymm\\rh3,%ymm15\n"
"\n"
"vpmullw		%ymm\\zl1,%ymm14,%ymm\\rh2\n"
"vpaddw		%ymm\\rh3,%ymm\\rl3,%ymm\\rl3\n"
"vpmullw		%ymm\\zl1,%ymm15,%ymm\\rh3\n"
"\n"
"vpmulhw		%ymm\\zh0,%ymm12,%ymm12\n"
"vpmulhw		%ymm\\zh0,%ymm13,%ymm13\n"
"\n"
"vpmulhw		%ymm\\zh1,%ymm14,%ymm14\n"
"vpmulhw		%ymm\\zh1,%ymm15,%ymm15\n"
"\n"
"vpmulhw		%ymm0,%ymm\\rh0,%ymm\\rh0\n"
"\n"
"vpmulhw		%ymm0,%ymm\\rh1,%ymm\\rh1\n"
"\n"
"vpmulhw		%ymm0,%ymm\\rh2,%ymm\\rh2\n"
"vpmulhw		%ymm0,%ymm\\rh3,%ymm\\rh3\n"
"\n"
"#\n"
"\n"
"#\n"
"\n"
"vpsubw		%ymm\\rh0,%ymm12,%ymm\\rh0\n"
"\n"
"vpsubw		%ymm\\rh1,%ymm13,%ymm\\rh1\n"
"\n"
"vpsubw		%ymm\\rh2,%ymm14,%ymm\\rh2\n"
"vpsubw		%ymm\\rh3,%ymm15,%ymm\\rh3\n"
".endm\n"
"\n"
".macro intt_levels0t5 off\n"
/* level 0 */
"vmovdqa		_16XFLO*2(%rsi),%ymm2\n"
"vmovdqa		_16XFHI*2(%rsi),%ymm3\n"
"\n"
"vmovdqa         (128*\\off+  0)*2(%rdi),%ymm4\n"
"vmovdqa         (128*\\off+ 32)*2(%rdi),%ymm6\n"
"vmovdqa         (128*\\off+ 16)*2(%rdi),%ymm5\n"
"vmovdqa         (128*\\off+ 48)*2(%rdi),%ymm7\n"
"\n"
"fqmulprecomp	2,3,4\n"
"fqmulprecomp	2,3,6\n"
"fqmulprecomp	2,3,5\n"
"fqmulprecomp	2,3,7\n"
"\n"
"vmovdqa         (128*\\off+ 64)*2(%rdi),%ymm8\n"
"vmovdqa         (128*\\off+ 96)*2(%rdi),%ymm10\n"
"vmovdqa         (128*\\off+ 80)*2(%rdi),%ymm9\n"
"vmovdqa         (128*\\off+112)*2(%rdi),%ymm11\n"
"\n"
"fqmulprecomp	2,3,8\n"
"fqmulprecomp	2,3,10\n"
"fqmulprecomp	2,3,9\n"
"fqmulprecomp	2,3,11\n"
"\n"
"vpermq		$0x4E,(_ZETAS_EXP+(1-\\off)*224+208)*2(%rsi),%ymm15\n"
"vpermq		$0x4E,(_ZETAS_EXP+(1-\\off)*224+176)*2(%rsi),%ymm1\n"
"vpermq		$0x4E,(_ZETAS_EXP+(1-\\off)*224+224)*2(%rsi),%ymm2\n"
"vpermq		$0x4E,(_ZETAS_EXP+(1-\\off)*224+192)*2(%rsi),%ymm3\n"
"vmovdqa		_REVIDXB*2(%rsi),%ymm12\n"
"vpshufb		%ymm12,%ymm15,%ymm15\n"
"vpshufb		%ymm12,%ymm1,%ymm1\n"
"vpshufb		%ymm12,%ymm2,%ymm2\n"
"vpshufb		%ymm12,%ymm3,%ymm3\n"
"\n"
"butterfly	4,5,8,9,6,7,10,11,15,1,2,3\n"
"\n"
/* level 1 */
"vpermq		$0x4E,(_ZETAS_EXP+(1-\\off)*224+144)*2(%rsi),%ymm2\n"
"vpermq		$0x4E,(_ZETAS_EXP+(1-\\off)*224+160)*2(%rsi),%ymm3\n"
"vmovdqa		_REVIDXB*2(%rsi),%ymm1\n"
"vpshufb		%ymm1,%ymm2,%ymm2\n"
"vpshufb		%ymm1,%ymm3,%ymm3\n"
"\n"
"butterfly	4,5,6,7,8,9,10,11,2,2,3,3\n"
"\n"
"shuffle1	4,5,3,5\n"
"shuffle1	6,7,4,7\n"
"shuffle1	8,9,6,9\n"
"shuffle1	10,11,8,11\n"
"\n"
/* level 2 */
"vmovdqa		_REVIDXD*2(%rsi),%ymm12\n"
"vpermd		(_ZETAS_EXP+(1-\\off)*224+112)*2(%rsi),%ymm12,%ymm2\n"
"vpermd		(_ZETAS_EXP+(1-\\off)*224+128)*2(%rsi),%ymm12,%ymm10\n"
"\n"
"butterfly	3,4,6,8,5,7,9,11,2,2,10,10\n"
"\n"
"vmovdqa		_16XV*2(%rsi),%ymm1\n"
"red16		3\n"
"\n"
"shuffle2	3,4,10,4\n"
"shuffle2	6,8,3,8\n"
"shuffle2	5,7,6,7\n"
"shuffle2	9,11,5,11\n"
"\n"
/* level 3 */
"vpermq		$0x1B,(_ZETAS_EXP+(1-\\off)*224+80)*2(%rsi),%ymm2\n"
"vpermq		$0x1B,(_ZETAS_EXP+(1-\\off)*224+96)*2(%rsi),%ymm9\n"
"\n"
"butterfly	10,3,6,5,4,8,7,11,2,2,9,9\n"
"\n"
"shuffle4	10,3,9,3\n"
"shuffle4	6,5,10,5\n"
"shuffle4	4,8,6,8\n"
"shuffle4	7,11,4,11\n"
"\n"
/* level 4 */
"vpermq		$0x4E,(_ZETAS_EXP+(1-\\off)*224+48)*2(%rsi),%ymm2\n"
"vpermq		$0x4E,(_ZETAS_EXP+(1-\\off)*224+64)*2(%rsi),%ymm7\n"
"\n"
"butterfly	9,10,6,4,3,5,8,11,2,2,7,7\n"
"\n"
"red16		9\n"
"\n"
"shuffle8	9,10,7,10\n"
"shuffle8	6,4,9,4\n"
"shuffle8	3,5,6,5\n"
"shuffle8	8,11,3,11\n"
"\n"
/* level 5 */
"vmovdqa		(_ZETAS_EXP+(1-\\off)*224+16)*2(%rsi),%ymm2\n"
"vmovdqa		(_ZETAS_EXP+(1-\\off)*224+32)*2(%rsi),%ymm8\n"
"\n"
"butterfly	7,9,6,3,10,4,5,11,2,2,8,8\n"
"\n"
"vmovdqa         %ymm7,(128*\\off+  0)*2(%rdi)\n"
"vmovdqa         %ymm9,(128*\\off+ 16)*2(%rdi)\n"
"vmovdqa         %ymm6,(128*\\off+ 32)*2(%rdi)\n"
"vmovdqa         %ymm3,(128*\\off+ 48)*2(%rdi)\n"
"vmovdqa         %ymm10,(128*\\off+ 64)*2(%rdi)\n"
"vmovdqa         %ymm4,(128*\\off+ 80)*2(%rdi)\n"
"vmovdqa         %ymm5,(128*\\off+ 96)*2(%rdi)\n"
"vmovdqa         %ymm11,(128*\\off+112)*2(%rdi)\n"
".endm\n"
"\n"
".macro intt_level6 off\n"
/* level 6 */
"vmovdqa         (64*\\off+  0)*2(%rdi),%ymm4\n"
"vmovdqa         (64*\\off+128)*2(%rdi),%ymm8\n"
"vmovdqa         (64*\\off+ 16)*2(%rdi),%ymm5\n"
"vmovdqa         (64*\\off+144)*2(%rdi),%ymm9\n"
"vpbroadcastq	(_ZETAS_EXP+0)*2(%rsi),%ymm2\n"
"\n"
"vmovdqa         (64*\\off+ 32)*2(%rdi),%ymm6\n"
"vmovdqa         (64*\\off+160)*2(%rdi),%ymm10\n"
"vmovdqa         (64*\\off+ 48)*2(%rdi),%ymm7\n"
"vmovdqa         (64*\\off+176)*2(%rdi),%ymm11\n"
"vpbroadcastq	(_ZETAS_EXP+4)*2(%rsi),%ymm3\n"
"\n"
"butterfly	4,5,6,7,8,9,10,11\n"
"\n"
".if \\off == 0\n"
"red16		4\n"
".endif\n"
"\n"
"vmovdqa		%ymm4,(64*\\off+  0)*2(%rdi)\n"
"vmovdqa		%ymm5,(64*\\off+ 16)*2(%rdi)\n"
"vmovdqa		%ymm6,(64*\\off+ 32)*2(%rdi)\n"
"vmovdqa		%ymm7,(64*\\off+ 48)*2(%rdi)\n"
"vmovdqa		%ymm8,(64*\\off+128)*2(%rdi)\n"
"vmovdqa		%ymm9,(64*\\off+144)*2(%rdi)\n"
"vmovdqa		%ymm10,(64*\\off+160)*2(%rdi)\n"
"vmovdqa		%ymm11,(64*\\off+176)*2(%rdi)\n"
".endm\n"
"\n"
".text\n"
"invntt_avx:\n"
"vmovdqa         _16XQ*2(%rsi),%ymm0\n"
"\n"
"intt_levels0t5	0\n"
"intt_levels0t5	1\n"
"\n"
"intt_level6	0\n"
"intt_level6	1\n"
"ret\n"
);

/*************** kyber/avx2/shuffle.S */
asm (""
".text\n"
"nttunpack128_avx:\n"
"#load\n"
"vmovdqa		(%rdi),%ymm4\n"
"vmovdqa		32(%rdi),%ymm5\n"
"vmovdqa		64(%rdi),%ymm6\n"
"vmovdqa		96(%rdi),%ymm7\n"
"vmovdqa		128(%rdi),%ymm8\n"
"vmovdqa		160(%rdi),%ymm9\n"
"vmovdqa		192(%rdi),%ymm10\n"
"vmovdqa		224(%rdi),%ymm11\n"
"\n"
"shuffle8	4,8,3,8\n"
"shuffle8	5,9,4,9\n"
"shuffle8	6,10,5,10\n"
"shuffle8	7,11,6,11\n"
"\n"
"shuffle4	3,5,7,5\n"
"shuffle4	8,10,3,10\n"
"shuffle4	4,6,8,6\n"
"shuffle4	9,11,4,11\n"
"\n"
"shuffle2	7,8,9,8\n"
"shuffle2	5,6,7,6\n"
"shuffle2	3,4,5,4\n"
"shuffle2	10,11,3,11\n"
"\n"
"shuffle1	9,5,10,5\n"
"shuffle1	8,4,9,4\n"
"shuffle1	7,3,8,3\n"
"shuffle1	6,11,7,11\n"
"\n"
"#store\n"
"vmovdqa		%ymm10,(%rdi)\n"
"vmovdqa		%ymm5,32(%rdi)\n"
"vmovdqa		%ymm9,64(%rdi)\n"
"vmovdqa		%ymm4,96(%rdi)\n"
"vmovdqa		%ymm8,128(%rdi)\n"
"vmovdqa		%ymm3,160(%rdi)\n"
"vmovdqa		%ymm7,192(%rdi)\n"
"vmovdqa		%ymm11,224(%rdi)\n"
"\n"
"ret\n"
"\n"
"nttunpack_avx:\n"
"call		nttunpack128_avx\n"
"add		$256,%rdi\n"
"call		nttunpack128_avx\n"
"ret\n"
"\n"
"ntttobytes128_avx:\n"
"#load\n"
"vmovdqa		(%rsi),%ymm5\n"
"vmovdqa		32(%rsi),%ymm6\n"
"vmovdqa		64(%rsi),%ymm7\n"
"vmovdqa		96(%rsi),%ymm8\n"
"vmovdqa		128(%rsi),%ymm9\n"
"vmovdqa		160(%rsi),%ymm10\n"
"vmovdqa		192(%rsi),%ymm11\n"
"vmovdqa		224(%rsi),%ymm12\n"
"\n"
"#csubq\n"
"csubq		5,13\n"
"csubq		6,13\n"
"csubq		7,13\n"
"csubq		8,13\n"
"csubq		9,13\n"
"csubq		10,13\n"
"csubq		11,13\n"
"csubq		12,13\n"
"\n"
"#bitpack\n"
"vpsllw		$12,%ymm6,%ymm4\n"
"vpor		%ymm4,%ymm5,%ymm4\n"
"\n"
"vpsrlw		$4,%ymm6,%ymm5\n"
"vpsllw		$8,%ymm7,%ymm6\n"
"vpor		%ymm5,%ymm6,%ymm5\n"
"\n"
"vpsrlw		$8,%ymm7,%ymm6\n"
"vpsllw		$4,%ymm8,%ymm7\n"
"vpor		%ymm6,%ymm7,%ymm6\n"
"\n"
"vpsllw		$12,%ymm10,%ymm7\n"
"vpor		%ymm7,%ymm9,%ymm7\n"
"\n"
"vpsrlw		$4,%ymm10,%ymm8\n"
"vpsllw		$8,%ymm11,%ymm9\n"
"vpor		%ymm8,%ymm9,%ymm8\n"
"\n"
"vpsrlw		$8,%ymm11,%ymm9\n"
"vpsllw		$4,%ymm12,%ymm10\n"
"vpor		%ymm9,%ymm10,%ymm9\n"
"\n"
"shuffle1	4,5,3,5\n"
"shuffle1	6,7,4,7\n"
"shuffle1	8,9,6,9\n"
"\n"
"shuffle2	3,4,8,4\n"
"shuffle2	6,5,3,5\n"
"shuffle2	7,9,6,9\n"
"\n"
"shuffle4	8,3,7,3\n"
"shuffle4	6,4,8,4\n"
"shuffle4	5,9,6,9\n"
"\n"
"shuffle8	7,8,5,8\n"
"shuffle8	6,3,7,3\n"
"shuffle8	4,9,6,9\n"
"\n"
"#store\n"
"vmovdqu		%ymm5,(%rdi)\n"
"vmovdqu		%ymm7,32(%rdi)\n"
"vmovdqu		%ymm6,64(%rdi)\n"
"vmovdqu		%ymm8,96(%rdi)\n"
"vmovdqu		%ymm3,128(%rdi)\n"
"vmovdqu		%ymm9,160(%rdi)\n"
"\n"
"ret\n"
"\n"
"ntttobytes_avx:\n"
"#consts\n"
"vmovdqa		_16XQ*2(%rdx),%ymm0\n"
"call		ntttobytes128_avx\n"
"add		$256,%rsi\n"
"add		$192,%rdi\n"
"call		ntttobytes128_avx\n"
"ret\n"
"\n"
"nttfrombytes128_avx:\n"
"#load\n"
"vmovdqu		(%rsi),%ymm4\n"
"vmovdqu		32(%rsi),%ymm5\n"
"vmovdqu		64(%rsi),%ymm6\n"
"vmovdqu		96(%rsi),%ymm7\n"
"vmovdqu		128(%rsi),%ymm8\n"
"vmovdqu		160(%rsi),%ymm9\n"
"\n"
"shuffle8	4,7,3,7\n"
"shuffle8	5,8,4,8\n"
"shuffle8	6,9,5,9\n"
"\n"
"shuffle4	3,8,6,8\n"
"shuffle4	7,5,3,5\n"
"shuffle4	4,9,7,9\n"
"\n"
"shuffle2	6,5,4,5\n"
"shuffle2	8,7,6,7\n"
"shuffle2	3,9,8,9\n"
"\n"
"shuffle1	4,7,10,7\n"
"shuffle1	5,8,4,8\n"
"shuffle1	6,9,5,9\n"
"\n"
"#bitunpack\n"
"vpsrlw		$12,%ymm10,%ymm11\n"
"vpsllw		$4,%ymm7,%ymm12\n"
"vpor		%ymm11,%ymm12,%ymm11\n"
"vpand		%ymm0,%ymm10,%ymm10\n"
"vpand		%ymm0,%ymm11,%ymm11\n"
"\n"
"vpsrlw		$8,%ymm7,%ymm12\n"
"vpsllw		$8,%ymm4,%ymm13\n"
"vpor		%ymm12,%ymm13,%ymm12\n"
"vpand		%ymm0,%ymm12,%ymm12\n"
"\n"
"vpsrlw		$4,%ymm4,%ymm13\n"
"vpand		%ymm0,%ymm13,%ymm13\n"
"\n"
"vpsrlw		$12,%ymm8,%ymm14\n"
"vpsllw		$4,%ymm5,%ymm15\n"
"vpor		%ymm14,%ymm15,%ymm14\n"
"vpand		%ymm0,%ymm8,%ymm8\n"
"vpand		%ymm0,%ymm14,%ymm14\n"
"\n"
"vpsrlw		$8,%ymm5,%ymm15\n"
"vpsllw		$8,%ymm9,%ymm1\n"
"vpor		%ymm15,%ymm1,%ymm15\n"
"vpand		%ymm0,%ymm15,%ymm15\n"
"\n"
"vpsrlw		$4,%ymm9,%ymm1\n"
"vpand		%ymm0,%ymm1,%ymm1\n"
"\n"
"#store\n"
"vmovdqa		%ymm10,(%rdi)\n"
"vmovdqa		%ymm11,32(%rdi)\n"
"vmovdqa		%ymm12,64(%rdi)\n"
"vmovdqa		%ymm13,96(%rdi)\n"
"vmovdqa		%ymm8,128(%rdi)\n"
"vmovdqa		%ymm14,160(%rdi)\n"
"vmovdqa		%ymm15,192(%rdi)\n"
"vmovdqa		%ymm1,224(%rdi)\n"
"\n"
"ret\n"
"\n"
"nttfrombytes_avx:\n"
"#consts\n"
"vmovdqa		_16XMASK*2(%rdx),%ymm0\n"
"call		nttfrombytes128_avx\n"
"add		$256,%rdi\n"
"add		$192,%rsi\n"
"call		nttfrombytes128_avx\n"
"ret\n"
);

/*************** kyber/avx2/basemul.S */
asm (""
".macro schoolbook off\n"
"vmovdqa		_16XQINV*2(%rcx),%ymm0\n"
"vmovdqa		(64*\\off+ 0)*2(%rsi),%ymm1		# a0\n"
"vmovdqa		(64*\\off+16)*2(%rsi),%ymm2		# b0\n"
"vmovdqa		(64*\\off+32)*2(%rsi),%ymm3		# a1\n"
"vmovdqa		(64*\\off+48)*2(%rsi),%ymm4		# b1\n"
"\n"
"vpmullw		%ymm0,%ymm1,%ymm9			# a0.lo\n"
"vpmullw		%ymm0,%ymm2,%ymm10			# b0.lo\n"
"vpmullw		%ymm0,%ymm3,%ymm11			# a1.lo\n"
"vpmullw		%ymm0,%ymm4,%ymm12			# b1.lo\n"
"\n"
"vmovdqa		(64*\\off+ 0)*2(%rdx),%ymm5		# c0\n"
"vmovdqa		(64*\\off+16)*2(%rdx),%ymm6		# d0\n"
"\n"
"vpmulhw		%ymm5,%ymm1,%ymm13			# a0c0.hi\n"
"vpmulhw		%ymm6,%ymm1,%ymm1			# a0d0.hi\n"
"vpmulhw		%ymm5,%ymm2,%ymm14			# b0c0.hi\n"
"vpmulhw		%ymm6,%ymm2,%ymm2			# b0d0.hi\n"
"\n"
"vmovdqa		(64*\\off+32)*2(%rdx),%ymm7		# c1\n"
"vmovdqa		(64*\\off+48)*2(%rdx),%ymm8		# d1\n"
"\n"
"vpmulhw		%ymm7,%ymm3,%ymm15			# a1c1.hi\n"
"vpmulhw		%ymm8,%ymm3,%ymm3			# a1d1.hi\n"
"vpmulhw		%ymm7,%ymm4,%ymm0			# b1c1.hi\n"
"vpmulhw		%ymm8,%ymm4,%ymm4			# b1d1.hi\n"
"\n"
"vmovdqa		%ymm13,(%rsp)\n"
"\n"
"vpmullw		%ymm5,%ymm9,%ymm13			# a0c0.lo\n"
"vpmullw		%ymm6,%ymm9,%ymm9			# a0d0.lo\n"
"vpmullw		%ymm5,%ymm10,%ymm5			# b0c0.lo\n"
"vpmullw		%ymm6,%ymm10,%ymm10			# b0d0.lo\n"
"\n"
"vpmullw		%ymm7,%ymm11,%ymm6			# a1c1.lo\n"
"vpmullw		%ymm8,%ymm11,%ymm11			# a1d1.lo\n"
"vpmullw		%ymm7,%ymm12,%ymm7			# b1c1.lo\n"
"vpmullw		%ymm8,%ymm12,%ymm12			# b1d1.lo\n"
"\n"
"vmovdqa		_16XQ*2(%rcx),%ymm8\n"
"vpmulhw		%ymm8,%ymm13,%ymm13\n"
"vpmulhw		%ymm8,%ymm9,%ymm9\n"
"vpmulhw		%ymm8,%ymm5,%ymm5\n"
"vpmulhw		%ymm8,%ymm10,%ymm10\n"
"vpmulhw		%ymm8,%ymm6,%ymm6\n"
"vpmulhw		%ymm8,%ymm11,%ymm11\n"
"vpmulhw		%ymm8,%ymm7,%ymm7\n"
"vpmulhw		%ymm8,%ymm12,%ymm12\n"
"\n"
"vpsubw		(%rsp),%ymm13,%ymm13			# -a0c0\n"
"vpsubw		%ymm9,%ymm1,%ymm9			# a0d0\n"
"vpsubw		%ymm5,%ymm14,%ymm5			# b0c0\n"
"vpsubw		%ymm10,%ymm2,%ymm10			# b0d0\n"
"\n"
"vpsubw		%ymm6,%ymm15,%ymm6			# a1c1\n"
"vpsubw		%ymm11,%ymm3,%ymm11			# a1d1\n"
"vpsubw		%ymm7,%ymm0,%ymm7			# b1c1\n"
"vpsubw		%ymm12,%ymm4,%ymm12			# b1d1\n"
"\n"
"vmovdqa		(%r9),%ymm0\n"
"vmovdqa		32(%r9),%ymm1\n"
"vpmullw		%ymm0,%ymm10,%ymm2\n"
"vpmullw		%ymm0,%ymm12,%ymm3\n"
"vpmulhw		%ymm1,%ymm10,%ymm10\n"
"vpmulhw		%ymm1,%ymm12,%ymm12\n"
"vpmulhw		%ymm8,%ymm2,%ymm2\n"
"vpmulhw		%ymm8,%ymm3,%ymm3\n"
"vpsubw		%ymm2,%ymm10,%ymm10			# rb0d0\n"
"vpsubw		%ymm3,%ymm12,%ymm12			# rb1d1\n"
"\n"
"vpaddw		%ymm5,%ymm9,%ymm9\n"
"vpaddw		%ymm7,%ymm11,%ymm11\n"
"vpsubw		%ymm13,%ymm10,%ymm13\n"
"vpsubw		%ymm12,%ymm6,%ymm6\n"
"\n"
"vmovdqa		%ymm13,(64*\\off+ 0)*2(%rdi)\n"
"vmovdqa		%ymm9,(64*\\off+16)*2(%rdi)\n"
"vmovdqa		%ymm6,(64*\\off+32)*2(%rdi)\n"
"vmovdqa		%ymm11,(64*\\off+48)*2(%rdi)\n"
".endm\n"
"\n"
".text\n"
"basemul_avx:\n"
"mov		%rsp,%r8\n"
"and		$-32,%rsp\n"
"sub		$32,%rsp\n"
"\n"
"lea		(_ZETAS_EXP+176)*2(%rcx),%r9\n"
"schoolbook	0\n"
"\n"
"add		$32*2,%r9\n"
"schoolbook	1\n"
"\n"
"add		$192*2,%r9\n"
"schoolbook	2\n"
"\n"
"add		$32*2,%r9\n"
"schoolbook	3\n"
"\n"
"mov		%r8,%rsp\n"
"ret\n"
);
