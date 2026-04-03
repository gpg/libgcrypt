#include <stdint.h>
#include <immintrin.h>

#define Q KYBER_Q
#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16
#define V 20159 // floor(2^26/q + 0.5)
#define FHI 1441 // mont^2/128
#define FLO -10079 // qinv*FHI
#define MONTSQHI 1353 // mont^2
#define MONTSQLO 20553 // qinv*MONTSQHI
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

typedef struct {
  __m256i s[25];
} keccakx4_state;

#define KeccakP1600times4_implementation_config "AVX2, all rounds unrolled"
#define KeccakP1600times4_fullUnrolling
#define KeccakP1600times4_useAVX2

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

/*************** kyber/ref/ntt.c */
// FIXME put asm implementation here

/*************** kyber/ref/poly.c */

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
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

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
**************************************************/
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
  ALIGNED_UINT8(KYBER_ETA1_2*KYBER_N/4+32) buf; // +32 bytes as required by poly_cbd_eta1
  prf(buf.coeffs, KYBER_ETA1_2*KYBER_N/4, seed, nonce);
  cbd3(r, (const uint8_t *)buf.vec);
}
#endif
#if !defined(KYBER_K) || KYBER_K == 3 || KYBER_K == 4
void poly_getnoise_eta1_3_4(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  ALIGNED_UINT8(KYBER_ETA1_3_4*KYBER_N/4+32) buf; // +32 bytes as required by poly_cbd_eta1
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
*              bounded by q in absolute value, output coefficients are bounded
*              by 16118 in absolute value.
*
* Arguments:   - poly *r: pointer to in/output polynomial
**************************************************/
void poly_ntt(poly *r)
{
  ntt_avx(r->vec, qdata.vec);
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

void poly_nttunpack(poly *r)//FIXME: static?
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
void polyvec_compress_4(uint8_t r[4*320+2], const polyvec_4 *a)
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

#include "kyber-common-vector-asm.c"
