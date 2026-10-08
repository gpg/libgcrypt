/* dilithium-vector-avx2-common.c - the Dilithium
 *                                  (common part, with AVX2 optimization)
 * Copyright (C) 2025, 2026 g10 Code GmbH
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

  Repository: https://github.com/pq-crystals/dilithium.git
  Branch: master
  Commit: 444cdcc84eb36b66fe27b3a2529ee48f6d8150c2

  Licence:
  Public Domain (https://creativecommons.org/share-your-work/public-domain/cc0/);
  or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).

  Authors:
        Léo Ducas
        Eike Kiltz
        Tancrède Lepoint
        Vadim Lyubashevsky
        Gregor Seiler
        Peter Schwabe
        Damien Stehlé

  Dilithium Home: https://github.com/pq-crystals/dilithium.git
 */
/*
 * - Fixed rej_uniform_avx for ISO C90
 */
/*************** dilithium/avx2/consts.c */
#define QINV 58728449 // q^(-1) mod 2^32
#define MONT -4186625 // 2^32 mod q
#define DIV 41978 // mont^2/256
#define DIV_QINV -8395782

const qdata_t qdata = {{
#define _8XQ 0
  Q, Q, Q, Q, Q, Q, Q, Q,

#define _8XQINV 8
  QINV, QINV, QINV, QINV, QINV, QINV, QINV, QINV,

#define _8XDIV_QINV 16
  DIV_QINV, DIV_QINV, DIV_QINV, DIV_QINV, DIV_QINV, DIV_QINV, DIV_QINV, DIV_QINV,

#define _8XDIV 24
  DIV, DIV, DIV, DIV, DIV, DIV, DIV, DIV,

#define _ZETAS_QINV 32
   -151046689,  1830765815, -1929875198, -1927777021,  1640767044,  1477910808,  1612161320,  1640734244,
    308362795,   308362795,   308362795,   308362795, -1815525077, -1815525077, -1815525077, -1815525077,
  -1374673747, -1374673747, -1374673747, -1374673747, -1091570561, -1091570561, -1091570561, -1091570561,
  -1929495947, -1929495947, -1929495947, -1929495947,   515185417,   515185417,   515185417,   515185417,
   -285697463,  -285697463,  -285697463,  -285697463,   625853735,   625853735,   625853735,   625853735,
   1727305304,  1727305304,  2082316400,  2082316400, -1364982364, -1364982364,   858240904,   858240904,
   1806278032,  1806278032,   222489248,   222489248,  -346752664,  -346752664,   684667771,   684667771,
   1654287830,  1654287830,  -878576921,  -878576921, -1257667337, -1257667337,  -748618600,  -748618600,
    329347125,   329347125,  1837364258,  1837364258, -1443016191, -1443016191, -1170414139, -1170414139,
  -1846138265, -1631226336, -1404529459,  1838055109,  1594295555, -1076973524, -1898723372,  -594436433,
   -202001019,  -475984260,  -561427818,  1797021249, -1061813248,  2059733581, -1661512036, -1104976547,
  -1750224323,  -901666090,   418987550,  1831915353, -1925356481,   992097815,   879957084,  2024403852,
   1484874664, -1636082790,  -285388938, -1983539117, -1495136972,  -950076368, -1714807468,  -952438995,
  -1574918427,  1350681039, -2143979939,  1599739335, -1285853323,  -993005454, -1440787840,   568627424,
   -783134478,  -588790216,   289871779, -1262003603,  2135294594, -1018755525,  -889861155,  1665705315,
   1321868265,  1225434135, -1784632064,   666258756,   675310538, -1555941048, -1999506068, -1499481951,
   -695180180, -1375177022,  1777179795,   334803717,  -178766299,  -518252220,  1957047970,  1146323031,
   -654783359, -1974159335,  1651689966,   140455867, -1039411342,  1955560694,  1529189038, -2131021878,
   -247357819,  1518161567,   -86965173,  1708872713,  1787797779,  1638590967,  -120646188, -1669960606,
   -916321552,  1155548552,  2143745726,  1210558298, -1261461890,  -318346816,   628664287, -1729304568,
   1422575624,  1424130038, -1185330464,   235321234,   168022240,  1206536194,   985155484,  -894060583,
      -898413, -1363460238,  -605900043,  2027833504,    14253662,  1014493059,   863641633,  1819892093,
   2124962073, -1223601433, -1920467227, -1637785316, -1536588520,   694382729,   235104446, -1045062172,
    831969619,  -300448763,   756955444,  -260312805,  1554794072,  1339088280, -2040058690,  -853476187,
  -2047270596, -1723816713, -1591599803,  -440824168,  1119856484,  1544891539,   155290192,  -973777462,
    991903578,   912367099,   -44694137,  1176904444,  -421552614,  -818371958,  1747917558,  -325927722,
    908452108,  1851023419, -1176751719, -1354528380,   -72690498,  -314284737,   985022747,   963438279,
  -1078959975,   604552167, -1021949428,   608791570,   173440395, -2126092136, -1316619236, -1039370342,
      6087993,  -110126092,   565464272, -1758099917, -1600929361,   879867909, -1809756372,   400711272,
   1363007700,    30313375,  -326425360,  1683520342,  -517299994,  2027935492, -1372618620,   128353682,
  -1123881663,   137583815,  -635454918,  -642772911,    45766801,   671509323, -2070602178,   419615363,
   1216882040,  -270590488, -1276805128,   371462360, -1357098057,  -384158533,   827959816,  -596344473,
    702390549,  -279505433,  -260424530,   -71875110, -1208667171, -1499603926,  2036925262,  -540420426,
    746144248, -1420958686,  2032221021,  1904936414,  1257750362,  1926727420,  1931587462,  1258381762,
    885133339,  1629985060,  1967222129,     6363718, -1287922800,  1136965286,  1779436847,  1116720494,
   1042326957,  1405999311,   713994583,   940195359, -1542497137,  2061661095,  -883155599,  1726753853,
  -1547952704,   394851342,   283780712,   776003547,  1123958025,   201262505,  1934038751,   374860238,

#define _ZETAS 328
  -3975713,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  1826347,  1826347,  1826347,  2353451,  2353451,  2353451,  2353451,
   -359251,  -359251,  -359251,  -359251, -2091905, -2091905, -2091905, -2091905,
   3119733,  3119733,  3119733,  3119733, -2884855, -2884855, -2884855, -2884855,
   3111497,  3111497,  3111497,  3111497,  2680103,  2680103,  2680103,  2680103,
   2725464,  2725464,  1024112,  1024112, -1079900, -1079900,  3585928,  3585928,
   -549488,  -549488, -1119584, -1119584,  2619752,  2619752, -2108549, -2108549,
  -2118186, -2118186, -3859737, -3859737, -1399561, -1399561, -3277672, -3277672,
   1757237,  1757237,   -19422,   -19422,  4010497,  4010497,   280005,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -3677745, -1452451,  2176455, -1257611, -4083598, -3190144, -3632928,
   3412210,  2147896, -2967645,  -411027,  -671102,   -22981,  -381987,  1852771,
  -3343383,   508951,    44288,   904516, -3724342,  1653064,  2389356,   759969,
    189548,  3159746, -2409325,  1315589,  1285669,  -812732, -3019102, -3628969,
  -1528703, -3041255,  3475950, -1585221,  1939314, -1000202, -3157330,   126922,
   -983419,  2715295, -3693493, -2477047, -1228525, -1308169,  1349076, -1430430,
    264944,  3097992, -1100098,  3958618,    -8578, -3249728,  -210977, -1316856,
  -3553272, -1851402,  -177440,  1341330, -1584928, -1439742, -3881060,  3839961,
   2091667, -3342478,   266997, -3520352,   900702,   495491,  -655327, -3556995,
    342297,  3437287,  2842341,  4055324, -3767016, -2994039, -1333058,  -451100,
  -1279661,  1500165,  -542412, -2584293, -2013608,  1957272, -3183426,   810149,
  -3038916,  2213111,  -426683, -1667432, -2939036,   183443,  -554416,  3937738,
   3407706,  2244091,  2434439, -3759364,  1859098, -1613174, -3122442,  -525098,
    286988, -3342277,  2691481,  1247620,  1250494,  1869119,  1237275,  1312455,
   1917081,   777191, -2831860, -3724270,  2432395,  3369112,   162844,  1652634,
   3523897,  -975884,  1723600, -1104333, -2235985,  -976891,  3919660,  1400424,
   2316500, -2446433, -1235728, -1197226,   909542,   -43260,  2031748,  -768622,
  -2437823,  1735879, -2590150,  2486353,  2635921,  1903435, -3318210,  3306115,
  -2546312,  2235880, -1671176,   594136,  2454455,   185531,  1616392, -3694233,
   3866901,  1717735, -1803090,  -260646,  -420899,  1612842,   -48306,  -846154,
   3817976, -3562462,  3513181, -3193378,   819034,  -522500,  3207046, -3595838,
   4108315,   203044,  1265009,  1595974, -3548272, -1050970, -1430225, -1962642,
  -1374803,  3406031, -1846953, -3776993,  -164721, -1207385,  3014001, -1799107,
    269760,   472078,  1910376, -3833893, -2286327, -3545687, -1362209,  1976782,
}};

/*************** dilithium/avx2/rejsample.c */
static
const uint8_t idxlut[256][8] = {
  { 0,  0,  0,  0,  0,  0,  0,  0},
  { 0,  0,  0,  0,  0,  0,  0,  0},
  { 1,  0,  0,  0,  0,  0,  0,  0},
  { 0,  1,  0,  0,  0,  0,  0,  0},
  { 2,  0,  0,  0,  0,  0,  0,  0},
  { 0,  2,  0,  0,  0,  0,  0,  0},
  { 1,  2,  0,  0,  0,  0,  0,  0},
  { 0,  1,  2,  0,  0,  0,  0,  0},
  { 3,  0,  0,  0,  0,  0,  0,  0},
  { 0,  3,  0,  0,  0,  0,  0,  0},
  { 1,  3,  0,  0,  0,  0,  0,  0},
  { 0,  1,  3,  0,  0,  0,  0,  0},
  { 2,  3,  0,  0,  0,  0,  0,  0},
  { 0,  2,  3,  0,  0,  0,  0,  0},
  { 1,  2,  3,  0,  0,  0,  0,  0},
  { 0,  1,  2,  3,  0,  0,  0,  0},
  { 4,  0,  0,  0,  0,  0,  0,  0},
  { 0,  4,  0,  0,  0,  0,  0,  0},
  { 1,  4,  0,  0,  0,  0,  0,  0},
  { 0,  1,  4,  0,  0,  0,  0,  0},
  { 2,  4,  0,  0,  0,  0,  0,  0},
  { 0,  2,  4,  0,  0,  0,  0,  0},
  { 1,  2,  4,  0,  0,  0,  0,  0},
  { 0,  1,  2,  4,  0,  0,  0,  0},
  { 3,  4,  0,  0,  0,  0,  0,  0},
  { 0,  3,  4,  0,  0,  0,  0,  0},
  { 1,  3,  4,  0,  0,  0,  0,  0},
  { 0,  1,  3,  4,  0,  0,  0,  0},
  { 2,  3,  4,  0,  0,  0,  0,  0},
  { 0,  2,  3,  4,  0,  0,  0,  0},
  { 1,  2,  3,  4,  0,  0,  0,  0},
  { 0,  1,  2,  3,  4,  0,  0,  0},
  { 5,  0,  0,  0,  0,  0,  0,  0},
  { 0,  5,  0,  0,  0,  0,  0,  0},
  { 1,  5,  0,  0,  0,  0,  0,  0},
  { 0,  1,  5,  0,  0,  0,  0,  0},
  { 2,  5,  0,  0,  0,  0,  0,  0},
  { 0,  2,  5,  0,  0,  0,  0,  0},
  { 1,  2,  5,  0,  0,  0,  0,  0},
  { 0,  1,  2,  5,  0,  0,  0,  0},
  { 3,  5,  0,  0,  0,  0,  0,  0},
  { 0,  3,  5,  0,  0,  0,  0,  0},
  { 1,  3,  5,  0,  0,  0,  0,  0},
  { 0,  1,  3,  5,  0,  0,  0,  0},
  { 2,  3,  5,  0,  0,  0,  0,  0},
  { 0,  2,  3,  5,  0,  0,  0,  0},
  { 1,  2,  3,  5,  0,  0,  0,  0},
  { 0,  1,  2,  3,  5,  0,  0,  0},
  { 4,  5,  0,  0,  0,  0,  0,  0},
  { 0,  4,  5,  0,  0,  0,  0,  0},
  { 1,  4,  5,  0,  0,  0,  0,  0},
  { 0,  1,  4,  5,  0,  0,  0,  0},
  { 2,  4,  5,  0,  0,  0,  0,  0},
  { 0,  2,  4,  5,  0,  0,  0,  0},
  { 1,  2,  4,  5,  0,  0,  0,  0},
  { 0,  1,  2,  4,  5,  0,  0,  0},
  { 3,  4,  5,  0,  0,  0,  0,  0},
  { 0,  3,  4,  5,  0,  0,  0,  0},
  { 1,  3,  4,  5,  0,  0,  0,  0},
  { 0,  1,  3,  4,  5,  0,  0,  0},
  { 2,  3,  4,  5,  0,  0,  0,  0},
  { 0,  2,  3,  4,  5,  0,  0,  0},
  { 1,  2,  3,  4,  5,  0,  0,  0},
  { 0,  1,  2,  3,  4,  5,  0,  0},
  { 6,  0,  0,  0,  0,  0,  0,  0},
  { 0,  6,  0,  0,  0,  0,  0,  0},
  { 1,  6,  0,  0,  0,  0,  0,  0},
  { 0,  1,  6,  0,  0,  0,  0,  0},
  { 2,  6,  0,  0,  0,  0,  0,  0},
  { 0,  2,  6,  0,  0,  0,  0,  0},
  { 1,  2,  6,  0,  0,  0,  0,  0},
  { 0,  1,  2,  6,  0,  0,  0,  0},
  { 3,  6,  0,  0,  0,  0,  0,  0},
  { 0,  3,  6,  0,  0,  0,  0,  0},
  { 1,  3,  6,  0,  0,  0,  0,  0},
  { 0,  1,  3,  6,  0,  0,  0,  0},
  { 2,  3,  6,  0,  0,  0,  0,  0},
  { 0,  2,  3,  6,  0,  0,  0,  0},
  { 1,  2,  3,  6,  0,  0,  0,  0},
  { 0,  1,  2,  3,  6,  0,  0,  0},
  { 4,  6,  0,  0,  0,  0,  0,  0},
  { 0,  4,  6,  0,  0,  0,  0,  0},
  { 1,  4,  6,  0,  0,  0,  0,  0},
  { 0,  1,  4,  6,  0,  0,  0,  0},
  { 2,  4,  6,  0,  0,  0,  0,  0},
  { 0,  2,  4,  6,  0,  0,  0,  0},
  { 1,  2,  4,  6,  0,  0,  0,  0},
  { 0,  1,  2,  4,  6,  0,  0,  0},
  { 3,  4,  6,  0,  0,  0,  0,  0},
  { 0,  3,  4,  6,  0,  0,  0,  0},
  { 1,  3,  4,  6,  0,  0,  0,  0},
  { 0,  1,  3,  4,  6,  0,  0,  0},
  { 2,  3,  4,  6,  0,  0,  0,  0},
  { 0,  2,  3,  4,  6,  0,  0,  0},
  { 1,  2,  3,  4,  6,  0,  0,  0},
  { 0,  1,  2,  3,  4,  6,  0,  0},
  { 5,  6,  0,  0,  0,  0,  0,  0},
  { 0,  5,  6,  0,  0,  0,  0,  0},
  { 1,  5,  6,  0,  0,  0,  0,  0},
  { 0,  1,  5,  6,  0,  0,  0,  0},
  { 2,  5,  6,  0,  0,  0,  0,  0},
  { 0,  2,  5,  6,  0,  0,  0,  0},
  { 1,  2,  5,  6,  0,  0,  0,  0},
  { 0,  1,  2,  5,  6,  0,  0,  0},
  { 3,  5,  6,  0,  0,  0,  0,  0},
  { 0,  3,  5,  6,  0,  0,  0,  0},
  { 1,  3,  5,  6,  0,  0,  0,  0},
  { 0,  1,  3,  5,  6,  0,  0,  0},
  { 2,  3,  5,  6,  0,  0,  0,  0},
  { 0,  2,  3,  5,  6,  0,  0,  0},
  { 1,  2,  3,  5,  6,  0,  0,  0},
  { 0,  1,  2,  3,  5,  6,  0,  0},
  { 4,  5,  6,  0,  0,  0,  0,  0},
  { 0,  4,  5,  6,  0,  0,  0,  0},
  { 1,  4,  5,  6,  0,  0,  0,  0},
  { 0,  1,  4,  5,  6,  0,  0,  0},
  { 2,  4,  5,  6,  0,  0,  0,  0},
  { 0,  2,  4,  5,  6,  0,  0,  0},
  { 1,  2,  4,  5,  6,  0,  0,  0},
  { 0,  1,  2,  4,  5,  6,  0,  0},
  { 3,  4,  5,  6,  0,  0,  0,  0},
  { 0,  3,  4,  5,  6,  0,  0,  0},
  { 1,  3,  4,  5,  6,  0,  0,  0},
  { 0,  1,  3,  4,  5,  6,  0,  0},
  { 2,  3,  4,  5,  6,  0,  0,  0},
  { 0,  2,  3,  4,  5,  6,  0,  0},
  { 1,  2,  3,  4,  5,  6,  0,  0},
  { 0,  1,  2,  3,  4,  5,  6,  0},
  { 7,  0,  0,  0,  0,  0,  0,  0},
  { 0,  7,  0,  0,  0,  0,  0,  0},
  { 1,  7,  0,  0,  0,  0,  0,  0},
  { 0,  1,  7,  0,  0,  0,  0,  0},
  { 2,  7,  0,  0,  0,  0,  0,  0},
  { 0,  2,  7,  0,  0,  0,  0,  0},
  { 1,  2,  7,  0,  0,  0,  0,  0},
  { 0,  1,  2,  7,  0,  0,  0,  0},
  { 3,  7,  0,  0,  0,  0,  0,  0},
  { 0,  3,  7,  0,  0,  0,  0,  0},
  { 1,  3,  7,  0,  0,  0,  0,  0},
  { 0,  1,  3,  7,  0,  0,  0,  0},
  { 2,  3,  7,  0,  0,  0,  0,  0},
  { 0,  2,  3,  7,  0,  0,  0,  0},
  { 1,  2,  3,  7,  0,  0,  0,  0},
  { 0,  1,  2,  3,  7,  0,  0,  0},
  { 4,  7,  0,  0,  0,  0,  0,  0},
  { 0,  4,  7,  0,  0,  0,  0,  0},
  { 1,  4,  7,  0,  0,  0,  0,  0},
  { 0,  1,  4,  7,  0,  0,  0,  0},
  { 2,  4,  7,  0,  0,  0,  0,  0},
  { 0,  2,  4,  7,  0,  0,  0,  0},
  { 1,  2,  4,  7,  0,  0,  0,  0},
  { 0,  1,  2,  4,  7,  0,  0,  0},
  { 3,  4,  7,  0,  0,  0,  0,  0},
  { 0,  3,  4,  7,  0,  0,  0,  0},
  { 1,  3,  4,  7,  0,  0,  0,  0},
  { 0,  1,  3,  4,  7,  0,  0,  0},
  { 2,  3,  4,  7,  0,  0,  0,  0},
  { 0,  2,  3,  4,  7,  0,  0,  0},
  { 1,  2,  3,  4,  7,  0,  0,  0},
  { 0,  1,  2,  3,  4,  7,  0,  0},
  { 5,  7,  0,  0,  0,  0,  0,  0},
  { 0,  5,  7,  0,  0,  0,  0,  0},
  { 1,  5,  7,  0,  0,  0,  0,  0},
  { 0,  1,  5,  7,  0,  0,  0,  0},
  { 2,  5,  7,  0,  0,  0,  0,  0},
  { 0,  2,  5,  7,  0,  0,  0,  0},
  { 1,  2,  5,  7,  0,  0,  0,  0},
  { 0,  1,  2,  5,  7,  0,  0,  0},
  { 3,  5,  7,  0,  0,  0,  0,  0},
  { 0,  3,  5,  7,  0,  0,  0,  0},
  { 1,  3,  5,  7,  0,  0,  0,  0},
  { 0,  1,  3,  5,  7,  0,  0,  0},
  { 2,  3,  5,  7,  0,  0,  0,  0},
  { 0,  2,  3,  5,  7,  0,  0,  0},
  { 1,  2,  3,  5,  7,  0,  0,  0},
  { 0,  1,  2,  3,  5,  7,  0,  0},
  { 4,  5,  7,  0,  0,  0,  0,  0},
  { 0,  4,  5,  7,  0,  0,  0,  0},
  { 1,  4,  5,  7,  0,  0,  0,  0},
  { 0,  1,  4,  5,  7,  0,  0,  0},
  { 2,  4,  5,  7,  0,  0,  0,  0},
  { 0,  2,  4,  5,  7,  0,  0,  0},
  { 1,  2,  4,  5,  7,  0,  0,  0},
  { 0,  1,  2,  4,  5,  7,  0,  0},
  { 3,  4,  5,  7,  0,  0,  0,  0},
  { 0,  3,  4,  5,  7,  0,  0,  0},
  { 1,  3,  4,  5,  7,  0,  0,  0},
  { 0,  1,  3,  4,  5,  7,  0,  0},
  { 2,  3,  4,  5,  7,  0,  0,  0},
  { 0,  2,  3,  4,  5,  7,  0,  0},
  { 1,  2,  3,  4,  5,  7,  0,  0},
  { 0,  1,  2,  3,  4,  5,  7,  0},
  { 6,  7,  0,  0,  0,  0,  0,  0},
  { 0,  6,  7,  0,  0,  0,  0,  0},
  { 1,  6,  7,  0,  0,  0,  0,  0},
  { 0,  1,  6,  7,  0,  0,  0,  0},
  { 2,  6,  7,  0,  0,  0,  0,  0},
  { 0,  2,  6,  7,  0,  0,  0,  0},
  { 1,  2,  6,  7,  0,  0,  0,  0},
  { 0,  1,  2,  6,  7,  0,  0,  0},
  { 3,  6,  7,  0,  0,  0,  0,  0},
  { 0,  3,  6,  7,  0,  0,  0,  0},
  { 1,  3,  6,  7,  0,  0,  0,  0},
  { 0,  1,  3,  6,  7,  0,  0,  0},
  { 2,  3,  6,  7,  0,  0,  0,  0},
  { 0,  2,  3,  6,  7,  0,  0,  0},
  { 1,  2,  3,  6,  7,  0,  0,  0},
  { 0,  1,  2,  3,  6,  7,  0,  0},
  { 4,  6,  7,  0,  0,  0,  0,  0},
  { 0,  4,  6,  7,  0,  0,  0,  0},
  { 1,  4,  6,  7,  0,  0,  0,  0},
  { 0,  1,  4,  6,  7,  0,  0,  0},
  { 2,  4,  6,  7,  0,  0,  0,  0},
  { 0,  2,  4,  6,  7,  0,  0,  0},
  { 1,  2,  4,  6,  7,  0,  0,  0},
  { 0,  1,  2,  4,  6,  7,  0,  0},
  { 3,  4,  6,  7,  0,  0,  0,  0},
  { 0,  3,  4,  6,  7,  0,  0,  0},
  { 1,  3,  4,  6,  7,  0,  0,  0},
  { 0,  1,  3,  4,  6,  7,  0,  0},
  { 2,  3,  4,  6,  7,  0,  0,  0},
  { 0,  2,  3,  4,  6,  7,  0,  0},
  { 1,  2,  3,  4,  6,  7,  0,  0},
  { 0,  1,  2,  3,  4,  6,  7,  0},
  { 5,  6,  7,  0,  0,  0,  0,  0},
  { 0,  5,  6,  7,  0,  0,  0,  0},
  { 1,  5,  6,  7,  0,  0,  0,  0},
  { 0,  1,  5,  6,  7,  0,  0,  0},
  { 2,  5,  6,  7,  0,  0,  0,  0},
  { 0,  2,  5,  6,  7,  0,  0,  0},
  { 1,  2,  5,  6,  7,  0,  0,  0},
  { 0,  1,  2,  5,  6,  7,  0,  0},
  { 3,  5,  6,  7,  0,  0,  0,  0},
  { 0,  3,  5,  6,  7,  0,  0,  0},
  { 1,  3,  5,  6,  7,  0,  0,  0},
  { 0,  1,  3,  5,  6,  7,  0,  0},
  { 2,  3,  5,  6,  7,  0,  0,  0},
  { 0,  2,  3,  5,  6,  7,  0,  0},
  { 1,  2,  3,  5,  6,  7,  0,  0},
  { 0,  1,  2,  3,  5,  6,  7,  0},
  { 4,  5,  6,  7,  0,  0,  0,  0},
  { 0,  4,  5,  6,  7,  0,  0,  0},
  { 1,  4,  5,  6,  7,  0,  0,  0},
  { 0,  1,  4,  5,  6,  7,  0,  0},
  { 2,  4,  5,  6,  7,  0,  0,  0},
  { 0,  2,  4,  5,  6,  7,  0,  0},
  { 1,  2,  4,  5,  6,  7,  0,  0},
  { 0,  1,  2,  4,  5,  6,  7,  0},
  { 3,  4,  5,  6,  7,  0,  0,  0},
  { 0,  3,  4,  5,  6,  7,  0,  0},
  { 1,  3,  4,  5,  6,  7,  0,  0},
  { 0,  1,  3,  4,  5,  6,  7,  0},
  { 2,  3,  4,  5,  6,  7,  0,  0},
  { 0,  2,  3,  4,  5,  6,  7,  0},
  { 1,  2,  3,  4,  5,  6,  7,  0},
  { 0,  1,  2,  3,  4,  5,  6,  7}
};

static
unsigned int rej_uniform_avx(int32_t * restrict r, const uint8_t buf[REJ_UNIFORM_BUFLEN+8])
{
  uint32_t t;
  unsigned int ctr, pos;
  uint32_t good;
  __m256i d, tmp;
  const __m256i bound = _mm256_set1_epi32(Q);
  const __m256i mask  = _mm256_set1_epi32(0x7FFFFF);
  const __m256i idx8  = _mm256_set_epi8(-1,15,14,13,-1,12,11,10,
                                        -1, 9, 8, 7,-1, 6, 5, 4,
                                        -1,11,10, 9,-1, 8, 7, 6,
                                        -1, 5, 4, 3,-1, 2, 1, 0);

  ctr = pos = 0;
  while(pos <= REJ_UNIFORM_BUFLEN - 24) {
    d = _mm256_loadu_si256((__m256i *)&buf[pos]);
    d = _mm256_permute4x64_epi64(d, 0x94);
    d = _mm256_shuffle_epi8(d, idx8);
    d = _mm256_and_si256(d, mask);
    pos += 24;

    tmp = _mm256_sub_epi32(d, bound);
    good = _mm256_movemask_ps((__m256)tmp);
    tmp = _mm256_cvtepu8_epi32(_mm_loadl_epi64((__m128i *)&idxlut[good]));
    d = _mm256_permutevar8x32_epi32(d, tmp);

    _mm256_storeu_si256((__m256i *)&r[ctr], d);
    ctr += _mm_popcnt_u32(good);

    if(ctr > N - 8) break;
  }

  while(ctr < N && pos <= REJ_UNIFORM_BUFLEN - 3) {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if(t < Q)
      r[ctr++] = t;
  }

  return ctr;
}

#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2 || DILITHIUM_MODE == 5
static unsigned int rej_eta_avx_2(int32_t * restrict r, const uint8_t buf[REJ_UNIFORM_ETA_BUFLEN_2]) {
  uint32_t t0, t1;
  unsigned int ctr, pos;
  uint32_t good;
  __m256i f0, f1, f2;
  __m128i g0, g1;
  const __m256i mask = _mm256_set1_epi8(15);
  const __m256i eta = _mm256_set1_epi8(ETA2);
  const __m256i bound = mask;
  const __m256i v = _mm256_set1_epi32(-6560);
  const __m256i p = _mm256_set1_epi32(5);

  ctr = pos = 0;
  while(ctr <= N - 8 && pos <= REJ_UNIFORM_ETA_BUFLEN_2 - 16) {
    f0 = _mm256_cvtepu8_epi16(_mm_loadu_si128((__m128i *)&buf[pos]));
    f1 = _mm256_slli_epi16(f0,4);
    f0 = _mm256_or_si256(f0,f1);
    f0 = _mm256_and_si256(f0,mask);

    f1 = _mm256_sub_epi8(f0,bound);
    f0 = _mm256_sub_epi8(eta,f0);
    good = _mm256_movemask_epi8(f1);

    g0 = _mm256_castsi256_si128(f0);
    g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
    g1 = _mm_shuffle_epi8(g0,g1);
    f1 = _mm256_cvtepi8_epi32(g1);
    f2 = _mm256_mulhrs_epi16(f1,v);
    f2 = _mm256_mullo_epi16(f2,p);
    f1 = _mm256_add_epi32(f1,f2);
    _mm256_storeu_si256((__m256i *)&r[ctr],f1);
    ctr += _mm_popcnt_u32(good & 0xFF);
    good >>= 8;
    pos += 4;

    if(ctr > N - 8) break;
    g0 = _mm_bsrli_si128(g0,8);
    g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
    g1 = _mm_shuffle_epi8(g0,g1);
    f1 = _mm256_cvtepi8_epi32(g1);
    f2 = _mm256_mulhrs_epi16(f1,v);
    f2 = _mm256_mullo_epi16(f2,p);
    f1 = _mm256_add_epi32(f1,f2);
    _mm256_storeu_si256((__m256i *)&r[ctr],f1);
    ctr += _mm_popcnt_u32(good & 0xFF);
    good >>= 8;
    pos += 4;

    if(ctr > N - 8) break;
    g0 = _mm256_extracti128_si256(f0,1);
    g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
    g1 = _mm_shuffle_epi8(g0,g1);
    f1 = _mm256_cvtepi8_epi32(g1);
    f2 = _mm256_mulhrs_epi16(f1,v);
    f2 = _mm256_mullo_epi16(f2,p);
    f1 = _mm256_add_epi32(f1,f2);
    _mm256_storeu_si256((__m256i *)&r[ctr],f1);
    ctr += _mm_popcnt_u32(good & 0xFF);
    good >>= 8;
    pos += 4;

    if(ctr > N - 8) break;
    g0 = _mm_bsrli_si128(g0,8);
    g1 = _mm_loadl_epi64((__m128i *)&idxlut[good]);
    g1 = _mm_shuffle_epi8(g0,g1);
    f1 = _mm256_cvtepi8_epi32(g1);
    f2 = _mm256_mulhrs_epi16(f1,v);
    f2 = _mm256_mullo_epi16(f2,p);
    f1 = _mm256_add_epi32(f1,f2);
    _mm256_storeu_si256((__m256i *)&r[ctr],f1);
    ctr += _mm_popcnt_u32(good);
    pos += 4;
  }

  while(ctr < N && pos < REJ_UNIFORM_ETA_BUFLEN_2) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

    if(t0 < 15) {
      t0 = t0 - (205*t0 >> 10)*5;
      r[ctr++] = 2 - t0;
    }
    if(t1 < 15 && ctr < N) {
      t1 = t1 - (205*t1 >> 10)*5;
      r[ctr++] = 2 - t1;
    }
  }

  return ctr;
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3
static unsigned int rej_eta_avx_4(int32_t * restrict r, const uint8_t buf[REJ_UNIFORM_ETA_BUFLEN_4]) {
  uint32_t t0, t1;
  unsigned int ctr, pos;
  uint32_t good;
  __m256i f0, f1;
  __m128i g0, g1;
  const __m256i mask = _mm256_set1_epi8(15);
  const __m256i eta = _mm256_set1_epi8(4);
  const __m256i bound = _mm256_set1_epi8(9);

  ctr = pos = 0;
  while(ctr <= N - 8 && pos <= REJ_UNIFORM_ETA_BUFLEN_4 - 16) {
    f0 = _mm256_cvtepu8_epi16(_mm_loadu_si128((__m128i *)&buf[pos]));
    f1 = _mm256_slli_epi16(f0,4);
    f0 = _mm256_or_si256(f0,f1);
    f0 = _mm256_and_si256(f0,mask);

    f1 = _mm256_sub_epi8(f0,bound);
    f0 = _mm256_sub_epi8(eta,f0);
    good = _mm256_movemask_epi8(f1);

    g0 = _mm256_castsi256_si128(f0);
    g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
    g1 = _mm_shuffle_epi8(g0,g1);
    f1 = _mm256_cvtepi8_epi32(g1);
    _mm256_storeu_si256((__m256i *)&r[ctr],f1);
    ctr += _mm_popcnt_u32(good & 0xFF);
    good >>= 8;
    pos += 4;

    if(ctr > N - 8) break;
    g0 = _mm_bsrli_si128(g0,8);
    g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
    g1 = _mm_shuffle_epi8(g0,g1);
    f1 = _mm256_cvtepi8_epi32(g1);
    _mm256_storeu_si256((__m256i *)&r[ctr],f1);
    ctr += _mm_popcnt_u32(good & 0xFF);
    good >>= 8;
    pos += 4;

    if(ctr > N - 8) break;
    g0 = _mm256_extracti128_si256(f0,1);
    g1 = _mm_loadl_epi64((__m128i *)&idxlut[good & 0xFF]);
    g1 = _mm_shuffle_epi8(g0,g1);
    f1 = _mm256_cvtepi8_epi32(g1);
    _mm256_storeu_si256((__m256i *)&r[ctr],f1);
    ctr += _mm_popcnt_u32(good & 0xFF);
    good >>= 8;
    pos += 4;

    if(ctr > N - 8) break;
    g0 = _mm_bsrli_si128(g0,8);
    g1 = _mm_loadl_epi64((__m128i *)&idxlut[good]);
    g1 = _mm_shuffle_epi8(g0,g1);
    f1 = _mm256_cvtepi8_epi32(g1);
    _mm256_storeu_si256((__m256i *)&r[ctr],f1);
    ctr += _mm_popcnt_u32(good);
    pos += 4;
  }

  while(ctr < N && pos < REJ_UNIFORM_ETA_BUFLEN_4) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

    if(t0 < 9)
      r[ctr++] = 4 - t0;
    if(t1 < 9 && ctr < N)
      r[ctr++] = 4 - t1;
  }

  return ctr;
}
#endif

/*************** dilithium/avx2/rounding.c */

#define _mm256_blendv_epi32(a,b,mask) \
  _mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), \
                                       _mm256_castsi256_ps(b), \
                                       _mm256_castsi256_ps(mask)))

/*************************************************
* Name:        power2round
*
* Description: For finite field elements a, compute a0, a1 such that
*              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
*              Assumes a to be positive standard representative.
*
* Arguments:   - __m256i *a1: output array of length N/8 with high bits
*              - __m256i *a0: output array of length N/8 with low bits a0
*              - const __m256i *a: input array of length N/8
*
**************************************************/
void power2round_avx(__m256i *a1, __m256i *a0, const __m256i *a)
{
  unsigned int i;
  __m256i f,f0,f1;
  const __m256i mask = _mm256_set1_epi32(-(1 << D));
  const __m256i half = _mm256_set1_epi32((1 << (D-1)) - 1);

  for(i = 0; i < N/8; ++i) {
    f = _mm256_load_si256(&a[i]);
    f1 = _mm256_add_epi32(f,half);
    f0 = _mm256_and_si256(f1,mask);
    f1 = _mm256_srli_epi32(f1,D);
    f0 = _mm256_sub_epi32(f,f0);
    _mm256_store_si256(&a1[i],f1);
    _mm256_store_si256(&a0[i],f0);
  }
}

/*************************************************
* Name:        decompose
*
* Description: For finite field element a, compute high and low parts a0, a1 such
*              that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
*              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
*              -ALPHA/2 <= a0 = a mod Q - Q < 0. Assumes a to be positive standard
*              representative.
*
* Arguments:   - __m256i *a1: output array of length N/8 with high parts
*              - __m256i *a0: output array of length N/8 with low parts a0
*              - const __m256i *a: input array of length N/8
*
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
void decompose_avx_88(__m256i *a1, __m256i *a0, const __m256i *a)
{
  unsigned int i;
  __m256i f,f0,f1,t;
  const __m256i q = _mm256_load_si256(&qdata.vec[_8XQ/8]);
  const __m256i hq = _mm256_srli_epi32(q,1);
  const __m256i v = _mm256_set1_epi32(11275);
  const __m256i alpha = _mm256_set1_epi32(2*GAMMA2_88);
  const __m256i off = _mm256_set1_epi32(127);
  const __m256i shift = _mm256_set1_epi32(128);
  const __m256i max = _mm256_set1_epi32(43);
  const __m256i zero = _mm256_setzero_si256();

  for(i=0;i<N/8;i++) {
    f = _mm256_load_si256(&a[i]);
    f1 = _mm256_add_epi32(f,off);
    f1 = _mm256_srli_epi32(f1,7);
    f1 = _mm256_mulhi_epu16(f1,v);
    f1 = _mm256_mulhrs_epi16(f1,shift);
    t = _mm256_sub_epi32(max,f1);
    f1 = _mm256_blendv_epi32(f1,zero,t);
    f0 = _mm256_mullo_epi32(f1,alpha);
    f0 = _mm256_sub_epi32(f,f0);
    f = _mm256_cmpgt_epi32(f0,hq);
    f = _mm256_and_si256(f,q);
    f0 = _mm256_sub_epi32(f0,f);
    _mm256_store_si256(&a1[i],f1);
    _mm256_store_si256(&a0[i],f0);
  }
}
#endif

#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
void decompose_avx_32(__m256i *a1, __m256i *a0, const __m256i *a)
{
  unsigned int i;
  __m256i f,f0,f1;
  const __m256i q = _mm256_load_si256(&qdata.vec[_8XQ/8]);
  const __m256i hq = _mm256_srli_epi32(q,1);
  const __m256i v = _mm256_set1_epi32(1025);
  const __m256i alpha = _mm256_set1_epi32(2*GAMMA2_32);
  const __m256i off = _mm256_set1_epi32(127);
  const __m256i shift = _mm256_set1_epi32(512);
  const __m256i mask = _mm256_set1_epi32(15);

  for(i=0;i<N/8;i++) {
    f = _mm256_load_si256(&a[i]);
    f1 = _mm256_add_epi32(f,off);
    f1 = _mm256_srli_epi32(f1,7);
    f1 = _mm256_mulhi_epu16(f1,v);
    f1 = _mm256_mulhrs_epi16(f1,shift);
    f1 = _mm256_and_si256(f1,mask);
    f0 = _mm256_mullo_epi32(f1,alpha);
    f0 = _mm256_sub_epi32(f,f0);
    f = _mm256_cmpgt_epi32(f0,hq);
    f = _mm256_and_si256(f,q);
    f0 = _mm256_sub_epi32(f0,f);
    _mm256_store_si256(&a1[i],f1);
    _mm256_store_si256(&a0[i],f0);
  }
}
#endif

/*************************************************
* Name:        make_hint
*
* Description: Compute indices of polynomial coefficients whose low bits
*              overflow into the high bits.
*
* Arguments:   - uint8_t *hint: hint array
*              - const __m256i *a0: low bits of input elements
*              - const __m256i *a1: high bits of input elements
*
* Returns number of overflowing low bits
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
unsigned int make_hint_avx_88(uint8_t hint[N], const __m256i * restrict a0, const __m256i * restrict a1)
{
  unsigned int i, n = 0;
  __m256i f0, f1, g0, g1;
  uint32_t bad;
  uint64_t idx;
  const __m256i low = _mm256_set1_epi32(-GAMMA2_88);
  const __m256i high = _mm256_set1_epi32(GAMMA2_88);

  for(i = 0; i < N/8; ++i) {
    f0 = _mm256_load_si256(&a0[i]);
    f1 = _mm256_load_si256(&a1[i]);
    g0 = _mm256_abs_epi32(f0);
    g0 = _mm256_cmpgt_epi32(g0,high);
    g1 = _mm256_cmpeq_epi32(f0,low);
    g1 = _mm256_sign_epi32(g1,f1);
    g0 = _mm256_or_si256(g0,g1);

    bad = _mm256_movemask_ps((__m256)g0);
    memcpy(&idx,idxlut[bad],8);
    idx += (uint64_t)0x0808080808080808*i;
    memcpy(&hint[n],&idx,8);
    n += _mm_popcnt_u32(bad);
  }

  return n;
}
#endif

#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
unsigned int make_hint_avx_32(uint8_t hint[N], const __m256i * restrict a0, const __m256i * restrict a1)
{
  unsigned int i, n = 0;
  __m256i f0, f1, g0, g1;
  uint32_t bad;
  uint64_t idx;
  const __m256i low = _mm256_set1_epi32(-GAMMA2_32);
  const __m256i high = _mm256_set1_epi32(GAMMA2_32);

  for(i = 0; i < N/8; ++i) {
    f0 = _mm256_load_si256(&a0[i]);
    f1 = _mm256_load_si256(&a1[i]);
    g0 = _mm256_abs_epi32(f0);
    g0 = _mm256_cmpgt_epi32(g0,high);
    g1 = _mm256_cmpeq_epi32(f0,low);
    g1 = _mm256_sign_epi32(g1,f1);
    g0 = _mm256_or_si256(g0,g1);

    bad = _mm256_movemask_ps((__m256)g0);
    memcpy(&idx,idxlut[bad],8);
    idx += (uint64_t)0x0808080808080808*i;
    memcpy(&hint[n],&idx,8);
    n += _mm_popcnt_u32(bad);
  }

  return n;
}
#endif

/*************************************************
* Name:        use_hint
*
* Description: Correct high parts according to hint.
*
* Arguments:   - __m256i *b: output array of length N/8 with corrected high parts
*              - const __m256i *a: input array of length N/8
*              - const __m256i *a: input array of length N/8 with hint bits
*
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
void use_hint_avx_88(__m256i *b, const __m256i *a, const __m256i * restrict hint) {
  unsigned int i;
  __m256i a0[N/8];
  __m256i f,g,h,t;
  const __m256i zero = _mm256_setzero_si256();
  const __m256i max = _mm256_set1_epi32(43);

  decompose_avx_88(b, a0, a);
  for(i=0;i<N/8;i++) {
    f = _mm256_load_si256(&a0[i]);
    g = _mm256_load_si256(&b[i]);
    h = _mm256_load_si256(&hint[i]);
    t = _mm256_blendv_epi32(zero,h,f);
    t = _mm256_slli_epi32(t,1);
    h = _mm256_sub_epi32(h,t);
    g = _mm256_add_epi32(g,h);
    g = _mm256_blendv_epi32(g,max,g);
    f = _mm256_cmpgt_epi32(g,max);
    g = _mm256_blendv_epi32(g,zero,f);
    _mm256_store_si256(&b[i],g);
  }
}
#endif

#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
void use_hint_avx_32(__m256i *b, const __m256i *a, const __m256i * restrict hint) {
  unsigned int i;
  __m256i a0[N/8];
  __m256i f,g,h,t;
  const __m256i zero = _mm256_setzero_si256();
  const __m256i mask = _mm256_set1_epi32(15);

  decompose_avx_32(b, a0, a);
  for(i=0;i<N/8;i++) {
    f = _mm256_load_si256(&a0[i]);
    g = _mm256_load_si256(&b[i]);
    h = _mm256_load_si256(&hint[i]);
    t = _mm256_blendv_epi32(zero,h,f);
    t = _mm256_slli_epi32(t,1);
    h = _mm256_sub_epi32(h,t);
    g = _mm256_add_epi32(g,h);
    g = _mm256_and_si256(g,mask);
    _mm256_store_si256(&b[i],g);
  }
}
#endif

#include "keccakx4.c"

/*************** dilithium/avx2/poly.c */

#ifdef DBENCH
#include "test/cpucycles.h"
extern const uint64_t timing_overhead;
extern uint64_t *tred, *tadd, *tmul, *tround, *tsample, *tpack;
#define DBENCH_START() uint64_t time = cpucycles()
#define DBENCH_STOP(t) t += cpucycles() - time - timing_overhead
#else
#define DBENCH_START()
#define DBENCH_STOP(t)
#endif

/*************************************************
* Name:        poly_reduce
*
* Description: Inplace reduction of all coefficients of polynomial to
*              representative in [-6283009,6283008]. Assumes input
*              coefficients to be at most 2^31 - 2^22 - 1 in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_reduce(poly *a) {
  unsigned int i;
  __m256i f,g;
  const __m256i q = _mm256_load_si256(&qdata.vec[_8XQ/8]);
  const __m256i off = _mm256_set1_epi32(1<<22);
  DBENCH_START();

  for(i = 0; i < N/8; i++) {
    f = _mm256_load_si256(&a->vec[i]);
    g = _mm256_add_epi32(f,off);
    g = _mm256_srai_epi32(g,23);
    g = _mm256_mullo_epi32(g,q);
    f = _mm256_sub_epi32(f,g);
    _mm256_store_si256(&a->vec[i],f);
  }

  DBENCH_STOP(*tred);
}

/*************************************************
* Name:        poly_addq
*
* Description: For all coefficients of in/out polynomial add Q if
*              coefficient is negative.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_caddq(poly *a) {
  unsigned int i;
  __m256i f,g;
  const __m256i q = _mm256_load_si256(&qdata.vec[_8XQ/8]);
  const __m256i zero = _mm256_setzero_si256();
  DBENCH_START();

  for(i = 0; i < N/8; i++) {
    f = _mm256_load_si256(&a->vec[i]);
    g = _mm256_blendv_epi32(zero,q,f);
    f = _mm256_add_epi32(f,g);
    _mm256_store_si256(&a->vec[i],f);
  }

  DBENCH_STOP(*tred);
}

/*************************************************
* Name:        poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first summand
*              - const poly *b: pointer to second summand
**************************************************/
void poly_add(poly *c, const poly *a, const poly *b)  {
  unsigned int i;
  __m256i f,g;
  DBENCH_START();

  for(i = 0; i < N/8; i++) {
    f = _mm256_load_si256(&a->vec[i]);
    g = _mm256_load_si256(&b->vec[i]);
    f = _mm256_add_epi32(f,g);
    _mm256_store_si256(&c->vec[i],f);
  }

  DBENCH_STOP(*tadd);
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract polynomials. No modular reduction is
*              performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
void poly_sub(poly *c, const poly *a, const poly *b) {
  unsigned int i;
  __m256i f,g;
  DBENCH_START();

  for(i = 0; i < N/8; i++) {
    f = _mm256_load_si256(&a->vec[i]);
    g = _mm256_load_si256(&b->vec[i]);
    f = _mm256_sub_epi32(f,g);
    _mm256_store_si256(&c->vec[i],f);
  }

  DBENCH_STOP(*tadd);
}

/*************************************************
* Name:        poly_shiftl
*
* Description: Multiply polynomial by 2^D without modular reduction. Assumes
*              input coefficients to be less than 2^{31-D} in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_shiftl(poly *a) {
  unsigned int i;
  __m256i f;
  DBENCH_START();

  for(i = 0; i < N/8; i++) {
    f = _mm256_load_si256(&a->vec[i]);
    f = _mm256_slli_epi32(f,D);
    _mm256_store_si256(&a->vec[i],f);
  }

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        poly_ntt
*
* Description: Inplace forward NTT. Coefficients can grow by up to
*              8*Q in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_ntt(poly *a) {
  DBENCH_START();

  ntt_avx(a->vec, qdata.vec);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Inplace inverse NTT and multiplication by 2^{32}.
*              Input coefficients need to be less than Q in absolute
*              value and output coefficients are again bounded by Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_invntt_tomont(poly *a) {
  DBENCH_START();

  invntt_avx(a->vec, qdata.vec);

  DBENCH_STOP(*tmul);
}

void poly_nttunpack(poly *a) {
  DBENCH_START();

  nttunpack_avx(a->vec);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        poly_pointwise_montgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              by 2^{-32}.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
  DBENCH_START();

  pointwise_avx(c->vec, a->vec, b->vec, qdata.vec);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod^+ Q = c1*2^D + c0
*              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
*              positive standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients c0
*              - const poly *a: pointer to input polynomial
**************************************************/
void poly_power2round(poly *a1, poly *a0, const poly *a)
{
  DBENCH_START();

  power2round_avx(a1->vec, a0->vec, a->vec);

  DBENCH_STOP(*tround);
}

/*************************************************
* Name:        poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod^+ Q = c1*ALPHA + c0
*              with -ALPHA/2 < c0 <= ALPHA/2 except if c1 = (Q-1)/ALPHA where we
*              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
*              Assumes coefficients to be positive standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients c0
*              - const poly *a: pointer to input polynomial
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
void poly_decompose_88(poly *a1, poly *a0, const poly *a)
{
  DBENCH_START();

  decompose_avx_88(a1->vec, a0->vec, a->vec);

  DBENCH_STOP(*tround);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
void poly_decompose_32(poly *a1, poly *a0, const poly *a)
{
  DBENCH_START();

  decompose_avx_32(a1->vec, a0->vec, a->vec);

  DBENCH_STOP(*tround);
}
#endif

/*************************************************
* Name:        poly_make_hint
*
* Description: Compute hint array. The coefficients of which are the
*              indices of the coefficients of the input polynomial
*              whose low bits overflow into the high bits.
*
* Arguments:   - uint8_t *h: pointer to output hint array (preallocated of length N)
*              - const poly *a0: pointer to low part of input polynomial
*              - const poly *a1: pointer to high part of input polynomial
*
* Returns number of hints, i.e. length of hint array.
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
unsigned int poly_make_hint_88(uint8_t hint[N], const poly *a0, const poly *a1)
{
  unsigned int r;
  DBENCH_START();

  r = make_hint_avx_88(hint, a0->vec, a1->vec);

  DBENCH_STOP(*tround);
  return r;
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
unsigned int poly_make_hint_32(uint8_t hint[N], const poly *a0, const poly *a1)
{
  unsigned int r;
  DBENCH_START();

  r = make_hint_avx_32(hint, a0->vec, a1->vec);

  DBENCH_STOP(*tround);
  return r;
}
#endif

/*************************************************
* Name:        poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - poly *b: pointer to output polynomial with corrected high bits
*              - const poly *a: pointer to input polynomial
*              - const poly *h: pointer to input hint polynomial
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
void poly_use_hint_88(poly *b, const poly *a, const poly *h)
{
  DBENCH_START();

  use_hint_avx_88(b->vec, a->vec, h->vec);

  DBENCH_STOP(*tround);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
void poly_use_hint_32(poly *b, const poly *a, const poly *h)
{
  DBENCH_START();

  use_hint_avx_32(b->vec, a->vec, h->vec);

  DBENCH_STOP(*tround);
}
#endif

/*************************************************
* Name:        poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input polynomial to be reduced by poly_reduce().
*
* Arguments:   - const poly *a: pointer to polynomial
*              - int32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
**************************************************/
int poly_chknorm(const poly *a, int32_t B) {
  unsigned int i;
  int r;
  __m256i f,t;
  const __m256i bound = _mm256_set1_epi32(B-1);
  DBENCH_START();

  if(B > (Q-1)/8)
    return 1;

  t = _mm256_setzero_si256();
  for(i = 0; i < N/8; i++) {
    f = _mm256_load_si256(&a->vec[i]);
    f = _mm256_abs_epi32(f);
    f = _mm256_cmpgt_epi32(f,bound);
    t = _mm256_or_si256(t,f);
  }

  r = 1 - _mm256_testz_si256(t,t);
  DBENCH_STOP(*tsample);
  return r;
}

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [0, Q-1] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_uniform(int32_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t;
  DBENCH_START();

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if(t < Q)
      a[ctr++] = t;
  }

  DBENCH_STOP(*tsample);
  return ctr;
}

/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,Q-1] by performing rejection sampling on the
*              output stream of SHAKE256(seed|nonce)
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void poly_uniform_4x(poly *a0,
                     poly *a1,
                     poly *a2,
                     poly *a3,
                     const uint8_t seed[32],
                     uint16_t nonce0,
                     uint16_t nonce1,
                     uint16_t nonce2,
                     uint16_t nonce3)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_BUFLEN+8) buf[4];
  keccakx4_state state;
  __m256i f;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec,f);
  _mm256_store_si256(buf[1].vec,f);
  _mm256_store_si256(buf[2].vec,f);
  _mm256_store_si256(buf[3].vec,f);

  buf[0].coeffs[SEEDBYTES+0] = nonce0;
  buf[0].coeffs[SEEDBYTES+1] = nonce0 >> 8;
  buf[1].coeffs[SEEDBYTES+0] = nonce1;
  buf[1].coeffs[SEEDBYTES+1] = nonce1 >> 8;
  buf[2].coeffs[SEEDBYTES+0] = nonce2;
  buf[2].coeffs[SEEDBYTES+1] = nonce2 >> 8;
  buf[3].coeffs[SEEDBYTES+0] = nonce3;
  buf[3].coeffs[SEEDBYTES+1] = nonce3 >> 8;

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, SEEDBYTES + 2);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a0->coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a1->coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a2->coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a3->coeffs, buf[3].coeffs);

  while(ctr0 < N || ctr1 < N || ctr2 < N || ctr3 < N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a0->coeffs + ctr0, N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a1->coeffs + ctr1, N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a2->coeffs + ctr2, N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a3->coeffs + ctr3, N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }
}

/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-ETA, ETA] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2 || DILITHIUM_MODE == 5
static unsigned int rej_eta_2(int32_t *a,
                              unsigned int len,
                              const uint8_t *buf,
                              unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t0, t1;
  DBENCH_START();

  ctr = pos = 0;
  while(ctr < len && pos < buflen) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

    if(t0 < 15) {
      t0 = t0 - (205*t0 >> 10)*5;
      a[ctr++] = 2 - t0;
    }
    if(t1 < 15 && ctr < len) {
      t1 = t1 - (205*t1 >> 10)*5;
      a[ctr++] = 2 - t1;
    }
  }

  DBENCH_STOP(*tsample);
  return ctr;
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3
static unsigned int rej_eta_4(int32_t *a,
                              unsigned int len,
                              const uint8_t *buf,
                              unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t0, t1;
  DBENCH_START();

  ctr = pos = 0;
  while(ctr < len && pos < buflen) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

    if(t0 < 9)
      a[ctr++] = 4 - t0;
    if(t1 < 9 && ctr < len)
      a[ctr++] = 4 - t1;
  }

  DBENCH_STOP(*tsample);
  return ctr;
}
#endif

/*************************************************
* Name:        poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-ETA,ETA] by performing rejection sampling using the
*              output stream of SHAKE256(seed|nonce)
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2 || DILITHIUM_MODE == 5
static
void poly_uniform_eta_4x_2(poly *a0,
                         poly *a1,
                         poly *a2,
                         poly *a3,
                         const uint8_t seed[64],
                         uint16_t nonce0,
                         uint16_t nonce1,
                         uint16_t nonce2,
                         uint16_t nonce3)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_ETA_BUFLEN_2) buf[4];

  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)&seed[0]);
  _mm256_store_si256(&buf[0].vec[0],f);
  _mm256_store_si256(&buf[1].vec[0],f);
  _mm256_store_si256(&buf[2].vec[0],f);
  _mm256_store_si256(&buf[3].vec[0],f);
  f = _mm256_loadu_si256((__m256i *)&seed[32]);
  _mm256_store_si256(&buf[0].vec[1],f);
  _mm256_store_si256(&buf[1].vec[1],f);
  _mm256_store_si256(&buf[2].vec[1],f);
  _mm256_store_si256(&buf[3].vec[1],f);

  buf[0].coeffs[64] = nonce0;
  buf[0].coeffs[65] = nonce0 >> 8;
  buf[1].coeffs[64] = nonce1;
  buf[1].coeffs[65] = nonce1 >> 8;
  buf[2].coeffs[64] = nonce2;
  buf[2].coeffs[65] = nonce2 >> 8;
  buf[3].coeffs[64] = nonce3;
  buf[3].coeffs[65] = nonce3 >> 8;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 66);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_ETA_NBLOCKS_2, &state);

  ctr0 = rej_eta_avx_2(a0->coeffs, buf[0].coeffs);
  ctr1 = rej_eta_avx_2(a1->coeffs, buf[1].coeffs);
  ctr2 = rej_eta_avx_2(a2->coeffs, buf[2].coeffs);
  ctr3 = rej_eta_avx_2(a3->coeffs, buf[3].coeffs);

  while(ctr0 < N || ctr1 < N || ctr2 < N || ctr3 < N) {
    shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_eta_2(a0->coeffs + ctr0, N - ctr0, buf[0].coeffs, SHAKE256_RATE);
    ctr1 += rej_eta_2(a1->coeffs + ctr1, N - ctr1, buf[1].coeffs, SHAKE256_RATE);
    ctr2 += rej_eta_2(a2->coeffs + ctr2, N - ctr2, buf[2].coeffs, SHAKE256_RATE);
    ctr3 += rej_eta_2(a3->coeffs + ctr3, N - ctr3, buf[3].coeffs, SHAKE256_RATE);
  }
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3
void poly_uniform_eta_4x_4(poly *a0,
                         poly *a1,
                         poly *a2,
                         poly *a3,
                         const uint8_t seed[64],
                         uint16_t nonce0,
                         uint16_t nonce1,
                         uint16_t nonce2,
                         uint16_t nonce3)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_ETA_BUFLEN_4) buf[4];

  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)&seed[0]);
  _mm256_store_si256(&buf[0].vec[0],f);
  _mm256_store_si256(&buf[1].vec[0],f);
  _mm256_store_si256(&buf[2].vec[0],f);
  _mm256_store_si256(&buf[3].vec[0],f);
  f = _mm256_loadu_si256((__m256i *)&seed[32]);
  _mm256_store_si256(&buf[0].vec[1],f);
  _mm256_store_si256(&buf[1].vec[1],f);
  _mm256_store_si256(&buf[2].vec[1],f);
  _mm256_store_si256(&buf[3].vec[1],f);

  buf[0].coeffs[64] = nonce0;
  buf[0].coeffs[65] = nonce0 >> 8;
  buf[1].coeffs[64] = nonce1;
  buf[1].coeffs[65] = nonce1 >> 8;
  buf[2].coeffs[64] = nonce2;
  buf[2].coeffs[65] = nonce2 >> 8;
  buf[3].coeffs[64] = nonce3;
  buf[3].coeffs[65] = nonce3 >> 8;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 66);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_ETA_NBLOCKS_4, &state);

  ctr0 = rej_eta_avx_4(a0->coeffs, buf[0].coeffs);
  ctr1 = rej_eta_avx_4(a1->coeffs, buf[1].coeffs);
  ctr2 = rej_eta_avx_4(a2->coeffs, buf[2].coeffs);
  ctr3 = rej_eta_avx_4(a3->coeffs, buf[3].coeffs);

  while(ctr0 < N || ctr1 < N || ctr2 < N || ctr3 < N) {
    shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_eta_4(a0->coeffs + ctr0, N - ctr0, buf[0].coeffs, SHAKE256_RATE);
    ctr1 += rej_eta_4(a1->coeffs + ctr1, N - ctr1, buf[1].coeffs, SHAKE256_RATE);
    ctr2 += rej_eta_4(a2->coeffs + ctr2, N - ctr2, buf[2].coeffs, SHAKE256_RATE);
    ctr3 += rej_eta_4(a3->coeffs + ctr3, N - ctr3, buf[3].coeffs, SHAKE256_RATE);
  }
}
#endif

/*************************************************
* Name:        poly_uniform_gamma1
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
*              of SHAKE256(seed|nonce)
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
#if 0 // !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
static
void poly_uniform_gamma1_17(poly *a,
                            const uint8_t seed[CRHBYTES],
                            uint16_t nonce)
{
  ALIGNED_UINT8(POLY_UNIFORM_GAMMA1_NBLOCKS_17*STREAM256_BLOCKBYTES+14) buf;
  stream256_state state;

  stream256_init(&state, seed, nonce);
  /* polyz_unpack reads 14 additional bytes */
  stream256_squeezeblocks(buf.coeffs, POLY_UNIFORM_GAMMA1_NBLOCKS_17, &state);
  polyz_unpack_17(a, buf.coeffs);
  stream256_close(&state);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
#define POLY_UNIFORM_GAMMA1_NBLOCKS_19 ((POLYZ_PACKEDBYTES_19 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
static void polyz_unpack_19(poly *r, const uint8_t *a);/* Forward declarations */
static
void poly_uniform_gamma1_19(poly *a,
                            const uint8_t seed[CRHBYTES],
                            uint16_t nonce)
{
  ALIGNED_UINT8(POLY_UNIFORM_GAMMA1_NBLOCKS_19*STREAM256_BLOCKBYTES+14) buf;
  stream256_state state;

  stream256_init(&state, seed, nonce);
  /* polyz_unpack reads 14 additional bytes */
  stream256_squeezeblocks(buf.coeffs, POLY_UNIFORM_GAMMA1_NBLOCKS_19, &state);
  polyz_unpack_19(a, buf.coeffs);
  stream256_close(&state);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
#define POLY_UNIFORM_GAMMA1_NBLOCKS_17 ((POLYZ_PACKEDBYTES_17 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
static void polyz_unpack_17(poly *r, const uint8_t *a);/* Forward declarations */
void poly_uniform_gamma1_4x_17(poly *a0,
                            poly *a1,
                            poly *a2,
                            poly *a3,
                            const uint8_t seed[64],
                            uint16_t nonce0,
                            uint16_t nonce1,
                            uint16_t nonce2,
                            uint16_t nonce3)
{
  ALIGNED_UINT8(POLY_UNIFORM_GAMMA1_NBLOCKS_17*STREAM256_BLOCKBYTES+14) buf[4];
  keccakx4_state state;
  __m256i f;

  f = _mm256_loadu_si256((__m256i *)&seed[0]);
  _mm256_store_si256(&buf[0].vec[0],f);
  _mm256_store_si256(&buf[1].vec[0],f);
  _mm256_store_si256(&buf[2].vec[0],f);
  _mm256_store_si256(&buf[3].vec[0],f);
  f = _mm256_loadu_si256((__m256i *)&seed[32]);
  _mm256_store_si256(&buf[0].vec[1],f);
  _mm256_store_si256(&buf[1].vec[1],f);
  _mm256_store_si256(&buf[2].vec[1],f);
  _mm256_store_si256(&buf[3].vec[1],f);

  buf[0].coeffs[64] = nonce0;
  buf[0].coeffs[65] = nonce0 >> 8;
  buf[1].coeffs[64] = nonce1;
  buf[1].coeffs[65] = nonce1 >> 8;
  buf[2].coeffs[64] = nonce2;
  buf[2].coeffs[65] = nonce2 >> 8;
  buf[3].coeffs[64] = nonce3;
  buf[3].coeffs[65] = nonce3 >> 8;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 66);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, POLY_UNIFORM_GAMMA1_NBLOCKS_17, &state);

  polyz_unpack_17(a0, buf[0].coeffs);
  polyz_unpack_17(a1, buf[1].coeffs);
  polyz_unpack_17(a2, buf[2].coeffs);
  polyz_unpack_17(a3, buf[3].coeffs);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
void poly_uniform_gamma1_4x_19(poly *a0,
                            poly *a1,
                            poly *a2,
                            poly *a3,
                            const uint8_t seed[64],
                            uint16_t nonce0,
                            uint16_t nonce1,
                            uint16_t nonce2,
                            uint16_t nonce3)
{
  ALIGNED_UINT8(POLY_UNIFORM_GAMMA1_NBLOCKS_19*STREAM256_BLOCKBYTES+14) buf[4];
  keccakx4_state state;
  __m256i f;

  f = _mm256_loadu_si256((__m256i *)&seed[0]);
  _mm256_store_si256(&buf[0].vec[0],f);
  _mm256_store_si256(&buf[1].vec[0],f);
  _mm256_store_si256(&buf[2].vec[0],f);
  _mm256_store_si256(&buf[3].vec[0],f);
  f = _mm256_loadu_si256((__m256i *)&seed[32]);
  _mm256_store_si256(&buf[0].vec[1],f);
  _mm256_store_si256(&buf[1].vec[1],f);
  _mm256_store_si256(&buf[2].vec[1],f);
  _mm256_store_si256(&buf[3].vec[1],f);

  buf[0].coeffs[64] = nonce0;
  buf[0].coeffs[65] = nonce0 >> 8;
  buf[1].coeffs[64] = nonce1;
  buf[1].coeffs[65] = nonce1 >> 8;
  buf[2].coeffs[64] = nonce2;
  buf[2].coeffs[65] = nonce2 >> 8;
  buf[3].coeffs[64] = nonce3;
  buf[3].coeffs[65] = nonce3 >> 8;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 66);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, POLY_UNIFORM_GAMMA1_NBLOCKS_19, &state);

  polyz_unpack_19(a0, buf[0].coeffs);
  polyz_unpack_19(a1, buf[1].coeffs);
  polyz_unpack_19(a2, buf[2].coeffs);
  polyz_unpack_19(a3, buf[3].coeffs);
}
#endif

/*************************************************
* Name:        polyeta_pack
*
* Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYETA_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2 || DILITHIUM_MODE == 5
static
void polyeta_pack_2(uint8_t r[POLYETA_PACKEDBYTES_2], const poly * restrict a) {
  unsigned int i;
  uint8_t t[8];
  DBENCH_START();

  for(i = 0; i < N/8; ++i) {
    t[0] = ETA2 - a->coeffs[8*i+0];
    t[1] = ETA2 - a->coeffs[8*i+1];
    t[2] = ETA2 - a->coeffs[8*i+2];
    t[3] = ETA2 - a->coeffs[8*i+3];
    t[4] = ETA2 - a->coeffs[8*i+4];
    t[5] = ETA2 - a->coeffs[8*i+5];
    t[6] = ETA2 - a->coeffs[8*i+6];
    t[7] = ETA2 - a->coeffs[8*i+7];

    r[3*i+0]  = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[3*i+1]  = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[3*i+2]  = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }

  DBENCH_STOP(*tpack);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3
static
void polyeta_pack_4(uint8_t r[POLYETA_PACKEDBYTES_4], const poly * restrict a) {
  unsigned int i;
  uint8_t t[8];
  DBENCH_START();

  for(i = 0; i < N/2; ++i) {
    t[0] = ETA4 - a->coeffs[2*i+0];
    t[1] = ETA4 - a->coeffs[2*i+1];
    r[i] = t[0] | (t[1] << 4);
  }

  DBENCH_STOP(*tpack);
}
#endif

/*************************************************
* Name:        polyeta_unpack
*
* Description: Unpack polynomial with coefficients in [-ETA,ETA].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2 || DILITHIUM_MODE == 5
static
void polyeta_unpack_2(poly * restrict r, const uint8_t a[POLYETA_PACKEDBYTES_2]) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N/8; ++i) {
    r->coeffs[8*i+0] =  (a[3*i+0] >> 0) & 7;
    r->coeffs[8*i+1] =  (a[3*i+0] >> 3) & 7;
    r->coeffs[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7;
    r->coeffs[8*i+3] =  (a[3*i+1] >> 1) & 7;
    r->coeffs[8*i+4] =  (a[3*i+1] >> 4) & 7;
    r->coeffs[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7;
    r->coeffs[8*i+6] =  (a[3*i+2] >> 2) & 7;
    r->coeffs[8*i+7] =  (a[3*i+2] >> 5) & 7;

    r->coeffs[8*i+0] = ETA2 - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = ETA2 - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = ETA2 - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = ETA2 - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = ETA2 - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = ETA2 - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = ETA2 - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = ETA2 - r->coeffs[8*i+7];
  }

  DBENCH_STOP(*tpack);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3
static
void polyeta_unpack_4(poly * restrict r, const uint8_t a[POLYETA_PACKEDBYTES_4]) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N/2; ++i) {
    r->coeffs[2*i+0] = a[i] & 0x0F;
    r->coeffs[2*i+1] = a[i] >> 4;
    r->coeffs[2*i+0] = ETA4 - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = ETA4 - r->coeffs[2*i+1];
  }

  DBENCH_STOP(*tpack);
}
#endif

/*************************************************
* Name:        polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
*              Input coefficients are assumed to be positive standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYT1_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
static
void polyt1_pack(uint8_t r[POLYT1_PACKEDBYTES], const poly * restrict a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N/4; ++i) {
    r[5*i+0] = (a->coeffs[4*i+0] >> 0);
    r[5*i+1] = (a->coeffs[4*i+0] >> 8) | (a->coeffs[4*i+1] << 2);
    r[5*i+2] = (a->coeffs[4*i+1] >> 6) | (a->coeffs[4*i+2] << 4);
    r[5*i+3] = (a->coeffs[4*i+2] >> 4) | (a->coeffs[4*i+3] << 6);
    r[5*i+4] = (a->coeffs[4*i+3] >> 2);
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyt1_unpack
*
* Description: Unpack polynomial t1 with 10-bit coefficients.
*              Output coefficients are positive standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
static
void polyt1_unpack(poly * restrict r, const uint8_t a[POLYT1_PACKEDBYTES]) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N/4; ++i) {
    r->coeffs[4*i+0] = ((a[5*i+0] >> 0) | ((uint32_t)a[5*i+1] << 8)) & 0x3FF;
    r->coeffs[4*i+1] = ((a[5*i+1] >> 2) | ((uint32_t)a[5*i+2] << 6)) & 0x3FF;
    r->coeffs[4*i+2] = ((a[5*i+2] >> 4) | ((uint32_t)a[5*i+3] << 4)) & 0x3FF;
    r->coeffs[4*i+3] = ((a[5*i+3] >> 6) | ((uint32_t)a[5*i+4] << 2)) & 0x3FF;
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYT0_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
static
void polyt0_pack(uint8_t r[POLYT0_PACKEDBYTES], const poly * restrict a) {
  unsigned int i;
  uint32_t t[8];
  DBENCH_START();

  for(i = 0; i < N/8; ++i) {
    t[0] = (1 << (D-1)) - a->coeffs[8*i+0];
    t[1] = (1 << (D-1)) - a->coeffs[8*i+1];
    t[2] = (1 << (D-1)) - a->coeffs[8*i+2];
    t[3] = (1 << (D-1)) - a->coeffs[8*i+3];
    t[4] = (1 << (D-1)) - a->coeffs[8*i+4];
    t[5] = (1 << (D-1)) - a->coeffs[8*i+5];
    t[6] = (1 << (D-1)) - a->coeffs[8*i+6];
    t[7] = (1 << (D-1)) - a->coeffs[8*i+7];

    r[13*i+ 0]  =  t[0];
    r[13*i+ 1]  =  t[0] >>  8;
    r[13*i+ 1] |=  t[1] <<  5;
    r[13*i+ 2]  =  t[1] >>  3;
    r[13*i+ 3]  =  t[1] >> 11;
    r[13*i+ 3] |=  t[2] <<  2;
    r[13*i+ 4]  =  t[2] >>  6;
    r[13*i+ 4] |=  t[3] <<  7;
    r[13*i+ 5]  =  t[3] >>  1;
    r[13*i+ 6]  =  t[3] >>  9;
    r[13*i+ 6] |=  t[4] <<  4;
    r[13*i+ 7]  =  t[4] >>  4;
    r[13*i+ 8]  =  t[4] >> 12;
    r[13*i+ 8] |=  t[5] <<  1;
    r[13*i+ 9]  =  t[5] >>  7;
    r[13*i+ 9] |=  t[6] <<  6;
    r[13*i+10]  =  t[6] >>  2;
    r[13*i+11]  =  t[6] >> 10;
    r[13*i+11] |=  t[7] <<  3;
    r[13*i+12]  =  t[7] >>  5;
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
static
void polyt0_unpack(poly * restrict r, const uint8_t a[POLYT0_PACKEDBYTES]) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N/8; ++i) {
    r->coeffs[8*i+0]  = a[13*i+0];
    r->coeffs[8*i+0] |= (uint32_t)a[13*i+1] << 8;
    r->coeffs[8*i+0] &= 0x1FFF;

    r->coeffs[8*i+1]  = a[13*i+1] >> 5;
    r->coeffs[8*i+1] |= (uint32_t)a[13*i+2] << 3;
    r->coeffs[8*i+1] |= (uint32_t)a[13*i+3] << 11;
    r->coeffs[8*i+1] &= 0x1FFF;

    r->coeffs[8*i+2]  = a[13*i+3] >> 2;
    r->coeffs[8*i+2] |= (uint32_t)a[13*i+4] << 6;
    r->coeffs[8*i+2] &= 0x1FFF;

    r->coeffs[8*i+3]  = a[13*i+4] >> 7;
    r->coeffs[8*i+3] |= (uint32_t)a[13*i+5] << 1;
    r->coeffs[8*i+3] |= (uint32_t)a[13*i+6] << 9;
    r->coeffs[8*i+3] &= 0x1FFF;

    r->coeffs[8*i+4]  = a[13*i+6] >> 4;
    r->coeffs[8*i+4] |= (uint32_t)a[13*i+7] << 4;
    r->coeffs[8*i+4] |= (uint32_t)a[13*i+8] << 12;
    r->coeffs[8*i+4] &= 0x1FFF;

    r->coeffs[8*i+5]  = a[13*i+8] >> 1;
    r->coeffs[8*i+5] |= (uint32_t)a[13*i+9] << 7;
    r->coeffs[8*i+5] &= 0x1FFF;

    r->coeffs[8*i+6]  = a[13*i+9] >> 6;
    r->coeffs[8*i+6] |= (uint32_t)a[13*i+10] << 2;
    r->coeffs[8*i+6] |= (uint32_t)a[13*i+11] << 10;
    r->coeffs[8*i+6] &= 0x1FFF;

    r->coeffs[8*i+7]  = a[13*i+11] >> 3;
    r->coeffs[8*i+7] |= (uint32_t)a[13*i+12] << 5;
    r->coeffs[8*i+7] &= 0x1FFF;

    r->coeffs[8*i+0] = (1 << (D-1)) - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = (1 << (D-1)) - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = (1 << (D-1)) - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = (1 << (D-1)) - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = (1 << (D-1)) - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = (1 << (D-1)) - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = (1 << (D-1)) - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = (1 << (D-1)) - r->coeffs[8*i+7];
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyz_pack
*
* Description: Bit-pack polynomial with coefficients
*              in [-(GAMMA1 - 1), GAMMA1].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYZ_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
static
void polyz_pack_17(uint8_t *r, const poly *a) {
  unsigned int i;
  uint32_t t[4];
  DBENCH_START();

  for(i = 0; i < N/4; ++i) {
    t[0] = GAMMA1_17 - a->coeffs[4*i+0];
    t[1] = GAMMA1_17 - a->coeffs[4*i+1];
    t[2] = GAMMA1_17 - a->coeffs[4*i+2];
    t[3] = GAMMA1_17 - a->coeffs[4*i+3];

    r[9*i+0]  = t[0];
    r[9*i+1]  = t[0] >> 8;
    r[9*i+2]  = t[0] >> 16;
    r[9*i+2] |= t[1] << 2;
    r[9*i+3]  = t[1] >> 6;
    r[9*i+4]  = t[1] >> 14;
    r[9*i+4] |= t[2] << 4;
    r[9*i+5]  = t[2] >> 4;
    r[9*i+6]  = t[2] >> 12;
    r[9*i+6] |= t[3] << 6;
    r[9*i+7]  = t[3] >> 2;
    r[9*i+8]  = t[3] >> 10;
  }

  DBENCH_STOP(*tpack);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
static
void polyz_pack_19(uint8_t *r, const poly *a) {
  unsigned int i;
  uint32_t t[4];
  DBENCH_START();

  for(i = 0; i < N/2; ++i) {
    t[0] = GAMMA1_19 - a->coeffs[2*i+0];
    t[1] = GAMMA1_19 - a->coeffs[2*i+1];

    r[5*i+0]  = t[0];
    r[5*i+1]  = t[0] >> 8;
    r[5*i+2]  = t[0] >> 16;
    r[5*i+2] |= t[1] << 4;
    r[5*i+3]  = t[1] >> 4;
    r[5*i+4]  = t[1] >> 12;
  }

  DBENCH_STOP(*tpack);
}
#endif

/*************************************************
* Name:        polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(GAMMA1 - 1), GAMMA1].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
static
void polyz_unpack_17(poly * restrict r, const uint8_t *a) {
  unsigned int i;
  __m256i f;
  const __m256i shufbidx = _mm256_set_epi8(-1, 9, 8, 7,-1, 7, 6, 5,-1, 5, 4, 3,-1, 3, 2, 1,
                                           -1, 8, 7, 6,-1, 6, 5, 4,-1, 4, 3, 2,-1, 2, 1, 0);
  const __m256i srlvdidx = _mm256_set_epi32(6,4,2,0,6,4,2,0);
  const __m256i mask = _mm256_set1_epi32(0x3FFFF);
  const __m256i gamma1 = _mm256_set1_epi32(GAMMA1_17);
  DBENCH_START();

  for(i = 0; i < N/8; i++) {
    f = _mm256_loadu_si256((__m256i *)&a[18*i]);
    f = _mm256_permute4x64_epi64(f,0x94);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_srlv_epi32(f,srlvdidx);
    f = _mm256_and_si256(f,mask);
    f = _mm256_sub_epi32(gamma1,f);
    _mm256_store_si256(&r->vec[i],f);
  }

  DBENCH_STOP(*tpack);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
static
void polyz_unpack_19(poly * restrict r, const uint8_t *a) {
  unsigned int i;
  __m256i f;
  const __m256i shufbidx = _mm256_set_epi8(-1,11,10, 9,-1, 9, 8, 7,-1, 6, 5, 4,-1, 4, 3, 2,
                                           -1, 9, 8, 7,-1, 7, 6, 5,-1, 4, 3, 2,-1, 2, 1, 0);
  const __m256i srlvdidx = _mm256_set1_epi64x((uint64_t)4 << 32);
  const __m256i mask = _mm256_set1_epi32(0xFFFFF);
  const __m256i gamma1 = _mm256_set1_epi32(GAMMA1_19);
  DBENCH_START();

  for(i = 0; i < N/8; i++) {
    f = _mm256_loadu_si256((__m256i *)&a[20*i]);
    f = _mm256_permute4x64_epi64(f,0x94);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_srlv_epi32(f,srlvdidx);
    f = _mm256_and_si256(f,mask);
    f = _mm256_sub_epi32(gamma1,f);
    _mm256_store_si256(&r->vec[i],f);
  }

  DBENCH_STOP(*tpack);
}
#endif

/*************************************************
* Name:        polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
*              Input coefficients are assumed to be positive standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYW1_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 2
void polyw1_pack_88(uint8_t *r, const poly * restrict a) {
  unsigned int i;
  __m256i f0,f1,f2,f3;
  const __m256i shift1 = _mm256_set1_epi16((64 << 8) + 1);
  const __m256i shift2 = _mm256_set1_epi32((4096 << 16) + 1);
  const __m256i shufdidx1 = _mm256_set_epi32(7,3,6,2,5,1,4,0);
  const __m256i shufdidx2 = _mm256_set_epi32(-1,-1,6,5,4,2,1,0);
  const __m256i shufbidx = _mm256_set_epi8(-1,-1,-1,-1,14,13,12,10, 9, 8, 6, 5, 4, 2, 1, 0,
                                           -1,-1,-1,-1,14,13,12,10, 9, 8, 6, 5, 4, 2, 1, 0);
  DBENCH_START();

  for(i = 0; i < N/32; i++) {
    f0 = _mm256_load_si256(&a->vec[4*i+0]);
    f1 = _mm256_load_si256(&a->vec[4*i+1]);
    f2 = _mm256_load_si256(&a->vec[4*i+2]);
    f3 = _mm256_load_si256(&a->vec[4*i+3]);
    f0 = _mm256_packus_epi32(f0,f1);
    f1 = _mm256_packus_epi32(f2,f3);
    f0 = _mm256_packus_epi16(f0,f1);
    f0 = _mm256_maddubs_epi16(f0,shift1);
    f0 = _mm256_madd_epi16(f0,shift2);
    f0 = _mm256_permutevar8x32_epi32(f0,shufdidx1);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    f0 = _mm256_permutevar8x32_epi32(f0,shufdidx2);
    _mm256_storeu_si256((__m256i *)&r[24*i],f0);
  }

  DBENCH_STOP(*tpack);
}
#endif
#if !defined(DILITHIUM_MODE) || DILITHIUM_MODE == 3 || DILITHIUM_MODE == 5
void polyw1_pack_32(uint8_t *r, const poly * restrict a) {
  unsigned int i;
  __m256i f0, f1, f2, f3, f4, f5, f6, f7;
  const __m256i shift = _mm256_set1_epi16((16 << 8) + 1);
  const __m256i shufbidx = _mm256_set_epi8(15,14, 7, 6,13,12, 5, 4,11,10, 3, 2, 9, 8, 1, 0,
                                           15,14, 7, 6,13,12, 5, 4,11,10, 3, 2, 9, 8, 1, 0);
  DBENCH_START();

  for(i = 0; i < N/64; ++i) {
    f0 = _mm256_load_si256(&a->vec[8*i+0]);
    f1 = _mm256_load_si256(&a->vec[8*i+1]);
    f2 = _mm256_load_si256(&a->vec[8*i+2]);
    f3 = _mm256_load_si256(&a->vec[8*i+3]);
    f4 = _mm256_load_si256(&a->vec[8*i+4]);
    f5 = _mm256_load_si256(&a->vec[8*i+5]);
    f6 = _mm256_load_si256(&a->vec[8*i+6]);
    f7 = _mm256_load_si256(&a->vec[8*i+7]);
    f0 = _mm256_packus_epi32(f0,f1);
    f1 = _mm256_packus_epi32(f2,f3);
    f2 = _mm256_packus_epi32(f4,f5);
    f3 = _mm256_packus_epi32(f6,f7);
    f0 = _mm256_packus_epi16(f0,f1);
    f1 = _mm256_packus_epi16(f2,f3);
    f0 = _mm256_maddubs_epi16(f0,shift);
    f1 = _mm256_maddubs_epi16(f1,shift);
    f0 = _mm256_packus_epi16(f0,f1);
    f0 = _mm256_permute4x64_epi64(f0,0xD8);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    _mm256_storeu_si256((__m256i *)&r[32*i], f0);
  }

  DBENCH_STOP(*tpack);
}
#endif


/*************** dilithium/avx2/consts.h */
asm (""
".equ _8XQ,          0\n"
".equ _8XQINV,       8\n"
".equ _8XDIV_QINV,  16\n"
".equ _8XDIV,       24\n"
".equ _ZETAS_QINV,  32\n"
".equ _ZETAS,      328\n"
);

/*************** dilithium/avx2/shuffle.inc */
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

/*************** dilithium/avx2/shuffle.S */
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
"#store\n"
"vmovdqa		%ymm9,(%rdi)\n"
"vmovdqa		%ymm8,32(%rdi)\n"
"vmovdqa		%ymm7,64(%rdi)\n"
"vmovdqa		%ymm6,96(%rdi)\n"
"vmovdqa		%ymm5,128(%rdi)\n"
"vmovdqa		%ymm4,160(%rdi)\n"
"vmovdqa		%ymm3,192(%rdi)\n"
"vmovdqa		%ymm11,224(%rdi)\n"
"\n"
"ret\n"
"\n"
".global nttunpack_avx\n"
"nttunpack_avx:\n"
"call		nttunpack128_avx\n"
"add		$256,%rdi\n"
"call		nttunpack128_avx\n"
"add		$256,%rdi\n"
"call		nttunpack128_avx\n"
"add		$256,%rdi\n"
"call		nttunpack128_avx\n"
"ret\n"
);

/*************** dilithium/avx2/pointwise.S */
asm (""
".text\n"
".global pointwise_avx\n"
"pointwise_avx:\n"
"#consts\n"
"vmovdqa		_8XQINV*4(%rcx),%ymm0\n"
"vmovdqa		_8XQ*4(%rcx),%ymm1\n"
"\n"
"xor		%eax,%eax\n"
"_looptop1:\n"
"#load\n"
"vmovdqa		(%rsi),%ymm2\n"
"vmovdqa		32(%rsi),%ymm4\n"
"vmovdqa		64(%rsi),%ymm6\n"
"vmovdqa		(%rdx),%ymm10\n"
"vmovdqa		32(%rdx),%ymm12\n"
"vmovdqa		64(%rdx),%ymm14\n"
"vpsrlq		$32,%ymm2,%ymm3\n"
"vpsrlq		$32,%ymm4,%ymm5\n"
"vmovshdup	%ymm6,%ymm7\n"
"vpsrlq		$32,%ymm10,%ymm11\n"
"vpsrlq		$32,%ymm12,%ymm13\n"
"vmovshdup	%ymm14,%ymm15\n"
"\n"
"#mul\n"
"vpmuldq		%ymm2,%ymm10,%ymm2\n"
"vpmuldq		%ymm3,%ymm11,%ymm3\n"
"vpmuldq		%ymm4,%ymm12,%ymm4\n"
"vpmuldq		%ymm5,%ymm13,%ymm5\n"
"vpmuldq		%ymm6,%ymm14,%ymm6\n"
"vpmuldq		%ymm7,%ymm15,%ymm7\n"
"\n"
"#reduce\n"
"vpmuldq		%ymm0,%ymm2,%ymm10\n"
"vpmuldq		%ymm0,%ymm3,%ymm11\n"
"vpmuldq		%ymm0,%ymm4,%ymm12\n"
"vpmuldq		%ymm0,%ymm5,%ymm13\n"
"vpmuldq		%ymm0,%ymm6,%ymm14\n"
"vpmuldq		%ymm0,%ymm7,%ymm15\n"
"vpmuldq		%ymm1,%ymm10,%ymm10\n"
"vpmuldq		%ymm1,%ymm11,%ymm11\n"
"vpmuldq		%ymm1,%ymm12,%ymm12\n"
"vpmuldq		%ymm1,%ymm13,%ymm13\n"
"vpmuldq		%ymm1,%ymm14,%ymm14\n"
"vpmuldq		%ymm1,%ymm15,%ymm15\n"
"vpsubq		%ymm10,%ymm2,%ymm2\n"
"vpsubq		%ymm11,%ymm3,%ymm3\n"
"vpsubq		%ymm12,%ymm4,%ymm4\n"
"vpsubq		%ymm13,%ymm5,%ymm5\n"
"vpsubq		%ymm14,%ymm6,%ymm6\n"
"vpsubq		%ymm15,%ymm7,%ymm7\n"
"vpsrlq		$32,%ymm2,%ymm2\n"
"vpsrlq		$32,%ymm4,%ymm4\n"
"vmovshdup	%ymm6,%ymm6\n"
"\n"
"#store\n"
"vpblendd	$0xAA,%ymm3,%ymm2,%ymm2\n"
"vpblendd	$0xAA,%ymm5,%ymm4,%ymm4\n"
"vpblendd	$0xAA,%ymm7,%ymm6,%ymm6\n"
"vmovdqa		%ymm2,(%rdi)\n"
"vmovdqa		%ymm4,32(%rdi)\n"
"vmovdqa		%ymm6,64(%rdi)\n"
"\n"
"add		$96,%rdi\n"
"add		$96,%rsi\n"
"add		$96,%rdx\n"
"add		$1,%eax\n"
"cmp		$10,%eax\n"
"jb 		_looptop1\n"
"\n"
"vmovdqa		(%rsi),%ymm2\n"
"vmovdqa		32(%rsi),%ymm4\n"
"vmovdqa		(%rdx),%ymm10\n"
"vmovdqa		32(%rdx),%ymm12\n"
"vpsrlq		$32,%ymm2,%ymm3\n"
"vpsrlq		$32,%ymm4,%ymm5\n"
"vmovshdup	%ymm10,%ymm11\n"
"vmovshdup	%ymm12,%ymm13\n"
"\n"
"#mul\n"
"vpmuldq		%ymm2,%ymm10,%ymm2\n"
"vpmuldq		%ymm3,%ymm11,%ymm3\n"
"vpmuldq		%ymm4,%ymm12,%ymm4\n"
"vpmuldq		%ymm5,%ymm13,%ymm5\n"
"\n"
"#reduce\n"
"vpmuldq		%ymm0,%ymm2,%ymm10\n"
"vpmuldq		%ymm0,%ymm3,%ymm11\n"
"vpmuldq		%ymm0,%ymm4,%ymm12\n"
"vpmuldq		%ymm0,%ymm5,%ymm13\n"
"vpmuldq		%ymm1,%ymm10,%ymm10\n"
"vpmuldq		%ymm1,%ymm11,%ymm11\n"
"vpmuldq		%ymm1,%ymm12,%ymm12\n"
"vpmuldq		%ymm1,%ymm13,%ymm13\n"
"vpsubq		%ymm10,%ymm2,%ymm2\n"
"vpsubq		%ymm11,%ymm3,%ymm3\n"
"vpsubq		%ymm12,%ymm4,%ymm4\n"
"vpsubq		%ymm13,%ymm5,%ymm5\n"
"vpsrlq		$32,%ymm2,%ymm2\n"
"vmovshdup	%ymm4,%ymm4\n"
"\n"
"#store\n"
"vpblendd	$0x55,%ymm2,%ymm3,%ymm2\n"
"vpblendd	$0x55,%ymm4,%ymm5,%ymm4\n"
"vmovdqa		%ymm2,(%rdi)\n"
"vmovdqa		%ymm4,32(%rdi)\n"
"\n"
"ret\n"
"\n"
".macro pointwise off\n"
"#load\n"
"vmovdqa		\\off(%rsi),%ymm6\n"
"vmovdqa		\\off+32(%rsi),%ymm8\n"
"vmovdqa		\\off(%rdx),%ymm10\n"
"vmovdqa		\\off+32(%rdx),%ymm12\n"
"vpsrlq		$32,%ymm6,%ymm7\n"
"vpsrlq		$32,%ymm8,%ymm9\n"
"vmovshdup	%ymm10,%ymm11\n"
"vmovshdup	%ymm12,%ymm13\n"
"\n"
"#mul\n"
"vpmuldq		%ymm6,%ymm10,%ymm6\n"
"vpmuldq		%ymm7,%ymm11,%ymm7\n"
"vpmuldq		%ymm8,%ymm12,%ymm8\n"
"vpmuldq		%ymm9,%ymm13,%ymm9\n"
".endm\n"
"\n"
".macro acc\n"
"vpaddq		%ymm6,%ymm2,%ymm2\n"
"vpaddq		%ymm7,%ymm3,%ymm3\n"
"vpaddq		%ymm8,%ymm4,%ymm4\n"
"vpaddq		%ymm9,%ymm5,%ymm5\n"
".endm\n"
"\n"
".global pointwise_acc_avx_2\n"
"pointwise_acc_avx_2:\n"
"#consts\n"
"vmovdqa		_8XQINV*4(%rcx),%ymm0\n"
"vmovdqa		_8XQ*4(%rcx),%ymm1\n"
"\n"
"xor		%eax,%eax\n"
"_looptop2:\n"
"pointwise	0\n"
"\n"
"#mov\n"
"vmovdqa		%ymm6,%ymm2\n"
"vmovdqa		%ymm7,%ymm3\n"
"vmovdqa		%ymm8,%ymm4\n"
"vmovdqa		%ymm9,%ymm5\n"
"\n"
"pointwise	1024\n"
"acc\n"
"\n"
"pointwise	2048\n"
"acc\n"
"pointwise	3072\n"
"acc\n"
"\n"
"#reduce\n"
"vpmuldq		%ymm0,%ymm2,%ymm6\n"
"vpmuldq		%ymm0,%ymm3,%ymm7\n"
"vpmuldq		%ymm0,%ymm4,%ymm8\n"
"vpmuldq		%ymm0,%ymm5,%ymm9\n"
"vpmuldq		%ymm1,%ymm6,%ymm6\n"
"vpmuldq		%ymm1,%ymm7,%ymm7\n"
"vpmuldq		%ymm1,%ymm8,%ymm8\n"
"vpmuldq		%ymm1,%ymm9,%ymm9\n"
"vpsubq		%ymm6,%ymm2,%ymm2\n"
"vpsubq		%ymm7,%ymm3,%ymm3\n"
"vpsubq		%ymm8,%ymm4,%ymm4\n"
"vpsubq		%ymm9,%ymm5,%ymm5\n"
"vpsrlq		$32,%ymm2,%ymm2\n"
"vmovshdup	%ymm4,%ymm4\n"
"\n"
"#store\n"
"vpblendd	$0xAA,%ymm3,%ymm2,%ymm2\n"
"vpblendd	$0xAA,%ymm5,%ymm4,%ymm4\n"
"\n"
"vmovdqa		%ymm2,(%rdi)\n"
"vmovdqa		%ymm4,32(%rdi)\n"
"\n"
"add		$64,%rsi\n"
"add		$64,%rdx\n"
"add		$64,%rdi\n"
"add		$1,%eax\n"
"cmp		$16,%eax\n"
"jb _looptop2\n"
"\n"
"ret\n"
"\n"
".global pointwise_acc_avx_3\n"
"pointwise_acc_avx_3:\n"
"#consts\n"
"vmovdqa		_8XQINV*4(%rcx),%ymm0\n"
"vmovdqa		_8XQ*4(%rcx),%ymm1\n"
"\n"
"xor		%eax,%eax\n"
"_looptop2_0:\n"
"pointwise	0\n"
"\n"
"#mov\n"
"vmovdqa		%ymm6,%ymm2\n"
"vmovdqa		%ymm7,%ymm3\n"
"vmovdqa		%ymm8,%ymm4\n"
"vmovdqa		%ymm9,%ymm5\n"
"\n"
"pointwise	1024\n"
"acc\n"
"\n"
"pointwise	2048\n"
"acc\n"
"pointwise	3072\n"
"acc\n"
"\n"
"pointwise	4096\n"
"acc\n"
"\n"
"#reduce\n"
"vpmuldq		%ymm0,%ymm2,%ymm6\n"
"vpmuldq		%ymm0,%ymm3,%ymm7\n"
"vpmuldq		%ymm0,%ymm4,%ymm8\n"
"vpmuldq		%ymm0,%ymm5,%ymm9\n"
"vpmuldq		%ymm1,%ymm6,%ymm6\n"
"vpmuldq		%ymm1,%ymm7,%ymm7\n"
"vpmuldq		%ymm1,%ymm8,%ymm8\n"
"vpmuldq		%ymm1,%ymm9,%ymm9\n"
"vpsubq		%ymm6,%ymm2,%ymm2\n"
"vpsubq		%ymm7,%ymm3,%ymm3\n"
"vpsubq		%ymm8,%ymm4,%ymm4\n"
"vpsubq		%ymm9,%ymm5,%ymm5\n"
"vpsrlq		$32,%ymm2,%ymm2\n"
"vmovshdup	%ymm4,%ymm4\n"
"\n"
"#store\n"
"vpblendd	$0xAA,%ymm3,%ymm2,%ymm2\n"
"vpblendd	$0xAA,%ymm5,%ymm4,%ymm4\n"
"\n"
"vmovdqa		%ymm2,(%rdi)\n"
"vmovdqa		%ymm4,32(%rdi)\n"
"\n"
"add		$64,%rsi\n"
"add		$64,%rdx\n"
"add		$64,%rdi\n"
"add		$1,%eax\n"
"cmp		$16,%eax\n"
"jb _looptop2_0\n"
"\n"
"ret\n"
"\n"
".global pointwise_acc_avx_5\n"
"pointwise_acc_avx_5:\n"
"#consts\n"
"vmovdqa		_8XQINV*4(%rcx),%ymm0\n"
"vmovdqa		_8XQ*4(%rcx),%ymm1\n"
"\n"
"xor		%eax,%eax\n"
"_looptop2_1:\n"
"pointwise	0\n"
"\n"
"#mov\n"
"vmovdqa		%ymm6,%ymm2\n"
"vmovdqa		%ymm7,%ymm3\n"
"vmovdqa		%ymm8,%ymm4\n"
"vmovdqa		%ymm9,%ymm5\n"
"\n"
"pointwise	1024\n"
"acc\n"
"\n"
"pointwise	2048\n"
"acc\n"
"\n"
"pointwise	3072\n"
"acc\n"
"\n"
"pointwise	4096\n"
"acc\n"
"\n"
"pointwise	5120\n"
"acc\n"
"\n"
"pointwise	6144\n"
"acc\n"
"\n"
"#reduce\n"
"vpmuldq		%ymm0,%ymm2,%ymm6\n"
"vpmuldq		%ymm0,%ymm3,%ymm7\n"
"vpmuldq		%ymm0,%ymm4,%ymm8\n"
"vpmuldq		%ymm0,%ymm5,%ymm9\n"
"vpmuldq		%ymm1,%ymm6,%ymm6\n"
"vpmuldq		%ymm1,%ymm7,%ymm7\n"
"vpmuldq		%ymm1,%ymm8,%ymm8\n"
"vpmuldq		%ymm1,%ymm9,%ymm9\n"
"vpsubq		%ymm6,%ymm2,%ymm2\n"
"vpsubq		%ymm7,%ymm3,%ymm3\n"
"vpsubq		%ymm8,%ymm4,%ymm4\n"
"vpsubq		%ymm9,%ymm5,%ymm5\n"
"vpsrlq		$32,%ymm2,%ymm2\n"
"vmovshdup	%ymm4,%ymm4\n"
"\n"
"#store\n"
"vpblendd	$0xAA,%ymm3,%ymm2,%ymm2\n"
"vpblendd	$0xAA,%ymm5,%ymm4,%ymm4\n"
"\n"
"vmovdqa		%ymm2,(%rdi)\n"
"vmovdqa		%ymm4,32(%rdi)\n"
"\n"
"add		$64,%rsi\n"
"add		$64,%rdx\n"
"add		$64,%rdi\n"
"add		$1,%eax\n"
"cmp		$16,%eax\n"
"jb _looptop2_1\n"
"\n"
"ret\n"
);

/*************** dilithium/avx2/invntt.S */
asm (""
".macro butterfly l,h,zl0=1,zl1=1,zh0=2,zh1=2\n"
"vpsubd		%ymm\\l,%ymm\\h,%ymm12\n"
"vpaddd		%ymm\\h,%ymm\\l,%ymm\\l\n"
"\n"
"vpmuldq		%ymm\\zl0,%ymm12,%ymm13\n"
"vmovshdup	%ymm12,%ymm\\h\n"
"vpmuldq		%ymm\\zl1,%ymm\\h,%ymm14\n"
"\n"
"vpmuldq		%ymm\\zh0,%ymm12,%ymm12\n"
"vpmuldq		%ymm\\zh1,%ymm\\h,%ymm\\h\n"
"\n"
"vpmuldq		%ymm0,%ymm13,%ymm13\n"
"vpmuldq		%ymm0,%ymm14,%ymm14\n"
"\n"
"vpsubd		%ymm13,%ymm12,%ymm12\n"
"vpsubd		%ymm14,%ymm\\h,%ymm\\h\n"
"\n"
"vmovshdup	%ymm12,%ymm12\n"
"vpblendd	$0xAA,%ymm\\h,%ymm12,%ymm\\h\n"
".endm\n"
"\n"
".macro levels0t5 off\n"
"vmovdqa		256*\\off+  0(%rdi),%ymm4\n"
"vmovdqa		256*\\off+ 32(%rdi),%ymm5\n"
"vmovdqa		256*\\off+ 64(%rdi),%ymm6\n"
"vmovdqa	 	256*\\off+ 96(%rdi),%ymm7\n"
"vmovdqa		256*\\off+128(%rdi),%ymm8\n"
"vmovdqa		256*\\off+160(%rdi),%ymm9\n"
"vmovdqa		256*\\off+192(%rdi),%ymm10\n"
"vmovdqa	 	256*\\off+224(%rdi),%ymm11\n"
"\n"
"/* level 0 */\n"
"vpermq		$0x1B,(_ZETAS_QINV+296-8*\\off-8)*4(%rsi),%ymm3\n"
"vpermq		$0x1B,(_ZETAS+296-8*\\off-8)*4(%rsi),%ymm15\n"
"vmovshdup	%ymm3,%ymm1\n"
"vmovshdup	%ymm15,%ymm2\n"
"butterfly	4,5,1,3,2,15\n"
"\n"
"vpermq		$0x1B,(_ZETAS_QINV+296-8*\\off-40)*4(%rsi),%ymm3\n"
"vpermq		$0x1B,(_ZETAS+296-8*\\off-40)*4(%rsi),%ymm15\n"
"vmovshdup	%ymm3,%ymm1\n"
"vmovshdup	%ymm15,%ymm2\n"
"butterfly	6,7,1,3,2,15\n"
"\n"
"vpermq		$0x1B,(_ZETAS_QINV+296-8*\\off-72)*4(%rsi),%ymm3\n"
"vpermq		$0x1B,(_ZETAS+296-8*\\off-72)*4(%rsi),%ymm15\n"
"vmovshdup	%ymm3,%ymm1\n"
"vmovshdup	%ymm15,%ymm2\n"
"butterfly	8,9,1,3,2,15\n"
"\n"
"vpermq		$0x1B,(_ZETAS_QINV+296-8*\\off-104)*4(%rsi),%ymm3\n"
"vpermq		$0x1B,(_ZETAS+296-8*\\off-104)*4(%rsi),%ymm15\n"
"vmovshdup	%ymm3,%ymm1\n"
"vmovshdup	%ymm15,%ymm2\n"
"butterfly	10,11,1,3,2,15\n"
"\n"
"/* level 1 */\n"
"vpermq		$0x1B,(_ZETAS_QINV+168-8*\\off-8)*4(%rsi),%ymm3\n"
"vpermq		$0x1B,(_ZETAS+168-8*\\off-8)*4(%rsi),%ymm15\n"
"vmovshdup	%ymm3,%ymm1\n"
"vmovshdup	%ymm15,%ymm2\n"
"butterfly	4,6,1,3,2,15\n"
"butterfly	5,7,1,3,2,15\n"
"\n"
"vpermq		$0x1B,(_ZETAS_QINV+168-8*\\off-40)*4(%rsi),%ymm3\n"
"vpermq		$0x1B,(_ZETAS+168-8*\\off-40)*4(%rsi),%ymm15\n"
"vmovshdup	%ymm3,%ymm1\n"
"vmovshdup	%ymm15,%ymm2\n"
"butterfly	8,10,1,3,2,15\n"
"butterfly	9,11,1,3,2,15\n"
"\n"
"/* level 2 */\n"
"vpermq		$0x1B,(_ZETAS_QINV+104-8*\\off-8)*4(%rsi),%ymm3\n"
"vpermq		$0x1B,(_ZETAS+104-8*\\off-8)*4(%rsi),%ymm15\n"
"vmovshdup	%ymm3,%ymm1\n"
"vmovshdup	%ymm15,%ymm2\n"
"butterfly	4,8,1,3,2,15\n"
"butterfly	5,9,1,3,2,15\n"
"butterfly	6,10,1,3,2,15\n"
"butterfly	7,11,1,3,2,15\n"
"\n"
"/* level 3 */\n"
"shuffle2	4,5,3,5\n"
"shuffle2	6,7,4,7\n"
"shuffle2	8,9,6,9\n"
"shuffle2	10,11,8,11\n"
"\n"
"vpermq		$0x1B,(_ZETAS_QINV+72-8*\\off-8)*4(%rsi),%ymm1\n"
"vpermq		$0x1B,(_ZETAS+72-8*\\off-8)*4(%rsi),%ymm2\n"
"butterfly	3,5\n"
"butterfly	4,7\n"
"butterfly	6,9\n"
"butterfly	8,11\n"
"\n"
"/* level 4 */\n"
"shuffle4	3,4,10,4\n"
"shuffle4	6,8,3,8\n"
"shuffle4	5,7,6,7\n"
"shuffle4	9,11,5,11\n"
"\n"
"vpermq		$0x1B,(_ZETAS_QINV+40-8*\\off-8)*4(%rsi),%ymm1\n"
"vpermq		$0x1B,(_ZETAS+40-8*\\off-8)*4(%rsi),%ymm2\n"
"butterfly	10,4\n"
"butterfly	3,8\n"
"butterfly	6,7\n"
"butterfly	5,11\n"
"\n"
"/* level 5 */\n"
"shuffle8	10,3,9,3\n"
"shuffle8	6,5,10,5\n"
"shuffle8	4,8,6,8\n"
"shuffle8	7,11,4,11\n"
"\n"
"vpbroadcastd	(_ZETAS_QINV+7-\\off)*4(%rsi),%ymm1\n"
"vpbroadcastd	(_ZETAS+7-\\off)*4(%rsi),%ymm2\n"
"butterfly	9,3\n"
"butterfly	10,5\n"
"butterfly	6,8\n"
"butterfly	4,11\n"
"\n"
"vmovdqa		%ymm9,256*\\off+  0(%rdi)\n"
"vmovdqa		%ymm10,256*\\off+ 32(%rdi)\n"
"vmovdqa		%ymm6,256*\\off+ 64(%rdi)\n"
"vmovdqa		%ymm4,256*\\off+ 96(%rdi)\n"
"vmovdqa		%ymm3,256*\\off+128(%rdi)\n"
"vmovdqa		%ymm5,256*\\off+160(%rdi)\n"
"vmovdqa		%ymm8,256*\\off+192(%rdi)\n"
"vmovdqa		%ymm11,256*\\off+224(%rdi)\n"
".endm\n"
"\n"
".macro levels6t7 off\n"
"vmovdqa		  0+32*\\off(%rdi),%ymm4\n"
"vmovdqa		128+32*\\off(%rdi),%ymm5\n"
"vmovdqa		256+32*\\off(%rdi),%ymm6\n"
"vmovdqa		384+32*\\off(%rdi),%ymm7\n"
"vmovdqa		512+32*\\off(%rdi),%ymm8\n"
"vmovdqa		640+32*\\off(%rdi),%ymm9\n"
"vmovdqa		768+32*\\off(%rdi),%ymm10\n"
"vmovdqa		896+32*\\off(%rdi),%ymm11\n"
"\n"
"/* level 6 */\n"
"vpbroadcastd	(_ZETAS_QINV+3)*4(%rsi),%ymm1\n"
"vpbroadcastd	(_ZETAS+3)*4(%rsi),%ymm2\n"
"butterfly	4,6\n"
"butterfly	5,7\n"
"\n"
"vpbroadcastd	(_ZETAS_QINV+2)*4(%rsi),%ymm1\n"
"vpbroadcastd	(_ZETAS+2)*4(%rsi),%ymm2\n"
"butterfly	8,10\n"
"butterfly	9,11\n"
"\n"
"/* level 7 */\n"
"vpbroadcastd	(_ZETAS_QINV+0)*4(%rsi),%ymm1\n"
"vpbroadcastd	(_ZETAS+0)*4(%rsi),%ymm2\n"
"\n"
"butterfly	4,8\n"
"butterfly	5,9\n"
"butterfly	6,10\n"
"butterfly	7,11\n"
"\n"
"vmovdqa         %ymm8,512+32*\\off(%rdi)\n"
"vmovdqa         %ymm9,640+32*\\off(%rdi)\n"
"vmovdqa         %ymm10,768+32*\\off(%rdi)\n"
"vmovdqa         %ymm11,896+32*\\off(%rdi)\n"
"\n"
"vmovdqa		(_8XDIV_QINV)*4(%rsi),%ymm1\n"
"vmovdqa		(_8XDIV)*4(%rsi),%ymm2\n"
"vpmuldq		%ymm1,%ymm4,%ymm12\n"
"vpmuldq		%ymm1,%ymm5,%ymm13\n"
"vmovshdup	%ymm4,%ymm8\n"
"vmovshdup	%ymm5,%ymm9\n"
"vpmuldq		%ymm1,%ymm8,%ymm14\n"
"vpmuldq		%ymm1,%ymm9,%ymm15\n"
"vpmuldq		%ymm2,%ymm4,%ymm4\n"
"vpmuldq		%ymm2,%ymm5,%ymm5\n"
"vpmuldq		%ymm2,%ymm8,%ymm8\n"
"vpmuldq		%ymm2,%ymm9,%ymm9\n"
"vpmuldq		%ymm0,%ymm12,%ymm12\n"
"vpmuldq		%ymm0,%ymm13,%ymm13\n"
"vpmuldq		%ymm0,%ymm14,%ymm14\n"
"vpmuldq		%ymm0,%ymm15,%ymm15\n"
"vpsubd		%ymm12,%ymm4,%ymm4\n"
"vpsubd		%ymm13,%ymm5,%ymm5\n"
"vpsubd		%ymm14,%ymm8,%ymm8\n"
"vpsubd		%ymm15,%ymm9,%ymm9\n"
"vmovshdup	%ymm4,%ymm4\n"
"vmovshdup	%ymm5,%ymm5\n"
"vpblendd	$0xAA,%ymm8,%ymm4,%ymm4\n"
"vpblendd	$0xAA,%ymm9,%ymm5,%ymm5\n"
"\n"
"vpmuldq		%ymm1,%ymm6,%ymm12\n"
"vpmuldq		%ymm1,%ymm7,%ymm13\n"
"vmovshdup	%ymm6,%ymm8\n"
"vmovshdup	%ymm7,%ymm9\n"
"vpmuldq		%ymm1,%ymm8,%ymm14\n"
"vpmuldq		%ymm1,%ymm9,%ymm15\n"
"vpmuldq		%ymm2,%ymm6,%ymm6\n"
"vpmuldq		%ymm2,%ymm7,%ymm7\n"
"vpmuldq		%ymm2,%ymm8,%ymm8\n"
"vpmuldq		%ymm2,%ymm9,%ymm9\n"
"vpmuldq		%ymm0,%ymm12,%ymm12\n"
"vpmuldq		%ymm0,%ymm13,%ymm13\n"
"vpmuldq		%ymm0,%ymm14,%ymm14\n"
"vpmuldq		%ymm0,%ymm15,%ymm15\n"
"vpsubd		%ymm12,%ymm6,%ymm6\n"
"vpsubd		%ymm13,%ymm7,%ymm7\n"
"vpsubd		%ymm14,%ymm8,%ymm8\n"
"vpsubd		%ymm15,%ymm9,%ymm9\n"
"vmovshdup	%ymm6,%ymm6\n"
"vmovshdup	%ymm7,%ymm7\n"
"vpblendd	$0xAA,%ymm8,%ymm6,%ymm6\n"
"vpblendd	$0xAA,%ymm9,%ymm7,%ymm7\n"
"\n"
"vmovdqa         %ymm4,  0+32*\\off(%rdi)\n"
"vmovdqa         %ymm5,128+32*\\off(%rdi)\n"
"vmovdqa         %ymm6,256+32*\\off(%rdi)\n"
"vmovdqa         %ymm7,384+32*\\off(%rdi)\n"
".endm\n"
"\n"
".text\n"
".global invntt_avx\n"
"invntt_avx:\n"
"vmovdqa		_8XQ*4(%rsi),%ymm0\n"
"\n"
"levels0t5	0\n"
"levels0t5	1\n"
"levels0t5	2\n"
"levels0t5	3\n"
"\n"
"levels6t7	0\n"
"levels6t7	1\n"
"levels6t7	2\n"
"levels6t7	3\n"
"\n"
"ret\n"
"\n"
);

/*************** dilithium/avx2/ntt.S */
asm (
".macro butterfly_ l,h,zl0=1,zl1=1,zh0=2,zh1=2\n"
"vpmuldq		%ymm\\zl0,%ymm\\h,%ymm13\n"
"vmovshdup	%ymm\\h,%ymm12\n"
"vpmuldq		%ymm\\zl1,%ymm12,%ymm14\n"
"\n"
"vpmuldq		%ymm\\zh0,%ymm\\h,%ymm\\h\n"
"vpmuldq		%ymm\\zh1,%ymm12,%ymm12\n"
"\n"
"vpmuldq		%ymm0,%ymm13,%ymm13\n"
"vpmuldq		%ymm0,%ymm14,%ymm14\n"
"\n"
"vmovshdup	%ymm\\h,%ymm\\h\n"
"vpblendd	$0xAA,%ymm12,%ymm\\h,%ymm\\h\n"
"\n"
"vpsubd		%ymm\\h,%ymm\\l,%ymm12\n"
"vpaddd		%ymm\\h,%ymm\\l,%ymm\\l\n"
"\n"
"vmovshdup	%ymm13,%ymm13\n"
"vpblendd	$0xAA,%ymm14,%ymm13,%ymm13\n"
"\n"
"vpaddd		%ymm13,%ymm12,%ymm\\h\n"
"vpsubd		%ymm13,%ymm\\l,%ymm\\l\n"
".endm\n"
"\n"
".macro levels0t1 off\n"
"/* level 0 */\n"
"vpbroadcastd	(_ZETAS_QINV+1)*4(%rsi),%ymm1\n"
"vpbroadcastd	(_ZETAS+1)*4(%rsi),%ymm2\n"
"\n"
"vmovdqa		  0+32*\\off(%rdi),%ymm4\n"
"vmovdqa		128+32*\\off(%rdi),%ymm5\n"
"vmovdqa		256+32*\\off(%rdi),%ymm6\n"
"vmovdqa	 	384+32*\\off(%rdi),%ymm7\n"
"vmovdqa		512+32*\\off(%rdi),%ymm8\n"
"vmovdqa		640+32*\\off(%rdi),%ymm9\n"
"vmovdqa		768+32*\\off(%rdi),%ymm10\n"
"vmovdqa	 	896+32*\\off(%rdi),%ymm11\n"
"\n"
"butterfly_	4,8\n"
"butterfly_	5,9\n"
"butterfly_	6,10\n"
"butterfly_	7,11\n"
"\n"
"/* level 1 */\n"
"vpbroadcastd	(_ZETAS_QINV+2)*4(%rsi),%ymm1\n"
"vpbroadcastd	(_ZETAS+2)*4(%rsi),%ymm2\n"
"butterfly_	4,6\n"
"butterfly_	5,7\n"
"\n"
"vpbroadcastd	(_ZETAS_QINV+3)*4(%rsi),%ymm1\n"
"vpbroadcastd	(_ZETAS+3)*4(%rsi),%ymm2\n"
"butterfly_	8,10\n"
"butterfly_	9,11\n"
"\n"
"vmovdqa		%ymm4,  0+32*\\off(%rdi)\n"
"vmovdqa		%ymm5,128+32*\\off(%rdi)\n"
"vmovdqa		%ymm6,256+32*\\off(%rdi)\n"
"vmovdqa		%ymm7,384+32*\\off(%rdi)\n"
"vmovdqa		%ymm8,512+32*\\off(%rdi)\n"
"vmovdqa		%ymm9,640+32*\\off(%rdi)\n"
"vmovdqa		%ymm10,768+32*\\off(%rdi)\n"
"vmovdqa		%ymm11,896+32*\\off(%rdi)\n"
".endm\n"
"\n"
".macro levels2t7 off\n"
"/* level 2 */\n"
"vmovdqa		256*\\off+  0(%rdi),%ymm4\n"
"vmovdqa		256*\\off+ 32(%rdi),%ymm5\n"
"vmovdqa		256*\\off+ 64(%rdi),%ymm6\n"
"vmovdqa	 	256*\\off+ 96(%rdi),%ymm7\n"
"vmovdqa		256*\\off+128(%rdi),%ymm8\n"
"vmovdqa		256*\\off+160(%rdi),%ymm9\n"
"vmovdqa		256*\\off+192(%rdi),%ymm10\n"
"vmovdqa	 	256*\\off+224(%rdi),%ymm11\n"
"\n"
"vpbroadcastd	(_ZETAS_QINV+4+\\off)*4(%rsi),%ymm1\n"
"vpbroadcastd	(_ZETAS+4+\\off)*4(%rsi),%ymm2\n"
"\n"
"butterfly_	4,8\n"
"butterfly_	5,9\n"
"butterfly_	6,10\n"
"butterfly_	7,11\n"
"\n"
"shuffle8	4,8,3,8\n"
"shuffle8	5,9,4,9\n"
"shuffle8	6,10,5,10\n"
"shuffle8	7,11,6,11\n"
"\n"
"/* level 3 */\n"
"vmovdqa		(_ZETAS_QINV+8+8*\\off)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+8+8*\\off)*4(%rsi),%ymm2\n"
"\n"
"butterfly_	3,5\n"
"butterfly_	8,10\n"
"butterfly_	4,6\n"
"butterfly_	9,11\n"
"\n"
"shuffle4	3,5,7,5\n"
"shuffle4	8,10,3,10\n"
"shuffle4	4,6,8,6\n"
"shuffle4	9,11,4,11\n"
"\n"
"/* level 4 */\n"
"vmovdqa		(_ZETAS_QINV+40+8*\\off)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+40+8*\\off)*4(%rsi),%ymm2\n"
"\n"
"butterfly_	7,8\n"
"butterfly_	5,6\n"
"butterfly_	3,4\n"
"butterfly_	10,11\n"
"\n"
"shuffle2	7,8,9,8\n"
"shuffle2	5,6,7,6\n"
"shuffle2	3,4,5,4\n"
"shuffle2	10,11,3,11\n"
"\n"
"/* level 5 */\n"
"vmovdqa		(_ZETAS_QINV+72+8*\\off)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+72+8*\\off)*4(%rsi),%ymm2\n"
"vpsrlq		$32,%ymm1,%ymm10\n"
"vmovshdup	%ymm2,%ymm15\n"
"\n"
"butterfly_	9,5,1,10,2,15\n"
"butterfly_	8,4,1,10,2,15\n"
"butterfly_	7,3,1,10,2,15\n"
"butterfly_	6,11,1,10,2,15\n"
"\n"
"/* level 6 */\n"
"vmovdqa		(_ZETAS_QINV+104+8*\\off)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+104+8*\\off)*4(%rsi),%ymm2\n"
"vpsrlq		$32,%ymm1,%ymm10\n"
"vmovshdup	%ymm2,%ymm15\n"
"butterfly_	9,7,1,10,2,15\n"
"butterfly_	8,6,1,10,2,15\n"
"\n"
"vmovdqa		(_ZETAS_QINV+104+8*\\off+32)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+104+8*\\off+32)*4(%rsi),%ymm2\n"
"vpsrlq		$32,%ymm1,%ymm10\n"
"vmovshdup	%ymm2,%ymm15\n"
"butterfly_	5,3,1,10,2,15\n"
"butterfly_	4,11,1,10,2,15\n"
"\n"
"/* level 7 */\n"
"vmovdqa		(_ZETAS_QINV+168+8*\\off)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+168+8*\\off)*4(%rsi),%ymm2\n"
"vpsrlq		$32,%ymm1,%ymm10\n"
"vmovshdup	%ymm2,%ymm15\n"
"butterfly_	9,8,1,10,2,15\n"
"\n"
"vmovdqa		(_ZETAS_QINV+168+8*\\off+32)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+168+8*\\off+32)*4(%rsi),%ymm2\n"
"vpsrlq		$32,%ymm1,%ymm10\n"
"vmovshdup	%ymm2,%ymm15\n"
"butterfly_	7,6,1,10,2,15\n"
"\n"
"vmovdqa		(_ZETAS_QINV+168+8*\\off+64)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+168+8*\\off+64)*4(%rsi),%ymm2\n"
"vpsrlq		$32,%ymm1,%ymm10\n"
"vmovshdup	%ymm2,%ymm15\n"
"butterfly_	5,4,1,10,2,15\n"
"\n"
"vmovdqa		(_ZETAS_QINV+168+8*\\off+96)*4(%rsi),%ymm1\n"
"vmovdqa		(_ZETAS+168+8*\\off+96)*4(%rsi),%ymm2\n"
"vpsrlq		$32,%ymm1,%ymm10\n"
"vmovshdup	%ymm2,%ymm15\n"
"butterfly_	3,11,1,10,2,15\n"
"\n"
"vmovdqa		%ymm9,256*\\off+  0(%rdi)\n"
"vmovdqa		%ymm8,256*\\off+ 32(%rdi)\n"
"vmovdqa		%ymm7,256*\\off+ 64(%rdi)\n"
"vmovdqa		%ymm6,256*\\off+ 96(%rdi)\n"
"vmovdqa		%ymm5,256*\\off+128(%rdi)\n"
"vmovdqa		%ymm4,256*\\off+160(%rdi)\n"
"vmovdqa		%ymm3,256*\\off+192(%rdi)\n"
"vmovdqa		%ymm11,256*\\off+224(%rdi)\n"
".endm\n"
"\n"
".text\n"
".global ntt_avx\n"
"ntt_avx:\n"
"vmovdqa		_8XQ*4(%rsi),%ymm0\n"
"\n"
"levels0t1	0\n"
"levels0t1	1\n"
"levels0t1	2\n"
"levels0t1	3\n"
"\n"
"levels2t7	0\n"
"levels2t7	1\n"
"levels2t7	2\n"
"levels2t7	3\n"
"\n"
"ret\n"
"\n"
);
