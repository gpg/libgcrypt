/* pkcs1v2.c - Test OAEP and PSS padding
 * Copyright (C) 2011 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef _GCRYPT_IN_LIBGCRYPT
# include "../src/gcrypt.h"
#else
# include <gcrypt.h>
#endif


#define my_isascii(c) (!((c) & 0x80))
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

static int verbose;
static int die_on_error;
static int error_count;


static void
info (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
}

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
  if (die_on_error)
    exit (1);
}

static void
die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
}

static void
show_sexp (const char *prefix, gcry_sexp_t a)
{
  char *buf;
  size_t size;

  if (prefix)
    fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = gcry_xmalloc (size);

  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  gcry_free (buf);
}


/* Convert STRING consisting of hex characters into its binary
   representation and return it as an allocated buffer. The valid
   length of the buffer is returned at R_LENGTH.  The string is
   delimited by end of string.  The function returns NULL on
   error.  */
static void *
data_from_hex (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = gcry_xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        die ("error parsing hex string `%s'\n", string);
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static int
extract_cmp_data (gcry_sexp_t sexp, const char *name, const char *expected,
                  const char *description)
{
  gcry_sexp_t l1;
  const void *a;
  size_t alen;
  void *b;
  size_t blen;
  int rc = 0;

  l1 = gcry_sexp_find_token (sexp, name, 0);
  a = gcry_sexp_nth_data (l1, 1, &alen);
  b = data_from_hex (expected, &blen);
  if (!a)
    {
      info ("%s: parameter \"%s\" missing in key\n", description, name);
      rc = 1;
    }
  else if ( alen != blen || memcmp (a, b, alen) )
    {
      info ("%s: parameter \"%s\" does not match expected value\n",
            description, name);
      rc = 1;
    }
  gcry_free (b);
  gcry_sexp_release (l1);
  return rc;
}


/* Check against the OAEP test vectors from
   ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1d2-vec.zip .  */
static void
check_oaep (void)
{
  static struct {
    const char *desc;
    const char *n, *e, *d;
    struct {
      const char *desc;
      const char *mesg;
      const char *seed;
      const char *encr;
    } m[6];
  } tbl[] = {
    {
      "Example 1: A 1024-bit RSA key pair",
      "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab"
      "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72"
      "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514"
      "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
      "010001",
      "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd"
      "8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55"
      "fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbf"
      "b78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1",
      {
        {
          "OAEP Example 1.1",
          "6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34",
          "18b776ea21069d69776a33e96bad48e1dda0a5ef",
          "354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb"
          "21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535f"
          "a9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426"
          "d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a"
        },{
          "OAEP Example 1.2",
          "750c4047f547e8e41411856523298ac9bae245efaf1397fbe56f9dd5",
          "0cc742ce4a9b7f32f951bcb251efd925fe4fe35f",
          "640db1acc58e0568fe5407e5f9b701dff8c3c91e716c536fc7fcec6cb5b71c11"
          "65988d4a279e1577d730fc7a29932e3f00c81515236d8d8e31017a7a09df4352"
          "d904cdeb79aa583adcc31ea698a4c05283daba9089be5491f67c1a4ee48dc74b"
          "bbe6643aef846679b4cb395a352d5ed115912df696ffe0702932946d71492b44"
        },{
          "OAEP Example 1.3",
          "d94ae0832e6445ce42331cb06d531a82b1db4baad30f746dc916df24d4e3c245"
          "1fff59a6423eb0e1d02d4fe646cf699dfd818c6e97b051",
          "2514df4695755a67b288eaf4905c36eec66fd2fd",
          "423736ed035f6026af276c35c0b3741b365e5f76ca091b4e8c29e2f0befee603"
          "595aa8322d602d2e625e95eb81b2f1c9724e822eca76db8618cf09c5343503a4"
          "360835b5903bc637e3879fb05e0ef32685d5aec5067cd7cc96fe4b2670b6eac3"
          "066b1fcf5686b68589aafb7d629b02d8f8625ca3833624d4800fb081b1cf94eb"
        },{
          "OAEP Example 1.4",
          "52e650d98e7f2a048b4f86852153b97e01dd316f346a19f67a85",
          "c4435a3e1a18a68b6820436290a37cefb85db3fb",
          "45ead4ca551e662c9800f1aca8283b0525e6abae30be4b4aba762fa40fd3d38e"
          "22abefc69794f6ebbbc05ddbb11216247d2f412fd0fba87c6e3acd888813646f"
          "d0e48e785204f9c3f73d6d8239562722dddd8771fec48b83a31ee6f592c4cfd4"
          "bc88174f3b13a112aae3b9f7b80e0fc6f7255ba880dc7d8021e22ad6a85f0755"
        },{
          "OAEP Example 1.5",
          "8da89fd9e5f974a29feffb462b49180f6cf9e802",
          "b318c42df3be0f83fea823f5a7b47ed5e425a3b5",
          "36f6e34d94a8d34daacba33a2139d00ad85a9345a86051e73071620056b920e2"
          "19005855a213a0f23897cdcd731b45257c777fe908202befdd0b58386b1244ea"
          "0cf539a05d5d10329da44e13030fd760dcd644cfef2094d1910d3f433e1c7c6d"
          "d18bc1f2df7f643d662fb9dd37ead9059190f4fa66ca39e869c4eb449cbdc439"
        },{
          "OAEP Example 1.6",
          "26521050844271",
          "e4ec0982c2336f3a677f6a356174eb0ce887abc2",
          "42cee2617b1ecea4db3f4829386fbd61dafbf038e180d837c96366df24c097b4"
          "ab0fac6bdf590d821c9f10642e681ad05b8d78b378c0f46ce2fad63f74e0ad3d"
          "f06b075d7eb5f5636f8d403b9059ca761b5c62bb52aa45002ea70baace08ded2"
          "43b9d8cbd62a68ade265832b56564e43a6fa42ed199a099769742df1539e8255"
        }
      }
    },
    {
      "Example 2: A 1025-bit RSA key pair",
      "01947c7fce90425f47279e70851f25d5e62316fe8a1df19371e3e628e260543e"
      "4901ef6081f68c0b8141190d2ae8daba7d1250ec6db636e944ec3722877c7c1d"
      "0a67f14b1694c5f0379451a43e49a32dde83670b73da91a1c99bc23b436a6005"
      "5c610f0baf99c1a079565b95a3f1526632d1d4da60f20eda25e653c4f002766f"
      "45",
      "010001",
      "0823f20fadb5da89088a9d00893e21fa4a1b11fbc93c64a3be0baaea97fb3b93"
      "c3ff713704c19c963c1d107aae99054739f79e02e186de86f87a6ddefea6d8cc"
      "d1d3c81a47bfa7255be20601a4a4b2f08a167b5e279d715b1b455bdd7eab2459"
      "41d9768b9acefb3ccda5952da3cee72525b4501663a8ee15c9e992d92462fe39",
      {
        {
          "OAEP Example 2.1",
          "8ff00caa605c702830634d9a6c3d42c652b58cf1d92fec570beee7",
          "8c407b5ec2899e5099c53e8ce793bf94e71b1782",
          "0181af8922b9fcb4d79d92ebe19815992fc0c1439d8bcd491398a0f4ad3a329a"
          "5bd9385560db532683c8b7da04e4b12aed6aacdf471c34c9cda891addcc2df34"
          "56653aa6382e9ae59b54455257eb099d562bbe10453f2b6d13c59c02e10f1f8a"
          "bb5da0d0570932dacf2d0901db729d0fefcc054e70968ea540c81b04bcaefe72"
          "0e"
        },{
          "OAEP Example 2.2",
          "2d",
          "b600cf3c2e506d7f16778c910d3a8b003eee61d5",
          "018759ff1df63b2792410562314416a8aeaf2ac634b46f940ab82d64dbf165ee"
          "e33011da749d4bab6e2fcd18129c9e49277d8453112b429a222a8471b0709939"
          "98e758861c4d3f6d749d91c4290d332c7a4ab3f7ea35ff3a07d497c955ff0ffc"
          "95006b62c6d296810d9bfab024196c7934012c2df978ef299aba239940cba102"
          "45"
        },{
          "OAEP Example 2.3",
          "74fc88c51bc90f77af9d5e9a4a70133d4b4e0b34da3c37c7ef8e",
          "a73768aeeaa91f9d8c1ed6f9d2b63467f07ccae3",
          "018802bab04c60325e81c4962311f2be7c2adce93041a00719c88f957575f2c7"
          "9f1b7bc8ced115c706b311c08a2d986ca3b6a9336b147c29c6f229409ddec651"
          "bd1fdd5a0b7f610c9937fdb4a3a762364b8b3206b4ea485fd098d08f63d4aa8b"
          "b2697d027b750c32d7f74eaf5180d2e9b66b17cb2fa55523bc280da10d14be20"
          "53"
        },{
          "OAEP Example 2.4",
          "a7eb2a5036931d27d4e891326d99692ffadda9bf7efd3e34e622c4adc085f721"
          "dfe885072c78a203b151739be540fa8c153a10f00a",
          "9a7b3b0e708bd96f8190ecab4fb9b2b3805a8156",
          "00a4578cbc176318a638fba7d01df15746af44d4f6cd96d7e7c495cbf425b09c"
          "649d32bf886da48fbaf989a2117187cafb1fb580317690e3ccd446920b7af82b"
          "31db5804d87d01514acbfa9156e782f867f6bed9449e0e9a2c09bcecc6aa0876"
          "36965e34b3ec766f2fe2e43018a2fddeb140616a0e9d82e5331024ee0652fc76"
          "41"
        },{
          "OAEP Example 2.5",
          "2ef2b066f854c33f3bdcbb5994a435e73d6c6c",
          "eb3cebbc4adc16bb48e88c8aec0e34af7f427fd3",
          "00ebc5f5fda77cfdad3c83641a9025e77d72d8a6fb33a810f5950f8d74c73e8d"
          "931e8634d86ab1246256ae07b6005b71b7f2fb98351218331ce69b8ffbdc9da0"
          "8bbc9c704f876deb9df9fc2ec065cad87f9090b07acc17aa7f997b27aca48806"
          "e897f771d95141fe4526d8a5301b678627efab707fd40fbebd6e792a25613e7a"
          "ec",
        },{
          "OAEP Example 2.6",
          "8a7fb344c8b6cb2cf2ef1f643f9a3218f6e19bba89c0",
          "4c45cf4d57c98e3d6d2095adc51c489eb50dff84",
          "010839ec20c27b9052e55befb9b77e6fc26e9075d7a54378c646abdf51e445bd"
          "5715de81789f56f1803d9170764a9e93cb78798694023ee7393ce04bc5d8f8c5"
          "a52c171d43837e3aca62f609eb0aa5ffb0960ef04198dd754f57f7fbe6abf765"
          "cf118b4ca443b23b5aab266f952326ac4581100644325f8b721acd5d04ff14ef"
          "3a"
        }
      }
    },
    {
      "Example 3: A 1026-bit RSA key pair",
      "02b58fec039a860700a4d7b6462f93e6cdd491161ddd74f4e810b40e3c165200"
      "6a5c277b2774c11305a4cbab5a78efa57e17a86df7a3fa36fc4b1d2249f22ec7"
      "c2dd6a463232accea906d66ebe80b5704b10729da6f833234abb5efdd4a292cb"
      "fad33b4d33fa7a14b8c397b56e3acd21203428b77cdfa33a6da706b3d8b0fc43"
      "e9",
      "010001",
      "15b48a5b5683a94670e23b5718f814fa0e13f85038f50711182cba61510581f3"
      "d22c7e232ef937e22e551d68b86e2f8cb1aad8be2e488f5df7efd279e3f568d4"
      "eaf36f80cf7141ace60fcc9113fb6c4a841fd50bbc7c512ffcbeff21487aa811"
      "eb3ca8c62005346a86de86bfa1d8a948fd3f348c22eaadf333c3ce6ce13208fd",
      {
        {
          "OAEP Example 3.1",
          "087820b569e8fa8d",
          "8ced6b196290805790e909074015e6a20b0c4894",
          "026a0485d96aebd96b4382085099b962e6a2bdec3d90c8db625e14372de85e2d"
          "5b7baab65c8faf91bb5504fb495afce5c988b3f6a52e20e1d6cbd3566c5cd1f2"
          "b8318bb542cc0ea25c4aab9932afa20760eaddec784396a07ea0ef24d4e6f4d3"
          "7e5052a7a31e146aa480a111bbe926401307e00f410033842b6d82fe5ce4dfae"
          "80"
        },{
          "OAEP Example 3.2",
          "4653acaf171960b01f52a7be63a3ab21dc368ec43b50d82ec3781e04",
          "b4291d6567550848cc156967c809baab6ca507f0",
          "024db89c7802989be0783847863084941bf209d761987e38f97cb5f6f1bc88da"
          "72a50b73ebaf11c879c4f95df37b850b8f65d7622e25b1b889e80fe80baca206"
          "9d6e0e1d829953fc459069de98ea9798b451e557e99abf8fe3d9ccf9096ebbf3"
          "e5255d3b4e1c6d2ecadf067a359eea86405acd47d5e165517ccafd47d6dbee4b"
          "f5"
        },{
          "OAEP Example 3.3",
          "d94cd0e08fa404ed89",
          "ce8928f6059558254008badd9794fadcd2fd1f65",
          "0239bce681032441528877d6d1c8bb28aa3bc97f1df584563618995797683844"
          "ca86664732f4bed7a0aab083aaabfb7238f582e30958c2024e44e57043b97950"
          "fd543da977c90cdde5337d618442f99e60d7783ab59ce6dd9d69c47ad1e962be"
          "c22d05895cff8d3f64ed5261d92b2678510393484990ba3f7f06818ae6ffce8a"
          "3a"
        },{
          "OAEP Example 3.4",
          "6cc641b6b61e6f963974dad23a9013284ef1",
          "6e2979f52d6814a57d83b090054888f119a5b9a3",
          "02994c62afd76f498ba1fd2cf642857fca81f4373cb08f1cbaee6f025c3b512b"
          "42c3e8779113476648039dbe0493f9246292fac28950600e7c0f32edf9c81b9d"
          "ec45c3bde0cc8d8847590169907b7dc5991ceb29bb0714d613d96df0f12ec5d8"
          "d3507c8ee7ae78dd83f216fa61de100363aca48a7e914ae9f42ddfbe943b09d9"
          "a0"
        },{
          "OAEP Example 3.5",
          "df5151832b61f4f25891fb4172f328d2eddf8371ffcfdbe997939295f30eca69"
          "18017cfda1153bf7a6af87593223",
          "2d760bfe38c59de34cdc8b8c78a38e66284a2d27",
          "0162042ff6969592a6167031811a239834ce638abf54fec8b99478122afe2ee6"
          "7f8c5b18b0339805bfdbc5a4e6720b37c59cfba942464c597ff532a119821545"
          "fd2e59b114e61daf71820529f5029cf524954327c34ec5e6f5ba7efcc4de943a"
          "b8ad4ed787b1454329f70db798a3a8f4d92f8274e2b2948ade627ce8ee33e43c"
          "60",
        },{
          "OAEP Example 3.6",
          "3c3bad893c544a6d520ab022319188c8d504b7a788b850903b85972eaa18552e"
          "1134a7ad6098826254ff7ab672b3d8eb3158fac6d4cbaef1",
          "f174779c5fd3cfe007badcb7a36c9b55bfcfbf0e",
          "00112051e75d064943bc4478075e43482fd59cee0679de6893eec3a943daa490"
          "b9691c93dfc0464b6623b9f3dbd3e70083264f034b374f74164e1a00763725e5"
          "74744ba0b9db83434f31df96f6e2a26f6d8eba348bd4686c2238ac07c37aac37"
          "85d1c7eea2f819fd91491798ed8e9cef5e43b781b0e0276e37c43ff9492d0057"
          "30"
        }
      }
    },
    {
      "Example 4: A 1027-bit RSA key pair",
      "051240b6cc0004fa48d0134671c078c7c8dec3b3e2f25bc2564467339db38853"
      "d06b85eea5b2de353bff42ac2e46bc97fae6ac9618da9537a5c8f553c1e35762"
      "5991d6108dcd7885fb3a25413f53efcad948cb35cd9b9ae9c1c67626d113d57d"
      "de4c5bea76bb5bb7de96c00d07372e9685a6d75cf9d239fa148d70931b5f3fb0"
      "39",
      "010001",
      "0411ffca3b7ca5e9e9be7fe38a85105e353896db05c5796aecd2a725161eb365"
      "1c8629a9b862b904d7b0c7b37f8cb5a1c2b54001018a00a1eb2cafe4ee4e9492"
      "c348bc2bedab4b9ebbf064e8eff322b9009f8eec653905f40df88a3cdc49d456"
      "7f75627d41aca624129b46a0b7c698e5e65f2b7ba102c749a10135b6540d0401",
      {
        {
          "OAEP Example 4.1",
          "4a86609534ee434a6cbca3f7e962e76d455e3264c19f605f6e5ff6137c65c56d"
          "7fb344cd52bc93374f3d166c9f0c6f9c506bad19330972d2",
          "1cac19ce993def55f98203f6852896c95ccca1f3",
          "04cce19614845e094152a3fe18e54e3330c44e5efbc64ae16886cb1869014cc5"
          "781b1f8f9e045384d0112a135ca0d12e9c88a8e4063416deaae3844f60d6e96f"
          "e155145f4525b9a34431ca3766180f70e15a5e5d8e8b1a516ff870609f13f896"
          "935ced188279a58ed13d07114277d75c6568607e0ab092fd803a223e4a8ee0b1"
          "a8"
        },{
          "OAEP Example 4.2",
          "b0adc4f3fe11da59ce992773d9059943c03046497ee9d9f9a06df1166db46d98"
          "f58d27ec074c02eee6cbe2449c8b9fc5080c5c3f4433092512ec46aa793743c8",
          "f545d5897585e3db71aa0cb8da76c51d032ae963",
          "0097b698c6165645b303486fbf5a2a4479c0ee85889b541a6f0b858d6b6597b1"
          "3b854eb4f839af03399a80d79bda6578c841f90d645715b280d37143992dd186"
          "c80b949b775cae97370e4ec97443136c6da484e970ffdb1323a20847821d3b18"
          "381de13bb49aaea66530c4a4b8271f3eae172cd366e07e6636f1019d2a28aed1"
          "5e"
        },{
          "OAEP Example 4.3",
          "bf6d42e701707b1d0206b0c8b45a1c72641ff12889219a82bdea965b5e79a96b"
          "0d0163ed9d578ec9ada20f2fbcf1ea3c4089d83419ba81b0c60f3606da99",
          "ad997feef730d6ea7be60d0dc52e72eacbfdd275",
          "0301f935e9c47abcb48acbbe09895d9f5971af14839da4ff95417ee453d1fd77"
          "319072bb7297e1b55d7561cd9d1bb24c1a9a37c619864308242804879d86ebd0"
          "01dce5183975e1506989b70e5a83434154d5cbfd6a24787e60eb0c658d2ac193"
          "302d1192c6e622d4a12ad4b53923bca246df31c6395e37702c6a78ae081fb9d0"
          "65"
        },{
          "OAEP Example 4.4",
          "fb2ef112f5e766eb94019297934794f7be2f6fc1c58e",
          "136454df5730f73c807a7e40d8c1a312ac5b9dd3",
          "02d110ad30afb727beb691dd0cf17d0af1a1e7fa0cc040ec1a4ba26a42c59d0a"
          "796a2e22c8f357ccc98b6519aceb682e945e62cb734614a529407cd452bee3e4"
          "4fece8423cc19e55548b8b994b849c7ecde4933e76037e1d0ce44275b08710c6"
          "8e430130b929730ed77e09b015642c5593f04e4ffb9410798102a8e96ffdfe11"
          "e4"
        },{
          "OAEP Example 4.5",
          "28ccd447bb9e85166dabb9e5b7d1adadc4b9d39f204e96d5e440ce9ad928bc1c"
          "2284",
          "bca8057f824b2ea257f2861407eef63d33208681",
          "00dbb8a7439d90efd919a377c54fae8fe11ec58c3b858362e23ad1b8a4431079"
          "9066b99347aa525691d2adc58d9b06e34f288c170390c5f0e11c0aa3645959f1"
          "8ee79e8f2be8d7ac5c23d061f18dd74b8c5f2a58fcb5eb0c54f99f01a8324756"
          "8292536583340948d7a8c97c4acd1e98d1e29dc320e97a260532a8aa7a758a1e"
          "c2"
        },{
          "OAEP Example 4.6",
          "f22242751ec6b1",
          "2e7e1e17f647b5ddd033e15472f90f6812f3ac4e",
          "00a5ffa4768c8bbecaee2db77e8f2eec99595933545520835e5ba7db9493d3e1"
          "7cddefe6a5f567624471908db4e2d83a0fbee60608fc84049503b2234a07dc83"
          "b27b22847ad8920ff42f674ef79b76280b00233d2b51b8cb2703a9d42bfbc825"
          "0c96ec32c051e57f1b4ba528db89c37e4c54e27e6e64ac69635ae887d9541619"
          "a9"
        }
      }
    },
    {
      "Example 5: A 1028-bit RSA key pair",
      "0aadf3f9c125e5d891f31ac448e993defe580f802b45f9d7f22ba5021e9c4757"
      "6b5a1e68031ba9db4e6dabe4d96a1d6f3d267268cff408005f118efcadb99888"
      "d1c234467166b2a2b849a05a889c060ac0da0c5fae8b55f309ba62e703742fa0"
      "326f2d10b011021489ff497770190d895fd39f52293c39efd73a698bdab9f10e"
      "d9",
      "010001",
      "0256eb4cba7067f2d2be540dcdff4582a36b7d31d1c9099bb214b79848466a26"
      "8f80f58a49ac04c0e3648934a0206c04537c19b236643a6082732144df75fa21"
      "7588f794682be89168276dc726c5c0cbdb84d31bbf26d0a43af495717f7d528a"
      "cfee341561f6ff3cae05c578f8470d9682f9c0d072f9f6068b56d5880f682be2"
      "c5",
      {
        {
          "OAEP Example 5.1",
          "af71a901e3a61d3132f0fc1fdb474f9ea6579257ffc24d164170145b3dbde8",
          "44c92e283f77b9499c603d963660c87d2f939461",
          "036046a4a47d9ed3ba9a89139c105038eb7492b05a5d68bfd53accff4597f7a6"
          "8651b47b4a4627d927e485eed7b4566420e8b409879e5d606eae251d22a5df79"
            "9f7920bfc117b992572a53b1263146bcea03385cc5e853c9a101c8c3e1bda31a"
          "519807496c6cb5e5efb408823a352b8fa0661fb664efadd593deb99fff5ed000"
          "e5"
        },{
          "OAEP Example 5.2",
          "a3b844a08239a8ac41605af17a6cfda4d350136585903a417a79268760519a4b"
          "4ac3303ec73f0f87cfb32399",
          "cb28f5860659fceee49c3eeafce625a70803bd32",
          "03d6eb654edce615bc59f455265ed4e5a18223cbb9be4e4069b473804d5de96f"
          "54dcaaa603d049c5d94aa1470dfcd2254066b7c7b61ff1f6f6770e3215c51399"
          "fd4e34ec5082bc48f089840ad04354ae66dc0f1bd18e461a33cc1258b443a283"
          "7a6df26759aa2302334986f87380c9cc9d53be9f99605d2c9a97da7b0915a4a7"
          "ad"
        },{
          "OAEP Example 5.3",
          "308b0ecbd2c76cb77fc6f70c5edd233fd2f20929d629f026953bb62a8f4a3a31"
          "4bde195de85b5f816da2aab074d26cb6acddf323ae3b9c678ac3cf12fbdde7",
          "2285f40d770482f9a9efa2c72cb3ac55716dc0ca",
          "0770952181649f9f9f07ff626ff3a22c35c462443d905d456a9fd0bff43cac2c"
          "a7a9f554e9478b9acc3ac838b02040ffd3e1847de2e4253929f9dd9ee4044325"
          "a9b05cabb808b2ee840d34e15d105a3f1f7b27695a1a07a2d73fe08ecaaa3c9c"
          "9d4d5a89ff890d54727d7ae40c0ec1a8dd86165d8ee2c6368141016a48b55b69"
          "67"
        },{
          "OAEP Example 5.4",
          "15c5b9ee1185",
          "49fa45d3a78dd10dfd577399d1eb00af7eed5513",
          "0812b76768ebcb642d040258e5f4441a018521bd96687e6c5e899fcd6c17588f"
          "f59a82cc8ae03a4b45b31299af1788c329f7dcd285f8cf4ced82606b97612671"
          "a45bedca133442144d1617d114f802857f0f9d739751c57a3f9ee400912c61e2"
          "e6992be031a43dd48fa6ba14eef7c422b5edc4e7afa04fdd38f402d1c8bb719a"
          "bf"
        },{
          "OAEP Example 5.5",
          "21026e6800c7fa728fcaaba0d196ae28d7a2ac4ffd8abce794f0985f60c8a673"
          "7277365d3fea11db8923a2029a",
          "f0287413234cc5034724a094c4586b87aff133fc",
          "07b60e14ec954bfd29e60d0047e789f51d57186c63589903306793ced3f68241"
          "c743529aba6a6374f92e19e0163efa33697e196f7661dfaaa47aac6bde5e51de"
          "b507c72c589a2ca1693d96b1460381249b2cdb9eac44769f2489c5d3d2f99f0e"
          "e3c7ee5bf64a5ac79c42bd433f149be8cb59548361640595513c97af7bc25097"
          "23"
        },{
          "OAEP Example 5.6",
          "541e37b68b6c8872b84c02",
          "d9fba45c96f21e6e26d29eb2cdcb6585be9cb341",
          "08c36d4dda33423b2ed6830d85f6411ba1dcf470a1fae0ebefee7c089f256cef"
          "74cb96ea69c38f60f39abee44129bcb4c92de7f797623b20074e3d9c2899701e"
          "d9071e1efa0bdd84d4c3e5130302d8f0240baba4b84a71cc032f2235a5ff0fae"
          "277c3e8f9112bef44c9ae20d175fc9a4058bfc930ba31b02e2e4f444483710f2"
          "4a"
        }
      }
    },
    {
      "Example 6: A 1029-bit RSA key pair",
      "12b17f6dad2ecd19ff46dc13f7860f09e0e0cfb677b38a52592305ceaf022c16"
      "6db90d04ac29e33f7dd12d9faf66e0816bb63ead267cc7d46c17c37be214bca2"
      "a22d723a64e44407436b6fc965729aefc2554f376cd5dcea68293780a62bf39d"
      "0029485a160bbb9e5dc0972d21a504f52e5ee028aa416332f510b2e9cff5f722"
      "af",
      "010001",
      "0295eca3560618369559cecd303aa9cfdafc1d9f06959df75ffef929aa896961"
      "bcd190dc6997eda7f5963e724d07b4dc11f3065e5ae97d96835112280b9084bb"
      "14f2a21ebd4e889d41b9c4132ec1956fcab8bb2fed0575884936522c5ff7d332"
      "61904824e7cadee4e0bb372d2457cf78e2bd1286228ff83f10731ce63c90cff3"
      "f9",
      {
        {
          "OAEP Example 6.1",
          "4046ca8baa3347ca27f49e0d81f9cc1d71be9ba517d4",
          "dd0f6cfe415e88e5a469a51fbba6dfd40adb4384",
          "0630eebcd2856c24f798806e41f9e67345eda9ceda386acc9facaea1eeed06ac"
          "e583709718d9d169fadf414d5c76f92996833ef305b75b1e4b95f662a20faedc"
          "3bae0c4827a8bf8a88edbd57ec203a27a841f02e43a615bab1a8cac0701de34d"
          "ebdef62a088089b55ec36ea7522fd3ec8d06b6a073e6df833153bc0aefd93bd1"
          "a3"
        },{
          "OAEP Example 6.2",
          "5cc72c60231df03b3d40f9b57931bc31109f972527f28b19e7480c7288cb3c92"
          "b22512214e4be6c914792ddabdf57faa8aa7",
          "8d14bd946a1351148f5cae2ed9a0c653e85ebd85",
          "0ebc37376173a4fd2f89cc55c2ca62b26b11d51c3c7ce49e8845f74e7607317c"
          "436bc8d23b9667dfeb9d087234b47bc6837175ae5c0559f6b81d7d22416d3e50"
          "f4ac533d8f0812f2db9e791fe9c775ac8b6ad0f535ad9ceb23a4a02014c58ab3"
          "f8d3161499a260f39348e714ae2a1d3443208fd8b722ccfdfb393e98011f99e6"
          "3f"
        },{
          "OAEP Example 6.3",
          "b20e651303092f4bccb43070c0f86d23049362ed96642fc5632c27db4a52e3d8"
          "31f2ab068b23b149879c002f6bf3feee97591112562c",
          "6c075bc45520f165c0bf5ea4c5df191bc9ef0e44",
          "0a98bf1093619394436cf68d8f38e2f158fde8ea54f3435f239b8d06b8321844"
          "202476aeed96009492480ce3a8d705498c4c8c68f01501dc81db608f60087350"
          "c8c3b0bd2e9ef6a81458b7c801b89f2e4fe99d4900ba6a4b5e5a96d865dc676c"
          "7755928794130d6280a8160a190f2df3ea7cf9aa0271d88e9e6905ecf1c5152d"
          "65"
        },{
          "OAEP Example 6.4",
          "684e3038c5c041f7",
          "3bbc3bd6637dfe12846901029bf5b0c07103439c",
          "008e7a67cacfb5c4e24bec7dee149117f19598ce8c45808fef88c608ff9cd6e6"
          "95263b9a3c0ad4b8ba4c95238e96a8422b8535629c8d5382374479ad13fa3997"
          "4b242f9a759eeaf9c83ad5a8ca18940a0162ba755876df263f4bd50c6525c560"
          "90267c1f0e09ce0899a0cf359e88120abd9bf893445b3cae77d3607359ae9a52"
          "f8"
        },{
          "OAEP Example 6.5",
          "32488cb262d041d6e4dd35f987bf3ca696db1f06ac29a44693",
          "b46b41893e8bef326f6759383a83071dae7fcabc",
          "00003474416c7b68bdf961c385737944d7f1f40cb395343c693cc0b4fe63b31f"
          "edf1eaeeac9ccc0678b31dc32e0977489514c4f09085f6298a9653f01aea4045"
          "ff582ee887be26ae575b73eef7f3774921e375a3d19adda0ca31aa1849887c1f"
          "42cac9677f7a2f4e923f6e5a868b38c084ef187594dc9f7f048fea2e02955384"
          "ab"
        },{
          "OAEP Example 6.6",
          "50ba14be8462720279c306ba",
          "0a2403312a41e3d52f060fbc13a67de5cf7609a7",
          "0a026dda5fc8785f7bd9bf75327b63e85e2c0fdee5dadb65ebdcac9ae1de95c9"
          "2c672ab433aa7a8e69ce6a6d8897fac4ac4a54de841ae5e5bbce7687879d7963"
          "4cea7a30684065c714d52409b928256bbf53eabcd5231eb7259504537399bd29"
          "164b726d33a46da701360a4168a091ccab72d44a62fed246c0ffea5b1348ab54"
          "70"
        }
      }
    },
    {
      "Example 7: A 1030-bit RSA key pair",
      "311179f0bcfc9b9d3ca315d00ef30d7bdd3a2cfae9911bfedcb948b3a4782d07"
      "32b6ab44aa4bf03741a644dc01bec3e69b01a033e675d8acd7c4925c6b1aec31"
      "19051dfd89762d215d45475ffcb59f908148623f37177156f6ae86dd7a7c5f43"
      "dc1e1f908254058a284a5f06c0021793a87f1ac5feff7dcaee69c5e51a3789e3"
      "73",
      "010001",
      "070cfcff2feb8276e27432c45dfee48f49b7917d6530e1f0ca3460f32e027617"
      "4487c56e22a45d2500d7775495219d7d165a9cf3bd92c32af9a98d8dc9cc2968"
      "00adc94a0a54fb40f34291bf84ee8ea12b6f109359c6d3542a50f9c767f5cfff"
      "05a681c2e656fb77caaadb4be9468d8abcd4df98f58e86d2053fa1349f748e21"
      "b1",
      {
        {
          "OAEP Example 7.1",
          "47aae909",
          "43dd09a07ff4cac71caa4632ee5e1c1daee4cd8f",
          "1688e4ce7794bba6cb7014169ecd559cede2a30b56a52b68d9fe18cf1973ef97"
          "b2a03153951c755f6294aa49adbdb55845ab6875fb3986c93ecf927962840d28"
          "2f9e54ce8b690f7c0cb8bbd73440d9571d1b16cd9260f9eab4783cc482e5223d"
          "c60973871783ec27b0ae0fd47732cbc286a173fc92b00fb4ba6824647cd93c85"
          "c1"
        },{
          "OAEP Example 7.2",
          "1d9b2e2223d9bc13bfb9f162ce735db48ba7c68f6822a0a1a7b6ae165834e7",
          "3a9c3cec7b84f9bd3adecbc673ec99d54b22bc9b",
          "1052ed397b2e01e1d0ee1c50bf24363f95e504f4a03434a08fd822574ed6b973"
          "6edbb5f390db10321479a8a139350e2bd4977c3778ef331f3e78ae118b268451"
          "f20a2f01d471f5d53c566937171b2dbc2d4bde459a5799f0372d6574239b2323"
          "d245d0bb81c286b63c89a361017337e4902f88a467f4c7f244bfd5ab46437ff3"
          "b6"
        },{
          "OAEP Example 7.3",
          "d976fc",
          "76a75e5b6157a556cf8884bb2e45c293dd545cf5",
          "2155cd843ff24a4ee8badb7694260028a490813ba8b369a4cbf106ec148e5298"
          "707f5965be7d101c1049ea8584c24cd63455ad9c104d686282d3fb803a4c11c1"
          "c2e9b91c7178801d1b6640f003f5728df007b8a4ccc92bce05e41a27278d7c85"
          "018c52414313a5077789001d4f01910b72aad05d220aa14a58733a7489bc5455"
          "6b"
        },{
          "OAEP Example 7.4",
          "d4738623df223aa43843df8467534c41d013e0c803c624e263666b239bde40a5"
          "f29aeb8de79e3daa61dd0370f49bd4b013834b98212aef6b1c5ee373b3cb",
          "7866314a6ad6f2b250a35941db28f5864b585859",
          "0ab14c373aeb7d4328d0aaad8c094d88b9eb098b95f21054a29082522be7c27a"
          "312878b637917e3d819e6c3c568db5d843802b06d51d9e98a2be0bf40c031423"
          "b00edfbff8320efb9171bd2044653a4cb9c5122f6c65e83cda2ec3c126027a9c"
          "1a56ba874d0fea23f380b82cf240b8cf540004758c4c77d934157a74f3fc12bf"
          "ac"
        },{
          "OAEP Example 7.5",
          "bb47231ca5ea1d3ad46c99345d9a8a61",
          "b2166ed472d58db10cab2c6b000cccf10a7dc509",
          "028387a318277434798b4d97f460068df5298faba5041ba11761a1cb7316b241"
          "84114ec500257e2589ed3b607a1ebbe97a6cc2e02bf1b681f42312a33b7a77d8"
          "e7855c4a6de03e3c04643f786b91a264a0d6805e2cea91e68177eb7a64d9255e"
          "4f27e713b7ccec00dc200ebd21c2ea2bb890feae4942df941dc3f97890ed3474"
          "78"
        },{
          "OAEP Example 7.6",
          "2184827095d35c3f86f600e8e59754013296",
          "52673bde2ca166c2aa46131ac1dc808d67d7d3b1",
          "14c678a94ad60525ef39e959b2f3ba5c097a94ff912b67dbace80535c187abd4"
          "7d075420b1872152bba08f7fc31f313bbf9273c912fc4c0149a9b0cfb79807e3"
          "46eb332069611bec0ff9bcd168f1f7c33e77313cea454b94e2549eecf002e2ac"
          "f7f6f2d2845d4fe0aab2e5a92ddf68c480ae11247935d1f62574842216ae6741"
          "15"
        }
      }
    },
    {
      "Example 8: A 1031-bit RSA key pair",
      "5bdf0e30d321dda5147f882408fa69195480df8f80d3f6e8bf5818504f36427c"
      "a9b1f5540b9c65a8f6974cf8447a244d9280201bb49fcbbe6378d1944cd227e2"
      "30f96e3d10f819dcef276c64a00b2a4b6701e7d01de5fabde3b1e9a0df82f463"
      "1359cd22669647fbb1717246134ed7b497cfffbdc42b59c73a96ed90166212df"
      "f7",
      "010001",
      "0f7d1e9e5aaa25fd13e4a0663ae144e0d15f5cd18bcdb09df2cc7e64e3c5e915"
      "ad62645304161d098c715bb7ab8bd01d07eaf3fed7c7ed08af2a8a62ef44ab16"
      "b320e14af72a48f96afe262a0ae4cf65e635e910790cd4ee5cea768a4b2639f7"
      "e6f677b3f0bb6be32b75747d8909036f0264f58d401cdba131716157a75ecf63"
      "31",
      {
        {
          "OAEP Example 8.1",
          "050b755e5e6880f7b9e9d692a74c37aae449b31bfea6deff83747a897f6c2c82"
          "5bb1adbf850a3c96994b5de5b33cbc7d4a17913a7967",
          "7706ffca1ecfb1ebee2a55e5c6e24cd2797a4125",
          "09b3683d8a2eb0fb295b62ed1fb9290b714457b7825319f4647872af889b3040"
          "9472020ad12912bf19b11d4819f49614824ffd84d09c0a17e7d17309d1291979"
          "0410aa2995699f6a86dbe3242b5acc23af45691080d6b1ae810fb3e3057087f0"
          "970092ce00be9562ff4053b6262ce0caa93e13723d2e3a5ba075d45f0d61b54b"
          "61"
        },{
          "OAEP Example 8.2",
          "4eb68dcd93ca9b19df111bd43608f557026fe4aa1d5cfac227a3eb5ab9548c18"
          "a06dded23f81825986b2fcd71109ecef7eff88873f075c2aa0c469f69c92bc",
          "a3717da143b4dcffbc742665a8fa950585548343",
          "2ecf15c97c5a15b1476ae986b371b57a24284f4a162a8d0c8182e7905e792256"
          "f1812ba5f83f1f7a130e42dcc02232844edc14a31a68ee97ae564a383a341165"
          "6424c5f62ddb646093c367be1fcda426cf00a06d8acb7e57776fbbd855ac3df5"
          "06fc16b1d7c3f2110f3d8068e91e186363831c8409680d8da9ecd8cf1fa20ee3"
          "9d"
        },{
          "OAEP Example 8.3",
          "8604ac56328c1ab5ad917861",
          "ee06209073cca026bb264e5185bf8c68b7739f86",
          "4bc89130a5b2dabb7c2fcf90eb5d0eaf9e681b7146a38f3173a3d9cfec52ea9e"
          "0a41932e648a9d69344c50da763f51a03c95762131e8052254dcd2248cba40fd"
          "31667786ce05a2b7b531ac9dac9ed584a59b677c1a8aed8c5d15d68c05569e2b"
          "e780bf7db638fd2bfd2a85ab276860f3777338fca989ffd743d13ee08e0ca989"
          "3f"
        },{
          "OAEP Example 8.4",
          "fdda5fbf6ec361a9d9a4ac68af216a0686f438b1e0e5c36b955f74e107f39c0d"
          "ddcc",
          "990ad573dc48a973235b6d82543618f2e955105d",
          "2e456847d8fc36ff0147d6993594b9397227d577752c79d0f904fcb039d4d812"
          "fea605a7b574dd82ca786f93752348438ee9f5b5454985d5f0e1699e3e7ad175"
          "a32e15f03deb042ab9fe1dd9db1bb86f8c089ccb45e7ef0c5ee7ca9b7290ca6b"
          "15bed47039788a8a93ff83e0e8d6244c71006362deef69b6f416fb3c684383fb"
          "d0"
        },{
          "OAEP Example 8.5",
          "4a5f4914bee25de3c69341de07",
          "ecc63b28f0756f22f52ac8e6ec1251a6ec304718",
          "1fb9356fd5c4b1796db2ebf7d0d393cc810adf6145defc2fce714f79d93800d5"
          "e2ac211ea8bbecca4b654b94c3b18b30dd576ce34dc95436ef57a09415645923"
          "359a5d7b4171ef22c24670f1b229d3603e91f76671b7df97e7317c97734476d5"
          "f3d17d21cf82b5ba9f83df2e588d36984fd1b584468bd23b2e875f32f68953f7"
          "b2"
        },{
          "OAEP Example 8.6",
          "8e07d66f7b880a72563abcd3f35092bc33409fb7f88f2472be",
          "3925c71b362d40a0a6de42145579ba1e7dd459fc",
          "3afd9c6600147b21798d818c655a0f4c9212db26d0b0dfdc2a7594ccb3d22f5b"
          "f1d7c3e112cd73fc7d509c7a8bafdd3c274d1399009f9609ec4be6477e453f07"
          "5aa33db382870c1c3409aef392d7386ae3a696b99a94b4da0589447e955d16c9"
          "8b17602a59bd736279fcd8fb280c4462d590bfa9bf13fed570eafde97330a2c2"
          "10"
        }
      }
    },
    {
      "Example 9: A 1536-bit RSA key pair",
      "cf2cd41e34ca3a728ea5cb8aff64c36d27bdef5364e336fd68d3123c5a196a8c"
      "287013e853d5156d58d151954520fb4f6d7b17abb6817765909c576119659d90"
      "2b1906ed8a2b10c155c24d124528dab9eeae379beac66e4a411786dcb8fd0062"
      "ebc030de1219a04c2a8c1b7dd3131e4d6b6caee2e31a5ed41ac1509b2ef1ee2a"
      "b18364be568ca941c25ecc84ff9d643b5ec1aaae102a20d73f479b780fd6da91"
      "075212d9eac03a0674d899eba2e431f4c44b615b6ba2232bd4b33baed73d625d",
      "010001",
      "198c141e23715a92bccf6a119a5bc11389468d2811f548d727e17b4ab0eb986d"
      "6f211efb53b71f7ccbea87ee69c75ee615008c5332deb52bf390abdfbfe37d72"
      "05368159b2638c1de326e21d22251f0fb5848b3bf15005d2a74330f0afe916ee"
      "62ccc1344d1d83a709e60676273840f7f377424a5e0a4da75f01b31ff76819cf"
      "9cbfdd215243c3917c03ef38199312e567b3bf7aed3ab457f371ef8a1423f45b"
      "68c6e282ec111bba2833b987fd69fad83bc1b8c613c5e1ea16c11ed125ea7ec1",
      {
        {
          "OAEP Example 9.1",
          "f735fd55ba92592c3b52b8f9c4f69aaa1cbef8fe88add095595412467f9cf4ec"
          "0b896c59eda16210e7549c8abb10cdbc21a12ec9b6b5b8fd2f10399eb6",
          "8ec965f134a3ec9931e92a1ca0dc8169d5ea705c",
          "267bcd118acab1fc8ba81c85d73003cb8610fa55c1d97da8d48a7c7f06896a4d"
          "b751aa284255b9d36ad65f37653d829f1b37f97b8001942545b2fc2c55a7376c"
          "a7a1be4b1760c8e05a33e5aa2526b8d98e317088e7834c755b2a59b12631a182"
          "c05d5d43ab1779264f8456f515ce57dfdf512d5493dab7b7338dc4b7d78db9c0"
          "91ac3baf537a69fc7f549d979f0eff9a94fda4169bd4d1d19a69c99e33c3b554"
          "90d501b39b1edae118ff6793a153261584d3a5f39f6e682e3d17c8cd1261fa72"
        },{
          "OAEP Example 9.2",
          "81b906605015a63aabe42ddf11e1978912f5404c7474b26dce3ed482bf961ecc"
          "818bf420c54659",
          "ecb1b8b25fa50cdab08e56042867f4af5826d16c",
          "93ac9f0671ec29acbb444effc1a5741351d60fdb0e393fbf754acf0de49761a1"
          "4841df7772e9bc82773966a1584c4d72baea00118f83f35cca6e537cbd4d811f"
          "5583b29783d8a6d94cd31be70d6f526c10ff09c6fa7ce069795a3fcd0511fd5f"
          "cb564bcc80ea9c78f38b80012539d8a4ddf6fe81e9cddb7f50dbbbbcc7e5d860"
          "97ccf4ec49189fb8bf318be6d5a0715d516b49af191258cd32dc833ce6eb4673"
          "c03a19bbace88cc54895f636cc0c1ec89096d11ce235a265ca1764232a689ae8"
        },{
          "OAEP Example 9.3",
          "fd326429df9b890e09b54b18b8f34f1e24",
          "e89bb032c6ce622cbdb53bc9466014ea77f777c0",
          "81ebdd95054b0c822ef9ad7693f5a87adfb4b4c4ce70df2df84ed49c04da58ba"
          "5fc20a19e1a6e8b7a3900b22796dc4e869ee6b42792d15a8eceb56c09c69914e"
          "813cea8f6931e4b8ed6f421af298d595c97f4789c7caa612c7ef360984c21b93"
          "edc5401068b5af4c78a8771b984d53b8ea8adf2f6a7d4a0ba76c75e1dd9f658f"
          "20ded4a46071d46d7791b56803d8fea7f0b0f8e41ae3f09383a6f9585fe7753e"
          "aaffd2bf94563108beecc207bbb535f5fcc705f0dde9f708c62f49a9c90371d3"
        },{
          "OAEP Example 9.4",
          "f1459b5f0c92f01a0f723a2e5662484d8f8c0a20fc29dad6acd43bb5f3effdf4"
          "e1b63e07fdfe6628d0d74ca19bf2d69e4a0abf86d293925a796772f8088e",
          "606f3b99c0b9ccd771eaa29ea0e4c884f3189ccc",
          "bcc35f94cde66cb1136625d625b94432a35b22f3d2fa11a613ff0fca5bd57f87"
          "b902ccdc1cd0aebcb0715ee869d1d1fe395f6793003f5eca465059c88660d446"
          "ff5f0818552022557e38c08a67ead991262254f10682975ec56397768537f497"
          "7af6d5f6aaceb7fb25dec5937230231fd8978af49119a29f29e424ab8272b475"
          "62792d5c94f774b8829d0b0d9f1a8c9eddf37574d5fa248eefa9c5271fc5ec25"
          "79c81bdd61b410fa61fe36e424221c113addb275664c801d34ca8c6351e4a858"
        },{
          "OAEP Example 9.5",
          "53e6e8c729d6f9c319dd317e74b0db8e4ccca25f3c8305746e137ac63a63ef37"
          "39e7b595abb96e8d55e54f7bd41ab433378ffb911d",
          "fcbc421402e9ecabc6082afa40ba5f26522c840e",
          "232afbc927fa08c2f6a27b87d4a5cb09c07dc26fae73d73a90558839f4fd66d2"
          "81b87ec734bce237ba166698ed829106a7de6942cd6cdce78fed8d2e4d81428e"
          "66490d036264cef92af941d3e35055fe3981e14d29cbb9a4f67473063baec79a"
          "1179f5a17c9c1832f2838fd7d5e59bb9659d56dce8a019edef1bb3accc697cc6"
          "cc7a778f60a064c7f6f5d529c6210262e003de583e81e3167b89971fb8c0e15d"
          "44fffef89b53d8d64dd797d159b56d2b08ea5307ea12c241bd58d4ee278a1f2e"
        },{
          "OAEP Example 9.6",
          "b6b28ea2198d0c1008bc64",
          "23aade0e1e08bb9b9a78d2302a52f9c21b2e1ba2",
          "438cc7dc08a68da249e42505f8573ba60e2c2773d5b290f4cf9dff718e842081"
          "c383e67024a0f29594ea987b9d25e4b738f285970d195abb3a8c8054e3d79d6b"
          "9c9a8327ba596f1259e27126674766907d8d582ff3a8476154929adb1e6d1235"
          "b2ccb4ec8f663ba9cc670a92bebd853c8dbf69c6436d016f61add836e9473245"
          "0434207f9fd4c43dec2a12a958efa01efe2669899b5e604c255c55fb7166de55"
          "89e369597bb09168c06dd5db177e06a1740eb2d5c82faeca6d92fcee9931ba9f"
        }
      }
    },
    {
      "Example 10: A 2048-bit RSA key pair",
      "ae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8"
      "df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5"
      "404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2f"
      "a1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a0"
      "3381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600"
      "c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aef"
      "a2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88"
      "d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb",
      "010001",
      "056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e59"
      "6a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d"
      "19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbe"
      "be57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f10"
      "2cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564"
      "fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c43"
      "0ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101"
      "848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79",
      {
        {
          "OAEP Example 10.1",
          "8bba6bf82a6c0f86d5f1756e97956870b08953b06b4eb205bc1694ee",
          "47e1ab7119fee56c95ee5eaad86f40d0aa63bd33",
          "53ea5dc08cd260fb3b858567287fa91552c30b2febfba213f0ae87702d068d19"
          "bab07fe574523dfb42139d68c3c5afeee0bfe4cb7969cbf382b804d6e6139614"
          "4e2d0e60741f8993c3014b58b9b1957a8babcd23af854f4c356fb1662aa72bfc"
          "c7e586559dc4280d160c126785a723ebeebeff71f11594440aaef87d10793a87"
          "74a239d4a04c87fe1467b9daf85208ec6c7255794a96cc29142f9a8bd418e3c1"
          "fd67344b0cd0829df3b2bec60253196293c6b34d3f75d32f213dd45c6273d505"
          "adf4cced1057cb758fc26aeefa441255ed4e64c199ee075e7f16646182fdb464"
          "739b68ab5daff0e63e9552016824f054bf4d3c8c90a97bb6b6553284eb429fcc"
        },{
          "OAEP Example 10.2",
          "e6ad181f053b58a904f2457510373e57",
          "6d17f5b4c1ffac351d195bf7b09d09f09a4079cf",
          "a2b1a430a9d657e2fa1c2bb5ed43ffb25c05a308fe9093c01031795f58744001"
          "10828ae58fb9b581ce9dddd3e549ae04a0985459bde6c626594e7b05dc4278b2"
          "a1465c1368408823c85e96dc66c3a30983c639664fc4569a37fe21e5a195b577"
          "6eed2df8d8d361af686e750229bbd663f161868a50615e0c337bec0ca35fec0b"
          "b19c36eb2e0bbcc0582fa1d93aacdb061063f59f2ce1ee43605e5d89eca183d2"
          "acdfe9f81011022ad3b43a3dd417dac94b4e11ea81b192966e966b182082e719"
          "64607b4f8002f36299844a11f2ae0faeac2eae70f8f4f98088acdcd0ac556e9f"
          "ccc511521908fad26f04c64201450305778758b0538bf8b5bb144a828e629795"
        },{
          "OAEP Example 10.3",
          "510a2cf60e866fa2340553c94ea39fbc256311e83e94454b4124",
          "385387514deccc7c740dd8cdf9daee49a1cbfd54",
          "9886c3e6764a8b9a84e84148ebd8c3b1aa8050381a78f668714c16d9cfd2a6ed"
          "c56979c535d9dee3b44b85c18be8928992371711472216d95dda98d2ee8347c9"
          "b14dffdff84aa48d25ac06f7d7e65398ac967b1ce90925f67dce049b7f812db0"
          "742997a74d44fe81dbe0e7a3feaf2e5c40af888d550ddbbe3bc20657a29543f8"
          "fc2913b9bd1a61b2ab2256ec409bbd7dc0d17717ea25c43f42ed27df8738bf4a"
          "fc6766ff7aff0859555ee283920f4c8a63c4a7340cbafddc339ecdb4b0515002"
          "f96c932b5b79167af699c0ad3fccfdf0f44e85a70262bf2e18fe34b850589975"
          "e867ff969d48eabf212271546cdc05a69ecb526e52870c836f307bd798780ede"
        },{
          "OAEP Example 10.4",
          "bcdd190da3b7d300df9a06e22caae2a75f10c91ff667b7c16bde8b53064a2649"
          "a94045c9",
          "5caca6a0f764161a9684f85d92b6e0ef37ca8b65",
          "6318e9fb5c0d05e5307e1683436e903293ac4642358aaa223d7163013aba87e2"
          "dfda8e60c6860e29a1e92686163ea0b9175f329ca3b131a1edd3a77759a8b97b"
          "ad6a4f8f4396f28cf6f39ca58112e48160d6e203daa5856f3aca5ffed577af49"
          "9408e3dfd233e3e604dbe34a9c4c9082de65527cac6331d29dc80e0508a0fa71"
          "22e7f329f6cca5cfa34d4d1da417805457e008bec549e478ff9e12a763c477d1"
          "5bbb78f5b69bd57830fc2c4ed686d79bc72a95d85f88134c6b0afe56a8ccfbc8"
          "55828bb339bd17909cf1d70de3335ae07039093e606d655365de6550b872cd6d"
          "e1d440ee031b61945f629ad8a353b0d40939e96a3c450d2a8d5eee9f678093c8"
        },{
          "OAEP Example 10.5",
          "a7dd6c7dc24b46f9dd5f1e91ada4c3b3df947e877232a9",
          "95bca9e3859894b3dd869fa7ecd5bbc6401bf3e4",
          "75290872ccfd4a4505660d651f56da6daa09ca1301d890632f6a992f3d565cee"
          "464afded40ed3b5be9356714ea5aa7655f4a1366c2f17c728f6f2c5a5d1f8e28"
          "429bc4e6f8f2cff8da8dc0e0a9808e45fd09ea2fa40cb2b6ce6ffff5c0e159d1"
          "1b68d90a85f7b84e103b09e682666480c657505c0929259468a314786d74eab1"
          "31573cf234bf57db7d9e66cc6748192e002dc0deea930585f0831fdcd9bc33d5"
          "1f79ed2ffc16bcf4d59812fcebcaa3f9069b0e445686d644c25ccf63b456ee5f"
          "a6ffe96f19cdf751fed9eaf35957754dbf4bfea5216aa1844dc507cb2d080e72"
          "2eba150308c2b5ff1193620f1766ecf4481bafb943bd292877f2136ca494aba0"
        },{
          "OAEP Example 10.6",
          "eaf1a73a1b0c4609537de69cd9228bbcfb9a8ca8c6c3efaf056fe4a7f4634ed0"
          "0b7c39ec6922d7b8ea2c04ebac",
          "9f47ddf42e97eea856a9bdbc714eb3ac22f6eb32",
          "2d207a73432a8fb4c03051b3f73b28a61764098dfa34c47a20995f8115aa6816"
          "679b557e82dbee584908c6e69782d7deb34dbd65af063d57fca76a5fd069492f"
          "d6068d9984d209350565a62e5c77f23038c12cb10c6634709b547c46f6b4a709"
          "bd85ca122d74465ef97762c29763e06dbc7a9e738c78bfca0102dc5e79d65b97"
          "3f28240caab2e161a78b57d262457ed8195d53e3c7ae9da021883c6db7c24afd"
          "d2322eac972ad3c354c5fcef1e146c3a0290fb67adf007066e00428d2cec18ce"
          "58f9328698defef4b2eb5ec76918fde1c198cbb38b7afc67626a9aefec4322bf"
          "d90d2563481c9a221f78c8272c82d1b62ab914e1c69f6af6ef30ca5260db4a46"
        }
      }
    }
  };
  gpg_error_t err;
  int tno, mno;

  for (tno = 0; tno < DIM (tbl); tno++)
    {
      void *rsa_n, *rsa_e, *rsa_d;
      size_t rsa_n_len, rsa_e_len, rsa_d_len;
      gcry_sexp_t sec_key, pub_key;

      if (verbose > 1)
        info ("(%s)\n", tbl[tno].desc);

      rsa_n = data_from_hex (tbl[tno].n, &rsa_n_len);
      rsa_e = data_from_hex (tbl[tno].e, &rsa_e_len);
      rsa_d = data_from_hex (tbl[tno].d, &rsa_d_len);
      err = gcry_sexp_build (&sec_key, NULL,
                             "(private-key (rsa (n %b)(e %b)(d %b)))",
                             (int)rsa_n_len, rsa_n,
                             (int)rsa_e_len, rsa_e,
                             (int)rsa_d_len, rsa_d);
      if (err)
        die ("constructing private key failed: %s\n", gpg_strerror (err));
      err = gcry_sexp_build (&pub_key, NULL,
                             "(public-key (rsa (n %b)(e %b)))",
                             (int)rsa_n_len, rsa_n,
                             (int)rsa_e_len, rsa_e);
      if (err)
        die ("constructing public key failed: %s\n", gpg_strerror (err));
      gcry_free (rsa_n);
      gcry_free (rsa_e);
      gcry_free (rsa_d);

      for (mno = 0; mno < DIM (tbl[0].m); mno++)
        {
          void *mesg, *seed, *encr;
          size_t mesg_len, seed_len, encr_len;
          gcry_sexp_t plain, ciph;

          if (verbose)
            info ("running test: %s\n", tbl[tno].m[mno].desc);

          mesg = data_from_hex (tbl[tno].m[mno].mesg, &mesg_len);
          seed = data_from_hex (tbl[tno].m[mno].seed, &seed_len);

          err = gcry_sexp_build (&plain, NULL,
                                 "(data (flags oaep)(hash-algo sha1)"
                                 "(value %b)(random-override %b))",
                                 (int)mesg_len, mesg,
                                 (int)seed_len, seed);
          if (err)
            die ("constructing plain data failed: %s\n", gpg_strerror (err));
          gcry_free (mesg);
          gcry_free (seed);

          err = gcry_pk_encrypt (&ciph, plain, pub_key);
          if (err)
            {
              show_sexp ("plain:\n", ciph);
              fail ("gcry_pk_encrypt failed: %s\n", gpg_strerror (err));
            }
          else
            {
              if (extract_cmp_data (ciph, "a", tbl[tno].m[mno].encr,
                                    tbl[tno].m[mno].desc))
                {
                  show_sexp ("encrypt result:\n", ciph);
                  fail ("mismatch in gcry_pk_encrypt\n");
                }
              gcry_sexp_release (ciph);
              ciph = NULL;
            }
          gcry_sexp_release (plain);
          plain = NULL;

          /* Now test the decryption.  */
          seed = data_from_hex (tbl[tno].m[mno].seed, &seed_len);
          encr = data_from_hex (tbl[tno].m[mno].encr, &encr_len);

          err = gcry_sexp_build (&ciph, NULL,
                                 "(enc-val (flags oaep)(hash-algo sha1)"
                                 "(random-override %b)"
                                 "(rsa (a %b)))",
                                 (int)seed_len, seed,
                                 (int)encr_len, encr);
          if (err)
            die ("constructing cipher data failed: %s\n", gpg_strerror (err));
          gcry_free (encr);
          gcry_free (seed);

          err = gcry_pk_decrypt (&plain, ciph, sec_key);
          if (err)
            {
              show_sexp ("ciph:\n", ciph);
              fail ("gcry_pk_decrypt failed: %s\n", gpg_strerror (err));
            }
          else
            {
              if (extract_cmp_data (plain, "value", tbl[tno].m[mno].mesg,
                                    tbl[tno].m[mno].desc))
                {
                  show_sexp ("decrypt result:\n", plain);
                  fail ("mismatch in gcry_pk_decrypt\n");
                }
              gcry_sexp_release (plain);
              plain = NULL;
            }
          gcry_sexp_release (ciph);
          ciph = NULL;
        }

      gcry_sexp_release (sec_key);
      gcry_sexp_release (pub_key);
    }
}


/* Check against the PSS test vectors from
   ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1d2-vec.zip .  */
static void
check_pss (void)
{
  static struct {
    const char *desc;
    const char *n, *e, *d;
    struct {
      const char *desc;
      const char *mesg;
      const char *salt;
      const char *sign;
    } m[6];
  } tbl[] = {
    {
      "Example 1: A 1024-bit RSA key pair",
      "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991"
      "d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1df"
      "d5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f1"
      "05acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",
      "010001",
      "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e8"
      "94a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9a"
      "e55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c"
      "31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",
      {
        {
          "PSS Example 1.1",
          "cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b6"
          "2371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb76"
          "9757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb0"
          "61a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d61"
          "93c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c"
          "296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16"
          "be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0",
          "dee959c7e06411361420ff80185ed57f3e6776af",
          "9074308fb598e9701b2294388e52f971faac2b60a5145af185df5287b5ed2887"
          "e57ce7fd44dc8634e407c8e0e4360bc226f3ec227f9d9e54638e8d31f5051215"
          "df6ebb9c2f9579aa77598a38f914b5b9c1bd83c4e2f9f382a0d0aa3542ffee65"
          "984a601bc69eb28deb27dca12c82c2d4c3f66cd500f1ff2b994d8a4e30cbb33c"
        },{
          "PSS Example 1.2",
          "851384cdfe819c22ed6c4ccb30daeb5cf059bc8e1166b7e3530c4c233e2b5f8f"
          "71a1cca582d43ecc72b1bca16dfc7013226b9e",
          "ef2869fa40c346cb183dab3d7bffc98fd56df42d",
          "3ef7f46e831bf92b32274142a585ffcefbdca7b32ae90d10fb0f0c729984f04e"
          "f29a9df0780775ce43739b97838390db0a5505e63de927028d9d29b219ca2c45"
          "17832558a55d694a6d25b9dab66003c4cccd907802193be5170d26147d37b935"
          "90241be51c25055f47ef62752cfbe21418fafe98c22c4d4d47724fdb5669e843"
        },{
          "PSS Example 1.3",
          "a4b159941761c40c6a82f2b80d1b94f5aa2654fd17e12d588864679b54cd04ef"
          "8bd03012be8dc37f4b83af7963faff0dfa225477437c48017ff2be8191cf3955"
          "fc07356eab3f322f7f620e21d254e5db4324279fe067e0910e2e81ca2cab31c7"
          "45e67a54058eb50d993cdb9ed0b4d029c06d21a94ca661c3ce27fae1d6cb20f4"
          "564d66ce4767583d0e5f060215b59017be85ea848939127bd8c9c4d47b51056c"
          "031cf336f17c9980f3b8f5b9b6878e8b797aa43b882684333e17893fe9caa6aa"
          "299f7ed1a18ee2c54864b7b2b99b72618fb02574d139ef50f019c9eef4169713"
          "38e7d470",
          "710b9c4747d800d4de87f12afdce6df18107cc77",
          "666026fba71bd3e7cf13157cc2c51a8e4aa684af9778f91849f34335d141c001"
          "54c4197621f9624a675b5abc22ee7d5baaffaae1c9baca2cc373b3f33e78e614"
          "3c395a91aa7faca664eb733afd14d8827259d99a7550faca501ef2b04e33c23a"
          "a51f4b9e8282efdb728cc0ab09405a91607c6369961bc8270d2d4f39fce612b1"
        },{
          "PSS Example 1.4",
          "bc656747fa9eafb3f0",
          "056f00985de14d8ef5cea9e82f8c27bef720335e",
          "4609793b23e9d09362dc21bb47da0b4f3a7622649a47d464019b9aeafe53359c"
          "178c91cd58ba6bcb78be0346a7bc637f4b873d4bab38ee661f199634c547a1ad"
          "8442e03da015b136e543f7ab07c0c13e4225b8de8cce25d4f6eb8400f81f7e18"
          "33b7ee6e334d370964ca79fdb872b4d75223b5eeb08101591fb532d155a6de87",
        },{
          "PSS Example 1.5",
          "b45581547e5427770c768e8b82b75564e0ea4e9c32594d6bff706544de0a8776"
          "c7a80b4576550eee1b2acabc7e8b7d3ef7bb5b03e462c11047eadd00629ae575"
          "480ac1470fe046f13a2bf5af17921dc4b0aa8b02bee6334911651d7f8525d10f"
          "32b51d33be520d3ddf5a709955a3dfe78283b9e0ab54046d150c177f037fdccc"
          "5be4ea5f68b5e5a38c9d7edcccc4975f455a6909b4",
          "80e70ff86a08de3ec60972b39b4fbfdcea67ae8e",
          "1d2aad221ca4d31ddf13509239019398e3d14b32dc34dc5af4aeaea3c095af73"
          "479cf0a45e5629635a53a018377615b16cb9b13b3e09d671eb71e387b8545c59"
          "60da5a64776e768e82b2c93583bf104c3fdb23512b7b4e89f633dd0063a530db"
          "4524b01c3f384c09310e315a79dcd3d684022a7f31c865a664e316978b759fad"
        },{
          "PSS Example 1.6",
          "10aae9a0ab0b595d0841207b700d48d75faedde3b775cd6b4cc88ae06e4694ec"
          "74ba18f8520d4f5ea69cbbe7cc2beba43efdc10215ac4eb32dc302a1f53dc6c4"
          "352267e7936cfebf7c8d67035784a3909fa859c7b7b59b8e39c5c2349f1886b7"
          "05a30267d402f7486ab4f58cad5d69adb17ab8cd0ce1caf5025af4ae24b1fb87"
          "94c6070cc09a51e2f9911311e3877d0044c71c57a993395008806b723ac38373"
          "d395481818528c1e7053739282053529510e935cd0fa77b8fa53cc2d474bd4fb"
          "3cc5c672d6ffdc90a00f9848712c4bcfe46c60573659b11e6457e861f0f604b6"
          "138d144f8ce4e2da73",
          "a8ab69dd801f0074c2a1fc60649836c616d99681",
          "2a34f6125e1f6b0bf971e84fbd41c632be8f2c2ace7de8b6926e31ff93e9af98"
          "7fbc06e51e9be14f5198f91f3f953bd67da60a9df59764c3dc0fe08e1cbef0b7"
          "5f868d10ad3fba749fef59fb6dac46a0d6e504369331586f58e4628f39aa2789"
          "82543bc0eeb537dc61958019b394fb273f215858a0a01ac4d650b955c67f4c58"
        }
      }
    },
    {
      "Example 2: A 1025-bit RSA key pair",
      "01d40c1bcf97a68ae7cdbd8a7bf3e34fa19dcca4ef75a47454375f94514d88fe"
      "d006fb829f8419ff87d6315da68a1ff3a0938e9abb3464011c303ad99199cf0c"
      "7c7a8b477dce829e8844f625b115e5e9c4a59cf8f8113b6834336a2fd2689b47"
      "2cbb5e5cabe674350c59b6c17e176874fb42f8fc3d176a017edc61fd326c4b33"
      "c9",
      "010001",
      "027d147e4673057377fd1ea201565772176a7dc38358d376045685a2e787c23c"
      "15576bc16b9f444402d6bfc5d98a3e88ea13ef67c353eca0c0ddba9255bd7b8b"
      "b50a644afdfd1dd51695b252d22e7318d1b6687a1c10ff75545f3db0fe602d5f"
      "2b7f294e3601eab7b9d1cecd767f64692e3e536ca2846cb0c2dd486a39fa75b1",
      {
        {
          "PSS Example 2.1",
          "daba032066263faedb659848115278a52c44faa3a76f37515ed336321072c40a"
          "9d9b53bc05014078adf520875146aae70ff060226dcb7b1f1fc27e9360",
          "57bf160bcb02bb1dc7280cf0458530b7d2832ff7",
          "014c5ba5338328ccc6e7a90bf1c0ab3fd606ff4796d3c12e4b639ed9136a5fec"
          "6c16d8884bdd99cfdc521456b0742b736868cf90de099adb8d5ffd1deff39ba4"
          "007ab746cefdb22d7df0e225f54627dc65466131721b90af445363a8358b9f60"
          "7642f78fab0ab0f43b7168d64bae70d8827848d8ef1e421c5754ddf42c2589b5"
          "b3"
        },{
          "PSS Example 2.2",
          "e4f8601a8a6da1be34447c0959c058570c3668cfd51dd5f9ccd6ad4411fe8213"
          "486d78a6c49f93efc2ca2288cebc2b9b60bd04b1e220d86e3d4848d709d032d1"
          "e8c6a070c6af9a499fcf95354b14ba6127c739de1bb0fd16431e46938aec0cf8"
          "ad9eb72e832a7035de9b7807bdc0ed8b68eb0f5ac2216be40ce920c0db0eddd3"
          "860ed788efaccaca502d8f2bd6d1a7c1f41ff46f1681c8f1f818e9c4f6d91a0c"
          "7803ccc63d76a6544d843e084e363b8acc55aa531733edb5dee5b5196e9f03e8"
          "b731b3776428d9e457fe3fbcb3db7274442d785890e9cb0854b6444dace791d7"
          "273de1889719338a77fe",
          "7f6dd359e604e60870e898e47b19bf2e5a7b2a90",
          "010991656cca182b7f29d2dbc007e7ae0fec158eb6759cb9c45c5ff87c7635dd"
          "46d150882f4de1e9ae65e7f7d9018f6836954a47c0a81a8a6b6f83f2944d6081"
          "b1aa7c759b254b2c34b691da67cc0226e20b2f18b42212761dcd4b908a62b371"
          "b5918c5742af4b537e296917674fb914194761621cc19a41f6fb953fbcbb649d"
          "ea"
        },{
          "PSS Example 2.3",
          "52a1d96c8ac39e41e455809801b927a5b445c10d902a0dcd3850d22a66d2bb07"
          "03e67d5867114595aabf5a7aeb5a8f87034bbb30e13cfd4817a9be7623002360"
          "6d0286a3faf8a4d22b728ec518079f9e64526e3a0cc7941aa338c437997c680c"
          "cac67c66bfa1",
          "fca862068bce2246724b708a0519da17e648688c",
          "007f0030018f53cdc71f23d03659fde54d4241f758a750b42f185f87578520c3"
          "0742afd84359b6e6e8d3ed959dc6fe486bedc8e2cf001f63a7abe16256a1b84d"
          "f0d249fc05d3194ce5f0912742dbbf80dd174f6c51f6bad7f16cf3364eba095a"
          "06267dc3793803ac7526aebe0a475d38b8c2247ab51c4898df7047dc6adf52c6"
          "c4"
        },{
          "PSS Example 2.4",
          "a7182c83ac18be6570a106aa9d5c4e3dbbd4afaeb0c60c4a23e1969d79ff",
          "8070ef2de945c02387684ba0d33096732235d440",
          "009cd2f4edbe23e12346ae8c76dd9ad3230a62076141f16c152ba18513a48ef6"
          "f010e0e37fd3df10a1ec629a0cb5a3b5d2893007298c30936a95903b6ba85555"
          "d9ec3673a06108fd62a2fda56d1ce2e85c4db6b24a81ca3b496c36d4fd06eb7c"
          "9166d8e94877c42bea622b3bfe9251fdc21d8d5371badad78a488214796335b4"
          "0b"
        },{
          "PSS Example 2.5",
          "86a83d4a72ee932a4f5630af6579a386b78fe88999e0abd2d49034a4bfc854dd"
          "94f1094e2e8cd7a179d19588e4aefc1b1bd25e95e3dd461f",
          "17639a4e88d722c4fca24d079a8b29c32433b0c9",
          "00ec430824931ebd3baa43034dae98ba646b8c36013d1671c3cf1cf8260c374b"
          "19f8e1cc8d965012405e7e9bf7378612dfcc85fce12cda11f950bd0ba8876740"
          "436c1d2595a64a1b32efcfb74a21c873b3cc33aaf4e3dc3953de67f0674c0453"
          "b4fd9f604406d441b816098cb106fe3472bc251f815f59db2e4378a3addc181e"
          "cf"
        },{
          "PSS Example 2.6",

          "049f9154d871ac4a7c7ab45325ba7545a1ed08f70525b2667cf1",
          "37810def1055ed922b063df798de5d0aabf886ee",
          "00475b1648f814a8dc0abdc37b5527f543b666bb6e39d30e5b49d3b876dccc58"
          "eac14e32a2d55c2616014456ad2f246fc8e3d560da3ddf379a1c0bd200f10221"
          "df078c219a151bc8d4ec9d2fc2564467811014ef15d8ea01c2ebbff8c2c8efab"
          "38096e55fcbe3285c7aa558851254faffa92c1c72b78758663ef4582843139d7"
          "a6"
        }
      }
    },
    {
      "Example 3: A 1026-bit RSA key pair",
      "02f246ef451ed3eebb9a310200cc25859c048e4be798302991112eb68ce6db67"
      "4e280da21feded1ae74880ca522b18db249385012827c515f0e466a1ffa691d9"
      "8170574e9d0eadb087586ca48933da3cc953d95bd0ed50de10ddcb6736107d6c"
      "831c7f663e833ca4c097e700ce0fb945f88fb85fe8e5a773172565b914a471a4"
      "43",
      "010001",
      "651451733b56de5ac0a689a4aeb6e6894a69014e076c88dd7a667eab3232bbcc"
      "d2fc44ba2fa9c31db46f21edd1fdb23c5c128a5da5bab91e7f952b67759c7cff"
      "705415ac9fa0907c7ca6178f668fb948d869da4cc3b7356f4008dfd5449d32ee"
      "02d9a477eb69fc29266e5d9070512375a50fbbcc27e238ad98425f6ebbf88991",
      {
        {
          "PSS Example 3.1",
          "594b37333bbb2c84524a87c1a01f75fcec0e3256f108e38dca36d70d0057",
          "f31ad6c8cf89df78ed77feacbcc2f8b0a8e4cfaa",
          "0088b135fb1794b6b96c4a3e678197f8cac52b64b2fe907d6f27de761124964a"
          "99a01a882740ecfaed6c01a47464bb05182313c01338a8cd097214cd68ca103b"
          "d57d3bc9e816213e61d784f182467abf8a01cf253e99a156eaa8e3e1f90e3c6e"
          "4e3aa2d83ed0345b89fafc9c26077c14b6ac51454fa26e446e3a2f153b2b1679"
          "7f"
        },{
          "PSS Example 3.2",
          "8b769528884a0d1ffd090cf102993e796dadcfbddd38e44ff6324ca451",
          "fcf9f0e1f199a3d1d0da681c5b8606fc642939f7",
          "02a5f0a858a0864a4f65017a7d69454f3f973a2999839b7bbc48bf7864116917"
          "9556f595fa41f6ff18e286c2783079bc0910ee9cc34f49ba681124f923dfa88f"
          "426141a368a5f5a930c628c2c3c200e18a7644721a0cbec6dd3f6279bde3e8f2"
          "be5e2d4ee56f97e7ceaf33054be7042bd91a63bb09f897bd41e81197dee99b11"
          "af"
        },{
          "PSS Example 3.3",
          "1abdba489c5ada2f995ed16f19d5a94d9e6ec34a8d84f84557d26e5ef9b02b22"
          "887e3f9a4b690ad1149209c20c61431f0c017c36c2657b35d7b07d3f5ad87085"
          "07a9c1b831df835a56f831071814ea5d3d8d8f6ade40cba38b42db7a2d3d7a29"
          "c8f0a79a7838cf58a9757fa2fe4c40df9baa193bfc6f92b123ad57b07ace3e6a"
          "c068c9f106afd9eeb03b4f37c25dbfbcfb3071f6f9771766d072f3bb070af660"
          "5532973ae25051",
          "986e7c43dbb671bd41b9a7f4b6afc80e805f2423",
          "0244bcd1c8c16955736c803be401272e18cb990811b14f72db964124d5fa7606"
          "49cbb57afb8755dbb62bf51f466cf23a0a1607576e983d778fceffa92df7548a"
          "ea8ea4ecad2c29dd9f95bc07fe91ecf8bee255bfe8762fd7690aa9bfa4fa0849"
          "ef728c2c42c4532364522df2ab7f9f8a03b63f7a499175828668f5ef5a29e380"
          "2c"
        },{
          "PSS Example 3.4",
          "8fb431f5ee792b6c2ac7db53cc428655aeb32d03f4e889c5c25de683c461b53a"
          "cf89f9f8d3aabdf6b9f0c2a1de12e15b49edb3919a652fe9491c25a7fce1f722"
          "c2543608b69dc375ec",
          "f8312d9c8eea13ec0a4c7b98120c87509087c478",
          "0196f12a005b98129c8df13c4cb16f8aa887d3c40d96df3a88e7532ef39cd992"
          "f273abc370bc1be6f097cfebbf0118fd9ef4b927155f3df22b904d90702d1f7b"
          "a7a52bed8b8942f412cd7bd676c9d18e170391dcd345c06a730964b3f30bcce0"
          "bb20ba106f9ab0eeb39cf8a6607f75c0347f0af79f16afa081d2c92d1ee6f836"
          "b8"
        },{
          "PSS Example 3.5",
          "fef4161dfaaf9c5295051dfc1ff3810c8c9ec2e866f7075422c8ec4216a9c4ff"
          "49427d483cae10c8534a41b2fd15fee06960ec6fb3f7a7e94a2f8a2e3e43dc4a"
          "40576c3097ac953b1de86f0b4ed36d644f23ae14425529622464ca0cbf0b1741"
          "347238157fab59e4de5524096d62baec63ac64",
          "50327efec6292f98019fc67a2a6638563e9b6e2d",
          "021eca3ab4892264ec22411a752d92221076d4e01c0e6f0dde9afd26ba5acf6d"
          "739ef987545d16683e5674c9e70f1de649d7e61d48d0caeb4fb4d8b24fba84a6"
          "e3108fee7d0705973266ac524b4ad280f7ae17dc59d96d3351586b5a3bdb895d"
          "1e1f7820ac6135d8753480998382ba32b7349559608c38745290a85ef4e9f9bd"
          "83"
        },{
          "PSS Example 3.6",
          "efd237bb098a443aeeb2bf6c3f8c81b8c01b7fcb3feb",
          "b0de3fc25b65f5af96b1d5cc3b27d0c6053087b3",
          "012fafec862f56e9e92f60ab0c77824f4299a0ca734ed26e0644d5d222c7f0bd"
          "e03964f8e70a5cb65ed44e44d56ae0edf1ff86ca032cc5dd4404dbb76ab85458"
          "6c44eed8336d08d457ce6c03693b45c0f1efef93624b95b8ec169c616d20e553"
          "8ebc0b6737a6f82b4bc0570924fc6b35759a3348426279f8b3d7744e2d222426"
          "ce"
        }
      }
    },
    {
      "Example 4: A 1027-bit RSA key pair",

      "054adb7886447efe6f57e0368f06cf52b0a3370760d161cef126b91be7f89c42"
      "1b62a6ec1da3c311d75ed50e0ab5fff3fd338acc3aa8a4e77ee26369acb81ba9"
      "00fa83f5300cf9bb6c53ad1dc8a178b815db4235a9a9da0c06de4e615ea1277c"
      "e559e9c108de58c14a81aa77f5a6f8d1335494498848c8b95940740be7bf7c37"
      "05",
      "010001",
      "fa041f8cd9697ceed38ec8caa275523b4dd72b09a301d3541d72f5d31c05cbce"
      "2d6983b36183af10690bd46c46131e35789431a556771dd0049b57461bf060c1"
      "f68472e8a67c25f357e5b6b4738fa541a730346b4a07649a2dfa806a69c975b6"
      "aba64678acc7f5913e89c622f2d8abb1e3e32554e39df94ba60c002e387d9011",
      {
        {
          "PSS Example 4.1",
          "9fb03b827c8217d9",
          "ed7c98c95f30974fbe4fbddcf0f28d6021c0e91d",
          "0323d5b7bf20ba4539289ae452ae4297080feff4518423ff4811a817837e7d82"
          "f1836cdfab54514ff0887bddeebf40bf99b047abc3ecfa6a37a3ef00f4a0c4a8"
          "8aae0904b745c846c4107e8797723e8ac810d9e3d95dfa30ff4966f4d75d1376"
          "8d20857f2b1406f264cfe75e27d7652f4b5ed3575f28a702f8c4ed9cf9b2d449"
          "48"
        },{
          "PSS Example 4.2",
          "0ca2ad77797ece86de5bf768750ddb5ed6a3116ad99bbd17edf7f782f0db1cd0"
          "5b0f677468c5ea420dc116b10e80d110de2b0461ea14a38be68620392e7e893c"
          "b4ea9393fb886c20ff790642305bf302003892e54df9f667509dc53920df583f"
          "50a3dd61abb6fab75d600377e383e6aca6710eeea27156e06752c94ce25ae99f"
          "cbf8592dbe2d7e27453cb44de07100ebb1a2a19811a478adbeab270f94e8fe36"
          "9d90b3ca612f9f",
          "22d71d54363a4217aa55113f059b3384e3e57e44",
          "049d0185845a264d28feb1e69edaec090609e8e46d93abb38371ce51f4aa65a5"
          "99bdaaa81d24fba66a08a116cb644f3f1e653d95c89db8bbd5daac2709c89840"
          "00178410a7c6aa8667ddc38c741f710ec8665aa9052be929d4e3b16782c16621"
          "14c5414bb0353455c392fc28f3db59054b5f365c49e1d156f876ee10cb4fd705"
          "98"
        },{
          "PSS Example 4.3",
          "288062afc08fcdb7c5f8650b29837300461dd5676c17a20a3c8fb5148949e3f7"
          "3d66b3ae82c7240e27c5b3ec4328ee7d6ddf6a6a0c9b5b15bcda196a9d0c76b1"
          "19d534d85abd123962d583b76ce9d180bce1ca",
          "4af870fbc6516012ca916c70ba862ac7e8243617",
          "03fbc410a2ced59500fb99f9e2af2781ada74e13145624602782e2994813eefc"
          "a0519ecd253b855fb626a90d771eae028b0c47a199cbd9f8e3269734af416359"
          "9090713a3fa910fa0960652721432b971036a7181a2bc0cab43b0b598bc62174"
          "61d7db305ff7e954c5b5bb231c39e791af6bcfa76b147b081321f72641482a2a"
          "ad"
        },{
          "PSS Example 4.4",
          "6f4f9ab9501199cef55c6cf408fe7b36c557c49d420a4763d2463c8ad44b3cfc"
          "5be2742c0e7d9b0f6608f08c7f47b693ee",
          "40d2e180fae1eac439c190b56c2c0e14ddf9a226",
          "0486644bc66bf75d28335a6179b10851f43f09bded9fac1af33252bb9953ba42"
          "98cd6466b27539a70adaa3f89b3db3c74ab635d122f4ee7ce557a61e59b82ffb"
          "786630e5f9db53c77d9a0c12fab5958d4c2ce7daa807cd89ba2cc7fcd02ff470"
          "ca67b229fcce814c852c73cc93bea35be68459ce478e9d4655d121c8472f371d"
          "4f"
        },{
          "PSS Example 4.5",
          "e17d20385d501955823c3f666254c1d3dd36ad5168b8f18d286fdcf67a7dad94"
          "097085fab7ed86fe2142a28771717997ef1a7a08884efc39356d76077aaf8245"
          "9a7fad45848875f2819b098937fe923bcc9dc442d72d754d812025090c9bc03d"
          "b3080c138dd63b355d0b4b85d6688ac19f4de15084a0ba4e373b93ef4a555096"
          "691915dc23c00e954cdeb20a47cd55d16c3d8681d46ed7f2ed5ea42795be17ba"
          "ed25f0f4d113b3636addd585f16a8b5aec0c8fa9c5f03cbf3b9b73",
          "2497dc2b4615dfae5a663d49ffd56bf7efc11304",
          "022a80045353904cb30cbb542d7d4990421a6eec16a8029a8422adfd22d6aff8"
          "c4cc0294af110a0c067ec86a7d364134459bb1ae8ff836d5a8a2579840996b32"
          "0b19f13a13fad378d931a65625dae2739f0c53670b35d9d3cbac08e733e4ec2b"
          "83af4b9196d63e7c4ff1ddeae2a122791a125bfea8deb0de8ccf1f4ffaf6e6fb"
          "0a"
        },{
          "PSS Example 4.6",
          "afbc19d479249018fdf4e09f618726440495de11ddeee38872d775fcea74a238"
          "96b5343c9c38d46af0dba224d047580cc60a65e9391cf9b59b36a860598d4e82"
          "16722f993b91cfae87bc255af89a6a199bca4a391eadbc3a24903c0bd667368f"
          "6be78e3feabfb4ffd463122763740ffbbefeab9a25564bc5d1c24c93e422f750"
          "73e2ad72bf45b10df00b52a147128e73fee33fa3f0577d77f80fbc2df1bed313"
          "290c12777f50",
          "a334db6faebf11081a04f87c2d621cdec7930b9b",
          "00938dcb6d583046065f69c78da7a1f1757066a7fa75125a9d2929f0b79a60b6"
          "27b082f11f5b196f28eb9daa6f21c05e5140f6aef1737d2023075c05ecf04a02"
          "8c686a2ab3e7d5a0664f295ce12995e890908b6ad21f0839eb65b70393a7b5af"
          "d9871de0caa0cedec5b819626756209d13ab1e7bb9546a26ff37e9a51af9fd56"
          "2e"
        }
      }
    },
    {
      "Example 5: A 1028-bit RSA key pair",
      "0d10f661f29940f5ed39aa260966deb47843679d2b6fb25b3de370f3ac7c1991"
      "6391fd25fb527ebfa6a4b4df45a1759d996c4bb4ebd18828c44fc52d01918717"
      "40525f47a4b0cc8da325ed8aa676b0d0f626e0a77f07692170acac8082f42faa"
      "7dc7cd123e730e31a87985204cabcbe6670d43a2dd2b2ddef5e05392fc213bc5"
      "07",
      "010001",
      "03ce08b104fff396a979bd3e4e46925b6319ddb63acbcfd819f17d16b8077b3a"
      "87101ff34b77fe48b8b205a96e9151ba8ecea64d0cce7b23c3e6a6b83058bc49"
      "dae816ae736db5a4708e2ad435232b567f9096ce59ff28061e79ab1c02d717e6"
      "b23cea6db8eb5192fa7c1eab227dba74621c45601896eef13792c8440beb15aa"
      "c1",
      {
        {
          "PSS Example 5.1",
          "30c7d557458b436decfdc14d06cb7b96b06718c48d7de57482a868ae7f065870"
          "a6216506d11b779323dfdf046cf5775129134b4d5689e4d9c0ce1e12d7d4b06c"
          "b5fc5820decfa41baf59bf257b32f025b7679b445b9499c92555145885992f1b"
          "76f84891ee4d3be0f5150fd5901e3a4c8ed43fd36b61d022e65ad5008dbf3329"
          "3c22bfbfd07321f0f1d5fa9fdf0014c2fcb0358aad0e354b0d29",
          "081b233b43567750bd6e78f396a88b9f6a445151",
          "0ba373f76e0921b70a8fbfe622f0bf77b28a3db98e361051c3d7cb92ad045291"
          "5a4de9c01722f6823eeb6adf7e0ca8290f5de3e549890ac2a3c5950ab217ba58"
          "590894952de96f8df111b2575215da6c161590c745be612476ee578ed384ab33"
          "e3ece97481a252f5c79a98b5532ae00cdd62f2ecc0cd1baefe80d80b962193ec"
          "1d"
        },{
          "PSS Example 5.2",
          "e7b32e1556ea1b2795046ac69739d22ac8966bf11c116f614b166740e96b9065"
          "3e5750945fcf772186c03790a07fda323e1a61916b06ee2157db3dff80d67d5e"
          "39a53ae268c8f09ed99a732005b0bc6a04af4e08d57a00e7201b3060efaadb73"
          "113bfc087fd837093aa25235b8c149f56215f031c24ad5bde7f29960df7d5240"
          "70f7449c6f785084be1a0f733047f336f9154738674547db02a9f44dfc6e6030"
          "1081e1ce99847f3b5b601ff06b4d5776a9740b9aa0d34058fd3b906e4f7859df"
          "b07d7173e5e6f6350adac21f27b2307469",
          "bd0ce19549d0700120cbe51077dbbbb00a8d8b09",
          "08180de825e4b8b014a32da8ba761555921204f2f90d5f24b712908ff84f3e22"
          "0ad17997c0dd6e706630ba3e84add4d5e7ab004e58074b549709565d43ad9e97"
          "b5a7a1a29e85b9f90f4aafcdf58321de8c5974ef9abf2d526f33c0f2f82e95d1"
          "58ea6b81f1736db8d1af3d6ac6a83b32d18bae0ff1b2fe27de4c76ed8c7980a3"
          "4e"
        },{
          "PSS Example 5.3",
          "8d8396e36507fe1ef6a19017548e0c716674c2fec233adb2f775665ec41f2bd0"
          "ba396b061a9daa7e866f7c23fd3531954300a342f924535ea1498c48f6c87993"
          "2865fc02000c528723b7ad0335745b51209a0afed932af8f0887c219004d2abd"
          "894ea92559ee3198af3a734fe9b9638c263a728ad95a5ae8ce3eb15839f3aa78"
          "52bb390706e7760e43a71291a2e3f827237deda851874c517665f545f27238df"
          "86557f375d09ccd8bd15d8ccf61f5d78ca5c7f5cde782e6bf5d0057056d4bad9"
          "8b3d2f9575e824ab7a33ff57b0ac100ab0d6ead7aa0b50f6e4d3e5ec0b966b",
          "815779a91b3a8bd049bf2aeb920142772222c9ca",
          "05e0fdbdf6f756ef733185ccfa8ced2eb6d029d9d56e35561b5db8e70257ee6f"
          "d019d2f0bbf669fe9b9821e78df6d41e31608d58280f318ee34f559941c8df13"
          "287574bac000b7e58dc4f414ba49fb127f9d0f8936638c76e85356c994f79750"
          "f7fa3cf4fd482df75e3fb9978cd061f7abb17572e6e63e0bde12cbdcf18c68b9"
          "79"
        },{
          "PSS Example 5.4",
          "328c659e0a6437433cceb73c14",
          "9aec4a7480d5bbc42920d7ca235db674989c9aac",
          "0bc989853bc2ea86873271ce183a923ab65e8a53100e6df5d87a24c4194eb797"
          "813ee2a187c097dd872d591da60c568605dd7e742d5af4e33b11678ccb639032"
          "04a3d080b0902c89aba8868f009c0f1c0cb85810bbdd29121abb8471ff2d39e4"
          "9fd92d56c655c8e037ad18fafbdc92c95863f7f61ea9efa28fea401369d19dae"
          "a1"
        },{
          "PSS Example 5.5",
          "f37b962379a47d415a376eec8973150bcb34edd5ab654041b61430560c214458"
          "2ba133c867d852d6b8e23321901302ecb45b09ec88b1527178fa043263f3067d"
          "9ffe973032a99f4cb08ad2c7e0a2456cdd57a7df56fe6053527a5aeb67d7e552"
          "063c1ca97b1beffa7b39e997caf27878ea0f62cbebc8c21df4c889a202851e94"
          "9088490c249b6e9acf1d8063f5be2343989bf95c4da01a2be78b4ab6b378015b"
          "c37957f76948b5e58e440c28453d40d7cfd57e7d690600474ab5e75973b1ea0c"
          "5f1e45d14190afe2f4eb6d3bdf71f1d2f8bb156a1c295d04aaeb9d689dce79ed"
          "62bc443e",
          "e20c1e9878512c39970f58375e1549a68b64f31d",
          "0aefa943b698b9609edf898ad22744ac28dc239497cea369cbbd84f65c95c0ad"
          "776b594740164b59a739c6ff7c2f07c7c077a86d95238fe51e1fcf33574a4ae0"
          "684b42a3f6bf677d91820ca89874467b2c23add77969c80717430d0efc1d3695"
          "892ce855cb7f7011630f4df26def8ddf36fc23905f57fa6243a485c770d5681f"
          "cd"
        },{
          "PSS Example 5.6",
          "c6103c330c1ef718c141e47b8fa859be4d5b96259e7d142070ecd485839dba5a"
          "8369c17c1114035e532d195c74f44a0476a2d3e8a4da210016caced0e367cb86"
          "7710a4b5aa2df2b8e5daf5fdc647807d4d5ebb6c56b9763ccdae4dea3308eb0a"
          "c2a89501cb209d2639fa5bf87ce790747d3cb2d295e84564f2f637824f0c1302"
          "8129b0aa4a422d162282",
          "23291e4a3307e8bbb776623ab34e4a5f4cc8a8db",
          "02802dccfa8dfaf5279bf0b4a29ba1b157611faeaaf419b8919d15941900c133"
          "9e7e92e6fae562c53e6cc8e84104b110bce03ad18525e3c49a0eadad5d3f28f2"
          "44a8ed89edbafbb686277cfa8ae909714d6b28f4bf8e293aa04c41efe7c0a812"
          "66d5c061e2575be032aa464674ff71626219bd74cc45f0e7ed4e3ff96eee758e"
          "8f"
        }
      }
    },
    {
      "Example 6: A 1029-bit RSA key pair",
      "164ca31cff609f3a0e7101b039f2e4fe6dd37519ab98598d179e174996598071"
      "f47d3a04559158d7be373cf1aa53f0aa6ef09039e5678c2a4c63900514c8c4f8"
      "aaed5de12a5f10b09c311af8c0ffb5b7a297f2efc63b8d6b0510931f0b98e48b"
      "f5fc6ec4e7b8db1ffaeb08c38e02adb8f03a48229c99e969431f61cb8c4dc698"
      "d1",
      "010001",
      "03b664ee3b7566723fc6eaf28abb430a3980f1126c81de8ad709eab39ac9dcd0"
      "b1550b3729d87068e952009df544534c1f50829a78f4591eb8fd57140426a6bb"
      "0405b6a6f51a57d9267b7bbc653391a699a2a90dac8ae226bcc60fa8cd934c73"
      "c7b03b1f6b818158631838a8612e6e6ea92be24f8324faf5b1fd8587225267ba"
      "6f",
      {
        {
          "PSS Example 6.1",
          "0a20b774addc2fa51245ed7cb9da609e50cac6636a52543f97458eed7340f8d5"
          "3ffc64918f949078ee03ef60d42b5fec246050bd5505cd8cb597bad3c4e713b0"
          "ef30644e76adabb0de01a1561efb255158c74fc801e6e919e581b46f0f0ddd08"
          "e4f34c7810b5ed8318f91d7c8c",
          "5b4ea2ef629cc22f3b538e016904b47b1e40bfd5",
          "04c0cfacec04e5badbece159a5a1103f69b3f32ba593cb4cc4b1b7ab455916a9"
          "6a27cd2678ea0f46ba37f7fc9c86325f29733b389f1d97f43e7201c0f348fc45"
          "fe42892335362eee018b5b161f2f9393031225c713012a576bc88e2305248986"
          "8d9010cbf033ecc568e8bc152bdc59d560e41291915d28565208e22aeec9ef85"
          "d1"
        },{
          "PSS Example 6.2",
          "2aaff6631f621ce615760a9ebce94bb333077ad86488c861d4b76d29c1f48746"
          "c611ae1e03ced4445d7cfa1fe5f62e1b3f08452bde3b6ef81973bafbb57f97bc"
          "eef873985395b8260589aa88cb7db50ab469262e551bdcd9a56f275a0ac4fe48"
          "4700c35f3dbf2b469ede864741b86fa59172a360ba95a02e139be50ddfb7cf0b"
          "42faeabbfbbaa86a4497699c4f2dfd5b08406af7e14144427c253ec0efa20eaf"
          "9a8be8cd49ce1f1bc4e93e619cf2aa8ed4fb39bc8590d0f7b96488f7317ac9ab"
          "f7bee4e3a0e715",
          "83146a9e782722c28b014f98b4267bda2ac9504f",
          "0a2314250cf52b6e4e908de5b35646bcaa24361da8160fb0f9257590ab3ace42"
          "b0dc3e77ad2db7c203a20bd952fbb56b1567046ecfaa933d7b1000c3de9ff05b"
          "7d989ba46fd43bc4c2d0a3986b7ffa13471d37eb5b47d64707bd290cfd6a9f39"
          "3ad08ec1e3bd71bb5792615035cdaf2d8929aed3be098379377e777ce79aaa47"
          "73"
        },{
          "PSS Example 6.3",
          "0f6195d04a6e6fc7e2c9600dbf840c39ea8d4d624fd53507016b0e26858a5e0a"
          "ecd7ada543ae5c0ab3a62599cba0a54e6bf446e262f989978f9ddf5e9a41",
          "a87b8aed07d7b8e2daf14ddca4ac68c4d0aabff8",
          "086df6b500098c120f24ff8423f727d9c61a5c9007d3b6a31ce7cf8f3cbec1a2"
          "6bb20e2bd4a046793299e03e37a21b40194fb045f90b18bf20a47992ccd799cf"
          "9c059c299c0526854954aade8a6ad9d97ec91a1145383f42468b231f4d72f237"
          "06d9853c3fa43ce8ace8bfe7484987a1ec6a16c8daf81f7c8bf42774707a9df4"
          "56"
        },{
          "PSS Example 6.4",
          "337d25fe9810ebca0de4d4658d3ceb8e0fe4c066aba3bcc48b105d3bf7e0257d"
          "44fecea6596f4d0c59a08402833678f70620f9138dfeb7ded905e4a6d5f05c47"
          "3d55936652e2a5df43c0cfda7bacaf3087f4524b06cf42157d01539739f7fdde"
          "c9d58125df31a32eab06c19b71f1d5bf",
          "a37932f8a7494a942d6f767438e724d6d0c0ef18",
          "0b5b11ad549863ffa9c51a14a1106c2a72cc8b646e5c7262509786105a984776"
          "534ca9b54c1cc64bf2d5a44fd7e8a69db699d5ea52087a4748fd2abc1afed1e5"
          "d6f7c89025530bdaa2213d7e030fa55df6f34bcf1ce46d2edf4e3ae4f3b01891"
          "a068c9e3a44bbc43133edad6ecb9f35400c4252a5762d65744b99cb9f4c55932"
          "9f"
        },{
          "PSS Example 6.5",
          "84ec502b072e8287789d8f9235829ea3b187afd4d4c785611bda5f9eb3cb9671"
          "7efa7007227f1c08cbcb972e667235e0fb7d431a6570326d2ecce35adb373dc7"
          "53b3be5f829b89175493193fab16badb41371b3aac0ae670076f24bef420c135"
          "add7cee8d35fbc944d79fafb9e307a13b0f556cb654a06f973ed22672330197e"
          "f5a748bf826a5db2383a25364b686b9372bb2339aeb1ac9e9889327d016f1670"
          "776db06201adbdcaf8a5e3b74e108b73",
          "7b790c1d62f7b84e94df6af28917cf571018110e",
          "02d71fa9b53e4654fefb7f08385cf6b0ae3a817942ebf66c35ac67f0b069952a"
          "3ce9c7e1f1b02e480a9500836de5d64cdb7ecde04542f7a79988787e24c2ba05"
          "f5fd482c023ed5c30e04839dc44bed2a3a3a4fee01113c891a47d32eb8025c28"
          "cb050b5cdb576c70fe76ef523405c08417faf350b037a43c379339fcb18d3a35"
          "6b"
        },{
          "PSS Example 6.6",
          "9906d89f97a9fdedd3ccd824db687326f30f00aa25a7fca2afcb3b0f86cd41e7"
          "3f0e8ff7d2d83f59e28ed31a5a0d551523374de22e4c7e8ff568b386ee3dc411"
          "63f10bf67bb006261c9082f9af90bf1d9049a6b9fae71c7f84fbe6e55f02789d"
          "e774f230f115026a4b4e96c55b04a95da3aacbb2cece8f81764a1f1c99515411"
          "087cf7d34aeded0932c183",
          "fbbe059025b69b89fb14ae2289e7aaafe60c0fcd",
          "0a40a16e2fe2b38d1df90546167cf9469c9e3c3681a3442b4b2c2f581deb385c"
          "e99fc6188bb02a841d56e76d301891e24560550fcc2a26b55f4ccb26d837d350"
          "a154bcaca8392d98fa67959e9727b78cad03269f56968fc56b68bd679926d83c"
          "c9cb215550645ccda31c760ff35888943d2d8a1d351e81e5d07b86182e751081"
          "ef"
        }
      }
    },
    {
      "Example 7: A 1030-bit RSA key pair",
      "37c9da4a66c8c408b8da27d0c9d79f8ccb1eafc1d2fe48746d940b7c4ef5dee1"
      "8ad12647cefaa0c4b3188b221c515386759b93f02024b25ab9242f8357d8f3fd"
      "49640ee5e643eaf6c64deefa7089727c8ff03993333915c6ef21bf5975b6e50d"
      "118b51008ec33e9f01a0a545a10a836a43ddbca9d8b5c5d3548022d7064ea29a"
      "b3",
      "010001",
      "3bed999052d957bc06d651eef6e3a98094b1621bd38b5449bd6c4aea3de7e084"
      "679a4484ded25be0f0826cf3377825414b14d4d61db14de626fbb80e5f4faec9"
      "56f9a0a2d24f99576380f084eb62e46a57d554278b535626193ce02060575eb6"
      "6c5798d36f6c5d40fb00d809b42a73102c1c74ee95bd71420fffef6318b52c29",
      {
        {
          "PSS Example 7.1",
          "9ead0e01945640674eb41cad435e2374eaefa8ad7197d97913c44957d8d83f40"
          "d76ee60e39bf9c0f9eaf3021421a074d1ade962c6e9d3dc3bb174fe4dfe652b0"
          "9115495b8fd2794174020a0602b5ca51848cfc96ce5eb57fc0a2adc1dda36a7c"
          "c452641a14911b37e45bfa11daa5c7ecdb74f6d0100d1d3e39e752800e203397"
          "de0233077b9a88855537fae927f924380d780f98e18dcff39c5ea741b17d6fdd"
          "1885bc9d581482d771ceb562d78a8bf88f0c75b11363e5e36cd479ceb0545f9d"
          "a84203e0e6e508375cc9e844b88b7ac7a0a201ea0f1bee9a2c577920ca02c01b"
          "9d8320e974a56f4efb5763b96255abbf8037bf1802cf018f56379493e569a9",
          "b7867a59958cb54328f8775e6546ec06d27eaa50",
          "187f390723c8902591f0154bae6d4ecbffe067f0e8b795476ea4f4d51ccc8105"
          "20bb3ca9bca7d0b1f2ea8a17d873fa27570acd642e3808561cb9e975ccfd80b2"
          "3dc5771cdb3306a5f23159dacbd3aa2db93d46d766e09ed15d900ad897a8d274"
          "dc26b47e994a27e97e2268a766533ae4b5e42a2fcaf755c1c4794b294c605558"
          "23"
        },{
          "PSS Example 7.2",
          "8d80d2d08dbd19c154df3f14673a14bd03735231f24e86bf153d0e69e74cbff7"
          "b1836e664de83f680124370fc0f96c9b65c07a366b644c4ab3",
          "0c09582266df086310821ba7e18df64dfee6de09",
          "10fd89768a60a67788abb5856a787c8561f3edcf9a83e898f7dc87ab8cce7942"
          "9b43e56906941a886194f137e591fe7c339555361fbbe1f24feb2d4bcdb80601"
          "f3096bc9132deea60ae13082f44f9ad41cd628936a4d51176e42fc59cb76db81"
          "5ce5ab4db99a104aafea68f5d330329ebf258d4ede16064bd1d00393d5e1570e"
          "b8"
        },{
          "PSS Example 7.3",
          "808405cdfc1a58b9bb0397c720722a81fffb76278f335917ef9c473814b3e016"
          "ba2973cd2765f8f3f82d6cc38aa7f8551827fe8d1e3884b7e61c94683b8f82f1"
          "843bdae2257eeec9812ad4c2cf283c34e0b0ae0fe3cb990cf88f2ef9",
          "28039dcfe106d3b8296611258c4a56651c9e92dd",
          "2b31fde99859b977aa09586d8e274662b25a2a640640b457f594051cb1e7f7a9"
          "11865455242926cf88fe80dfa3a75ba9689844a11e634a82b075afbd69c12a0d"
          "f9d25f84ad4945df3dc8fe90c3cefdf26e95f0534304b5bdba20d3e5640a2ebf"
          "b898aac35ae40f26fce5563c2f9f24f3042af76f3c7072d687bbfb959a88460a"
          "f1"
        },{
          "PSS Example 7.4",
          "f337b9bad937de22a1a052dff11134a8ce26976202981939b91e0715ae5e6096"
          "49da1adfcef3f4cca59b238360e7d1e496c7bf4b204b5acff9bbd6166a1d87a3"
          "6ef2247373751039f8a800b8399807b3a85f44893497c0d05fb7017b82228152"
          "de6f25e6116dcc7503c786c875c28f3aa607e94ab0f19863ab1b5073770b0cd5"
          "f533acde30c6fb953cf3da680264e30fc11bff9a19bffab4779b6223c3fb3fe0"
          "f71abade4eb7c09c41e24c22d23fa148e6a173feb63984d1bc6ee3a02d915b75"
          "2ceaf92a3015eceb38ca586c6801b37c34cefb2cff25ea23c08662dcab26a7a9"
          "3a285d05d3044c",
          "a77821ebbbef24628e4e12e1d0ea96de398f7b0f",
          "32c7ca38ff26949a15000c4ba04b2b13b35a3810e568184d7ecabaa166b7ffab"
          "ddf2b6cf4ba07124923790f2e5b1a5be040aea36fe132ec130e1f10567982d17"
          "ac3e89b8d26c3094034e762d2e031264f01170beecb3d1439e05846f25458367"
          "a7d9c02060444672671e64e877864559ca19b2074d588a281b5804d23772fbbe"
          "19"
        },{
          "PSS Example 7.5",
          "45013cebafd960b255476a8e2598b9aa32efbe6dc1f34f4a498d8cf5a2b4548d"
          "08c55d5f95f7bcc9619163056f2d58b52fa032",
          "9d5ad8eb452134b65dc3a98b6a73b5f741609cd6",
          "07eb651d75f1b52bc263b2e198336e99fbebc4f332049a922a10815607ee2d98"
          "9db3a4495b7dccd38f58a211fb7e193171a3d891132437ebca44f318b280509e"
          "52b5fa98fcce8205d9697c8ee4b7ff59d4c59c79038a1970bd2a0d451ecdc5ef"
          "11d9979c9d35f8c70a6163717607890d586a7c6dc01c79f86a8f28e85235f8c2"
          "f1"
        },{
          "PSS Example 7.6",
          "2358097086c899323e75d9c90d0c09f12d9d54edfbdf70a9c2eb5a04d8f36b9b"
          "2bdf2aabe0a5bda1968937f9d6ebd3b6b257efb3136d4131f9acb59b85e2602c"
          "2a3fcdc835494a1f4e5ec18b226c80232b36a75a45fdf09a7ea9e98efbde1450"
          "d1194bf12e15a4c5f9eb5c0bce5269e0c3b28cfab655d81a61a20b4be2f54459"
          "bb25a0db94c52218be109a7426de83014424789aaa90e5056e632a698115e282"
          "c1a56410f26c2072f193481a9dcd880572005e64f4082ecf",
          "3f2efc595880a7d47fcf3cba04983ea54c4b73fb",
          "18da3cdcfe79bfb77fd9c32f377ad399146f0a8e810620233271a6e3ed324890"
          "3f5cdc92dc79b55d3e11615aa056a795853792a3998c349ca5c457e8ca7d29d7"
          "96aa24f83491709befcfb1510ea513c92829a3f00b104f655634f320752e130e"
          "c0ccf6754ff893db302932bb025eb60e87822598fc619e0e981737a9a4c4152d"
          "33"
        }
      }
    },
    {
      "Example 8: A 1031-bit RSA key pair",
      "495370a1fb18543c16d3631e3163255df62be6eee890d5f25509e4f778a8ea6f"
      "bbbcdf85dff64e0d972003ab3681fbba6dd41fd541829b2e582de9f2a4a4e0a2"
      "d0900bef4753db3cee0ee06c7dfae8b1d53b5953218f9cceea695b08668edeaa"
      "dced9463b1d790d5ebf27e9115b46cad4d9a2b8efab0561b0810344739ada073"
      "3f",
      "010001",
      "6c66ffe98980c38fcdeab5159898836165f4b4b817c4f6a8d486ee4ea9130fe9"
      "b9092bd136d184f95f504a607eac565846d2fdd6597a8967c7396ef95a6eeebb"
      "4578a643966dca4d8ee3de842de63279c618159c1ab54a89437b6a6120e4930a"
      "fb52a4ba6ced8a4947ac64b30a3497cbe701c2d6266d517219ad0ec6d347dbe9",
      {
        {
          "PSS Example 8.1",
          "81332f4be62948415ea1d899792eeacf6c6e1db1da8be13b5cea41db2fed4670"
          "92e1ff398914c714259775f595f8547f735692a575e6923af78f22c6997ddb90"
          "fb6f72d7bb0dd5744a31decd3dc3685849836ed34aec596304ad11843c4f8848"
          "9f209735f5fb7fdaf7cec8addc5818168f880acbf490d51005b7a8e84e43e542"
          "87977571dd99eea4b161eb2df1f5108f12a4142a83322edb05a75487a3435c9a"
          "78ce53ed93bc550857d7a9fb",
          "1d65491d79c864b373009be6f6f2467bac4c78fa",
          "0262ac254bfa77f3c1aca22c5179f8f040422b3c5bafd40a8f21cf0fa5a667cc"
          "d5993d42dbafb409c520e25fce2b1ee1e716577f1efa17f3da28052f40f0419b"
          "23106d7845aaf01125b698e7a4dfe92d3967bb00c4d0d35ba3552ab9a8b3eef0"
          "7c7fecdbc5424ac4db1e20cb37d0b2744769940ea907e17fbbca673b20522380"
          "c5"
        },{
          "PSS Example 8.2",
          "e2f96eaf0e05e7ba326ecca0ba7fd2f7c02356f3cede9d0faabf4fcc8e60a973"
          "e5595fd9ea08",
          "435c098aa9909eb2377f1248b091b68987ff1838",
          "2707b9ad5115c58c94e932e8ec0a280f56339e44a1b58d4ddcff2f312e5f34dc"
          "fe39e89c6a94dcee86dbbdae5b79ba4e0819a9e7bfd9d982e7ee6c86ee68396e"
          "8b3a14c9c8f34b178eb741f9d3f121109bf5c8172fada2e768f9ea1433032c00"
          "4a8aa07eb990000a48dc94c8bac8aabe2b09b1aa46c0a2aa0e12f63fbba775ba"
          "7e"
        },{
          "PSS Example 8.3",
          "e35c6ed98f64a6d5a648fcab8adb16331db32e5d15c74a40edf94c3dc4a4de79"
          "2d190889f20f1e24ed12054a6b28798fcb42d1c548769b734c96373142092aed"
          "277603f4738df4dc1446586d0ec64da4fb60536db2ae17fc7e3c04bbfbbbd907"
          "bf117c08636fa16f95f51a6216934d3e34f85030f17bbbc5ba69144058aff081"
          "e0b19cf03c17195c5e888ba58f6fe0a02e5c3bda9719a7",
          "c6ebbe76df0c4aea32c474175b2f136862d04529",
          "2ad20509d78cf26d1b6c406146086e4b0c91a91c2bd164c87b966b8faa42aa0c"
          "a446022323ba4b1a1b89706d7f4c3be57d7b69702d168ab5955ee290356b8c4a"
          "29ed467d547ec23cbadf286ccb5863c6679da467fc9324a151c7ec55aac6db40"
          "84f82726825cfe1aa421bc64049fb42f23148f9c25b2dc300437c38d428aa75f"
          "96"
        },{
          "PSS Example 8.4",
          "dbc5f750a7a14be2b93e838d18d14a8695e52e8add9c0ac733b8f56d2747e529"
          "a0cca532dd49b902aefed514447f9e81d16195c2853868cb9b30f7d0d495c69d"
          "01b5c5d50b27045db3866c2324a44a110b1717746de457d1c8c45c3cd2a92970"
          "c3d59632055d4c98a41d6e99e2a3ddd5f7f9979ab3cd18f37505d25141de2a1b"
          "ff17b3a7dce9419ecc385cf11d72840f19953fd0509251f6cafde2893d0e75c7"
          "81ba7a5012ca401a4fa99e04b3c3249f926d5afe82cc87dab22c3c1b105de48e"
          "34ace9c9124e59597ac7ebf8",
          "021fdcc6ebb5e19b1cb16e9c67f27681657fe20a",
          "1e24e6e58628e5175044a9eb6d837d48af1260b0520e87327de7897ee4d5b9f0"
          "df0be3e09ed4dea8c1454ff3423bb08e1793245a9df8bf6ab3968c8eddc3b532"
          "8571c77f091cc578576912dfebd164b9de5454fe0be1c1f6385b328360ce67ec"
          "7a05f6e30eb45c17c48ac70041d2cab67f0a2ae7aafdcc8d245ea3442a6300cc"
          "c7"
        },{
          "PSS Example 8.5",
          "04dc251be72e88e5723485b6383a637e2fefe07660c519a560b8bc18bdedb86e"
          "ae2364ea53ba9dca6eb3d2e7d6b806af42b3e87f291b4a8881d5bf572cc9a85e"
          "19c86acb28f098f9da0383c566d3c0f58cfd8f395dcf602e5cd40e8c7183f714"
          "996e2297ef",
          "c558d7167cbb4508ada042971e71b1377eea4269",
          "33341ba3576a130a50e2a5cf8679224388d5693f5accc235ac95add68e5eb1ee"
          "c31666d0ca7a1cda6f70a1aa762c05752a51950cdb8af3c5379f18cfe6b5bc55"
          "a4648226a15e912ef19ad77adeea911d67cfefd69ba43fa4119135ff642117ba"
          "985a7e0100325e9519f1ca6a9216bda055b5785015291125e90dcd07a2ca9673"
          "ee"
        },{
          "PSS Example 8.6",
          "0ea37df9a6fea4a8b610373c24cf390c20fa6e2135c400c8a34f5c183a7e8ea4"
          "c9ae090ed31759f42dc77719cca400ecdcc517acfc7ac6902675b2ef30c50966"
          "5f3321482fc69a9fb570d15e01c845d0d8e50d2a24cbf1cf0e714975a5db7b18"
          "d9e9e9cb91b5cb16869060ed18b7b56245503f0caf90352b8de81cb5a1d9c633"
          "6092f0cd",
          "76fd4e64fdc98eb927a0403e35a084e76ba9f92a",
          "1ed1d848fb1edb44129bd9b354795af97a069a7a00d0151048593e0c72c3517f"
          "f9ff2a41d0cb5a0ac860d736a199704f7cb6a53986a88bbd8abcc0076a2ce847"
          "880031525d449da2ac78356374c536e343faa7cba42a5aaa6506087791c06a8e"
          "989335aed19bfab2d5e67e27fb0c2875af896c21b6e8e7309d04e4f6727e6946"
          "3e"
        }
      }
    },
    {
      "Example 9: A 1536-bit RSA key pair",
      "e6bd692ac96645790403fdd0f5beb8b9bf92ed10007fc365046419dd06c05c5b"
      "5b2f48ecf989e4ce269109979cbb40b4a0ad24d22483d1ee315ad4ccb1534268"
      "352691c524f6dd8e6c29d224cf246973aec86c5bf6b1401a850d1b9ad1bb8cbc"
      "ec47b06f0f8c7f45d3fc8f319299c5433ddbc2b3053b47ded2ecd4a4caefd614"
      "833dc8bb622f317ed076b8057fe8de3f84480ad5e83e4a61904a4f248fb39702"
      "7357e1d30e463139815c6fd4fd5ac5b8172a45230ecb6318a04f1455d84e5a8b",
      "010001",
      "6a7fd84fb85fad073b34406db74f8d61a6abc12196a961dd79565e9da6e5187b"
      "ce2d980250f7359575359270d91590bb0e427c71460b55d51410b191bcf309fe"
      "a131a92c8e702738fa719f1e0041f52e40e91f229f4d96a1e6f172e15596b451"
      "0a6daec26105f2bebc53316b87bdf21311666070e8dfee69d52c71a976caae79"
      "c72b68d28580dc686d9f5129d225f82b3d615513a882b3db91416b48ce088882"
      "13e37eeb9af800d81cab328ce420689903c00c7b5fd31b75503a6d419684d629",
      {
        {
          "PSS Example 9.1",
          "a88e265855e9d7ca36c68795f0b31b591cd6587c71d060a0b3f7f3eaef437959"
          "22028bc2b6ad467cfc2d7f659c5385aa70ba3672cdde4cfe4970cc7904601b27"
          "8872bf51321c4a972f3c95570f3445d4f57980e0f20df54846e6a52c668f1288"
          "c03f95006ea32f562d40d52af9feb32f0fa06db65b588a237b34e592d55cf979"
          "f903a642ef64d2ed542aa8c77dc1dd762f45a59303ed75e541ca271e2b60ca70"
          "9e44fa0661131e8d5d4163fd8d398566ce26de8730e72f9cca737641c2441594"
          "20637028df0a18079d6208ea8b4711a2c750f5",
          "c0a425313df8d7564bd2434d311523d5257eed80",
          "586107226c3ce013a7c8f04d1a6a2959bb4b8e205ba43a27b50f124111bc35ef"
          "589b039f5932187cb696d7d9a32c0c38300a5cdda4834b62d2eb240af33f79d1"
          "3dfbf095bf599e0d9686948c1964747b67e89c9aba5cd85016236f566cc5802c"
          "b13ead51bc7ca6bef3b94dcbdbb1d570469771df0e00b1a8a06777472d231627"
          "9edae86474668d4e1efff95f1de61c6020da32ae92bbf16520fef3cf4d88f611"
          "21f24bbd9fe91b59caf1235b2a93ff81fc403addf4ebdea84934a9cdaf8e1a9e"
        },{
          "PSS Example 9.2",
          "c8c9c6af04acda414d227ef23e0820c3732c500dc87275e95b0d095413993c26"
          "58bc1d988581ba879c2d201f14cb88ced153a01969a7bf0a7be79c84c1486bc1"
          "2b3fa6c59871b6827c8ce253ca5fefa8a8c690bf326e8e37cdb96d90a82ebab6"
          "9f86350e1822e8bd536a2e",
          "b307c43b4850a8dac2f15f32e37839ef8c5c0e91",
          "80b6d643255209f0a456763897ac9ed259d459b49c2887e5882ecb4434cfd66d"
          "d7e1699375381e51cd7f554f2c271704b399d42b4be2540a0eca61951f55267f"
          "7c2878c122842dadb28b01bd5f8c025f7e228418a673c03d6bc0c736d0a29546"
          "bd67f786d9d692ccea778d71d98c2063b7a71092187a4d35af108111d83e83ea"
          "e46c46aa34277e06044589903788f1d5e7cee25fb485e92949118814d6f2c3ee"
          "361489016f327fb5bc517eb50470bffa1afa5f4ce9aa0ce5b8ee19bf5501b958"
        },{
          "PSS Example 9.3",
          "0afad42ccd4fc60654a55002d228f52a4a5fe03b8bbb08ca82daca558b44dbe1"
          "266e50c0e745a36d9d2904e3408abcd1fd569994063f4a75cc72f2fee2a0cd89"
          "3a43af1c5b8b487df0a71610024e4f6ddf9f28ad0813c1aab91bcb3c9064d5ff"
          "742deffea657094139369e5ea6f4a96319a5cc8224145b545062758fefd1fe34"
          "09ae169259c6cdfd6b5f2958e314faecbe69d2cace58ee55179ab9b3e6d1ecc1"
          "4a557c5febe988595264fc5da1c571462eca798a18a1a4940cdab4a3e92009cc"
          "d42e1e947b1314e32238a2dece7d23a89b5b30c751fd0a4a430d2c548594",
          "9a2b007e80978bbb192c354eb7da9aedfc74dbf5",
          "484408f3898cd5f53483f80819efbf2708c34d27a8b2a6fae8b322f9240237f9"
          "81817aca1846f1084daa6d7c0795f6e5bf1af59c38e1858437ce1f7ec419b98c"
          "8736adf6dd9a00b1806d2bd3ad0a73775e05f52dfef3a59ab4b08143f0df05cd"
          "1ad9d04bececa6daa4a2129803e200cbc77787caf4c1d0663a6c5987b6059520"
          "19782caf2ec1426d68fb94ed1d4be816a7ed081b77e6ab330b3ffc073820fecd"
          "e3727fcbe295ee61a050a343658637c3fd659cfb63736de32d9f90d3c2f63eca"
        },{
          "PSS Example 9.4",
          "1dfd43b46c93db82629bdae2bd0a12b882ea04c3b465f5cf93023f01059626db"
          "be99f26bb1be949dddd16dc7f3debb19a194627f0b224434df7d8700e9e98b06"
          "e360c12fdbe3d19f51c9684eb9089ecbb0a2f0450399d3f59eac7294085d044f"
          "5393c6ce737423d8b86c415370d389e30b9f0a3c02d25d0082e8ad6f3f1ef24a"
          "45c3cf82b383367063a4d4613e4264f01b2dac2e5aa42043f8fb5f69fa871d14"
          "fb273e767a531c40f02f343bc2fb45a0c7e0f6be2561923a77211d66a6e2dbb4"
          "3c366350beae22da3ac2c1f5077096fcb5c4bf255f7574351ae0b1e1f0363281"
          "7c0856d4a8ba97afbdc8b85855402bc56926fcec209f9ea8",
          "70f382bddf4d5d2dd88b3bc7b7308be632b84045",
          "84ebeb481be59845b46468bafb471c0112e02b235d84b5d911cbd1926ee5074a"
          "e0424495cb20e82308b8ebb65f419a03fb40e72b78981d88aad143053685172c"
          "97b29c8b7bf0ae73b5b2263c403da0ed2f80ff7450af7828eb8b86f0028bd2a8"
          "b176a4d228cccea18394f238b09ff758cc00bc04301152355742f282b54e663a"
          "919e709d8da24ade5500a7b9aa50226e0ca52923e6c2d860ec50ff480fa57477"
          "e82b0565f4379f79c772d5c2da80af9fbf325ece6fc20b00961614bee89a183e"
        },{
          "PSS Example 9.5",
          "1bdc6e7c98fb8cf54e9b097b66a831e9cfe52d9d4888448ee4b0978093ba1d7d"
          "73ae78b3a62ba4ad95cd289ccb9e005226bb3d178bccaa821fb044a4e21ee976"
          "96c14d0678c94c2dae93b0ad73922218553daa7e44ebe57725a7a45cc72b9b21"
          "38a6b17c8db411ce8279ee1241aff0a8bec6f77f87edb0c69cb27236e3435a80"
          "0b192e4f11e519e3fe30fc30eaccca4fbb41769029bf708e817a9e683805be67"
          "fa100984683b74838e3bcffa79366eed1d481c76729118838f31ba8a048a93c1"
          "be4424598e8df6328b7a77880a3f9c7e2e8dfca8eb5a26fb86bdc556d42bbe01"
          "d9fa6ed80646491c9341",
          "d689257a86effa68212c5e0c619eca295fb91b67",
          "82102df8cb91e7179919a04d26d335d64fbc2f872c44833943241de845481027"
          "4cdf3db5f42d423db152af7135f701420e39b494a67cbfd19f9119da233a23da"
          "5c6439b5ba0d2bc373eee3507001378d4a4073856b7fe2aba0b5ee93b27f4afe"
          "c7d4d120921c83f606765b02c19e4d6a1a3b95fa4c422951be4f52131077ef17"
          "179729cddfbdb56950dbaceefe78cb16640a099ea56d24389eef10f8fecb31ba"
          "3ea3b227c0a86698bb89e3e9363905bf22777b2a3aa521b65b4cef76d83bde4c"
        },{
          "PSS Example 9.6",
          "88c7a9f1360401d90e53b101b61c5325c3c75db1b411fbeb8e830b75e96b5667"
          "0ad245404e16793544ee354bc613a90cc9848715a73db5893e7f6d279815c0c1"
          "de83ef8e2956e3a56ed26a888d7a9cdcd042f4b16b7fa51ef1a0573662d16a30"
          "2d0ec5b285d2e03ad96529c87b3d374db372d95b2443d061b6b1a350ba87807e"
          "d083afd1eb05c3f52f4eba5ed2227714fdb50b9d9d9dd6814f62f6272fcd5cdb"
          "ce7a9ef797",
          "c25f13bf67d081671a0481a1f1820d613bba2276",
          "a7fdb0d259165ca2c88d00bbf1028a867d337699d061193b17a9648e14ccbbaa"
          "deacaacdec815e7571294ebb8a117af205fa078b47b0712c199e3ad05135c504"
          "c24b81705115740802487992ffd511d4afc6b854491eb3f0dd523139542ff15c"
          "3101ee85543517c6a3c79417c67e2dd9aa741e9a29b06dcb593c2336b3670ae3"
          "afbac7c3e76e215473e866e338ca244de00b62624d6b9426822ceae9f8cc4608"
          "95f41250073fd45c5a1e7b425c204a423a699159f6903e710b37a7bb2bc8049f"
        }
      }
    },
    {
      "Example 10: A 2048-bit RSA key pair",
      "a5dd867ac4cb02f90b9457d48c14a770ef991c56c39c0ec65fd11afa8937cea5"
      "7b9be7ac73b45c0017615b82d622e318753b6027c0fd157be12f8090fee2a7ad"
      "cd0eef759f88ba4997c7a42d58c9aa12cb99ae001fe521c13bb5431445a8d5ae"
      "4f5e4c7e948ac227d3604071f20e577e905fbeb15dfaf06d1de5ae6253d63a6a"
      "2120b31a5da5dabc9550600e20f27d3739e2627925fea3cc509f21dff04e6eea"
      "4549c540d6809ff9307eede91fff58733d8385a237d6d3705a33e39190099207"
      "0df7adf1357cf7e3700ce3667de83f17b8df1778db381dce09cb4ad058a51100"
      "1a738198ee27cf55a13b754539906582ec8b174bd58d5d1f3d767c613721ae05",
      "010001",
      "2d2ff567b3fe74e06191b7fded6de112290c670692430d5969184047da234c96"
      "93deed1673ed429539c969d372c04d6b47e0f5b8cee0843e5c22835dbd3b05a0"
      "997984ae6058b11bc4907cbf67ed84fa9ae252dfb0d0cd49e618e35dfdfe59bc"
      "a3ddd66c33cebbc77ad441aa695e13e324b518f01c60f5a85c994ad179f2a6b5"
      "fbe93402b11767be01bf073444d6ba1dd2bca5bd074d4a5fae3531ad1303d84b"
      "30d897318cbbba04e03c2e66de6d91f82f96ea1d4bb54a5aae102d594657f5c9"
      "789553512b296dea29d8023196357e3e3a6e958f39e3c2344038ea604b31edc6"
      "f0f7ff6e7181a57c92826a268f86768e96f878562fc71d85d69e448612f7048f",
      {
        {
          "PSS Example 10.1",
          "883177e5126b9be2d9a9680327d5370c6f26861f5820c43da67a3ad609",
          "04e215ee6ff934b9da70d7730c8734abfcecde89",
          "82c2b160093b8aa3c0f7522b19f87354066c77847abf2a9fce542d0e84e920c5"
          "afb49ffdfdace16560ee94a1369601148ebad7a0e151cf16331791a5727d05f2"
          "1e74e7eb811440206935d744765a15e79f015cb66c532c87a6a05961c8bfad74"
          "1a9a6657022894393e7223739796c02a77455d0f555b0ec01ddf259b6207fd0f"
          "d57614cef1a5573baaff4ec00069951659b85f24300a25160ca8522dc6e6727e"
          "57d019d7e63629b8fe5e89e25cc15beb3a647577559299280b9b28f79b040900"
          "0be25bbd96408ba3b43cc486184dd1c8e62553fa1af4040f60663de7f5e49c04"
          "388e257f1ce89c95dab48a315d9b66b1b7628233876ff2385230d070d07e1666"
        },{
          "PSS Example 10.2",
          "dd670a01465868adc93f26131957a50c52fb777cdbaa30892c9e12361164ec13"
          "979d43048118e4445db87bee58dd987b3425d02071d8dbae80708b039dbb64db"
          "d1de5657d9fed0c118a54143742e0ff3c87f74e45857647af3f79eb0a14c9d75"
          "ea9a1a04b7cf478a897a708fd988f48e801edb0b7039df8c23bb3c56f4e821ac",
          "8b2bdd4b40faf545c778ddf9bc1a49cb57f9b71b",
          "14ae35d9dd06ba92f7f3b897978aed7cd4bf5ff0b585a40bd46ce1b42cd27030"
          "53bb9044d64e813d8f96db2dd7007d10118f6f8f8496097ad75e1ff692341b28"
          "92ad55a633a1c55e7f0a0ad59a0e203a5b8278aec54dd8622e2831d87174f8ca"
          "ff43ee6c46445345d84a59659bfb92ecd4c818668695f34706f66828a8995963"
          "7f2bf3e3251c24bdba4d4b7649da0022218b119c84e79a6527ec5b8a5f861c15"
          "9952e23ec05e1e717346faefe8b1686825bd2b262fb2531066c0de09acde2e42"
          "31690728b5d85e115a2f6b92b79c25abc9bd9399ff8bcf825a52ea1f56ea76dd"
          "26f43baafa18bfa92a504cbd35699e26d1dcc5a2887385f3c63232f06f3244c3"
        },{
          "PSS Example 10.3",
          "48b2b6a57a63c84cea859d65c668284b08d96bdcaabe252db0e4a96cb1bac601"
          "9341db6fbefb8d106b0e90eda6bcc6c6262f37e7ea9c7e5d226bd7df85ec5e71"
          "efff2f54c5db577ff729ff91b842491de2741d0c631607df586b905b23b91af1"
          "3da12304bf83eca8a73e871ff9db",
          "4e96fc1b398f92b44671010c0dc3efd6e20c2d73",
          "6e3e4d7b6b15d2fb46013b8900aa5bbb3939cf2c095717987042026ee62c74c5"
          "4cffd5d7d57efbbf950a0f5c574fa09d3fc1c9f513b05b4ff50dd8df7edfa201"
          "02854c35e592180119a70ce5b085182aa02d9ea2aa90d1df03f2daae885ba2f5"
          "d05afdac97476f06b93b5bc94a1a80aa9116c4d615f333b098892b25fface266"
          "f5db5a5a3bcc10a824ed55aad35b727834fb8c07da28fcf416a5d9b2224f1f8b"
          "442b36f91e456fdea2d7cfe3367268de0307a4c74e924159ed33393d5e065553"
          "1c77327b89821bdedf880161c78cd4196b5419f7acc3f13e5ebf161b6e7c6724"
          "716ca33b85c2e25640192ac2859651d50bde7eb976e51cec828b98b6563b86bb"
        },{
          "PSS Example 10.4",
          "0b8777c7f839baf0a64bbbdbc5ce79755c57a205b845c174e2d2e90546a089c4"
          "e6ec8adffa23a7ea97bae6b65d782b82db5d2b5a56d22a29a05e7c4433e2b82a"
          "621abba90add05ce393fc48a840542451a",
          "c7cd698d84b65128d8835e3a8b1eb0e01cb541ec",
          "34047ff96c4dc0dc90b2d4ff59a1a361a4754b255d2ee0af7d8bf87c9bc9e7dd"
          "eede33934c63ca1c0e3d262cb145ef932a1f2c0a997aa6a34f8eaee7477d82cc"
          "f09095a6b8acad38d4eec9fb7eab7ad02da1d11d8e54c1825e55bf58c2a23234"
          "b902be124f9e9038a8f68fa45dab72f66e0945bf1d8bacc9044c6f07098c9fce"
          "c58a3aab100c805178155f030a124c450e5acbda47d0e4f10b80a23f803e774d"
          "023b0015c20b9f9bbe7c91296338d5ecb471cafb032007b67a60be5f69504a9f"
          "01abb3cb467b260e2bce860be8d95bf92c0c8e1496ed1e528593a4abb6df462d"
          "de8a0968dffe4683116857a232f5ebf6c85be238745ad0f38f767a5fdbf486fb"
        },{
          "PSS Example 10.5",
          "f1036e008e71e964dadc9219ed30e17f06b4b68a955c16b312b1eddf028b7497"
          "6bed6b3f6a63d4e77859243c9cccdc98016523abb02483b35591c33aad81213b"
          "b7c7bb1a470aabc10d44256c4d4559d916",
          "efa8bff96212b2f4a3f371a10d574152655f5dfb",
          "7e0935ea18f4d6c1d17ce82eb2b3836c55b384589ce19dfe743363ac9948d1f3"
          "46b7bfddfe92efd78adb21faefc89ade42b10f374003fe122e67429a1cb8cbd1"
          "f8d9014564c44d120116f4990f1a6e38774c194bd1b8213286b077b0499d2e7b"
          "3f434ab12289c556684deed78131934bb3dd6537236f7c6f3dcb09d476be0772"
          "1e37e1ceed9b2f7b406887bd53157305e1c8b4f84d733bc1e186fe06cc59b6ed"
          "b8f4bd7ffefdf4f7ba9cfb9d570689b5a1a4109a746a690893db3799255a0cb9"
          "215d2d1cd490590e952e8c8786aa0011265252470c041dfbc3eec7c3cbf71c24"
          "869d115c0cb4a956f56d530b80ab589acfefc690751ddf36e8d383f83cedd2cc"
        },{
          "PSS Example 10.6",
          "25f10895a87716c137450bb9519dfaa1f207faa942ea88abf71e9c17980085b5"
          "55aebab76264ae2a3ab93c2d12981191ddac6fb5949eb36aee3c5da940f00752"
          "c916d94608fa7d97ba6a2915b688f20323d4e9d96801d89a72ab5892dc2117c0"
          "7434fcf972e058cf8c41ca4b4ff554f7d5068ad3155fced0f3125bc04f919337"
          "8a8f5c4c3b8cb4dd6d1cc69d30ecca6eaa51e36a05730e9e342e855baf099def"
          "b8afd7",
          "ad8b1523703646224b660b550885917ca2d1df28",
          "6d3b5b87f67ea657af21f75441977d2180f91b2c5f692de82955696a686730d9"
          "b9778d970758ccb26071c2209ffbd6125be2e96ea81b67cb9b9308239fda17f7"
          "b2b64ecda096b6b935640a5a1cb42a9155b1c9ef7a633a02c59f0d6ee59b852c"
          "43b35029e73c940ff0410e8f114eed46bbd0fae165e42be2528a401c3b28fd81"
          "8ef3232dca9f4d2a0f5166ec59c42396d6c11dbc1215a56fa17169db9575343e"
          "f34f9de32a49cdc3174922f229c23e18e45df9353119ec4319cedce7a17c6408"
          "8c1f6f52be29634100b3919d38f3d1ed94e6891e66a73b8fb849f5874df59459"
          "e298c7bbce2eee782a195aa66fe2d0732b25e595f57d3e061b1fc3e4063bf98f"
        }
      }
    }
  };
  gpg_error_t err;
  int tno, mno;

  for (tno = 0; tno < DIM (tbl); tno++)
    {
      void *rsa_n, *rsa_e, *rsa_d;
      size_t rsa_n_len, rsa_e_len, rsa_d_len;
      gcry_sexp_t sec_key, pub_key;

      if (verbose > 1)
        info ("(%s)\n", tbl[tno].desc);

      rsa_n = data_from_hex (tbl[tno].n, &rsa_n_len);
      rsa_e = data_from_hex (tbl[tno].e, &rsa_e_len);
      rsa_d = data_from_hex (tbl[tno].d, &rsa_d_len);
      err = gcry_sexp_build (&sec_key, NULL,
                             "(private-key (rsa (n %b)(e %b)(d %b)))",
                             (int)rsa_n_len, rsa_n,
                             (int)rsa_e_len, rsa_e,
                             (int)rsa_d_len, rsa_d);
      if (err)
        die ("constructing private key failed: %s\n", gpg_strerror (err));
      err = gcry_sexp_build (&pub_key, NULL,
                             "(public-key (rsa (n %b)(e %b)))",
                             (int)rsa_n_len, rsa_n,
                             (int)rsa_e_len, rsa_e);
      if (err)
        die ("constructing public key failed: %s\n", gpg_strerror (err));
      gcry_free (rsa_n);
      gcry_free (rsa_e);
      gcry_free (rsa_d);

      for (mno = 0; mno < DIM (tbl[0].m); mno++)
        {
          void *mesg, *salt, *sign;
          size_t mesg_len, salt_len, sign_len;
          gcry_sexp_t sigtmpl, sig;
          char mhash[20];

          if (verbose)
            info ("running test: %s\n", tbl[tno].m[mno].desc);

          mesg = data_from_hex (tbl[tno].m[mno].mesg, &mesg_len);
          salt = data_from_hex (tbl[tno].m[mno].salt, &salt_len);

          gcry_md_hash_buffer (GCRY_MD_SHA1, mhash, mesg, mesg_len);
          err = gcry_sexp_build (&sigtmpl, NULL,
                                 "(data (flags pss)"
                                 "(hash sha1 %b)"
                                 "(random-override %b))",
                                 20, mhash,
                                 (int)salt_len, salt);
          if (err)
            die ("constructing sig template failed: %s\n", gpg_strerror (err));
          gcry_free (mesg);
          gcry_free (salt);

          err = gcry_pk_sign (&sig, sigtmpl, sec_key);
          if (err)
            {
              show_sexp ("sigtmpl:\n", sigtmpl);
              fail ("gcry_pk_sign failed: %s\n", gpg_strerror (err));
            }
          else
            {
              if (extract_cmp_data (sig, "s", tbl[tno].m[mno].sign,
                                    tbl[tno].m[mno].desc))
                {
                  show_sexp ("sign result:\n", sig);
                  fail ("mismatch in gcry_pk_sign\n");
                }
              gcry_sexp_release (sig);
              sig = NULL;
            }
          gcry_sexp_release (sigtmpl);
          sigtmpl = NULL;

          /* Now test the verification.  */
          salt = data_from_hex (tbl[tno].m[mno].salt, &salt_len);
          sign = data_from_hex (tbl[tno].m[mno].sign, &sign_len);

          err = gcry_sexp_build (&sig, NULL,
                                 "(sig-val(rsa(s %b)))",
                                 (int)sign_len, sign);
          if (err)
            die ("constructing verify data failed: %s\n", gpg_strerror (err));
          err = gcry_sexp_build (&sigtmpl, NULL,
                                 "(data (flags pss)"
                                 "(hash sha1 %b)"
                                 "(random-override %b))",
                                 20, mhash,
                                 (int)salt_len, salt);
          if (err)
            die ("constructing verify tmpl failed: %s\n", gpg_strerror (err));
          gcry_free (sign);
          gcry_free (salt);

          err = gcry_pk_verify (sig, sigtmpl, pub_key);
          if (err)
            {
              show_sexp ("sig:\n", sig);
              show_sexp ("sigtmpl:\n", sigtmpl);
              fail ("gcry_pk_verify failed: %s\n", gpg_strerror (err));
            }
          gcry_sexp_release (sig);
          sig = NULL;
          gcry_sexp_release (sigtmpl);
          sigtmpl = NULL;
        }

      gcry_sexp_release (sec_key);
      gcry_sexp_release (pub_key);
    }
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  int debug = 0;
  int run_oaep = 0;
  int run_pss = 0;

  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = 2;
          debug = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--die"))
        {
          die_on_error = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--oaep"))
        {
          run_oaep = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--pss"))
        {
          run_pss = 1;
          argc--; argv++;
        }
    }

  if (!run_oaep && !run_pss)
    run_oaep = run_pss = 1;

  gcry_control (GCRYCTL_SET_VERBOSITY, (int)verbose);
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version ("1.5.0"))
    die ("version mismatch\n");
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  /* No valuable keys are create, so we can speed up our RNG. */
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  if (run_oaep)
    check_oaep ();
  if (run_pss)
    check_pss ();

  if (verbose)
    fprintf (stderr, "\nAll tests completed.  Errors: %i\n", error_count);

  return error_count ? 1 : 0;
}
