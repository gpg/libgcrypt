/* dsa-rfc6979.c - Test for Deterministic DSA
 * Copyright (C) 2008 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
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
# include "../src/gcrypt-int.h"
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


static void
extract_cmp_data (gcry_sexp_t sexp, const char *name, const char *expected)
{
  gcry_sexp_t l1;
  const void *a;
  size_t alen;
  void *b;
  size_t blen;

  l1 = gcry_sexp_find_token (sexp, name, 0);
  a = gcry_sexp_nth_data (l1, 1, &alen);
  b = data_from_hex (expected, &blen);
  if (!a)
    fail ("parameter \"%s\" missing in key\n", name);
  else if ( alen != blen || memcmp (a, b, alen) )
    {
      fail ("parameter \"%s\" does not match expected value\n", name);
      if (verbose)
        {
          info ("expected: %s\n", expected);
          show_sexp ("sexp: ", sexp);
        }
    }
  gcry_free (b);
  gcry_sexp_release (l1);
}


/* These test vectors are from RFC 6979.  */
static void
check_dsa_rfc6979 (void)
{
  static struct {
    const char *name;
    const char *key;
  } keys[] = {
    {
      "DSA, 1024 bits",
      "(private-key"
      " (DSA"
      " (p #86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447"
      "     E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88"
      "     73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C"
      "     881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779#)"
      " (q #996F967F6C8E388D9E28D01E205FBA957A5698B1#)"
      " (g #07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D"
      "     89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD"
      "     87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4"
      "     17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD#)"
      " (x #411602CB19A6CCC34494D79D98EF1E7ED5AF25F7#)"
      " (y #5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653"
      "     92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D"
      "     4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6"
      "     82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B#)"
      " ))"
    },
    {
      "DSA, 2048 bits",
      "(private-key"
      " (DSA"
      " (p #9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48"
      "     C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F"
      "     FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5"
      "     B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2"
      "     35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41"
      "     F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE"
      "     92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15"
      "     3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B#)"
      " (q #F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F#)"
      " (g #5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613"
      "     D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4"
      "     6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472"
      "     085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5"
      "     AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA"
      "     3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71"
      "     BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0"
      "     DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7#)"
      " (x #69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC#)"
      " (y #667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94"
      "     9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61"
      "     1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE"
      "     CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB"
      "     5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254"
      "     687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1"
      "     23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA"
      "     74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF#)"
      " ))"
    },
    { NULL }
  };

  static struct {
    const char *keyname;
    const char *name;
    const char *hashname;
    const char *message;
    const char *k, *r, *s;
  } tests[] = {
    {
      "DSA, 1024 bits",
      "With SHA-1, message = \"sample\"",
      "sha1", "sample",
      "7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B",
      "2E1A0C2562B2912CAAF89186FB0F42001585DA55",
      "29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5"
    },
    {
      "DSA, 1024 bits",
      "With SHA-224, message = \"sample\"",
      "sha224", "sample",
      "562097C06782D60C3037BA7BE104774344687649",
      "4BC3B686AEA70145856814A6F1BB53346F02101E",
      "410697B92295D994D21EDD2F4ADA85566F6F94C1"
    },
    {
      "DSA, 1024 bits",
      "With SHA-256, message = \"sample\"",
      "sha256", "sample",
      "519BA0546D0C39202A7D34D7DFA5E760B318BCFB",
      "81F2F5850BE5BC123C43F71A3033E9384611C545",
      "4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89"
    },
    {
      "DSA, 1024 bits",
      "With SHA-384, message = \"sample\"",
      "sha384", "sample",
      "95897CD7BBB944AA932DBC579C1C09EB6FCFC595",
      "07F2108557EE0E3921BC1774F1CA9B410B4CE65A",
      "54DF70456C86FAC10FAB47C1949AB83F2C6F7595"
    },
    {
      "DSA, 1024 bits",
      "With SHA-512, message = \"sample\"",
      "sha512", "sample",
      "09ECE7CA27D0F5A4DD4E556C9DF1D21D28104F8B",
      "16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B",
      "02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C"
    },
    {
      "DSA, 1024 bits",
      "With SHA-1, message = \"test\"",
      "sha1", "test",
      "5C842DF4F9E344EE09F056838B42C7A17F4A6433",
      "42AB2052FD43E123F0607F115052A67DCD9C5C77",
      "183916B0230D45B9931491D4C6B0BD2FB4AAF088"
    },
    {
      "DSA, 1024 bits",
      "With SHA-224, message = \"test\"",
      "sha224", "test",
      "4598B8EFC1A53BC8AECD58D1ABBB0C0C71E67297",
      "6868E9964E36C1689F6037F91F28D5F2C30610F2",
      "49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F"
    },
    {
      "DSA, 1024 bits",
      "With SHA-256, message = \"test\"",
      "sha256", "test",
      "5A67592E8128E03A417B0484410FB72C0B630E1A",
      "22518C127299B0F6FDC9872B282B9E70D0790812",
      "6837EC18F150D55DE95B5E29BE7AF5D01E4FE160"
    },
    {
      "DSA, 1024 bits",
      "With SHA-384, message = \"test\"",
      "sha384", "test",
      "220156B761F6CA5E6C9F1B9CF9C24BE25F98CD89",
      "854CF929B58D73C3CBFDC421E8D5430CD6DB5E66",
      "91D0E0F53E22F898D158380676A871A157CDA622"
    },
    {
      "DSA, 1024 bits",
      "With SHA-512, message = \"test\"",
      "sha512", "test",
      "65D2C2EEB175E370F28C75BFCDC028D22C7DBE9C",
      "8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0",
      "7C670C7AD72B6C050C109E1790008097125433E8"
    },
    {
      "DSA, 2048 bits",
      "With SHA-1, message = \"sample\"",
      "sha1", "sample",
      "888FA6F7738A41BDC9846466ABDB8174C0338250AE50CE955CA16230F9CBD53E",
      "3A1B2DBD7489D6ED7E608FD036C83AF396E290DBD602408E8677DAABD6E7445A",
      "D26FCBA19FA3E3058FFC02CA1596CDBB6E0D20CB37B06054F7E36DED0CDBBCCF"
    },
    {
      "DSA, 2048 bits",
      "With SHA-224, message = \"sample\"",
      "sha224", "sample",
      "BC372967702082E1AA4FCE892209F71AE4AD25A6DFD869334E6F153BD0C4D806",
      "DC9F4DEADA8D8FF588E98FED0AB690FFCE858DC8C79376450EB6B76C24537E2C",
      "A65A9C3BC7BABE286B195D5DA68616DA8D47FA0097F36DD19F517327DC848CEC"
    },
    {
      "DSA, 2048 bits",
      "With SHA-256, message = \"sample\"",
      "sha256", "sample",
      "8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52",
      "EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809",
      "7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53"
    },
    {
      "DSA, 2048 bits",
      "With SHA-384, message = \"sample\"",
      "sha384", "sample",
      "C345D5AB3DA0A5BCB7EC8F8FB7A7E96069E03B206371EF7D83E39068EC564920",
      "B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B",
      "19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B"
    },
    {
      "DSA, 2048 bits",
      "With SHA-512, message = \"sample\"",
      "sha512", "sample",
      "5A12994431785485B3F5F067221517791B85A597B7A9436995C89ED0374668FC",
      "2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E",
      "D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351"
    },
    {
      "DSA, 2048 bits",
      "With SHA-1, message = \"test\"",
      "sha1", "test",
      "6EEA486F9D41A037B2C640BC5645694FF8FF4B98D066A25F76BE641CCB24BA4F",
      "C18270A93CFC6063F57A4DFA86024F700D980E4CF4E2CB65A504397273D98EA0",
      "414F22E5F31A8B6D33295C7539C1C1BA3A6160D7D68D50AC0D3A5BEAC2884FAA"
    },
    {
      "DSA, 2048 bits",
      "With SHA-224, message = \"test\"",
      "sha224", "test",
      "06BD4C05ED74719106223BE33F2D95DA6B3B541DAD7BFBD7AC508213B6DA6670",
      "272ABA31572F6CC55E30BF616B7A265312018DD325BE031BE0CC82AA17870EA3",
      "E9CC286A52CCE201586722D36D1E917EB96A4EBDB47932F9576AC645B3A60806"
    },
    {
      "DSA, 2048 bits",
      "With SHA-256, message = \"test\"",
      "sha256", "test",
      "1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7",
      "8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0",
      "7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E"
    },
    {
      "DSA, 2048 bits",
      "With SHA-384, message = \"test\"",
      "sha384", "test",
      "206E61F73DBE1B2DC8BE736B22B079E9DACD974DB00EEBBC5B64CAD39CF9F91C",
      "239E66DDBE8F8C230A3D071D601B6FFBDFB5901F94D444C6AF56F732BEB954BE",
      "6BD737513D5E72FE85D1C750E0F73921FE299B945AAD1C802F15C26A43D34961"
    },
    {
      "DSA, 2048 bits",
      "With SHA-512, message = \"test\"",
      "sha512", "test",
      "AFF1651E4CD6036D57AA8B2A05CCF1A9D5A40166340ECBBDC55BE10B568AA0AA",
      "89EC4BB1400ECCFF8E7D9AA515CD1DE7803F2DAFF09693EE7FD1353E90A68307",
      "C9F0BDABCC0D880BB137A994CC7F3980CE91CC10FAF529FC46565B15CEA854E1"
    },
    { NULL }
  };

  gpg_error_t err;
  int tno, i, hashalgo;
  gcry_sexp_t seckey, data, sig;
  unsigned char digest[64];
  int digestlen;

  for (tno = 0; tests[tno].keyname; tno++)
    {
      if (verbose)
        info ("Test %d: %s. %s.\n", tno, tests[tno].keyname, tests[tno].name);

      {
        for (i=0; keys[i].name; i++)
          if (!strcmp (tests[tno].keyname, keys[i].name))
            break;
        if (!keys[i].name)
          die ("Key '%s' used by test '%s' not found\n",
               tests[tno].keyname, tests[tno].name);

        err = gcry_sexp_new (&seckey, keys[i].key, 0, 1);
        if (err)
          die ("reading key failed: %s\n", gpg_strerror (err));
      }

      hashalgo = gcry_md_map_name (tests[tno].hashname);
      if (!hashalgo)
        die ("hash with name '%s' is not supported\n", tests[tno].hashname);

      digestlen = gcry_md_get_algo_dlen (hashalgo);
      if (digestlen > sizeof digest)
        die ("internal error: digest does not fit into our buffer\n");

      gcry_md_hash_buffer (hashalgo, digest,
                           tests[tno].message, strlen (tests[tno].message));

      err = gcry_sexp_build (&data, NULL,
                             "(data "
                             " (flags rfc6979)"
                             " (hash %s %b))",
                             tests[tno].hashname, digestlen, digest);
      if (err)
        die ("building data sexp failed: %s\n", gpg_strerror (err));

      err = gcry_pk_sign (&sig, data, seckey);
      if (err)
        fail ("signing failed: %s\n", gpg_strerror (err));

      extract_cmp_data (sig, "r", tests[tno].r);
      extract_cmp_data (sig, "s", tests[tno].s);

      err = gcry_pk_verify (sig, data, seckey);
      if (err)
        fail ("verification failed: %s\n", gpg_strerror (err));


      gcry_sexp_release (sig);
      gcry_sexp_release (data);
      gcry_sexp_release (seckey);
    }
}



int
main (int argc, char **argv)
{
  int debug = 0;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    {
      verbose = 2;
      debug = 1;
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  /* Check that we test exactly our version - including the patchlevel.  */
  if (strcmp (GCRYPT_VERSION, gcry_check_version (NULL)))
    die ("version mismatch; pgm=%s, library=%s\n",
         GCRYPT_VERSION,gcry_check_version (NULL));
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  /* No valuable keys are create, so we can speed up our RNG. */
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  check_dsa_rfc6979 ();

  return error_count ? 1 : 0;
}
