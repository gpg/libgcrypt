/* ecc-curves.c  -  Elliptic Curve parameter mangement
 * Copyright (C) 2007, 2008, 2010, 2011 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "mpi.h"
#include "context.h"
#include "ec-context.h"
#include "ecc-common.h"


/* This tables defines aliases for curve names.  */
static const struct
{
  const char *name;  /* Our name.  */
  const char *other; /* Other name. */
} curve_aliases[] =
  {
    { "NIST P-192", "1.2.840.10045.3.1.1" }, /* X9.62 OID  */
    { "NIST P-192", "prime192v1" },          /* X9.62 name.  */
    { "NIST P-192", "secp192r1"  },          /* SECP name.  */
    { "NIST P-192", "nistp192"   },          /* rfc5656.  */

    { "NIST P-224", "secp224r1" },
    { "NIST P-224", "1.3.132.0.33" },        /* SECP OID.  */
    { "NIST P-224", "nistp224"   },          /* rfc5656.  */

    { "NIST P-256", "1.2.840.10045.3.1.7" }, /* From NIST SP 800-78-1.  */
    { "NIST P-256", "prime256v1" },
    { "NIST P-256", "secp256r1"  },
    { "NIST P-256", "nistp256"   },          /* rfc5656.  */

    { "NIST P-384", "secp384r1" },
    { "NIST P-384", "1.3.132.0.34" },
    { "NIST P-384", "nistp384"   },          /* rfc5656.  */

    { "NIST P-521", "secp521r1" },
    { "NIST P-521", "1.3.132.0.35" },
    { "NIST P-521", "nistp521"   },          /* rfc5656.  */

    { "brainpoolP160r1", "1.3.36.3.3.2.8.1.1.1" },
    { "brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3" },
    { "brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5" },
    { "brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7" },
    { "brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9" },
    { "brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11"},
    { "brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13"},

    { NULL, NULL}
  };


typedef struct
{
  const char *desc;           /* Description of the curve.  */
  unsigned int nbits;         /* Number of bits.  */
  unsigned int fips:1;        /* True if this is a FIPS140-2 approved curve. */

  enum gcry_mpi_ec_models model;/* The model describing this curve.  */

  const char *p;              /* Order of the prime field.  */
  const char *a, *b;          /* The coefficients.  For Twisted Edwards
                                 Curves b is used for d.  */
  const char *n;              /* The order of the base point.  */
  const char *g_x, *g_y;      /* Base point.  */
} ecc_domain_parms_t;


/* This static table defines all available curves.  */
static const ecc_domain_parms_t domain_parms[] =
  {
    {
      "NIST P-192", 192, 1,
      MPI_EC_WEIERSTRASS,
      "0xfffffffffffffffffffffffffffffffeffffffffffffffff",
      "0xfffffffffffffffffffffffffffffffefffffffffffffffc",
      "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
      "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",

      "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
      "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
    },
    {
      "NIST P-224", 224, 1,
      MPI_EC_WEIERSTRASS,
      "0xffffffffffffffffffffffffffffffff000000000000000000000001",
      "0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
      "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
      "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d" ,

      "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
      "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"
    },
    {
      "NIST P-256", 256, 1,
      MPI_EC_WEIERSTRASS,
      "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
      "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
      "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",

      "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    },
    {
      "NIST P-384", 384, 1,
      MPI_EC_WEIERSTRASS,
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
      "ffffffff0000000000000000ffffffff",
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
      "ffffffff0000000000000000fffffffc",
      "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
      "c656398d8a2ed19d2a85c8edd3ec2aef",
      "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
      "581a0db248b0a77aecec196accc52973",

      "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
      "5502f25dbf55296c3a545e3872760ab7",
      "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
      "0a60b1ce1d7e819d7a431d7c90ea0e5f"
    },
    {
      "NIST P-521", 521, 1,
      MPI_EC_WEIERSTRASS,
      "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
      "0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10"
      "9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
      "0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",

      "0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d"
      "baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
      "0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6"
      "62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
    },

    { "brainpoolP160r1", 160, 0,
      MPI_EC_WEIERSTRASS,
      "0xe95e4a5f737059dc60dfc7ad95b3d8139515620f",
      "0x340e7be2a280eb74e2be61bada745d97e8f7c300",
      "0x1e589a8595423412134faa2dbdec95c8d8675e58",
      "0xe95e4a5f737059dc60df5991d45029409e60fc09",
      "0xbed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3",
      "0x1667cb477a1a8ec338f94741669c976316da6321"
    },

    { "brainpoolP192r1", 192, 0,
      MPI_EC_WEIERSTRASS,
      "0xc302f41d932a36cda7a3463093d18db78fce476de1a86297",
      "0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
      "0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
      "0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
      "0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6",
      "0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f"
    },

    { "brainpoolP224r1", 224, 0,
      MPI_EC_WEIERSTRASS,
      "0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
      "0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
      "0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
      "0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
      "0x0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
      "0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd"
    },

    { "brainpoolP256r1", 256, 0,
      MPI_EC_WEIERSTRASS,
      "0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
      "0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
      "0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
      "0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
      "0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
      "0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"
    },

    { "brainpoolP320r1", 320, 0,
      MPI_EC_WEIERSTRASS,
      "0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28"
      "fcd412b1f1b32e27",
      "0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f4"
      "92f375a97d860eb4",
      "0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd88453981"
      "6f5eb4ac8fb1f1a6",
      "0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e9"
      "8691555b44c59311",
      "0x43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c7"
      "10af8d0d39e20611",
      "0x14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7"
      "d35245d1692e8ee1"
    },

    { "brainpoolP384r1", 384, 0,
      MPI_EC_WEIERSTRASS,
      "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123"
      "acd3a729901d1a71874700133107ec53",
      "0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f"
      "8aa5814a503ad4eb04a8c7dd22ce2826",
      "0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d5"
      "7cb4390295dbc9943ab78696fa504c11",
      "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7"
      "cf3ab6af6b7fc3103b883202e9046565",
      "0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8"
      "e826e03436d646aaef87b2e247d4af1e",
      "0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff9912928"
      "0e4646217791811142820341263c5315"
    },

    { "brainpoolP512r1", 512, 0,
      MPI_EC_WEIERSTRASS,
      "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330871"
      "7d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
      "0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc"
      "2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
      "0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a7"
      "2bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
      "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870"
      "553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
      "0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098e"
      "ff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
      "0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111"
      "b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892"
    },

    { NULL, 0, 0, 0, NULL, NULL, NULL, NULL }
  };




/* Helper to scan a hex string. */
static gcry_mpi_t
scanval (const char *string)
{
  gpg_error_t err;
  gcry_mpi_t val;

  err = gcry_mpi_scan (&val, GCRYMPI_FMT_HEX, string, 0, NULL);
  if (err)
    log_fatal ("scanning ECC parameter failed: %s\n", gpg_strerror (err));
  return val;
}


/* Generate the crypto system setup.  This function takes the NAME of
   a curve or the desired number of bits and stores at R_CURVE the
   parameters of the named curve or those of a suitable curve.  If
   R_NBITS is not NULL, the chosen number of bits is stored there.  */
gpg_err_code_t
_gcry_ecc_fill_in_curve (unsigned int nbits, const char *name,
                         elliptic_curve_t *curve, unsigned int *r_nbits)
{
  int idx, aliasno;
  const char *resname = NULL; /* Set to a found curve name.  */

  if (name)
    {
      /* First check our native curves.  */
      for (idx = 0; domain_parms[idx].desc; idx++)
        if (!strcmp (name, domain_parms[idx].desc))
          {
            resname = domain_parms[idx].desc;
            break;
          }
      /* If not found consult the alias table.  */
      if (!domain_parms[idx].desc)
        {
          for (aliasno = 0; curve_aliases[aliasno].name; aliasno++)
            if (!strcmp (name, curve_aliases[aliasno].other))
              break;
          if (curve_aliases[aliasno].name)
            {
              for (idx = 0; domain_parms[idx].desc; idx++)
                if (!strcmp (curve_aliases[aliasno].name,
                             domain_parms[idx].desc))
                  {
                    resname = domain_parms[idx].desc;
                    break;
                  }
            }
        }
    }
  else
    {
      for (idx = 0; domain_parms[idx].desc; idx++)
        if (nbits == domain_parms[idx].nbits)
          break;
    }
  if (!domain_parms[idx].desc)
    return GPG_ERR_UNKNOWN_CURVE;

  /* In fips mode we only support NIST curves.  Note that it is
     possible to bypass this check by specifying the curve parameters
     directly.  */
  if (fips_mode () && !domain_parms[idx].fips )
    return GPG_ERR_NOT_SUPPORTED;

  switch (domain_parms[idx].model)
    {
    case MPI_EC_WEIERSTRASS:
    case MPI_EC_TWISTEDEDWARDS:
      break;
    case MPI_EC_MONTGOMERY:
      return GPG_ERR_NOT_SUPPORTED;
    default:
      return GPG_ERR_BUG;
    }


  if (r_nbits)
    *r_nbits = domain_parms[idx].nbits;

  curve->model = domain_parms[idx].model;
  curve->p = scanval (domain_parms[idx].p);
  curve->a = scanval (domain_parms[idx].a);
  curve->b = scanval (domain_parms[idx].b);
  curve->n = scanval (domain_parms[idx].n);
  curve->G.x = scanval (domain_parms[idx].g_x);
  curve->G.y = scanval (domain_parms[idx].g_y);
  curve->G.z = mpi_alloc_set_ui (1);
  curve->name = resname;

  return 0;
}


/* Return the name matching the parameters in PKEY.  This works only
   with curves described by the Weierstrass equation. */
const char *
_gcry_ecc_get_curve (gcry_mpi_t *pkey, int iterator, unsigned int *r_nbits)
{
  gpg_err_code_t err;
  elliptic_curve_t E;
  int idx;
  gcry_mpi_t tmp;
  const char *result = NULL;

  if (r_nbits)
    *r_nbits = 0;

  if (!pkey)
    {
      idx = iterator;
      if (idx >= 0 && idx < DIM (domain_parms))
        {
          result = domain_parms[idx].desc;
          if (r_nbits)
            *r_nbits = domain_parms[idx].nbits;
        }
      return result;
    }

  if (!pkey[0] || !pkey[1] || !pkey[2] || !pkey[3] || !pkey[4])
    return NULL;

  E.model = MPI_EC_WEIERSTRASS;
  E.p = pkey[0];
  E.a = pkey[1];
  E.b = pkey[2];
  _gcry_mpi_point_init (&E.G);
  err = _gcry_ecc_os2ec (&E.G, pkey[3]);
  if (err)
    {
      _gcry_mpi_point_free_parts (&E.G);
      return NULL;
    }
  E.n = pkey[4];

  for (idx = 0; domain_parms[idx].desc; idx++)
    {
      tmp = scanval (domain_parms[idx].p);
      if (!mpi_cmp (tmp, E.p))
        {
          mpi_free (tmp);
          tmp = scanval (domain_parms[idx].a);
          if (!mpi_cmp (tmp, E.a))
            {
              mpi_free (tmp);
              tmp = scanval (domain_parms[idx].b);
              if (!mpi_cmp (tmp, E.b))
                {
                  mpi_free (tmp);
                  tmp = scanval (domain_parms[idx].n);
                  if (!mpi_cmp (tmp, E.n))
                    {
                      mpi_free (tmp);
                      tmp = scanval (domain_parms[idx].g_x);
                      if (!mpi_cmp (tmp, E.G.x))
                        {
                          mpi_free (tmp);
                          tmp = scanval (domain_parms[idx].g_y);
                          if (!mpi_cmp (tmp, E.G.y))
                            {
                              mpi_free (tmp);
                              result = domain_parms[idx].desc;
                              if (r_nbits)
                                *r_nbits = domain_parms[idx].nbits;
                              break;
                            }
                        }
                    }
                }
            }
        }
      mpi_free (tmp);
    }

  _gcry_mpi_point_free_parts (&E.G);

  return result;
}


/* Helper to extract an MPI from key parameters.  */
static gpg_err_code_t
mpi_from_keyparam (gcry_mpi_t *r_a, gcry_sexp_t keyparam, const char *name)
{
  gcry_err_code_t ec = 0;
  gcry_sexp_t l1;

  l1 = gcry_sexp_find_token (keyparam, name, 0);
  if (l1)
    {
      *r_a = gcry_sexp_nth_mpi (l1, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l1);
      if (!*r_a)
        ec = GPG_ERR_INV_OBJ;
    }
  return ec;
}

/* Helper to extract a point from key parameters.  If no parameter
   with NAME is found, the functions tries to find a non-encoded point
   by appending ".x", ".y" and ".z" to NAME.  ".z" is in this case
   optional and defaults to 1.  */
static gpg_err_code_t
point_from_keyparam (gcry_mpi_point_t *r_a,
                     gcry_sexp_t keyparam, const char *name)
{
  gcry_err_code_t ec;
  gcry_mpi_t a = NULL;
  gcry_mpi_point_t point;

  ec = mpi_from_keyparam (&a, keyparam, name);
  if (ec)
    return ec;

  if (a)
    {
      point = gcry_mpi_point_new (0);
      ec = _gcry_ecc_os2ec (point, a);
      mpi_free (a);
      if (ec)
        {
          gcry_mpi_point_release (point);
          return ec;
        }
    }
  else
    {
      char *tmpname;
      gcry_mpi_t x = NULL;
      gcry_mpi_t y = NULL;
      gcry_mpi_t z = NULL;

      tmpname = gcry_malloc (strlen (name) + 2 + 1);
      if (!tmpname)
        return gpg_err_code_from_syserror ();
      strcpy (stpcpy (tmpname, name), ".x");
      ec = mpi_from_keyparam (&x, keyparam, tmpname);
      if (ec)
        {
          gcry_free (tmpname);
          return ec;
        }
      strcpy (stpcpy (tmpname, name), ".y");
      ec = mpi_from_keyparam (&y, keyparam, tmpname);
      if (ec)
        {
          mpi_free (x);
          gcry_free (tmpname);
          return ec;
        }
      strcpy (stpcpy (tmpname, name), ".z");
      ec = mpi_from_keyparam (&z, keyparam, tmpname);
      if (ec)
        {
          mpi_free (y);
          mpi_free (x);
          gcry_free (tmpname);
          return ec;
        }
      if (!z)
        z = mpi_set_ui (NULL, 1);
      if (x && y)
        point = gcry_mpi_point_snatch_set (NULL, x, y, z);
      else
        {
          mpi_free (x);
          mpi_free (y);
          mpi_free (z);
          point = NULL;
        }
      gcry_free (tmpname);
    }

  if (point)
    *r_a = point;
  return 0;
}


/* This function creates a new context for elliptic curve operations.
   Either KEYPARAM or CURVENAME must be given.  If both are given and
   KEYPARAM has no curve parameter, CURVENAME is used to add missing
   parameters.  On success 0 is returned and the new context stored at
   R_CTX.  On error NULL is stored at R_CTX and an error code is
   returned.  The context needs to be released using
   gcry_ctx_release.  */
gpg_err_code_t
_gcry_mpi_ec_new (gcry_ctx_t *r_ctx,
                  gcry_sexp_t keyparam, const char *curvename)
{
  gpg_err_code_t errc;
  gcry_ctx_t ctx = NULL;
  enum gcry_mpi_ec_models model = MPI_EC_WEIERSTRASS;
  gcry_mpi_t p = NULL;
  gcry_mpi_t a = NULL;
  gcry_mpi_t b = NULL;
  gcry_mpi_point_t G = NULL;
  gcry_mpi_t n = NULL;
  gcry_mpi_point_t Q = NULL;
  gcry_mpi_t d = NULL;
  gcry_sexp_t l1;

  *r_ctx = NULL;

  if (keyparam)
    {
      errc = mpi_from_keyparam (&p, keyparam, "p");
      if (errc)
        goto leave;
      errc = mpi_from_keyparam (&a, keyparam, "a");
      if (errc)
        goto leave;
      errc = mpi_from_keyparam (&b, keyparam, "b");
      if (errc)
        goto leave;
      errc = point_from_keyparam (&G, keyparam, "g");
      if (errc)
        goto leave;
      errc = mpi_from_keyparam (&n, keyparam, "n");
      if (errc)
        goto leave;
      errc = point_from_keyparam (&Q, keyparam, "q");
      if (errc)
        goto leave;
      errc = mpi_from_keyparam (&d, keyparam, "d");
      if (errc)
        goto leave;
    }


  /* Check whether a curve parameter is available and use that to fill
     in missing values.  If no curve parameter is available try an
     optional provided curvename.  If only the curvename has been
     given use that one. */
  if (keyparam)
    l1 = gcry_sexp_find_token (keyparam, "curve", 5);
  else
    l1 = NULL;
  if (l1 || curvename)
    {
      char *name;
      elliptic_curve_t *E;

      if (l1)
        {
          name = _gcry_sexp_nth_string (l1, 1);
          gcry_sexp_release (l1);
          if (!name)
            {
              errc = GPG_ERR_INV_OBJ; /* Name missing or out of core. */
              goto leave;
            }
        }
      else
        name = NULL;

      E = gcry_calloc (1, sizeof *E);
      if (!E)
        {
          errc = gpg_err_code_from_syserror ();
          gcry_free (name);
          goto leave;
        }

      errc = _gcry_ecc_fill_in_curve (0, name? name : curvename, E, NULL);
      gcry_free (name);
      if (errc)
        {
          gcry_free (E);
          goto leave;
        }

      model = E->model;

      if (!p)
        {
          p = E->p;
          E->p = NULL;
        }
      if (!a)
        {
          a = E->a;
          E->a = NULL;
        }
      if (!b)
        {
          b = E->b;
          E->b = NULL;
        }
      if (!G)
        {
          G = gcry_mpi_point_snatch_set (NULL, E->G.x, E->G.y, E->G.z);
          E->G.x = NULL;
          E->G.y = NULL;
          E->G.z = NULL;
        }
      if (!n)
        {
          n = E->n;
          E->n = NULL;
        }
      _gcry_ecc_curve_free (E);
      gcry_free (E);
    }

  errc = _gcry_mpi_ec_p_new (&ctx, model, p, a, b);
  if (!errc)
    {
      mpi_ec_t ec = _gcry_ctx_get_pointer (ctx, CONTEXT_TYPE_EC);

      if (b)
        {
          ec->b = b;
          b = NULL;
        }
      if (G)
        {
          ec->G = G;
          G = NULL;
        }
      if (n)
        {
          ec->n = n;
          n = NULL;
        }
      if (Q)
        {
          ec->Q = Q;
          Q = NULL;
        }
      if (d)
        {
          ec->d = d;
          d = NULL;
        }

      *r_ctx = ctx;
    }

 leave:
  mpi_free (p);
  mpi_free (a);
  mpi_free (b);
  gcry_mpi_point_release (G);
  mpi_free (n);
  gcry_mpi_point_release (Q);
  mpi_free (d);
  return errc;
}


/* Return the parameters of the curve NAME in an MPI array.  */
gcry_err_code_t
_gcry_ecc_get_param (const char *name, gcry_mpi_t *pkey)
{
  gpg_err_code_t err;
  unsigned int nbits;
  elliptic_curve_t E;
  mpi_ec_t ctx;
  gcry_mpi_t g_x, g_y;

  err = _gcry_ecc_fill_in_curve (0, name, &E, &nbits);
  if (err)
    return err;

  g_x = mpi_new (0);
  g_y = mpi_new (0);
  ctx = _gcry_mpi_ec_p_internal_new (0, E.p, E.a, NULL);
  if (_gcry_mpi_ec_get_affine (g_x, g_y, &E.G, ctx))
    log_fatal ("ecc get param: Failed to get affine coordinates\n");
  _gcry_mpi_ec_free (ctx);
  _gcry_mpi_point_free_parts (&E.G);

  pkey[0] = E.p;
  pkey[1] = E.a;
  pkey[2] = E.b;
  pkey[3] = _gcry_ecc_ec2os (g_x, g_y, E.p);
  pkey[4] = E.n;
  pkey[5] = NULL;

  mpi_free (g_x);
  mpi_free (g_y);

  return 0;
}


/* Return the parameters of the curve NAME as an S-expression.  */
gcry_sexp_t
_gcry_ecc_get_param_sexp (const char *name)
{
  gcry_mpi_t pkey[6];
  gcry_sexp_t result;
  int i;

  if (_gcry_ecc_get_param (name, pkey))
    return NULL;

  if (gcry_sexp_build (&result, NULL,
                       "(public-key(ecc(p%m)(a%m)(b%m)(g%m)(n%m)))",
                       pkey[0], pkey[1], pkey[2], pkey[3], pkey[4]))
    result = NULL;

  for (i=0; pkey[i]; i++)
    gcry_mpi_release (pkey[i]);

  return result;
}
