/* mlkem-test.c - Test for the ML-KEM algorithm (Crystals-Kyber)
 * Copyright (C) 2023 MTG AG
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
#include <config.h>
#endif
//#include "g10lib.h"
#include "gcrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#if 0
#ifdef _GCRYPT_IN_LIBGCRYPT
#include "../src/gcrypt-int.h"
#else
#include <gcrypt.h>
#endif
#endif


#define PGM "mlkem-test"
#include "t-common.h"
#define N_GEN_ENC_DEC_TESTS 250
// #define N_GEN_ENC_DEC_TESTS 3 // two tests running, starting from 3 with
// newly added call to mlkem_check_secret_key it fails.

// test-utils.h must be included after t-common.h
#include "test-utils.h"

static void test_hex_decoding(void)
{
  const char *hex1                 = "value = FF00a0";
  const char *hex2                 = "value=FF00a0";
  const char *hex_arr[]            = {hex1, hex2};
  const unsigned char exp_result[] = {255, 0, 160};
  size_t bin_len;
  unsigned i;
  for (i = 0; i < 2; i++)
    {
      unsigned char *buffer
          = fill_bin_buf_from_hex_line(&bin_len, '=', hex_arr[i], 0);
      if (bin_len != sizeof(exp_result) || memcmp(exp_result, buffer, bin_len))
        {
          fail("error with mlkem hex decoding test");
        }
      xfree(buffer);
    }
  info("success: mlkem hex decoding test\n");
}

typedef struct
{
  const char *index;
  unsigned char *result_buf;
  size_t result_buf_len;
} test_vec_desc_entry;

#if 0
static void
show_sexp (const char *prefix, gcry_sexp_t a)
{
  char *buf;
  size_t size;

  fprintf (stderr, "%s: ", PGM);
  if (prefix)
    fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = xmalloc (size);

  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  gcry_free (buf);
}
#endif

static int check_mlkem_gen_enc_dec(unsigned mlkem_bits,
                                   int do_print_secmem_peak_usages)
{

  gcry_sexp_t skey, pkey;
  gcry_sexp_t ct, shared_secret, shared_secret2;
  gcry_sexp_t keyparm, key, l;

  gcry_mpi_t ss, ss2;
  int rc;

  if (verbose > 1)
    info("creating ML-KEM %u key\n", mlkem_bits);

  rc = gcry_sexp_build(&keyparm,
                       NULL,
                       "(genkey\n"
                       " (mlkem\n"
                       "  (nbits%u)\n"
                       " ))",
                       mlkem_bits,
                       NULL);
  if (rc)
    die("error creating S-expression: %s\n", gpg_strerror(rc));
  if(do_print_secmem_peak_usages)
  {
      gcry_control(GCRYCTL_RST_SECMEM_PEAK_USG);
  }

  if(do_print_secmem_peak_usages)
  {
      printf("\nsecmem stats before test:\n");
      gcry_control(GCRYCTL_DUMP_SECMEM_STATS);
  }
  rc = gcry_pk_genkey(&key, keyparm);
  if(do_print_secmem_peak_usages)
  {
      printf("\nsecmem stats for mlkem %u key generation:\n", mlkem_bits);
      gcry_control(GCRYCTL_DUMP_SECMEM_STATS);
  }

  if (rc)
    die("error generating ML-KEM key: %s\n", gpg_strerror(rc));


  pkey = gcry_sexp_find_token(key, "public-key", 0);
  if (!pkey)
    {
      die("public part missing in return value\n");
    }

  skey = gcry_sexp_find_token(key, "private-key", 0);
  if (!skey)
    die("private part missing in return value\n");

  if(do_print_secmem_peak_usages)
  {
      gcry_control(GCRYCTL_RST_SECMEM_PEAK_USG);
  }
  rc = gcry_pk_encap(&ct, &shared_secret, pkey);
  if (rc)
    {
      printf("error when calling gcry_pk_encap\n");
      goto leave;
    }

  if(do_print_secmem_peak_usages)
  {
      printf("secmem stats for mlkem %u encapsulation:\n", mlkem_bits);
      gcry_control(GCRYCTL_DUMP_SECMEM_STATS);
  }
  if(do_print_secmem_peak_usages)
  {
      gcry_control(GCRYCTL_RST_SECMEM_PEAK_USG);
  }
  rc = gcry_pk_decrypt(&shared_secret2, ct, skey);
  if(do_print_secmem_peak_usages)
  {
      printf("secmem stats for mlkem %u decapsulation:\n", mlkem_bits);
      gcry_control(GCRYCTL_DUMP_SECMEM_STATS);
  }
  if (rc)
    {
      printf("error when calling gcry_pk_decrypt\n");
      goto leave;
    }

  l = gcry_sexp_find_token(shared_secret, "value", 0);
  if (!l)
    {
      die("could not extract shared secret from encapsulation");
    }
  ss = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release(l);

  l = gcry_sexp_find_token(shared_secret2, "value", 0);
  if (!l)
    {
      die("could not extract shared secret from encapsulation");
    }
  ss2 = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release(l);
  if (!ss)
    {
      die("ss = NULL\n");
    }
  if (!ss2)
    {
      die("ss2 = NULL\n");
    }

  /* Compare.  */
  if (gcry_mpi_cmp(ss, ss2))
    {
      printf("decryption result incorrect\n");
      die("check_mlkem_gen_enc_dec test: error with decryption result\n");
    }
  gcry_mpi_release(ss);
  gcry_mpi_release(ss2);
  gcry_sexp_release(keyparm);
  gcry_sexp_release(key);
  gcry_sexp_release(ct);
  gcry_sexp_release(shared_secret);
  gcry_sexp_release(shared_secret2);
  gcry_sexp_release(skey);
  gcry_sexp_release(pkey);


leave:
  return rc;

  if(do_print_secmem_peak_usages)
  {
      printf("\nsecmem stats at the end of the test:\n");
      gcry_control(GCRYCTL_DUMP_SECMEM_STATS);
  }
}
static void check_mlkem_kat(const char *fname, unsigned mlkem_bits)
{
  const size_t nb_kat_tests = 0; /* zero means all */
  FILE *fp;
  int lineno = 0;
  char *line;

  enum
  {
    public_key_idx    = 0,
    privat_key_idx    = 1,
    ciphertext_idx    = 2,
    shared_secret_idx = 3
  };

  test_vec_desc_entry test_vec[] = {{
                                        "Public Key:",
                                        NULL,
                                        0,
                                    },
                                    {
                                        "Secret Key:",
                                        NULL,
                                        0,
                                    },
                                    {
                                        "Ciphertext:",
                                        NULL,
                                        0,
                                    },
                                    {
                                        "Shared Secret A:",
                                        NULL,
                                        0,
                                    }};
  size_t test_count              = 0;
  gcry_sexp_t public_key_sx = NULL, private_key_sx = NULL,
              ciphertext_sx = NULL, shared_secret_expected_sx = NULL,
              shared_secret_sx = NULL;


  info("Checking ML-KEM KAT.\n");

  fp = fopen(fname, "r");
  if (!fp)
    die("error opening '%s': %s\n", fname, strerror(errno));


  while ((line = read_textline(fp, &lineno))
         && !(nb_kat_tests && nb_kat_tests <= test_count))
    {
      gcry_sexp_t l;
      gcry_mpi_t ss_expected, ss;
      int have_flags;
      int rc;
      int is_complete = 1;
      gcry_error_t err;
      unsigned i;
      for (i = 0; i < sizeof(test_vec) / sizeof(test_vec[0]); i++)
        {
          test_vec_desc_entry *e = &test_vec[i];
          if (!strncmp(line, e->index, strlen(e->index)))
            {
              if (e->result_buf != NULL)
                {
                  fail("trying to set test vector element twice");
                }
              e->result_buf = fill_bin_buf_from_hex_line(
                  &e->result_buf_len, ':', line, lineno);
              break;
            }
          else if (!strncmp(line, "#", 1)
                   || !strncmp(line, "Shared Secret B:", 15))
            {
              continue;
            }
          /* may not fail here because mlkem test vectors as generated
            by reference implementation contain random seeds without prefix */
        }

      // check if we completed one test vector:
      for (i = 0; i < sizeof(test_vec) / sizeof(test_vec[0]); i++)
        {
          is_complete &= (test_vec[i].result_buf != NULL);
        }
      if (!is_complete)
        {
          xfree(line);
          continue;
        }
      test_count++;
      err = gcry_sexp_build(&private_key_sx,
                            NULL,
                            "(private-key (mlkem (s %b) (nbits%u) ))",
                            (int)test_vec[privat_key_idx].result_buf_len,
                            test_vec[privat_key_idx].result_buf,
                            mlkem_bits,
                            NULL);
      if (err)
        {
          fail("error building private key SEXP for test, %s: %s",
               "sk",
               gpg_strerror(err));
          goto leave;
        }
#if 0
        printf("private key sx directly after building:\n");
        gcry_sexp_dump(private_key_sx);
        char print_buf[100000];
        gcry_sexp_sprint(private_key_sx, GCRYSEXP_FMT_ADVANCED, print_buf, sizeof(print_buf)-1);
        printf("private_key_sx: %s", print_buf);
#endif

      err = gcry_sexp_build(&shared_secret_expected_sx,
                            NULL,
                            "(data (value %b))",
                            (int)test_vec[shared_secret_idx].result_buf_len,
                            test_vec[shared_secret_idx].result_buf);
      if (err)
        {
          fail("error building expected shared secret SEXP for test, %s: %s",
               "pk",
               gpg_strerror(err));
          goto leave;
        }

      l = gcry_sexp_find_token(shared_secret_expected_sx, "value", 0);
      ss_expected = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release(l);

      err = gcry_sexp_build(&ciphertext_sx,
                            NULL,
                            "(ciphertext (mlkem(c %b)))",
                            (int)test_vec[ciphertext_idx].result_buf_len,
                            test_vec[ciphertext_idx].result_buf);
      if (err)
        {
          fail("error building ciphertext SEXP for test, %s: %s",
               "pk",
               gpg_strerror(err));
          goto leave;
        }

      l          = gcry_sexp_find_token(ciphertext_sx, "flags", 0);
      have_flags = !!l;
      gcry_sexp_release(l);


      rc = gcry_pk_decrypt(&shared_secret_sx, ciphertext_sx, private_key_sx);
      if (rc)
        {
          die("decryption failed: %s\n", gcry_strerror(rc));
        }

      l = gcry_sexp_find_token(shared_secret_sx, "value", 0);
      if (l)
        {
          if (!have_flags)
            {
              // printf("compatibility mode of pk_decrypt broken:
              // !have_flags\n"); die ("compatibility mode of pk_decrypt
              // broken: !have_flags\n");
            }
          ss = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
          gcry_sexp_release(l);
        }
      else
        {
          if (have_flags)
            // die ("compatibility mode of pk_decrypt broken: have_flags is
            // true\n");
            ss = gcry_sexp_nth_mpi(shared_secret_sx, 0, GCRYMPI_FMT_USG);
        }
      if (!ss)
        {
          die("ss = NULL\n");
        }
      if (!ss_expected)
        {
          die("ss_expected = NULL\n");
        }

      /* Compare.  */
      if (gcry_mpi_cmp(ss_expected, ss))
        {
          die("error with decryption result\n");
        }
      printf(".");


      xfree(line);
      for (i = 0; i < sizeof(test_vec) / sizeof(test_vec[0]); i++)
        {
          test_vec_desc_entry *e = &test_vec[i];
          if (e->result_buf)
            {
              xfree(e->result_buf);
            }
          e->result_buf     = NULL;
          e->result_buf_len = 0;
        }

      gcry_sexp_release(public_key_sx);
      public_key_sx = NULL;
      gcry_sexp_release(private_key_sx);
      private_key_sx = NULL;
      gcry_sexp_release(ciphertext_sx);
      ciphertext_sx = NULL;
      gcry_sexp_release(shared_secret_sx);
      shared_secret_sx = NULL;
      gcry_sexp_release(shared_secret_expected_sx);
      shared_secret_expected_sx = NULL;
      gcry_mpi_release(ss_expected);
      ss_expected = NULL;
      gcry_mpi_release(ss);
      ss = NULL;
    }

  printf("\n");
  xfree(line);
leave:
  line = line;
}

int main(int argc, char **argv)
{

  int last_argc = -1;
  char *fname   = NULL;
  unsigned i;
  int run_kat_tests      = 1;
  unsigned mlkem_bits[3] = {128, 192, 256};
  if (argc)
    {
      argc--;
      argv++;
    }

  while (argc && last_argc != argc)
    {
      last_argc = argc;
      if (!strcmp(*argv, "--"))
        {
          argc--;
          argv++;
          break;
        }
      else if (!strcmp(*argv, "--help"))
        {
          fputs("usage: " PGM " [options]\n"
                "Options:\n"
                "  --verbose            print timings etc.\n"
                "  --debug              flyswatter\n"
                "  --no-kat-tests       do not run the KAT tests\n",
                stdout);
          exit(0);
        }
      else if (!strcmp(*argv, "--verbose"))
        {
          verbose++;
          argc--;
          argv++;
        }
      else if (!strcmp(*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--;
          argv++;
        }
      else if (!strcmp(*argv, "--no-kat-tests"))
        {
          run_kat_tests = 0;
          argc--;
          argv++;
        }
      else if (!strcmp(*argv, "--data"))
        {
          argc--;
          argv++;
          if (argc)
            {
              xfree(fname);
              fname = xstrdup(*argv);
              argc--;
              argv++;
            }
        }
      else if (!strncmp(*argv, "--", 2))
        die("unknown option '%s'", *argv);
    }

  if (!fname)
  {
    test_hex_decoding();
  }

  printf("starting generate/encrypt/decrypt test\n");
  for (i = 0; i < N_GEN_ENC_DEC_TESTS; i++)
    {
      if (check_mlkem_gen_enc_dec(mlkem_bits[i % 3], (i < 3) && verbose))
        {
          fail("check_mlkem_gen_enc_dec() yielded an error, aborting");
        }
      printf(".");
    }
  printf("\n\n");
  if (!run_kat_tests)
    {
      printf("skipping KAT tests as requested\n");
      goto leave;
    }
  if (!fname)
    {
      const char *mlkem_kat_files[]
          = {"mlkem-512_ref.inp", "mlkem-768_ref.inp", "mlkem-1024_ref.inp"};

      for (i = 0; i < sizeof(mlkem_kat_files) / sizeof(mlkem_kat_files[0]);
           i++)
        {
          printf("starting KAT tests for ML-KEM with bit strength %u ", mlkem_bits[i]);
          check_mlkem_kat(mlkem_kat_files[i], mlkem_bits[i]);
          printf("\n");
        }
    }
  else
    {
        fail("handling of user chosen test data file is not supported");
    }
  printf("\nAll tests passed.\n");
leave:
  xfree(fname);
}
