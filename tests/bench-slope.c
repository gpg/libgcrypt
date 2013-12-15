/* bench-slope.c - for libgcrypt
 * Copyright (C) 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>

#ifdef _GCRYPT_IN_LIBGCRYPT
# include "../src/gcrypt-int.h"
# include "../compat/libcompat.h"
#else
# include <gcrypt.h>
#endif

#ifndef STR
#define STR(v) #v
#define STR2(v) STR(v)
#endif

#define PGM "bench-slope"

static int verbose;
static int csv_mode;
static int num_measurement_repetitions;

/* CPU Ghz value provided by user, allows constructing cycles/byte and other
   results.  */
static double cpu_ghz = -1;

/* Whether we are running as part of the regression test suite.  */
static int in_regression_test;

/* The name of the currently printed section.  */
static char *current_section_name;
/* The name of the currently printed algorithm.  */
static char *current_algo_name;
/* The name of the currently printed mode.  */
static char *current_mode_name;


/*************************************** Default parameters for measurements. */

/* Start at small buffer size, to get reasonable timer calibration for fast
 * implementations (AES-NI etc). Sixteen selected to support the largest block
 * size of current set cipher blocks. */
#define BUF_START_SIZE			16

/* From ~0 to ~4kbytes give comparable results with results from academia
 * (SUPERCOP). */
#define BUF_END_SIZE			(BUF_START_SIZE + 4096)

/* With 128 byte steps, we get (4096)/64 = 64 data points. */
#define BUF_STEP_SIZE			64

/* Number of repeated measurements at each data point. The median of these
 * measurements is selected as data point further analysis. */
#define NUM_MEASUREMENT_REPETITIONS	64

/**************************************************** High-resolution timers. */

/* This benchmarking module needs needs high resolution timer.  */
#undef NO_GET_NSEC_TIME
#if defined(_WIN32)
struct nsec_time
{
  LARGE_INTEGER perf_count;
};

static void
get_nsec_time (struct nsec_time *t)
{
  BOOL ok;

  ok = QueryPerformanceCounter (&t->perf_count);
  assert (ok);
}

static double
get_time_nsec_diff (struct nsec_time *start, struct nsec_time *end)
{
  static double nsecs_per_count = 0.0;
  double nsecs;

  if (nsecs_per_count == 0.0)
    {
      LARGE_INTEGER perf_freq;
      BOOL ok;

      /* Get counts per second. */
      ok = QueryPerformanceFrequency (&perf_freq);
      assert (ok);

      nsecs_per_count = 1.0 / perf_freq.QuadPart;
      nsecs_per_count *= 1000000.0 * 1000.0;	/* sec => nsec */

      assert (nsecs_per_count > 0.0);
    }

  nsecs = end->perf_count.QuadPart - start->perf_count.QuadPart;	/* counts */
  nsecs *= nsecs_per_count;	/* counts * (nsecs / count) => nsecs */

  return nsecs;
}
#elif defined(HAVE_CLOCK_GETTIME)
struct nsec_time
{
  struct timespec ts;
};

static void
get_nsec_time (struct nsec_time *t)
{
  int err;

  err = clock_gettime (CLOCK_REALTIME, &t->ts);
  assert (err == 0);
}

static double
get_time_nsec_diff (struct nsec_time *start, struct nsec_time *end)
{
  double nsecs;

  nsecs = end->ts.tv_sec - start->ts.tv_sec;
  nsecs *= 1000000.0 * 1000.0;	/* sec => nsec */

  /* This way we don't have to care if tv_nsec unsigned or signed. */
  if (end->ts.tv_nsec >= start->ts.tv_nsec)
    nsecs += end->ts.tv_nsec - start->ts.tv_nsec;
  else
    nsecs -= start->ts.tv_nsec - end->ts.tv_nsec;

  return nsecs;
}
#elif defined(HAVE_GETTIMEOFDAY)
struct nsec_time
{
  struct timeval tv;
};

static void
get_nsec_time (struct nsec_time *t)
{
  int err;

  err = gettimeofday (&t->tv, NULL);
  assert (err == 0);
}

static double
get_time_nsec_diff (struct nsec_time *start, struct nsec_time *end)
{
  double nsecs;

  nsecs = end->tv.tv_sec - start->tv.tv_sec;
  nsecs *= 1000000;		/* sec => µsec */

  /* This way we don't have to care if tv_usec unsigned or signed. */
  if (end->tv.tv_usec >= start->tv.tv_usec)
    nsecs += end->tv.tv_usec - start->tv.tv_usec;
  else
    nsecs -= start->tv.tv_usec - end->tv.tv_usec;

  nsecs *= 1000;		/* µsec => nsec */

  return nsecs;
}
#else
#define NO_GET_NSEC_TIME 1
#endif


/* If no high resolution timer found, provide dummy bench-slope.  */
#ifdef NO_GET_NSEC_TIME


int
main (void)
{
  /* No nsec timer => SKIP test. */
  return 77;
}


#else /* !NO_GET_NSEC_TIME */


/********************************************** Slope benchmarking framework. */

struct bench_obj
{
  const struct bench_ops *ops;

  unsigned int num_measure_repetitions;
  unsigned int min_bufsize;
  unsigned int max_bufsize;
  unsigned int step_size;

  void *priv;
};

typedef int (*const bench_initialize_t) (struct bench_obj * obj);
typedef void (*const bench_finalize_t) (struct bench_obj * obj);
typedef void (*const bench_do_run_t) (struct bench_obj * obj, void *buffer,
				      size_t buflen);

struct bench_ops
{
  bench_initialize_t initialize;
  bench_finalize_t finalize;
  bench_do_run_t do_run;
};


double
get_slope (double (*const get_x) (unsigned int idx, void *priv),
	   void *get_x_priv, double y_points[], unsigned int npoints,
	   double *overhead)
{
  double sumx, sumy, sumx2, sumy2, sumxy;
  unsigned int i;
  double b, a;

  sumx = sumy = sumx2 = sumy2 = sumxy = 0;

  for (i = 0; i < npoints; i++)
    {
      double x, y;

      x = get_x (i, get_x_priv);	/* bytes */
      y = y_points[i];		/* nsecs */

      sumx += x;
      sumy += y;
      sumx2 += x * x;
      /*sumy2 += y * y;*/
      sumxy += x * y;
    }

  b = (npoints * sumxy - sumx * sumy) / (npoints * sumx2 - sumx * sumx);
  a = (sumy - b * sumx) / npoints;

  if (overhead)
    *overhead = a;		/* nsecs */

  return b;			/* nsecs per byte */
}


double
get_bench_obj_point_x (unsigned int idx, void *priv)
{
  struct bench_obj *obj = priv;
  return (double) (obj->min_bufsize + (idx * obj->step_size));
}


unsigned int
get_num_measurements (struct bench_obj *obj)
{
  unsigned int buf_range = obj->max_bufsize - obj->min_bufsize;
  unsigned int num = buf_range / obj->step_size + 1;

  while (obj->min_bufsize + (num * obj->step_size) > obj->max_bufsize)
    num--;

  return num + 1;
}


static int
double_cmp (const void *_a, const void *_b)
{
  const double *a, *b;

  a = _a;
  b = _b;

  if (*a > *b)
    return 1;
  if (*a < *b)
    return -1;
  return 0;
}


double
do_bench_obj_measurement (struct bench_obj *obj, void *buffer, size_t buflen,
			  double *measurement_raw,
			  unsigned int loop_iterations)
{
  const unsigned int num_repetitions = obj->num_measure_repetitions;
  const bench_do_run_t do_run = obj->ops->do_run;
  struct nsec_time start, end;
  unsigned int rep, loop;
  double res;

  if (num_repetitions < 1 || loop_iterations < 1)
    return 0.0;

  for (rep = 0; rep < num_repetitions; rep++)
    {
      get_nsec_time (&start);

      for (loop = 0; loop < loop_iterations; loop++)
	do_run (obj, buffer, buflen);

      get_nsec_time (&end);

      measurement_raw[rep] = get_time_nsec_diff (&start, &end);
    }

  /* Return median of repeated measurements. */
  qsort (measurement_raw, num_repetitions, sizeof (measurement_raw[0]),
	 double_cmp);

  if (num_repetitions % 2 == 1)
    return measurement_raw[num_repetitions / 2];

  res = measurement_raw[num_repetitions / 2]
    + measurement_raw[num_repetitions / 2 - 1];
  return res / 2;
}


unsigned int
adjust_loop_iterations_to_timer_accuracy (struct bench_obj *obj, void *buffer,
					  double *measurement_raw)
{
  const double increase_thres = 3.0;
  double tmp, nsecs;
  unsigned int loop_iterations;
  unsigned int test_bufsize;

  test_bufsize = obj->min_bufsize;
  if (test_bufsize == 0)
    test_bufsize += obj->step_size;

  loop_iterations = 0;
  do
    {
      /* Increase loop iterations until we get other results than zero.  */
      nsecs =
	do_bench_obj_measurement (obj, buffer, test_bufsize,
				  measurement_raw, ++loop_iterations);
    }
  while (nsecs < 1.0 - 0.1);
  do
    {
      /* Increase loop iterations until we get reasonable increase for elapsed time.  */
      tmp =
	do_bench_obj_measurement (obj, buffer, test_bufsize,
				  measurement_raw, ++loop_iterations);
    }
  while (tmp < nsecs * (increase_thres - 0.1));

  return loop_iterations;
}


/* Benchmark and return linear regression slope in nanoseconds per byte.  */
double
do_slope_benchmark (struct bench_obj *obj)
{
  unsigned int num_measurements;
  double *measurements = NULL;
  double *measurement_raw = NULL;
  double slope, overhead;
  unsigned int loop_iterations, midx, i;
  unsigned char *real_buffer = NULL;
  unsigned char *buffer;
  size_t cur_bufsize;
  int err;

  err = obj->ops->initialize (obj);
  if (err < 0)
    return -1;

  num_measurements = get_num_measurements (obj);
  measurements = calloc (num_measurements, sizeof (*measurements));
  if (!measurements)
    goto err_free;

  measurement_raw =
    calloc (obj->num_measure_repetitions, sizeof (*measurement_raw));
  if (!measurement_raw)
    goto err_free;

  if (num_measurements < 1 || obj->num_measure_repetitions < 1 ||
      obj->max_bufsize < 1 || obj->min_bufsize > obj->max_bufsize)
    goto err_free;

  real_buffer = malloc (obj->max_bufsize + 128);
  if (!real_buffer)
    goto err_free;
  /* Get aligned buffer */
  buffer = real_buffer;
  buffer += 128 - ((real_buffer - (unsigned char *) 0) & (128 - 1));

  for (i = 0; i < obj->max_bufsize; i++)
    buffer[i] = 0x55 ^ (-i);

  /* Adjust number of loop iterations up to timer accuracy.  */
  loop_iterations = adjust_loop_iterations_to_timer_accuracy (obj, buffer,
							      measurement_raw);

  /* Perform measurements */
  for (midx = 0, cur_bufsize = obj->min_bufsize;
       cur_bufsize <= obj->max_bufsize; cur_bufsize += obj->step_size, midx++)
    {
      measurements[midx] =
	do_bench_obj_measurement (obj, buffer, cur_bufsize, measurement_raw,
				  loop_iterations);
      measurements[midx] /= loop_iterations;
    }

  assert (midx == num_measurements);

  slope =
    get_slope (&get_bench_obj_point_x, obj, measurements, num_measurements,
	       &overhead);

  free (measurement_raw);
  free (real_buffer);
  obj->ops->finalize (obj);

  return slope;

err_free:
  if (measurement_raw)
    free (measurement_raw);
  if (measurements)
    free (measurements);
  if (real_buffer)
    free (real_buffer);
  obj->ops->finalize (obj);

  return -1;
}


/********************************************************** Printing results. */

static void
double_to_str (char *out, size_t outlen, double value)
{
  const char *fmt;

  if (value < 1.0)
    fmt = "%.3f";
  else if (value < 100.0)
    fmt = "%.2f";
  else
    fmt = "%.1f";

  snprintf (out, outlen, fmt, value);
}

static void
bench_print_result_csv (double nsecs_per_byte)
{
  double cycles_per_byte, mbytes_per_sec;
  char nsecpbyte_buf[16];
  char mbpsec_buf[16];
  char cpbyte_buf[16];

  *cpbyte_buf = 0;

  double_to_str (nsecpbyte_buf, sizeof (nsecpbyte_buf), nsecs_per_byte);

  /* If user didn't provide CPU speed, we cannot show cycles/byte results.  */
  if (cpu_ghz > 0.0)
    {
      cycles_per_byte = nsecs_per_byte * cpu_ghz;
      double_to_str (cpbyte_buf, sizeof (cpbyte_buf), cycles_per_byte);
    }

  mbytes_per_sec =
    (1000.0 * 1000.0 * 1000.0) / (nsecs_per_byte * 1024 * 1024);
  double_to_str (mbpsec_buf, sizeof (mbpsec_buf), mbytes_per_sec);

  /* We print two empty fields to allow for future enhancements.  */
  printf ("%s,%s,%s,,,%s,ns/B,%s,MiB/s,%s,c/B\n",
          current_section_name,
          current_algo_name? current_algo_name : "",
          current_mode_name? current_mode_name : "",
          nsecpbyte_buf,
          mbpsec_buf,
          cpbyte_buf);

}

static void
bench_print_result_std (double nsecs_per_byte)
{
  double cycles_per_byte, mbytes_per_sec;
  char nsecpbyte_buf[16];
  char mbpsec_buf[16];
  char cpbyte_buf[16];

  strcpy (cpbyte_buf, "-");

  double_to_str (nsecpbyte_buf, sizeof (nsecpbyte_buf), nsecs_per_byte);

  /* If user didn't provide CPU speed, we cannot show cycles/byte results.  */
  if (cpu_ghz > 0.0)
    {
      cycles_per_byte = nsecs_per_byte * cpu_ghz;
      double_to_str (cpbyte_buf, sizeof (cpbyte_buf), cycles_per_byte);
    }

  mbytes_per_sec =
    (1000.0 * 1000.0 * 1000.0) / (nsecs_per_byte * 1024 * 1024);
  double_to_str (mbpsec_buf, sizeof (mbpsec_buf), mbytes_per_sec);

  strncat (nsecpbyte_buf, " ns/B", sizeof (nsecpbyte_buf) - 1);
  strncat (mbpsec_buf, " MiB/s", sizeof (mbpsec_buf) - 1);
  strncat (cpbyte_buf, " c/B", sizeof (cpbyte_buf) - 1);

  printf ("%14s %15s %13s\n", nsecpbyte_buf, mbpsec_buf, cpbyte_buf);
}

static void
bench_print_result (double nsecs_per_byte)
{
  if (csv_mode)
    bench_print_result_csv (nsecs_per_byte);
  else
    bench_print_result_std (nsecs_per_byte);
}

static void
bench_print_section (const char *section_name, const char *print_name)
{
  if (csv_mode)
    {
      gcry_free (current_section_name);
      current_section_name = gcry_xstrdup (section_name);
    }
  else
    printf ("%s:\n", print_name);
}

static void
bench_print_header (int algo_width, const char *algo_name)
{
  if (csv_mode)
    {
      gcry_free (current_algo_name);
      current_algo_name = gcry_xstrdup (algo_name);
    }
  else
    {
      if (algo_width < 0)
        printf (" %-*s | ", -algo_width, algo_name);
      else
        printf (" %-*s | ", algo_width, algo_name);
      printf ("%14s %15s %13s\n", "nanosecs/byte", "mebibytes/sec",
              "cycles/byte");
    }
}

static void
bench_print_algo (int algo_width, const char *algo_name)
{
  if (csv_mode)
    {
      gcry_free (current_algo_name);
      current_algo_name = gcry_xstrdup (algo_name);
    }
  else
    {
      if (algo_width < 0)
        printf (" %-*s | ", -algo_width, algo_name);
      else
        printf (" %-*s | ", algo_width, algo_name);
    }
}

static void
bench_print_mode (int width, const char *mode_name)
{
  if (csv_mode)
    {
      gcry_free (current_mode_name);
      current_mode_name = gcry_xstrdup (mode_name);
    }
  else
    {
      if (width < 0)
        printf (" %-*s | ", -width, mode_name);
      else
        printf (" %*s | ", width, mode_name);
      fflush (stdout);
    }
}

static void
bench_print_footer (int algo_width)
{
  if (!csv_mode)
    printf (" %-*s =\n", algo_width, "");
}


/********************************************************* Cipher benchmarks. */

struct bench_cipher_mode
{
  int mode;
  const char *name;
  struct bench_ops *ops;

  int algo;
};


static int
bench_encrypt_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd;
  int err, keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;
  obj->num_measure_repetitions = num_measurement_repetitions;

  err = gcry_cipher_open (&hd, mode->algo, mode->mode, 0);
  if (err)
    {
      fprintf (stderr, PGM ": error opening cipher `%s'\n",
	       gcry_cipher_algo_name (mode->algo));
      exit (1);
    }

  keylen = gcry_cipher_get_algo_keylen (mode->algo);
  if (keylen)
    {
      char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      err = gcry_cipher_setkey (hd, key, keylen);
      if (err)
	{
	  fprintf (stderr, PGM ": gcry_cipher_setkey failed: %s\n",
		   gpg_strerror (err));
	  gcry_cipher_close (hd);
	  exit (1);
	}
    }
  else
    {
      fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
	       gcry_cipher_algo_name (mode->algo));
      gcry_cipher_close (hd);
      exit (1);
    }

  obj->priv = hd;

  return 0;
}

static void
bench_encrypt_free (struct bench_obj *obj)
{
  gcry_cipher_hd_t hd = obj->priv;

  gcry_cipher_close (hd);
}

static void
bench_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  gcry_cipher_hd_t hd = obj->priv;
  int err;

  err = gcry_cipher_encrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  gcry_cipher_hd_t hd = obj->priv;
  int err;

  err = gcry_cipher_decrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static struct bench_ops encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_encrypt_do_bench
};

static struct bench_ops decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_decrypt_do_bench
};


#ifdef HAVE_U64_TYPEDEF
static void
bench_ccm_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  gcry_cipher_hd_t hd = obj->priv;
  int err;
  char tag[8];
  char nonce[11] = { 0x80, 0x01, };
  u64 params[3];

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  /* Set CCM lengths */
  params[0] = buflen;
  params[1] = 0;		/*aadlen */
  params[2] = sizeof (tag);
  err =
    gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, params, sizeof (params));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_ctl failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_encrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_gettag (hd, tag, sizeof (tag));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_ccm_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  gcry_cipher_hd_t hd = obj->priv;
  int err;
  char tag[8] = { 0, };
  char nonce[11] = { 0x80, 0x01, };
  u64 params[3];

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  /* Set CCM lengths */
  params[0] = buflen;
  params[1] = 0;		/*aadlen */
  params[2] = sizeof (tag);
  err =
    gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, params, sizeof (params));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_ctl failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_decrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_checktag (hd, tag, sizeof (tag));
  if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
    err = gpg_error (GPG_ERR_NO_ERROR);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_ccm_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  gcry_cipher_hd_t hd = obj->priv;
  int err;
  char tag[8] = { 0, };
  char nonce[11] = { 0x80, 0x01, };
  u64 params[3];
  char data = 0xff;

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  /* Set CCM lengths */
  params[0] = sizeof (data);	/*datalen */
  params[1] = buflen;		/*aadlen */
  params[2] = sizeof (tag);
  err =
    gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, params, sizeof (params));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_ctl failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_authenticate (hd, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_authenticate failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_encrypt (hd, &data, sizeof (data), &data, sizeof (data));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_gettag (hd, tag, sizeof (tag));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static struct bench_ops ccm_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ccm_encrypt_do_bench
};

static struct bench_ops ccm_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ccm_decrypt_do_bench
};

static struct bench_ops ccm_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ccm_authenticate_do_bench
};
#endif /*HAVE_U64_TYPEDEF*/


static void
bench_gcm_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  gcry_cipher_hd_t hd = obj->priv;
  int err;
  char tag[16];
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, };

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  err = gcry_cipher_encrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_gettag (hd, tag, sizeof (tag));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_gcm_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  gcry_cipher_hd_t hd = obj->priv;
  int err;
  char tag[16] = { 0, };
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, };

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  err = gcry_cipher_decrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_checktag (hd, tag, sizeof (tag));
  if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
    err = gpg_error (GPG_ERR_NO_ERROR);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_gcm_authenticate_do_bench (struct bench_obj *obj, void *buf,
           size_t buflen)
{
  gcry_cipher_hd_t hd = obj->priv;
  int err;
  char tag[16] = { 0, };
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, };
  char data = 0xff;

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  err = gcry_cipher_authenticate (hd, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_authenticate failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_encrypt (hd, &data, sizeof (data), &data, sizeof (data));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_gettag (hd, tag, sizeof (tag));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static struct bench_ops gcm_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_encrypt_do_bench
};

static struct bench_ops gcm_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_decrypt_do_bench
};

static struct bench_ops gcm_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_authenticate_do_bench
};


static struct bench_cipher_mode cipher_modes[] = {
  {GCRY_CIPHER_MODE_ECB, "ECB enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_ECB, "ECB dec", &decrypt_ops},
  {GCRY_CIPHER_MODE_CBC, "CBC enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_CBC, "CBC dec", &decrypt_ops},
  {GCRY_CIPHER_MODE_CFB, "CFB enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_CFB, "CFB dec", &decrypt_ops},
  {GCRY_CIPHER_MODE_OFB, "OFB enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_OFB, "OFB dec", &decrypt_ops},
  {GCRY_CIPHER_MODE_CTR, "CTR enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_CTR, "CTR dec", &decrypt_ops},
#ifdef HAVE_U64_TYPEDEF
  {GCRY_CIPHER_MODE_CCM, "CCM enc", &ccm_encrypt_ops},
  {GCRY_CIPHER_MODE_CCM, "CCM dec", &ccm_decrypt_ops},
  {GCRY_CIPHER_MODE_CCM, "CCM auth", &ccm_authenticate_ops},
#endif
  {GCRY_CIPHER_MODE_GCM, "GCM enc", &gcm_encrypt_ops},
  {GCRY_CIPHER_MODE_GCM, "GCM dec", &gcm_decrypt_ops},
  {GCRY_CIPHER_MODE_GCM, "GCM auth", &gcm_authenticate_ops},
  {0},
};


static void
cipher_bench_one (int algo, struct bench_cipher_mode *pmode)
{
  struct bench_cipher_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;
  unsigned int blklen;

  mode.algo = algo;

  /* Check if this mode is ok */
  blklen = gcry_cipher_get_algo_blklen (algo);
  if (!blklen)
    return;

  /* Stream cipher? Only test with ECB. */
  if (blklen == 1 && mode.mode != GCRY_CIPHER_MODE_ECB)
    return;
  if (blklen == 1 && mode.mode == GCRY_CIPHER_MODE_ECB)
    {
      mode.mode = GCRY_CIPHER_MODE_STREAM;
      mode.name = mode.ops == &encrypt_ops ? "STREAM enc" : "STREAM dec";
    }

  /* CCM has restrictions for block-size */
  if (mode.mode == GCRY_CIPHER_MODE_CCM && blklen != GCRY_CCM_BLOCK_LEN)
    return;

  /* CCM has restrictions for block-size */
  if (mode.mode == GCRY_CIPHER_MODE_GCM && blklen != GCRY_GCM_BLOCK_LEN)
    return;

  bench_print_mode (14, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}


static void
_cipher_bench (int algo)
{
  const char *algoname;
  int i;

  algoname = gcry_cipher_algo_name (algo);

  bench_print_header (14, algoname);

  for (i = 0; cipher_modes[i].mode; i++)
    cipher_bench_one (algo, &cipher_modes[i]);

  bench_print_footer (14);
}


void
cipher_bench (char **argv, int argc)
{
  int i, algo;

  bench_print_section ("cipher", "Cipher");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  algo = gcry_cipher_map_name (argv[i]);
	  if (algo)
	    _cipher_bench (algo);
	}
    }
  else
    {
      for (i = 1; i < 400; i++)
	if (!gcry_cipher_test_algo (i))
	  _cipher_bench (i);
    }
}


/*********************************************************** Hash benchmarks. */

struct bench_hash_mode
{
  const char *name;
  struct bench_ops *ops;

  int algo;
};


static int
bench_hash_init (struct bench_obj *obj)
{
  struct bench_hash_mode *mode = obj->priv;
  gcry_md_hd_t hd;
  int err;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;
  obj->num_measure_repetitions = num_measurement_repetitions;

  err = gcry_md_open (&hd, mode->algo, 0);
  if (err)
    {
      fprintf (stderr, PGM ": error opening hash `%s'\n",
	       gcry_md_algo_name (mode->algo));
      exit (1);
    }

  obj->priv = hd;

  return 0;
}

static void
bench_hash_free (struct bench_obj *obj)
{
  gcry_md_hd_t hd = obj->priv;

  gcry_md_close (hd);
}

static void
bench_hash_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  gcry_md_hd_t hd = obj->priv;

  gcry_md_reset (hd);
  gcry_md_write (hd, buf, buflen);
  gcry_md_final (hd);
}

static struct bench_ops hash_ops = {
  &bench_hash_init,
  &bench_hash_free,
  &bench_hash_do_bench
};


static struct bench_hash_mode hash_modes[] = {
  {"", &hash_ops},
  {0},
};


static void
hash_bench_one (int algo, struct bench_hash_mode *pmode)
{
  struct bench_hash_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;

  mode.algo = algo;

  if (mode.name[0] == '\0')
    bench_print_algo (-14, gcry_md_algo_name (algo));
  else
    bench_print_algo (14, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}

static void
_hash_bench (int algo)
{
  int i;

  for (i = 0; hash_modes[i].name; i++)
    hash_bench_one (algo, &hash_modes[i]);
}

void
hash_bench (char **argv, int argc)
{
  int i, algo;

  bench_print_section ("hash", "Hash");
  bench_print_header (14, "");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  algo = gcry_md_map_name (argv[i]);
	  if (algo)
	    _hash_bench (algo);
	}
    }
  else
    {
      for (i = 1; i < 400; i++)
	if (!gcry_md_test_algo (i))
	  _hash_bench (i);
    }

  bench_print_footer (14);
}


/************************************************************ MAC benchmarks. */

struct bench_mac_mode
{
  const char *name;
  struct bench_ops *ops;

  int algo;
};


static int
bench_mac_init (struct bench_obj *obj)
{
  struct bench_mac_mode *mode = obj->priv;
  gcry_mac_hd_t hd;
  int err;
  unsigned int keylen;
  void *key;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;
  obj->num_measure_repetitions = num_measurement_repetitions;

  keylen = gcry_mac_get_algo_keylen (mode->algo);
  if (keylen == 0)
    keylen = 32;
  key = malloc (keylen);
  if (!key)
    {
      fprintf (stderr, PGM ": couldn't allocate %d bytes\n", keylen);
      exit (1);
    }
  memset(key, 42, keylen);

  err = gcry_mac_open (&hd, mode->algo, 0, NULL);
  if (err)
    {
      fprintf (stderr, PGM ": error opening mac `%s'\n",
	       gcry_mac_algo_name (mode->algo));
      free (key);
      exit (1);
    }

  err = gcry_mac_setkey (hd, key, keylen);
  free (key);
  if (err)
    {
      fprintf (stderr, PGM ": error setting key for mac `%s'\n",
	       gcry_mac_algo_name (mode->algo));
      exit (1);
    }

  obj->priv = hd;

  return 0;
}

static void
bench_mac_free (struct bench_obj *obj)
{
  gcry_mac_hd_t hd = obj->priv;

  gcry_mac_close (hd);
}

static void
bench_mac_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  gcry_mac_hd_t hd = obj->priv;
  size_t bs;
  char b;

  gcry_mac_reset (hd);
  gcry_mac_write (hd, buf, buflen);
  bs = sizeof(b);
  gcry_mac_read (hd, &b, &bs);
}

static struct bench_ops mac_ops = {
  &bench_mac_init,
  &bench_mac_free,
  &bench_mac_do_bench
};


static struct bench_mac_mode mac_modes[] = {
  {"", &mac_ops},
  {0},
};


static void
mac_bench_one (int algo, struct bench_mac_mode *pmode)
{
  struct bench_mac_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;

  mode.algo = algo;

  if (mode.name[0] == '\0')
    bench_print_algo (-18, gcry_mac_algo_name (algo));
  else
    bench_print_algo (18, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}

static void
_mac_bench (int algo)
{
  int i;

  for (i = 0; mac_modes[i].name; i++)
    mac_bench_one (algo, &mac_modes[i]);
}

void
mac_bench (char **argv, int argc)
{
  int i, algo;

  bench_print_section ("mac", "MAC");
  bench_print_header (18, "");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  algo = gcry_mac_map_name (argv[i]);
	  if (algo)
	    _mac_bench (algo);
	}
    }
  else
    {
      for (i = 1; i < 500; i++)
	if (!gcry_mac_test_algo (i))
	  _mac_bench (i);
    }

  bench_print_footer (18);
}


/************************************************************** Main program. */

void
print_help (void)
{
  static const char *help_lines[] = {
    "usage: bench-slope [options] [hash|mac|cipher [algonames]]",
    "",
    " options:",
    "   --cpu-mhz <mhz>           Set CPU speed for calculating cycles",
    "                             per bytes results.",
    "   --disable-hwf <features>  Disable hardware acceleration feature(s)",
    "                             for benchmarking.",
    "   --repetitions <n>         Use N repetitions (default "
                                     STR2(NUM_MEASUREMENT_REPETITIONS) ")",
    "   --csv                     Use CSV output format",
    NULL
  };
  const char **line;

  for (line = help_lines; *line; line++)
    fprintf (stdout, "%s\n", *line);
}


/* Warm up CPU.  */
static void
warm_up_cpu (void)
{
  struct nsec_time start, end;

  get_nsec_time (&start);
  do
    {
      get_nsec_time (&end);
    }
  while (get_time_nsec_diff (&start, &end) < 1000.0 * 1000.0 * 1000.0);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  int debug = 0;

  if (argc)
    {
      argc--;
      argv++;
    }

  /* We skip this test if we are running under the test suite (no args
     and srcdir defined) and GCRYPT_NO_BENCHMARKS is set.  */
  if (!argc && getenv ("srcdir") && getenv ("GCRYPT_NO_BENCHMARKS"))
    exit (77);

  if (getenv ("GCRYPT_IN_REGRESSION_TEST"))
    {
      in_regression_test = 1;
      num_measurement_repetitions = 2;
    }
  else
    num_measurement_repetitions = NUM_MEASUREMENT_REPETITIONS;

  while (argc && last_argc != argc)
    {
      last_argc = argc;

      if (!strcmp (*argv, "--"))
	{
	  argc--;
	  argv++;
	  break;
	}
      else if (!strcmp (*argv, "--help"))
	{
	  print_help ();
	  exit (0);
	}
      else if (!strcmp (*argv, "--verbose"))
	{
	  verbose++;
	  argc--;
	  argv++;
	}
      else if (!strcmp (*argv, "--debug"))
	{
	  verbose += 2;
	  debug++;
	  argc--;
	  argv++;
	}
      else if (!strcmp (*argv, "--csv"))
	{
	  csv_mode = 1;
	  argc--;
	  argv++;
	}
      else if (!strcmp (*argv, "--disable-hwf"))
	{
	  argc--;
	  argv++;
	  if (argc)
	    {
	      if (gcry_control (GCRYCTL_DISABLE_HWF, *argv, NULL))
		fprintf (stderr,
			 PGM
			 ": unknown hardware feature `%s' - option ignored\n",
			 *argv);
	      argc--;
	      argv++;
	    }
	}
      else if (!strcmp (*argv, "--cpu-mhz"))
	{
	  argc--;
	  argv++;
	  if (argc)
	    {
	      cpu_ghz = atof (*argv);
	      cpu_ghz /= 1000;	/* Mhz => Ghz */

	      argc--;
	      argv++;
	    }
	}
      else if (!strcmp (*argv, "--repetitions"))
	{
	  argc--;
	  argv++;
	  if (argc)
	    {
	      num_measurement_repetitions = atof (*argv);
              if (num_measurement_repetitions < 2)
                {
                  fprintf (stderr,
                           PGM
                           ": value for --repetitions too small - using %d\n",
                           NUM_MEASUREMENT_REPETITIONS);
                  num_measurement_repetitions = NUM_MEASUREMENT_REPETITIONS;
                }
	      argc--;
	      argv++;
	    }
	}
    }

  gcry_control (GCRYCTL_SET_VERBOSITY, (int) verbose);

  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fprintf (stderr, PGM ": version mismatch; pgm=%s, library=%s\n",
	       GCRYPT_VERSION, gcry_check_version (NULL));
      exit (1);
    }

  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  if (in_regression_test)
    fputs ("Note: " PGM " running in quick regression test mode.\n", stdout);

  if (!argc)
    {
      warm_up_cpu ();
      hash_bench (NULL, 0);
      mac_bench (NULL, 0);
      cipher_bench (NULL, 0);
    }
  else if (!strcmp (*argv, "hash"))
    {
      argc--;
      argv++;

      warm_up_cpu ();
      hash_bench ((argc == 0) ? NULL : argv, argc);
    }
  else if (!strcmp (*argv, "mac"))
    {
      argc--;
      argv++;

      warm_up_cpu ();
      mac_bench ((argc == 0) ? NULL : argv, argc);
    }
  else if (!strcmp (*argv, "cipher"))
    {
      argc--;
      argv++;

      warm_up_cpu ();
      cipher_bench ((argc == 0) ? NULL : argv, argc);
    }
  else
    {
      fprintf (stderr, PGM ": unknown argument: %s\n", *argv);
      print_help ();
    }

  return 0;
}

#endif /* !NO_GET_NSEC_TIME */
