/* benchmark.c - for libgcrypt
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/times.h>
#include <gcrypt.h>

#define PGM "benchmark"
#define BUG() do {fprintf ( stderr, "Ooops at %s:%d\n", __FILE__ , __LINE__ );\
		  exit(2);} while(0)


/* Helper for the start and stop timer. */
static clock_t started_at, stopped_at;


static void
start_timer (void)
{
  struct tms tmp;

  times (&tmp);
  started_at = stopped_at = tmp.tms_utime;
}

static void
stop_timer (void)
{
  struct tms tmp;

  times (&tmp);
  stopped_at = tmp.tms_utime;
}

static const char *
elapsed_time (void)
{
  static char buf[50];

  sprintf (buf, "%5.0fms",
           (((double) (stopped_at - started_at))/CLOCKS_PER_SEC)*10000000);
  return buf;
}


static void
random_bench (void)
{
  char buf[128];
  int i;

  printf ("%-10s", "random");

  start_timer ();
  for (i=0; i < 100; i++)
    gcry_randomize (buf, sizeof buf, GCRY_STRONG_RANDOM);
  stop_timer ();
  printf (" %s", elapsed_time ());

  start_timer ();
  for (i=0; i < 100; i++)
    gcry_randomize (buf, 8, GCRY_STRONG_RANDOM);
  stop_timer ();
  printf (" %s", elapsed_time ());

  putchar ('\n');
}



static void
md_bench ( const char *algoname )
{
  int algo = gcry_md_map_name (algoname);
  GcryMDHd hd;
  int i;
  char buf[1000];

  if (!algo)
    {
      fprintf (stderr, PGM ": invalid hash algorithm `%s'/n", algoname);
      exit (1);
    }
  
  hd = gcry_md_open (algo, 0);
  if (!hd)
    {
      fprintf (stderr, PGM ": error opeing hash algorithm `%s'/n", algoname);
      exit (1);
    }

  for (i=0; i < sizeof buf; i++)
    buf[i] = i;

  printf ("%-10s", gcry_md_algo_name (algo));

  start_timer ();
  for (i=0; i < 1000; i++)
    gcry_md_write (hd, buf, sizeof buf);
  gcry_md_final (hd);
  stop_timer ();
  printf (" %s", elapsed_time ());

  gcry_md_reset (hd);
  start_timer ();
  for (i=0; i < 10000; i++)
    gcry_md_write (hd, buf, sizeof buf/10);
  gcry_md_final (hd);
  stop_timer ();
  printf (" %s", elapsed_time ());

  gcry_md_reset (hd);
  start_timer ();
  for (i=0; i < 1000000; i++)
    gcry_md_write (hd, "", 1);
  gcry_md_final (hd);
  stop_timer ();
  printf (" %s", elapsed_time ());

  gcry_md_close (hd);
  putchar ('\n');
}

static void
cipher_bench ( const char *algoname )
{
  static int header_printed;
  int algo = gcry_cipher_map_name (algoname);
  GcryCipherHd hd;
  int err, i;
  int keylen, blklen;
  char key[128];
  char outbuf[1000], buf[1000];
  size_t buflen;
  static struct { int mode; const char *name; int blocked; } modes[] = {
    { GCRY_CIPHER_MODE_ECB, "ECB", 1 },
    { GCRY_CIPHER_MODE_CBC, "CBC", 1 },
    { GCRY_CIPHER_MODE_CFB, "CFB", 0 },
    { GCRY_CIPHER_MODE_STREAM, "STREAM", 0 },
    {0}
  };
  int modeidx;

  if (!header_printed)
    {
      printf ("%-10s", "Algo");
      for (modeidx=0; modes[modeidx].mode; modeidx++)
        printf (" %-15s", modes[modeidx].name );
      putchar ('\n');
      printf ( "----------");
      for (modeidx=0; modes[modeidx].mode; modeidx++)
        printf (" ---------------" );
      putchar ('\n');
      header_printed = 1;
    }

  if (!algo)
    {
      fprintf (stderr, PGM ": invalid cipher algorithm `%s'\n", algoname);
      exit (1);
    }

  keylen = gcry_cipher_get_algo_keylen (algo);
  if ( keylen > sizeof key )
    {
        fprintf (stderr, PGM ": algo %d, keylength problem (%d)\n",
                 algo, keylen );
        exit (1);
    }
  for (i=0; i < keylen; i++)
    key[i] = i + (clock () & 0xff);

  blklen = gcry_cipher_get_algo_blklen (algo);

  printf ("%-10s", gcry_cipher_algo_name (algo));
  fflush (stdout);

  for (modeidx=0; modes[modeidx].mode; modeidx++)
    {
      if ((blklen > 1 && modes[modeidx].mode == GCRY_CIPHER_MODE_STREAM)
          | (blklen == 1 && modes[modeidx].mode != GCRY_CIPHER_MODE_STREAM))
        {
          printf ("                " );
          continue;
        }

      for (i=0; i < sizeof buf; i++)
        buf[i] = i;

      hd = gcry_cipher_open (algo, modes[modeidx].mode, 0);
      if (!hd)
        {
          fprintf (stderr, PGM ": error opening cipher `%s'\n", algoname);
          exit (1);
        }
      
      if (gcry_cipher_setkey (hd, key, keylen))
        { 
          fprintf (stderr, "gcry_cipher_setkey failed: %s\n",
                   gcry_strerror (-1) );
          gcry_cipher_close (hd);
          exit (1);
        }

      buflen = sizeof buf;
      if (modes[modeidx].blocked)
        buflen = (buflen / blklen) * blklen;

      start_timer ();
      for (i=err=0; !err && i < 1000; i++)
        err = gcry_cipher_encrypt ( hd, outbuf, buflen, buf, buflen);
      stop_timer ();
      printf (" %s", elapsed_time ());
      fflush (stdout);
      gcry_cipher_close (hd);
      if (err)
        { 
          fprintf (stderr, "gcry_cipher_encrypt failed: %s\n",
                   gcry_strerror (err) );
          exit (1);
        }

      hd = gcry_cipher_open (algo, modes[modeidx].mode, 0);
      if (!hd)
        {
          fprintf (stderr, PGM ": error opening cipher `%s'/n", algoname);
          exit (1);
        }
      
      if (gcry_cipher_setkey (hd, key, keylen))
        { 
          fprintf (stderr, "gcry_cipher_setkey failed: %s\n",
                   gcry_strerror (-1) );
          gcry_cipher_close (hd);
          exit (1);
        }

      start_timer ();
      for (i=err=0; !err && i < 1000; i++)
        err = gcry_cipher_decrypt ( hd, outbuf, buflen,  buf, buflen);
      stop_timer ();
      printf (" %s", elapsed_time ());
      fflush (stdout);
      gcry_cipher_close (hd);
      if (err)
        { 
          fprintf (stderr, "gcry_cipher_decrypt failed: %s\n",
                   gcry_strerror (err) );
          exit (1);
        }
    }

  putchar ('\n');
}

int
main( int argc, char **argv )
{
  if (argc < 2 )
    {
      fprintf (stderr, "usage: benchmark md|cipher|random [algonames]\n");
      return 1;
    }
  argc--; argv++;
  
  if ( !strcmp (*argv, "random"))
    {
      random_bench ();
    }
  else if ( !strcmp (*argv, "md"))
    {
      for (argc--, argv++; argc; argc--, argv++)
        md_bench ( *argv );
    }
  else if ( !strcmp (*argv, "cipher"))
    {
      for (argc--, argv++; argc; argc--, argv++)
        cipher_bench ( *argv );
    }
  else
    {
      fprintf (stderr, PGM ": bad arguments\n");
      return 1;
    }
  
  return 0;
}


