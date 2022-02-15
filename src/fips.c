/* fips.c - FIPS mode management
 * Copyright (C) 2008  Free Software Foundation, Inc.
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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#ifdef ENABLE_HMAC_BINARY_CHECK
# include <dlfcn.h>
# include <elf.h>
# include <limits.h>
# include <link.h>
#endif
#ifdef HAVE_SYSLOG
# include <syslog.h>
#endif /*HAVE_SYSLOG*/

/* The name of the file used to force libgcrypt into fips mode. */
#define FIPS_FORCE_FILE "/etc/gcrypt/fips_enabled"

#include "g10lib.h"
#include "cipher-proto.h"
#include "../random/random.h"

/* The states of the finite state machine used in fips mode.  */
enum module_states
  {
    /* POWEROFF cannot be represented.  */
    STATE_POWERON  = 0,
    STATE_INIT,
    STATE_SELFTEST,
    STATE_OPERATIONAL,
    STATE_ERROR,
    STATE_FATALERROR,
    STATE_SHUTDOWN
  };


/* Flag telling whether we are in fips mode.  It uses inverse logic so
   that fips mode is the default unless changed by the initialization
   code. To check whether fips mode is enabled, use the function
   fips_mode()! */
int _gcry_no_fips_mode_required;

/* This is the lock we use to protect the FSM.  */
GPGRT_LOCK_DEFINE (fsm_lock);

/* The current state of the FSM.  The whole state machinery is only
   used while in fips mode. Change this only while holding fsm_lock. */
static enum module_states current_state;





static void fips_new_state (enum module_states new_state);



/* Convert lowercase hex digits; assumes valid hex digits. */
#define loxtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): (*(p)-'a'+10))
#define loxtoi_2(p)   ((loxtoi_1(p) * 16) + loxtoi_1((p)+1))

/* Returns true if P points to a lowercase hex digit. */
#define loxdigit_p(p) !!strchr ("01234567890abcdef", *(p))



/*
 * Returns 1 if the FIPS mode is to be activated based on the
 * environment variable LIBGCRYPT_FORCE_FIPS_MODE, the file defined by
 * FIPS_FORCE_FILE, or /proc/sys/crypto/fips_enabled.
 * This function aborts on misconfigured filesystems.
 */
static int
check_fips_system_setting (void)
{
  /* Do we have the environment variable set?  */
  if (getenv ("LIBGCRYPT_FORCE_FIPS_MODE"))
    return 1;

  /* For testing the system it is useful to override the system
     provided detection of the FIPS mode and force FIPS mode using a
     file.  The filename is hardwired so that there won't be any
     confusion on whether /etc/gcrypt/ or /usr/local/etc/gcrypt/ is
     actually used.  The file itself may be empty.  */
  if ( !access (FIPS_FORCE_FILE, F_OK) )
    return 1;

  /* Checking based on /proc file properties.  */
  {
    static const char procfname[] = "/proc/sys/crypto/fips_enabled";
    FILE *fp;
    int saved_errno;

    fp = fopen (procfname, "r");
    if (fp)
      {
        char line[256];

        if (fgets (line, sizeof line, fp) && atoi (line))
          {
            /* System is in fips mode.  */
            fclose (fp);
            return 1;
          }
        fclose (fp);
      }
    else if ((saved_errno = errno) != ENOENT
             && saved_errno != EACCES
             && !access ("/proc/version", F_OK) )
      {
        /* Problem reading the fips file despite that we have the proc
           file system.  We better stop right away. */
        log_info ("FATAL: error reading `%s' in libgcrypt: %s\n",
                  procfname, strerror (saved_errno));
#ifdef HAVE_SYSLOG
        syslog (LOG_USER|LOG_ERR, "Libgcrypt error: "
                "reading `%s' failed: %s - abort",
                procfname, strerror (saved_errno));
#endif /*HAVE_SYSLOG*/
        abort ();
      }
  }

  return 0;
}

/*
 * Initial check if the FIPS mode should be activated on startup.
 * Called by the constructor at the initialization of the library.
 */
int
_gcry_fips_to_activate (void)
{
  return check_fips_system_setting ();
}


/* Check whether the OS is in FIPS mode and record that in a module
   local variable.  If FORCE is passed as true, fips mode will be
   enabled anyway. Note: This function is not thread-safe and should
   be called before any threads are created.  This function may only
   be called once.  */
void
_gcry_initialize_fips_mode (int force)
{
  static int done;
  gpg_error_t err;

  /* Make sure we are not accidentally called twice.  */
  if (done)
    {
      if ( fips_mode () )
        {
          fips_new_state (STATE_FATALERROR);
          fips_noreturn ();
        }
      /* If not in fips mode an assert is sufficient.  */
      gcry_assert (!done);
    }
  done = 1;

  /* If the calling application explicitly requested fipsmode, do so.  */
  if (force)
    {
      gcry_assert (!_gcry_no_fips_mode_required);
      goto leave;
    }

  /* If the system explicitly requested fipsmode, do so.  */
  if (check_fips_system_setting ())
    {
      gcry_assert (!_gcry_no_fips_mode_required);
      goto leave;
    }

  /* Fips not not requested, set flag.  */
  _gcry_no_fips_mode_required = 1;

 leave:
  if (!_gcry_no_fips_mode_required)
    {
      /* Yes, we are in FIPS mode.  */

      /* Intitialize the lock to protect the FSM.  */
      err = gpgrt_lock_init (&fsm_lock);
      if (err)
        {
          /* If that fails we can't do anything but abort the
             process. We need to use log_info so that the FSM won't
             get involved.  */
          log_info ("FATAL: failed to create the FSM lock in libgcrypt: %s\n",
                    gpg_strerror (err));
#ifdef HAVE_SYSLOG
          syslog (LOG_USER|LOG_ERR, "Libgcrypt error: "
                  "creating FSM lock failed: %s - abort",
                  gpg_strerror (err));
#endif /*HAVE_SYSLOG*/
          abort ();
        }

      /* Now get us into the INIT state.  */
      fips_new_state (STATE_INIT);
    }

  return;
}

static void
lock_fsm (void)
{
  gpg_error_t err;

  err = gpgrt_lock_lock (&fsm_lock);
  if (err)
    {
      log_info ("FATAL: failed to acquire the FSM lock in libgrypt: %s\n",
                gpg_strerror (err));
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_ERR, "Libgcrypt error: "
              "acquiring FSM lock failed: %s - abort",
              gpg_strerror (err));
#endif /*HAVE_SYSLOG*/
      abort ();
    }
}

static void
unlock_fsm (void)
{
  gpg_error_t err;

  err = gpgrt_lock_unlock (&fsm_lock);
  if (err)
    {
      log_info ("FATAL: failed to release the FSM lock in libgrypt: %s\n",
                gpg_strerror (err));
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_ERR, "Libgcrypt error: "
              "releasing FSM lock failed: %s - abort",
              gpg_strerror (err));
#endif /*HAVE_SYSLOG*/
      abort ();
    }
}


static const char *
state2str (enum module_states state)
{
  const char *s;

  switch (state)
    {
    case STATE_POWERON:     s = "Power-On"; break;
    case STATE_INIT:        s = "Init"; break;
    case STATE_SELFTEST:    s = "Self-Test"; break;
    case STATE_OPERATIONAL: s = "Operational"; break;
    case STATE_ERROR:       s = "Error"; break;
    case STATE_FATALERROR:  s = "Fatal-Error"; break;
    case STATE_SHUTDOWN:    s = "Shutdown"; break;
    default:                s = "?"; break;
    }
  return s;
}


/* Return true if the library is in the operational state.  */
int
_gcry_fips_is_operational (void)
{
  int result;

  if (!fips_mode ())
    result = 1;
  else
    {
      lock_fsm ();
      if (current_state == STATE_INIT)
        {
          /* If we are still in the INIT state, we need to run the
             selftests so that the FSM can eventually get into
             operational state.  Given that we would need a 2-phase
             initialization of libgcrypt, but that has traditionally
             not been enforced, we use this on demand self-test
             checking.  Note that Proper applications would do the
             application specific libgcrypt initialization between a
             gcry_check_version() and gcry_control
             (GCRYCTL_INITIALIZATION_FINISHED) where the latter will
             run the selftests.  The drawback of these on-demand
             self-tests are a small chance that self-tests are
             performed by several threads; that is no problem because
             our FSM make sure that we won't oversee any error. */
          unlock_fsm ();
          _gcry_fips_run_selftests (0);

          /* Release resources for random.  */
          _gcry_random_close_fds ();
          lock_fsm ();
        }

      result = (current_state == STATE_OPERATIONAL);
      unlock_fsm ();
    }
  return result;
}


/* This is test on whether the library is in the operational state.  In
   contrast to _gcry_fips_is_operational this function won't do a
   state transition on the fly.  */
int
_gcry_fips_test_operational (void)
{
  int result;

  if (!fips_mode ())
    result = 1;
  else
    {
      lock_fsm ();
      result = (current_state == STATE_OPERATIONAL);
      unlock_fsm ();
    }
  return result;
}

int
_gcry_fips_indicator_cipher (va_list arg_ptr)
{
  enum gcry_cipher_algos alg = va_arg (arg_ptr, enum gcry_cipher_algos);
  enum gcry_cipher_modes mode;

  switch (alg)
    {
    case GCRY_CIPHER_AES:
    case GCRY_CIPHER_AES192:
    case GCRY_CIPHER_AES256:
      mode = va_arg (arg_ptr, enum gcry_cipher_modes);
      switch (mode)
        {
        case GCRY_CIPHER_MODE_ECB:
        case GCRY_CIPHER_MODE_CBC:
        case GCRY_CIPHER_MODE_CFB:
        case GCRY_CIPHER_MODE_CFB8:
        case GCRY_CIPHER_MODE_OFB:
        case GCRY_CIPHER_MODE_CTR:
        case GCRY_CIPHER_MODE_CCM:
        case GCRY_CIPHER_MODE_GCM:
        case GCRY_CIPHER_MODE_XTS:
          return GPG_ERR_NO_ERROR;
        default:
          return GPG_ERR_NOT_SUPPORTED;
        }
    default:
      return GPG_ERR_NOT_SUPPORTED;
    }
}

int
_gcry_fips_indicator_kdf (va_list arg_ptr)
{
  enum gcry_kdf_algos alg = va_arg (arg_ptr, enum gcry_kdf_algos);

  switch (alg)
    {
    case GCRY_KDF_PBKDF2:
      return GPG_ERR_NO_ERROR;
    default:
      return GPG_ERR_NOT_SUPPORTED;
    }
}


/* This is a test on whether the library is in the error or
   operational state. */
int
_gcry_fips_test_error_or_operational (void)
{
  int result;

  if (!fips_mode ())
    result = 1;
  else
    {
      lock_fsm ();
      result = (current_state == STATE_OPERATIONAL
                || current_state == STATE_ERROR);
      unlock_fsm ();
    }
  return result;
}


static void
reporter (const char *domain, int algo, const char *what, const char *errtxt)
{
  if (!errtxt && !_gcry_log_verbosity (2))
    return;

  log_info ("libgcrypt selftest: %s %s%s (%d): %s%s%s%s\n",
            !strcmp (domain, "hmac")? "digest":domain,
            !strcmp (domain, "hmac")? "HMAC-":"",
            !strcmp (domain, "cipher")? _gcry_cipher_algo_name (algo) :
            !strcmp (domain, "digest")? _gcry_md_algo_name (algo) :
            !strcmp (domain, "hmac")?   _gcry_md_algo_name (algo) :
            !strcmp (domain, "pubkey")? _gcry_pk_algo_name (algo) : "",
            algo, errtxt? errtxt:"Okay",
            what?" (":"", what? what:"", what?")":"");
}

/* Run self-tests for all required cipher algorithms.  Return 0 on
   success. */
static int
run_cipher_selftests (int extended)
{
  static int algos[] =
    {
      GCRY_CIPHER_AES128,
      GCRY_CIPHER_AES192,
      GCRY_CIPHER_AES256,
      0
    };
  int idx;
  gpg_error_t err;
  int anyerr = 0;

  for (idx=0; algos[idx]; idx++)
    {
      err = _gcry_cipher_selftest (algos[idx], extended, reporter);
      reporter ("cipher", algos[idx], NULL,
                err? gpg_strerror (err):NULL);
      if (err)
        anyerr = 1;
    }
  return anyerr;
}


/* Run self-tests for all required hash algorithms.  Return 0 on
   success. */
static int
run_digest_selftests (int extended)
{
  static int algos[] =
    {
      GCRY_MD_SHA1,
      GCRY_MD_SHA224,
#ifndef ENABLE_HMAC_BINARY_CHECK
      GCRY_MD_SHA256,
#endif
      GCRY_MD_SHA384,
      GCRY_MD_SHA512,
      0
    };
  int idx;
  gpg_error_t err;
  int anyerr = 0;

  for (idx=0; algos[idx]; idx++)
    {
      err = _gcry_md_selftest (algos[idx], extended, reporter);
      reporter ("digest", algos[idx], NULL,
                err? gpg_strerror (err):NULL);
      if (err)
        anyerr = 1;
    }
  return anyerr;
}


/* Run self-tests for MAC algorithms.  Return 0 on success. */
static int
run_mac_selftests (int extended)
{
  static int algos[] =
    {
      GCRY_MAC_HMAC_SHA1,
      GCRY_MAC_HMAC_SHA224,
#ifndef ENABLE_HMAC_BINARY_CHECK
      GCRY_MAC_HMAC_SHA256,
#endif
      GCRY_MAC_HMAC_SHA384,
      GCRY_MAC_HMAC_SHA512,
      GCRY_MAC_HMAC_SHA3_224,
      GCRY_MAC_HMAC_SHA3_256,
      GCRY_MAC_HMAC_SHA3_384,
      GCRY_MAC_HMAC_SHA3_512,
      GCRY_MAC_CMAC_AES,
      0
    };
  int idx;
  gpg_error_t err;
  int anyerr = 0;

  for (idx=0; algos[idx]; idx++)
    {
      err = _gcry_mac_selftest (algos[idx], extended, reporter);
      reporter ("mac", algos[idx], NULL,
                err? gpg_strerror (err):NULL);
      if (err)
        anyerr = 1;
    }
  return anyerr;
}

/* Run self-tests for all KDF algorithms.  Return 0 on success. */
static int
run_kdf_selftests (int extended)
{
  static int algos[] =
    {
      GCRY_KDF_PBKDF2,
      0
    };
  int idx;
  gpg_error_t err;
  int anyerr = 0;

  for (idx=0; algos[idx]; idx++)
    {
      err = _gcry_kdf_selftest (algos[idx], extended, reporter);
      reporter ("kdf", algos[idx], NULL, err? gpg_strerror (err):NULL);
      if (err)
        anyerr = 1;
    }
  return anyerr;
}


/* Run self-tests for all required public key algorithms.  Return 0 on
   success. */
static int
run_pubkey_selftests (int extended)
{
  static int algos[] =
    {
      GCRY_PK_RSA,
      GCRY_PK_ECC,
      0
    };
  int idx;
  gpg_error_t err;
  int anyerr = 0;

  for (idx=0; algos[idx]; idx++)
    {
      err = _gcry_pk_selftest (algos[idx], extended, reporter);
      reporter ("pubkey", algos[idx], NULL,
                err? gpg_strerror (err):NULL);
      if (err)
        anyerr = 1;
    }
  return anyerr;
}


/* Run self-tests for the random number generator.  Returns 0 on
   success. */
static int
run_random_selftests (void)
{
  gpg_error_t err;

  err = _gcry_random_selftest (reporter);
  reporter ("random", 0, NULL, err? gpg_strerror (err):NULL);

  return !!err;
}

#ifdef ENABLE_HMAC_BINARY_CHECK
# ifndef KEY_FOR_BINARY_CHECK
# define KEY_FOR_BINARY_CHECK "What am I, a doctor or a moonshuttle conductor?"
# endif
#define HMAC_LEN 32

static const unsigned char __attribute__ ((section (".rodata1")))
hmac_for_the_implementation[HMAC_LEN];

/*
 * In the ELF file opened as FP, determine the offset of the given
 * virtual address ADDR and return it in OFFSET.  Rewinds FP to the
 * beginning on success.
 */
static gpg_error_t
get_file_offset (FILE *fp, unsigned long addr, unsigned long *offset)
{
  ElfW (Ehdr) ehdr;
  ElfW (Phdr) phdr;
  uint16_t e_phidx;

  /* Read the ELF header */
  if (fseek (fp, 0, SEEK_SET) != 0)
    return gpg_error_from_syserror ();
  if (fread (&ehdr, sizeof (ehdr), 1, fp) != 1)
    return gpg_error_from_syserror ();

  /* The program header entry size should match the size of the phdr struct */
  if (ehdr.e_phentsize != sizeof (phdr))
    return gpg_error (GPG_ERR_INV_OBJ);
  if (ehdr.e_phoff == 0)
    return gpg_error (GPG_ERR_INV_OBJ);

  /* Jump to the first program header */
  if (fseek (fp, ehdr.e_phoff, SEEK_SET) != 0)
    return gpg_error_from_syserror ();

  /* Iterate over the program headers, compare their virtual addresses
     with the address we are looking for, and if the program header
     matches, calculate the offset of the given ADDR in the file using
     the program header's p_offset field.  */
  for (e_phidx = 0; e_phidx < ehdr.e_phnum; e_phidx++)
    {
      if (fread (&phdr, sizeof (phdr), 1, fp) != 1)
        return gpg_error_from_syserror ();
      if (phdr.p_type == PT_LOAD
          && phdr.p_vaddr <= addr && addr < phdr.p_vaddr + phdr.p_memsz)
        {
          /* Found segment, compute the offset of ADDR in the file */
          *offset = phdr.p_offset + (addr - phdr.p_vaddr);

          if (fseek (fp, 0, SEEK_SET) != 0)
            return gpg_error_from_syserror ();
          return 0;
        }
    }

  /* Segment not found in the file */
  return gpg_error (GPG_ERR_INV_OBJ);
}

static gpg_error_t
hmac256_check (const char *filename, const char *key, struct link_map *lm)
{
  gpg_error_t err;
  FILE *fp;
  gcry_md_hd_t hd;
  size_t buffer_size, nread;
  char *buffer;
  unsigned long addr;
  unsigned long offset = 0;
  unsigned long pos = 0;

  addr = (unsigned long)hmac_for_the_implementation - lm->l_addr;
  fp = fopen (filename, "rb");
  if (!fp)
    return gpg_error (GPG_ERR_INV_OBJ);

  err = get_file_offset (fp, addr, &offset);
  if (err)
    {
      fclose (fp);
      return err;
    }

  err = _gcry_md_open (&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
  if (err)
    {
      fclose (fp);
      return err;
    }

  err = _gcry_md_setkey (hd, key, strlen (key));
  if (err)
    {
      fclose (fp);
      _gcry_md_close (hd);
      return err;
    }

  buffer_size = 32768;
  buffer = xtrymalloc (buffer_size + HMAC_LEN);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      fclose (fp);
      _gcry_md_close (hd);
      return err;
    }

  nread = fread (buffer, 1, HMAC_LEN, fp);
  pos += nread;
  if (nread < HMAC_LEN)
    {
      xfree (buffer);
      fclose (fp);
      _gcry_md_close (hd);
      return gpg_error (GPG_ERR_TOO_SHORT);
    }

  while (1)
    {
      nread = fread (buffer+HMAC_LEN, 1, buffer_size, fp);
      if (nread < buffer_size)
        {
          if (pos - HMAC_LEN <= offset && offset <= pos + nread)
            memset (buffer + HMAC_LEN + offset - pos, 0, HMAC_LEN);
          _gcry_md_write (hd, buffer, nread+HMAC_LEN);
          break;
        }

      if (pos - HMAC_LEN <= offset && offset <= pos + nread)
        memset (buffer + HMAC_LEN + offset - pos, 0, HMAC_LEN);
      _gcry_md_write (hd, buffer, nread);
      memcpy (buffer, buffer+buffer_size, HMAC_LEN);
      pos += nread;
    }

  if (ferror (fp))
    err = gpg_error (GPG_ERR_INV_HANDLE);
  else
    {
      unsigned char *digest;

      digest = _gcry_md_read (hd, 0);
      if (!memcmp (digest, hmac_for_the_implementation, HMAC_LEN))
        /* Success.  */
        err = 0;
      else
        err = gpg_error (GPG_ERR_CHECKSUM);
    }

  _gcry_md_close (hd);
  xfree (buffer);
  fclose (fp);

  return err;
}

/* Run an integrity check on the binary.  Returns 0 on success.  */
static int
check_binary_integrity (void)
{
  gpg_error_t err;
  Dl_info info;
  const char *key = KEY_FOR_BINARY_CHECK;
  void *extra_info;

  if (!dladdr1 (hmac_for_the_implementation, &info, &extra_info,
                RTLD_DL_LINKMAP))
    err = gpg_error_from_syserror ();
  else
    err = hmac256_check (info.dli_fname, key, extra_info);

  reporter ("binary", 0, NULL, err? gpg_strerror (err):NULL);
#ifdef HAVE_SYSLOG
  if (err)
    syslog (LOG_USER|LOG_ERR, "Libgcrypt error: "
            "integrity check failed: %s",
            gpg_strerror (err));
#endif /*HAVE_SYSLOG*/
  return !!err;
}


/* Run self-tests for HMAC-SHA256 algorithm before verifying library integrity.
 * Return 0 on success. */
static int
run_hmac_sha256_selftests (int extended)
{
  gpg_error_t err;
  int anyerr = 0;

  err = _gcry_md_selftest (GCRY_MD_SHA256, extended, reporter);
  reporter ("digest", GCRY_MD_SHA256, NULL,
            err? gpg_strerror (err):NULL);
  if (err)
    anyerr = 1;

  err = _gcry_mac_selftest (GCRY_MAC_HMAC_SHA256, extended, reporter);
  reporter ("mac", GCRY_MAC_HMAC_SHA256, NULL,
            err? gpg_strerror (err):NULL);
  if (err)
    anyerr = 1;

  return anyerr;
}
#endif


/* Run the self-tests.  If EXTENDED is true, extended versions of the
   selftest are run, that is more tests than required by FIPS.  */
gpg_err_code_t
_gcry_fips_run_selftests (int extended)
{
  enum module_states result = STATE_ERROR;
  gcry_err_code_t ec = GPG_ERR_SELFTEST_FAILED;

  if (fips_mode ())
    fips_new_state (STATE_SELFTEST);

#ifdef ENABLE_HMAC_BINARY_CHECK
  if (run_hmac_sha256_selftests (extended))
    goto leave;

  if (fips_mode ())
    {
      /* Now check the integrity of the binary.  We do this this after
         having checked the HMAC code.  */
      if (check_binary_integrity ())
        goto leave;
    }
#endif

  if (run_cipher_selftests (extended))
    goto leave;

  if (run_digest_selftests (extended))
    goto leave;

  if (run_mac_selftests (extended))
    goto leave;

  if (run_kdf_selftests (extended))
    goto leave;

  /* Run random tests before the pubkey tests because the latter
     require random.  */
  if (run_random_selftests ())
    goto leave;

  if (run_pubkey_selftests (extended))
    goto leave;

  /* All selftests passed.  */
  result = STATE_OPERATIONAL;
  ec = 0;

 leave:
  if (fips_mode ())
    fips_new_state (result);

  return ec;
}


/* This function is used to tell the FSM about errors in the library.
   The FSM will be put into an error state.  This function should not
   be called directly but by one of the macros

     fips_signal_error (description)
     fips_signal_fatal_error (description)

   where DESCRIPTION is a string describing the error. */
void
_gcry_fips_signal_error (const char *srcfile, int srcline, const char *srcfunc,
                         int is_fatal, const char *description)
{
  if (!fips_mode ())
    return;  /* Not required.  */

  /* Set new state before printing an error.  */
  fips_new_state (is_fatal? STATE_FATALERROR : STATE_ERROR);

  /* Print error.  */
  log_info ("%serror in libgcrypt, file %s, line %d%s%s: %s\n",
            is_fatal? "fatal ":"",
            srcfile, srcline,
            srcfunc? ", function ":"", srcfunc? srcfunc:"",
            description? description : "no description available");
#ifdef HAVE_SYSLOG
  syslog (LOG_USER|LOG_ERR, "Libgcrypt error: "
          "%serror in file %s, line %d%s%s: %s",
          is_fatal? "fatal ":"",
          srcfile, srcline,
          srcfunc? ", function ":"", srcfunc? srcfunc:"",
          description? description : "no description available");
#endif /*HAVE_SYSLOG*/
}


/* Perform a state transition to NEW_STATE.  If this is an invalid
   transition, the module will go into a fatal error state. */
static void
fips_new_state (enum module_states new_state)
{
  int ok = 0;
  enum module_states last_state;

  lock_fsm ();

  last_state = current_state;
  switch (current_state)
    {
    case STATE_POWERON:
      if (new_state == STATE_INIT
          || new_state == STATE_ERROR
          || new_state == STATE_FATALERROR)
        ok = 1;
      break;

    case STATE_INIT:
      if (new_state == STATE_SELFTEST
          || new_state == STATE_ERROR
          || new_state == STATE_FATALERROR)
        ok = 1;
      break;

    case STATE_SELFTEST:
      if (new_state == STATE_OPERATIONAL
          || new_state == STATE_ERROR
          || new_state == STATE_FATALERROR)
        ok = 1;
      break;

    case STATE_OPERATIONAL:
      if (new_state == STATE_SHUTDOWN
          || new_state == STATE_SELFTEST
          || new_state == STATE_ERROR
          || new_state == STATE_FATALERROR)
        ok = 1;
      break;

    case STATE_ERROR:
      if (new_state == STATE_SHUTDOWN
          || new_state == STATE_ERROR
          || new_state == STATE_FATALERROR
          || new_state == STATE_SELFTEST)
        ok = 1;
      break;

    case STATE_FATALERROR:
      if (new_state == STATE_SHUTDOWN )
        ok = 1;
      break;

    case STATE_SHUTDOWN:
      /* We won't see any transition *from* Shutdown because the only
         allowed new state is Power-Off and that one can't be
         represented.  */
      break;

    }

  if (ok)
    {
      current_state = new_state;
    }

  unlock_fsm ();

  if (!ok || _gcry_log_verbosity (2))
    log_info ("libgcrypt state transition %s => %s %s\n",
              state2str (last_state), state2str (new_state),
              ok? "granted":"denied");

  if (!ok)
    {
      /* Invalid state transition.  Halting library. */
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_ERR,
              "Libgcrypt error: invalid state transition %s => %s",
              state2str (last_state), state2str (new_state));
#endif /*HAVE_SYSLOG*/
      fips_noreturn ();
    }
  else if (new_state == STATE_ERROR || new_state == STATE_FATALERROR)
    {
#ifdef HAVE_SYSLOG
      syslog (LOG_USER|LOG_WARNING,
              "Libgcrypt notice: state transition %s => %s",
              state2str (last_state), state2str (new_state));
#endif /*HAVE_SYSLOG*/
    }
}




/* This function should be called to ensure that the execution shall
   not continue. */
void
_gcry_fips_noreturn (void)
{
#ifdef HAVE_SYSLOG
  syslog (LOG_USER|LOG_ERR, "Libgcrypt terminated the application");
#endif /*HAVE_SYSLOG*/
  fflush (NULL);
  abort ();
  /*NOTREACHED*/
}
