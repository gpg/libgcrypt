dnl Autoconf macros for libgcrypt

# Configure paths for GCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-08

dnl AM_PATH_GCRYPT([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for gcrypt, and define GCRYPT_CFLAGS and GCRYPT_LIBS
dnl
AC_DEFUN(AM_PATH_GCRYPT,
[dnl
dnl Get the cflags and libraries from the gcrypt-config script
dnl
AC_ARG_WITH(gcrypt-prefix,
          [  --with-gcrypt-prefix=PFX   Prefix where gcrypt is installed (optional)],
          gcrypt_config_prefix="$withval", gcrypt_config_prefix="")
AC_ARG_ENABLE(gcrypttest,
          [  --disable-gcrypttest    Do not try to compile and run a test gcrypt program],
          , enable_gcrypttest=yes)

  if test x$gcrypt_config_prefix != x ; then
     gcrypt_config_args="$gcrypt_config_args --prefix=$gcrypt_config_prefix"
     if test x${GCRYPT_CONFIG+set} != xset ; then
        GCRYPT_CONFIG=$gcrypt_config_prefix/bin/gcrypt-config
     fi
  fi

  AC_PATH_PROG(GCRYPT_CONFIG, gcrypt-config, no)
  min_gcrypt_version=ifelse([$1], ,1.1.0,$1)
  AC_MSG_CHECKING(for gcrypt - version >= $min_gcrypt_version)
  no_gcrypt=""
  if test "$GCRYPT_CONFIG" = "no" ; then
    no_gcrypt=yes
  else
    GCRYPT_CFLAGS=`$GCRYPT_CONFIG $gcrypt_config_args --cflags`
    GCRYPT_LIBS=`$GCRYPT_CONFIG $gcrypt_config_args --libs`
    gcrypt_config_major_version=`$GCRYPT_CONFIG $gcrypt_config_args --version | \
           sed 's/.* \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    gcrypt_config_minor_version=`$GCRYPT_CONFIG $gcrypt_config_args --version | \
           sed 's/.* \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    gcrypt_config_micro_version=`$GCRYPT_CONFIG $gcrypt_config_args --version | \
           sed 's/.* \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
    if test "x$enable_gcrypttest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $GCRYPT_CFLAGS"
      LIBS="$LIBS $GCRYPT_LIBS"
dnl
dnl Now check if the installed gcrypt is sufficiently new. Also sanity
dnl checks the results of gcrypt-config to some extent
dnl
      rm -f conf.gcrypttest
      AC_TRY_RUN([
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main ()
{
    int major, minor, micro;
    unsigned int major_gcrypt, minor_gcrypt, micro_gcrypt, patlvl_gcrypt;
    char *tmp_version;
    char ver_string[20];

    system ("touch conf.gcrypttest");

    /* HP/UX 9 (%@#!) writes to sscanf strings */
    tmp_version = strdup("$min_gcrypt_version");
    if( !tmp_version )
        exit(1);
    if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
       printf("%s, bad version string\n", "$min_gcrypt_version");
       exit(1);
    }

    sprintf( ver_string, "%lX", gcrypt_version() );
    if ( sscanf(ver_string, "%1x%2x%1x%2x",
                     &major_gcrypt, &minor_gcrypt, &patlvl_gcrypt, &micro_gcrypt) != 4) {
       printf("%s, gcrypt returned bad version string\n", ver_string );
       exit(1);
    }

    if ((major_gcrypt != $gcrypt_config_major_version) ||
        (minor_gcrypt != $gcrypt_config_minor_version) ||
        (micro_gcrypt != $gcrypt_config_micro_version))
    {
      printf("\n*** 'gcrypt-config --version' returned %d.%d.%d, but GCRYPT (%u.%u.%u)\n",
             $gcrypt_config_major_version, $gcrypt_config_minor_version, $gcrypt_config_micro_version,
             major_gcrypt, minor_gcrypt, micro_gcrypt);
      printf("*** was found! If gcrypt-config was correct, then it is best\n");
      printf("*** to remove the old version of GCRYPT. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If gcrypt-config was wrong, set the environment variable GCRYPT_CONFIG\n");
      printf("*** to point to the correct copy of gcrypt-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( gcrypt_version() != GCRYPT_VERSION )
    {
      printf("*** GCRYPT header file (version %lx) does not match\n", GCRYPT_VERSION);
      printf("*** library (version %lx)\n", gcrypt_version() );
    }
    else
    {
      if ((major_gcrypt > major) ||
         ((major_gcrypt == major) && (minor_gcrypt > minor)) ||
         ((major_gcrypt == major) && (minor_gcrypt == minor) && (micro_gcrypt >= micro)))
      {
        return 0;
      }
     else
      {
        printf("\n*** An old version of GCRYPT (%u.%u.%u) was found.\n",
               major_gcrypt, minor_gcrypt, micro_gcrypt);
        printf("*** You need a version of GCRYPT newer than %d.%d.%d. The latest version of\n",
               major, minor, micro);
        printf("*** GCRYPT is always available from ftp://ftp.gnupg.org/pub/gcrypt/gnupg.\n");
        printf("*** (It comes along with GnuPG).\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the gcrypt-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of GCRYPT, but you can also set the GCRYPT_CONFIG environment to point to the\n");
        printf("*** correct copy of gcrypt-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_gcrypt=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_gcrypt" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     AC_MSG_RESULT(no)
     if test "$GCRYPT_CONFIG" = "no" ; then
       echo "*** The gcrypt-config script installed by GCRYPT could not be found"
       echo "*** If GCRYPT was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the GCRYPT_CONFIG environment variable to the"
       echo "*** full path to gcrypt-config."
     else
       if test -f conf.gcrypttest ; then
        :
       else
          echo "*** Could not run gcrypt test program, checking why..."
          CFLAGS="$CFLAGS $GCRYPT_CFLAGS"
          LIBS="$LIBS $GCRYPT_LIBS"
          AC_TRY_LINK([
#include <gcrypt.h>
#include <stdio.h>
],      [ return !!gcrypt_version(); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding GCRYPT or finding the wrong"
          echo "*** version of GCRYPT. If it is not finding GCRYPT, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means GCRYPT was incorrectly installed"
          echo "*** or that you have moved GCRYPT since it was installed. In the latter case, you"
          echo "*** may want to edit the gcrypt-config script: $GCRYPT_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     GCRYPT_CFLAGS=""
     GCRYPT_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GCRYPT_CFLAGS)
  AC_SUBST(GCRYPT_LIBS)
  rm -f conf.gcrypttest
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
