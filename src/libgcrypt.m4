dnl Autoconf macros for libgcrypt
dnl $id$

# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBGCRYPT([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libgcrypt, and define GCRYPT_CFLAGS and GCRYPT_LIBS
dnl
AC_DEFUN(AM_PATH_LIBGCRYPT,
[dnl
dnl Get the cflags and libraries from the libgcrypt-config script
dnl
AC_ARG_WITH(libgcrypt-prefix,
          [  --with-libgcrypt-prefix=PFX   Prefix where libgcrypt is installed (optional)],
          libgcrypt_config_prefix="$withval", libgcrypt_config_prefix="")
AC_ARG_ENABLE(libgcrypttest,
          [  --disable-libgcrypttest    Do not try to compile and run a test libgcrypt program],
          , enable_libgcrypttest=yes)

  if test x$libgcrypt_config_prefix != x ; then
     libgcrypt_config_args="$libgcrypt_config_args --prefix=$libgcrypt_config_prefix"
     if test x${LIBGCRYPT_CONFIG+set} != xset ; then
        LIBGCRYPT_CONFIG=$libgcrypt_config_prefix/bin/libgcrypt-config
     fi
  fi

  AC_PATH_PROG(LIBGCRYPT_CONFIG, libgcrypt-config, no)
  min_libgcrypt_version=ifelse([$1], ,1.1.0,$1)
  AC_MSG_CHECKING(for libgcrypt - version >= $min_libgcrypt_version)
  no_libgcrypt=""
  if test "$LIBGCRYPT_CONFIG" = "no" ; then
    no_libgcrypt=yes
  else
    LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --cflags`
    LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --libs`
    libgcrypt_config_version=`$LIBGCRYPT_CONFIG $libgcrypt_config_args --version`
    if test "x$enable_libgcrypttest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBGCRYPT_CFLAGS"
      LIBS="$LIBS $LIBGCRYPT_LIBS"
dnl
dnl Now check if the installed libgcrypt is sufficiently new. Also sanity
dnl checks the results of libgcrypt-config to some extent
dnl
      rm -f conf.libgcrypttest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

int
main ()
{
    system ("touch conf.libgcrypttest");

    if( strcmp( gcry_check_version(NULL), "$libgcrypt_config_version" ) )
    {
      printf("\n*** 'libgcrypt-config --version' returned %s, but LIBGCRYPT (%s)\n",
             "$libgcrypt_config_version", gcry_check_version(NULL) );
      printf("*** was found! If libgcrypt-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBGCRYPT. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If libgcrypt-config was wrong, set the environment variable LIBGCRYPT_CONFIG\n");
      printf("*** to point to the correct copy of libgcrypt-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(gcry_check_version(NULL), LIBGCRYPT_VERSION ) )
    {
      printf("\n*** LIBGCRYPT header file (version %s) does not match\n", LIBGCRYPT_VERSION);
      printf("*** library (version %s)\n", gcry_check_version(NULL) );
    }
    else
    {
      if ( gcry_check_version( "$min_libgcrypt_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBGCRYPT (%s) was found.\n",
                gcry_check_version(NULL) );
        printf("*** You need a version of LIBGCRYPT newer than %s. The latest version of\n",
               "$min_libgcrypt_version" );
        printf("*** LIBGCRYPT is always available from ftp://ftp.gnupg.org/pub/libgcrypt/gnupg.\n");
        printf("*** (It is distributed along with GnuPG).\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libgcrypt-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBGCRYPT, but you can also set the LIBGCRYPT_CONFIG environment to point to the\n");
        printf("*** correct copy of libgcrypt-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_libgcrypt=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_libgcrypt" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libgcrypttest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBGCRYPT_CONFIG" = "no" ; then
       echo "*** The libgcrypt-config script installed by LIBGCRYPT could not be found"
       echo "*** If LIBGCRYPT was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBGCRYPT_CONFIG environment variable to the"
       echo "*** full path to libgcrypt-config."
     else
       if test -f conf.libgcrypttest ; then
        :
       else
          echo "*** Could not run libgcrypt test program, checking why..."
          CFLAGS="$CFLAGS $LIBGCRYPT_CFLAGS"
          LIBS="$LIBS $LIBGCRYPT_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
],      [ return !!gcry_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBGCRYPT or finding the wrong"
          echo "*** version of LIBGCRYPT. If it is not finding LIBGCRYPT, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBGCRYPT was incorrectly installed"
          echo "*** or that you have moved LIBGCRYPT since it was installed. In the latter case, you"
          echo "*** may want to edit the libgcrypt-config script: $LIBGCRYPT_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBGCRYPT_CFLAGS=""
     LIBGCRYPT_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBGCRYPT_CFLAGS)
  AC_SUBST(LIBGCRYPT_LIBS)
  rm -f conf.libgcrypttest
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
