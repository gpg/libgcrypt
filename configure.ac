# Configure.ac script for Libgcrypt
# Copyright (C) 1998, 1999, 2000, 2001,
#               2002, 2003 Free Software Foundation, Inc.
#
# This file is part of Libgcrypt.
#
# Libgcrypt is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser general Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Libgcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
#
# (Process this file with autoconf to produce a configure script.)
AC_REVISION($Revision$)dnl

AC_PREREQ(2.52)
# Version number: Remember to change it immediately *after* a release but
# remove a "-cvs" prefix right *before* a release and append it soon later.
AC_INIT(libgcrypt, 1.1.13-cvs, bug-libgcrypt@gnupg.org)
# LT Version numbers, remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
LIBGCRYPT_LT_CURRENT=6
LIBGCRYPT_LT_AGE=5
LIBGCRYPT_LT_REVISION=1
#-----------------------

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR([src/gcrypt.h])
AC_CONFIG_AUX_DIR(scripts)
AC_CANONICAL_TARGET()
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_CONFIG_HEADER(config.h)

AH_TOP([
/* need this, because some autoconf tests rely on this (e.g. stpcpy)
 * and it should be used for new programs  */
#define _GNU_SOURCE  1
])


AH_BOTTOM([
#include "gcrypt-defs.h"
#define _GCRYPT_IN_LIBGCRYPT 1
])

AH_VERBATIM([_REENTRANT],
[/* To allow the use of Libgcrypt in multithreaded programs we have to use
    special features from the library. */
#ifndef _REENTRANT
# define _REENTRANT 1
#endif])



AC_SUBST(LIBGCRYPT_LT_CURRENT)
AC_SUBST(LIBGCRYPT_LT_AGE)
AC_SUBST(LIBGCRYPT_LT_REVISION)
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])

AC_PROG_AWK

dnl Definitions for symmetric ciphers.
available_ciphers="arcfour blowfish cast5 des aes twofish serpent"
enabled_ciphers=""

dnl Definitions for public-key ciphers.
available_pubkey_ciphers="dsa elgamal rsa"
enabled_pubkey_ciphers=""

dnl Definitions for message digests.
available_digests="crc md4 md5 rmd160 sha1 sha256"
enabled_digests=""

AC_CHECK_SIZEOF(unsigned short, 2)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned long, 4)
AC_CHECK_SIZEOF(unsigned long long, 0)

if test "$ac_cv_sizeof_unsigned_short" = "0" \
   || test "$ac_cv_sizeof_unsigned_int" = "0" \
   || test "$ac_cv_sizeof_unsigned_long" = "0"; then
    AC_MSG_WARN([Hmmm, something is wrong with the sizes - using defaults]);
fi

dnl Do we have any 64-bit data types?
if test "$ac_cv_sizeof_unsigned_int" != "8" \
   && test "$ac_cv_sizeof_unsigned_long" != "8" \
   && test "$ac_cv_sizeof_unsigned_long_long" != "8" \
   && test "$ac_cv_sizeof_uint64_t" != "8"; then
    AC_MSG_WARN([No 64-bit types.  Disabling TIGER/192, SHA-384, and SHA-512])
else
  available_digests="$available_digests sha512 tiger"
fi

dnl If not specified otherwise, all algorithms will be included.
default_ciphers="$available_ciphers"
default_pubkey_ciphers="$available_pubkey_ciphers"
default_digests="$available_digests"

dnl Support for the --enable-ciphers switch.
AC_ARG_ENABLE(ciphers,
	      AC_HELP_STRING([--enable-ciphers=ciphers],
			     [select the symmetric ciphers to include]),
	      [enabled_ciphers=$(echo $enableval | tr , ' ' | tr '[A-Z]' '[a-z]')],
	      [enabled_ciphers=""])
if test "x$enabled_ciphers" = "x" \
   -o "$enabled_ciphers" = "yes"  \
   -o "$enabled_ciphers" = "no"; then
   enabled_ciphers=$default_ciphers
fi
AC_MSG_CHECKING([which symmetric ciphers to include])
for cipher in $enabled_ciphers; do
    LIST_MEMBER($cipher, $available_ciphers)
    if test "$found" = "0"; then
       AC_MSG_ERROR([unsupported cipher specified])
    fi
done
AC_MSG_RESULT([$enabled_ciphers])

dnl Support for the --enable-pubkey-ciphers switch.
AC_ARG_ENABLE(pubkey-ciphers,
	      AC_HELP_STRING([--enable-pubkey-ciphers=ciphers],
			     [select the public-key ciphers to include]),
	      [enabled_pubkey_ciphers=$(echo $enableval | tr , ' ' | tr '[A-Z]' '[a-z]')],
	      [enabled_pubkey_ciphers=""])
if test "x$enabled_pubkey_ciphers" = "x" \
   -o "$enabled_pubkey_ciphers" = "yes"  \
   -o "$enabled_pubkey_ciphers" = "no"; then
   enabled_pubkey_ciphers=$default_pubkey_ciphers
fi
AC_MSG_CHECKING([which public-key ciphers to include])
for cipher in $enabled_pubkey_ciphers; do
    LIST_MEMBER($cipher, $available_pubkey_ciphers)
    if test "$found" = "0"; then
       AC_MSG_ERROR([unsupported public-key cipher specified])
    fi
done
AC_MSG_RESULT([$enabled_pubkey_ciphers])

dnl Support for the --enable-digests switch.
AC_ARG_ENABLE(digests,
	      AC_HELP_STRING([--enable-digests=digests],
			     [select the message digests to include]),
	      [enabled_digests=$(echo $enableval | tr , ' ' | tr '[A-Z]' '[a-z]')],
	      [enabled_digests=""])
if test "x$enabled_digests" = "x" \
   -o "$enabled_digests" = "yes"  \
   -o "$enabled_digests" = "no"; then
   enabled_digests=$default_digests
fi
AC_MSG_CHECKING([which message digests to include])
for digest in $enabled_digests; do
    LIST_MEMBER($digest, $available_digests)
    if test "$found" = "0"; then
       AC_MSG_ERROR([unsupported message digest specified])
    fi
done
AC_MSG_RESULT([$enabled_digests])

dnl Define automake conditionals and config.h symbols depending on the
dnl selected ciphers, pubkey-ciphers and digests.

LIST_MEMBER(arcfour, $enabled_ciphers)
AM_CONDITIONAL(USE_ARCFOUR, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_ARCFOUR, $found, [Defined if this module should be included])
LIST_MEMBER(blowfish, $enabled_ciphers)
AM_CONDITIONAL(USE_BLOWFISH, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_BLOWFISH, $found, [Defined if this module should be included])
LIST_MEMBER(cast5, $enabled_ciphers)
AM_CONDITIONAL(USE_CAST5, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_CAST5, $found, [Defined if this module should be included])
LIST_MEMBER(des, $enabled_ciphers)
AM_CONDITIONAL(USE_DES, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_DES, $found, [Defined if this module should be included])
LIST_MEMBER(aes, $enabled_ciphers)
AM_CONDITIONAL(USE_AES, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_AES, $found, [Defined if this module should be included])
LIST_MEMBER(twofish, $enabled_ciphers)
AM_CONDITIONAL(USE_TWOFISH, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_TWOFISH, $found, [Defined if this module should be included])
LIST_MEMBER(serpent, $enabled_ciphers)
AM_CONDITIONAL(USE_SERPENT, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_SERPENT, $found, [Defined if this module should be included])

LIST_MEMBER(dsa, $enabled_pubkey_ciphers)
AM_CONDITIONAL(USE_DSA, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_DSA, $found, [Defined if this module should be included])
LIST_MEMBER(rsa, $enabled_pubkey_ciphers)
AM_CONDITIONAL(USE_RSA, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RSA, $found, [Defined if this module should be included])
LIST_MEMBER(elgamal, $enabled_pubkey_ciphers)
AM_CONDITIONAL(USE_ELGAMAL, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_ELGAMAL, $found, [Defined if this module should be included])

LIST_MEMBER(crc, $enabled_digests)
AM_CONDITIONAL(USE_CRC, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_CRC, $found, [Defined if this module should be included])
LIST_MEMBER(md4, $enabled_digests)
AM_CONDITIONAL(USE_MD4, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_MD4, $found, [Defined if this module should be included])
LIST_MEMBER(md5, $enabled_digests)
AM_CONDITIONAL(USE_MD5, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_MD5, $found, [Defined if this module should be included])
LIST_MEMBER(sha1, $enabled_digests)
AM_CONDITIONAL(USE_SHA1, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_SHA1, $found, [Defined if this module should be included])
LIST_MEMBER(sha256, $enabled_digests)
AM_CONDITIONAL(USE_SHA256, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_SHA256, $found, [Defined if this module should be included])
LIST_MEMBER(sha512, $enabled_digests)
AM_CONDITIONAL(USE_SHA512, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_SHA512, $found, [Defined if this module should be included])
LIST_MEMBER(tiger, $enabled_digests)
AM_CONDITIONAL(USE_TIGER, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_TIGER, $found, [Defined if this module should be included])

# rmd160 should be included always.
AM_CONDITIONAL(USE_RMD160, true)
AC_DEFINE_UNQUOTED(USE_RMD160, 1, [Defined if this module should be included])


AC_SUBST(LIBGCRYPT_CIPHERS, $enabled_ciphers)
AC_SUBST(LIBGCRYPT_PUBKEY_CIPHERS, $enabled_pubkey_ciphers)
AC_SUBST(LIBGCRYPT_DIGESTS, $enabled_digests)

dnl
dnl  Check for random module options
dnl

AC_MSG_CHECKING([which random module to use])
AC_ARG_ENABLE(static-rnd,
    [  --enable-static-rnd=[egd|unix|linux|default|auto]  ],
[use_static_rnd=$enableval], [use_static_rnd=default] )

if test "$use_static_rnd" = no; then
    use_static_rnd=default
fi

case "$use_static_rnd" in
    egd | linux | unix | default )
      AC_MSG_RESULT($use_static_rnd)
      ;;
    auto )
      AC_MSG_RESULT(automagically selected at runtime)
      ;;
    * )
      AC_MSG_RESULT(invalid argument)
      AC_MSG_ERROR(there is no random module rnd$use_static_rnd)
      ;;
esac

AC_ARG_WITH(egd-socket,
    [  --with-egd-socket=NAME  Use NAME for the EGD socket)],
            egd_socket_name="$withval", egd_socket_name="" )
AC_DEFINE_UNQUOTED(EGD_SOCKET_NAME, "$egd_socket_name",
                   [Define if you don't want the default EGD socket name.
                    For details see cipher/rndegd.c])



dnl
dnl See whether the user wants to disable checking for /dev/random

AC_MSG_CHECKING([whether use of /dev/random is requested])
AC_ARG_ENABLE(dev-random,
[  --disable-dev-random    disable the use of dev random],
    try_dev_random=$enableval, try_dev_random=yes)
AC_MSG_RESULT($try_dev_random)


dnl
dnl  Check other options
dnl

AC_MSG_CHECKING([whether assembler modules are requested])
AC_ARG_ENABLE(asm,
[  --disable-asm           do not use assembler modules],
     try_asm_modules=$enableval, try_asm_modules=yes)
AC_MSG_RESULT($try_asm_modules)

AC_MSG_CHECKING([whether memory guard is requested])
AC_ARG_ENABLE(m-guard,
    [  --enable-m-guard        enable memory guard facility],
    use_m_guard=$enableval, use_m_guard=no)
    AC_MSG_RESULT($use_m_guard)
if test "$use_m_guard" = yes ; then
    AC_DEFINE(M_GUARD,1,[Define to use the (obsolete) malloc guarding feature])
fi

dnl
dnl Check whether we want to use Linux capabilities
dnl
AC_MSG_CHECKING([whether use of capabilities is requested])
AC_ARG_WITH(capabilities,
    [  --with-capabilities     use linux capabilities [default=no]],
[use_capabilities="$withval"],[use_capabilities=no])
AC_MSG_RESULT($use_capabilities)


AM_MAINTAINER_MODE

dnl Checks for programs.

dnl
dnl Setup some stuff depending on host/target.
dnl
case "${target}" in
    *-*-mingw32*)
        # special stuff for Windoze NT
        disallowed_modules="rndunix rndlinux rndegd"
        ;;
    *)
        disallowed_modules="rndw32"
       ;;
esac

AC_PROG_MAKE_SET
AM_SANITY_CHECK
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
dnl AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_CC
AC_PROG_CPP
AM_PROG_AS
AC_ISC_POSIX
AC_PROG_INSTALL
AC_PROG_AWK
GPH_PROG_DB2ANY

AM_PROG_LIBTOOL


MPI_OPT_FLAGS=""


try_gettext=no
case "${target}" in
    *-*-mingw32*)
        # special stuff for Windoze NT
        ac_cv_have_dev_random=no
        AC_DEFINE(USE_ONLY_8DOT3,1,
                  [set this to limit filenames to the 8.3 format])
        AC_DEFINE(HAVE_DRIVE_LETTERS,1,
                  [defined if we must run on a stupid file system])
        AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
                  [defined if we run on some of the PCDOS like systems 
                   (DOS, Windoze. OS/2) with special properties like
                    no file modes])
        try_gettext="no"
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        # OS/2 with the EMX environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        AC_DEFINE(HAVE_DOSISH_SYSTEM)
        try_gettext="no"
        ;;

    i?86-*-msdosdjgpp*)
        # DOS with the DJGPP environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        AC_DEFINE(HAVE_DOSISH_SYSTEM)
        try_gettext="no"
        ;;

    *-*-freebsd*)
       # FreeBSD
       CPPFLAGS="$CPPFLAGS -I/usr/local/include"
       LDFLAGS="$LDFLAGS -L/usr/local/lib"
       ;;

    *-*-hpux*)
        if test -z "$GCC" ; then
            CFLAGS="$CFLAGS -Ae -D_HPUX_SOURCE"
        fi
        ;;
    *-dec-osf4*)
        if test -z "$GCC" ; then
            # Suppress all warnings
            # to get rid of the unsigned/signed char mismatch warnings.
            CFLAGS="$CFLAGS -w"
        fi
        ;;
    m68k-atari-mint)
        ;;
    *)
       ;;
esac

AC_SUBST(MPI_OPT_FLAGS)
GNUPG_SYS_SYMBOL_UNDERSCORE
GNUPG_CHECK_PIC
#GNUPG_CHECK_EXPORTDYNAMIC
#if test "$NO_PIC" = yes; then
#    try_dynload=no
#fi

# For now we hardcode the use of version scripts.  It would be better
# to write a text for this or even implement this within libtool
have_ld_version_script=no
case "${target}" in
    *-*-mingw32*)
        PRINTABLE_OS_NAME="MingW32"
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        PRINTABLE_OS_NAME="OS/2"
        ;;
    i?86-*-msdosdjgpp*)
        PRINTABLE_OS_NAME="MSDOS/DJGPP"
        try_dynload=no
        ;;
    *-linux*)
        PRINTABLE_OS_NAME="GNU/Linux"
        have_ld_version_script=yes
        ;;
dnl let that after linux to avoid gnu-linux problems
    *-gnu*)
        PRINTABLE_OS_NAME="GNU/Hurd"
        have_ld_version_script=yes
        ;;
    *)
        PRINTABLE_OS_NAME=`uname -s || echo "Unknown"`
        ;;
esac
AC_DEFINE_UNQUOTED(PRINTABLE_OS_NAME, "$PRINTABLE_OS_NAME",
                   [A human readable text with the name of the OS])
AC_ARG_ENABLE([ld-version-script],
              AC_HELP_STRING([--enable-ld-version-script],
                             [enable/disable use of linker version script.
                              (default is system dependent)]),
              [have_ld_version_script=$enableval],
              [ : ] )
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")


dnl  Fixme: Are these the best flags for OpenBSD????
case "${target}" in
    *-openbsd* | *-netbsd*)
        NAME_OF_DEV_RANDOM="/dev/srandom"
        NAME_OF_DEV_URANDOM="/dev/urandom"
#       DYNLINK_MOD_CFLAGS="-shared -rdynamic $CFLAGS_PIC -Wl,-Bshareable -Wl,-x"
        ;;

    *-solaris* | *-irix* | *-dec-osf* )
        NAME_OF_DEV_RANDOM="/dev/random"
        NAME_OF_DEV_URANDOM="/dev/random"
#       DYNLINK_MOD_CFLAGS="-shared $CFLAGS_PIC"
        ;;

    *)
        NAME_OF_DEV_RANDOM="/dev/random"
        NAME_OF_DEV_URANDOM="/dev/urandom"
        # -shared is a gcc-ism.  Find pic flags from GNUPG_CHECK_PIC.
#        if test -n "$GCC" ; then
#           DYNLINK_MOD_CFLAGS="-shared $CFLAGS_PIC"                            
#        else
#           DYNLINK_MOD_CFLAGS="$CFLAGS_PIC"
#        fi
        ;;
esac
AC_DEFINE_UNQUOTED(NAME_OF_DEV_RANDOM, "$NAME_OF_DEV_RANDOM",
                   [defined to the name of the strong random device])
AC_DEFINE_UNQUOTED(NAME_OF_DEV_URANDOM, "$NAME_OF_DEV_URANDOM",
                   [defined to the name of the weaker random device])
AC_SUBST(MPI_OPT_FLAGS)


dnl Checks for libraries.

USE_NLS=no
USE_INCLUDED_LIBINTL=no
AC_SUBST(USE_NLS)
AC_SUBST(USE_INCLUDED_LIBINTL)


dnl Solaris needs -lsocket and -lnsl. Unisys system includes
dnl gethostbyname in libsocket but needs libnsl for socket.
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket, ac_need_libsocket=1, ac_try_nsl=1)
if test x$ac_need_libsocket = x1; then
    LIBS="$LIBS -lsocket"
fi
if test x$ac_try_nsl = x1; then
    AC_CHECK_LIB(nsl, gethostbyname, ac_need_libnsl=1)
    if test x$ac_need_libnsl = x1
    then
        LIBS="$LIBS -lnsl"
    fi
fi


dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h sys/select.h)


dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST

GNUPG_CHECK_ENDIAN


GNUPG_CHECK_TYPEDEF(byte, HAVE_BYTE_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ushort, HAVE_USHORT_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ulong, HAVE_ULONG_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u16, HAVE_U16_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u32, HAVE_U32_TYPEDEF)

#
# Checks for library functions.
#
AC_FUNC_VPRINTF
dnl We have replacements for these in src/missing-string.c
AC_CHECK_FUNCS(stpcpy strcasecmp)
dnl We have replacements for these in src/g10lib.h
AC_CHECK_FUNCS(strtoul memmove stricmp atexit raise)
dnl Other checks
AC_CHECK_FUNCS(strerror rand mmap getpagesize waitpid wait4)
AC_CHECK_FUNCS(gettimeofday getrusage gethrtime clock_gettime)

GNUPG_CHECK_MLOCK
GNUPG_FUNC_MKDIR_TAKES_ONE_ARG

# 
# The ATH systems needs to know whether pth or pthreads are available.
# 
have_pth=no
have_pthread=no
AC_CHECK_LIB(pth,pth_version,have_pth=yes)
if test "$have_pth" = yes; then
  AC_DEFINE(HAVE_PTH, ,[Define if we have Pth.])
fi
AC_CHECK_LIB(pthread,pthread_create,have_pthread=yes)
if test "$have_pthread" != yes; then
  AC_CHECK_LIB(c,pthread_create,have_pthread=yes)
fi
if test "$have_pthread" = yes; then
  AC_DEFINE(HAVE_PTHREAD, ,[Define if we have pthread.])
fi
AM_CONDITIONAL(HAVE_PTH, test "$have_pth" = "yes")
AM_CONDITIONAL(HAVE_PTHREAD, test "$have_pthread" = "yes")


#
# Check whether we can use Linux capabilities as requested
#
if test "$use_capabilities" = "yes" ; then
use_capabilities=no
AC_CHECK_HEADERS(sys/capability.h)
if test "$ac_cv_header_sys_capability_h" = "yes" ; then
  AC_CHECK_LIB(cap, cap_init, ac_need_libcap=1)
  if test "$ac_cv_lib_cap_cap_init" = "yes"; then
     AC_DEFINE(USE_CAPABILITIES,1,
               [define if capabilities should be used])
     LIBS="$LIBS -lcap"
     use_capabilities=yes
  fi
fi
if test "$use_capabilities" = "no" ; then
    AC_MSG_WARN([[
***
*** The use of capabilities on this system is not possible.
*** You need a recent Linux kernel and some patches:
***   fcaps-2.2.9-990610.patch      (kernel patch for 2.2.9)
***   fcap-module-990613.tar.gz     (kernel module)
***   libcap-1.92.tar.gz            (user mode library and utilities)
*** And you have to configure the kernel with CONFIG_VFS_CAP_PLUGIN
*** set (filesystems menu). Be warned: This code is *really* ALPHA.
***]])
fi
fi


GNUPG_CHECK_IPC
if test "$ac_cv_header_sys_shm_h" = "yes"; then
  AC_DEFINE(USE_SHM_COPROCESSING,1,
            [define if the shared memory interface should be made available])
fi

dnl
dnl check whether we have a random device
dnl
if test "$try_dev_random" = yes ; then
    AC_CACHE_CHECK(for random device, ac_cv_have_dev_random,
    [if test -r "$NAME_OF_DEV_RANDOM" && test -r "$NAME_OF_DEV_URANDOM" ; then
      ac_cv_have_dev_random=yes; else ac_cv_have_dev_random=no; fi])
    if test "$ac_cv_have_dev_random" = yes; then
        AC_DEFINE(HAVE_DEV_RANDOM,1,
                 [defined if the system supports a random device] )
    fi
else
    AC_MSG_CHECKING(for random device)
    ac_cv_have_dev_random=no
    AC_MSG_RESULT(has been disabled)
fi

#dnl
#dnl and whether this device supports ioctl
#dnl (Note, that we should do a real test here)
#dnl
#if test "$ac_cv_have_dev_random" = yes ; then
#    AC_CHECK_HEADERS(linux/random.h)
#    AC_CACHE_CHECK(for random device ioctl, ac_cv_have_dev_random_ioctl,
#      [ if test "$ac_cv_header_linux_random_h" = yes ; then
#          ac_cv_have_dev_random_ioctl=yes;
#        else
#          ac_cv_have_dev_random_ioctl=no;
#        fi
#      ])
#    if test "$ac_cv_have_dev_random_ioctl" = yes; then
#        AC_DEFINE(HAVE_DEV_RANDOM_IOCTL,1,
#                  [defined if the random device supports some IOCTLs])
#    fi
#fi
#

dnl
dnl Figure out the random modules that are available for this
dnl configuration.
dnl
print_egd_notice=no
random_modules=""
if test "$use_static_rnd" = default; then

     # Figure out the default random module.
     if test "$ac_cv_have_dev_random" = yes; then
        random_modules="rndlinux"
     else
         case "${target}" in
            *-*-mingw32*|*-*-cygwin*)
                random_modules="rndw32"
                ;;
            i?86-emx-os2|i?86-*-os2*emx)
                random_modules="rndos2"
                ;;
            m68k-atari-mint)
                random_modules="rndatari"
                ;;
            i?86-*-msdosdjgpp*)
                :
                ;;
            *)
                random_modules="rndlinux rndegd rndunix"
                AC_DEFINE(USE_ALL_RANDOM_MODULES, 1, 
                          [Allow to select random modules at runtime.])
                ;;
         esac
     fi
else
     if test "$use_static_rnd" = auto; then
          random_modules="rndlinux rndegd rndunix"
          AC_DEFINE(USE_ALL_RANDOM_MODULES, 1)
     else
          random_modules="rnd$use_static_rnd";
     fi
fi

if test -z "$random_modules"; then
   AC_MSG_ERROR(no random module available)
fi


dnl Filter out the modules contained in `disallowed_modules'.
random_modules_tmp=$random_modules
random_modules=""
for rndmod in $random_modules_tmp; do
    LIST_MEMBER($rndmod, $disallowed_modules)
    if test "$found" = "0"; then
       random_modules="$random_modules $rndmod"
    fi
done

dnl Define conditionals and config.h symbols depending on the enabled
dnl random modules.

LIST_MEMBER(rndlinux, $random_modules)
AM_CONDITIONAL(USE_RNDLINUX, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RNDLINUX, $found, [Defined if the /dev/random based RNG should be used.])

LIST_MEMBER(rndunix, $random_modules)
AM_CONDITIONAL(USE_RNDUNIX, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RNDUNIX, $found, [Defined if the default Unix RNG should be used.])
if test "$found" = "1"; then
   print_egd_notice=yes
fi

LIST_MEMBER(rndegd, $random_modules)
AM_CONDITIONAL(USE_RNDEGD, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RNDEGD, $found, [Defined if the EGD based RNG should be used.])
if test "$found" = "1"; then
   EGDLIBS=$NETLIBS
   AC_SUBST(EGDLIBS)
fi

LIST_MEMBER(rndw32, $random_modules)
AM_CONDITIONAL(USE_RNDW32, test "$found" = "1")
AC_DEFINE_UNQUOTED(USE_RNDW32, $found, [Defined if the Windows specific RNG should be used.])

AC_MSG_RESULT()


#
# setup assembler stuff
#
AC_MSG_CHECKING(for mpi assembler functions)
if test -f $srcdir/mpi/config.links ; then
    . $srcdir/mpi/config.links
    AC_CONFIG_LINKS("$mpi_ln_list")
    ac_cv_mpi_mod_list="$mpi_mod_list"
    ac_cv_mpi_sflags="$mpi_sflags"
    ac_cv_mpi_config_done="yes"
    AC_MSG_RESULT(done)
else
    AC_MSG_RESULT(failed)
    AC_MSG_ERROR([mpi/config.links missing!])
fi
MPI_MOD_LIST_LO=""
MPI_MOD_LIST_O=""
if test "$ac_cv_mpi_mod_list" != ""; then
  for i in $ac_cv_mpi_mod_list; do
      MPI_MOD_LIST_LO="$MPI_MOD_LIST_LO $i.lo"
      MPI_MOD_LIST_O="$MPI_MOD_LIST_O $i.o"
  done
fi
AC_SUBST(MPI_MOD_LIST_LO)
AC_SUBST(MPI_MOD_LIST_O)
MPI_SFLAGS="$ac_cv_mpi_sflags"
AC_SUBST(MPI_SFLAGS)

# [not used anymore]
## Set the condtionals for the assembler modules
## Fixme: We should put this into acinclude and write a script
##        which can be run to update this list and the mpi/Makefile
#AM_CONDITIONAL(MPI_MOD_ASM_MPIH_ADD1, test "$mpi_mod_asm_mpih_add1" = yes )
#AM_CONDITIONAL(MPI_MOD_ASM_MPIH_SUB1, test "$mpi_mod_asm_mpih_sub1" = yes )
#AM_CONDITIONAL(MPI_MOD_ASM_MPIH_MUL1, test "$mpi_mod_asm_mpih_mul1" = yes )
#AM_CONDITIONAL(MPI_MOD_ASM_MPIH_MUL2, test "$mpi_mod_asm_mpih_mul2" = yes )
#AM_CONDITIONAL(MPI_MOD_ASM_MPIH_MUL3, test "$mpi_mod_asm_mpih_mul3" = yes )
#AM_CONDITIONAL(MPI_MOD_ASM_MPIH_LSHIFT, test "$mpi_mod_asm_mpih_lshift" = yes )
#AM_CONDITIONAL(MPI_MOD_ASM_MPIH_RSHIFT, test "$mpi_mod_asm_mpih_rshift" = yes )
#AM_CONDITIONAL(MPI_MOD_ASM_UDIV, test "$mpi_mod_asm_udiv" = yes )
#AM_CONDITIONAL(MPI_MOD_ASM_UDIV_QRNND, test "$mpi_mod_asm_udiv_qrnnd" = yes )
## And the corresponding conditionals for C
#AM_CONDITIONAL(MPI_MOD_C_MPIH_ADD1, test "$mpi_mod_c_mpih_add1" = yes )
#AM_CONDITIONAL(MPI_MOD_C_MPIH_SUB1, test "$mpi_mod_c_mpih_sub1" = yes )
#AM_CONDITIONAL(MPI_MOD_C_MPIH_MUL1, test "$mpi_mod_c_mpih_mul1" = yes )
#AM_CONDITIONAL(MPI_MOD_C_MPIH_MUL2, test "$mpi_mod_c_mpih_mul2" = yes )
#AM_CONDITIONAL(MPI_MOD_C_MPIH_MUL3, test "$mpi_mod_c_mpih_mul3" = yes )
#AM_CONDITIONAL(MPI_MOD_C_MPIH_LSHIFT, test "$mpi_mod_c_mpih_lshift" = yes )
#AM_CONDITIONAL(MPI_MOD_C_MPIH_RSHIFT, test "$mpi_mod_c_mpih_rshift" = yes )
#AM_CONDITIONAL(MPI_MOD_C_UDIV, test "$mpi_mod_c_udiv" = yes )
#AM_CONDITIONAL(MPI_MOD_C_UDIV_QRNND, test "$mpi_mod_c_udiv_qrnnd" = yes )
#


# Allow users to append something to the version string without
# flagging it as development version.  The user version part is
# considered everything after a dash.
changequote(,)dnl
tmp_pat='[a-zA-Z]'
changequote([,])dnl
if echo "$VERSION" | sed 's/-.*//' | grep "$tmp_pat" >/dev/null ; then
    AC_DEFINE(IS_DEVELOPMENT_VERSION,1,
              [Defined if this is not a regular release])
fi

AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

GNUPG_CHECK_GNUMAKE

if test "$GCC" = yes; then
    if test "$MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
    else
        CFLAGS="$CFLAGS -Wall"
    fi
fi

dnl
dnl Make the version number in src/gcrypt.h the same as the one here.
dnl (this is easier than to have a *.in file just for one substitution)
dnl
GNUPG_FIX_HDR_VERSION([src/gcrypt.h], GCRYPT_VERSION)

LIBGCRYPT_CONFIG_LIBS="-lgcrypt"
LIBGCRYPT_CONFIG_CFLAGS=""
AC_SUBST(LIBGCRYPT_CONFIG_LIBS)
AC_SUBST(LIBGCRYPT_CONFIG_CFLAGS)

AC_CONFIG_COMMANDS([gcrypt-defs],[[
chmod +x src/libgcrypt-config
cat >gcrypt-defs.tmp <<G10EOF
/* Generated automatically by configure */
#ifdef HAVE_DRIVE_LETTERS
  #define GNUPG_LOCALEDIR "c:/lib/gnupg/locale"
  #define GNUPG_LIBDIR  "c:/lib/gnupg"
  #define GNUPG_DATADIR "c:/lib/gnupg"
  #define GNUPG_HOMEDIR "c:/gnupg-test"
#else
  #define GNUPG_LOCALEDIR "${prefix}/${DATADIRNAME}/locale"
  #define GNUPG_LIBDIR  "${libdir}/gnupg"
  #define GNUPG_DATADIR "${datadir}/gnupg"
  #ifdef __VMS
    #define GNUPG_HOMEDIR "/SYS\$LOGIN/gnupg" 
  #else
    #define GNUPG_HOMEDIR "~/.gnupg-test" 
  #endif
#endif
G10EOF
if cmp -s gcrypt-defs.h gcrypt-defs.tmp 2>/dev/null; then
    echo "gcrypt-defs.h is unchanged"
    rm -f gcrypt-defs.tmp
else
    rm -f gcrypt-defs.h
    mv gcrypt-defs.tmp gcrypt-defs.h
    echo "gcrypt-defs.h created"
fi
]],[[
prefix=$prefix
exec_prefix=$exec_prefix
libdir=$libdir
datadir=$datadir
DATADIRNAME=$DATADIRNAME
]])


AC_CONFIG_FILES([
Makefile
mpi/Makefile
cipher/Makefile
doc/Makefile
doc/version.sgml
src/Makefile
src/libgcrypt-config
tests/Makefile
w32-dll/Makefile
])
AC_OUTPUT

# Give some feedback
echo

if test "$print_egd_notice" = "yes"; then
cat <<G10EOF
  
   The performance of the Unix random gatherer module (rndunix) is not
   very good and it does not keep the entropy pool over multiple
   invocations of GnuPG.  The suggested way to overcome this problem is
   to use the
  
                 Entropy Gathering Daemon (EGD)
  
   which provides a entropy source for the whole system.  It is written
   in Perl and available at the GnuPG FTP servers.  To enable EGD you
   should rerun configure with the option "--enable-static-rnd=egd".
   For more information consult the GnuPG webpages:
  
             http://www.gnupg.org/download.html#egd

G10EOF
fi

warn=""
for file in "random_modules"; do
  case "$file" in rndunix | rndw32) warn="$warn $file";; esac
done
if test -n "$warn"; then
  echo "Please note that you are building a version of Libgcrypt with"
  echo "  $warn"
  echo "included.  These parts are licensed under the GPL and thus the"
  echo "use of this library has to comply with the conditions of the GPL."
fi

# Give some feedback
echo
echo   "                Configured for: $PRINTABLE_OS_NAME ($target)"
if test -n "$show_extraasm"; then
  echo "  Extra cpu specific functions:$show_extraasm"
fi
echo
