dnl ##
dnl ##  GNU Pth - The GNU Portable Threads
dnl ##  Copyright (c) 1999-2004 Ralf S. Engelschall <rse@engelschall.com>
dnl ##
dnl ##  This file is part of GNU Pth, a non-preemptive thread scheduling
dnl ##  library which can be found at http://www.gnu.org/software/pth/.
dnl ##
dnl ##  This library is free software; you can redistribute it and/or
dnl ##  modify it under the terms of the GNU Lesser General Public
dnl ##  License as published by the Free Software Foundation; either
dnl ##  version 2.1 of the License, or (at your option) any later version.
dnl ##
dnl ##  This library is distributed in the hope that it will be useful,
dnl ##  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl ##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
dnl ##  Lesser General Public License for more details.
dnl ##
dnl ##  You should have received a copy of the GNU Lesser General Public
dnl ##  License along with this library; if not, write to the Free Software
dnl ##  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
dnl ##  USA, or contact Ralf S. Engelschall <rse@engelschall.com>.
dnl ##
dnl ##  aclocal.m4: Pth Autoconf macros
dnl ##
                        dnl # ``"Reuse an expert's code" is the right
                        dnl #   advice for most people. But it's a useless
                        dnl #   advice for the experts writing the code
                        dnl #   in the first place.'
                        dnl #               -- Dan J. Bernstein

dnl ##
dnl ##  Check for socket/network size type
dnl ##
dnl ##  configure.ac:
dnl ##    AC_CHECK_SOCKLENTYPE(<action-with-${ac_type}>)
dnl ##


dnl ##
dnl ##  Check for an ANSI C typedef in a header
dnl ##
dnl ##  configure.ac:
dnl ##    AC_CHECK_TYPEDEF(<typedef>, <header>)
dnl ##  acconfig.h:
dnl ##    #undef HAVE_<typedef>
dnl ##

AC_DEFUN(AC_CHECK_TYPEDEF,[dnl
AC_REQUIRE([AC_HEADER_STDC])dnl
AC_MSG_CHECKING(for typedef $1)
AC_CACHE_VAL(ac_cv_typedef_$1,
[AC_EGREP_CPP(dnl
changequote(<<,>>)dnl
<<(^|[^a-zA-Z_0-9])$1[^a-zA-Z_0-9]>>dnl
changequote([,]), [
#include <$2>
], ac_cv_typedef_$1=yes, ac_cv_typedef_$1=no)])dnl
AC_MSG_RESULT($ac_cv_typedef_$1)
if test $ac_cv_typedef_$1 = yes; then
    AC_DEFINE(HAVE_[]translit($1, [a-z], [A-Z]), 1,
              [define if typedef $1 exists in header $2])
fi
])


dnl ##
dnl ##  Check for argument type of a function
dnl ##
dnl ##  configure.ac:
dnl ##    AC_CHECK_ARGTYPE(<header> [...], <func>, <arg-number>,
dnl ##                     <max-arg-number>, <action-with-${ac_type}>)
dnl ##

AC_DEFUN(AC_CHECK_ARGTYPE,[dnl
AC_REQUIRE_CPP()dnl
AC_MSG_CHECKING([for type of argument $3 for $2()])
AC_CACHE_VAL([ac_cv_argtype_$2$3],[
cat >conftest.$ac_ext <<EOF
[#]line __oline__ "configure"
#include "confdefs.h"
EOF
for ifile in $1; do
    echo "#include <$ifile>" >>conftest.$ac_ext
done
gpat=''
spat=''
i=1
changequote(, )dnl
while test $i -le $4; do
    gpat="$gpat[^,]*"
    if test $i -eq $3; then
        spat="$spat\\([^,]*\\)"
    else
        spat="$spat[^,]*"
    fi
    if test $i -lt $4; then
        gpat="$gpat,"
        spat="$spat,"
    fi
    i=`expr $i + 1`
done
changequote([, ])dnl
(eval "$ac_cpp conftest.$ac_ext") 2>&AC_FD_CC |\
changequote(, )dnl
sed -e ':join' \
    -e '/,[ 	]*$/N' \
    -e 's/,[ 	]*\n[ 	]*/, /' \
    -e 'tjoin' |\
egrep "[^a-zA-Z0-9_]$2[ 	]*\\($gpat\\)" | head -1 |\
sed -e "s/.*[^a-zA-Z0-9_]$2[ 	]*($spat).*/\\1/" \
    -e 's/(\*[a-zA-Z_][a-zA-Z_0-9]*)/(*)/' \
    -e 's/^[ 	]*//' -e 's/[ 	]*$//' \
    -e 's/^/arg:/' \
    -e 's/^arg:\([^ 	]*\)$/type:\1/' \
    -e 's/^arg:\(.*_t\)*$/type:\1/' \
    -e 's/^arg:\(.*\*\)$/type:\1/' \
    -e 's/^arg:\(.*[ 	]\*\)[_a-zA-Z][_a-zA-Z0-9]*$/type:\1/' \
    -e 's/^arg:\(.*[ 	]char\)$/type:\1/' \
    -e 's/^arg:\(.*[ 	]short\)$/type:\1/' \
    -e 's/^arg:\(.*[ 	]int\)$/type:\1/' \
    -e 's/^arg:\(.*[ 	]long\)$/type:\1/' \
    -e 's/^arg:\(.*[ 	]float\)$/type:\1/' \
    -e 's/^arg:\(.*[ 	]double\)$/type:\1/' \
    -e 's/^arg:\(.*[ 	]unsigned\)$/type:\1/' \
    -e 's/^arg:\(.*[ 	]signed\)$/type:\1/' \
    -e 's/^arg:\(.*struct[ 	][_a-zA-Z][_a-zA-Z0-9]*\)$/type:\1/' \
    -e 's/^arg:\(.*\)[ 	]_[_a-zA-Z0-9]*$/type:\1/' \
    -e 's/^arg:\(.*\)[ 	]\([^ 	]*\)$/type:\1/' \
    -e 's/^type://' >conftest.output
ac_cv_argtype_$2$3=`cat conftest.output`
changequote([, ])dnl
rm -f conftest*
])
AC_MSG_RESULT([$ac_cv_argtype_$2$3])
ac_type="$ac_cv_argtype_$2$3"
[$5]
])


dnl #   Background:
dnl #   this exists because of shortsightedness on the POSIX committee.
dnl #   BSD systems used "int *" as the parameter to accept(2),
dnl #   getsockname(2), getpeername(2) et al. Consequently many Unix
dnl #   flavors took an "int *" for that parameter. The POSIX committee
dnl #   decided that "int" was just too generic and had to be replaced
dnl #   with "size_t" almost everywhere. There's no problem with that
dnl #   when you're passing by value. But when you're passing by
dnl #   reference (as it is the case for accept(2) and friends) this
dnl #   creates a gross source incompatibility with existing programs.
dnl #   On 32-bit architectures it creates only a warning. On 64-bit
dnl #   architectures it creates broken code -- because "int *" is a
dnl #   pointer to a 64-bit quantity and "size_t *" is usually a pointer
dnl #   to a 32-bit quantity. Some Unix flavors adopted "size_t *" for
dnl #   the sake of POSIX compliance. Others ignored it because it was
dnl #   such a broken interface. Chaos ensued. POSIX finally woke up
dnl #   and decided that it was wrong and created a new type socklen_t.
dnl #   The only useful value for socklen_t is "int", and that's how
dnl #   everyone who has a clue implements it. It is almost always the
dnl #   case that this type should be defined to be an "int", unless the
dnl #   system being compiled for was created in the window of POSIX
dnl #   madness.

AC_DEFUN(AC_CHECK_SOCKLENTYPE,[dnl
AC_CHECK_TYPEDEF(socklen_t, sys/socket.h)
AC_CHECK_ARGTYPE(sys/types.h sys/socket.h, accept, 3, 3, [:])
AC_MSG_CHECKING(for fallback socklen_t)
AC_CACHE_VAL(ac_cv_check_socklentype, [
if test ".$ac_cv_typedef_socklen_t" = .yes; then
    ac_cv_check_socklentype='socklen_t'
elif test ".$ac_type" != .; then
    ac_cv_check_socklentype=`echo "$ac_type" | sed -e 's/[ 	]*\*$//'`
else
    ac_cv_check_socklentype='int'
fi
])
AC_MSG_RESULT([$ac_cv_check_socklentype])
ac_type="$ac_cv_check_socklentype"
ifelse([$1], , :, [$1])
])

