# Copyright (C) 2001, 2002, 2003, 2005 Free Software Foundation, Inc.
#
# This file is part of Libgcrypt.
#
# Libgcrypt is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
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

## Process this file with automake to produce Makefile.in

tests_bin = \
        version mpitests tsexp t-convert \
	t-mpi-bit t-mpi-point curves t-lock \
	prime basic keygen pubkey hmac hashtest t-kdf keygrip \
	fips186-dsa aeswrap pkcs1v2 random dsa-rfc6979 t-ed25519

tests_bin_last = benchmark bench-slope

tests_sh =

tests_sh_last = hashtest-256g

TESTS = $(tests_bin) $(tests_sh) $(tests_bin_last) $(tests_sh_last)

# Force sequential run of some tests.
bench-slope.log:    benchmark.log
hashtest-256g.log:  bench-slope.log


TESTS_ENVIRONMENT = GCRYPT_IN_REGRESSION_TEST=1


# Need to include ../src in addition to top_srcdir because gcrypt.h is
# a built header.
AM_CPPFLAGS = -I../src -I$(top_srcdir)/src
AM_CFLAGS = $(GPG_ERROR_CFLAGS)
AM_LDFLAGS = -no-install

default_ldadd = \
	../src/libgcrypt.la $(DL_LIBS) \
        ../compat/libcompat.la $(GPG_ERROR_LIBS)

EXTRA_PROGRAMS = testapi pkbench
noinst_PROGRAMS = $(tests_bin) $(tests_bin_last) fipsdrv rsacvt genhashdata
noinst_HEADERS = t-common.h

EXTRA_DIST = README rsa-16k.key cavs_tests.sh cavs_driver.pl \
	     pkcs1v2-oaep.h pkcs1v2-pss.h pkcs1v2-v15c.h pkcs1v2-v15s.h \
	     t-ed25519.inp stopwatch.h hashtest-256g.in

LDADD = $(default_ldadd) $(LIBTHREAD)
t_lock_LDADD = $(default_ldadd) $(LIBMULTITHREAD)
