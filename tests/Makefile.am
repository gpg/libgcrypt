# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

INCLUDES = -I$(top_srcdir)/src
LDADD = ../src/libgcrypt.la

AM_CFLAGS = -Wall @GPG_ERROR_CFLAGS@

TEST_PROGS = \
	ac tsexp keygen pubkey basic prime \
	register testapi ac-schemes encoding

TESTS = $(TEST_PROGS)
EXTRA_PROGRAMS = benchmark $(TEST_PROGS)

benchmark_SOURCES = benchmark.c
benchmark_LDADD = -ltest-suite $(LDADD) -ldl

lib_LTLIBRARIES = libtest-suite.la libtest-standalone.la

# This is a hack: prevent installation of shared libraries.
install-libLTLIBRARIES:

libtest_suite_la_SOURCES = test.c \
	ac.c tsexp.c keygen.c pubkey.c basic.c prime.c \
	register.c testapi.c ac-schemes.c encoding.c

libtest_suite_la_CFLAGS = $(AM_CFLAGS)

libtest_standalone_la_SOURCES = standalone.c
libtest_standalone_la_CFLAGS = $(AM_CFLAGS)

standalone_libraries = libtest-standalone.la libtest-suite.la $(LDADD) -ldl

ac_SOURCES =
ac_LDADD = $(standalone_libraries)

tsexp_SOURCES =
tsexp_LDADD = $(standalone_libraries)

keygen_SOURCES =
keygen_LDADD = $(standalone_libraries)

pubkey_SOURCES =
pubkey_LDADD = $(standalone_libraries)

basic_SOURCES =
basic_LDADD = $(standalone_libraries)

prime_SOURCES =
prime_LDADD = $(standalone_libraries)

register_SOURCES =
register_LDADD = $(standalone_libraries)

testapi_SOURCES =
testapi_LDADD = $(standalone_libraries)

ac_schemes_SOURCES =
ac_schemes_LDADD = $(standalone_libraries)

encoding_SOURCES =
encoding_LDADD = $(standalone_libraries)
