# Copyright (C) 2005 Free Software Foundation, Inc.
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

TESTS = \
basic-compat prime-compat general-compat ac-compat \
ac-data-compat ac-schemes-compat benchmark-compat \
full-compat keygen-compat pkbench-compat \
pubkey-compat register-compat tsexp-compat \
keygrip-compat multithreading-pthread-compat \
multithreading-pth-compat

EXTRA_DIST = multithreading-compat.h

noinst_PROGRAMS = $(TESTS)

noinst_LIBRARIES = libcommon.a

libcommon_a_SOURCES = \
common-startup.c common.h

INCLUDES = \
-I$(top_srcdir)/src/compat \
-I$(top_builddir)/src/subsystems/mpi \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src \
-I$(top_srcdir)/src/subsystems/asym-cipher/modules \
-I$(top_srcdir)/src/subsystems/sym-cipher/modules \
-I$(top_srcdir)/src/subsystems/hash/modules \
@GPG_ERROR_CFLAGS@

AM_CFLAGS = @GPG_ERROR_CFLAGS@
LDADD = ../src/libgcrypt.la libcommon.a

multithreading_pth_compat_LDADD =  $(LDADD) @PTH_LDFLAGS@ @PTH_LIBS@
multithreading_pthread_compat_LDADD =  $(LDADD) -lpthread
