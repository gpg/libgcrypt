## Process this file with automake to produce Makefile.in
# Copyright (C) 1992, 1999, 2000, 2002 Free Software Foundation, Inc.
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

INCLUDES =  -I$(top_srcdir)/src
CFLAGS = @CFLAGS@ @MPI_OPT_FLAGS@
ASFLAGS = @MPI_SFLAGS@

EXTRA_DIST = config.links
DISTCLEANFILES = mpih-add1.S mpih-mul1.S mpih-mul2.S mpih-mul3.S  \
		 mpih-lshift.S mpih-rshift.S mpih-sub1.S asm-syntax.h sysdep.h
# Note: we only use .S files so we should delete all left over .s
# CLEANFILES = _*.s
CLEANFILES = *.s

#OMIT_DEPENDENCIES = types.h gcrypt.h

noinst_LTLIBRARIES = libmpi.la

libmpi_la_LDFLAGS =
libmpi_la_SOURCES = longlong.h	   \
	      mpi-add.c      \
	      mpi-bit.c      \
	      mpi-cmp.c      \
	      mpi-div.c      \
	      mpi-gcd.c      \
	      mpi-internal.h \
	      mpi-inline.h   \
	      mpi-inline.c   \
	      mpi-inv.c      \
	      mpi-mul.c      \
	      mpi-pow.c      \
	      mpi-mpow.c     \
	      mpi-scan.c     \
	      mpicoder.c     \
	      mpih-div.c     \
	      mpih-mul.c     \
	      mpiutil.c      

EXTRA_libmpi_la_SOURCES = \
         mpih-mul1.S    \
         mpih-mul2.S    \
	 mpih-mul3.S    \
	 mpih-add1.S    \
	 mpih-sub1.S    \
	 mpih-lshift.S  \
	 mpih-rshift.S  \
         udiv-qrnnd.S   \
         udiv-w-sdiv.c  \
         udiv.S  


# Note this objects are actually links, the sourcefiles are
# distributed by special code in dist-hook
common_asm_objects = \
         mpih-mul1.lo    \
         mpih-mul2.lo    \
	 mpih-mul3.lo    \
	 mpih-add1.lo    \
	 mpih-sub1.lo    \
	 mpih-lshift.lo  \
	 mpih-rshift.lo

libmpi_la_DEPENDENCIES = $(common_asm_objects) @MPI_EXTRA_ASM_OBJS@
libmpi_la_LIBADD = $(common_asm_objects) @MPI_EXTRA_ASM_OBJS@

# cancel the default rules used by libtool which do not really
# work and add one to cpp .S files
#.S.o:
#
#.S.lo:

.S.s:
	 $(CPP) $(INCLUDES) $(DEFS) $< | grep -v '^#' >$*.s

# Hmmm, we should use this, so that OSes which do not distinguish
# filename case still work.  We have to see how libtool can handle this
#   $(CPP) $(INCLUDES) $(DEFS) $< | grep -v '^#' > _$*.s
#   $(COMPILE) -c _$*.s
#   mv -f _$*.o $*.o
