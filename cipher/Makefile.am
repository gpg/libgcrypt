# Makefile for cipher modules
# Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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

# Process this file with automake to produce Makefile.in


INCLUDES = -I$(top_srcdir)/src 

noinst_LTLIBRARIES = libcipher.la

#OMIT_DEPENDENCIES = types.h gcrypt.h


# The configure script greps the module names from the EXTRA_PROGRAMS line
EXTRA_PROGRAMS = rndlinux rndunix rndegd rndw32 sha1 rmd160 md4 md5 tiger

EXTRA_rndlinux_SOURCES = rndlinux.c
EXTRA_rndunix_SOURCES = rndunix.c
EXTRA_rndegd_SOURCES = rndegd.c
EXTRA_rndw32_SOURCES = rndw32.c
EXTRA_md4_SOURCES = md4.c
EXTRA_md5_SOURCES = md5.c
EXTRA_rmd160_SOURCES = rmd160.c
EXTRA_sha1_SOURCES = sha1.c
EXTRA_tiger_SOURCES = tiger.c


libcipher_la_LDFLAGS =
libcipher_la_SOURCES = cipher.c  \
		 pubkey.c	\
		 md.c		\
		 dynload.c	\
		 dynload.h	\
		 bithelp.h	\
		 des.c		\
		 des.h		\
		 rijndael.c     \
		 twofish.c	\
		 blowfish.c	\
		 blowfish.h	\
		 cast5.c	\
		 cast5.h	\
		 arcfour.c arcfour.h \
		 elgamal.c	\
		 elgamal.h	\
		 primegen.c	\
		 random.h	\
		 random.c	\
		 rand-internal.h \
		 rmd.h		\
		 dsa.h		\
		 dsa.c		\
		 rsa.c rsa.h    \
		 construct.c

# configure creates the constructor file
BUILT_SOURCES = construct.c
DISTCLEANFILES = construct.c

libcipher_la_DEPENDENCIES = @STATIC_CIPHER_OBJS@
libcipher_la_LIBADD =	    @STATIC_CIPHER_OBJS@

# We need to lower the optimization for this module.
tiger.o: $(srcdir)/tiger.c
	`echo $(COMPILE) -c $(srcdir)/tiger.c | sed -e 's/-O[2-9s]*/-O1/g' `

tiger.lo: $(srcdir)/tiger.c
	`echo $(LTCOMPILE) -c $(srcdir)/tiger.c | sed -e 's/-O[2-9s]*/-O1/g' `




