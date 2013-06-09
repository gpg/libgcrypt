# Makefile for cipher modules
# Copyright (C) 1998, 1999, 2000, 2001, 2002,
#               2003, 2009 Free Software Foundation, Inc.
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
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

# Process this file with automake to produce Makefile.in

EXTRA_DIST = Manifest

# Need to include ../src in addition to top_srcdir because gcrypt.h is
# a built header.
AM_CPPFLAGS = -I../src -I$(top_srcdir)/src
AM_CFLAGS = $(GPG_ERROR_CFLAGS)

AM_CCASFLAGS = $(NOEXECSTACK_FLAGS)


noinst_LTLIBRARIES = libcipher.la

GCRYPT_MODULES = @GCRYPT_CIPHERS@ @GCRYPT_PUBKEY_CIPHERS@ \
                 @GCRYPT_DIGESTS@ @GCRYPT_KDFS@

libcipher_la_DEPENDENCIES = $(GCRYPT_MODULES)
libcipher_la_LIBADD = $(GCRYPT_MODULES)

libcipher_la_SOURCES = \
cipher.c cipher-internal.h \
cipher-cbc.c cipher-cfb.c cipher-ofb.c cipher-ctr.c cipher-aeswrap.c \
cipher-selftest.c cipher-selftest.h \
pubkey.c pubkey-internal.h \
md.c \
kdf.c kdf-internal.h \
hmac-tests.c \
bithelp.h  \
bufhelp.h  \
primegen.c  \
hash-common.c hash-common.h \
dsa-common.c \
rmd.h

EXTRA_libcipher_la_SOURCES = \
arcfour.c \
blowfish.c blowfish-amd64.S \
cast5.c cast5-amd64.S \
crc.c \
des.c \
dsa.c \
elgamal.c \
ecc.c \
idea.c \
md4.c \
md5.c \
rijndael.c rijndael-tables.h rijndael-amd64.S \
rmd160.c \
rsa.c \
scrypt.c \
seed.c \
serpent.c serpent-sse2-amd64.S serpent-avx2-amd64.S \
sha1.c \
sha256.c \
sha512.c \
tiger.c \
whirlpool.c \
twofish.c twofish-amd64.S \
rfc2268.c \
camellia.c camellia.h camellia-glue.c camellia-aesni-avx-amd64.S

if ENABLE_O_FLAG_MUNGING
o_flag_munging = sed -e 's/-O\([2-9s][2-9s]*\)/-O1/' -e 's/-Ofast/-O1/g'
else
o_flag_munging = cat
endif


# We need to lower the optimization for this module.
tiger.o: $(srcdir)/tiger.c
	`echo $(COMPILE) -c $(srcdir)/tiger.c | $(o_flag_munging) `

tiger.lo: $(srcdir)/tiger.c
	`echo $(LTCOMPILE) -c $(srcdir)/tiger.c | $(o_flag_munging) `
