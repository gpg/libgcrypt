# Makefile for cipher modules
# Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.
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

if USE_ARCFOUR
  tmp_arcfour = arcfour.c
endif
if USE_BLOWFISH
  tmp_blowfish = blowfish.c
endif
if USE_CAST5
  tmp_cast5 = cast5.c
endif
if USE_DES
  tmp_des = des.c
endif
if USE_AES
  tmp_aes = rijndael.c
endif
if USE_TWOFISH
  tmp_twofish = twofish.c
endif

ciphers = \
$(tmp_arcfour) \
$(tmp_blowfish) \
$(tmp_cast5) \
$(tmp_des) \
$(tmp_aes) \
$(tmp_twofish)

if USE_DSA
  tmp_dsa = dsa.c
endif
if USE_RSA
  tmp_rsa = rsa.c
endif
if USE_ELGAMAL
  tmp_elgamal = elgamal.c
endif

pubkey_ciphers = \
$(tmp_dsa) \
$(tmp_rsa) \
$(tmp_elgamal)

if USE_CRC
  tmp_crc = crc.c
endif
if USE_MD4
  tmp_md4 = md4.c
endif
if USE_MD5
  tmp_md5 = md5.c
endif
if USE_SHA1
  tmp_sha1 = sha1.c
endif
if USE_SHA256
  tmp_sha256 = sha256.c
endif
if USE_TIGER
  tmp_tiger = tiger.c
endif
if USE_RMD160
  tmp_rmd160 = rmd160.c
endif

digests = \
$(tmp_crc) \
$(tmp_md4) \
$(tmp_md5) \
$(tmp_sha1) \
$(tmp_sha256) \
$(tmp_tiger) \
$(tmp_rmd160)

if USE_RNDLINUX
  tmp_rndlinux = rndlinux.c
endif
if USE_RNDUNIX
  tmp_rndunix = rndunix.c
endif
if USE_RNDEGD
  tmp_rndegd = rndegd.c
endif
if USE_RNDW32
  tmp_rndw32 = rndw32.c
endif

random = \
$(tmp_rndlinux) \
$(tmp_rndunix) \
$(tmp_rndegd) \
$(tmp_rndw32)

libcipher_la_LDFLAGS =
libcipher_la_SOURCES = \
cipher.c $(ciphers) \
pubkey.c $(pubkey_ciphers) \
md.c  $(digests) \
bithelp.h   \
primegen.c  \
random.c random.h $(random) \
rand-internal.h \
rmd.h

# We need to lower the optimization for this module.
tiger.o: $(srcdir)/tiger.c
	`echo $(COMPILE) -c $(srcdir)/tiger.c | sed -e 's/-O[2-9s]*/-O1/g' `

tiger.lo: $(srcdir)/tiger.c
	`echo $(LTCOMPILE) -c $(srcdir)/tiger.c | sed -e 's/-O[2-9s]*/-O1/g' `
