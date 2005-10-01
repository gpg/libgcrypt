noinst_LTLIBRARIES = libgcrypt-cipher-modules.la

libgcrypt_cipher_modules_la_SOURCES = \
blowfish.c blowfish.h \
des.c des.h \
arcfour.c arcfour.h \
cast5.c cast5.h \
rijndael.c rijndael.h \
twofish.c twofish.h \
serpent.c serpent.h \
rfc2268.c rfc2268.h

libgcrypt_cipher_modules_la_CFLAGS = \
-I$(top_srcdir)/src/subsystems \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src \
@GPG_ERROR_CFLAGS@
