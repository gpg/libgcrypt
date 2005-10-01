SUBDIRS = \
include \
liberty \
common \
ath \
subsystems \
modules \
compat \
scripts

EXTRA_DIST = OVERVIEW libgcrypt-config.in libgcrypt.m4 \
libgcrypt.vers libgcrypt-core.vers ChangeLog.old

lib_LTLIBRARIES = libgcrypt-core.la libgcrypt.la

if HAVE_LD_VERSION_SCRIPT
  libgcrypt_core_version_script_cmd = -Wl,--version-script=$(srcdir)/libgcrypt-core.vers
else
  libgcrypt_core_version_script_cmd = 
endif

if HAVE_LD_VERSION_SCRIPT
  libgcrypt_version_script_cmd = -Wl,--version-script=$(srcdir)/libgcrypt.vers
else
  libgcrypt_version_script_cmd = 
endif

libgcrypt_core_la_SOURCES =
libgcrypt_la_SOURCES =

libgcrypt_core_la_LDFLAGS = $(libgcrypt_core_version_script_cmd) -version-info \
	@LIBGCRYPT_LT_CURRENT@:@LIBGCRYPT_LT_REVISION@:@LIBGCRYPT_LT_AGE@
libgcrypt_la_LDFLAGS = $(libgcrypt_version_script_cmd) -version-info \
	@LIBGCRYPT_LT_CURRENT@:@LIBGCRYPT_LT_REVISION@:@LIBGCRYPT_LT_AGE@

# FIXME: liberty missing (did not get built for whatever reason?)

libgcrypt_core_la_DEPENDENCIES = \
ath/libgcrypt-ath.la \
common/libgcrypt-common.la \
subsystems/hash/libgcrypt-md.la \
subsystems/asym-cipher/libgcrypt-ac.la \
subsystems/sym-cipher/libgcrypt-cipher.la \
modules/hash/libgcrypt-md-modules.la \
modules/asym-cipher/libgcrypt-ac-modules.la \
modules/sym-cipher/libgcrypt-cipher-modules.la \
subsystems/mpi/libgcrypt-mpi.la \
subsystems/prime/libgcrypt-prime.la \
subsystems/random/libgcrypt-random.la \
subsystems/secmem/libgcrypt-secmem.la \
subsystems/sexp/libgcrypt-sexp.la \
$(srcdir)/libgcrypt-core.vers

libgcrypt_la_DEPENDENCIES = \
ath/libgcrypt-ath.la \
common/libgcrypt-common.la \
compat/libgcrypt-compat.la \
subsystems/hash/libgcrypt-md.la \
subsystems/asym-cipher/libgcrypt-ac.la \
modules/hash/libgcrypt-md-modules.la \
modules/asym-cipher/libgcrypt-ac-modules.la \
modules/sym-cipher/libgcrypt-cipher-modules.la \
subsystems/mpi/libgcrypt-mpi.la \
subsystems/prime/libgcrypt-prime.la \
subsystems/random/libgcrypt-random.la \
subsystems/secmem/libgcrypt-secmem.la \
subsystems/sexp/libgcrypt-sexp.la \
subsystems/sym-cipher/libgcrypt-cipher.la \
$(srcdir)/libgcrypt.vers

libgcrypt_core_la_LIBADD = \
ath/libgcrypt-ath.la \
common/libgcrypt-common.la \
subsystems/hash/libgcrypt-md.la \
subsystems/asym-cipher/libgcrypt-ac.la \
modules/hash/libgcrypt-md-modules.la \
modules/asym-cipher/libgcrypt-ac-modules.la \
modules/sym-cipher/libgcrypt-cipher-modules.la \
subsystems/mpi/libgcrypt-mpi.la \
subsystems/prime/libgcrypt-prime.la \
subsystems/random/libgcrypt-random.la \
subsystems/secmem/libgcrypt-secmem.la \
subsystems/sexp/libgcrypt-sexp.la \
subsystems/sym-cipher/libgcrypt-cipher.la \
@LTLIBOBJS@ \
@GPG_ERROR_LIBS@

libgcrypt_la_LIBADD = \
ath/libgcrypt-ath.la \
common/libgcrypt-common.la \
compat/libgcrypt-compat.la \
subsystems/hash/libgcrypt-md.la \
subsystems/asym-cipher/libgcrypt-ac.la \
modules/hash/libgcrypt-md-modules.la \
modules/asym-cipher/libgcrypt-ac-modules.la \
modules/sym-cipher/libgcrypt-cipher-modules.la \
subsystems/mpi/libgcrypt-mpi.la \
subsystems/prime/libgcrypt-prime.la \
subsystems/random/libgcrypt-random.la \
subsystems/secmem/libgcrypt-secmem.la \
subsystems/sexp/libgcrypt-sexp.la \
subsystems/sym-cipher/libgcrypt-cipher.la \
@LTLIBOBJS@ \
@GPG_ERROR_LIBS@
