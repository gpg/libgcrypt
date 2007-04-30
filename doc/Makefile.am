## Process this file with automake to create Makefile.in
# Copyright (C) 2002 Free Software Foundation, Inc.
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

EXTRA_DIST = README.apichanges HACKING 

DISTCLEANFILES = gcrypt.cps

info_TEXINFOS = gcrypt.texi
gcrypt_TEXINFOS = lgpl.texi gpl.texi


online: gcrypt.html gcrypt.pdf gcrypt.info
	set -e; \
	echo "Uploading current manuals to www.gnupg.org ..."; \
        user=werner ; dir="webspace/manuals/gcrypt-devel/" ; \
	(cd gcrypt.html && rsync -vr --exclude='.svn' .  \
	  $${user}@cvs.gnupg.org:$${dir} ); \
        rsync -v gcrypt.pdf gcrypt.info $${user}@cvs.gnupg.org:$${dir}

