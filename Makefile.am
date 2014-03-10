# Makefile.am

SUBDIRS = src doc
ACLOCAL_AMFLAGS = -I admin

dist_doc_DATA=README

EXTRA_DIST=tcprelay.bkl gen-win-makefile.cmd makefile.gcc extracfg.h src/bsdstring.c

dist-hook:
	rm -rf `find $(distdir) -name .svn`

appsdir = $(datadir)/applications

