# doc/Makefile.am

MANPAGEEN=${srcdir}/tcprelay.1
HTMLPAGEEN=${srcdir}/tcprelay.html

dist_doc_DATA=${HTMLPAGEEN}

EXTRA_DIST=${HTMLPAGEEN}

dist_man_MANS=${MANPAGEEN}

if BUILD_DOCS

${HTMLPAGEEN}: ${MANPAGEEN}
	man2html ${MANPAGEEN} > $@

endif

