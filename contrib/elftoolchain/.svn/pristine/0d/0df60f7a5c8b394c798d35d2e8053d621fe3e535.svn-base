#
# Rules for recursing into directories
# $Id$

# Pass down 'test' as a valid target.

.include "$(TOP)/mk/elftoolchain.os.mk"

.if ${OS_HOST} == FreeBSD
SUBDIR_TARGETS+=	clobber test
.elif ${OS_HOST} == OpenBSD
clobber: _SUBDIRUSE
.elif ${OS_HOST} == Linux  # Ubuntu 'bmake' version 20200710-15.
SUBDIR_TARGETS+=	cleandepend clobber test
.else		# NetBSD
TARGETS+=	cleandepend clobber test
.endif

.include <bsd.subdir.mk>
