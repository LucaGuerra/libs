# $Id$

#
# Rules for invoking test suites.
#

TEST_DIRECTORY=		tests
TEST_TARGET=		test

TEST_FRAMEWORK?=	tet	# Or: 'atf', 'custom' or 'libtest'.

.if !target(${TEST_TARGET})
# The special target 'test' runs the test suite associated with a
# utility or library.
test:	all .PHONY
	(cd ${TOP}/${TEST_DIRECTORY}/${TEST_FRAMEWORK}/${.CURDIR:T} && \
	${MAKE} all && \
	${MAKE} ${TEST_TARGET})
.endif
