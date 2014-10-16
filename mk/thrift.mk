# included mk file for the thrift module

THRIFT_DIR := ${MODULE_DIR}/thrift
THRIFT_BUILDCONF := ${THRIFT_DIR}/buildconf
THRIFT_CONFIGURE := ${THRIFT_DIR}/configure
THRIFT_MAKEFILE := ${THRIFT_DIR}/Makefile

${THRIFT_CONFIGURE}:
	cd ${THRIFT_DIR} && ./bootstrap.sh

${THRIFT_MAKEFILE}: ${THRIFT_CONFIGURE}
	cd ${THRIFT_DIR} && ${THRIFT_CONFIGURE}  --prefix=${INSTALL_DIR} --without-csharp --without-java --without-erlang --without-python --without-perl --without-php --without-ruby --without-haskell --without-go --without-d

thrift: ${THRIFT_MAKEFILE}
	make -C ${THRIFT_DIR}
	make -C ${THRIFT_DIR} install

thrift_test: ${THRIFT_MAKEFILE}
	make -C ${THRIFT_DIR} test

thrift_clean: ${THRIFT_MAKEFILE}
	make -C ${THRIFT_DIR} clean

thrift_distclean:
	# The following doesn't seem to work, so use git clean instead
	# make -C ${THRIFT_DIR} distclean
	cd ${THRIFT_DIR} && git clean -f -X -d

.PHONY: thrift thrift_test thrift_clean thrift_distclean
