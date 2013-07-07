# included mk file for the thrift module

THRIFT_DIR := ${MODULE_DIR}/thrift
THRIFT_CONFIGURE := ${THRIFT_DIR}/configure
THRIFT_MAKEFILE := ${THRIFT_DIR}/Makefile

${THRIFT_CONFIGURE}:
	cd ${THRIFT_DIR} && ./buildconf

${THRIFT_MAKEFILE}: ${THRIFT_CONFIGURE}
	cd ${THRIFT_DIR} && ./configure --without-csharp --without-java --without-erlang --without-python --without-perl --without-php --without-ruby --without-haskell --without-go --without-d

thrift: ${THRIFT_MAKEFILE}
	make -C ${THRIFT_DIR}

thrift_test: ${THRIFT_MAKEFILE}
	make -C ${THRIFT_DIR} test

thrift_clean: ${THRIFT_MAKEFILE}
	make -C ${THRIFT_DIR} clean

thrift_distclean: ${THRIFT_MAKEFILE}
	make -C ${THRIFT_DIR} distclean

.PHONY: thrift thrift_test thrift_clean thrift_distclean
