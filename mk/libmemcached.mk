# included mk file for the libmemcached module

LIBMEM_DIR := ${MODULE_DIR}/libmemcached
LIBMEM_CONFIGURE := ${LIBMEM_DIR}/configure
LIBMEM_MAKEFILE := ${LIBMEM_DIR}/Makefile

${LIBMEM_CONFIGURE}:
	cd ${LIBMEM_DIR} && ./config/autorun.sh

${LIBMEM_MAKEFILE}: ${LIBMEM_CONFIGURE}
	cd ${LIBMEM_DIR} && ./configure --prefix=${INSTALL_DIR} \
		--with-lib-prefix=${INSTALL_DIR} \
		CFLAGS="-I${INSTALL_DIR}/include" \
		LDFLAGS="-L${INSTALL_DIR}/lib"

libmemcached: libevhtp ${LIBMEM_MAKEFILE}
	${MAKE} -C ${LIBMEM_DIR}
	${MAKE} -C ${LIBMEM_DIR} install

libmemcached_test: libevhtp ${LIBMEM_MAKEFILE}
	${MAKE} -C ${LIBMEM_DIR} test

libmemcached_clean: ${LIBMEM_MAKEFILE}
	${MAKE} -C ${LIBMEM_DIR} clean
	rm ${LIBMEM_CONFIGURE}

libmemcached_distclean: ${LIBMEM_MAKEFILE}
	${MAKE} -C ${LIBMEM_DIR} distclean
	rm ${LIBMEM_CONFIGURE}

.PHONY: libmemcached libmemcached_test libmemcached_clean libmemcached_distclean
