# included mk file for the libevhtp module

LIBEVHTP_DIR := ${MODULE_DIR}/libevhtp
LIBEVHTP_BUILD_DIR := ${ROOT}/build/libevhtp
LIBEVHTP_MAKEFILE := ${LIBEVHTP_BUILD_DIR}/build/Makefile

${LIBEVHTP_BUILD_DIR}:
	mkdir -p ${LIBEVHTP_BUILD_DIR}

${LIBEVHTP_MAKEFILE}: ${LIBEVHTP_BUILD_DIR}
	cd ${LIBEVHTP_BUILD_DIR} && cmake ${LIBEVHTP_DIR} -DEVHTP_DISABLE_SSL=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DEVHTP_DISABLE_REGEX=ON -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}

libevhtp: ${LIBEVHTP_MAKEFILE}
	make -C ${LIBEVHTP_BUILD_DIR}
	make -C ${LIBEVHTP_BUILD_DIR} install

libevhtp_test: ${LIBEVHTP_MAKEFILE}
	make -C ${LIBEVHTP_BUILD_DIR} test

libevhtp_clean: ${LIBEVHTP_MAKEFILE}
	make -C ${LIBEVHTP_BUILD_DIR} clean

libevhtp_distclean:
	rm -rf ${LIBEVHTP_BUILD_DIR}

.PHONY: libevhtp libevhtp_test libevhtp_clean libevhtp_distclean
