# included mk file for the curl module

CURL_DIR := ${MODULE_DIR}/curl
CURL_CONFIGURE := ${CURL_DIR}/configure
CURL_MAKEFILE := ${CURL_DIR}/Makefile

${CURL_CONFIGURE}:
	cd ${CURL_DIR} && ./buildconf

${CURL_MAKEFILE}: ${CURL_CONFIGURE}
	cd ${CURL_DIR} && ./configure --prefix=${INSTALL_DIR} --enable-ares=${INSTALL_DIR}

curl: ${CURL_MAKEFILE}
	make -C ${CURL_DIR}
	make -C ${CURL_DIR} install

curl_test: ${CURL_MAKEFILE}
	make -C ${CURL_DIR} test

curl_clean: ${CURL_MAKEFILE}
	make -C ${CURL_DIR} clean

curl_distclean: ${CURL_MAKEFILE}
	make -C ${CURL_DIR} distclean

.PHONY: curl curl_test curl_clean curl_distclean
