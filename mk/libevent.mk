# included mk file for the libevent module

LIBEVENT_DIR := ${MODULE_DIR}/libevent
LIBEVENT_CONFIGURE := ${LIBEVENT_DIR}/configure
LIBEVENT_MAKEFILE := ${LIBEVENT_DIR}/Makefile


${LIBEVENT_CONFIGURE}:
	cd modules/libevent && ./autogen.sh

${LIBEVENT_MAKEFILE}: ${LIBEVENT_CONFIGURE}
	cd modules/libevent && ./configure --prefix=${INSTALL_DIR}

libevent: ${LIBEVENT_MAKEFILE}
	make -C ${LIBEVENT_DIR}
	make -C ${LIBEVENT_DIR} install

libevent_test: ${LIBEVENT_MAKEFILE}
	make -C ${LIBEVENT_DIR} check

libevent_clean: ${LIBEVENT_MAKEFILE}
	make -C ${LIBEVENT_DIR} clean

libevent_distclean: ${LIBEVENT_MAKEFILE}
	make -C ${LIBEVENT_DIR} distclean

.PHONY: libevent libevent_test libevent_clean libevent_distclean