# included mk file for the c-ares module

C_ARES_DIR := ${MODULE_DIR}/c-ares
C_ARES_CONFIGURE := ${C_ARES_DIR}/configure
C_ARES_MAKEFILE := ${C_ARES_DIR}/Makefile

${C_ARES_CONFIGURE}:
	cd ${C_ARES_DIR} && ./buildconf

${C_ARES_MAKEFILE}: ${C_ARES_CONFIGURE}
	cd ${C_ARES_DIR} && ./configure --prefix=${INSTALL_DIR}

c-ares: ${C_ARES_MAKEFILE}
	make -C ${C_ARES_DIR}
	make -C ${C_ARES_DIR} install

c-ares_test:
	true

c-ares_clean: ${C_ARES_MAKEFILE}
	make -C ${C_ARES_DIR} clean

c-ares_distclean: ${C_ARES_MAKEFILE}
	make -C ${C_ARES_DIR} distclean

.PHONY: c-ares c-ares_test c-ares_clean c-ares_distclean
