# included mk file for the pjsip module

PJSIP_DIR := ${MODULE_DIR}/pjsip
PJSIP_CONFIG_ARTIFACT := ${PJSIP_DIR}/build.mak

${PJSIP_CONFIG_ARTIFACT}: 
	cd ${MODULE_DIR}/pjsip && ./configure --without-ffmpeg --disable-ffmpeg --prefix=${INSTALL_DIR} --enable-epoll CFLAGS=-ggdb3

pjsip: ${PJSIP_CONFIG_ARTIFACT}
	make -C ${MODULE_DIR}/pjsip dep
	make -C ${MODULE_DIR}/pjsip
	make -C ${MODULE_DIR}/pjsip install

pjsip_test:
	make -C ${MODULE_DIR}/pjsip selftest

pjsip_clean:
	make -C ${MODULE_DIR}/pjsip clean

pjsip_distclean:
	make -C ${MODULE_DIR}/pjsip distclean

.PHONY: pjsip pjsip_test pjsip_clean pjsip_distclean
