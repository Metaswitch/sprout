# included mk file for the sipp module

SIPP_DIR := ${MODULE_DIR}/sipp

sipp:
	cd ${SIPP_DIR} && autoreconf -vifs && ./configure --with-rtpstream && make

sipp_test:
	true

sipp_clean:
	${MAKE} -C ${SIPP_DIR} clean

sipp_distclean: sipp_clean

.PHONY: sipp sipp_test sipp_clean sipp_distclean
