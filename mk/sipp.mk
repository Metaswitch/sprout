# included mk file for the sipp module

SIPP_DIR := ${MODULE_DIR}/sipp

sipp:
	${MAKE} -j1 -C ${SIPP_DIR} debug_ossl

sipp_test:
	true

sipp_clean:
	${MAKE} -j1 -C ${SIPP_DIR} clean

sipp_distclean: sipp_clean

.PHONY: sipp sipp_test sipp_clean sipp_distclean
