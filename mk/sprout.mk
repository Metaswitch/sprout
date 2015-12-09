# included mk file for the sprout SIP router

ifndef PJSIP_DIR
  include ${MK_DIR}/pjsip.mk
endif

ifndef LIBMEM_DIR
  include ${MK_DIR}/libmemcached.mk
endif

SPROUT_DIR := ${ROOT}/src

sprout: pjsip libmemcached
	${MAKE} -C ${SPROUT_DIR}

sprout_test:
	${MAKE} -C ${SPROUT_DIR} test

sprout_full_test:
	${MAKE} -C ${SPROUT_DIR} full_test

sprout_clean:
	${MAKE} -C ${SPROUT_DIR} clean

sprout_distclean: sprout_clean

.PHONY: sprout sprout_test sprout_clean sprout_distclean
