# included mk file for the sprout SIP router

ifndef PJSIP_DIR
  include ${MK_DIR}/pjsip.mk
endif

ifndef LIBMEM_DIR
  include ${MK_DIR}/libmemcached.mk
endif

SPROUT_DIR := ${ROOT}/sprout
SPROUT_TEST_DIR := ${ROOT}/tests

sprout: pjsip libmemcached
	make -C ${SPROUT_DIR}

sprout_test:
	make -C ${SPROUT_DIR} test

sprout_clean:
	make -C ${SPROUT_DIR} clean
	-make -C ${SPROUT_TEST_DIR} clean

sprout_distclean: sprout_clean

.PHONY: sprout sprout_test sprout_clean sprout_distclean
