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
	make -f sprout_base.mk -C ${SPROUT_DIR}
	make -f sprout_scscf.mk -C ${SPROUT_DIR}
	make -f sprout_icscf.mk -C ${SPROUT_DIR}
	make -f sprout_bgcf.mk -C ${SPROUT_DIR}
	make -f sprout_mmtel_as.mk -C ${SPROUT_DIR}
	make -f gemini.mk -C ${SPROUT_DIR}
	make -f memento-sip.mk -C ${SPROUT_DIR}
sprout_test:
	make -C ${SPROUT_DIR} test

sprout_clean:
	make -f sprout_base.mk -C ${SPROUT_DIR} clean
	make -f sprout_scscf.mk -C ${SPROUT_DIR} clean
	make -f sprout_icscf.mk -C ${SPROUT_DIR} clean
	make -f sprout_bgcf.mk -C ${SPROUT_DIR} clean
	make -f sprout_mmtel_as.mk -C ${SPROUT_DIR} clean
	make -f gemini.mk -C ${SPROUT_DIR} clean
	make -f memento-sip.mk -C ${SPROUT_DIR} clean
	make -C ${SPROUT_DIR} clean
	-make -C ${SPROUT_TEST_DIR} clean

sprout_distclean: sprout_clean

.PHONY: sprout sprout_test sprout_clean sprout_distclean
