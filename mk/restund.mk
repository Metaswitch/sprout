# included mk file for the libre module

ifndef LIBRE_DIR
  include ${MK_DIR}/libre.mk
endif

RESTUND_DIR := ${MODULE_DIR}/restund

restund: libre
	${MAKE} -j1 -C ${RESTUND_DIR} LIBRE_MK=${LIBRE_DIR}/mk/re.mk \
		EXTRA_CFLAGS='-I${INCLUDE_DIR}/re -I${RESTUND_DIR}/include -D_GNU_SOURCE' \
                LIBRE_SO='${LIB_DIR}'
	${MAKE} -j1 -C ${RESTUND_DIR} install DESTDIR=${ROOT} \
		LIBRE_MK=${LIBRE_DIR}/mk/re.mk

restund_test:
	@echo "No tests for restund"

restund_clean:
	${MAKE} -j1 -C ${RESTUND_DIR} clean \
		LIBRE_MK=${LIBRE_DIR}/mk/re.mk

restund_distclean:
	${MAKE} -j1 -C ${RESTUND_DIR} distclean \
		LIBRE_MK=${LIBRE_DIR}/mk/re.mk

.PHONY: restund restund_test restund_clean restund_distclean
