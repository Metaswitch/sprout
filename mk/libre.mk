# included mk file for the libre module

LIBRE_DIR := ${MODULE_DIR}/libre
LIBRE_FLAGS := EXTRA_CFLAGS="-D_GNU_SOURCE"

libre:
	make -C ${LIBRE_DIR} ${LIBRE_FLAGS}
	make -C ${LIBRE_DIR} install DESTDIR=${ROOT} ${LIBRE_FLAGS}

libre_test:
	@echo "No tests for libre"

libre_clean:
	make -C ${LIBRE_DIR} clean

libre_distclean:
	make -C ${LIBRE_DIR} distclean

.PHONY: libre libre_test libre_clean libre_distclean