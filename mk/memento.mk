# included mk file for the memento  module

MEMENTO_DIR := ${MODULE_DIR}/memento

memento:
	cd modules/memento && git submodule update --init && make -C ${MEMENTO_DIR}

memento_test:
	cd modules/memento && make -C ${MEMENTO_DIR} test

memento_clean:
	cd modules/memento && make -C ${MEMENTO_DIR} clean

memento_distclean:
	cd modules/memento && make -C ${MEMENTO_DIR} clean

.PHONY: memento memento_test memento_clean memento_distclean
