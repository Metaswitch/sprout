# included mk file for the memento  module

MEMENTO_DIR := ${MODULE_DIR}/memento

memento:
	cd modules/memento && git submodule update --init && make -C ${MEMENTO_DIR} object
	cp ${MEMENTO_DIR}/*.a ${LIB_DIR}/
	cp ${MEMENTO_DIR}/usr/lib/libthrift* ${LIB_DIR}/
	cp ${MEMENTO_DIR}/usr/lib/libcassandra* ${LIB_DIR}/
	cp ${MEMENTO_DIR}/include/*.h ${INCLUDE_DIR}
	cp ${MEMENTO_DIR}/usr/include/*ass* ${INCLUDE_DIR}
	cp -R ${MEMENTO_DIR}/usr/include/thrift* ${INCLUDE_DIR}

memento_test:
	cd modules/memento && make -C ${MEMENTO_DIR} test

memento_clean:
	cd modules/memento && make -C ${MEMENTO_DIR} clean

memento_distclean:
	cd modules/memento && make -C ${MEMENTO_DIR} clean

.PHONY: memento memento_test memento_clean memento_distclean
