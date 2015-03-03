# included mk file for the cassandra module

CASSANDRA_DIR := ${MODULE_DIR}/cassandra
CASSANDRA_BUILD_DIR := ${ROOT}/build/cassandra

${CASSANDRA_BUILD_DIR}:
	mkdir -p ${CASSANDRA_BUILD_DIR}

${CASSANDRA_BUILD_DIR}/interface/thrift:
	mkdir -p ${CASSANDRA_BUILD_DIR}/interface/thrift

cassandra: ${CASSANDRA_BUILD_DIR}/interface/thrift
	${INSTALL_DIR}/bin/thrift --gen cpp -o ${CASSANDRA_BUILD_DIR}/interface/thrift ${CASSANDRA_DIR}/interface/cassandra.thrift
	g++ -shared -Wl,-soname,libcassandra.so -fPIC -o ${INSTALL_DIR}/lib/libcassandra.so -DHAVE_INTTYPES_H -DHAVE_NETINET_IN_H -I ${INSTALL_DIR}/include/ -I ${CASSANDRA_BUILD_DIR}/interface/thrift/gen-cpp/ ${CASSANDRA_BUILD_DIR}/interface/thrift/gen-cpp/Cassandra.cpp ${CASSANDRA_BUILD_DIR}/interface/thrift/gen-cpp/cassandra_types.cpp
	cp ${CASSANDRA_BUILD_DIR}/interface/thrift/gen-cpp/*.h ${INSTALL_DIR}/include/

cassandra_test:

cassandra_clean:
	rm -rf ${CASSANDRA_BUILD_DIR}/interface/thrift/gen-cpp

cassandra_distclean:
	rm -rf ${CASSANDRA_BUILD_DIR}

.PHONY: cassandra cassandra_test cassandra_clean cassandra_distclean
