# included mk file for the cassandra module

CASSANDRA_DIR := ${MODULE_DIR}/cassandra
THRIFT_DIR := ${MODULE_DIR}/thrift

cassandra:
	${THRIFT_DIR}/compiler/thrift --gen cpp -o ${CASSANDRA_DIR}/interface/thrift ${CASSANDRA_DIR}/interface/cassandra.thrift
	g++ -shared -Wl,-soname,libcassandra.so -fPIC -o ${INSTALL_DIR}/usr/lib/libcassandra.so -DHAVE_INTTYPES_H -DHAVE_NETINET_IN_H -I ${THRIFT_DIR}/lib/cpp/src/ -I ${CASSANDRA_DIR}/interface/thrift/gen-cpp/ ${CASSANDRA_DIR}/interface/thrift/gen-cpp/Cassandra.cpp ${CASSANDRA_DIR}/interface/thrift/gen-cpp/cassandra_types.cpp

cassandra_test:

cassandra_clean:
	rm -rf ${CASSANDRA_DIR}/interface/thrift/gen-cpp

cassandra_distclean:
	rm -rf ${CASSANDRA_DIR}/interface/thrift/gen-cpp

.PHONY: cassandra cassandra_test cassandra_clean cassandra_distclean
