# included mk file for the cassandra module

CASSANDRA_DIR := ${MODULE_DIR}/cassandra
CASSANDRA_BUILD_DIR := ${ROOT}/build/cassandra
CASSANDRA_THRIFT_DIR := ${CASSANDRA_BUILD_DIR}/interface/thrift
CASSANDRA_GEN_DIR := ${CASSANDRA_THRIFT_DIR}/gen-cpp
CASSANDRA_CPP_SENTINEL := ${CASSANDRA_THRIFT_DIR}/gen-cpp/.cpp-built

CPP_FILES := Cassandra.cpp cassandra_types.cpp
LIB_FILE := libcassandra.so

C_PATHS := ${patsubst %.cpp,${CASSANDRA_GEN_DIR}/%.cpp,${CPP_FILES}}
O_PATHS := ${patsubst %.cpp,${CASSANDRA_GEN_DIR}/%.o,${CPP_FILES}}
D_PATHS := ${patsubst %.cpp,${CASSANDRA_GEN_DIR}/%.d,${CPP_FILES}}
LIB_PATH := ${INSTALL_DIR}/lib/${LIB_FILE}

CPP_FLAGS := -DHAVE_INTTYPES_H -DHAVE_NETINET_IN_H -I ${INSTALL_DIR}/include/ -I ${CASSANDRA_GEN_DIR}/ -fPIC
LD_FLAGS := -shared -Wl,-soname,${LIB_FILE}

${CASSANDRA_BUILD_DIR}:
	mkdir -p ${CASSANDRA_BUILD_DIR}

${CASSANDRA_BUILD_DIR}/interface/thrift:
	mkdir -p ${CASSANDRA_BUILD_DIR}/interface/thrift

cassandra: ${LIB_PATH}

${CASSANDRA_CPP_SENTINEL} : ${CASSANDRA_DIR}/interface/cassandra.thrift ${CASSANDRA_THRIFT_DIR} ${INSTALL_DIR}/bin/thrift
	${INSTALL_DIR}/bin/thrift --gen cpp -o ${CASSANDRA_THRIFT_DIR} ${CASSANDRA_DIR}/interface/cassandra.thrift
	cp ${CASSANDRA_GEN_DIR}/*.h ${INSTALL_DIR}/include/
	touch $@

${C_PATHS}: ${CASSANDRA_CPP_SENTINEL}

${CASSANDRA_GEN_DIR}/%.d: ${CASSANDRA_GEN_DIR}/%.cpp
	g++ -MM ${CPP_FLAGS} $< > $@

${CASSANDRA_GEN_DIR}/%.o: ${CASSANDRA_GEN_DIR}/%.cpp
	g++ -c -o $@ ${CPP_FLAGS} $<

${LIB_PATH}: ${O_PATHS}
	g++ -o ${LIB_PATH} ${LD_FLAGS} ${CPP_FLAGS} $+

cassandra_test:

cassandra_clean:
	rm -rf ${CASSANDRA_GEN_DIR}

cassandra_distclean:
	rm -rf ${CASSANDRA_BUILD_DIR}

include ${D_PATHS}

.PHONY: cassandra cassandra_test cassandra_clean cassandra_distclean
