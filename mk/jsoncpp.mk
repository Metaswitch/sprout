# included mk file for the jsoncpp module

JSONCPP_DIR := ${MODULE_DIR}/jsoncpp
JSONCPP_PLATFORM := linux-gcc

jsoncpp: ${INCLUDE_DIR} ${LIB_DIR}
	cd ${JSONCPP_DIR} && scons platform=${JSONCPP_PLATFORM} check
	cp ${JSONCPP_DIR}/libs/linux-*/*.so ${LIB_DIR}/libjsoncpp.so
	cp ${JSONCPP_DIR}/libs/linux-*/*.a ${LIB_DIR}/libjsoncpp.a
	cp -r ${JSONCPP_DIR}/include/json ${INCLUDE_DIR}

jsoncpp_test:
	cd ${JSONCPP_DIR} && scons platform=${JSONCPP_PLATFORM} check

jsoncpp_clean:
	rm -rf ${JSONCPP_DIR}/bin ${JSONCPP_DIR}/libs

jsoncpp_distclean: jsoncpp_clean

.PHONY: jsoncpp jsoncpp_test jsoncpp_clean jsoncpp_distclean
