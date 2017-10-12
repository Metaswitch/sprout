# included mk file for the websocket++ module

WEBSOCKETPP_DIR := ${MODULE_DIR}/websocketpp

websocketpp:
	${MAKE} -j1 -C ${WEBSOCKETPP_DIR}
	${MAKE} -j1  -C ${WEBSOCKETPP_DIR} install prefix=${PREFIX}

websocketpp_test:
	${MAKE} -j1 -C ${WEBSOCKETPP_DIR}/test/basic BOOST_LIB_PATH=/usr/lib

websocketpp_clean:
	${MAKE} -j1 -C ${WEBSOCKETPP_DIR} clean

websocketpp_distclean:
	${MAKE} -j1 -C ${WEBSOCKETPP_DIR} clean

.PHONY: websocketpp websocketpp_test websocketpp_clean websocketpp_distclean
