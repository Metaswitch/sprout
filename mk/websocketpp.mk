# included mk file for the websocket++ module

WEBSOCKETPP_DIR := ${MODULE_DIR}/websocketpp

websocketpp:
	make -C ${WEBSOCKETPP_DIR}
	make -C ${WEBSOCKETPP_DIR} install prefix=${PREFIX}

websocketpp_test:
	make -C ${WEBSOCKETPP_DIR}/test/basic BOOST_LIB_PATH=/usr/lib

websocketpp_clean:
	make -C ${WEBSOCKETPP_DIR} clean

websocketpp_distclean:
	make -C ${WEBSOCKETPP_DIR} clean

.PHONY: websocketpp websocketpp_test websocketpp_clean websocketpp_distclean
