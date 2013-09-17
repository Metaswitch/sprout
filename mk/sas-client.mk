# included mk file for the sas-client  module

SAS_CLIENT_DIR := ${MODULE_DIR}/sas-client

sas-client: 
	make -C ${SAS_CLIENT_DIR}
	cp ${SAS_CLIENT_DIR}/*.a ${LIB_DIR}/
	cp ${SAS_CLIENT_DIR}/include/*.h ${INCLUDE_DIR}

sas-client_test:
	@echo "No tests for sas-client"

sas-client_clean:
	make -C ${SAS_CLIENT_DIR} clean

sas-client_distclean:
	make -C ${SAS_CLIENT_DIR} clean

.PHONY: sas-client sas-client_test sas-client_clean sas-client_distclean
