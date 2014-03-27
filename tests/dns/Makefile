# dnstest/sipresolvertest Makefile

ROOT := $(abspath $(shell pwd)/../../)
MK_DIR := ${ROOT}/mk
BUILD_DIR := ${ROOT}/build
BIN_DIR := ${BUILD_DIR}/bin
OBJ_DIR := ${BUILD_DIR}/obj/dnstest

include ${MK_DIR}/linux.mk

CPPFLAGS += -Wno-write-strings \
            -ggdb3 -std=c++0x
CPPFLAGS += -I${ROOT}/include \
						-I${ROOT}/modules/cpp-common/include \
            -I${ROOT}/usr/include

LDFLAGS += -L${ROOT}/usr/lib
LDFLAGS += -ldl \
					 -lrt \
           -lcares \
					 -lpthread \
           -lboost_regex \
           -lboost_system \
           -lboost_thread \
           -lboost_date_time

# .cpp files will either be local or in the sprout directory or the cpp-common directory							
vpath %.cpp .:${ROOT}/sprout:${ROOT}/modules/cpp-common/src

OBJS_DNSTEST         := $(addprefix $(OBJ_DIR)/,dnstest.o dnsparser.o dnscachedresolver.o utils.o logger.o log.o)
OBJS_SIPRESOLVETEST  := $(addprefix $(OBJ_DIR)/,sipresolvetest.o sipresolver.o baseresolver.o dnsparser.o dnscachedresolver.o utils.o logger.o log.o)

.PHONY: all
all: $(BIN_DIR)/dnstest
all: $(BIN_DIR)/sipresolvetest

.PHONY: clean
clean:
	rm -f $(BIN_DIR)/dnstest
	rm -f $(BIN_DIR)/sipresolvetest
	rm -f ${OBJS_DNSTEST}
	rm -f ${OBJS_SIPRESOLVETEST}

$(OBJS_DNSTEST): | $(OBJ_DIR)

$(OBJS_SIPRESOLVETEST): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/dnstest : $(OBJS_DNSTEST) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS) $(TARGET_ARCH) $(LOADLIBES) $(LDLIBS)

$(BIN_DIR)/sipresolvetest : $(OBJS_SIPRESOLVETEST) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS) $(TARGET_ARCH) $(LOADLIBES) $(LDLIBS)

$(OBJ_DIR)/%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c -o $@ $<


