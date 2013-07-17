# store-read store-write Makefile

ROOT := $(abspath $(shell pwd)/../../)
MK_DIR := ${ROOT}/mk
BUILD_DIR := ${ROOT}/build
BIN_DIR := ${BUILD_DIR}/bin
OBJ_DIR := ${BUILD_DIR}/obj/storetest

include ${MK_DIR}/linux.mk

CPPFLAGS += -Wno-write-strings \
            -ggdb3 -std=c++0x
CPPFLAGS += -I${ROOT}/include \
            -I${ROOT}/usr/include

LDFLAGS += -L${ROOT}/usr/lib
LDFLAGS += -ldl \
					 -lrt \
           -lboost_regex \
           -lboost_system \
           -lboost_thread \
           -lboost_date_time

# Statically link libmemcached
SLIBS = ${ROOT}/usr/lib/libmemcached.a ${ROOT}/usr/lib/libmemcachedutil.a ${ROOT}/usr/lib/libmemcachedprotocol.a

# .cpp files will either be local or in the sprout directory							
vpath %.cpp .:${ROOT}/sprout

OBJS_READ  := $(addprefix $(OBJ_DIR)/,store-read.o memcachedstore.o store.o logger.o utils.o log.o)
OBJS_WRITE := $(addprefix $(OBJ_DIR)/,store-write.o memcachedstore.o store.o logger.o utils.o log.o)

.PHONY: all
all: $(BIN_DIR)/store-read $(BIN_DIR)/store-write

.PHONY: clean
clean:
	rm -f $(BIN_DIR)/store-read $(BIN_DIR)/store-write
	rm -f ${OBJS_READ} ${OBJS_WRITE}

$(OBJS_READ): | $(OBJ_DIR)
$(OBJS_WRITE): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(BIN_DIR)/store-read : $(OBJS_READ)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^ $(SLIBS) $(LDFLAGS) $(TARGET_ARCH) $(LOADLIBES) $(LDLIBS)

$(BIN_DIR)/store-write : $(OBJS_WRITE)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^ $(SLIBS) $(LDFLAGS) $(TARGET_ARCH) $(LOADLIBES) $(LDLIBS)

$(OBJ_DIR)/%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c -o $@ $<


