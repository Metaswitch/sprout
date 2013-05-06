# curl4 test Makefile

all: build

ROOT := $(abspath $(shell pwd)/../../)
MK_DIR := ${ROOT}/mk

VPATH += .:${ROOT}/sprout

TARGET := curltest4
TARGET_SOURCES := curltest4.cpp \
                  hssconnection.cpp

CPPFLAGS += -Wno-write-strings
CPPFLAGS += -I${ROOT}/include \
            -I${ROOT}/usr/include

LDFLAGS += -L${ROOT}/usr/lib
LDFLAGS += -lcurl \
	   -ljson_linux-gcc-4.4.6_libmt 

include ${MK_DIR}/platform.mk

test:
	@echo "No test for curl1test"

distclean: clean

.PHONY: test distclean
