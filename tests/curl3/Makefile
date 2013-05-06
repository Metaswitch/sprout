# curl3 test Makefile

all: build

ROOT := $(abspath $(shell pwd)/../../)
MK_DIR := ${ROOT}/mk

TARGET := curltest3
TARGET_SOURCES := curltest3.cpp

CPPFLAGS += -Wno-write-strings
CPPFLAGS += -I${ROOT}/include \
            -I${ROOT}/usr/include

LDFLAGS += -L${ROOT}/usr/lib
LDFLAGS += -lcurl \
	   -ljson_linux-gcc-4.4.6_libmt 

include ${MK_DIR}/platform.mk

test:
	@echo "No test for curl3test"

distclean: clean

.PHONY: test distclean
