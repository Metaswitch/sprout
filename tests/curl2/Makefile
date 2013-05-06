# curl2 test Makefile

all: build

ROOT := $(abspath $(shell pwd)/../../)
MK_DIR := ${ROOT}/mk

TARGET := curltest2
TARGET_SOURCES := curltest2.cpp

CPPFLAGS += -Wno-write-strings
CPPFLAGS += -I${ROOT}/include \
            -I${ROOT}/usr/include

LDFLAGS += -L${ROOT}/usr/lib
LDFLAGS += -lcurl

#include ${MK_DIR}/platform.mk

build:
	@echo "Curl2test is deprecated"

test:
	@echo "No test for curl2test"

distclean: clean

clean:

.PHONY: test distclean
