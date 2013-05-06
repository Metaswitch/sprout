# curl1 test Makefile

all: build

ROOT := $(abspath $(shell pwd)/../../)
MK_DIR := ${ROOT}/mk

TARGET := curltest1
TARGET_SOURCES := curltest1.cpp

CPPFLAGS += -Wno-write-strings
CPPFLAGS += -I${ROOT}/include \
            -I${ROOT}/usr/include

LDFLAGS += -L${ROOT}/usr/lib
LDFLAGS += -lcurl

include ${MK_DIR}/platform.mk

test:
	@echo "No test for curl1test"

distclean: clean

.PHONY: test distclean
