# memento-sip Makefile

all: stage-build

ROOT := $(abspath $(shell pwd)/../)
MK_DIR := ${ROOT}/mk

TARGET := memento-sip.so

TARGET_SOURCES := sproutletappserver.cpp \
                  memento-sipplugin.cpp

CPPFLAGS += -Wno-write-strings \
            -ggdb3 -std=c++0x

#	Build location independent code for shared object
CPPFLAGS += -fpic
CPPFLAGS += -I${ROOT}/include \
            -I${ROOT}/modules/cpp-common/include \
            -I${ROOT}/modules/app-servers/include \
            -I${ROOT}/usr/include \
            -I${ROOT}/modules/rapidjson/include

CPPFLAGS += $(shell PKG_CONFIG_PATH=${ROOT}/usr/lib/pkgconfig pkg-config --cflags libpjproject)

# Add cpp-common/src as VPATH so build will find modules there.
VPATH = ${ROOT}/modules/cpp-common/src:

# Production build:
#
# Enable optimization in production only.
CPPFLAGS := $(filter-out -O2,$(CPPFLAGS))
CPPFLAGS_BUILD += -O2

LDFLAGS += -L${ROOT}/usr/lib -shared

LDFLAGS_BUILD += -lmemento -lthrift -lcassandra

include ${MK_DIR}/platform.mk

.PHONY: stage-build
stage-build: build

.PHONY: debug
debug: | build_test
	gdb --args $(TARGET_BIN_TEST) $(EXTRA_TEST_ARGS)

.PHONY: distclean
distclean: clean
