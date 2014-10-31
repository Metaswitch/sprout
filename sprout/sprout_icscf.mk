# sprout-icscf Makefile

all: stage-build

ROOT := $(abspath $(shell pwd)/../)
MK_DIR := ${ROOT}/mk

TARGET := sprout_icscf.so
TARGET_TEST := sprout_icscf.so_test

TARGET_SOURCES := icscfsproutlet.cpp \
                  icscfrouter.cpp \
                  scscfselector.cpp \
                  icscfplugin.cpp

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

# Production build:
#
# Enable optimization in production only.
CPPFLAGS := $(filter-out -O2,$(CPPFLAGS))
CPPFLAGS_BUILD += -O2

LDFLAGS += -L${ROOT}/usr/lib -shared

include ${MK_DIR}/platform.mk

.PHONY: stage-build
stage-build: build

.PHONY: distclean
distclean: clean
