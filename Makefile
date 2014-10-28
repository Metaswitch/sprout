# Top level Makefile for building NGV Server components

# this should come first so make does the right thing by default

all: build

ROOT ?= ${PWD}
MK_DIR := ${ROOT}/mk
PREFIX ?= ${ROOT}/usr
INSTALL_DIR ?= ${PREFIX}
MODULE_DIR := ${ROOT}/modules

DEB_COMPONENT := sprout
DEB_MAJOR_VERSION := 1.0${DEB_VERSION_QUALIFIER}
DEB_NAMES := sprout-libs sprout-libs-dbg
DEB_NAMES += sprout sprout-dbg
DEB_NAMES += sprout-base sprout-base-dbg
DEB_NAMES += sprout-scscf sprout-scscf-dbg
DEB_NAMES += sprout-icscf sprout-icscf-dbg
DEB_NAMES += sprout-bgcf sprout-bgcf-dbg
DEB_NAMES += sprout-mmtel-as sprout-mmtel-as-dbg
DEB_NAMES += gemini-as gemini-as-dbg
DEB_NAMES += memento-as memento-as-dbg
DEB_NAMES += call-diversion-as call-diversion-as-dbg
DEB_NAMES += bono bono-dbg restund
DEB_NAMES += clearwater-sip-stress clearwater-sip-stress-dbg clearwater-sip-stress-stats

INCLUDE_DIR := ${INSTALL_DIR}/include
LIB_DIR := ${INSTALL_DIR}/lib

SUBMODULES := pjsip jsoncpp c-ares curl libevhtp libmemcached libre restund openssl websocketpp sipp sas-client thrift cassandra memento

include $(patsubst %, ${MK_DIR}/%.mk, ${SUBMODULES})
include ${MK_DIR}/sprout.mk

build: ${SUBMODULES} sprout scripts/sipp-stats/clearwater-sipp-stats-1.0.0.gem

test: ${SUBMODULES} sprout_test

testall: $(patsubst %, %_test, ${SUBMODULES}) test

clean: $(patsubst %, %_clean, ${SUBMODULES}) sprout_clean
	rm -rf ${ROOT}/usr
	rm -rf ${ROOT}/build

distclean: $(patsubst %, %_distclean, ${SUBMODULES}) sprout_distclean
	rm -rf ${ROOT}/usr
	rm -rf ${ROOT}/build

include build-infra/cw-deb.mk

.PHONY: deb
deb: build deb-only

.PHONY: all build test clean distclean

scripts/sipp-stats/clearwater-sipp-stats-1.0.0.gem : $(shell find scripts/sipp-stats/ -type f | grep -v ".gem")
	cd scripts/sipp-stats; gem build clearwater-sipp-stats.gemspec
