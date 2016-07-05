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
DEB_NAMES += mangelwurzel-as mangelwurzel-as-dbg
DEB_NAMES += bono bono-dbg restund
DEB_NAMES += clearwater-sipp clearwater-sipp-dbg
DEB_NAMES += clearwater-sip-stress clearwater-sip-stress-stats clearwater-sip-perf

INCLUDE_DIR := ${INSTALL_DIR}/include
LIB_DIR := ${INSTALL_DIR}/lib

# Each submodule installs itself, thus updating timestamps of include and
# library files.
#
# To work around this, we install them elsewhere, and then synchronize them to allow
# incremental builds to work
PRE_ROOT := ${ROOT}/build/module-install
PRE_PREFIX := ${PRE_ROOT}/usr
PRE_INSTALL_DIR := ${PRE_PREFIX}
PRE_INCLUDE_DIR := ${PRE_INSTALL_DIR}/include
PRE_LIB_DIR := ${PRE_INSTALL_DIR}/lib

sync_install:
	# pkg-config generates files which explcitly refer to the pre synchronized
	# directory, so we need to fix them up
	sed -e 's/build\/module-install\///g' -i ${PRE_INSTALL_DIR}/lib/pkgconfig/*.pc

	# rsync using checksums, as the modification time is wrong. This may lead
	# to false negatives, but they are very unlikely and tricky to workaround
	rsync --links -v -r --checksum ${PRE_INSTALL_DIR}/ ${INSTALL_DIR}/

SUBMODULES := pjsip c-ares curl libevhtp libmemcached libre restund openssl websocketpp sipp sas-client thrift cassandra

include $(patsubst %, ${MK_DIR}/%.mk, ${SUBMODULES})
include ${MK_DIR}/sprout.mk

build: ${SUBMODULES} sync_install sprout scripts/sipp-stats/clearwater-sipp-stats-1.0.0.gem plugins-build

test: ${SUBMODULES} sync_install sprout_test plugins-test

full_test: ${SUBMODULES} sync_install sprout_full_test plugins-test

testall: $(patsubst %, %_test, ${SUBMODULES}) full_test

clean: $(patsubst %, %_clean, ${SUBMODULES}) sprout_clean plugins-clean
	rm -rf ${ROOT}/usr
	rm -rf ${ROOT}/build

distclean: $(patsubst %, %_distclean, ${SUBMODULES}) sprout_distclean
	rm -rf ${ROOT}/usr
	rm -rf ${ROOT}/build

.PHONY: plugins-build
plugins-build:
	find plugins -mindepth 1 -maxdepth 1 -type d -exec ${MAKE} -C {} build \;

.PHONY: plugins-test
plugins-test:
	find plugins -mindepth 1 -maxdepth 1 -type d -exec ${MAKE} -C {} test \;

.PHONY: plugins-clean
plugins-clean:
	find plugins -mindepth 1 -maxdepth 1 -type d -exec ${MAKE} -C {} clean \;

.PHONY: plugins-deb
plugins-deb:
	find plugins -mindepth 1 -maxdepth 1 -type d -exec ${MAKE} -C {} deb \;

.PHONY: plugins-deb-only
plugins-deb-only:
	find plugins -mindepth 1 -maxdepth 1 -type d -exec ${MAKE} -C {} deb-only \;

include build-infra/cw-deb.mk

deb-only: plugins-deb-only

.PHONY: deb
deb: build deb-only plugins-deb

.PHONY: all build test clean distclean

scripts/sipp-stats/clearwater-sipp-stats-1.0.0.gem : $(shell find scripts/sipp-stats/ -type f | grep -v ".gem")
	cd scripts/sipp-stats; gem build clearwater-sipp-stats.gemspec
