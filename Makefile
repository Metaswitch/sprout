# Top level Makefile for building NGV Server components

# this should come first so make does the right thing by default

all: build

ROOT ?= ${PWD}
MK_DIR := ${ROOT}/mk
PREFIX ?= ${ROOT}/usr
INSTALL_DIR ?= ${PREFIX}
MODULE_DIR := ${ROOT}/modules

DEB_COMPONENT := sprout
DEB_MAJOR_VERSION ?= 1.0${DEB_VERSION_QUALIFIER}
DEB_NAMES := sprout-libs sprout-libs-dbg
DEB_NAMES += sprout sprout-dbg
DEB_NAMES += sprout-node sprout-node-dbg
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
DEB_NAMES += bono-node bono-node-dbg
DEB_NAMES += clearwater-sipp clearwater-sipp-dbg
DEB_NAMES += clearwater-sip-stress clearwater-sip-stress-stats clearwater-sip-perf

INCLUDE_DIR := ${INSTALL_DIR}/include
LIB_DIR := ${INSTALL_DIR}/lib

SUBMODULES := pjsip c-ares curl libevhtp libmemcached libre restund openssl websocketpp sipp sas-client thrift cassandra

include build-infra/cw-module-install.mk

include $(patsubst %, ${MK_DIR}/%.mk, ${SUBMODULES})
include ${MK_DIR}/sprout.mk

.PHONY: update_submodules
update_submodules: ${SUBMODULES} sync_install

build: update_submodules sprout scripts/sipp-stats/clearwater-sipp-stats-1.0.0.gem plugins-build

test: update_submodules sprout_test plugins-test

full_test: update_submodules sprout_full_test plugins-test

testall: $(patsubst %, %_test, ${SUBMODULES}) full_test

clean: $(patsubst %, %_clean, ${SUBMODULES}) sprout_clean plugins-clean
	rm -rf ${ROOT}/usr
	rm -rf ${ROOT}/build

distclean: $(patsubst %, %_distclean, ${SUBMODULES}) sprout_distclean
	rm -rf ${ROOT}/usr
	rm -rf ${ROOT}/build

#
# Plugin handling.
#

# Generate a list of all the plugins available.
PLUGINS := $(patsubst plugins/%,%,$(shell find plugins -mindepth 1 -maxdepth 1 -type d ))

# Macro to define rules for building plugins.
#
# $1 - The name of the plugin to build.
# $1 - The make target (e.g build, test, clean, ...)
define plugin_template
.PHONY: plugin-$1-$2

# Note that the plugins are not required to have a 'build' target, but assume
# the default target performs a build.
plugin-$1-$2:
	make -C plugins/$1 $$(filter-out build,$2)
endef

.PHONY: plugins-build
plugins-build: $(patsubst %,plugin-%-build,$(PLUGINS))
$(foreach plugin,$(PLUGINS),$(eval $(call plugin_template,${plugin},build)))

.PHONY: plugins-test
plugins-test: $(patsubst %,plugin-%-test,$(PLUGINS))
$(foreach plugin,$(PLUGINS),$(eval $(call plugin_template,${plugin},test)))

.PHONY: plugins-clean
plugins-clean: $(patsubst %,plugin-%-clean,$(PLUGINS))
$(foreach plugin,$(PLUGINS),$(eval $(call plugin_template,${plugin},clean)))

.PHONY: plugins-deb
plugins-deb: $(patsubst %,plugin-%-deb,$(PLUGINS))
$(foreach plugin,$(PLUGINS),$(eval $(call plugin_template,${plugin},deb)))

.PHONY: plugins-deb-only
plugins-deb-only: $(patsubst %,plugin-%-deb-only,$(PLUGINS))
$(foreach plugin,$(PLUGINS),$(eval $(call plugin_template,${plugin},deb-only)))

#
# Debian file handling.
#
include build-infra/cw-deb.mk

deb-only: plugins-deb-only

.PHONY: deb
deb: build deb-only plugins-deb

.PHONY: all build test clean distclean

scripts/sipp-stats/clearwater-sipp-stats-1.0.0.gem : $(shell find scripts/sipp-stats/ -type f | grep -v ".gem")
	cd scripts/sipp-stats; gem build clearwater-sipp-stats.gemspec
