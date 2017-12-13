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
DEB_NAMES += call-diversion-as call-diversion-as-dbg
DEB_NAMES += mangelwurzel-as mangelwurzel-as-dbg
DEB_NAMES += bono bono-dbg restund
DEB_NAMES += bono-node bono-node-dbg
DEB_NAMES += clearwater-sipp clearwater-sipp-dbg
DEB_NAMES += clearwater-sip-stress clearwater-sip-stress-stats clearwater-sip-perf

INCLUDE_DIR := ${INSTALL_DIR}/include
LIB_DIR := ${INSTALL_DIR}/lib

SUBMODULES := pjsip c-ares curl libevhtp libmemcached libre restund openssl websocketpp sipp sas-client

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

# Macro to define the rule for building a single target for a single plugin.
#
# Parameters:
#   $1 - The name of the plugin to build.
#   $2 - The make target (e.g build, test, clean, ...)
#
# Note that the plugins are not required to have a 'build' target, but assume
# the default target performs a build.  For this reason we never call "make
# build" for a plugin, and always just call "make" instead.
define plugin_name_target_template

.PHONY: plugin-$1-$2
plugin-$1-$2:
	make -C plugins/$1 $$(filter-out build,$2)

endef

# Macro to define the rules for building a single target for all plugins.
#
# Parameters:
#   $1 - The make target (e.g. build, test, clean, ...)
#
# This template:
#   - Defines the plugins-<target> rule.
#   - Generates a rule for each plugin to build that target.
define plugin_target_template

.PHONY: plugins-$1
plugins-$1: $$(patsubst %,plugin-%-$1,$$(PLUGINS))
$$(foreach plugin,$$(PLUGINS),$$(eval $$(call plugin_name_target_template,$$(plugin),$1)))

endef

# Define the possible make targets for the plugins and generate the makefile
# rules.
PLUGIN_TARGETS := build test clean deb-only
$(foreach target,$(PLUGIN_TARGETS),$(eval $(call plugin_target_template,$(target))))

#
# Debian file handling.
#
include build-infra/cw-deb.mk

deb-only: plugins-deb-only

.PHONY: deb
deb: build deb-only

.PHONY: all build test clean distclean

scripts/sipp-stats/clearwater-sipp-stats-1.0.0.gem : $(shell find scripts/sipp-stats/ -type f | grep -v ".gem")
	cd scripts/sipp-stats; gem build clearwater-sipp-stats.gemspec
