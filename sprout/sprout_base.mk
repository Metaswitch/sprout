# sprout-base Makefile

all: stage-build

ROOT := $(abspath $(shell pwd)/../)
MK_DIR := ${ROOT}/mk

TARGET := sprout
TARGET_TEST := sprout_base_test

TARGET_SOURCES := logger.cpp \
                  saslogger.cpp \
                  utils.cpp \
                  analyticslogger.cpp \
                  stack.cpp \
                  dnsparser.cpp \
                  dnscachedresolver.cpp \
                  baseresolver.cpp \
                  sipresolver.cpp \
                  bono.cpp \
                  registration_utils.cpp \
                  registrar.cpp \
                  authentication.cpp \
                  options.cpp \
                  connection_pool.cpp \
                  flowtable.cpp \
                  httpconnection.cpp \
                  httpresolver.cpp \
                  hssconnection.cpp \
                  websockets.cpp \
                  localstore.cpp \
                  memcachedstore.cpp \
                  memcachedstoreview.cpp \
                  memcached_config.cpp \
                  avstore.cpp \
                  regstore.cpp \
                  xdmconnection.cpp \
                  simservs.cpp \
                  enumservice.cpp \
                  bgcfservice.cpp \
                  icscfrouter.cpp \
                  scscfselector.cpp \
                  dnsresolver.cpp \
                  log.cpp \
                  pjutils.cpp \
                  statistic.cpp \
                  zmq_lvc.cpp \
                  trustboundary.cpp \
                  sessioncase.cpp \
                  ifchandler.cpp \
                  aschain.cpp \
                  custom_headers.cpp \
                  accumulator.cpp \
                  connection_tracker.cpp \
                  quiescing_manager.cpp \
                  dialog_tracker.cpp \
                  load_monitor.cpp \
                  counter.cpp \
                  basicproxy.cpp \
                  acr.cpp \
                  signalhandler.cpp \
                  health_checker.cpp \
                  subscription.cpp \
                  notify_utils.cpp \
                  unique.cpp \
                  chronosconnection.cpp \
                  accesslogger.cpp \
                  httpstack.cpp \
                  httpstack_utils.cpp \
                  handlers.cpp \
                  ipv6utils.cpp \
                  contact_filtering.cpp \
                  sproutletproxy.cpp \
                  pluginloader.cpp \
                  alarm.cpp \
                  communicationmonitor.cpp \
                  thread_dispatcher.cpp \
                  common_sip_processing.cpp \
                  exception_handler.cpp

TARGET_SOURCES_BUILD := main.cpp

CPPFLAGS += -Wno-write-strings \
            -ggdb3 -std=c++0x
CPPFLAGS += -I${ROOT}/include \
            -I${ROOT}/modules/cpp-common/include \
            -I${ROOT}/modules/app-servers/include \
            -I${ROOT}/usr/include \
            -I${ROOT}/modules/rapidjson/include

CPPFLAGS += $(shell PKG_CONFIG_PATH=${ROOT}/usr/lib/pkgconfig pkg-config --cflags libpjproject)

# Add cpp-common/src as VPATH so build will find modules there.
VPATH = ${ROOT}/modules/cpp-common/src

# Production build:
#
# Enable optimization in production only.
CPPFLAGS := $(filter-out -O2,$(CPPFLAGS))
CPPFLAGS_BUILD += -O2


LDFLAGS += -L${ROOT}/usr/lib -rdynamic
LDFLAGS += -lmemcached \
           -lmemcachedutil \
           -ljsoncpp \
           -lssl \
           -lcrypto \
           -ldl \
           -lwebsocketpp \
           -lboost_regex \
           -lboost_system \
           -lboost_thread \
           -lboost_date_time \
           -lcares \
           -lzmq \
           -levhtp \
           -levent \
           -levent_pthreads \
           -lcurl \
           -lsas \
           -lboost_filesystem

LDFLAGS += $(shell PKG_CONFIG_PATH=${ROOT}/usr/lib/pkgconfig pkg-config --libs libpjproject)

include ${MK_DIR}/platform.mk

.PHONY: stage-build
stage-build: build

.PHONY: distclean
distclean: clean

# Build rules for SIPp cryptographic modules.
$(OBJ_DIR_TEST)/md5.o : $(SIPP_DIR)/md5.c
	$(CXX) $(CPPFLAGS) -I$(SIPP_DIR) -c $(SIPP_DIR)/md5.c -o $@
