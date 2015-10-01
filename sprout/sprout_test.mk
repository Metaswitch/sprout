# Sprout unit test Makefile

all: stage-build

ROOT := $(abspath $(shell pwd)/../)
MK_DIR := ${ROOT}/mk

GTEST_DIR := $(ROOT)/modules/gmock/gtest
GMOCK_DIR := $(ROOT)/modules/gmock
SIPP_DIR := $(ROOT)/modules/sipp

TARGET := sprout
TARGET_TEST := sprout_test

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
                  dnsresolver.cpp \
                  bgcfservice.cpp \
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
                  icscfrouter.cpp \
                  scscfselector.cpp \
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
                  sproutletappserver.cpp \
                  scscfsproutlet.cpp \
                  icscfsproutlet.cpp \
                  bgcfsproutlet.cpp \
                  mmtel.cpp \
                  mobiletwinned.cpp \
                  mangelwurzel.cpp \
                  alarm.cpp \
                  base_communication_monitor.cpp \
                  communicationmonitor.cpp \
                  thread_dispatcher.cpp \
                  common_sip_processing.cpp \
                  exception_handler.cpp \
                  uri_classifier.cpp \
                  snmp_scalar.cpp \
                  snmp_row.cpp \
                  sip_string_to_request_type.cpp \
                  session_expires_helper.cpp

TARGET_SOURCES_TEST := test_main.cpp \
                       fakecurl.cpp \
                       fakehttpconnection.cpp \
                       fakexdmconnection.cpp \
                       fakehssconnection.cpp \
                       fakelogger.cpp \
                       faketransport_udp.cpp \
                       faketransport_tcp.cpp \
                       fakednsresolver.cpp \
                       fakechronosconnection.cpp \
                       basetest.cpp \
                       siptest.cpp \
                       sip_common.cpp \
                       sipresolver_test.cpp \
                       authentication_test.cpp \
                       simservs_test.cpp \
                       httpconnection_test.cpp \
                       hssconnection_test.cpp \
                       xdmconnection_test.cpp \
                       enumservice_test.cpp \
                       regstore_test.cpp \
                       avstore_test.cpp \
                       registrar_test.cpp \
                       bono_test.cpp \
                       bgcfservice_test.cpp \
                       options_test.cpp \
                       logger_test.cpp \
                       utils_test.cpp \
                       aschain_test.cpp \
                       sessioncase_test.cpp \
                       ifchandler_test.cpp \
                       custom_headers_test.cpp \
                       connection_tracker_test.cpp \
                       quiescing_manager_test.cpp \
                       dialog_tracker_test.cpp \
                       flow_test.cpp \
                       load_monitor_test.cpp \
                       icscfsproutlet_test.cpp \
                       basicproxy_test.cpp \
                       scscfselector_test.cpp \
                       acr_test.cpp \
                       subscription_test.cpp \
                       chronosconnection_test.cpp \
                       handlers_test.cpp \
                       httpresolver_test.cpp \
                       mock_sas.cpp \
                       contact_filtering_test.cpp \
                       appserver_test.cpp \
                       scscf_test.cpp \
                       sproutletproxy_test.cpp \
                       gruu_test.cpp \
                       mobiletwinned_test.cpp \
                       mangelwurzel_test.cpp \
                       alarm_test.cpp \
                       communicationmonitor_test.cpp \
                       common_sip_processing_test.cpp \
                       fakesnmp.cpp \
                       uriclassifier_test.cpp \
                       session_expires_helper_test.cpp


# Put the interposer in here, so it will be loaded before pjsip.
TARGET_EXTRA_OBJS_TEST := gmock-all.o \
                          gtest-all.o \
                          md5.o \
                          test_interposer.so \
                          fakezmq.so

TEST_XML = $(TEST_OUT_DIR)/test_detail_$(TARGET_TEST).xml
COVERAGE_XML = $(TEST_OUT_DIR)/coverage_$(TARGET_TEST).xml
COVERAGE_LIST_TMP = $(TEST_OUT_DIR)/coverage_list_tmp
COVERAGE_LIST = $(TEST_OUT_DIR)/coverage_list
COVERAGE_MASTER_LIST = ut/coverage-not-yet
VG_XML = $(TEST_OUT_DIR)/vg_$(TARGET_TEST).memcheck
VG_OUT = $(TEST_OUT_DIR)/vg_$(TARGET_TEST).txt
VG_LIST = $(TEST_OUT_DIR)/vg_$(TARGET_TEST)_list
VG_SUPPRESS = $(TARGET_TEST).supp

EXTRA_CLEANS += $(TEST_XML) \
                $(COVERAGE_XML) \
                $(VG_XML) $(VG_OUT) \
                $(OBJ_DIR_TEST)/*.gcno \
                $(OBJ_DIR_TEST)/*.gcda \
                *.gcov

CPPFLAGS += -Wno-write-strings \
            -ggdb3 -std=c++0x
CPPFLAGS += -I${ROOT}/include \
            -I${ROOT}/include/mangelwurzel \
            -I${ROOT}/modules/cpp-common/include \
            -I${ROOT}/modules/cpp-common/test_utils \
            -I${ROOT}/modules/app-servers/include \
            -I${ROOT}/modules/app-servers/test \
            -I${ROOT}/modules/gemini/include \
            -I${ROOT}/sprout/ut \
            -I${ROOT}/modules/gemini/src/ut \
            -I${ROOT}/usr/include \
            -I${ROOT}/modules/rapidjson/include

CPPFLAGS += $(shell PKG_CONFIG_PATH=${ROOT}/usr/lib/pkgconfig pkg-config --cflags libpjproject)

# Add cpp-common/src as VPATH so build will find modules there.
VPATH = ${ROOT}/modules/cpp-common/src:${ROOT}/modules/cpp-common/test_utils:${ROOT}/modules/app-servers/test:${ROOT}/modules/gemini/src:${ROOT}/sprout/mangelwurzel

# Production build:
#
# Enable optimization in production only.
CPPFLAGS := $(filter-out -O2,$(CPPFLAGS))
CPPFLAGS_BUILD += -O2

# Test build:
#
# Turn on code coverage.
# Disable optimization, for speed and coverage accuracy.
# Allow testing of private and protected fields/methods.
# Add the Google Mock / Google Test includes.
CPPFLAGS_TEST  += -DUNIT_TEST \
                  -fprofile-arcs -ftest-coverage \
                  -O0 \
                  -fno-access-control \
                  -I$(GTEST_DIR)/include -I$(GMOCK_DIR)/include -I$(SIPP_DIR)

LDFLAGS += -L${ROOT}/usr/lib
LDFLAGS += -lmemcached \
           -lmemcachedutil \
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
           $(shell net-snmp-config --netsnmp-agent-libs)

# Test build fakes out cURL
LDFLAGS_BUILD += -lcurl -lsas -lz

# Include memento if desired
#LDFLAGS += -lmemento -lthrift -lcassandra

# Test build uses just-built libraries, which may not be installed
LDFLAGS_TEST += -Wl,-rpath=$(ROOT)/usr/lib

LDFLAGS += $(shell PKG_CONFIG_PATH=${ROOT}/usr/lib/pkgconfig pkg-config --libs libpjproject)

# Now the GMock / GTest boilerplate.
GTEST_HEADERS := $(GTEST_DIR)/include/gtest/*.h \
                 $(GTEST_DIR)/include/gtest/internal/*.h
GMOCK_HEADERS := $(GMOCK_DIR)/include/gmock/*.h \
                 $(GMOCK_DIR)/include/gmock/internal/*.h \
                 $(GTEST_HEADERS)

GTEST_SRCS_ := $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)
GMOCK_SRCS_ := $(GMOCK_DIR)/src/*.cc $(GMOCK_HEADERS)
# End of boilerplate

COVERAGEFLAGS = $(OBJ_DIR_TEST) --object-directory=$(shell pwd) --root=${ROOT} \
                --exclude='(^include/|^modules/gmock/|^modules/rapidjson/|^modules/cpp-common/include/|^modules/cpp-common/test_utils/|^ut/|^usr/|^modules/gemini/src/ut/|^modules/gemini/include/|^sprout/ut/|^sprout/mangelwurzel/ut/)' \
                --sort-percentage

VGFLAGS = --suppressions=$(VG_SUPPRESS) \
          --leak-check=full \
          --track-origins=yes \
          --malloc-fill=cc \
          --num-callers=40 \
          --free-fill=df

# Define JUSTTEST=<testname> to test just that test.  Easier than
# passing the --gtest_filter in EXTRA_TEST_ARGS.
ifdef JUSTTEST
  EXTRA_TEST_ARGS ?= --gtest_filter=$(JUSTTEST)
endif

include ${MK_DIR}/platform.mk
include ${ROOT}/modules/cpp-common/makefiles/alarm-utils.mk

.PHONY: stage-build
stage-build: build

.PHONY: test
test: run_test coverage vg coverage-check vg-check

# Run the test.  You can set EXTRA_TEST_ARGS to pass extra arguments
# to the test, e.g.,
#
#   make EXTRA_TEST_ARGS=--gtest_filter=StatefulProxyTest* run_test
#
# runs just the StatefulProxyTest tests.
#
# Ignore failure here; it will be detected by Jenkins.
.PHONY: run_test
run_test: | build_test
	rm -f $(TEST_XML)
	rm -f $(OBJ_DIR_TEST)/*.gcda
	$(TARGET_BIN_TEST) $(EXTRA_TEST_ARGS) --gtest_output=xml:$(TEST_XML)

.PHONY: coverage
coverage: | run_test
	$(GCOVR) $(COVERAGEFLAGS) --xml > $(COVERAGE_XML)

# Check that we have 100% coverage of all files except those that we
# have declared we're being relaxed on.  In particular, all new files
# must have 100% coverage or be added to $(COVERAGE_MASTER_LIST).
# The string "Marking build unstable" is recognised by the CI scripts
# and if it is found the build is marked unstable.
.PHONY: coverage-check
coverage-check: | coverage
	@xmllint --xpath '//class[@line-rate!="1.0"]/@filename' $(COVERAGE_XML) \
		| tr ' ' '\n' \
		| grep filename= \
		| cut -d\" -f2 \
		| sort > $(COVERAGE_LIST_TMP)
	@sort $(COVERAGE_MASTER_LIST) | comm -23 $(COVERAGE_LIST_TMP) - > $(COVERAGE_LIST)
	@if grep -q ^ $(COVERAGE_LIST) ; then \
		echo "Error: some files unexpectedly have less than 100% code coverage:" ; \
		cat $(COVERAGE_LIST) ; \
		/bin/false ; \
		echo "Marking build unstable." ; \
	fi

# Get quick coverage data at the command line. Add --branches to get branch info
# instead of line info in report.  *.gcov files generated in current directory
# if you need to see full detail.
.PHONY: coverage_raw
coverage_raw: | run_test
	$(GCOVR) $(COVERAGEFLAGS) --keep

.PHONY: debug
debug: | build_test
	gdb --args $(TARGET_BIN_TEST) $(EXTRA_TEST_ARGS)

# Don't run VG against death tests; they don't play nicely.
# Be aware that running this will count towards coverage.
# Don't send output to console, or it might be confused with the full
# unit-test run earlier.
# Test failure should not lead to build failure - instead we observe
# test failure from Jenkins.
.PHONY: vg
vg: | build_test
	-valgrind --xml=yes --xml-file=$(VG_XML) $(VGFLAGS) \
	  $(TARGET_BIN_TEST) --gtest_filter='-*DeathTest*' $(EXTRA_TEST_ARGS) > $(VG_OUT) 2>&1

# Check whether there were any errors from valgrind. Output to screen any errors found,
# and details of where to find the full logs.
# The output file will contain <error><kind>ERROR</kind></error>, or 'XPath set is empty'
# if there are no errors.
.PHONY: vg-check
vg-check: | vg
	@xmllint --xpath '//error/kind' $(VG_XML) 2>&1 | \
		sed -e 's#<kind>##g' | \
		sed -e 's#</kind>#\n#g' | \
		sort > $(VG_LIST)
	@if grep -q -v "XPath set is empty" $(VG_LIST) ; then \
		echo "Error: some memory errors have been detected" ; \
		cat $(VG_LIST) ; \
		echo "See $(VG_XML) for further details." ; \
	fi

.PHONY: vg_raw
vg_raw: | build_test
	-valgrind --gen-suppressions=all --show-reachable=yes $(VGFLAGS) \
	  $(TARGET_BIN_TEST) --gtest_filter='-*DeathTest*' $(EXTRA_TEST_ARGS)

.PHONY: distclean
distclean: clean

build: ${ROOT}/usr/include/sprout_alarmdefinition.h

${ROOT}/usr/include/sprout_alarmdefinition.h : ${BUILD_DIR}/bin/alarm_header ${ROOT}/sprout-base.root/usr/share/clearwater/infrastructure/alarms/sprout_alarms.json
	${BUILD_DIR}/bin/alarm_header -j "${ROOT}/sprout-base.root/usr/share/clearwater/infrastructure/alarms/sprout_alarms.json" -n "sprout"
	mv sprout_alarmdefinition.h $@

# Build rules for GMock/GTest library.
$(OBJ_DIR_TEST)/gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) -I$(GTEST_DIR)/include -I$(GMOCK_DIR) -I$(GMOCK_DIR)/include \
            -c $(GTEST_DIR)/src/gtest-all.cc -o $@

$(OBJ_DIR_TEST)/gmock-all.o : $(GMOCK_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) -I$(GTEST_DIR)/include -I$(GMOCK_DIR) -I$(GMOCK_DIR)/include \
            -c $(GMOCK_DIR)/src/gmock-all.cc -o $@

# Build rules for SIPp cryptographic modules.
$(OBJ_DIR_TEST)/md5.o : $(SIPP_DIR)/md5.c
	$(CXX) $(CPPFLAGS) -I$(SIPP_DIR) -c $(SIPP_DIR)/md5.c -o $@

# Build rule for our interposer.
$(OBJ_DIR_TEST)/test_interposer.so: ${ROOT}/modules/cpp-common/test_utils/test_interposer.cpp ${ROOT}/modules/cpp-common/test_utils/test_interposer.hpp
	$(CXX) $(CPPFLAGS) -shared -fPIC -ldl $< -o $@

# Build rule for our fake zmq.
$(OBJ_DIR_TEST)/fakezmq.so: ${ROOT}/modules/cpp-common/test_utils/fakezmq.cpp ${ROOT}/modules/cpp-common/test_utils/fakezmq.h
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) -I$(GTEST_DIR)/include -I$(GMOCK_DIR) -I$(GMOCK_DIR)/include -shared -fPIC -ldl $< -o $@
