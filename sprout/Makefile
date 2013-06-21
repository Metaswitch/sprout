# Sprout Makefile

all: stage-build

ROOT := $(abspath $(shell pwd)/../)
MK_DIR := ${ROOT}/mk

GTEST_DIR := $(ROOT)/modules/gmock/gtest
GMOCK_DIR := $(ROOT)/modules/gmock

TARGET := sprout
TARGET_TEST := sprout_test

TARGET_SOURCES := logger.cpp \
                  utils.cpp \
                  analyticslogger.cpp \
                  stack.cpp \
                  stateful_proxy.cpp \
                  registration_utils.cpp \
                  registrar.cpp \
                  authentication.cpp \
                  options.cpp \
                  connection_pool.cpp \
                  flowtable.cpp \
                  httpconnection.cpp \
                  hssconnection.cpp \
                  websockets.cpp \
                  store.cpp \
                  localstore.cpp \
                  memcachedstore.cpp \
                  xdmconnection.cpp \
                  simservs.cpp \
                  callservices.cpp \
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
                  sas.cpp

TARGET_SOURCES_BUILD := main.cpp

TARGET_SOURCES_TEST := test_main.cpp \
                       fakecurl.cpp \
                       fakehttpconnection.cpp \
                       fakexdmconnection.cpp \
                       fakehssconnection.cpp \
                       fakelogger.cpp \
                       faketransport_udp.cpp \
                       faketransport_tcp.cpp \
                       fakednsresolver.cpp \
                       basetest.cpp \
                       siptest.cpp \
                       authentication_test.cpp \
                       simservs_test.cpp \
                       httpconnection_test.cpp \
                       hssconnection_test.cpp \
                       xdmconnection_test.cpp \
                       enumservice_test.cpp \
                       memcachedstore_test.cpp \
                       registrar_test.cpp \
                       stateful_proxy_test.cpp \
                       bgcfservice_test.cpp \
                       stack_test.cpp \
                       options_test.cpp \
                       logger_test.cpp \
                       utils_test.cpp \
                       callservices_test.cpp \
                       aschain_test.cpp \
                       sessioncase_test.cpp \
                       ifchandler_test.cpp

# Put the interposer in here, so it will be loaded before pjsip.
TARGET_EXTRA_OBJS_TEST := gmock-all.o \
	                  gtest-all.o \
	                  test_interposer.so

TEST_XML = $(TEST_OUT_DIR)/test_detail_$(TARGET_TEST).xml
COVERAGE_XML = $(TEST_OUT_DIR)/coverage_$(TARGET_TEST).xml
COVERAGE_LIST_TMP = $(TEST_OUT_DIR)/coverage_list_tmp
COVERAGE_LIST = $(TEST_OUT_DIR)/coverage_list
COVERAGE_MASTER_LIST = ut/coverage-not-yet
VG_XML = $(TEST_OUT_DIR)/vg_$(TARGET_TEST).memcheck
VG_OUT = $(TEST_OUT_DIR)/vg_$(TARGET_TEST).txt

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
            -I${ROOT}/usr/include
CPPFLAGS += $(shell PKG_CONFIG_PATH=${ROOT}/usr/lib/pkgconfig pkg-config --cflags libpjproject)

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
                  -I$(GTEST_DIR)/include -I$(GMOCK_DIR)/include

LDFLAGS += -L${ROOT}/usr/lib
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
           -lzmq

# Test build fakes out cURL
LDFLAGS_BUILD += -lcurl

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

COVERAGEFLAGS = $(OBJ_DIR_TEST) --object-directory=$(shell pwd) \
                --root=$(shell pwd) --exclude=^ut/ \
                --sort-percentage --exclude-lines

VGFLAGS = --suppressions=$(VG_SUPPRESS) \
          --leak-check=full \
          --track-origins=yes \
          --malloc-fill=cc \
          --free-fill=df

# Define JUSTTEST=<testname> to test just that test.  Easier than
# passing the --gtest_filter in EXTRA_TEST_ARGS.
ifdef JUSTTEST
  EXTRA_TEST_ARGS ?= --gtest_filter=*$(JUSTTEST)*
endif

include ${MK_DIR}/platform.mk

.PHONY: stage-build
stage-build: build

.PHONY: test
test: run_test coverage vg coverage-check

# Run the test.  You can set EXTRA_TEST_ARGS to pass extra arguments
# to the test, e.g.,
#
#   make EXTRA_TEST_ARGS=--gtest_filter=StatefulProxyTest* run_test
#
# runs just the StatefulProxyTest tests.
#
# Ignore failure here; it will be detected by Jenkins.
.PHONY: run_test
run_test: build_test | $(TEST_OUT_DIR)
	rm -f $(TEST_XML)
	rm -f $(OBJ_DIR_TEST)/*.gcda
	$(TARGET_BIN_TEST) $(EXTRA_TEST_ARGS) --gtest_output=xml:$(TEST_XML)

.PHONY: coverage
coverage: | $(TEST_OUT_DIR)
	$(GCOVR) $(COVERAGEFLAGS) --xml > $(COVERAGE_XML)

# Check that we have 100% coverage of all files except those that we
# have declared we're being relaxed on.  In particular, all new files
# must have 100% coverage or be added to $(COVERAGE_MASTER_LIST).
# The string "Marking build unstable" is recognised by the CI scripts
# and if it is found the build is marked unstable.
.PHONY: coverage-check
coverage-check: coverage
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
coverage_raw: | $(TEST_OUT_DIR)
	$(GCOVR) $(COVERAGEFLAGS) --keep

.PHONY: debug
debug: build_test
	gdb --args $(TARGET_BIN_TEST) $(EXTRA_TEST_ARGS)

# Don't run VG against death tests; they don't play nicely.
# Be aware that running this will count towards coverage.
# Don't send output to console, or it might be confused with the full
# unit-test run earlier.
# Test failure should not lead to build failure - instead we observe
# test failure from Jenkins.
.PHONY: vg
vg: build_test | $(TEST_OUT_DIR)
	-valgrind --xml=yes --xml-file=$(VG_XML) $(VGFLAGS) \
	  $(TARGET_BIN_TEST) --gtest_filter='-*DeathTest*' $(EXTRA_TEST_ARGS) > $(VG_OUT) 2>&1

.PHONY: vg_raw
vg_raw: build_test | $(TEST_OUT_DIR)
	-valgrind --gen-suppressions=all $(VGFLAGS) \
	  $(TARGET_BIN_TEST) --gtest_filter='-*DeathTest*' $(EXTRA_TEST_ARGS)

.PHONY: distclean
distclean: clean

# Build rules for GMock/GTest library.
$(OBJ_DIR_TEST)/gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) -I$(GTEST_DIR)/include -I$(GMOCK_DIR) -I$(GMOCK_DIR)/include \
            -c $(GTEST_DIR)/src/gtest-all.cc -o $@

$(OBJ_DIR_TEST)/gmock-all.o : $(GMOCK_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) -I$(GTEST_DIR)/include -I$(GMOCK_DIR) -I$(GMOCK_DIR)/include \
            -c $(GMOCK_DIR)/src/gmock-all.cc -o $@

# Build rule for our interposer.
$(OBJ_DIR_TEST)/test_interposer.so: ut/test_interposer.cpp ut/test_interposer.hpp
	$(CXX) $(CPPFLAGS) -shared -fPIC -ldl $< -o $@
