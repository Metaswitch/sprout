# Platform makefile
#
# Contains the generic build logic for all components.  Include this
# in your Makefile, and define the following:
#
# TARGET               The bare name of the production binary (sprout)
#
# TARGET_TEST          The bare name of the test binary (sprout_test)
#
# TARGET_SOURCES       The bare names of the source files that are
#                      built into both the production and test
#                      binaries (foo.cpp bar.cpp)
#
# TARGET_SOURCES_BUILD The bare names of the source files that are
#                      built into the production binary only (baz.cpp)
#
# TARGET_SOURCES_TEST  The bare names of the source files that are
#                      built into the test binary only (bam.cpp)
#
# TARGET_EXTRA_OBJS_TEST  The bare names of any extra object files
#                      which should be built into the test binary
#                      and cleaned (bap.o)
#
# CPPFLAGS             The flags to pass to the C compiler and linker
#                      (-g)
#
# CPPFLAGS_BUILD       The extra flags to pass to the C compiler and
#                      linker for the production build (-O2)
#
# CPPFLAGS_TEST        The extra flags to pass to the C compiler and
#                      linker for the test build (-O0 -fprofile-arcs)
#
# LDFLAGS              The flags to pass to the linker (-lmemcached)
#
# LDFLAGS_BUILD        The extra flags to pass to the linker for the
#                      production build (-lcurl)
#
# LDFLAGS_TEST         The extra flags to pass to the linker for the
#                      test build
#
# EXTRA_CLEANS         The files which should be cleaned
#                      ($(TEST_OUT_DIR)/coverage.xml)
#

# Assumes ROOT has been set and points to the root of the repo
MK_DIR ?= ${ROOT}/mk

# All generated files go below here
BUILD_DIR := ${ROOT}/build

# Production and test binaries go into the same directory, below here
BIN_DIR := ${BUILD_DIR}/bin

# Production object files go to OBJ_DIR, and test ones to OBJ_DIR_TEST
OBJ_DIR := ${BUILD_DIR}/obj/${TARGET}
OBJ_DIR_TEST := ${BUILD_DIR}/obj/${TARGET_TEST}

# Test output files (reports etc) go here.
TEST_OUT_DIR := ${BUILD_DIR}/testout

# Unit test source code for a component lives in UT_DIR relative to the
# production source code.
UT_DIR ?= ut

PLATFORM := $(shell uname)
PREFIX ?= /usr

ifeq (${PLATFORM},Linux)
  include ${MK_DIR}/linux.mk
else
ifeq (${PLATFORM},Darwin)
  include ${MK_DIR}/linux.mk
  -include ${MK_DIR}/darwin.mk
endif
endif

GCOVR=${ROOT}/modules/gcovr/scripts/gcovr

# The production executable is TARGET_BIN; the test executable is TARGET_BIN_TEST
TARGET_BIN := ${BIN_DIR}/${TARGET}
TARGET_BIN_TEST := ${BIN_DIR}/${TARGET_TEST}

# The production object files are TARGET_OBJS. This is derived from:
TARGET_OBJS := $(patsubst %.cpp, ${OBJ_DIR}/%.o, ${TARGET_SOURCES} ${TARGET_SOURCES_BUILD})
TARGET_OBJS_TEST := $(patsubst %.cpp, ${OBJ_DIR_TEST}/%.o, ${TARGET_SOURCES} ${TARGET_SOURCES_TEST}) \
                    $(patsubst %,     ${OBJ_DIR_TEST}/%, $(TARGET_EXTRA_OBJS_TEST))

# The dependencies
DEPS := $(patsubst %.o, %.depends, $(patsubst %.so, %.depends, ${TARGET_OBJS} ${TARGET_OBJS_TEST}))

# Build the production binary.
.PHONY: build
build: ${BIN_DIR} ${OBJ_DIR} ${TARGET_BIN}

# Buld the test binary.
.PHONY: build_test
build_test: ${BIN_DIR} ${OBJ_DIR} ${OBJ_DIR_TEST} ${TEST_OUT_DIR} ${TARGET_BIN_TEST}

# Install the production binary.
.PHONY: install
install:
	mkdir -p ${PREFIX}/bin
	cp ${TARGET_BIN} ${PREFIX}/bin/

# Clean up.
.PHONY: clean
clean:
	rm -f ${TARGET_BIN}
	rm -f ${TARGET_OBJS}
	rm -f ${TARGET_OBJS_TEST}
	rm -f ${EXTRA_CLEANS}
	rm -f $(DEPS)


${TARGET_BIN}: ${TARGET_OBJS}
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_BUILD) -o $@ $^ $(LDFLAGS) $(LDFLAGS_BUILD) $(TARGET_ARCH) $(LOADLIBES) $(LDLIBS)

${TARGET_BIN_TEST}: ${TARGET_OBJS_TEST}
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_TEST) -o $@ $^ $(LDFLAGS) $(LDFLAGS_TEST) $(TARGET_ARCH) $(LOADLIBES) $(LDLIBS)

${OBJ_DIR}/%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_BUILD) $(TARGET_ARCH) -c -o $@ $<

${OBJ_DIR_TEST}/%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_TEST) $(TARGET_ARCH) -c -o $@ $<

${OBJ_DIR_TEST}/%.o: $(UT_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_TEST) $(TARGET_ARCH) -c -o $@ $<

${OBJ_DIR}/%.depends: %.cpp | ${OBJ_DIR}
	@echo $@
	@$(CXX) -M -MQ ${OBJ_DIR}/$*.o -MQ $@ $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_BUILD) $(TARGET_ARCH) -c -o $@ $<

${OBJ_DIR_TEST}/%.depends: %.cpp | ${OBJ_DIR_TEST}
	@echo $@
	@$(CXX) -M -MQ ${OBJ_DIR_TEST}/$*.o -MQ $@ $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_TEST) $(TARGET_ARCH) -c -o $@ $<

${OBJ_DIR_TEST}/%.depends: $(UT_DIR)/%.cpp | ${OBJ_DIR_TEST}
	@echo $@
	@$(CXX) -M -MQ ${OBJ_DIR_TEST}/$*.o -MQ $@ $(CXXFLAGS) $(CPPFLAGS) $(CPPFLAGS_TEST) $(TARGET_ARCH) -c -o $@ $<

${OBJ_DIR}:
	mkdir -p ${OBJ_DIR}

${OBJ_DIR_TEST}:
	mkdir -p ${OBJ_DIR_TEST}

${BIN_DIR}:
	mkdir -p ${BIN_DIR}

$(TEST_OUT_DIR):
	mkdir -p $(TEST_OUT_DIR)

-include $(DEPS)
