# Development

This document describes how to build and test Sprout and Bono.

Sprout development is ongoing on Ubuntu 12.04, so the processes described
below are targetted for (and tested on) this platform.  The code has been
written to be portable, though, and should compile on other platforms once the
required dependencies are installed.

## Dependencies

Sprout and Bono depend on a number of tools and libraries.  Some of these are
included as git submodules, but the rest must be installed separately.

On Ubuntu 12.04,

1. add the Clearwater repository to provide the ZeroMQ library

    This step is necessary because Sprout and Bono rely on a newer version than Ubuntu provide.

        echo "deb http://repo.cw-ngv.com/latest binary/" | sudo tee /etc/apt/sources.list.d/clearwater.list

    For non-Ubuntu systems, you can build ZeroMQ from source. The source code is found [here](http://www.zeromq.org/intro:get-the-software).

2.  update the package list

        sudo apt-get update

3.  install the required packages

        sudo apt-get install ntp build-essential autoconf scons pkg-config libtool libcloog-ppl0 gdb pstack git git-svn dpkg-dev devscripts dh-make python-setuptools python-virtualenv python-dev libcurl4-openssl-dev libmysqlclient-dev libgmp10 libgmp-dev libc-ares-dev ncurses-dev libxml2-dev libxslt1-dev libboost-all-dev libzmq3-dev valgrind libxml2-utils rubygems

## Getting the Code

The sprout code is all in the `sprout` repository, and its submodules, which
are in the `modules` subdirectory.

To get all the code, clone the sprout repository with the `--recursive` flag to
indicate that submodules should be cloned too.

    git clone --recursive git@bitbucket.org:metaswitch/sprout.git

## Building Binaries

Note that the first build can take a long time - up to an hour on a slow
machine. It takes 20-30 minutes on an EC2 m1.medium instance.

To build sprout and all its dependencies, change to the top-level `sprout`
directory and issue `make all`.

On completion,

* the sprout binary is in `build/bin`
* libraries on which it depends are in `usr/lib`.

Subsequent builds should be quicker, but still check all of the
dependencies.  For fast builds when you've only changed sprout code, change to
the `sprout` subdirectory below the top-level `sprout` directory and then run
`make all`.

## Building Debian Packages

To build Debian packages, run `make deb`.  On completion, Debian packages
are in the parent of the top-level `sprout` directory.

`make deb` does a full build before building the Debian packages and, even if
the code is already built, it can take a minute or two to check all the
dependencies.  If you are sure the code has already been built, you can use
`make deb-only` to just build the Debian packages without checking the
binaries.

`make deb` and `make deb-only` can push the resulting binaries to a Debian
repository server.  To push to a repository server on the build machine, set
the `REPO_DIR` environment variable to the appropriate path.  To push (via
scp) to a repository server on a remote machine, also set the `REPO_SERVER`
environment variable to the user and server name.

## Running Unit Tests

To run the sprout unit test suite, change to the `sprout` subdirectory below
the top-level `sprout` directory and issue `make test`.

Sprout unit tests use the [Google Test](https://code.google.com/p/googletest/)
framework, so the output from the test run looks something like this.

    [==========] Running 92 tests from 20 test cases.
    [----------] Global test environment set-up.
    [----------] 1 test from AuthenticationTest
    [ RUN      ] AuthenticationTest.NoAuthorization
    [       OK ] AuthenticationTest.NoAuthorization (27 ms)
    [----------] 1 test from AuthenticationTest (27 ms total)

    [----------] 6 tests from SimServsTest
    [ RUN      ] SimServsTest.EmptyXml
    [       OK ] SimServsTest.EmptyXml (1 ms)
    ...
    [ RUN      ] SessionCaseTest.Names
    [       OK ] SessionCaseTest.Names (0 ms)
    [----------] 1 test from SessionCaseTest (0 ms total)

    [----------] Global test environment tear-down
    [==========] 92 tests from 20 test cases ran. (27347 ms total)
    [  PASSED  ] 92 tests.

`make test` also automatically runs code coverage (using
[gcov](http://gcc.gnu.org/onlinedocs/gcc/Gcov.html)) and memory leak checks
(using [Valgrind](http://valgrind.org/)).  If code coverage decreases or
memory is leaked during the tests, an error is displayed. To see the detailed
code coverage results, run `make coverage_raw`.

The sprout makefile offers the following additional options and targets.

*   `make run_test` just runs the tests without doing code coverage or memory
    leak checks.
*   Passing `JUSTTEST=testname` just runs the specified test case.
*   Passing `NOISY=T` enables verbose logging during the tests; you can add
    a logging level (e.g., `NOISY=T:99`) to control which logs you see.
*   `make debug` runs the tests under gdb.
*   `make vg_raw` just runs the memory leak checks.

## Running Sprout Locally

To run sprout on the machine it was built on, change to the top-level `sprout`
directory and then run the following command.

    LD_LIBRARY_PATH=usr/lib:$LD_LIBRARY_PATH build/bin/sprout -t 5060

This is the bare minimum, and just opens port 5060 for trusted SIP traffic.
For all command-line options, use the `-h` option.
