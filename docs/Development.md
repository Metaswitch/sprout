# Development

This document describes how to build and test Sprout and Bono.

Sprout/Bono development is ongoing on Ubuntu 14.04, so the processes described
below are targetted for (and tested on) this platform.  The code has been
written to be portable, though, and should compile on other platforms once the
required dependencies are installed.

## Dependencies

Sprout and Bono depend on a number of tools and libraries.  Some of these are
included as git submodules, but the rest must be installed separately.

On Ubuntu 14.04,

1.  update the package list

        sudo apt-get update

2.  install the required packages

        sudo apt-get install ntp build-essential autoconf scons pkg-config libtool libcloog-ppl1 gdb pstack git git-svn dpkg-dev devscripts dh-make python-setuptools python-virtualenv python-dev libcurl4-openssl-dev libmysqlclient-dev libgmp10 libgmp-dev libc-ares-dev ncurses-dev libxml2-dev libxslt1-dev libboost-all-dev libzmq3-dev valgrind libxml2-utils ruby libevent-dev libevent-pthreads-2.0-5 cmake flex bison libboost-filesystem-dev libsnmp-dev

## Getting the Code

The sprout/bono code is all in the `sprout` repository, and its submodules, which
are in the `modules` subdirectory.

To get all the code, clone the sprout repository with the `--recursive` flag to
indicate that submodules should be cloned too.

    git clone --recursive git@github.com:Metaswitch/sprout.git

This accesses the repository over SSH on Github, and will not work unless you have a Github account and registered SSH key. If you do not have both of these, you will need to configure Git to read over HTTPS instead:

    git config --global url."https://github.com/".insteadOf git@github.com:
    git clone --recursive git@github.com:Metaswitch/sprout.git

## Building Binaries

Note that the first build can take a long time - up to an hour on a slow
machine. It takes 20-30 minutes on an EC2 m1.medium instance.

To build sprout, bono, and all their dependencies, change to the top-level `sprout`
directory and issue `make`.  Both the sprout and bono functions are
provided by the same "sprout" binary - command-line parameters control which
behavior the binary performs.

On completion,

* the sprout binary is in `build/bin`
* libraries on which it depends are in `usr/lib`.

Subsequent builds should be quicker, but still check all of the
dependencies.  For fast builds when you've only changed sprout code, change to
the `src` subdirectory below the top-level `sprout` directory and then run
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

Sprout uses our common infrastructure to run the unit tests. How to run the UTs, and the different options available when running the UTs are described [here](http://clearwater.readthedocs.io/en/latest/Running_unit_tests.html#c-unit-tests).

## Running Sprout and Bono Locally

To run sprout or bono on the machine it was built on, change to the top-level `sprout` directory and then run the following command, passing in the appropriate parameters

    MIBS="" LD_LIBRARY_PATH=usr/lib:$LD_LIBRARY_PATH build/bin/sprout <parameters>

As an example, to run Sprout as a basic S-CSCF on port 5054 run the following command:

    MIBS="" LD_LIBRARY_PATH=usr/lib:$LD_LIBRARY_PATH build/bin/sprout -t --domain=<Home Domain> --hss=<Homestead cluster>

To run bono as a basic P-CSCF on port 5060 run the following command:

    MIBS="" LD_LIBRARY_PATH=usr/lib:$LD_LIBRARY_PATH build/bin/sprout -t --pcscf=5058,5060 --routing-proxy=<I-CSCF address, or S-CSCF if there's no I-CSCF>,0,50,600

For all command-line options, use the `-h` option.

Sprout attempts to connect to the local SNMP agent (snmpd) to provide statistics. If running it interactively, you will see warnings ("Warning (Net-SNMP): Warning: Failed to connect to the agentx master agent ([NIL])") unless you install the `snmpd` package, and configure it as an AgentX master in /etc/snmp/snmpd.conf (http://www.net-snmp.org/docs/README.agentx.html).
