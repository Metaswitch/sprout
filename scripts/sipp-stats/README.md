## Clearwater SIPp stats server

This component runs as a service on a SIPp stress node and is responsible for parsing SIPp's statistics files and presenting a selected subset of the values over the 0mq stats interface.

Currently the service assumes that SIPp is running the `sip-stress.xml` script and that SIPp is configured to write its logs out to `/var/log/clearwater-sipp/`.  This is true for the `clearwater-sip-stress-stats` Debian package.  If the name of the script is changed, or the order of the SIP messages is changed, this service will need to be changed too.

# Installing

## Automated

The easiest way to install the package on a target machine is to install the `clearwater-sip-stress-stats` Debian package (which will also draw in the `clearwater-sip-stress` package).

This also installs an `init.d` control scipt and starts the service.

## Manual

To install manually, the sprout build will generate a `clearwater-sipp-stats-1.0.0.gem` file in this folder, which can be installed on a target machine with the following:

    sudo apt-get install ruby1.9.3 make libzmq3
    gem install --local <path to .gem file>

This installs the `clearwater-sipp-stats` executable which can be run to start the service.

# Statistics Format

The statistics are presented over the standard 0mq interface (using a ZMQ::PUB socket, a PUB-SUB envelope and a last-value-cache) and can be read using the `cw_stats` executable.  The statistic is called `call_stats` and is formated as follows:

    <number of inital REGISTERs sent>
    <number of recurring REGISTERs sent>
    <number of INVITEs sent>
    <number of successful call setups>
    <number of initial REGISTERs sent in the last minute>
    <number of recurring REGISTERs sent in the last minute>
    <number of INVITEs sent in the last minute>
    <number of successful call setups in the last minute>

# Reading the statistics

As mentioned above, these statistics can be retrieved using the clearwater statistics client `cw_stat`, with the following incantation:

    cw_stat [-v] [-s] <hostname> call_stats

Where `<hostname>` refers to the SIPp node in question.
