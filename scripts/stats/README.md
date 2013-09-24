# Statistic Collector

This document describes the addition of a new statistics interface to Bono (and hence to Sprout).  This interface may be used to query a running system of it's state by a remote client.

## Interface defintion

Bono and Sprout expose a [0MQ](http://www.zeromq.org/) subscription service that exposes the following topics:

 * Bono:
  * `connected_sprouts` - The list of connected Sprout nodes
  * `client_count` - A count of client TCP connections
  * `latency_us` - SIP request latency (between receiving request and either replying or forwarding on) in microseconds
 * Sprout:
  * `connected_homers` - The list of connected Homer nodes
  * `connected_homesteads` - The list of connected Homestead nodes
  * `latency_us` - SIP request latency (between receiving request and either replying or forwarding on) in microseconds

_Implementation note: The topics are indicated with a Pub-Sub envelope, as described [here](http://zguide.zeromq.org/page:all#Pub-Sub-Message-Envelopes)._

When a subscriber registers interest in one (or both) of these topics, Bono/Sprout immediately publishes the last known value of the statistic (allowing a client to subscribe, receive this value and immediately unsubscribe without having to wait for the value to change to get a notification).  Bono/Sprout also publishes the value of each statistic whenever it changes to allow clients to report an up to date value constantly.  _Implementation note: 0MQ optimizes publishing to a no-op if there are no subscribers currently attached._

The message consists of at least two parts:
 * The topic
 * The *status*. This is "OK" for success or an error message for failure cases. Errors are only returned immediately on subscription - the status is *always* "OK" for subsequent notifications. Current status values are as follows, but clients must be prepared to accept any. All non-"OK" values are failures.
   * "OK"
   * "Unknown" - the topic is not known to this server.
 * The value - zero or more strings.

### `connected_*TYPE*s` (*TYPE* can be: homer, homestead, sprout)

The connected *TYPE*s statistics is reported as a multipart message, consisting of:

 * A list of entries, one for each remote server:
    * Remote IP address of the connection
    * The count of connections to that remote IP address

As an example, the following might be a single status report from a small cluster (each line is a part of the message):

    connected_sprouts
    OK
    10.1.1.1
    5
    10.1.1.2
    4
    10.1.1.3
    1

_Implementation Note: 0MQ's multipart messages are sent as one message with boundaries inserted and are automatically split again at the receiving end.  This allows us to detect when we've reached the end of the list of sprout nodes without needing to send the count explicitly._

### `client_count`

The client count statistic is much simpler, it is reported as a single integer e.g.

    client_count
    OK
    14000

_In the current implementation, this statistic is reported on every change to the value (166 changes per second under stress).  If testing indicates this causes a major perfomance drain, the statistics will only be reported periodically instead._

## Client Specification

A CLI script is supplied to query the current state of either of the two statistics of a given host, used as:

    cw_stat <hostname> <statname>

Where `<statname>` may be `client_count`, `connected_sprouts` or blank to query both at once.

The CLI may alternatively be run in subscription mode with

    cw_stat -s <hostname> <statname>

which will stay connected to the specified host and will report changes until killed (with `Ctrl + C`).

## Client Usage Instructions

The CLI client is made up of a ruby library and launcher script, found in the `lib` and `bin` folders respectively.  To prepare your system for running the CLI tool, make sure `ruby` is installed (tested working on version 1.9.3 and 2.0.0) along with `gem` and the `bundler` gem.

In this folder, run `bundle install` (if you're using a system-wide ruby, you'll need `sudo` on this line) to pull in the appropriate gems then run `bin/cw_stat` for usage instructions.  As an example, to query the current client count on `bono-1.cw-ngv.com`, run

    bin/cw_stat bono-1.cw-ngv.com client_count

If no statistics is specified, all known statistics will be queried.

## Future development

0MQ supplies bindings for pretty much every language you could care to name (certainly Java, C, Ruby, Python).  This allows for quite a few potential uses in existing code.

The following are a list of ideas for future development (in no particular order):

 * More stats
 * Stats in Sprout/Homer/Homestead
 * Integrate with BGB to report stats across a deployment
 * Integrate with Chef commands as a knife plugin
 * A splunk-like stats collector
 * Using 0MQ as a configuration interface
 * Using 0MQ as a clustering device
