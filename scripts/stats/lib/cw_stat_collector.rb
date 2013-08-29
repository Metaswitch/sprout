#!/usr/bin/env ruby

# @file cw_stat_collector.rb
#
# Project Clearwater - IMS in the Cloud
# Copyright (C) 2013  Metaswitch Networks Ltd
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version, along with the "Special Exception" for use of
# the program along with SSL, set forth below. This program is distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details. You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
# The author can be reached by email at clearwater@metaswitch.com or by
# post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
#
# Special Exception
# Metaswitch Networks Ltd  grants you permission to copy, modify,
# propagate, and distribute a work formed by combining OpenSSL with The
# Software, or a work derivative of such a combination, even if such
# copying, modification, propagation, or distribution would otherwise
# violate the terms of the GPL. You must comply with the GPL in all
# respects for all of the code used other than OpenSSL.
# "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
# Project and licensed under the OpenSSL Licenses, or a work based on such
# software and licensed under the OpenSSL Licenses.
# "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
# under which the OpenSSL Project distributes the OpenSSL toolkit software,
# as those licenses appear in the file LICENSE-OPENSSL.

require 'ffi-rzmq'
require 'optparse'
require 'timeout'

# This class creates and owns a subscription to a statistic exposed by a clearwater component.
#
# The subscription is created at class initialization time but the values will not be read until the run method is called.
#
# The subscription can be created in single-shot mode, where the value of the statistic will be polled once only or in repeated mode, where the collector will loop, reporting changes to the statistic when they happen.
class CWStatCollector
  @@stat_renderers = {}

  # Registers a renderer to use for a given statistic.  If a rendered is not specified, the statistic cannot be queried
  #
  # For most cases, SimpleStatRenderer will be sufficient.
  def self.register_renderer(statname, klass)
    @@stat_renderers[statname] = klass
  end

  # Create a collector for each known statistic.
  #
  # @param options Two options are supported:
  #   - :verbose to add more logging
  #   - :subscribe to use repeated mode
  def self.all_collectors(hostname, options)
    @@stat_renderers.keys.map do |statname|
      CWStatCollector.new(hostname, statname, options)
    end
  end

  # Create a StatCollector and start the subscription.  This will throw an exception if the requested statistic is not recognized.
  #
  # @param options Two options are supported:
  #   - :verbose to add more logging
  #   - :subscribe to use repeated mode
  def initialize(hostname, statname, options)
    fail "Statistic \"#{statname}\" not recognised" if not @@stat_renderers.include? statname
    @verbose = options[:verbose]
    @subscribe = options[:subscribe]
    @statname = statname
    @stat_renderer = @@stat_renderers[statname].new
    log "Creating subscription for #{statname} from #{hostname}"
    log "Stats will be rendered using #{@stat_renderer.class}"
    @context = ZMQ::Context.new
    @socket = @context.socket(ZMQ::SUB)
    @socket.connect("tcp://#{hostname}")
    @socket.setsockopt(ZMQ::SUBSCRIBE, statname)
    @latest_status = {}
    @latest_stats = {}
  end

  # Start the processing to retrieve the value for the collected
  # statistic.  If the collector is in subscribe mode, this function
  # loops forever.  If we don't get our first response within 5
  # seconds, assume the remote node is down and bail out.
  #
  # If a block is given, the rendered statistic will be yielded to the
  # block.  Otherwise, the rendered statistic will be written to
  # STDOUT. If the statistic does not exist (i.e., the subscription
  # does not return OK), the block is not evaluated / nothing is
  # written to STDOUT.
  def run &blk
    begin 
      Timeout::timeout(5) do
        get_stat &blk
      end
    rescue Timeout::Error => e
      puts "Error: No response from host, ensure <hostname> is correct"
      throw e
    rescue Exception => e
      puts "Error: Unexpected exception occurred: #{e}"
      puts e.backtrace
      throw e
    end

    if @subscribe
      loop { get_stat &blk }
    end
  end

  private

  def log msg
    puts "DEBUG: #{msg}" if @verbose
  end

  def read_one_entry
    log "Waiting for next entry"
    @socket.recv_strings(msg = [])
    log "Received entry: #{msg[0]} (#{msg[1]}) => #{msg[2..-1]}"
    @latest_status[msg[0]] = msg[1]
    @latest_stats[msg[0]] = msg[2..-1]
    msg[0]
  end

  def get_stat
    loop do
      topic = read_one_entry
      break if topic == @statname
    end
    if @latest_status[@statname] == "OK"
      rendered_response = @stat_renderer.render(@latest_stats[@statname])
      if block_given?
        yield rendered_response
      else
        puts "#{@statname}:\n#{rendered_response}"
      end
    else
      # Just swallow unknown statistics.
    end
  end
end

# A base class for stat renderers.  A subclass must implement the render method.
#
# @abstract
class AbstractRenderer
  # Render a message (as an array of strings) into an appropriate format for further processing.
  def render msg
    fail "Abstract renderer should never be used directly"
  end
end

# This renderer reports call statistics.
#
# The output format is picked to be human readable, while still easy to
# parse so it can be given to another tool (cacti for example).
class CallStatsRenderer < AbstractRenderer
  # @see AbstractRenderer#render
  def render(msg)
    <<-EOF
initial_registers:#{msg[0]}
initial_registers_delta:#{msg[4]}
ongoing_registers:#{msg[1]}
ongoing_registers_delta:#{msg[5]}
call_attempts:#{msg[2]}
call_attempts_delta:#{msg[6]}
successful_calls:#{msg[4]}
successful_calls_delta:#{msg[7]}
    EOF
  end
end

# This simple renderer assumes that there is only one section in the reported statistic and extracts it.
#
# This will be sufficient for many statistics.
class SimpleStatRenderer < AbstractRenderer
  # @see AbstractRenderer#render
  def render(msg)
    msg[0] or "No value returned"
  end
end

# The connected_sprouts (etc) statistic is reported as:
#
# <ip_address1>
#
# <connection_count1>
#
# <ip_address2>
#
# <connection_count2>
#
# <ip_address3>
#
# <connection_count3>
#
# ...
#
# We convert it into a hash of ip_address => connection_count
class ConnectedIpsRenderer < AbstractRenderer
  # @see AbstractRenderer#render
  def render(msg)
    hash = {}
    while not msg.empty?
      k = msg.shift
      v = msg.shift
      hash[k] = v.to_i
    end
    hash
  end
end

# This renderer reports latency statistics.
#
# The output format is picked to be human readable, while still easy to
# parse so it can be given to another tool (cacti for example).
class LatencyStatsRenderer < AbstractRenderer
  # @see AbstractRenderer#render
  def render(msg)
    <<-EOF
mean:#{msg[0]}
variance:#{msg[1]}
lwm:#{msg[2]}
hwm:#{msg[3]}
    EOF
  end
end

# Register the statistics we currently expose
CWStatCollector.register_renderer("client_count", SimpleStatRenderer)
CWStatCollector.register_renderer("connected_homesteads", ConnectedIpsRenderer)
CWStatCollector.register_renderer("connected_homers", ConnectedIpsRenderer)
CWStatCollector.register_renderer("connected_sprouts", ConnectedIpsRenderer)
CWStatCollector.register_renderer("call_stats", CallStatsRenderer)
CWStatCollector.register_renderer("latency_us", LatencyStatsRenderer)
