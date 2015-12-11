#!/usr/bin/env ruby

# @file clearwater-sipp-stats.rb
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

# Utility function to parse a 'change to subscribers' message.  The
# format is a single byte with a value of 0 or 1 for unsubscribe and
# subscribe respectively, followed by the subscribed topic.
#
# @return [[Boolean, String]] The first value indicates if this is a new
#   subscription, the second is the topic subscribed for.
def parse_sub_msg(message)
  bytes = message.bytes.to_a
  connect = bytes[0] == 1
  topic = bytes[1..-1].map { |b| b.chr }.join
  [connect, topic]
end

c = ZMQ::Context.new
s = c.socket(ZMQ::XPUB)
s.setsockopt(ZMQ::RCVTIMEO, 1000)
s.bind("tcp://*:6666")

# All statistics and deltas begin at 0
initial_old_stats = ["0"] * 8
old_stats = initial_old_stats
loop do
  begin
    # Reload the CSV file in case SIPp has crashed
    stats_file = Dir.glob("/var/log/clearwater-sipp/sip-stress_*_counts.csv").sort_by { |f| File.mtime(f) }.reverse.first
    f = File.open(stats_file)
    f.seek(0, IO::SEEK_END)
  rescue Exception => e
    # There is no stats file or we can't read it
    puts "Error: #{e.class} - #{e.message}, retrying"
    sleep 1
    retry
  end

  # Wait up to one second (see setting of ZMQ::RCVTIMEO above) for a
  # new subscriber to appear, this also gives SIPp a chance to write some
  # new stats
  sub_msg = ""
  if s.recv_string(sub_msg) != -1
    connect, topic = parse_sub_msg(sub_msg)
    if connect
      if topic == "call_stats"
        puts "New subscriber, publishing last known values"
        s.send_strings ["call_stats", "OK"] + old_stats
      else
        puts "Unknown statistic requested"
        s.send_strings [topic, "Unknown"]
      end
    end
  end

  # Check if the stats file has changed, if not then f.readline will throw
  # an EOFError.
  begin 
    line = f.readline
    fields = line.split ';'
    # Pull out fields
    #  4 - "2_REGISTER_Sent", i.e. number of initial REGISTERs sent
    # 28 - "10_REGISTER_Sent", i.e. number of re-REGISTERs sent
    # 44 - "17_INVITE_Sent", i.e. number of INVITEs sent
    # 92 - "35_200_Recv", i.e. number of 200 OKs to BYEs received
    stats = fields.values_at(4, 28, 44, 92)

    # Calculate the deltas.  If we've not yet seen two real sets of values
    # then we should report zeros otherwise the first non-zero result will 
    # be factors larger than the others.
    deltas = stats.zip(old_stats).map do |values|
      (values[0].to_i - values[1].to_i).to_s
    end unless old_stats == initial_old_stats
    deltas = ["0"] * 4 if deltas.nil?

    # Broadcast the new statistics
    message = ["call_stats"] + stats + deltas
    s.send_strings message
    puts "New statistics generated, publishing"
    old_stats = stats + deltas
  rescue EOFError
    # File is still at EOF, nothing to do
  end
end
