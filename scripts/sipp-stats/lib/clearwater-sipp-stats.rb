#!/usr/bin/env ruby

# @file clearwater-sipp-stats.rb
#
# Copyright (C) Metaswitch Networks
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

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
