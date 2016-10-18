#!/usr/bin/python
# Copyright (C) 2016 Metaswitch Networks Ltd

import sys
import requests
import re
import datetime
import calendar
import glob
import os
from collections import defaultdict

## ToDo: figure out whether it is OK to use this and if so put error handling in
from dateutil import parser

TEMP_DIR = './tmp'
BUCKET_DIR = os.path.join(TEMP_DIR, 'bucketed_logs')
OUTPUT_FILE_SUBSCRIBERS = './registered_subscribers.csv'
OUTPUT_FILE_BINDINGS = './registered_bindings.csv'

def print_usage():
    print "Usage: verify_licensing_hwm TIMESTAMP LOGFILE_DIR " \
          "[MAX_EXPIRY_TIME] [NUMBER_OF_SUBSCRIBERS]"
    print "-- TIMESTAMP is the time of the HWM that you wish to verify in UTC" \
          " time"
    print "-- LOGFILE_DIR species the directory in which the Sprout log " \
          "files are located"
    print "-- MAX_EXPIRY_TIME is the maximum registration expiry time " \
          "permitted in the deployment (in minutes).  Default 5"
    print "-- NUMBER_OF_SUBSCRIBERS is the approximate number of subscribers " \
          "in the deployment.  Default 1000000.  This value is only used " \
          "to optimize script performance, but if set too low the script " \
          "may use excessive amounts of resources."

def split_into_buckets(fname, buckets, timestamp_dt, max_expiry_time_s):
    print "Splitting file %s" % fname
    file_handles = {}

    for bucket in range(buckets):
        file_handles[bucket] = open(os.path.join(BUCKET_DIR, "bucket_" +
            str(bucket) + ".log"), 'wa')

    with open(fname, 'r') as fh:
        for line in fh:
            line_info = decode_line(line)
            bucket = abs(hash(line_info["impu"])) % buckets
            file_handles[bucket].write(line)

    for bucket in file_handles:
        file_handles[bucket].close()

def process_bucket(fname, subscribers_fh, bindings_fh, timestamp_dt):
    print "Processing bucket file %s" % fname

    binding_data = defaultdict(dict)

    # Build up binding data so that it is indexed first by IMPU and then by
    # binding.
    # At the end of processing we have a record for each binding that we've seen
    # at least once containing:
    # - the time that we last saw a register for this binding
    # - an expiry time which is 0 if the binding was not registered at the time
    # we are interested in, and > 0 if the binding was registered at that time.
    with open(fname, 'r') as fh:
        for line in fh:
            line_info = decode_line(line)

            log_time_dt = line_info["timestamp_dt"]
            log_impu = line_info["impu"]
            log_binding = line_info["binding"]
            log_expires = int(line_info["expires"])

            # Did this log happen before the point we're interested in?
            if (log_time_dt > timestamp_dt):
                continue

            # Get the record for this IMPU, creating one if it doesn't exist.
            impu_record = binding_data[log_impu]

            # If there is already a record for this binding that has been
            # updated more recently than this log then ignore this log
            if ((log_binding in impu_record) and
                    (impu_record[log_binding]["updated"] > log_time_dt)):
                continue

            # We now know that this log happened before the time of interest,
            # but more recently than any information we already had for the
            # binding.  It therefore supercedes anything that was already
            # stored.

            # If this is a register that expires before the time we are
            # interested in then it's effectively a de-register...
            if ((log_expires > 0) and
                ((log_time_dt + datetime.timedelta(seconds=log_expires)) <
                    timestamp_dt)):
                log_expires = 0

            impu_record[log_binding] = {"updated": log_time_dt,
                                        "expires": log_expires}


    registered_subs = 0
    registered_bindings = 0

    for impu, impu_record in binding_data.iteritems():
        registered_impu_bindings = 0
        for binding, binding_record in impu_record.iteritems():
            if binding_record["expires"] > 0:
                registered_impu_bindings = registered_impu_bindings + 1
                registered_bindings = registered_bindings + 1
                bindings_fh.write("%s,%s,%s,%d\n" % (impu,
                                                   binding,
                                                   str(binding_record["updated"]),
                                                   binding_record["expires"]))
        if registered_impu_bindings > 0:
            registered_subs = registered_subs + 1
            subscribers_fh.write("%s\n" % impu)

    return {"subs":registered_subs, "binds":registered_bindings}


def file_is_relevant(fname, timestamp_dt, max_expiry_time_s):
    with open(fname, 'rb') as fh:
        first_line_info = decode_line(next(fh).decode())
        fh.seek(-1024, 2)
        last_line_info = decode_line(fh.readlines()[-1].decode())

        # When deciding whether this file is relevant we allow a margin or error
        # as we can't be sure that the logs are in absolute chronological order.
        time_margin = datetime.timedelta(hours=1)
        if (((first_line_info["timestamp_dt"] - time_margin) > timestamp_dt) or
                ((last_line_info["timestamp_dt"]
                  + datetime.timedelta(seconds=max_expiry_time_s)
                  + time_margin) < timestamp_dt)):
            print "Skipping file %s" % fname
            return False
        return True

def decode_line(line):
    regex = "(?P<timestamp>.*) Registration: USER_URI=(?P<impu>.*) BINDING_ID=(?P<binding>[^ ]*).*EXPIRES=(?P<expires>.*)"
    match_result = re.match(regex, line)
    if match_result is None:
        print "Error: Cannot parse line: %s" % line
        sys.exit()

    timestamp_dt = parser.parse(match_result.group("timestamp"))

    return {"timestamp_dt": timestamp_dt,
            "impu": match_result.group("impu"),
            "binding": match_result.group("binding"),
            "expires": match_result.group("expires")}


if __name__ == "__main__":

    if (len(sys.argv) < 3):
        print_usage()
        sys.exit(1)

    # ToDo: Can we just assume that the timestamp entered here is in the same timezone
    # as the timestamp that appears in the syslogs?
    try:
        timestamp_dt = parser.parse(sys.argv[1])
    except:
        print "Unrecognised timestamp format"
        sys.exit()

    if (len(sys.argv) >= 4):
        try:
            max_expiry_time_s = int(sys.argv[3]) * 60
        except:
            print "%s is not a valid value for MAX_EXPIRY_TIME\n" % (sys.argv[3])
            print_usage()
            sys.exit()
    else:
       max_expiry_time_s = 300

    if (len(sys.argv) >= 5):
        try:
            buckets = max(1, int(int(sys.argv[4]) / 100000))
        except:
            print "%s is not a valid value for NUMBER_OF_SUBSCRIBERS\n" % (sys.argv[4])
            print_usage()
            sys.exit()
    else:
       buckets = 10

    raw_file_list = glob.glob(sys.argv[2] + '/log*')

    if os.path.exists(TEMP_DIR):
        print "Temporary directory " + TEMP_DIR + " already exists -- please " \
              "delete before running this script"
        sys.exit()
    os.makedirs(TEMP_DIR)
    os.makedirs(BUCKET_DIR)

    registered_subscribers_fh = open(OUTPUT_FILE_SUBSCRIBERS, "w")
    registered_bindings_fh = open(OUTPUT_FILE_BINDINGS, "w")

    for fname in raw_file_list:
        if (file_is_relevant(fname, timestamp_dt, max_expiry_time_s)):
            split_into_buckets(fname, buckets, timestamp_dt, max_expiry_time_s)

    bucket_file_list = glob.glob(BUCKET_DIR + '/*')

    total_registered_subs = 0
    total_registered_bindings = 0

    for fname in bucket_file_list:
        counts = process_bucket(fname,
                                registered_subscribers_fh,
                                registered_bindings_fh,
                                timestamp_dt)
        total_registered_subs = total_registered_subs + counts["subs"]
        total_registered_bindings = total_registered_bindings + counts["binds"]

    print "Registered subscribers = %d" % total_registered_subs
    print "Registered bindings = %d" % total_registered_bindings


