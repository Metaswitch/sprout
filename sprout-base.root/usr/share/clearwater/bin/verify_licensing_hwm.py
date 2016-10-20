#!/usr/bin/python
# Copyright (C) 2016 Metaswitch Networks Ltd

import sys
import re
import glob
import os
from collections import defaultdict
import argparse
import csv
import time
import datetime
import logging

TEMP_DIR = 'tmp'
OUTPUT_FILE_SUBSCRIBERS = 'registered_subscribers.csv'
OUTPUT_FILE_BINDINGS = 'registered_bindings.csv'
def bucket_dir(bucket):
    return os.path.join(TEMP_DIR, "bucket" + str(bucket))
LOG_FILENAME = 'verify_licensing_hwm.log'

# We can't be certain that logs appear in log files on the syslog server in
# strict chronological order.  To determine whether a log file might contain
# logs that are relevant to the time we are interested in, we look at the
# timestamps of the first and last logs in the file, and parse the file if they
# are witin TIME_MARGIN_MS of being applicable.
TIME_MARGIN_MS = 10 * 60 * 1000

EPOCH_DT = datetime.datetime.utcfromtimestamp(0)

def split_into_buckets(fname, bucket_dir_fn, buckets):
    """
    Take a file containing Sprout registration logs and split in into a set of
    N files, by assigning each log to a bucket based on it's IMPU.   The output
    files all have the same name but are placed in bucket scope subdirectories.

    Arguments:
      fname   -- the log file to process
      bucket_dir_fn
              -- a function that takes a bucket number and returns the
              directory to which that bucket's logs should be written.
      buckets -- the number of buckets to split the log file into.
    """

    logging.info("Split file %s" % fname)

    file_handles = {}
    for bucket in range(buckets):
        file_handles[bucket] = open(os.path.join(bucket_dir_fn(bucket), fname),
                                    'wa')

    with open(fname, 'r') as fh:
        for line in fh:
            try:
                line_info = decode_line(line)
                bucket = abs(hash(line_info["impu"])) % buckets
                file_handles[bucket].write(line)
            except:
                # We couldn't process this line.   Just skip it.
                pass

    for bucket in file_handles:
        file_handles[bucket].close()

def process_bucket(bucket_dir, subscriber_writer, binding_writer,
                   time_of_interest_ms):
    """
    Takes a set of log files containing all registration logs relating to a
    subset of IMPUs and determines which IMPUs (subscribers) / bindings were
    registered at a given time of interest.

    Arguments:
      bucket_dir        -- the directory containing the log files to process
      subscriber_writer -- a CSV writer to which the set of registered IMPUs
                           should be written
      binding_writer    -- a CSV writer to which the set of regsitered bindings
                           should be written
      time_of_interest_ms -- the time at which we wish to know the number of
                             registrations
    """

    bucket_file_list = glob.glob(os.path.join(bucket_dir, "*"))

    # Build up information about registered bindings in a dictionary of
    # dictionaries, indexed first by IMPU and then by binding ID.
    #
    # At the end of processing this data structure will contain a record for
    # each binging that we've seen at least once containing:
    # - the time that we last saw a register for this binding
    # - an expiry time which is 0 if the binding WAS NOT still registered at
    # the time we are interested in, and > 0 if the binding WAS registered at
    # that time.
    binding_data = defaultdict(dict)
    for fname in bucket_file_list:
        logging.debug("Processing bucket file %s" % fname)
        with open(fname, 'r') as fh:
            for line in fh:
                line_info = decode_line(line)

                try:
                    log_time_ms = string_to_ms(line_info["timestamp_str"])
                except:
                    # Can't decode the timestamp in this log.   Skip it.
                    logging.warning("Cannot decode timestamp in log %s from " \
                                    "file %s" % (line, fname))
                    continue

                log_impu = line_info["impu"]
                log_binding = line_info["binding"]
                log_expires_ms = int(line_info["expires_ms"])

                # Did this log happen before the point we're interested in?
                if (log_time_ms > time_of_interest_ms):
                    continue

                # Get the record for this IMPU, creating one if it doesn't
                # exist.
                impu_record = binding_data[log_impu]

                # If there is already a record for this binding that has been
                # updated more recently than this log then ignore this log
                if ((log_binding in impu_record) and
                        (impu_record[log_binding]["updated_ms"] > log_time_ms)):
                    continue

                # We now know that this log happened before the time of
                # interest, but more recently than any information we already
                # had for the binding.  It therefore supercedes anything that
                # was already stored.

                # If this is a register that expires before the time we are
                # interested in then it's effectively a de-register...
                if ((log_expires_ms > 0) and
                    ((log_time_ms + log_expires_ms) < time_of_interest_ms)):
                    log_expires_ms = 0

                impu_record[log_binding] = {"updated_ms": log_time_ms,
                                            "expires_ms": log_expires_ms}

    # Now we need to run through binding_data and
    # - count up the number of registered IMPUs / bindings (where an IMPU is
    #   registered if it has at least one registered binding)
    # - write out the details about all registered IMPUs / bindings.
    registered_subs = 0
    registered_bindings = 0

    for impu, impu_record in binding_data.iteritems():
        # Track the number of bindings registered for this IMPU
        registered_impu_bindings = 0
        for binding, binding_record in impu_record.iteritems():
            if binding_record["expires_ms"] > 0:
                registered_impu_bindings = registered_impu_bindings + 1
                registered_bindings = registered_bindings + 1
                binding_writer.writerow({
                    'IMPU': impu,
                    'Binding ID': binding,
                    'Last update': str(binding_record["updated_ms"]),
                    'Expires': binding_record["expires_ms"]/1000})
        # If there was at least one registered binding then the IMPU was
        # registered.
        if registered_impu_bindings > 0:
            registered_subs = registered_subs + 1
            subscriber_writer.writerow({'IMPU': impu})

    return {"subs":registered_subs, "binds":registered_bindings}

def file_is_relevant(fname, time_of_interest_ms, max_expiry_time_ms):
    """
    Look at the first and last entries in a registration log file to determine
    (based on timestamp) whetether the log file may contain logs that are
    relevant in determining which bindings were registered at a given time.

    Arguments:
      fname -- the name of the log file to process
      time_of_interest_ms
            -- the time at which we want to know which bindings were registered.
      max_expiry_time_ms
            -- the maximum registration expiry time permitted by the system
               (used to determine the oldest logs that may be relevant).
    """

    with open(fname, 'rb') as fh:
        # Check the first line of the file.
        try:
            first_line_info = decode_line(next(fh).decode())
            first_line_ms = string_to_ms(first_line_info["timestamp_str"])

            # Check whether the events in this file are too late to be of
            # interest.  See comment on TIME_MARGIN_MS.
            if ((first_line_ms - TIME_MARGIN_MS) > time_of_interest_ms):
                logging.info("Skipping file %s (events too late)" % fname)
                return False

        except:
            # Failed to parse the first line.  There may still be other logs in
            # the file that are of interest...
            logging.error("Failed to parse first line of file %s" % fname)

        # Check the last line of the file.
        try:
            fh.seek(-500, 2)
        except:
            # File is less than 500 bytes long -- reset the file poistion to the
            # beginning and we'll just read all of it.
            fh.seek(0, 0)
        try:
            last_line_info = decode_line(fh.readlines()[-1].decode())
            last_line_ms = string_to_ms(last_line_info["timestamp_str"])

            # If the last event in the file is so early that even a register
            # with the maximum possible expiry time would have expired before
            # the time we are interested in then we assume the file isn't of
            # interest.  See comment on TIME_MARGIN_MS.
            if ((last_line_ms + max_expiry_time_ms + TIME_MARGIN_MS) <
                    time_of_interest_ms):
                logging.info("Skipping file %s (events too early: " \
                             "last timestamp = %d)" % (fname, last_line_ms))
                return False
        except:
            # Veer on the side of caution -- we failed to parse the last line,
            # but there may be events in this file that are of interest still.
            logging.error("Failed to parse last line of file %s" % fname)

        # Looks like at least some of the events in this file might be of
        # interest.
        return True

def decode_line(line):
    """
    Decode a Registration log.

    Arguments:
      line -- a string containing the log to be decoded.
    """
    regex = "(?P<timestamp_str>.*) Registration: USER_URI=(?P<impu>.*) BINDING_ID=(?P<binding>[^ ]*).*EXPIRES=(?P<expires>\d+)"
    match_result = re.match(regex, line)
    if match_result is None:
        logging.error("Cannot parse line: %s" % line)
        raise Exception()

    return {"timestamp_str": match_result.group("timestamp_str"),
            "impu": match_result.group("impu"),
            "binding": match_result.group("binding"),
            "expires_ms": int(match_result.group("expires")) * 1000}

def string_to_ms(timestamp_str):
    """
    Convert a timestamp string to ms since the epoch.   Assumes that the
    timestamp string is UTC and is in RFC3339 format.

    Arguments:
      timestamp_str -- The timestamp to convert (UTC timestamp in RFC3339
                       format)
    """
    timestamp_dt = datetime.datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f+00:00')
    timestamp_ms = int((timestamp_dt - EPOCH_DT).total_seconds() * 1000.0)
    return timestamp_ms

def main():
    # ToDo: remote this after we finish testing
    start_time = time.time()

    parser = argparse.ArgumentParser(
        description='Verify the number of ' \
            'subscribers and bindings that were registered at a given time ' \
            'by parsing registration syslogs from Sprout nodes. ' \
            'The script outputs counts of registered subscibers and bindings ' \
            'and also writes lists of registered IMPUs and binding IDs to ' \
            + OUTPUT_FILE_SUBSCRIBERS + ' and ' + OUTPUT_FILE_BINDINGS +
            ' respectively.  This script must be run on a syslog server that ' \
            'has copies of Registration logs from all Sprout nodes in the ' \
            'deployment over the time period in question.')
    parser.add_argument('timestamp_s',
        type=int,
        help='the time at which the number of registrations should be ' \
             'determined.   Specicified in seconds since the epoch.')
    parser.add_argument('logfiles_directory',
        help='the directory in which the sprout registration logs are ' \
             'located.')
    parser.add_argument('--max_expiry',
        metavar='N (minutes)',
        dest='max_expiry_time_m',
        action='store',
        default=60,
        type=int,
        help='the maximum registration expiry time permitted in the ' \
             'deployment (in minutes).  This does not need to be precise but ' \
             'setting this value too high will ' \
             'reduce script performance.   Setting this value too low will ' \
             'cause the script to return inaccurate results.  Default: 60m')
    parser.add_argument('--subs',
        metavar='N',
        dest='num_subs',
        action='store',
        default=1000000,
        type=int,
        help='the approximate number of subscribers in the deployment. ' \
             'Default 1000000.   This value is only used to optimize ' \
             'performance, but setting it too low may cause the script to ' \
             'fail due to lack of resources.')
    parser.add_argument('--debug',
        dest='debug',
        action='store_true',
        help='write debug logs to ' + LOG_FILENAME)

    args = parser.parse_args()

    if (args.debug):
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=LOG_FILENAME,
                        level=log_level,
                        format="%(asctime)s - %(levelname)s - %(message)s")

    max_expiry_time_ms = args.max_expiry_time_m * 60 * 1000
    timestamp_ms = args.timestamp_s * 1000

    # On a large system (e.g. 1m+ subscribers) we can't rely on being able to
    # build up a single table of all bindings in RAM.   (1m registered
    # subsribers would use O(1GB) of RAM).  To avoid this and to ensure that we
    # can scale to an arbitrary number of subscribers we first re-write the logs
    # into a set of "log buckets" with logs assigned to a bucket by hashing the
    # subscriber's IMPU.   This means that all logs relating to a single
    # subscriber get assigned to the same bucket (meaning that the bucket can be
    # processed in isolation) whilst reducing the number of subscribers in each
    # bucket by a factor of the number of buckets.
    # Calculate the number of buckets by dividing the expected number of
    # subscribers by 10.  By default we assume 1 million subs / 10 buckets.
    buckets = max(1, int(args.num_subs / 100000))

    # Check that the temporary directory we are going to use for our interim log
    # files does not already exist.   If it does, prompt the user to delete it
    # and re-run, otherwise create it.
    # WIBNI: Would be better to prompt the user and ask for confirmation that it
    # is OK for us to overwrite the existing directory.
    if os.path.exists(TEMP_DIR):
        print "Temporary directory " + TEMP_DIR + " already exists -- please " \
              "delete before running this script."
        sys.exit()
    os.makedirs(TEMP_DIR)

    # Make subdirectories for each of the buckets we're going to use.
    for bucket in range(buckets):
        os.makedirs(bucket_dir(bucket))

    # ToDo: confirm file names and fixup filter appropriately.
    # Loop over all of the input log files and split them into buckets.
    print "Pre-processing log files:"
    raw_file_list = glob.glob(os.path.join(args.logfiles_directory,'log*'))
    for fname in raw_file_list:
        if (file_is_relevant(fname, timestamp_ms, max_expiry_time_ms)):
            print "  Processing log file %s..." % fname
            split_into_buckets(fname, bucket_dir, buckets)

    total_registered_subs = 0
    total_registered_bindings = 0

    # Open files for the lists of registered subscribers and the list of
    # registered bindings and create CSV writers for them.
    with open(OUTPUT_FILE_SUBSCRIBERS, "w") as registered_subscribers_fh:
        with open(OUTPUT_FILE_BINDINGS, "w") as registered_bindings_fh:
            sub_fieldnames = ['IMPU']
            registered_subscriber_writer = csv.DictWriter(
                                               registered_subscribers_fh,
                                               fieldnames=sub_fieldnames)
            registered_subscriber_writer.writeheader()

            binding_fieldnames = ['IMPU',
                                  'Binding ID',
                                  'Last update',
                                  'Expires']
            registered_binding_writer = csv.DictWriter(
                                            registered_bindings_fh,
                                            fieldnames=binding_fieldnames)
            registered_binding_writer.writeheader()

            # Now run through the buckets of logs we've created one by one and
            # build up counts and lists of registered subscribers and bindings.
            print "Processing %d buckets of logs" % buckets
            for bucket in range(buckets):
                print "  -- processing bucket %d..." % bucket
                counts = process_bucket(bucket_dir(bucket),
                                        registered_subscriber_writer,
                                        registered_binding_writer,
                                        timestamp_ms)
                total_registered_subs = total_registered_subs + counts["subs"]
                total_registered_bindings = (total_registered_bindings +
                                             counts["binds"])

    print "Registered subscribers = %d" % total_registered_subs
    print "Registered bindings = %d" % total_registered_bindings

    #ToDo: remove this after we finish testing.
    end_time=time.time()
    print "Time taken = %d" % (end_time-start_time)

if __name__ == "__main__":
    main()


