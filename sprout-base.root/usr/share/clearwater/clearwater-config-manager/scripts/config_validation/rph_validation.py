# @file rph_validation.py
#
# Copyright (C) Metaswitch Networks 2017
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

import json
import subprocess
import sys
JSON_GENERIC_VALIDATE = '/usr/share/clearwater/clearwater-config-manager/scripts/validate_json.py'

# All possible Resource Priority header values specified in RFC 4412.
# Each separate headers list is in order from low priority to high priority
# (ie. wps.0 is higher priority than wps.1).
DRSN_HEADERS = ["drsn.routine", "drsn.priority", "drsn.immediate",
                "drsn.flash", "drsn.flash-override",
                "drsn.flash-override-override"]
DSN_HEADERS = ["dsn.routine", "dsn.priority", "dsn.immediate",
               "dsn.flash", "dsn.flash-override"]
Q735_HEADERS = ["q735.4", "q735.3", "q735.2", "q735.1", "q735.0"]
ETS_HEADERS = ["ets.4", "ets.3", "ets.2", "ets.1", "ets.0"]
WPS_HEADERS = ["wps.4", "wps.3", "wps.2", "wps.1", "wps.0"]
HEADERS_LISTS = {"drsn": DRSN_HEADERS, "dsn": DSN_HEADERS,
                 "q735": Q735_HEADERS, "ets": ETS_HEADERS, "wps": WPS_HEADERS}

# Headers in the RPH json config file.
PRIORITY_BLOCKS = "priority_blocks"
PRIORITY = "priority"
RPH_VALUES = "rph_values"


# Parse the commmand line options.
if len(sys.argv) != 3:
    print "Usage: python rph_validation.py <schema to validate against> <file to validate>"
    sys.exit(1)

schema_file = sys.argv[1]
config_file = sys.argv[2]

error_list = []

# Validate the config file against the schema.
try:
    subprocess.check_output(['python', JSON_GENERIC_VALIDATE, schema_file,
                             config_file], stderr=subprocess.STDOUT)
except subprocess.CalledProcessError as exc:
    errors = exc.output.splitlines()
    error_list.extend(errors)
    for line in errors:
        print line
    sys.exit(1)

# If we have reached this point, the config file exists and has been validated
# against the schema, so we can load and parse the config file with confidence.
raw_config = json.load(open(config_file))

parsed_config = {}

encountered_priorities = []
for priority_block in raw_config[PRIORITY_BLOCKS]:
    priority = priority_block[PRIORITY]
    if priority in encountered_priorities:
        error_list.append("More than one priority block with priority {} "
                          "is present.".format(priority))
    else:
        encountered_priorities.append(priority)
    if RPH_VALUES in priority_block:
        headers_with_priority = priority_block[RPH_VALUES]
        for header in headers_with_priority:
            # RFC 4412 states namespace names are case insensitive, so these
            # names could be present in any mix of upper/lower case. For string
            # comparison reasons, convert them all to be lower case.
            if header.lower() in parsed_config:
                error_list.append("{} is present more than once.".format(header.lower()))
            else:
                parsed_config.update({header.lower(): priority})

# Check the priorites are set in a way which is valid.
# A higher priority header cannot be given a lower priority than a lower
# priority header (ie. wps.0 must be higher proirity that wps.1).
for header_list in HEADERS_LISTS:
    headers_to_check = HEADERS_LISTS[header_list]
    place_in_list = 0
    for header in headers_to_check:
        if header in parsed_config:
            header_priority = parsed_config[header]
            if (place_in_list + 1) < len(headers_to_check):
                higher_priority_header = headers_to_check[place_in_list + 1]
                if higher_priority_header not in parsed_config:
                    error = "{} is not present, which will result in it " \
                            "having a lower priority than {}, which is not " \
                            "permitted.".format(higher_priority_header, header)
                    error_list.append(error)
                else:
                    next_priority = parsed_config[higher_priority_header]
                    if next_priority < header_priority:
                        error = "{} is a lower priority than {}, which is " \
                                "not permitted.".format(
                                        higher_priority_header, header)
                        error_list.append(error)
        place_in_list += 1

# If any errors were found during the additional validation, print them out,
# and exit with a failure code.
if error_list:
    print "{} is not valid.".format(config_file)
    print "The errors are printed below:"

    for error in error_list:
        print error

    sys.exit(1)
