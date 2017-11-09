# Copyright (C) Metaswitch Networks 2017
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

import jsonschema
import json
import sys
import yaml

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
HEADERS_LISTS = {"drsn":DRSN_HEADERS, "dsn":DSN_HEADERS, "q735":Q735_HEADERS,
                 "ets":ETS_HEADERS, "wps":WPS_HEADERS}

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

# Load the schema and config files.
try:
    schema = json.load(open(schema_file))
except IOError:
    print "Unable to open {}".format(schema_file)
    sys.exit(1)
except ValueError as e:
    print "{} is not valid.".format(schema_file)
    print "The errors, and the location of the errors in the schema file, are displayed below:"
    print e.message
    sys.exit(1)

try:
    raw_config = json.load(open(config_file))
except IOError:
    print "Unable to open {}.".format(config_file)
    sys.exit(1)
except ValueError as e:
    print "{} is not valid.".format(config_file)
    print "The errors, and the location of the errors in the configuration file, are displayed below:"
    print e.message
    sys.exit(1)

# Validate the config file against the schema.
validator = jsonschema.Draft4Validator(schema)
error_list = sorted(validator.iter_errors(raw_config), key=lambda e: e.path)

# If there were any errors, we want to print them our in a user friendly
# fashion, then exit with a failure code.

# For each error, we have a deque that tells us where in the file the error is,
# and a string that holds the actual error message, e.g.:
#   "deque([u'hostnames', 0, u'records', u'target'])"
#   "1 is not of type u'string'"
#
# We want to turn this into a list that maps to the structure of the JSON file,
# e.g.:
#
# hostnames:
#   element 1:
#     The errors are:
#     - Additional properties are not allowed ('name2' was unexpected)
#     name:
#       The errors are:
#       - 1 is not of type 'string'
#     records:
#       rrtype:
#         The errors are:
#         - 'CNAME2' does not match '^CNAME$'
#       target:
#         The errors are:
#         - 1 is not of type 'string'
#
# We construct a nested dictionary of the errors, then print it out in a YAML
# format.
if error_list:
    print "{} is not valid.".format(config_file)
    print "The errors, and the location of the errors in the configuration file, are displayed below:"

    temp_dict = {}
    for error in error_list:
        nest = temp_dict

        # Treat the first entry differently, as this is the key we'll use to
        # actually set the error messages in the dictionary.
        if len(error.path) == 0:
            last = "Top level"
        else:
            last = error.path.pop()

        if isinstance(last, int):
            last = 'element %i' % (last + 1)

        for error_part in error.path:
            if isinstance(error_part, int):
                error_part = 'element %i' % (error_part + 1)

            nest = nest.setdefault(str(error_part), {})

        nest.setdefault(str(last), {}).setdefault('The errors are', []).append(error.message)

    print(yaml.dump(temp_dict, default_flow_style=False).replace("u'", "'"))
    sys.exit(1)

# If we have reached this point, the config file has been validated against the
# schema, so we can parse it with confidence.
parsed_config = {}
error_list = []

encountered_priorities = []
for priority_block in raw_config[PRIORITY_BLOCKS]:
    priority = priority_block[PRIORITY]
    if priority in encountered_priorities:
        error_list.append("More than one priority block with priority {} " \
                          "is present.".format(priority))
    else:
        encountered_priorities.append(priority)
    if RPH_VALUES in priority_block:
        headers_with_priority = priority_block[RPH_VALUES]
        for header in headers_with_priority:
            if header in parsed_config:
                error_list.append("{} is present more than once.".format(header))
            else:
                parsed_config.update({header:priority})

# Check the priorites are set in a way which is valid.
# A higher priority header cannot be given a lower priority than a lower priority
# header (ie. wps.0 must be higher proirity that wps.1).
for header_list in HEADERS_LISTS:
    headers_to_check = HEADERS_LISTS[header_list]
    place_in_list = 0
    for header in headers_to_check:
        if header in parsed_config:
            header_priority = parsed_config[header]
            remainder_of_list = headers_to_check[(place_in_list + 1):len(headers_to_check)]
            for higher_priority_header in remainder_of_list:
                if higher_priority_header not in parsed_config:
                    error = "{} is not present, which will result in it " \
                            "having a lower priority than {}, which is not " \
                            "permitted.".format(higher_priority_header, header)
                    error_list.append(error)
                else:
                    next_priority = parsed_config[higher_priority_header]
                    if next_priority <= header_priority:
                        error = "{} is not a higher priority than {}, which " \
                                "is not permitted.".format(higher_priority_header,
                                header)
                        error_list.append(error)
        place_in_list += 1

# If any errors were found during the additional validation, print them out, and
# exit with a failure code.
if error_list:
    print "{} is not valid.".format(config_file)
    print "The erros are printed below:"

    for error in error_list:
        print error

    sys.exit(1)

