#!/bin/bash

# Copyright (C) Metaswitch Networks 2017
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

import jsonschema
import json
import sys

schema_file = sys.argv[1]
config_file = sys.argv[2]

try:
    schema = json.load(open(schema_file))
except ValueError:
    print "Uploading {} is aborted: {} is not valid json".format(config_file, schema_file)

try:
    config = json.load(open(config_file))
except ValueError:
    print "Uploading {} is aborted: it is not valid json".format(config_file)

validator = jsonschema.Draft3Validator(schema)
error_list = validator.iter_errors(config)

if error_list is not None:
    print "Uploading {} is aborted as the file fails the following format check:".format(config_file)
    for error in error_list:
        print "     {}".format(error.message)

