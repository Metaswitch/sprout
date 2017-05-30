#!/bin/bash

# @file on-eclipse-build.sh
#
# Copyright (C) Metaswitch Networks 2013
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

if [ -e 'on-eclipse-build.local.sh' ]; then
  ./on-eclipse-build.local.sh
fi
