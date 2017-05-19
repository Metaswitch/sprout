#!/bin/bash

# @file poll_restund.sh
#
# Copyright (C) Metaswitch Networks
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

# This script uses a STUN message to poll restund and check whether it is
# healthy.

# Read the config, defaulting appropriately.
. /etc/clearwater/config

# Send the STUN message.  The nc line also includes checking the first line of the response starts
# "\x01\x01" - a positive response.
# The -q option forces netcat to quit after 1 second. This works
# around a netcat bug where it tight-loops forever if the UDP port
# it's trying to contact is closed.
printf '\x00\x01\x00\x00\x21\x12\xa4\x42MonitPollXid' |
nc -v -C -u -w 2 -q 1 $local_ip 3478 2> /tmp/poll_restund.sh.nc.stderr.$$ | tee /tmp/poll_restund.sh.nc.stdout.$$ | head -1 | grep -U -P -q '^\x01\x01'
rc=$?

# Check the return code and log if appropriate
if [ $rc != 0 ] ; then
  echo STUN poll failed to $local_ip    >&2
  cat /tmp/poll_restund.sh.nc.stderr.$$ >&2
  cat /tmp/poll_restund.sh.nc.stdout.$$ >&2
fi
rm -f /tmp/poll_restund.sh.nc.stderr.$$ /tmp/poll_restund.sh.nc.stdout.$$

exit $rc
