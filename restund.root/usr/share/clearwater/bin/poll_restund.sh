#!/bin/bash

# @file poll_restund.sh
#
# Project Clearwater - IMS in the Cloud
# Copyright (C) 2014  Metaswitch Networks Ltd
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

# This script uses a STUN message to poll restund and check whether it is
# healthy.

# In case restund has only just restarted, give it a few seconds to come up
sleep 5

# Read the config, defaulting appropriately.
. /etc/clearwater/config

# Send the STUN message.  The nc line also includes checking the first line of the response starts
# "\x01\x01" - a positive response.
printf '\x00\x01\x00\x00\x21\x12\xa4\x42MonitPollXid' |
nc -v -C -u -w 2 $local_ip 3478 2> /tmp/poll_restund.sh.nc.stderr.$$ | tee /tmp/poll_restund.sh.nc.stdout.$$ | head -1 | grep -U -P -q '^\x01\x01'
rc=$?

# Check the return code and log if appropriate
if [ $rc != 0 ] ; then
  echo STUN poll failed to $local_ip    >&2
  cat /tmp/poll_restund.sh.nc.stderr.$$ >&2
  cat /tmp/poll_restund.sh.nc.stdout.$$ >&2
fi
rm -f /tmp/poll_restund.sh.nc.stderr.$$ /tmp/poll_restund.sh.nc.stdout.$$

exit $rc
