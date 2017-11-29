#!/bin/bash

# @file poll_sprout_http.sh
#
# Copyright (C) Metaswitch Networks 2016
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

scscf=5054
. /etc/clearwater/config
rc=0

# If we have S-CSCF configured, check it.
if [ "$scscf" != "0" ] ; then
  http_ip=$(/usr/share/clearwater/bin/bracket-ipv6-address $local_ip)
  /usr/share/clearwater/bin/poll-http $http_ip:9888
  rc=$?
fi

# If the sprout process is not stable, we ignore a non-zero return code and
# return zero.
if [ $rc != 0 ]; then
  /usr/share/clearwater/infrastructure/monit_stability/sprout-stability check
  if [ $? != 0 ]; then
    echo "return code $rc ignored" >&2
    rc=0
  fi
fi

exit $rc
