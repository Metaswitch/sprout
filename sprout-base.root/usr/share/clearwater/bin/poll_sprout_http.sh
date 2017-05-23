#!/bin/bash

# @file poll_sprout_http.sh
#
# Copyright (C) Metaswitch Networks 2017
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

scscf=5054
. /etc/clearwater/config

# If we have S-CSCF configured, check it.
rc=0
if [ "$scscf" != "0" ] ; then
  http_ip=$(/usr/share/clearwater/bin/bracket-ipv6-address $local_ip)
  /usr/share/clearwater/bin/poll-http $http_ip:9888
  rc=$?
fi

exit $rc
