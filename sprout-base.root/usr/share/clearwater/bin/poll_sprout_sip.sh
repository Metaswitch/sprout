#!/bin/bash

# @file poll_sprout_sip.sh
#
# Copyright (C) Metaswitch Networks 2015
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

# This script uses a SIP message to poll a process and check whether it is
# healthy.

# Read the config, defaulting appropriately.
scscf=5054
icscf=0
bgcf=5053
. /etc/clearwater/config
[ -z $signaling_namespace ] || namespace_prefix="ip netns exec $signaling_namespace"

# If we have S-CSCF configured, check it.
rc=0
if [ "$scscf" != "0" ] ; then
  $namespace_prefix /usr/share/clearwater/bin/poll-sip $scscf
  rc=$?
fi

# If that succeeded and we have I-CSCF configured, check it.
if [ $rc = 0 ] && [ "$icscf" != "0" ] ; then
  $namespace_prefix /usr/share/clearwater/bin/poll-sip $icscf
  rc=$?
fi

# If that succeeded and we have BGCF configured, check it.
if [ $rc = 0 ] && [ "$bgcf" != "0" ]; then
  $namespace_prefix /usr/share/clearwater/bin/poll-sip $bgcf
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
