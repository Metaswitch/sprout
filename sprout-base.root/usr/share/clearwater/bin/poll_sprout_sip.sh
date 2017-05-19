#!/bin/bash

# @file poll_sprout.sh
#
# Copyright (C) Metaswitch Networks
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

exit $rc
