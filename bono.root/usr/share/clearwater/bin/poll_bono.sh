#!/bin/bash

# @file poll_bono.sh
#
# Copyright (C) Metaswitch Networks 2017
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

# This script uses a SIP message to poll a process and check whether it is
# healthy.

. /etc/clearwater/config
[ -z $signaling_namespace ] || namespace_prefix="ip netns exec $signaling_namespace"

# Just call into the poll-sip script, specifying our port.
$namespace_prefix /usr/share/clearwater/bin/poll-sip 5058
exit $?
