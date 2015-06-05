# @file sprout_chronos_plugin.py
#
# Project Clearwater - IMS in the Cloud
# Copyright (C) 2015  Metaswitch Networks Ltd
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

from metaswitch.clearwater.cluster_manager.plugin_base import \
    SynchroniserPluginBase
from metaswitch.clearwater.cluster_manager.plugin_utils import \
    write_chronos_cluster_settings, run_command
from metaswitch.clearwater.cluster_manager.alarms import issue_alarm
from metaswitch.clearwater.cluster_manager import pdlogs
from metaswitch.clearwater.cluster_manager import constants
import subprocess
import logging

_log = logging.getLogger("sprout_chronos_plugin")


class SproutChronosPlugin(SynchroniserPluginBase):
    def __init__(self, params):
        self.local_server = params.ip
        self._key = "/clearwater/{}/sprout/clustering/chronos".format(params.local_site)
        _log.debug("Raising not-clustered alarm")
        issue_alarm(constants.RAISE_CHRONOS_NOT_YET_CLUSTERED)
        pdlogs.NOT_YET_CLUSTERED_ALARM.log(cluster_desc=self.cluster_description())

    def key(self):
        return self._key

    def files(self):
        return ["/etc/chronos/chronos_cluster.conf"]

    def cluster_description(self):
        return "local chronos cluster"

    def on_cluster_changing(self, cluster_view):
        _log.debug("Sprout's Chronos cluster is changing")
        write_chronos_cluster_settings("/etc/chronos/chronos_cluster.conf",
                               cluster_view,
                               self.local_server)
        run_command("service chronos reload")

    def on_joining_cluster(self, cluster_view):
        _log.debug("This Sprout's Chronos is joining a Chronos cluster")
        self.on_cluster_changing(cluster_view)

    def on_new_cluster_config_ready(self, cluster_view):
        _log.debug("Started running Chronos resynchronization")
        run_command("service chronos resync")
        run_command("service chronos wait-sync")
        _log.debug("Finished running Chronos resynchronization")

    def on_stable_cluster(self, cluster_view):
        self.on_cluster_changing(cluster_view)
        issue_alarm(constants.CLEAR_CHRONOS_NOT_YET_CLUSTERED)
        _log.debug("Sprout Chronos cluster is stable again")

    def on_leaving_cluster(self, cluster_view):
        pass


def load_as_plugin(params):
    is_icscf_only = (subprocess.check_output('. /etc/clearwater/config && echo -n $scscf',
                                             shell=True,
                                             stderr=subprocess.STDOUT) == "0")
    if not is_icscf_only:
        _log.info("Loading the Sprout Chronos plugin")
        return SproutChronosPlugin(params)
