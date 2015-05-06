
from metaswitch.clearwater.cluster_manager.plugin_base import \
    SynchroniserPluginBase
from metaswitch.clearwater.cluster_manager.plugin_utils import \
    run_command, write_cluster_settings
from metaswitch.clearwater.cluster_manager.alarms import issue_alarm
from metaswitch.clearwater.cluster_manager import constants
import logging
import os

_log = logging.getLogger("memcached_plugin")


class SproutMemcachedPlugin(SynchroniserPluginBase):
    def __init__(self, _ip):
        issue_alarm(constants.RAISE_MEMCACHED_NOT_YET_CLUSTERED)

    def key(self):
        return "/sprout/clustering/memcached"

    def on_cluster_changing(self, cluster_view):
        write_cluster_settings("/etc/clearwater/cluster_settings",
                               cluster_view)
        run_command("service sprout reload")

    def on_joining_cluster(self, cluster_view):
        self.on_cluster_changing(cluster_view)

    def on_new_cluster_config_ready(self, cluster_view):
        run_command("service astaire reload")
        run_command("service astaire wait-sync")

    def on_stable_cluster(self, cluster_view):
        self.on_cluster_changing(cluster_view)
        issue_alarm(constants.CLEAR_MEMCACHED_NOT_YET_CLUSTERED)

    def on_leaving_cluster(self, cluster_view):
        pass


def load_as_plugin():
    return SproutMemcachedPlugin()
