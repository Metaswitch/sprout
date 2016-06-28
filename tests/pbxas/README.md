This directory contains a plugin that acts like a TAS for a non-registering PBX. When it is invoked it:

* Rewrites the request URI to be the contact URI of the PBX.
* Adds route headers specifying the path to the PBX (e.g. through a P-CSCF).

To use the plugin:

* Edit the TARGET and PATH variables to be the values you need.
* Run `make`
* Copy the resulting `pbxas-plugin.so` to `/usr/share/clearwater/sprout/plugins/` on your sprout node, and restart sprout.
* Configure the iFCs for the PBX to invoke `pbxas.<sprout-cluster-name>` for terminating requests.
