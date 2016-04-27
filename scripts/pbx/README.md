This folder contains a SIPp script for testing calls to and from an unregistered PBX.

To test a call from the PBX:

* create a subscriber to represent a PBX, and a subscriber to represent a callee
* edit input.csv to contain the PBX URI, the PBX's authentication credentails, and the callee's URI
* configure Bono to treat this box's IP address as an unregisterred PBX, and configure the PBX's service routes
* Run the following command:

    sipp -sf pbx-uac.xml [[pcscf]] -m 1 -t t1 -inf input.csv

To test a call to the PBX:

* create a subscriber to represent a PBX, and a subscriber to represent a caller
* configure your P-CSCF to allow it to route requests to the IP address of the box representing the PBX
* on the box you are using to represent the PBX, edit `pbx-uas.xml` to specify it's public IP address, then run:

    sipp -sf pbx-uas.xml [[pcscf]] -t t1

* make a call to the PBX. Hang up when you are done.
