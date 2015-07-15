This folder contains a SIPp script for testing calls to and from an unregistered PBX.

To test with this script:

* create a subscriber to represent a PBX, and a subscriber to represent a callee
* edit input.csv to contain the PBX URI, the PBX's authentication credentails, and the callee's URI
* from an IP address that the P-CSCF will allow to make unregistered PBX calls, run:

    sipp -sf pbx.xml [[pcscf]] -m 1 -t t1 -inf input.csv

