#!/usr/bin/python

# @file as.py
#
# Project Clearwater - IMS in the Cloud
# Copyright (C) 2013  Metaswitch Networks Ltd
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

# Basic logging SIP AS, simply passing all messages on and always record-routing itself
#
# Note that this only supports UDP - not TCP
#
# Install:
#   apt-get install -y python-pip build-essential python-dev
#   pip install --upgrade pip
#   pip install twisted
#
# Run:
#   as.py <public IP/hostname>

import sys, random
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.protocols import sip
from twisted.python import log

class SIPProxy(sip.Proxy):
    def handle_request(self, req, addr):
        print "Received SIP request from %s:%d:" % addr
        print req.toString()
        # Add a via header for us
        via = self.getVia()
        if not via.branch:
            # Twisted SIP is still not compliant with RFC3261 s16.11.
            # Work around this, assuming our caller *is* compliant.
            topVia = sip.parseViaHeader(req.headers["via"][0])
            via.branch = topVia.branch + "-AS-059" # chosen by fair random.org. guaranteed to be random.
        req.headers["via"].insert(0, via.toString())
        # Determine the next hop - use the route headers if present, else the request URI
        uri = req.uri
        if "route" in req.headers:
            # If we're the first route header, strip it
            _, route, _ = sip.parseAddress(req.headers["route"][0])
            if route.host == self.host:
                req.headers["route"].pop(0)
            # Now find the next hop
            if len(req.headers["route"]) > 0:
                _, uri, _ = sip.parseAddress(req.headers["route"][0])
        # Insert a record-route header to keep us in the path
        req.headers.setdefault("record-route", []).insert(0, sip.URL(host = self.host, port = self.port, other = ["transport=UDP", "lr"]))
        # Assert that we're authorized. Workaround pending sto131 completion.
        if "authorization" not in req.headers:
            req.addHeader("authorization", 'Digest username="as@cw-ngv.com", realm="cw-ngv.com", nonce="0000000000000000", uri="sip:cw-ngv.com", response="00000000000000000000000000000000", algorithm=md5, opaque="0000000000000000",integrity-protected="yes"')
        print "Sending SIP request to %s:" % uri
        print req.toString()
        print "==============================================================================="
        # Send the message on
        self.sendMessage(uri, req)

    def handle_response(self, rsp, addr):
        print "Received SIP response from %s:%d:" % addr
        print rsp.toString()
        # Strip the top via
        rsp.headers["via"].pop(0)
        # Determine the next hop from the next via
        via = sip.parseViaHeader(rsp.headers["via"][0])
        # rport handling is a bit mysterious - rport should be filled
        # in by Twisted, but apparently it's not. This seems to work
        # for now, though, presumably by defaulting to port 5060.
        uri = sip.URL(host = via.received or via.host, port = via.rportValue if via.rportRequested else self.PORT)
        print "Sending SIP response to %s:" % uri
        print rsp.toString()
        print "==============================================================================="
        # Send the message on
        self.sendMessage(uri, rsp)

if len(sys.argv) != 2:
    sys.exit("Usage: as.py <host>")
# For debugging, uncomment this
# log.startLogging(sys.stdout)
reactor.listenUDP(5060, SIPProxy(sys.argv[1]))
reactor.run()
