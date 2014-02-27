/**
 * @file rftsx_test.cpp UT for RfTsx class.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

extern "C" {
#include <pjlib-util.h>
}

#include <string>
#include <sstream>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "fakelogger.hpp"
#include "siptest.hpp"
#include "utils.h"
#include "pjutils.h"
#include "stack.h"
#include "rftsx.h"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

/// Fixture for RfTsxTest.
class RfTsxTest : public SipTest
{
public:
  FakeLogger _log;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  RfTsxTest() : SipTest(NULL)
  {
  }

  ~RfTsxTest()
  {
  }

protected:

  pjsip_msg* parse_msg(const std::string& msg)
  {
    pjsip_rx_data* rdata = build_rxdata(msg);
    RfTsxTest::parse_rxdata(rdata);
    return rdata->msg_info.msg;
  }
};

class SIPRequest
{
public:
  string _method;
  string _requri;
  string _from;
  string _to;
  string _call_id;
  string _routes;
  string _extra_hdrs;
  string _body;

  SIPRequest(std::string method) :
    _method(method),
    _requri("sip:6505550001@homedomain"),
    _from("\"6505550000\" <sip:6505550000@homedomain>;tag=12345678"),
    _to("\"6505550001\" <sip:6505550001@homedomain>;tag=87654321"),
    _call_id("0123456789abcdef-10.83.18.38"),
    _routes(),
    _extra_hdrs(),
    _body()
  {
  }

  string get()
  {
    char buf[16384];

    int n = snprintf(buf, sizeof(buf),
                     "%1$s %2$s SIP/2.0\r\n"
                     "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                     "%6$s"
                     "Max-Forwards: 68\r\n"
                     "Supported: outbound, path\r\n"
                     "To: %3$s\r\n"
                     "From: %4$s\r\n"
                     "Call-ID: %5$s\r\n"
                     "CSeq: 1 %1$s\r\n"
                     "%7$s"
                     "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
                     "User-Agent: Cleaarwater UT\r\n"
                     "Content-Length: %8$d\r\n"
                     "\r\n"
                     "%9$s",
                     _method.c_str(),    // $1
                     _requri.c_str(),    // $2
                     _to.c_str(),        // $3
                     _from.c_str(),      // $4
                     _call_id.c_str(),   // $5
                     _routes.c_str(),    // $6
                     _extra_hdrs.c_str(),// $7
                     (int)_body.length(),// $8
                     _body.c_str()       // $9
      );

    printf("%s\n", buf);

    EXPECT_LT(n, (int)sizeof(buf));

    return string(buf, n);
  }

};


class SIPResponse
{
public:
  int _status_code;
  string _method;
  string _from;
  string _to;
  string _call_id;
  string _routes;
  string _extra_hdrs;
  string _body;

  SIPResponse(int status_code, std::string method) :
    _status_code(status_code),
    _method(method),
    _from("\"6505550001\" <sip:6505550001@homedomain>;tag=12345678"),
    _to("\"6505550000\" <sip:6505550000@homedomain>;tag=87654321"),
    _call_id("0123456789abcdef-10.83.18.38"),
    _extra_hdrs(),
    _body()
  {
  }

  string get()
  {
    char buf[16384];

    string reason = PJUtils::pj_str_to_string(pjsip_get_status_text(_status_code));

    int n = snprintf(buf, sizeof(buf),
                     "SIP/2.0 %2$d %3$s\r\n"
                     "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                     "Max-Forwards: 68\r\n"
                     "Supported: outbound, path\r\n"
                     "To: %4$s\r\n"
                     "From: %5$s\r\n"
                     "Call-ID: %6$s\r\n"
                     "CSeq: 1 %1$s\r\n"
                     "%7$s"
                     "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
                     "User-Agent: Cleaarwater UT\r\n"
                     "Content-Length: %8$d\r\n"
                     "\r\n"
                     "%9$s",
                     _method.c_str(),    // $1
                     _status_code,       // $2
                     reason.c_str(),     // $3
                     _to.c_str(),        // $4
                     _from.c_str(),      // $5
                     _call_id.c_str(),   // $6
                     _extra_hdrs.c_str(),// $7
                     (int)_body.length(),// $8
                     _body.c_str()       // $9

      );

    printf("%s\n", buf);

    EXPECT_LT(n, (int)sizeof(buf));

    return string(buf, n);
  }

};



TEST_F(RfTsxTest, SCSCF_Successful_Call)
{
  // Tests mainline Rf message generation for a successful call through
  // a S-CSCF.
  pj_time_val ts;

  // Create an RfTsx instance for the test.
  RfTsx rf(NULL, 0, "sprout.homedomain", SCSCF, CALLING_PARTY);

  // Build the original INVITE request.
  SIPRequest invite("INVITE");
  invite._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;lr>\r\n";
  invite._to = "\"6505550001\" <sip:6505550001@homedomain>";   // Strip tag.
  invite._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\">\r\n";
  invite._extra_hdrs += "P-Asserted-Identity: \"6505550000\" <sip:6505550000@homedomain>\r\n";
  invite._extra_hdrs += "P-Asserted-Identity: <tel:6505550000>\r\n";
  invite._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain\r\n";
  invite._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";
  invite._extra_hdrs += "Content-Type: application/sdp\r\n";
  invite._body =
"v=0\r\n"
"o=- 2728502836004741600 2 IN IP4 127.0.0.1\r\n"
"s=Doubango Telecom - chrome\r\n"
"t=0 0\r\n"
"a=group:BUNDLE audio video\r\n"
"a=msid-semantic: WMS kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai\r\n"
"m=audio 1988 RTP/SAVPF 111 103 104 0 8 106 105 13 126\r\n"
"c=IN IP4 10.83.18.38\r\n"
"a=rtcp:1988 IN IP4 10.83.18.38\r\n"
"a=candidate:2337948804 1 udp 2113937151 10.233.25.133 63500 typ host generation 0\r\n"
"a=candidate:2337948804 2 udp 2113937151 10.233.25.133 63500 typ host generation 0\r\n"
"a=candidate:168968752 1 udp 1845501695 149.7.216.41 1988 typ srflx raddr 10.233.25.133 rport 63500 generation 0\r\n"
"a=candidate:168968752 2 udp 1845501695 149.7.216.41 1988 typ srflx raddr 10.233.25.133 rport 63500 generation 0\r\n"
"a=candidate:3319380084 1 tcp 1509957375 10.233.25.133 0 typ host generation 0\r\n"
"a=candidate:3319380084 2 tcp 1509957375 10.233.25.133 0 typ host generation 0\r\n"
"a=ice-ufrag:AsOMyGJXMiYLcrKq\r\n"
"a=ice-pwd:oFkGAy/EaNu8bzpx/XaeLhoi\r\n"
"a=ice-options:google-ice\r\n"
"a=fingerprint:sha-256 B6:06:E1:15:DC:E5:FB:A4:5E:B8:33:71:86:14:FA:ED:E2:18:5C:F7:CA:70:F7:6B:43:C1:A3:F1:DF:C9:C5:68\r\n"
"a=setup:actpass\r\n"
"a=mid:audio\r\n"
"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
"a=sendrecv\r\n"
"a=rtcp-mux\r\n"
"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Ad5YtxY2RkmCgcLea2k4eRDNE6Wfou0LYG34J4bi\r\n"
"a=rtpmap:111 opus/48000/2\r\n"
"a=fmtp:111 minptime=10\r\n"
"a=rtpmap:103 ISAC/16000\r\n"
"a=rtpmap:104 ISAC/32000\r\n"
"a=rtpmap:0 PCMU/8000\r\n"
"a=rtpmap:8 PCMA/8000\r\n"
"a=rtpmap:106 CN/32000\r\n"
"a=rtpmap:105 CN/16000\r\n"
"a=rtpmap:13 CN/8000\r\n"
"a=rtpmap:126 telephone-event/8000\r\n"
"a=maxptime:60\r\n"
"a=ssrc:56565031 cname:GNCJjRNeQjxcopHb\r\n"
"a=ssrc:56565031 msid:kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai de817a30-abe7-4174-89be-7cc261e67be3\r\n"
"a=ssrc:56565031 mslabel:kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai\r\n"
"a=ssrc:56565031 label:de817a30-abe7-4174-89be-7cc261e67be3\r\n"
"m=video 1988 RTP/SAVPF 100 116 117\r\n"
"c=IN IP4 10.83.18.38\r\n"
"a=rtcp:1988 IN IP4 10.83.18.38\r\n"
"a=candidate:2337948804 1 udp 2113937151 10.233.25.133 63500 typ host generation 0\r\n"
"a=candidate:2337948804 2 udp 2113937151 10.233.25.133 63500 typ host generation 0\r\n"
"a=candidate:168968752 1 udp 1845501695 149.7.216.41 1988 typ srflx raddr 10.233.25.133 rport 63500 generation 0\r\n"
"a=candidate:168968752 2 udp 1845501695 149.7.216.41 1988 typ srflx raddr 10.233.25.133 rport 63500 generation 0\r\n"
"a=candidate:3319380084 1 tcp 1509957375 10.233.25.133 0 typ host generation 0\r\n"
"a=candidate:3319380084 2 tcp 1509957375 10.233.25.133 0 typ host generation 0\r\n"
"a=ice-ufrag:AsOMyGJXMiYLcrKq\r\n"
"a=ice-pwd:oFkGAy/EaNu8bzpx/XaeLhoi\r\n"
"a=ice-options:google-ice\r\n"
"a=fingerprint:sha-256 B6:06:E1:15:DC:E5:FB:A4:5E:B8:33:71:86:14:FA:ED:E2:18:5C:F7:CA:70:F7:6B:43:C1:A3:F1:DF:C9:C5:68\r\n"
"a=setup:actpass\r\n"
"a=mid:video\r\n"
"a=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\n"
"a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
"a=sendrecv\r\n"
"a=rtcp-mux\r\n"
"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Ad5YtxY2RkmCgcLea2k4eRDNE6Wfou0LYG34J4bi\r\n"
"a=rtpmap:100 VP8/90000\r\n"
"a=rtcp-fb:100 ccm fir\r\n"
"a=rtcp-fb:100 nack\r\n"
"a=rtcp-fb:100 goog-remb\r\n"
"a=rtpmap:116 red/90000\r\n"
"a=rtpmap:117 ulpfec/90000\r\n"
"a=ssrc:117659952 cname:GNCJjRNeQjxcopHb\r\n"
"a=ssrc:117659952 msid:kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai e767ec36-3ed6-474b-9b6d-632eb1cb37c8\r\n"
"a=ssrc:117659952 mslabel:kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai\r\n"
"a=ssrc:117659952 label:e767ec36-3ed6-474b-9b6d-632eb1cb37c8\r\n";

  // Convert the message to a pjsip_rx_data and parse it.

  // Pass the request to the RfTsx as a received request.
  ts.sec = 1;
  ts.msec = 0;
  rf.rx_request(parse_msg(invite.get()), ts);

  // Build a 100 Trying response and pass it to the RfTsx as a transmitted
  // response.
  SIPResponse r100trying(100, "INVITE");
  ts.msec = 5;
  rf.tx_response(parse_msg(r100trying.get()), ts);

  // Update the message as if we're transmitting it to an AS, by replacing
  // the existing Route header with the usual two Route headers.
  invite._routes = "Route: <sip:as1.homedomain:5060;transport=TCP;lr>\r\nRoute: <sip:odi_12345678@sprout.homedomain:5054;transport=TCP;lr>\r\n";

  // Pass the request to the RfTsx as a transmitted request.
  ts.msec = 10;
  rf.tx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the RfTsx as a received response (from the AS).
  ts.msec = 15;
  rf.rx_response(parse_msg(r100trying.get()), ts);

  // Update the INVITE request as it comes back from the AS - remove the first
  // Route header and change the RequestURI to do a redirect.
  invite._routes = "Route: <sip:odi_12345678@sprout.homedomain:5054;transport=TCP;lr>\r\n";
  invite._requri = "sip:6505559999@homedomain";

  // Pass the request to the RfTsx as a received request.
  ts.msec = 20;
  rf.rx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the RfTsx again as a transmitted response,
  // this time to the target endpoint.
  ts.msec = 25;
  rf.tx_response(parse_msg(r100trying.get()), ts);

  // Update the request as it is finally forwarded by the S-CSCF by replacing
  // the RequestURI with a contact URI and adding a Path header to route the
  // request to the appropriate P-CSCF.
  invite._requri = "sip:6505559999@10.20.30.40:12345;transport=TCP";
  invite._routes = "Route: <sip:xf2367gh@pcscf-1.homedomain:5052;transport=TCP;lr>\r\n";

  // Pass the request to the RfTsx as a finally transmitted request.
  ts.msec = 30;
  rf.tx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the RfTsx again as a received response,
  // this time from the target endpoint.
  ts.msec = 35;
  rf.rx_response(parse_msg(r100trying.get()), ts);

  // Now build a 200 OK response.
  SIPResponse r200ok(200, "INVITE");
  r200ok._extra_hdrs = "Contact: <sip:6505550001@10.83.18.50:12345;transport=TCP;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-cdef12345678>\">\r\n";
  r200ok._extra_hdrs += "P-Asserted-Identity: \"6505550001\" <sip:6505550001@homedomain>\r\n";
  r200ok._extra_hdrs += "P-Asserted-Identity: <tel:6505550001>\r\n";
  r200ok._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain;term-ioi=homedomain\r\n";
  r200ok._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";
  r200ok._extra_hdrs += "Content-Type: application/sdp\r\n";
  r200ok._body =
"v=0\r\n"
"o=- 2728502836004741600 2 IN IP4 127.0.0.1\r\n"
"s=Doubango Telecom - chrome\r\n"
"t=0 0\r\n"
"a=group:BUNDLE audio video\r\n"
"a=msid-semantic: WMS kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai\r\n"
"m=audio 1988 RTP/SAVPF 111 103 104 0 8 106 105 13 126\r\n"
"c=IN IP4 10.83.18.50\r\n"
"a=rtcp:1988 IN IP4 10.83.18.50\r\n"
"a=candidate:2337948804 1 udp 2113937151 10.233.25.133 63500 typ host generation 0\r\n"
"a=candidate:2337948804 2 udp 2113937151 10.233.25.133 63500 typ host generation 0\r\n"
"a=candidate:168968752 1 udp 1845501695 149.7.216.41 1988 typ srflx raddr 10.233.25.133 rport 63500 generation 0\r\n"
"a=candidate:168968752 2 udp 1845501695 149.7.216.41 1988 typ srflx raddr 10.233.25.133 rport 63500 generation 0\r\n"
"a=candidate:3319380084 1 tcp 1509957375 10.233.25.133 0 typ host generation 0\r\n"
"a=candidate:3319380084 2 tcp 1509957375 10.233.25.133 0 typ host generation 0\r\n"
"a=ice-ufrag:AsOMyGJXMiYLcrKq\r\n"
"a=ice-pwd:oFkGAy/EaNu8bzpx/XaeLhoi\r\n"
"a=ice-options:google-ice\r\n"
"a=fingerprint:sha-256 B6:06:E1:15:DC:E5:FB:A4:5E:B8:33:71:86:14:FA:ED:E2:18:5C:F7:CA:70:F7:6B:43:C1:A3:F1:DF:C9:C5:68\r\n"
"a=setup:actpass\r\n"
"a=mid:audio\r\n"
"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
"a=sendrecv\r\n"
"a=rtcp-mux\r\n"
"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Ad5YtxY2RkmCgcLea2k4eRDNE6Wfou0LYG34J4bi\r\n"
"a=rtpmap:111 opus/48000/2\r\n"
"a=fmtp:111 minptime=10\r\n"
"a=rtpmap:103 ISAC/16000\r\n"
"a=rtpmap:104 ISAC/32000\r\n"
"a=rtpmap:0 PCMU/8000\r\n"
"a=rtpmap:8 PCMA/8000\r\n"
"a=rtpmap:106 CN/32000\r\n"
"a=rtpmap:105 CN/16000\r\n"
"a=rtpmap:13 CN/8000\r\n"
"a=rtpmap:126 telephone-event/8000\r\n"
"a=maxptime:60\r\n"
"a=ssrc:56565031 cname:GNCJjRNeQjxcopHb\r\n"
"a=ssrc:56565031 msid:kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai de817a30-abe7-4174-89be-7cc261e67be3\r\n"
"a=ssrc:56565031 mslabel:kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai\r\n"
"a=ssrc:56565031 label:de817a30-abe7-4174-89be-7cc261e67be3\r\n"
"m=video 1988 RTP/SAVPF 100 116 117\r\n"
"c=IN IP4 10.83.18.50\r\n"
"a=rtcp:1988 IN IP4 10.83.18.50\r\n"
"a=candidate:2337948804 1 udp 2113937151 10.233.25.133 63500 typ host generation 0\r\n"
"a=candidate:2337948804 2 udp 2113937151 10.233.25.133 63500 typ host generation 0\r\n"
"a=candidate:168968752 1 udp 1845501695 149.7.216.41 1988 typ srflx raddr 10.233.25.133 rport 63500 generation 0\r\n"
"a=candidate:168968752 2 udp 1845501695 149.7.216.41 1988 typ srflx raddr 10.233.25.133 rport 63500 generation 0\r\n"
"a=candidate:3319380084 1 tcp 1509957375 10.233.25.133 0 typ host generation 0\r\n"
"a=candidate:3319380084 2 tcp 1509957375 10.233.25.133 0 typ host generation 0\r\n"
"a=ice-ufrag:AsOMyGJXMiYLcrKq\r\n"
"a=ice-pwd:oFkGAy/EaNu8bzpx/XaeLhoi\r\n"
"a=ice-options:google-ice\r\n"
"a=fingerprint:sha-256 B6:06:E1:15:DC:E5:FB:A4:5E:B8:33:71:86:14:FA:ED:E2:18:5C:F7:CA:70:F7:6B:43:C1:A3:F1:DF:C9:C5:68\r\n"
"a=setup:actpass\r\n"
"a=mid:video\r\n"
"a=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\n"
"a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
"a=sendrecv\r\n"
"a=rtcp-mux\r\n"
"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Ad5YtxY2RkmCgcLea2k4eRDNE6Wfou0LYG34J4bi\r\n"
"a=rtpmap:100 VP8/90000\r\n"
"a=rtcp-fb:100 ccm fir\r\n"
"a=rtcp-fb:100 nack\r\n"
"a=rtcp-fb:100 goog-remb\r\n"
"a=rtpmap:116 red/90000\r\n"
"a=rtpmap:117 ulpfec/90000\r\n"
"a=ssrc:117659952 cname:GNCJjRNeQjxcopHb\r\n"
"a=ssrc:117659952 msid:kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai e767ec36-3ed6-474b-9b6d-632eb1cb37c8\r\n"
"a=ssrc:117659952 mslabel:kggfXRSBx2oJdICzWljVBW1yFkgxxI0apXai\r\n"
"a=ssrc:117659952 label:e767ec36-3ed6-474b-9b6d-632eb1cb37c8\r\n";

  // Pass the response to RfTsx as if it was making its way back through the
  // AS chain.
  ts.msec = 40;
  rf.rx_response(parse_msg(r200ok.get()), ts);
  ts.msec = 50;
  rf.tx_response(parse_msg(r200ok.get()), ts);
  ts.msec = 60;
  rf.rx_response(parse_msg(r200ok.get()), ts);
  ts.msec = 70;
  rf.tx_response(parse_msg(r200ok.get()), ts);

  // Get and print the Rf message.
  string rf_msg = rf.get_message();
  printf("%s\n", rf_msg.c_str());
}


