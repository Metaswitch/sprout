/**
 * @file acr_test.cpp UT for ACR class.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

extern "C" {
#include <pjlib-util.h>
}

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "test_utils.hpp"
#include "siptest.hpp"
#include "utils.h"
#include "pjutils.h"
#include "stack.h"
#include "acr.h"

#include "rapidjson/error/en.h"

using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

/// Fixture for ACRTest.
class ACRTest : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  ACRTest() : SipTest(NULL)
  {
  }

  ~ACRTest()
  {
  }

protected:

  // Compares output ACR against expected ACR from file.
  bool compare_acr(const std::string& output,
                   const std::string& expected_file)
  {
    // Parse the output ACR.
    rapidjson::Document json_output;
    json_output.Parse<0>(output.c_str());

    if (json_output.HasParseError())
    {
      printf("Failed to parse output ACR: %s at %ld\n%s\n",
             rapidjson::GetParseError_En(json_output.GetParseError()),
             json_output.GetErrorOffset(),
             output.c_str());
    }

    // Read and parse the expected ACR.
    std::string expected_pathname = UT_DIR + "/" + expected_file;
    std::ifstream fs(expected_pathname.c_str());
    std::string exp_str((std::istreambuf_iterator<char>(fs)),
                         std::istreambuf_iterator<char>());
    rapidjson::Document json_expected;
    json_expected.Parse<0>(exp_str.c_str());

    if (json_expected.HasParseError())
    {
      printf("Failed to parse expected ACR from file %s: %s at %ld\n%s\n",
             expected_file.c_str(),
             rapidjson::GetParseError_En(json_expected.GetParseError()),
             json_expected.GetErrorOffset(),
             exp_str.c_str());
    }

    bool rc = (json_output == json_expected);

    if (!rc)
    {
      printf("JSON comparison failed\nReceived\n%s\nExpected\n%s\n",
             output.c_str(),
             exp_str.c_str());
    }

    return rc;
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

    EXPECT_LT(n, (int)sizeof(buf));

    TRC_DEBUG("Request\n%s", buf);

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

    EXPECT_LT(n, (int)sizeof(buf));

    TRC_DEBUG("Response\n%s", buf);

    return string(buf, n);
  }

};


TEST_F(ACRTest, SCSCFRegister)
{
  // Tests mainline Rf message generation for a successful registration transaction
  // at the S-CSCF.
  pj_time_val ts;
  ACR* acr;
  std::string acr_message;

  // Create a Ralf ACR factory for S-CSCF ACRs.
  RalfACRFactory f(NULL, ACR::SCSCF);

  // Create an ACR instance for the ACR[EVENT] triggered by the REGISTER.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_ORIGINATING);

  // Build the original REGISTER request.
  SIPRequest reg("REGISTER");
  reg._requri = "sip:homedomain";
  reg._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;orig;lr>\r\n";
  reg._from = "\"6505550000\" <sip:6505550000@homedomain>";   // Strip tag.
  reg._to = "\"6505550000\" <sip:6505550000@homedomain>";   // Strip tag.
  reg._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  reg._extra_hdrs += "Expires: 300\r\n";
  reg._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain\r\n";
  reg._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";

  // Pass the request to the ACR as a received request.
  ts.sec = 1;
  ts.msec = 0;
  acr->rx_request(parse_msg(reg.get()), ts);

  // Now build a 200 OK response.
  SIPResponse reg200ok(200, "REGISTER");
  reg200ok._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;expires=300;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  reg200ok._extra_hdrs = "P-Associated-URI: <sip:6505550000@homedomain>, <tel:6505550000>\r\n";

  // Pass the response to ACR as a transmitted response.
  ts.msec = 25;
  acr->tx_response(parse_msg(reg200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_scscfregister.json"));
  delete acr;
}

TEST_F(ACRTest, CancelledACR)
{
  // Tests mainline Rf message generation for a successful registration transaction
  // at the S-CSCF.
  pj_time_val ts;
  ACR* acr;
  std::string acr_message;

  // Create a Ralf ACR factory for S-CSCF ACRs.
  RalfACRFactory f(NULL, ACR::SCSCF);

  // Create an ACR instance for the ACR[EVENT] triggered by the REGISTER.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_ORIGINATING);

  // Build the original REGISTER request.
  SIPRequest reg("REGISTER");
  reg._requri = "sip:homedomain";
  reg._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;orig;lr>\r\n";
  reg._from = "\"6505550000\" <sip:6505550000@homedomain>";   // Strip tag.
  reg._to = "\"6505550000\" <sip:6505550000@homedomain>";   // Strip tag.
  reg._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";

  // Pass the request to the ACR as a received request.
  ts.sec = 1;
  ts.msec = 0;
  acr->rx_request(parse_msg(reg.get()), ts);

  // Cancel the ACR.
  acr->cancel();

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_EQ(acr_message, "Cancelled ACR");
  delete acr;
}

TEST_F(ACRTest, SCSCFOrigCall)
{
  // Tests mainline Rf message generation for a successful originating call
  // through a S-CSCF.
  pj_time_val ts;
  ACR* acr;
  std::string acr_message;

  // Create a Ralf ACR factory for S-CSCF ACRs.
  RalfACRFactory f(NULL, ACR::SCSCF);

  // Create an ACR instance for the ACR[START] triggered by the INVITE.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_ORIGINATING);

  // Build the original INVITE request.
  SIPRequest invite("INVITE");
  invite._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;orig;lr>\r\n";
  invite._to = "\"6505550001\" <sip:6505550001@homedomain>";   // Strip tag.
  invite._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  invite._extra_hdrs += "Session-Expires: 600\r\n";
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

  // Pass the request to the ACR as a received request.
  ts.sec = 1;
  ts.msec = 0;
  acr->rx_request(parse_msg(invite.get()), ts);

  // Build a 100 Trying response and pass it to the ACR as a transmitted
  // response.
  SIPResponse r100trying(100, "INVITE");
  ts.msec = 5;
  acr->tx_response(parse_msg(r100trying.get()), ts);

  // Update the message as if we're transmitting it to an AS, by replacing
  // the existing Route header with the usual two Route headers.
  invite._routes = "Route: <sip:as1.homedomain:5060;transport=TCP;lr>\r\nRoute: <sip:odi_12345678@sprout.homedomain:5054;transport=TCP;lr>\r\n";

  // The S-CSCF decides to perform session based billing on this hop, so sets
  // the session ID explicitly.
  acr->override_session_id(invite._call_id);

  // Pass the request to the ACR as a transmitted request.
  ts.msec = 10;
  acr->tx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR as a received response (from the AS).
  ts.msec = 15;
  acr->rx_response(parse_msg(r100trying.get()), ts);

  // Update the INVITE request as it comes back from the AS - remove the first
  // Route header and change the RequestURI to do a redirect.
  invite._routes = "Route: <sip:odi_12345678@sprout.homedomain:5054;transport=TCP;lr>\r\n";
  invite._requri = "sip:6505559999@homedomain";

  // Pass the request to the ACR as a received request.
  ts.msec = 20;
  acr->rx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR again as a transmitted response,
  // this time to the target endpoint.
  ts.msec = 25;
  acr->tx_response(parse_msg(r100trying.get()), ts);

  // Update the request as it is finally forwarded by the S-CSCF by adding
  // a Route header routing the request to the I-CSCF.
  invite._routes = "Route: <sip:sprout.homedomain:5052;transport=TCP;lr>\r\n";

  // Pass the request to the ACR as a finally transmitted request.
  ts.msec = 30;
  acr->tx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR again as a received response,
  // this time from the target endpoint.
  ts.msec = 35;
  acr->rx_response(parse_msg(r100trying.get()), ts);

  // Now build a 200 OK response.
  SIPResponse invite200ok(200, "INVITE");
  invite200ok._extra_hdrs = "Contact: <sip:6505559999@10.83.18.50:12345;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-cdef12345678>\"\r\n";
  invite200ok._extra_hdrs += "P-Asserted-Identity: \"6505550001\" <sip:6505550001@homedomain>\r\n";
  invite200ok._extra_hdrs += "P-Asserted-Identity: <tel:6505550001>\r\n";
  invite200ok._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain;term-ioi=homedomain\r\n";
  invite200ok._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";
  invite200ok._extra_hdrs += "Content-Type: application/sdp\r\n";
  invite200ok._body =
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

  // Pass the response to ACR as if it was making its way back through the
  // AS chain.
  ts.msec = 40;
  acr->rx_response(parse_msg(invite200ok.get()), ts);
  ts.msec = 50;
  acr->tx_response(parse_msg(invite200ok.get()), ts);
  ts.msec = 60;
  acr->rx_response(parse_msg(invite200ok.get()), ts);
  acr->as_info("sip:as1.homedomain:5060;transport=TCP",
               "sip:6505559999@homedomain",
               200,
               false);
  ts.msec = 70;
  acr->tx_response(parse_msg(invite200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_scscforigcall_start.json"));
  delete acr;

  // Create an ACR instance for the ACR[INTERIM] triggered by a reINVITE.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_ORIGINATING);

  // Build the reINVITE request.
  SIPRequest reinvite("INVITE");
  reinvite._requri = "sip:6505559999@10.83.18.50:12345;transport=TCP";
  reinvite._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;orig;lr>\r\n";
  reinvite._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  reinvite._extra_hdrs += "P-Asserted-Identity: \"6505550000\" <sip:6505550000@homedomain>\r\n";
  reinvite._extra_hdrs += "P-Asserted-Identity: <tel:6505550000>\r\n";
  reinvite._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain\r\n";
  reinvite._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";

  // Pass the reINVITE request to the ACR on its way through the S-CSCF.  We're
  // assuming the AS didn't Record-Route itself.
  ts.sec = 60;
  ts.msec = 0;
  acr->rx_request(parse_msg(reinvite.get()), ts);
  ts.msec = 5;
  acr->tx_request(parse_msg(reinvite.get()), ts);

  // Build a 200 OK response, and pass it to the ACR on the way through the S-CSCF.
  // Now build a 200 OK response.
  SIPResponse reinvite200ok(200, "INVITE");
  reinvite200ok._extra_hdrs = "Contact: <sip:6505559999@10.83.18.50:12345;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-cdef12345678>\"\r\n";
  reinvite200ok._extra_hdrs += "P-Asserted-Identity: \"6505550001\" <sip:6505550001@homedomain>\r\n";
  reinvite200ok._extra_hdrs += "P-Asserted-Identity: <tel:6505550001>\r\n";
  reinvite200ok._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain;term-ioi=homedomain\r\n";
  reinvite200ok._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";
  ts.msec = 10;
  acr->rx_response(parse_msg(reinvite200ok.get()), ts);
  ts.msec = 15;
  acr->tx_response(parse_msg(reinvite200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_scscforigcall_interim.json"));
  delete acr;

  // Create an ACR instance for the ACR[STOP] triggered by a BYE.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_ORIGINATING);

  // Build the BYE request.
  SIPRequest bye("BYE");
  bye._requri = "sip:6505559999@10.83.18.50:12345;transport=TCP";
  bye._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;orig;lr>\r\n";
  bye._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  bye._extra_hdrs += "P-Asserted-Identity: \"6505550000\" <sip:6505550000@homedomain>\r\n";
  bye._extra_hdrs += "P-Asserted-Identity: <tel:6505550000>\r\n";
  bye._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain\r\n";
  bye._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";

  // Pass the BYE request to the ACR on its way through the S-CSCF.  We're
  // assuming the AS didn't Record-Route itself.
  ts.sec = 120;
  ts.msec = 0;
  acr->rx_request(parse_msg(bye.get()), ts);
  ts.msec = 5;
  acr->tx_request(parse_msg(bye.get()), ts);

  // Build a 200 OK response, and pass it to the ACR on the way through the S-CSCF.
  // Now build a 200 OK response.
  SIPResponse bye200ok(200, "BYE");
  bye200ok._extra_hdrs = "Contact: <sip:6505559999@10.83.18.50:12345;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-cdef12345678>\"\r\n";
  bye200ok._extra_hdrs += "P-Asserted-Identity: \"6505550001\" <sip:6505550001@homedomain>\r\n";
  bye200ok._extra_hdrs += "P-Asserted-Identity: <tel:6505550001>\r\n";
  bye200ok._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain;term-ioi=homedomain\r\n";
  bye200ok._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";
  ts.msec = 15;
  acr->rx_response(parse_msg(bye200ok.get()), ts);
  ts.msec = 20;
  acr->tx_response(parse_msg(bye200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_scscforigcall_stop.json"));
  delete acr;
}

TEST_F(ACRTest, SCSCFTermCall)
{
  // Tests mainline Rf message generation for a successful terminating call
  // through a S-CSCF.
  pj_time_val ts;
  ACR* acr;
  std::string acr_message;

  // Create a Ralf ACR factory for S-CSCF ACRs.
  RalfACRFactory f(NULL, ACR::SCSCF);

  // Create an ACR instance for the test.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_TERMINATING);

  // Build the original INVITE request.
  SIPRequest invite("INVITE");
  invite._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;lr>\r\n";
  invite._to = "\"6505550001\" <sip:6505550001@homedomain>";   // Strip tag.
  invite._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  invite._extra_hdrs += "Session-Expires: 600\r\n";
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

  // Pass the request to the ACR as a received request.
  ts.sec = 1;
  ts.msec = 0;
  acr->rx_request(parse_msg(invite.get()), ts);

  // Build a 100 Trying response and pass it to the ACR as a transmitted
  // response.
  SIPResponse r100trying(100, "INVITE");
  ts.msec = 5;
  acr->tx_response(parse_msg(r100trying.get()), ts);

  // Update the message as if we're transmitting it to an AS, by replacing
  // the existing Route header with the usual two Route headers.
  invite._routes = "Route: <sip:as1.homedomain:5060;transport=TCP;lr>\r\nRoute: <sip:odi_12345678@sprout.homedomain:5054;transport=TCP;lr>\r\n";

  // Pass the request to the ACR as a transmitted request.
  ts.msec = 10;
  acr->tx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR as a received response (from the AS).
  ts.msec = 15;
  acr->rx_response(parse_msg(r100trying.get()), ts);

  // Update the INVITE request as it comes back from the AS - remove the first
  // Route header and change the RequestURI to do a redirect.
  invite._routes = "Route: <sip:odi_12345678@sprout.homedomain:5054;transport=TCP;lr>\r\n";
  invite._requri = "sip:6505559999@homedomain";

  // Pass the request to the ACR as a received request.
  ts.msec = 20;
  acr->rx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR again as a transmitted response,
  // this time to the target endpoint.
  ts.msec = 25;
  acr->tx_response(parse_msg(r100trying.get()), ts);

  // Update the request as it is finally forwarded by the S-CSCF by adding
  // a Route header routing the request to the appropriate flow on the
  // appropriate P-CSCF, and converting the RequestURI to a contact URI.
  invite._routes = "Route: <sip:abcdefgh@pcscf1.homedomain:5058;transport=TCP;lr>\r\n";
  invite._requri = "sip:6505559999@10.83.18.50:5060;transport=TCP";

  // The S-CSCF decides to perform session based billing on this hop, so sets
  // the session ID explicitly.
  acr->override_session_id(invite._call_id);

  // Pass the request to the ACR as a finally transmitted request.
  ts.msec = 30;
  acr->tx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR again as a received response,
  // this time from the target endpoint.
  ts.msec = 35;
  acr->rx_response(parse_msg(r100trying.get()), ts);

  // Now build a 200 OK response.
  SIPResponse r200ok(200, "INVITE");
  r200ok._extra_hdrs = "Contact: <sip:6505559999@10.83.18.50:12345;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-cdef12345678>\"\r\n";
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

  // Pass the response to ACR as if it was making its way back through the
  // AS chain.
  ts.msec = 40;
  acr->rx_response(parse_msg(r200ok.get()), ts);
  ts.msec = 50;
  acr->tx_response(parse_msg(r200ok.get()), ts);
  ts.msec = 60;
  acr->rx_response(parse_msg(r200ok.get()), ts);
  acr->as_info("sip:as1.homedomain:5060;transport=TCP",
               "sip:6505559999@homedomain",
               200,
               false);
  ts.msec = 70;
  acr->tx_response(parse_msg(r200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  string rf_acr = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(rf_acr, "acr_scscftermcall_start.json"));

  delete acr;

  // Create an ACR instance for the ACR[INTERIM] triggered by a reINVITE.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_TERMINATING);

  // Build the reINVITE request.
  SIPRequest reinvite("INVITE");
  reinvite._requri = "sip:6505559999@10.83.18.50:12345;transport=TCP";
  reinvite._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;lr>\r\n";
  reinvite._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  reinvite._extra_hdrs += "P-Asserted-Identity: \"6505550000\" <sip:6505550000@homedomain>\r\n";
  reinvite._extra_hdrs += "P-Asserted-Identity: <tel:6505550000>\r\n";
  reinvite._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain\r\n";
  reinvite._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";

  // Pass the reINVITE request to the ACR on its way through the S-CSCF.  We're
  // assuming the AS didn't Record-Route itself.
  ts.sec = 60;
  ts.msec = 0;
  acr->rx_request(parse_msg(reinvite.get()), ts);
  ts.msec = 5;
  acr->tx_request(parse_msg(reinvite.get()), ts);

  // Build a 200 OK response, and pass it to the ACR on the way through the S-CSCF.
  // Now build a 200 OK response.
  SIPResponse reinvite200ok(200, "INVITE");
  reinvite200ok._extra_hdrs = "Contact: <sip:6505559999@10.83.18.50:12345;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-cdef12345678>\"\r\n";
  reinvite200ok._extra_hdrs += "P-Asserted-Identity: \"6505550001\" <sip:6505550001@homedomain>\r\n";
  reinvite200ok._extra_hdrs += "P-Asserted-Identity: <tel:6505550001>\r\n";
  reinvite200ok._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain;term-ioi=homedomain\r\n";
  reinvite200ok._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";
  ts.msec = 10;
  acr->rx_response(parse_msg(reinvite200ok.get()), ts);
  ts.msec = 15;
  acr->tx_response(parse_msg(reinvite200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_scscftermcall_interim.json"));
  delete acr;

  // Create an ACR instance for the ACR[STOP] triggered by a BYE.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_TERMINATING);

  // Build the BYE request.
  SIPRequest bye("BYE");
  bye._requri = "sip:6505559999@10.83.18.50:12345;transport=TCP";
  bye._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;lr>\r\n";
  bye._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  bye._extra_hdrs += "P-Asserted-Identity: \"6505550000\" <sip:6505550000@homedomain>\r\n";
  bye._extra_hdrs += "P-Asserted-Identity: <tel:6505550000>\r\n";
  bye._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain\r\n";
  bye._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";

  // Pass the BYE request to the ACR on its way through the S-CSCF.  We're
  // assuming the AS didn't Record-Route itself.
  ts.sec = 120;
  ts.msec = 0;
  acr->rx_request(parse_msg(bye.get()), ts);
  ts.msec = 5;
  acr->tx_request(parse_msg(bye.get()), ts);

  // Build a 200 OK response, and pass it to the ACR on the way through the S-CSCF.
  // Now build a 200 OK response.
  SIPResponse bye200ok(200, "BYE");
  bye200ok._extra_hdrs = "Contact: <sip:6505559999@10.83.18.50:12345;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-cdef12345678>\"\r\n";
  bye200ok._extra_hdrs += "P-Asserted-Identity: \"6505550001\" <sip:6505550001@homedomain>\r\n";
  bye200ok._extra_hdrs += "P-Asserted-Identity: <tel:6505550001>\r\n";
  bye200ok._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain;term-ioi=homedomain\r\n";
  bye200ok._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";
  ts.msec = 15;
  acr->rx_response(parse_msg(bye200ok.get()), ts);
  ts.msec = 20;
  acr->tx_response(parse_msg(bye200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_scscftermcall_stop.json"));
  delete acr;
}

TEST_F(ACRTest, ICSCFRegister)
{
  // Tests mainline Rf message generation for a successful registration transaction
  // at the I-CSCF.
  pj_time_val ts;
  ACR* acr;
  std::string acr_message;

  // Create a Ralf ACR factory for I-CSCF ACRs.
  RalfACRFactory f(NULL, ACR::ICSCF);

  // Create an ACR instance for the ACR[EVENT] triggered by the REGISTER.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_ORIGINATING);

  // Build the original REGISTER request.
  SIPRequest reg("REGISTER");
  reg._requri = "sip:homedomain";
  reg._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;orig;lr>\r\n";
  reg._from = "\"6505550000\" <sip:6505550000@homedomain>";   // Strip tag.
  reg._to = "\"6505550000\" <sip:6505550000@homedomain>";   // Strip tag.
  reg._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  reg._extra_hdrs += "Expires: 300\r\n";
  reg._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain\r\n";
  reg._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";

  // Pass the request to the ACR as a received request.
  ts.sec = 1;
  ts.msec = 0;
  acr->rx_request(parse_msg(reg.get()), ts);

  // The I-CSCF now does a UAR query to the HSS and should received back a
  // server capabilities structure, which it adds to the ACR.
  ServerCapabilities caps;
  caps.scscf = "sip:scscf1.homedomain";
  caps.mandatory_caps.push_back(10);
  caps.mandatory_caps.push_back(20);
  caps.optional_caps.push_back(30);
  acr->server_capabilities(caps);

  // I-CSCF sends an ACR immediately after the UAR query completes.
  ts.msec = 10;
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_icscfregister_caps.json"));

  // I-CSCF updates the request URI of the REGISTER and forwards it to the
  // assigned S-CSCF.
  reg._requri = caps.scscf;
  acr->tx_request(parse_msg(reg.get()), ts);

  // Now build a 200 OK response.
  SIPResponse reg200ok(200, "REGISTER");
  reg200ok._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;expires=300;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  reg200ok._extra_hdrs = "P-Associated-URI: <sip:6505550000@homedomain>, <tel:6505550000>\r\n";

  // Pass the response to ACR as a received and transmitted response.
  ts.msec = 25;
  acr->rx_response(parse_msg(reg200ok.get()), ts);
  acr->tx_response(parse_msg(reg200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_icscfregister_final.json"));
  delete acr;
}

TEST_F(ACRTest, SCSCFPublish)
{
  // Tests mainline Rf message generation for a successful publish transaction (with body)
  // at the S-CSCF.
  pj_time_val ts;
  ACR* acr;
  std::string acr_message;

  // Create a Ralf ACR factory for S-CSCF ACRs.
  RalfACRFactory f(NULL, ACR::SCSCF);

  // Create an ACR instance for the ACR[EVENT] triggered by the REGISTER.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_ORIGINATING);

  // Build the original REGISTER request.
  SIPRequest pub("PUBLISH");
  pub._requri = "sip:homedomain";
  pub._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;orig;lr>\r\n";
  pub._from = "\"6505550000\" <sip:6505550000@homedomain>";   // Strip tag.
  pub._to = "\"6505550000\" <sip:6505550000@homedomain>";   // Strip tag.
  pub._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  pub._extra_hdrs += "Expires: 300\r\n";
  pub._extra_hdrs += "P-Charging-Vector: icid-value=1234bc9876e;icid-generated-at=10.83.18.28;orig-ioi=homedomain\r\n";
  pub._extra_hdrs += "P-Charging-Function-Addresses: ccf=192.1.1.1;ccf=192.1.1.2;ecf=192.1.1.3;ecf=192.1.1.4\r\n";
  pub._extra_hdrs += "Content-Type: text/plain\r\n";
  pub._body = "Hello world!";

  // Pass the request to the ACR as a received request.
  ts.sec = 1;
  ts.msec = 0;
  acr->rx_request(parse_msg(pub.get()), ts);

  // Now build a 200 OK response.
  SIPResponse pub200ok(200, "PUBLISH");

  // Pass the response to ACR as a transmitted response.
  ts.msec = 25;
  acr->tx_response(parse_msg(pub200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  acr_message = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(acr_message, "acr_scscfpublish.json"));
  delete acr;
}

TEST_F(ACRTest, SCSCFTermChangeCallId)
{
  // Tests mainline Rf message generation for a successful terminating call
  // through a S-CSCF.
  pj_time_val ts;
  ACR* acr;
  std::string acr_message;

  // Create a Ralf ACR factory for S-CSCF ACRs.
  RalfACRFactory f(NULL, ACR::SCSCF);

  // Create an ACR instance for the test.
  acr = f.get_acr(0, ACR::CALLING_PARTY, ACR::NODE_ROLE_TERMINATING);

  // Build the original INVITE request.
  SIPRequest invite("INVITE");
  invite._routes = "Route: <sip:sprout.homedomain:5054;transport=TCP;lr>\r\n";
  invite._to = "\"6505550001\" <sip:6505550001@homedomain>";   // Strip tag.
  invite._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n";
  invite._extra_hdrs += "Session-Expires: 600\r\n";
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
"m=audio 1988 RTP/SAVPF 0 8\r\n"
"c=IN IP4 10.83.18.38\r\n";

  const std::string ORIG_CALL_ID = invite._call_id;
  const std::string NEW_CALL_ID = "differentfromapreviouscallid@10.83.18.38";

  // Pass the request to the ACR as a received request.
  ts.sec = 1;
  ts.msec = 0;
  acr->rx_request(parse_msg(invite.get()), ts);

  // Build a 100 Trying response and pass it to the ACR as a transmitted
  // response.
  SIPResponse r100trying(100, "INVITE");
  ts.msec = 5;
  acr->tx_response(parse_msg(r100trying.get()), ts);

  // Update the message as if we're transmitting it to an AS, by replacing
  // the existing Route header with the usual two Route headers.
  invite._routes = "Route: <sip:as1.homedomain:5060;transport=TCP;lr>\r\nRoute: <sip:odi_12345678@sprout.homedomain:5054;transport=TCP;lr>\r\n";

  // Pass the request to the ACR as a transmitted request.
  ts.msec = 10;
  acr->tx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR as a received response (from the AS).
  ts.msec = 15;
  acr->rx_response(parse_msg(r100trying.get()), ts);

  // Update the INVITE request as it comes back from the AS - remove the first
  // Route header and change the Call ID.
  invite._routes = "Route: <sip:odi_12345678@sprout.homedomain:5054;transport=TCP;lr>\r\n";
  invite._call_id = NEW_CALL_ID;
  r100trying._call_id = NEW_CALL_ID;

  // Pass the request to the ACR as a received request.
  ts.msec = 20;
  acr->rx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR again as a transmitted response,
  // this time to the target endpoint.
  ts.msec = 25;
  acr->tx_response(parse_msg(r100trying.get()), ts);

  // Update the request as it is finally forwarded by the S-CSCF by adding
  // a Route header routing the request to the appropriate flow on the
  // appropriate P-CSCF, and converting the RequestURI to a contact URI.
  //
  // Also simulate the S-CSCF deciding to bill at this hop in the call and
  // deciding on a session ID to use.
  invite._routes = "Route: <sip:abcdefgh@pcscf1.homedomain:5058;transport=TCP;lr>\r\n";
  invite._requri = "sip:6505559999@10.83.18.50:5060;transport=TCP";
  acr->override_session_id(NEW_CALL_ID);

  // Pass the request to the ACR as a finally transmitted request.
  ts.msec = 30;
  acr->tx_request(parse_msg(invite.get()), ts);

  // Pass the 100 Trying response to the ACR again as a received response,
  // this time from the target endpoint.
  ts.msec = 35;
  acr->rx_response(parse_msg(r100trying.get()), ts);

  // Now build a 200 OK response.
  SIPResponse r200ok(200, "INVITE");
  r200ok._extra_hdrs = "Contact: <sip:6505559999@10.83.18.50:12345;transport=TCP>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-cdef12345678>\"\r\n";
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
"m=audio 1988 RTP/SAVPF 0 8\r\n"
"c=IN IP4 10.83.18.50\r\n";
  r200ok._call_id = NEW_CALL_ID;

  // Pass the response to ACR as if it was making its way back through the
  // AS chain.
  ts.msec = 40;
  acr->rx_response(parse_msg(r200ok.get()), ts);
  ts.msec = 50;
  acr->tx_response(parse_msg(r200ok.get()), ts);
  ts.msec = 60;

  r200ok._call_id = ORIG_CALL_ID;

  acr->rx_response(parse_msg(r200ok.get()), ts);
  acr->as_info("sip:as1.homedomain:5060;transport=TCP",
               "sip:6505559999@homedomain",
               200,
               false);
  ts.msec = 70;
  acr->tx_response(parse_msg(r200ok.get()), ts);

  // Build and checked the resulting Rf ACR message.
  string rf_acr = acr->get_message(ts);
  EXPECT_TRUE(compare_acr(rf_acr, "acr_scscftermcall_start_changed_call_id.json"));

  delete acr;
}

