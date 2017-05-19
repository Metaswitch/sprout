/**
 * @file mangelwurzel_test.cpp UT fixture for mangelwurzel.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "gtest/gtest.h"

#include "siptest.hpp"
#include "mangelwurzel.h"
#include "mocktsxhelper.h"
#include "stack.h"
#include "pjutils.h"

using namespace std;
using testing::InSequence;
using testing::Return;
using testing::ReturnNull;
using testing::_;

/// Fixture for MangelwurzelTest.
///
/// This derives from SipTest to ensure PJSIP is set up correctly, but doesn't
/// actually use most of its function (and doesn't register a module).
class MangelwurzelTest : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    _helper = new MockSproutletTsxHelper();
  }

  static void TearDownTestCase()
  {
    delete _helper; _helper = NULL;
    SipTest::TearDownTestCase();
  }

  MangelwurzelTest() : SipTest(NULL)
  {
  }

  ~MangelwurzelTest()
  {
  }

  class Message
  {
  public:
    string _requri;
    string _method;
    string _from;
    string _to;
    string _call_id;
    string _routes;
    string _extra_hdrs;

    Message() :
      _requri("sip:6505550001@homedomain"),
      _method("INVITE"),
      _from("\"6505550000\" <sip:6505550000@homedomain>;tag=12345678"),
      _to("\"6505550001\" <sip:6505550001@homedomain>;tag=87654321"),
      _call_id("0123456789abcdef-10.83.18.38"),
      _routes(),
      _extra_hdrs()
    {
    }

    string get_request()
    {
      char buf[16384];

      int n = snprintf(buf, sizeof(buf),
                       "%7$s %1$s SIP/2.0\r\n"
                       "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                       "%5$s"
                       "Max-Forwards: 68\r\n"
                       "Supported: outbound, path\r\n"
                       "To: %2$s\r\n"
                       "From: %3$s\r\n"
                       "Call-ID: %4$s\r\n"
                       "CSeq: 1 INVITE\r\n"
                       "%6$s"
                       "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
                       "User-Agent: Cleaarwater UT\r\n",
                       _requri.c_str(),     // $1
                       _to.c_str(),         // $2
                       _from.c_str(),       // $3
                       _call_id.c_str(),    // $4
                       _routes.c_str(),     // $5
                       _extra_hdrs.c_str(), // $6
                       _method.c_str()      // $7
                      );

      EXPECT_LT(n, (int)sizeof(buf));

      TRC_DEBUG("Request\n%s", buf);

      string ret(buf, n);
      return ret;
    }

    string get_response()
    {
      char buf[16384];

      int n = snprintf(buf, sizeof(buf),
                       "SIP/2.0 200 OK\r\n"
                       "Via: SIP/2.0/TCP 11.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                       "Max-Forwards: 68\r\n"
                       "Supported: outbound, path\r\n"
                       "To: %1$s\r\n"
                       "From: %2$s\r\n"
                       "Call-ID: %3$s\r\n"
                       "CSeq: 1 INVITE\r\n"
                       "%4$s"
                       "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
                       "User-Agent: Clearwater UT\r\n",
                       _to.c_str(),        // $1
                       _from.c_str(),      // $2
                       _call_id.c_str(),   // $3
                       _extra_hdrs.c_str() // $4
                      );

      EXPECT_LT(n, (int)sizeof(buf));

      TRC_DEBUG("Response\n%s", buf);

      string ret(buf, n);
      return ret;
    }
  };

  static MockSproutletTsxHelper* _helper;
};

MockSproutletTsxHelper* MangelwurzelTest::_helper = NULL;

MATCHER_P(ReqUriEquals, req_uri, "")
{
  std::string arg_req_uri = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI,
                                                   arg->line.req.uri);
  TRC_DEBUG("arg_req_uri %s", arg_req_uri.c_str());
  return arg_req_uri == req_uri;
}

/// Check the rot13 mangalgorithm works as expected for various strings.
TEST_F(MangelwurzelTest, Rot13)
{
  MangelwurzelTsx::Config config;
  Message msg;
  MangelwurzelTsx mangelwurzel_tsx(NULL, config);
  mangelwurzel_tsx.set_helper(_helper);

  std::string test_str = "pogo123";
  mangelwurzel_tsx.rot13(test_str);
  EXPECT_EQ(test_str, "cbtb678");

  test_str = "example.com";
  mangelwurzel_tsx.rot13(test_str);
  EXPECT_EQ(test_str, "rknzcyr.pbz");

  test_str = "";
  mangelwurzel_tsx.rot13(test_str);
  EXPECT_EQ(test_str, "");
}

/// Check the reverse mangalgorithm works as expected for various strings.
TEST_F(MangelwurzelTest, Reverse)
{
  MangelwurzelTsx::Config config;
  Message msg;
  MangelwurzelTsx mangelwurzel_tsx(NULL, config);
  mangelwurzel_tsx.set_helper(_helper);

  std::string test_str = "pogo123";
  mangelwurzel_tsx.reverse(test_str);
  EXPECT_EQ(test_str, "321ogop");

  test_str = "example.com";
  mangelwurzel_tsx.reverse(test_str);
  EXPECT_EQ(test_str, "moc.elpmaxe");

  test_str = "";
  mangelwurzel_tsx.reverse(test_str);
  EXPECT_EQ(test_str, "");
}

/// Test creating a mangelwurzel transaction with no config options set. The
/// config should all be defaulted correctly.
TEST_F(MangelwurzelTest, CreateDefaults)
{
  Mangelwurzel mangelwurzel("mangelwurzel", 5058, "sip:mangelwurzel.homedomain:5058;transport=tcp");
  Message msg;
  msg._routes = "Route: <sip:mangelwurzel.homedomain>\r\n";
  pjsip_msg* req = parse_msg(msg.get_request());

  // No parameters on the Route header URI. Check the default values are all
  // set.
  pjsip_sip_uri* uri = NULL;
  MangelwurzelTsx* mangelwurzel_tsx =
    (MangelwurzelTsx*)mangelwurzel.get_tsx(NULL, "mangelwurzel", req, uri, NULL, 0);
  EXPECT_TRUE(mangelwurzel_tsx != NULL);
  EXPECT_FALSE(mangelwurzel_tsx->_config.dialog);
  EXPECT_FALSE(mangelwurzel_tsx->_config.req_uri);
  EXPECT_FALSE(mangelwurzel_tsx->_config.to);
  EXPECT_FALSE(mangelwurzel_tsx->_config.change_domain);
  EXPECT_FALSE(mangelwurzel_tsx->_config.routes);
  EXPECT_FALSE(mangelwurzel_tsx->_config.orig);
  EXPECT_FALSE(mangelwurzel_tsx->_config.ootb);
  EXPECT_EQ(mangelwurzel_tsx->_config.mangalgorithm, MangelwurzelTsx::ROT_13);
  mangelwurzel_tsx->set_helper(_helper);

  delete mangelwurzel_tsx; mangelwurzel_tsx = NULL;
}

/// Test creating a mangelwurzel transaction with all the config options set.
TEST_F(MangelwurzelTest, CreateFullConfig)
{
  Mangelwurzel mangelwurzel("mangelwurzel", 5058, "sip:mangelwurzel.homedomain:5058;transport=tcp");
  Message msg;
  msg._routes = "Route: <sip:mangelwurzel.homedomain;dialog;req-uri;to;routes;change-domain;orig;ootb;mangalgorithm=reverse>\r\n";
  pjsip_msg* req = parse_msg(msg.get_request());

  // Set all the parameters on the Route header URI. Check the values are all
  // accurate in the transaction's config.
  pjsip_sip_uri* uri = NULL;
  MangelwurzelTsx* mangelwurzel_tsx =
    (MangelwurzelTsx*)mangelwurzel.get_tsx(NULL,
                                           "mangelwurzel",
                                           req,
                                           uri,
                                           NULL,
                                           0);
  EXPECT_TRUE(mangelwurzel_tsx != NULL);
  EXPECT_TRUE(mangelwurzel_tsx->_config.dialog);
  EXPECT_TRUE(mangelwurzel_tsx->_config.req_uri);
  EXPECT_TRUE(mangelwurzel_tsx->_config.to);
  EXPECT_TRUE(mangelwurzel_tsx->_config.change_domain);
  EXPECT_TRUE(mangelwurzel_tsx->_config.routes);
  EXPECT_TRUE(mangelwurzel_tsx->_config.orig);
  EXPECT_TRUE(mangelwurzel_tsx->_config.ootb);
  EXPECT_EQ(mangelwurzel_tsx->_config.mangalgorithm, MangelwurzelTsx::REVERSE);
  mangelwurzel_tsx->set_helper(_helper);

  delete mangelwurzel_tsx; mangelwurzel_tsx = NULL;
}

/// Test creating a mangelwurzel transaction with the mangalgorithm set to
/// rot13.
TEST_F(MangelwurzelTest, CreateRot13)
{
  Mangelwurzel mangelwurzel("mangelwurzel", 5058, "sip:mangelwurzel.homedomain:5058;transport=tcp");
  Message msg;
  msg._routes = "Route: <sip:mangelwurzel.homedomain;mangalgorithm=rot13>\r\n";
  pjsip_msg* req = parse_msg(msg.get_request());

  // Check that setting the mangalgorithm to rot13 works.
  pjsip_sip_uri* uri = NULL;
  MangelwurzelTsx* mangelwurzel_tsx =
    (MangelwurzelTsx*)mangelwurzel.get_tsx(NULL,
                                           "mangelwurzel",
                                           req,
                                           uri,
                                           NULL,
                                           0);
  EXPECT_TRUE(mangelwurzel_tsx != NULL);
  EXPECT_EQ(mangelwurzel_tsx->_config.mangalgorithm, MangelwurzelTsx::ROT_13);
  mangelwurzel_tsx->set_helper(_helper);

  delete mangelwurzel_tsx; mangelwurzel_tsx = NULL;
}

/// Test creating a mangelwurzel transaction with an invalid mangalgorithm.
TEST_F(MangelwurzelTest, CreateInvalidMangalgorithm)
{
  CapturingTestLogger log;
  Mangelwurzel mangelwurzel("mangelwurzel", 5058, "sip:mangelwurzel.homedomain:5058;transport=tcp");
  Message msg;
  msg._routes = "Route: <sip:mangelwurzel.homedomain;mangalgorithm=invalid>\r\n";
  pjsip_msg* req = parse_msg(msg.get_request());

  // Check that setting the mangalgorithm to an invalid value doesn't fail, but
  // that a log is raised.
  pjsip_sip_uri* uri = NULL;
  MangelwurzelTsx* mangelwurzel_tsx =
    (MangelwurzelTsx*)mangelwurzel.get_tsx(NULL,
                                           "mangelwurzel",
                                           req,
                                           uri,
                                           NULL,
                                           0);
  EXPECT_TRUE(mangelwurzel_tsx != NULL);
  EXPECT_TRUE(log.contains("Invalid mangalgorithm specified"));
  EXPECT_EQ(mangelwurzel_tsx->_config.mangalgorithm, MangelwurzelTsx::ROT_13);
  mangelwurzel_tsx->set_helper(_helper);

  delete mangelwurzel_tsx; mangelwurzel_tsx = NULL;
}

/// Test creating a mangelwurzel transaction with no mangelwurzel Route header.
/// We should pick up information from the Request-URI.
TEST_F(MangelwurzelTest, CreateNoRouteHdr)
{
  Mangelwurzel mangelwurzel("mangelwurzel", 5058, "sip:mangelwurzel.homedomain:5058;transport=tcp");
  Message msg;
  msg._requri = "sip:mangelwurzel.homedomain;mangalgorithm=reverse";
  pjsip_msg* req = parse_msg(msg.get_request());

  pjsip_sip_uri* uri = NULL;
  MangelwurzelTsx* mangelwurzel_tsx =
    (MangelwurzelTsx*)mangelwurzel.get_tsx(NULL,
                                           "mangelwurzel",
                                           req,
                                           uri,
                                           NULL,
                                           0);
  EXPECT_TRUE(mangelwurzel_tsx != NULL);
  EXPECT_EQ(mangelwurzel_tsx->_config.mangalgorithm, MangelwurzelTsx::REVERSE);
  mangelwurzel_tsx->set_helper(_helper);
  delete mangelwurzel_tsx; mangelwurzel_tsx = NULL;
}

TEST_F(MangelwurzelTest, InitialReq)
{
  // Create a request with an S-CSCF Route header, a Contact header and a
  // Record-Route header.
  Message msg;
  msg._routes = "Route: <sip:mangelwurzel.homedomain;dialog;req-uri;to;routes;change-domain;orig;ootb;mangalgorithm=rot13>\r\nRoute: <sip:odi_a1b2c3@sprout.homedomain:5054;transport=TCP;lr>\r\n";
  msg._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>\r\nRecord-Route: <sip:homedomain>\r\n";
  pjsip_msg* req = parse_msg(msg.get_request());

  // Save off the original request. We expect mangelwurzel to request it later.
  pjsip_msg* original_req = parse_msg(msg.get_request());
  EXPECT_CALL(*_helper, free_msg(original_req));

  // Set up the mangelwurzel transaction's config. Turn everything on.
  MangelwurzelTsx::Config config;
  config.dialog = true;
  config.req_uri = true;
  config.to = true;
  config.routes = true;
  config.change_domain = true;
  config.orig = true;
  config.ootb = true;
  MangelwurzelTsx mangelwurzel_tsx(NULL, config);
  mangelwurzel_tsx.set_helper(_helper);

  // Create the corresponding Route header for this config set. We expect
  // mangelwurzel to request it when it Record-Routes itself.
  pjsip_route_hdr* hdr = pjsip_rr_hdr_create(stack_data.pool);
  hdr->name_addr.uri =
    PJUtils::uri_from_string("sip:mangelwurzel.homedomain;dialog;req-uri;to;routes;change-domain;orig;ootb;mangalgorithm=rot13",
                             stack_data.pool);
  EXPECT_CALL(*_helper, route_hdr()).WillRepeatedly(Return(hdr));

  // Strip off the top route header like the Sproulet Proxy normally would.
  pjsip_route_hdr* route = (pjsip_route_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_ROUTE, NULL);
  pj_list_erase(route);

  // Trigger initial request processing in mangelwurzel and catch the request
  // again when mangelwurzel sends it on.
  EXPECT_CALL(*_helper, original_request()).WillOnce(Return(original_req));
  EXPECT_CALL(*_helper, get_pool(req)).WillOnce(Return(stack_data.pool));
  EXPECT_CALL(*_helper, send_request(req));
  mangelwurzel_tsx.on_rx_initial_request(req);

  // Check mangelwurzel has made the appropriate manipulations.
  EXPECT_EQ("To: \"6505550001\" <sip:1050005556@ubzrqbznva>;tag=32109876",
            get_headers(req, "To"));
  EXPECT_EQ("From: \"6505550000\" <sip:6505550000@homedomain>;tag=67890123",
            get_headers(req, "From"));
  EXPECT_EQ("Call-ID: 5678901234nopqrs-65.38.63.83",
            get_headers(req, "Call-ID"));
  EXPECT_EQ("Contact: <sip:1050005555@65.38.63.83:36530;transport=TCP>",
            get_headers(req, "Contact"));
  EXPECT_EQ("Route: <sip:sprout.homedomain:5054;transport=TCP;lr;orig>",
            get_headers(req, "Route"));
  EXPECT_EQ("", get_headers(req, "Via"));
  EXPECT_THAT(req, ReqUriEquals("sip:1050005556@ubzrqbznva"));
  EXPECT_EQ("Record-Route: <sip:mangelwurzel.homedomain;dialog;req-uri;to;routes;change-domain;orig;ootb;mangalgorithm=rot13>\r\nRecord-Route: <sip:ubzrqbznva>",
            get_headers(req, "Record-Route"));
}

TEST_F(MangelwurzelTest, Response)
{
  // Setup a response with an S-CSCF Route header, a Contact header and a
  // Record-Route header.
  Message msg;
  msg._routes = "Route: <sip:odi_a1b2c3@sprout.homedomain:5054;transport=TCP;lr>\r\n";
  msg._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>\r\nRecord-Route: <sip:homedomain>\r\n";

  // Save off the original request. We expect mangelwurzel to request it later.
  pjsip_msg* original_req = parse_msg(msg.get_request());
  EXPECT_CALL(*_helper, free_msg(original_req));

  // Set up the mangelwurzel transaction's config. Turn everything on.
  MangelwurzelTsx::Config config;
  config.dialog = true;
  config.req_uri = true;
  config.to = true;
  config.routes = true;
  config.change_domain = true;
  config.orig = true;
  config.ootb = true;
  MangelwurzelTsx mangelwurzel_tsx(NULL, config);
  mangelwurzel_tsx.set_helper(_helper);
  mangelwurzel_tsx._unmodified_request = original_req;

  // Create the response and trigger response processing on mangelwurzel. Catch
  // the response again when mangelwurzel sends it on.
  pjsip_msg* rsp = parse_msg(msg.get_response());
  EXPECT_CALL(*_helper, get_pool(rsp)).WillOnce(Return(stack_data.pool));
  EXPECT_CALL(*_helper, send_response(rsp));
  mangelwurzel_tsx.on_rx_response(rsp, 0);

  // Check mangelwurzel has made the appropriate manipulations.
  EXPECT_EQ("To: \"6505550001\" <sip:6505550001@homedomain>;tag=32109876",
            get_headers(rsp, "To"));
  EXPECT_EQ("From: \"6505550000\" <sip:6505550000@homedomain>;tag=67890123",
            get_headers(rsp, "From"));
  EXPECT_EQ("Call-ID: 5678901234nopqrs-65.38.63.83",
            get_headers(rsp, "Call-ID"));
  EXPECT_EQ("Contact: <sip:1050005555@65.38.63.83:36530;transport=TCP>",
            get_headers(rsp, "Contact"));
  EXPECT_EQ("Via: SIP/2.0/TCP 11.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\nVia: SIP/2.0/TCP 10.83.18.38:36530;rport=5060;received=0.0.0.0;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI",
            get_headers(rsp, "Via"));
  EXPECT_EQ("Record-Route: <sip:ubzrqbznva>",
            get_headers(rsp, "Record-Route"));
}

TEST_F(MangelwurzelTest, InDialogReq)
{
  // Create a request with an S-CSCF Route header, a Contact header and a
  // Record-Route header. The request is addressed to a tel URI.
  Message msg;
  msg._to = "\"6505550001\" <tel:6505550001>;tag=87654321";
  msg._routes = "Route: <sip:odi_a1b2c3@sprout.homedomain:5054;transport=TCP;lr;orig>\r\n";
  msg._extra_hdrs = "Contact: <sip:6505550000@10.83.18.38:36530;transport=TCP>\r\nRecord-Route: <sip:homedomain>\r\n";
  pjsip_msg* req = parse_msg(msg.get_request());

  // Set up the mangelwurzel transaction's config. This is different to the
  // mainline case in order to test more code paths.
  MangelwurzelTsx::Config config;
  config.dialog = true;
  config.req_uri = true;
  config.to = true;
  config.routes = true;
  config.change_domain = false;
  config.orig = false;
  config.ootb = false;
  config.mangalgorithm = MangelwurzelTsx::REVERSE;
  MangelwurzelTsx mangelwurzel_tsx(NULL, config);
  mangelwurzel_tsx.set_helper(_helper);

  // Trigger in dialog request processing in mangelwurzel and catch the request
  // again when mangelwurzel sends it on.
  EXPECT_CALL(*_helper, get_pool(req)).WillOnce(Return(stack_data.pool));
  EXPECT_CALL(*_helper, send_request(req));
  mangelwurzel_tsx.on_rx_in_dialog_request(req);

  // Check mangelwurzel has made the appropriate manipulations.
  EXPECT_EQ("To: \"6505550001\" <tel:1000555056>;tag=12345678",
            get_headers(req, "To"));
  EXPECT_EQ("From: \"6505550000\" <sip:6505550000@homedomain>;tag=87654321",
            get_headers(req, "From"));
  EXPECT_EQ("Call-ID: 83.81.38.01-fedcba9876543210",
            get_headers(req, "Call-ID"));
  EXPECT_EQ("Contact: <sip:0000555056@10.83.18.38:36530;transport=TCP>",
            get_headers(req, "Contact"));
  EXPECT_EQ("Route: <sip:3c2b1a_ido@niamodemoh.tuorps:5054;transport=TCP;lr>",
            get_headers(req, "Route"));
  EXPECT_EQ("", get_headers(req, "Via"));
  EXPECT_THAT(req, ReqUriEquals("sip:1000555056@homedomain"));
}


TEST_F(MangelwurzelTest, REGISTER)
{
  // Create a request with an S-CSCF Route header, a Contact header and a
  // Record-Route header. The request is addressed to a tel URI.
  Message msg;
  msg._method = "REGISTER";
  pjsip_msg* req = parse_msg(msg.get_request());

  // Save off the original request. We expect mangelwurzel to request it later.
  pjsip_msg* original_req = parse_msg(msg.get_request());
  EXPECT_CALL(*_helper, free_msg(original_req));

  // Set up the mangelwurzel transaction's config. This is different to the
  // mainline case in order to test more code paths.
  MangelwurzelTsx::Config config;
  config.dialog = true;
  config.req_uri = true;
  config.to = true;
  config.routes = true;
  config.change_domain = false;
  config.orig = false;
  config.ootb = false;
  config.mangalgorithm = MangelwurzelTsx::REVERSE;
  MangelwurzelTsx mangelwurzel_tsx(NULL, config);
  mangelwurzel_tsx.set_helper(_helper);

  // Trigger in dialog request processing in mangelwurzel and catch the request
  // again when mangelwurzel sends it on.
  EXPECT_CALL(*_helper, original_request()).WillOnce(Return(original_req));
  EXPECT_CALL(*_helper, create_response(_, PJSIP_SC_OK, ""));
  EXPECT_CALL(*_helper, send_response(_));
  EXPECT_CALL(*_helper, free_msg(req));
  mangelwurzel_tsx.on_rx_initial_request(req);
}
