#include "sproutletappserver.h"
#include "mockappserver.hpp"
#include "mocksproutlet.hpp"
#include "siptest.hpp"
#include "stack.h"
#include "gtest/gtest.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::PrintToString;
using ::testing::DoAll;
using ::testing::SaveArg;
using ::testing::Return;

class SproutletAppServerShimTest : public SipTest
{
public:
  static void SetUpTestCase() { SipTest::SetUpTestCase(); }
  static void TearDownTestCase() { SipTest::TearDownTestCase(); }
  
  virtual void SetUp()
  {
    _app_server = new MockAppServer();
    _sproutlet = new SproutletAppServerShim(_app_server);
    _app_server_tsx = NULL;
    _app_server_tsx_helper = NULL;
  }

  virtual void TearDown()
  {
    delete _sproutlet; _sproutlet = NULL;
    delete _app_server; _app_server = NULL;
    delete _app_server_tsx; _app_server_tsx = NULL;
  }

  SproutletAppServerShimTest() : SipTest(NULL) {}
  ~SproutletAppServerShimTest() {}

  // Helper function to pretend to be an AppServer
  MockAppServerTsx* app_server_get_app_tsx(AppServerTsxHelper* helper,
                                           pjsip_msg* msg)
  {
    _app_server_tsx = new MockAppServerTsx(helper);
    _app_server_tsx_helper = dynamic_cast<SproutletAppServerTsxHelper*>(helper);
    return _app_server_tsx;
  }

  // Helper function to pretend to be an AppServerTsx
  void app_server_tsx_on_initial_request(pjsip_msg* const msg)
  {
    // Some tedious de-consting of the argument (this is because gmock
    // only captures const versions of arguments)
    pjsip_msg* non_const_msg = msg;
    _app_server_tsx_helper->send_request(non_const_msg);
  }

protected:
  SproutletAppServerShim* _sproutlet;
  MockAppServer* _app_server;
  MockAppServerTsx* _app_server_tsx;
  SproutletAppServerTsxHelper* _app_server_tsx_helper;
};

namespace SIP
{
class Message
{
public:
  string _method;
  string _toscheme;
  string _status;
  string _from;
  string _fromdomain;
  string _to;
  string _todomain;
  string _top_route;
  string _next_route;

  Message() :
    _method("OPTIONS"),
    _toscheme("sip"),
    _status("200 OK"),
    _from("6505551000"),
    _fromdomain("homedomain"),
    _to("6505551234"),
    _todomain("homedomain"),
    _top_route(""),
    _next_route("")
  {
  }

  string get_request();
  string get_response();
};
}

string SIP::Message::get_request()
{
  char buf[16384];

  // The remote target.
  string target = string(_toscheme).append(":").append(_to);
  if (!_todomain.empty())
  {
    target.append("@").append(_todomain);
  }

  int n = snprintf(buf, sizeof(buf),
                   "%1$s sip:%4$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213;branch=z9hG4bK0123456789abcdef\r\n"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <sip:%4$s>\r\n"
                   "%5$s"
                   "%6$s"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "Content-Length: 0\r\n\r\n",
                   /*  1 */ _method.c_str(),
                   /*  2 */ _from.c_str(),
                   /*  3 */ _fromdomain.c_str(),
                   /*  4 */ target.c_str(),
                   /*  5 */ _top_route.empty() ? "" : string(_top_route).append("\r\n").c_str(),
                   /*  6 */ _next_route.empty() ? "" : string(_next_route).append("\r\n").c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}

string SIP::Message::get_response()
{
  char buf[16384];

  // The remote target.
  string target = string(_toscheme).append(":").append(_to);
  if (!_todomain.empty())
  {
    target.append("@").append(_todomain);
  }

  int n = snprintf(buf, sizeof(buf),
                   "SIP/2.0 %1$s\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213;branch=z9hG4bK0123456789abcdef\r\n"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <sip:%4$s@%5$s>\r\n"
                   "%6$s"
                   "%7$s"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %8$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "Content-Length: 0\r\n\r\n",
                   /*  1 */ _status.c_str(),
                   /*  2 */ _from.c_str(),
                   /*  3 */ _fromdomain.c_str(),
                   /*  4 */ _to.c_str(),
                   /*  5 */ _todomain.c_str(),
                   /*  6 */ _top_route.empty() ? "" : string(_top_route).append("\r\n").c_str(),
                   /*  7 */ _next_route.empty() ? "" : string(_next_route).append("\r\n").c_str(),
                   /*  8 */ _method.c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}

// Count the Route: headers in a msg and compare to the number
MATCHER_P(MsgWithNRoutes,
          count,
          std::string(negation ? "doesn't" : "does") +
            " have " +
            PrintToString(count) +
            " Route: headers")
{
  int actual_count = 0;
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr(arg,
                                                  PJSIP_H_ROUTE,
                                                  NULL);
  while (hdr != NULL)
  {
    ++actual_count;
    hdr = (pjsip_hdr*)pjsip_msg_find_hdr(arg,
                                         PJSIP_H_ROUTE,
                                         hdr->next);
  }

  return (count == actual_count);
}

TEST_F(SproutletAppServerShimTest, BasicTest)
{
  MockSproutletTsxHelper helper;

  // Create incoming message
  SIP::Message req;
  req._top_route = "Route: <sip:odi_123456@domain.com>";
  req._next_route = "Route: <sip:somewhere.com>";
  pjsip_msg* msg = parse_msg(req.get_request());

  // Get a transaction from the shim
  EXPECT_CALL(*_app_server, get_app_tsx(_, _)).
    WillOnce(Invoke(this,
                    &SproutletAppServerShimTest::app_server_get_app_tsx));
  SproutletTsx* tsx = _sproutlet->get_app_tsx(&helper, msg);
  ASSERT_NE((SproutletTsx*)NULL, tsx);

  // When we report the message as an incoming request we'll simply forward the
  // request back to the shim helper.
  //
  // Note that the top Route: header should have been stripped off.
  EXPECT_CALL(*_app_server_tsx, on_initial_request(MsgWithNRoutes(1))).
    WillOnce(Invoke(this,
                    &SproutletAppServerShimTest::app_server_tsx_on_initial_request));
 
  // This requires a pool to be make available
  EXPECT_CALL(helper, get_pool(msg)).
    WillOnce(Return(stack_data.pool));

  // And should call back to the original helper with the Route: header re-added.
  EXPECT_CALL(helper, send_request(MsgWithNRoutes(2))).
    WillOnce(Return(4));

  tsx->on_initial_request(msg);

  delete tsx; tsx = NULL;
}

TEST_F(SproutletAppServerShimTest, AppServerSaysNo)
{
  MockSproutletTsxHelper helper;

  // Create incoming message
  SIP::Message req;
  req._top_route = "Route: <sip:odi_123456@domain.com>";
  req._next_route = "Route: <sip:somewhere.com>";
  pjsip_msg* msg = parse_msg(req.get_request());

  // Fail to get a transaction from the shim since the AS doesn't want it.
  EXPECT_CALL(*_app_server, get_app_tsx(_, _)).WillOnce(Return((AppServerTsx*)NULL));
  SproutletTsx* tsx = _sproutlet->get_app_tsx(&helper, msg);
  ASSERT_EQ((SproutletTsx*)NULL, tsx);
}
