/**
 * @file appserver_test.cpp UT fixture for application server modules.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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


#include <string>
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "stack.h"
#include "utils.h"
#include "pjutils.h"
#include "analyticslogger.h"
#include "mockappserver.hpp"

using namespace std;
using testing::InSequence;
using testing::Return;

/// Fixture for AppServerTest.
///
/// This derives from SipTest to ensure PJSIP is set up correctly, but doesn't
/// actually use most of its function (and doesn't register a module).
class AppServerTest : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    _service_tsx = new MockServiceTsx();
  }

  static void TearDownTestCase()
  {
    delete _service_tsx; _service_tsx = NULL;
    SipTest::TearDownTestCase();
  }

  AppServerTest() : SipTest(NULL)
  {
  }

  ~AppServerTest()
  {
  }

  static MockServiceTsx* _service_tsx; 
};
MockServiceTsx* AppServerTest::_service_tsx = NULL;

namespace AS
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
  string _route;

  Message() :
    _method("OPTIONS"),
    _toscheme("sip"),
    _status("200 OK"),
    _from("6505551000"),
    _fromdomain("homedomain"),
    _to("6505551234"),
    _todomain("homedomain"),
    _route("")
  {
  }

  string get_request();
  string get_response();
};
}

string AS::Message::get_request()
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
                   /*  5 */ _route.empty() ? "" : string(_route).append("\r\n").c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}

string AS::Message::get_response()
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
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %7$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "Content-Length: 0\r\n\r\n",
                   /*  1 */ _status.c_str(),
                   /*  2 */ _from.c_str(),
                   /*  3 */ _fromdomain.c_str(),
                   /*  4 */ _to.c_str(),
                   /*  5 */ _todomain.c_str(),
                   /*  6 */ _route.empty() ? "" : string(_route).append("\r\n").c_str(),
                   /*  7 */ _method.c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}

using AS::Message;


/// Compares a pjsip_uri with a std::string.
MATCHER_P(UriEquals, uri, "")
{
  std::string arg_uri = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, arg);
  return arg_uri == uri; 
}


/// Dummy AppServerTsx that adds itself to the dialog.
class DummyDialogASTsx : public AppServerTsx
{
public:
  DummyDialogASTsx(ServiceTsx* service_tsx) :
    AppServerTsx(service_tsx) {}

  void on_initial_request(pjsip_msg* req)
  {
    add_to_dialog();
  }

  bool on_response(pjsip_msg* rsp, int fork_id)
  {
    // This is superfluous - we could just return true.
    send_response(rsp);
    return false;
  }
};
 

/// Dummy AppServerTsx that rejects the transaction.
class DummyRejectASTsx : public AppServerTsx
{
public:
  DummyRejectASTsx(ServiceTsx* service_tsx) :
    AppServerTsx(service_tsx) {}

  void on_initial_request(pjsip_msg* req)
  {
    reject(404, "Who?");
  }
};
 

/// Dummy AppServerTsx that forks the transaction.
class DummyForkASTsx : public AppServerTsx
{
public:
  DummyForkASTsx(ServiceTsx* service_tsx) :
    AppServerTsx(service_tsx) {}

  void on_initial_request(pjsip_msg* req)
  {
    pjsip_msg* req1 = clone_request(req);
    pjsip_msg* req2 = clone_request(req);
    pj_pool_t* pool = get_pool(req);
    add_target(PJUtils::uri_from_string("sip:alice@example.com", pool), req1);
    add_target(PJUtils::uri_from_string("sip:bob@example.com", pool), req2);
  }

  bool on_response(pjsip_msg* rsp, int fork_id)
  {
    // Drop all responses - naughty!
    free_msg(rsp);
    return false;
  }
};
 

/// Test the DummyDialogASTsx by passing a request and a response in.
TEST_F(AppServerTest, DummyDialogTest)
{
  Message msg;
  DummyDialogASTsx as_tsx(_service_tsx);

  EXPECT_CALL(*_service_tsx, add_to_dialog(""));
  as_tsx.on_initial_request(parse_msg(msg.get_request()));

  pjsip_msg* rsp = parse_msg(msg.get_response());
  EXPECT_CALL(*_service_tsx, send_response(rsp));
  as_tsx.on_response(rsp, 0);
}


/// Test the DummyRejectASTsx by passing a request in and getting it rejected.
TEST_F(AppServerTest, DummyRejectTest)
{
  Message msg;
  DummyRejectASTsx as_tsx(_service_tsx);

  EXPECT_CALL(*_service_tsx, reject(404, "Who?"));
  as_tsx.on_initial_request(parse_msg(msg.get_request()));
}


/// Test the DummyForkASTsx by passing a request in and checking it's forked.
TEST_F(AppServerTest, DummyForkTest)
{
  Message msg;
  DummyForkASTsx as_tsx(_service_tsx);

  pjsip_msg* req = parse_msg(msg.get_request());
  pjsip_msg req1;
  pjsip_msg req2;
  {
    // Use a sequence to ensure this happens in order.
    InSequence seq;
    EXPECT_CALL(*_service_tsx, clone_request(req))
      .WillOnce(Return(&req1))
      .WillOnce(Return(&req2));
    EXPECT_CALL(*_service_tsx, get_pool(req))
      .WillOnce(Return(stack_data.pool));
    EXPECT_CALL(*_service_tsx, add_target(UriEquals("sip:alice@example.com"), &req1));
    EXPECT_CALL(*_service_tsx, add_target(UriEquals("sip:bob@example.com"), &req2));
  }
  as_tsx.on_initial_request(req);

  pjsip_msg* rsp = parse_msg(msg.get_response());
  EXPECT_CALL(*_service_tsx, free_msg(rsp));
  as_tsx.on_response(rsp, 0);

  rsp = parse_msg(msg.get_response());
  EXPECT_CALL(*_service_tsx, free_msg(rsp));
  as_tsx.on_response(rsp, 0);
}
