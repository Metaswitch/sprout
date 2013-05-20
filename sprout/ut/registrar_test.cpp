/**
 * @file registrar_test.cpp UT for Sprout registrar module.
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

///
///----------------------------------------------------------------------------

#include <string>
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "utils.h"
#include "localstorefactory.h"
#include "analyticslogger.h"
#include "stack.h"
#include "registrar.h"
#include "registration_utils.h"
#include "fakelogger.hpp"
#include "fakehssconnection.hpp"

using namespace std;

/// Fixture for RegistrarTest.
class RegistrarTest : public SipTest
{
public:
  FakeLogger _log;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    _store = RegData::create_local_store();
    _analytics = new AnalyticsLogger("foo");
    _hss_connection = new FakeHSSConnection();
    _ifc_handler = new IfcHandler(_hss_connection, _store);
    delete _analytics->_logger;
    _analytics->_logger = NULL;
    pj_status_t ret = init_registrar(_store, _analytics, _ifc_handler);
    ASSERT_EQ(PJ_SUCCESS, ret);
    stack_data.sprout_cluster_domain = pj_str("all.the.sprout.nodes");
  }

  static void TearDownTestCase()
  {
    destroy_registrar();
    delete _ifc_handler; _ifc_handler = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics;
    RegData::destroy_local_store(_store); _store = NULL;

    SipTest::TearDownTestCase();
  }

  RegistrarTest() : SipTest(&mod_registrar)
  {
    _analytics->_logger = &_log;
    _store->flush_all();  // start from a clean slate on each test
  }

  ~RegistrarTest()
  {
    _analytics->_logger = NULL;
  }

protected:
  static RegData::Store* _store;
  static AnalyticsLogger* _analytics;
  static IfcHandler* _ifc_handler;
  static FakeHSSConnection* _hss_connection;
};

RegData::Store* RegistrarTest::_store;
AnalyticsLogger* RegistrarTest::_analytics;
IfcHandler* RegistrarTest::_ifc_handler;
FakeHSSConnection* RegistrarTest::_hss_connection;

class Message
{
public:
  string _method;
  string _user;
  string _domain;
  string _content_type;
  string _body;
  string _contact;
  string _contact_instance;
  string _contact_params;
  string _expires;
  string _path;

  Message() :
    _method("REGISTER"),
    _user("6505550231"),
    _domain("homedomain"),
    _contact("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob"),
    _contact_instance(";+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\""),
    _contact_params(";expires=3600;+sip.ice;reg-id=1"),
    _expires(""),
    _path("Path: sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob")
  {
  }

  string get();
};

string Message::get()
{
  char buf[16384];

  int n = snprintf(buf, sizeof(buf),
                   "%1$s sip:%3$s SIP/2.0\r\n"
                   "%10$s"
                   "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "Supported: outbound, path\r\n"
                   "To: <sip:%2$s@%3$s>\r\n"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: 16567 %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "%11$s"
                   "Contact: %8$s%7$s%9$s\r\n"
                   "Route: <sip:sprout.example.com;transport=tcp;lr>\r\n"
                   "P-Access-Network-Info: DUMMY\r\n"
                   "P-Visited-Network-ID: DUMMY\r\n"
                   "%4$s"
                   "Content-Length:  %5$d\r\n"
                   "\r\n"
                   "%6$s",
                   /*  1 */ _method.c_str(),
                   /*  2 */ _user.c_str(),
                   /*  3 */ _domain.c_str(),
                   /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                   /*  5 */ (int)_body.length(),
                   /*  6 */ _body.c_str(),
                   /*  7 */ _contact_params.c_str(),
                   /*  8 */ (_contact == "*") ? "*" : string("<").append(_contact).append(">").c_str(),
                   /*  9 */ _contact_instance.c_str(),
                   /* 10 */ _path.empty() ? "" : string(_path).append("\r\n").c_str(),
                   /* 11 */ _expires.empty() ? "" : string(_expires).append("\r\n").c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  // cout << ret <<endl;
  return ret;
}


TEST_F(RegistrarTest, NotRegister)
{
  Message msg;
  msg._method = "INVITE";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

TEST_F(RegistrarTest, NotOurs)
{
  Message msg;
  msg._domain = "not-us.example.org";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

/// Simple correct example with Expires header
TEST_F(RegistrarTest, SimpleMainlineExpiresHeader)
{
  Message msg;
  msg._expires = "Expires: 300";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();
}

/// Simple correct example with Expires parameter
TEST_F(RegistrarTest, SimpleMainlineExpiresParameter)
{
  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();
}

/// Simple correct example with Expires parameter set to 0
TEST_F(RegistrarTest, SimpleMainlineDeregister)
{
  Message msg;
  msg._contact_params = ";expires=0;+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("", get_headers(out, "Contact"));  // no existing bindings
  free_txdata();
}

/// Simple correct example with no expiry header or parameter.
TEST_F(RegistrarTest, SimpleMainlineNoExpiresHeaderParameter)
{
  Message msg;
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();
}

TEST_F(RegistrarTest, MultipleRegistrations)
{
  // First registration OK.
  Message msg;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  free_txdata();

  // Second registration also OK.  Bindings are ordered by binding ID.
  Message msg0;
  msg = msg0;
  msg._contact = "sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob";
  msg._contact_instance = ";+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\"";
  msg._path = "Path: sip:XxxxxxxXXXXXXAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-119.compute-1.amazonaws.com:5060;lr;ob";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\"\r\n"
            "Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();

  // Reregistration of first binding is OK but doesn't add a new one.
  msg = msg0;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\"\r\n"
            "Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();

  // Registering the first binding again but without the binding ID counts as a separate binding (named by the contact itself).  Bindings are ordered by binding ID.
  msg = msg0;
  msg._contact_instance = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\"\r\n"
            "Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n"
            "Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();

  // Reregistering that yields no change.
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\"\r\n"
            "Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"\r\n"
            "Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();

  // Registration of star clears all bindings.
  msg = msg0;
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("", get_headers(out, "Contact"));
  EXPECT_EQ("", get_headers(out, "Require")); // even though we have path, we have no bindings
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();
}

TEST_F(RegistrarTest, NoPath)
{
  Message msg;
  msg._path = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("", get_headers(out, "Require")); // because we have no path
  EXPECT_EQ("", get_headers(out, "Path"));
  free_txdata();
}

// Generate a REGISTER flow to app servers from the iFC.
// First case - REGISTER is generated with a multipart body
TEST_F(RegistrarTest, AppServersWithMultipartBody)
{
  _hss_connection->set_user_ifc("sip:6505550231@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "    <ServiceInfo>banana</ServiceInfo>\n"
                                "      <Extension><IncludeRegisterRequest/><IncludeRegisterResponse/></Extension>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);


  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // INVITE passed on to AS
  SCOPED_TRACE("REGISTER (S)");
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pj_str_t multipart = pj_str("multipart");
  pj_str_t mixed = pj_str("mixed");
  EXPECT_EQ(0, pj_strcmp(&multipart, &out->body->content_type.type));
  EXPECT_EQ(0, pj_strcmp(&mixed, &out->body->content_type.subtype));

  tpAS.expect_target(current_txdata(), false);

  free_txdata();
}

/// Second case - REGISTER is generated with a non-multipart body
TEST_F(RegistrarTest, AppServersWithOneBody)
{
  _hss_connection->set_user_ifc("sip:6505550231@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "      <Extension><IncludeRegisterRequest/></Extension>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);


  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  pj_str_t message = pj_str("message");
  pj_str_t sip = pj_str("sip");
  EXPECT_EQ(0, pj_strcmp(&message, &out->body->content_type.type));
  EXPECT_EQ(0, pj_strcmp(&sip, &out->body->content_type.subtype));

  tpAS.expect_target(current_txdata(), false);

  free_txdata();
}

/// Third case - REGISTER is generated with no body
TEST_F(RegistrarTest, AppServersWithNoBody)
{
  _hss_connection->set_user_ifc("sip:6505550231@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);


  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob;expires=300;+sip.ice;reg-id=1;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);

  free_txdata();
}

/// Check that the network-initiated deregistration code works as expected
TEST_F(RegistrarTest, DeregisterAppServersWithNoBody)
{
  _hss_connection->set_user_ifc("sip:6505550231@homedomain",
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<ServiceProfile>\n"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>1</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, TransportFlow::Trust::TRUSTED, "1.2.3.4", 56789);

  register_uri(_store, "6505550231", "homedomain", "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213", 30);
  RegData::AoR* aor_data;
  aor_data = _store->get_aor_data("sip:6505550231@homedomain");
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;

  RegistrationUtils::network_initiated_deregistration(_ifc_handler, _store, "sip:6505550231@homedomain", "*");

  SCOPED_TRACE("deREGISTER");
  // Check that we send a REGISTER to the AS on network-initiated deregistration
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);

  free_txdata();
  // Check that we deleted the binding
  aor_data = _store->get_aor_data("sip:6505551234@homedomain");
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;
}
