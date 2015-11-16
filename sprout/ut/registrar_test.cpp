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

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "utils.h"
#include "analyticslogger.h"
#include "stack.h"
#include "registrar.h"
#include "registration_utils.h"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"
#include "test_interposer.hpp"
#include "mock_store.h"
#include "fakesnmp.hpp"

using ::testing::MatchesRegex;
using ::testing::_;
using ::testing::Return;

/// Fixture for RegistrarTest.
class RegistrarTest : public SipTest
{
public:

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    stack_data.scscf_uri = pj_str("sip:all.the.sprout.nodes:5058;transport=TCP");

    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new LocalStore();
    _store = new RegStore((Store*)_local_data_store, _chronos_connection);
    _analytics = new AnalyticsLogger(&PrintingTestLogger::DEFAULT);
    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();
    pj_status_t ret = init_registrar(_store,
                                     _hss_connection,
                                     _analytics,
                                     _acr_factory,
                                     300,
                                     false,
                                     &SNMP::FAKE_REGISTRATION_STATS_TABLES,
                                     &SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES);
    ASSERT_EQ(PJ_SUCCESS, ret);

    _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "");
    _hss_connection->set_impu_result("tel:6505550231", "reg", HSSConnection::STATE_REGISTERED, "");
    _hss_connection->set_rc("/impu/sip%3A6505550231%40homedomain/reg-data", HTTP_OK);
    _chronos_connection->set_result("", HTTP_OK);
    _chronos_connection->set_result("post_identity", HTTP_OK);
  }

  static void TearDownTestCase()
  {
    destroy_registrar();
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics;
    delete _store; _store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
    SipTest::TearDownTestCase();
  }

  RegistrarTest() : SipTest(&mod_registrar)
  {
    _local_data_store->flush_all();  // start from a clean slate on each test
  }

  ~RegistrarTest()
  {
    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();

    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->reset_count(); 
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->reset_count(); 
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->reset_count(); 
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->reset_count(); 
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->reset_count(); 
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->reset_count(); 
    // Stop and restart the layer just in case
    //pjsip_tsx_layer_instance()->stop();
    //pjsip_tsx_layer_instance()->start();
  }

protected:
  static LocalStore* _local_data_store;
  static RegStore* _store;
  static AnalyticsLogger* _analytics;
  static IfcHandler* _ifc_handler;
  static ACRFactory* _acr_factory;
  static FakeHSSConnection* _hss_connection;
  static FakeChronosConnection* _chronos_connection;
};

LocalStore* RegistrarTest::_local_data_store;
RegStore* RegistrarTest::_store;
AnalyticsLogger* RegistrarTest::_analytics;
IfcHandler* RegistrarTest::_ifc_handler;
ACRFactory* RegistrarTest::_acr_factory;
FakeHSSConnection* RegistrarTest::_hss_connection;
FakeChronosConnection* RegistrarTest::_chronos_connection;

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
  string _auth;
  string _cseq;
  string _scheme;
  string _route;
  bool _gruu_support;

  Message() :
    _method("REGISTER"),
    _user("6505550231"),
    _domain("homedomain"),
    _contact("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob"),
    _contact_instance(";+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\""),
    _contact_params(";expires=3600;+sip.ice;reg-id=1"),
    _expires(""),
    _path("Path: <sip:GgAAAAAAAACYyAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-220.compute-1.amazonaws.com:5060;lr;ob>"),
    _auth(""),
    _cseq("16567"),
    _scheme("sip"),
    _route("homedomain"),
    _gruu_support(true)
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
                   "From: <%2$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "Supported: outbound, path%15$s\r\n"
                   "To: <%2$s>\r\n"
                   "Max-Forwards: 68\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqsUOO4ohntC@10.114.61.213\r\n"
                   "CSeq: %13$s %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "%11$s"
                   "Contact: %8$s%7$s%9$s\r\n"
                   "Route: <sip:%14$s;transport=tcp;lr>\r\n"
                   "P-Access-Network-Info: DUMMY\r\n"
                   "P-Visited-Network-ID: DUMMY\r\n"
                   "P-Charging-Vector: icid-value=100\r\n"
                   "%12$s"
                   "%4$s"
                   "Content-Length:  %5$d\r\n"
                   "\r\n"
                   "%6$s",
                   /*  1 */ _method.c_str(),
                   /*  2 */ (_scheme == "tel") ? string(_scheme).append(":").append(_user).c_str() : string(_scheme).append(":").append(_user).append("@").append(_domain).c_str(),
                   /*  3 */ _domain.c_str(),
                   /*  4 */ _content_type.empty() ? "" : string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                   /*  5 */ (int)_body.length(),
                   /*  6 */ _body.c_str(),
                   /*  7 */ _contact_params.c_str(),
                   /*  8 */ (_contact == "*") ? "*" : string("<").append(_contact).append(">").c_str(),
                   /*  9 */ _contact_instance.c_str(),
                   /* 10 */ _path.empty() ? "" : string(_path).append("\r\n").c_str(),
                   /* 11 */ _expires.empty() ? "" : string(_expires).append("\r\n").c_str(),
                   /* 12 */ _auth.empty() ? "" : string(_auth).append("\r\n").c_str(),
                   /* 13 */ _cseq.c_str(),
                   /* 14 */ _route.c_str(),
                   /* 15 */ _gruu_support ? ", gruu" : ""
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);

  TRC_DEBUG("REGISTER message\n%s", ret.c_str());
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

TEST_F(RegistrarTest, RouteHeaderNotMatching)
{
  Message msg;
  msg._domain = "notthehomedomain";
  pj_bool_t ret = inject_msg_direct(msg.get());
  EXPECT_EQ(PJ_FALSE, ret);
}

TEST_F(RegistrarTest, BadScheme)
{
  Message msg;
  msg._scheme = "sips";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(404, out->line.status.code);
  EXPECT_EQ("Not Found", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures); 
}

TEST_F(RegistrarTest, DeRegBadScheme)
{
  Message msg;
  msg._scheme = "sips";
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(404, out->line.status.code);
  EXPECT_EQ("Not Found", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures); 
}

///----------------------------------------------------------------------------
/// Check that a bare +sip.instance keyword doesn't break contact parsing
///----------------------------------------------------------------------------
TEST_F(RegistrarTest, BadGRUU)
{
  Message msg;
  msg._contact_instance = ";+sip.instance";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}

/// Simple correct example with Authorization header
TEST_F(RegistrarTest, SimpleMainlineAuthHeader)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}

/// Simple correct example with Authorization header and Tel URIs
TEST_F(RegistrarTest, SimpleMainlineAuthHeaderWithTelURI)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("tel:6505550231", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");
  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._scheme = "tel";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <tel:6505550231>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}

/// Simple correct example with Expires header - check that
/// appropriate headers are passed through
TEST_F(RegistrarTest, SimpleMainlinePassthrough)
{
  Message msg;
  msg._expires = "Expires: 300";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("P-Charging-Vector: icid-value=\"100\"", get_headers(out, "P-Charging-Vector"));
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=ccf1;ecf=ecf1;ecf=ecf2", get_headers(out, "P-Charging-Function-Addresses"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 

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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
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
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes); 
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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}

/// UE without support for GRUUs
TEST_F(RegistrarTest, GRUUNotSupported)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._gruu_support = false;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  // No pub-gruu as UE doesn't support GRUUs.
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
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
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // Second registration also OK.  Bindings are ordered by binding ID.
  Message msg0;
  msg = msg0;
  msg._contact = "sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob";
  msg._contact_instance = ";+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\"";
  msg._path = "Path: <sip:XxxxxxxXXXXXXAW4z38AABcUwStNKgAAa3WOL+1v72nFJg==@ec2-107-22-156-119.compute-1.amazonaws.com:5060;lr;ob>";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  // Expires timer for first contact may have ticked down, so give it some leeway.
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  // Creating a new binding for an existing URI is counted as a re-registration,
  // not an initial registration. 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();

  // Reregistration of first binding is OK but doesn't add a new one.
  msg = msg0;
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
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
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;reg-id=1"));

  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(3,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(3,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();

  // Reregistering that yields no change.
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;reg-id=1"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(4,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(4,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();

  // Reregistering again with an updated cseq triggers an update of the binding.
  msg._cseq = "16568";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:eeeebbbbaaaa11119c661a7acf228ed7@10.114.61.111:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-a55444444440>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-a55444444440\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]);\\+sip.ice;reg-id=1"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(5,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(5,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();

  // Registration of star but with a non zero expiry means the request is rejected with a 400.
  msg = msg0;
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(400, out->line.status.code);
  EXPECT_EQ("Bad Request", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures); 
  free_txdata();

  // Registration of star with expiry = 0 clears all bindings.
  msg = msg0;
  msg._expires = "Expires: 0";
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
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes); 
  
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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("", get_headers(out, "Require")); // because we have no path
  EXPECT_EQ("", get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}

// Generate a REGISTER flow to app servers from the iFC.
// First case - REGISTER is generated with a multipart body
TEST_F(RegistrarTest, AppServersWithMultipartBody)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
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
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
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
  inject_msg(respond_to_current_txdata(200));
  
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 

  free_txdata();
}

// Generate a REGISTER flow to app servers from the iFC.
// First case - REGISTER is generated with a multipart body
TEST_F(RegistrarTest, AppServersWithMultipartBodyWithTelURI)
{
  _hss_connection->set_impu_result("tel:6505550231", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>tel:6505550231</Identity></PublicIdentity>\n"
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
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._scheme = "tel";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <tel:6505550231>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
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
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  
  free_txdata();
}

/// Second case - REGISTER is generated with a non-multipart body
TEST_F(RegistrarTest, AppServersWithOneBody)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "      <Extension><IncludeRegisterRequest/></Extension>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
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
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  
  free_txdata();
}

/// Third case - REGISTER is generated with no body
TEST_F(RegistrarTest, AppServersWithNoBody)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  
  free_txdata();
}

/// Verify that third-party REGISTERs have appropriate headers passed through
TEST_F(RegistrarTest, AppServersPassthrough)
{
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));

  // Test the headers we expect to have passed through
  EXPECT_EQ("P-Charging-Vector: icid-value=\"100\"", get_headers(out, "P-Charging-Vector"));
  EXPECT_EQ("P-Charging-Function-Addresses: ccf=ccf1;ecf=ecf1;ecf=ecf2", get_headers(out, "P-Charging-Function-Addresses"));

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 

  free_txdata();
}


/// Check that the network-initiated deregistration code works as expected
TEST_F(RegistrarTest, DeregisterAppServersWithNoBody)
{
  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  std::string user = "sip:6505550231@homedomain";
  register_uri(_store, _hss_connection, "6505550231", "homedomain", "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213", 30);

  _hss_connection->set_impu_result("sip:6505550231@homedomain", "dereg-admin", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "        <Extension></Extension>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>1</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  RegStore::AoR* aor_data;
  aor_data = _store->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;

  RegistrationUtils::remove_bindings(_store,
                                     _hss_connection,
                                     user,
                                     "*",
                                     HSSConnection::DEREG_ADMIN,
                                     0);

  SCOPED_TRACE("deREGISTER");
  // Check that we send a REGISTER to the AS on network-initiated deregistration
  ASSERT_TRUE(current_txdata() != NULL);
  pjsip_msg* out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes); 
  
  free_txdata();
  // Check that we deleted the binding
  aor_data = _store->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;
}

TEST_F(RegistrarTest, AppServersInitialRegistration)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension><RegistrationType>0</RegistrationType></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

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
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (reregister)");
  Message msg2;
  msg2._expires = "Expires: 800";
  msg2._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (reregister, about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (reregister, injected)");
  ASSERT_EQ(1, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER not passed on to AS
  ASSERT_EQ(0, txdata_count());

  free_txdata();
}

TEST_F(RegistrarTest, AppServersInitialRegistrationFailure)
{
  std::string user = "sip:6505550231@homedomain";
  std::string xml =            ("<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:app-server:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>1</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, xml);
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "dereg-admin", HSSConnection::STATE_NOT_REGISTERED, xml);

  // We add two identical IP addresses so that we hit the retry behaviour, 
  // but we don't have to worry about which IP address is selected first. 
  add_host_mapping("app-server", "1.2.3.4, 1.2.3.4");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

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
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  RegStore::AoR* aor_data;
  aor_data = _store->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  // Respond with a 500 - this should trigger a deregistration since
  // DEFAULT_HANDLING is 1
  inject_msg(respond_to_current_txdata(500));

  tpAS.expect_target(current_txdata(), false);
  // Respond with a 500 - this should trigger a deregistration since
  // DEFAULT_HANDLING is 1
  inject_msg(respond_to_current_txdata(500));

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures); 
  
  // Check that we deleted the binding
  aor_data = _store->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  ASSERT_EQ(0u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;

  SCOPED_TRACE("deREGISTER");
  // Check that we send a deREGISTER to the AS on network-initiated deregistration
  out = current_txdata()->msg;
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes); 
  
  free_txdata();
}

TEST_F(RegistrarTest, AppServersDeRegistrationFailure)
{
  std::string user = "sip:6505550231@homedomain";
  std::string xml =            ("<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:app-server:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, xml);
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "dereg-admin", HSSConnection::STATE_NOT_REGISTERED, xml);

  // We add two identical IP addresses so that we hit the retry behaviour, 
  // but we don't have to worry about which IP address is selected first. 
  add_host_mapping("app-server", "1.2.3.4, 1.2.3.4");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);
  
  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes); 
  free_txdata();

  RegStore::AoR* aor_data;
  aor_data = _store->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);
  
  tpAS.expect_target(current_txdata(), false);
  // Respond with a 500 - this should trigger a deregistration since
  // DEFAULT_HANDLING is 1
  inject_msg(respond_to_current_txdata(500));
  
  tpAS.expect_target(current_txdata(), false);
  // Respond with a 500 - this should trigger a deregistration since
  // DEFAULT_HANDLING is 1
  inject_msg(respond_to_current_txdata(500));
  
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures); 

  // Check that we deleted the binding
  aor_data = _store->get_aor_data(user, 0);
  ASSERT_TRUE(aor_data != NULL);
  ASSERT_EQ(0u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;

  free_txdata();
}

TEST_F(RegistrarTest, AppServersReRegistrationFailure)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension><RegistrationType>1</RegistrationType></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>1</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(1, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER not passed on to AS
  ASSERT_EQ(0, txdata_count());

  SCOPED_TRACE("REGISTER (reregister)");
  Message msg2;
  msg2._expires = "Expires: 800";
  msg2._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (reregister, about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (reregister, injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(500));
  
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_failures); 

  free_txdata();
}

TEST_F(RegistrarTest, AppServersReRegistration)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                                "<IMSSubscription><ServiceProfile>\n"
                                "<PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>"
                                "  <InitialFilterCriteria>\n"
                                "    <Priority>1</Priority>\n"
                                "    <TriggerPoint>\n"
                                "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                                "    <SPT>\n"
                                "      <ConditionNegated>0</ConditionNegated>\n"
                                "      <Group>0</Group>\n"
                                "      <Method>REGISTER</Method>\n"
                                "      <Extension><RegistrationType>1</RegistrationType></Extension>\n"
                                "    </SPT>\n"
                                "  </TriggerPoint>\n"
                                "  <ApplicationServer>\n"
                                "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                                "    <DefaultHandling>0</DefaultHandling>\n"
                                "  </ApplicationServer>\n"
                                "  </InitialFilterCriteria>\n"
                                "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(1, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  ASSERT_EQ(0, txdata_count());

  SCOPED_TRACE("REGISTER (reregister)");
  Message msg2;
  msg2._expires = "Expires: 800";
  msg2._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (reregister, about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (reregister, injected)");
  ASSERT_EQ(2, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes);
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 

  free_txdata();
}


/// Homestead fails associated URI request
TEST_F(RegistrarTest, AssociatedUrisNotFound)
{
  Message msg;
  msg._user = "6505550232";
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(403, out->line.status.code);
  EXPECT_EQ("Forbidden", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures); 
}

/// Homestead fails associated URI request
TEST_F(RegistrarTest, DeRegAssociatedUrisNotFound)
{
  Message msg;
  msg._user = "6505550232";
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(403, out->line.status.code);
  EXPECT_EQ("Forbidden", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures); 
}

/// Homestead fails associated URI request
TEST_F(RegistrarTest, AssociatedUrisTimeOut)
{
  Message msg;
  msg._user = "6505550232";
  _hss_connection->set_rc("/impu/sip%3A6505550232%40homedomain/reg-data",
                          503);

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(504, out->line.status.code);
  EXPECT_EQ("Server Timeout", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_failures); 

  _hss_connection->delete_rc("/impu/sip%3A6505550232%40homedomain/reg-data");
}

/// Multiple P-Associated-URIs
TEST_F(RegistrarTest, MultipleAssociatedUris)
{
  Message msg;
  msg._user = "6505550233";

  _hss_connection->set_impu_result("sip:6505550233@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550233@homedomain</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>sip:6505550234@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);

  EXPECT_EQ("P-Associated-URI: <sip:6505550233@homedomain>\r\n"
            "P-Associated-URI: <sip:6505550234@homedomain>",
            get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}

/// Multiple P-Associated-URIs with Tel URIs
TEST_F(RegistrarTest, MultipleAssociatedUrisWithTelURI)
{
  Message msg;
  msg._user = "6505550233";
  msg._scheme = "tel";
  _hss_connection->set_impu_result("tel:6505550233", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>tel:6505550233</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>tel:6505550234</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);

  EXPECT_EQ("P-Associated-URI: <tel:6505550233>\r\n"
            "P-Associated-URI: <tel:6505550234>",
            get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}

/// Register with non-primary P-Associated-URI
TEST_F(RegistrarTest, NonPrimaryAssociatedUri)
{
  Message msg;
  msg._user = "6505550234";

  _hss_connection->set_impu_result("sip:6505550234@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550233@homedomain</Identity></PublicIdentity>\n"
                              "  <PublicIdentity><Identity>sip:6505550234@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("P-Associated-URI: <sip:6505550233@homedomain>\r\n"
            "P-Associated-URI: <sip:6505550234@homedomain>",
            get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // Check that we registered the correct URI (0233, not 0234).
  RegStore::AoR* aor_data = _store->get_aor_data("sip:6505550233@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;
  aor_data = _store->get_aor_data("sip:6505550234@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;
}

/// Test for issue 356
TEST_F(RegistrarTest, AppServersWithNoExtension)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>1</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>0</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <ConditionNegated>0</ConditionNegated>\n"
                              "        <Group>0</Group>\n"
                              "        <Method>REGISTER</Method>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  TransportFlow tpAS(TransportFlow::Protocol::UDP, stack_data.scscf_port, "1.2.3.4", 56789);

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
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  SCOPED_TRACE("REGISTER (forwarded)");
  // REGISTER passed on to AS
  out = current_txdata()->msg;
  ReqMatcher r1("REGISTER");
  ASSERT_NO_FATAL_FAILURE(r1.matches(out));
  EXPECT_EQ(NULL, out->body);

  tpAS.expect_target(current_txdata(), false);
  inject_msg(respond_to_current_txdata(200));
  
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_THIRD_PARTY_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 

  free_txdata();
}

/// Test for issue 358 - IFCs match on SDP but REGISTER doesn't have any - should be no match
TEST_F(RegistrarTest, AppServersWithSDPIFCs)
{
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED,
                              "<IMSSubscription><ServiceProfile>\n"
                              "  <PublicIdentity><Identity>sip:6505550231@homedomain</Identity></PublicIdentity>\n"
                              "  <InitialFilterCriteria>\n"
                              "    <Priority>2</Priority>\n"
                              "    <TriggerPoint>\n"
                              "      <ConditionTypeCNF>1</ConditionTypeCNF>\n"
                              "      <SPT>\n"
                              "        <Group>1</Group>\n"
                              "        <SessionDescription>\n"
                              "          <Line>m</Line>\n"
                              "          <Content>audio</Content>\n"
                              "        </SessionDescription>\n"
                              "      </SPT>\n"
                              "    </TriggerPoint>\n"
                              "    <ApplicationServer>\n"
                              "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                              "      <DefaultHandling>0</DefaultHandling>\n"
                              "    </ApplicationServer>\n"
                              "  </InitialFilterCriteria>\n"
                              "</ServiceProfile></IMSSubscription>");

  SCOPED_TRACE("REGISTER (1)");
  Message msg;
  msg._expires = "Expires: 800";
  msg._contact_params = ";+sip.ice;reg-id=1";
  SCOPED_TRACE("REGISTER (about to inject)");
  inject_msg(msg.get());
  SCOPED_TRACE("REGISTER (injected)");
  ASSERT_EQ(1, txdata_count());
  SCOPED_TRACE("REGISTER (200 OK)");
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}

/// Simple correct example with a subscription
TEST_F(RegistrarTest, RegistrationWithSubscription)
{
  // We have a private ID in this test, so set up the expect response to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  RegStore::AoR::Subscription* s1;
  int now = time(NULL);
  RegStore::AoR* aor_data1 = _store->get_aor_data(std::string("sip:6505550231@homedomain"), 0);

  // Add a subscription
  s1 = aor_data1->get_subscription("1234");
  s1->_req_uri = std::string("sip:6505550231@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:6505550231@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:6505550231@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("sip:abcdefgh@bono1.homedomain;lr"));
  s1->_expires = now + 300;

  // Set the NOTIFY CSeq value to 1.
  aor_data1->_notify_cseq = 1;

  // Write the record back to the store.
  pj_status_t rc = _store->set_aor_data(std::string("sip:6505550231@homedomain"), aor_data1, false, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // Register again with an updated cseq
  msg._cseq = "16568";
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();
}

/// Simple correct example with a subscription and Tel URIs
TEST_F(RegistrarTest, RegistrationWithSubscriptionWithTelURI)
{
  // We have a private ID in this test, so set up the expect response to the query.
  _hss_connection->set_impu_result("tel:6505550231", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  RegStore::AoR::Subscription* s1;
  int now = time(NULL);
  RegStore::AoR* aor_data1 = _store->get_aor_data(std::string("tel:6505550231"), 0);

  // Add a subscription
  s1 = aor_data1->get_subscription("1234");
  s1->_req_uri = std::string("sip:6505550231@192.91.191.29:59934;transport=tcp");
  s1->_from_uri = std::string("<sip:6505550231@cw-ngv.com>");
  s1->_from_tag = std::string("4321");
  s1->_to_uri = std::string("<sip:6505550231@cw-ngv.com>");
  s1->_to_tag = std::string("1234");
  s1->_cid = std::string("xyzabc@192.91.191.29");
  s1->_route_uris.push_back(std::string("sip:abcdefgh@bono1.homedomain;lr"));
  s1->_expires = now + 300;

  // Set the NOTIFY CSeq value to 1.
  aor_data1->_notify_cseq = 1;

  // Write the record back to the store.
  pj_status_t rc = _store->set_aor_data(std::string("tel:6505550231"), aor_data1, false, 0);
  EXPECT_TRUE(rc);
  delete aor_data1; aor_data1 = NULL;
  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  msg._scheme = "tel";
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  pjsip_msg* out = pop_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <tel:6505550231>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // Register again with an updated cseq
  msg._cseq = "16568";
  inject_msg(msg.get());
  ASSERT_EQ(2, txdata_count());
  out = pop_txdata()->msg;
  out = pop_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));  // that's a bit odd; we glom together the params
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <tel:6505550231>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();
}

// Test that an emergency registration is successful, and creates an emergency binding
TEST_F(RegistrarTest, MainlineEmergencyRegistration)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // There should be one binding, and it is an emergency registration. The emergency binding should have 'sos' prepended to its key.
  RegStore::AoR* aor_data = _store->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  EXPECT_TRUE(aor_data->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;
}

// Test that an emergency registration is successful, and creates an emergency binding, with Tel URIs
TEST_F(RegistrarTest, MainlineEmergencyRegistrationWithTelURI)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("tel:6505550231", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._scheme = "tel";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=300;+sip.ice;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <tel:6505550231>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // There should be one binding, and it is an emergency registration. The emergency binding should have 'sos' prepended to its key.
  RegStore::AoR* aor_data = _store->get_aor_data("tel:6505550231", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  EXPECT_TRUE(aor_data->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;
}

// Test that an emergency registration is successful, and creates an emergency binding.
// The Contact header doesn't include a +sip_instance, so the binding id is the contact URI containing 'sos'
TEST_F(RegistrarTest, MainlineEmergencyRegistrationNoSipInstance)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._contact_instance = "";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=300;+sip.ice;reg-id=1",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // There should be one binding, and it is an emergency registration
  RegStore::AoR* aor_data = _store->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  EXPECT_TRUE(aor_data->get_binding(std::string("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob"))->_emergency_registration);
  delete aor_data; aor_data = NULL;
}


// Test that an emergency registration can't be deregistered
TEST_F(RegistrarTest, EmergencyDeregistration)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a emergency registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // There should be one binding, and it is an emergency registration. The emergency binding should have 'sos' prepended to its key.
  RegStore::AoR* aor_data = _store->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  EXPECT_TRUE(aor_data->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Attempt to deregister a single emergency binding
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._cseq = "16568";
  msg._contact_params = ";expires=0;+sip.ice;reg-id=1";
  inject_msg(msg.get());

  // This should be rejected with a 501
  out = current_txdata()->msg;
  EXPECT_EQ(501, out->line.status.code);
  EXPECT_EQ("Not Implemented", str_pj(out->line.status.reason));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_failures); 
  free_txdata();

  // Attempt to reduce the expiry time of an emergency binding.
  msg._expires = "Expires: 100";
  msg._cseq = "16569";
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._contact_params = ";expires=100;+sip.ice;reg-id=1";
  inject_msg(msg.get());

  // Emergency binding isn't changed
  out = current_txdata()->msg;
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();
}


// Test multiple emergency and standard registrations.
TEST_F(RegistrarTest, MultipleEmergencyRegistrations)
{
  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  // Make a standard registration
  Message msg;
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  inject_msg(msg.get());

  // Check the 200 OK
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();

  // There should be one binding, and it isn't an emergency registration
  RegStore::AoR* aor_data = _store->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(1u, aor_data->_bindings.size());
  EXPECT_FALSE(aor_data->get_binding(std::string("<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Make an emergency registration
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  inject_msg(msg.get());

  // Check the 200 OK - the contact header should contain the sos URI parameter
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();

  // There should be two bindings. The emergency binding should have 'sos' prepended to its key.
  aor_data = _store->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(2u, aor_data->_bindings.size());
  EXPECT_TRUE(aor_data->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Make an emergency registration
  msg._contact = "sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob";
  msg._contact_instance = "";
  inject_msg(msg.get());

  // Check the 200 OK - the contact header should contain the sos URI parameter
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\"\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;reg-id=1\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_attempts); 
  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.re_reg_tbl)->_successes); 
  free_txdata();

  // There should be three bindings.
  aor_data = _store->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(3u, aor_data->_bindings.size());
  EXPECT_TRUE(aor_data->get_binding(std::string("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Attempt to deregister all bindings
  msg._expires = "Expires: 0";
  msg._contact = "*";
  msg._contact_instance = "";
  msg._contact_params = "";
  inject_msg(msg.get());

  // Check the 200 OK. The emergency bindings shouldn't have been deregistered, but the standard one has
  ASSERT_EQ(1, txdata_count());
  out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_THAT(get_headers(out, "Contact"),
              MatchesRegex("Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;reg-id=1\r\n"
                           "Contact: <sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob>;expires=(300|[1-2][0-9][0-9]|[1-9][0-9]);\\+sip.ice;\\+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-b665231f1213>\";reg-id=1;pub-gruu=\"sip:6505550231@homedomain;gr=urn:uuid:00000000-0000-0000-0000-b665231f1213\""));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.de_reg_tbl)->_successes); 
  free_txdata();

  // There should be two emergency bindings
  aor_data = _store->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(2u, aor_data->_bindings.size());
  EXPECT_TRUE(aor_data->get_binding(std::string("sos<urn:uuid:00000000-0000-0000-0000-b665231f1213>:1"))->_emergency_registration);
  EXPECT_TRUE(aor_data->get_binding(std::string("sip:f5cc3de4334589d89c661a7acf228ed7@10.114.61.213:5061;transport=tcp;sos;ob"))->_emergency_registration);
  delete aor_data; aor_data = NULL;

  // Wait 5 mins and the emergency bindings should have expired
  cwtest_advance_time_ms(300100);
  aor_data = _store->get_aor_data("sip:6505550231@homedomain", 0);
  ASSERT_TRUE(aor_data != NULL);
  EXPECT_EQ(0u, aor_data->_bindings.size());
  delete aor_data; aor_data = NULL;
}


/// Simple correct example with rinstance parameter in Contact URI
TEST_F(RegistrarTest, RinstanceParameter)
{
  Message msg;
  msg._contact = "sip:6505550138@172.18.42.27:46826;transport=tcp;rinstance=7690e89fc4105d1e";
  msg._contact_instance = "";
  msg._contact_params = ";Expires=390";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(200, out->line.status.code);
  EXPECT_EQ("OK", str_pj(out->line.status.reason));
  EXPECT_EQ("Supported: outbound", get_headers(out, "Supported"));
  EXPECT_EQ("Contact: <sip:6505550138@172.18.42.27:46826;transport=tcp;rinstance=7690e89fc4105d1e>;expires=300",
            get_headers(out, "Contact"));
  EXPECT_EQ("Require: outbound", get_headers(out, "Require")); // because we have path
  EXPECT_EQ(msg._path, get_headers(out, "Path"));
  EXPECT_EQ("P-Associated-URI: <sip:6505550231@homedomain>", get_headers(out, "P-Associated-URI"));
  EXPECT_EQ("Service-Route: <sip:all.the.sprout.nodes:5058;transport=TCP;lr;orig>", get_headers(out, "Service-Route"));
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_attempts); 
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_REGISTRATION_STATS_TABLES.init_reg_tbl)->_successes); 
  free_txdata();
}


/// Fixture for RegistrarTest.
class RegistrarTestMockStore : public SipTest
{
public:

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
    stack_data.scscf_uri = pj_str("sip:all.the.sprout.nodes:5058;transport=TCP");
  }

  void SetUp()
  {
    _chronos_connection = new FakeChronosConnection();
    _local_data_store = new MockStore();
    _store = new RegStore((Store*)_local_data_store, _chronos_connection);
    _analytics = new AnalyticsLogger(&PrintingTestLogger::DEFAULT);
    _hss_connection = new FakeHSSConnection();
    _acr_factory = new ACRFactory();
    pj_status_t ret = init_registrar(_store,
                                     _hss_connection,
                                     _analytics,
                                     _acr_factory,
                                     300,
                                     false,
                                     &SNMP::FAKE_REGISTRATION_STATS_TABLES,
                                     &SNMP::FAKE_REGISTRATION_STATS_TABLES);
    ASSERT_EQ(PJ_SUCCESS, ret);

    _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "");
    _hss_connection->set_impu_result("tel:6505550231", "reg", HSSConnection::STATE_REGISTERED, "");
    _hss_connection->set_rc("/impu/sip%3A6505550231%40homedomain/reg-data", HTTP_OK);
    _chronos_connection->set_result("", HTTP_OK);
    _chronos_connection->set_result("post_identity", HTTP_OK);
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }

  void TearDown()
  {
    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();

    destroy_registrar();
    delete _acr_factory; _acr_factory = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _analytics;
    delete _store; _store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _chronos_connection; _chronos_connection = NULL;
  }

  RegistrarTestMockStore() : SipTest(&mod_registrar)
  {
  }


protected:
  MockStore* _local_data_store;
  RegStore* _store;
  AnalyticsLogger* _analytics;
  IfcHandler* _ifc_handler;
  ACRFactory* _acr_factory;
  FakeHSSConnection* _hss_connection;
  FakeChronosConnection* _chronos_connection;
};


// Check that the registrar does not infinite loop when the underlying store is
// in an odd state, specifically when it:
// -  Returns NOT_FOUND to all gets
// -  Returns ERROR to all sets.
//
// This is a repro for https://github.com/Metaswitch/sprout/issues/977
TEST_F(RegistrarTestMockStore, RegStoreWritesFail)
{
  EXPECT_CALL(*_local_data_store, get_data(_, _, _, _, _))
    .WillOnce(Return(Store::NOT_FOUND));

  EXPECT_CALL(*_local_data_store, set_data(_, _, _, _, _, _))
    .WillOnce(Return(Store::ERROR));

  // We have a private ID in this test, so set up the expect response
  // to the query.
  _hss_connection->set_impu_result("sip:6505550231@homedomain", "reg", HSSConnection::STATE_REGISTERED, "", "?private_id=Alice");

  Message msg;
  msg._expires = "Expires: 300";
  msg._auth = "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"";
  msg._contact_params = ";+sip.ice;reg-id=1";
  inject_msg(msg.get());
  ASSERT_EQ(1, txdata_count());
  pjsip_msg* out = current_txdata()->msg;
  EXPECT_EQ(500, out->line.status.code);
  free_txdata();
}
