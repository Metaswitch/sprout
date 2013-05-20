/**
 * @file aschain_test.cpp UT for Sprout IfcHandler module
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
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>

#include "stack.h"
#include "utils.h"
#include "siptest.hpp"
#include "fakehssconnection.hpp"
#include "localstorefactory.h"
#include "fakelogger.hpp"

#include "ifchandler.h"

using namespace std;

/// Fixture for IfcHandlerTest
class IfcHandlerTest : public SipTest
{
public:
  FakeLogger _log;
  static FakeHSSConnection* _hss_connection;
  static RegData::Store* _store;
  static IfcHandler* _ifc_handler;
  pjsip_msg* TEST_MSG;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    _hss_connection = new FakeHSSConnection();
    _store = RegData::create_local_store();
    _ifc_handler = new IfcHandler(_hss_connection, _store);
  }

  static void TearDownTestCase()
  {
    RegData::destroy_local_store(_store);
    delete _ifc_handler; _ifc_handler = NULL;
    delete _hss_connection; _hss_connection = NULL;

    SipTest::TearDownTestCase();
  }

  IfcHandlerTest() : SipTest(NULL)
  {
    _store->flush_all();  // start from a clean slate on each test
    if (_hss_connection)
    {
      _hss_connection->flush_all();
    }

    string str("INVITE sip:5755550033@homedomain SIP/2.0\n"
               "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
               "Max-Forwards: 69\n"
               "From: <sip:5755550033@homedomain>;tag=13919SIPpTag0011234\n"
               "To: <sip:5755550033@homedomain>\n"
               "Contact: <sip:5755550018@10.16.62.109:58309;transport=TCP;ob>\n"
               "Call-ID: 1-13919@10.151.20.48\n"
               "CSeq: 4 INVITE\n"
               "Route: <sip:testnode;transport=TCP;lr;orig>\n"
               "Content-Length: 0\n\n");
    pjsip_rx_data* rdata = build_rxdata(str);
    parse_rxdata(rdata);
    TEST_MSG = rdata->msg_info.msg;
  }

  ~IfcHandlerTest()
  {
  }

  void doBaseTest(string description,
                  string ifc,
                  pjsip_msg* msg,
                  string served_user,
                  bool reg,
                  const SessionCase& sescase,
                  bool expected,
                  bool third_party_reg);
  void doTest(string description,
              string frag,
              bool reg,
              const SessionCase& sescase,
              bool expected);
  void doCaseTest(string description, string frag, bool test[]);
};

FakeHSSConnection* IfcHandlerTest::_hss_connection;
RegData::Store* IfcHandlerTest::_store;
IfcHandler* IfcHandlerTest::_ifc_handler;

TEST_F(IfcHandlerTest, ServedUser)
{
  string str0("INVITE $1 SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 69\n"
             "From: <sip:5755550018@homedomain>;tag=13919SIPpTag0011234\n"
             "To: <sip:5755550099@homedomain>\n"
             "Contact: <sip:5755550018@10.16.62.109:58309;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 4 INVITE\n"
             "Route: <sip:testnode;transport=TCP;lr;orig>\n"
             "Content-Length: 0\n$2\n");
  string str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@homedomain"), "$2", "");
  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);

  EXPECT_EQ("sip:5755550018@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata));
  EXPECT_EQ("sip:5755550018@homedomain", IfcHandler::served_user_from_msg(SessionCase::OriginatingCdiv, rdata));
  EXPECT_EQ("sip:5755550099@homedomain", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata));

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@testnode"), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("sip:5755550099@testnode", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata));

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@remotenode"), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata));

  // Should obey P-Served-User URI and ignore other fields (and also ignore sescase and regstate on P-S-U), but only on originating sessions.
  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@testnode"),
                                "$2", "P-Served-User: Billy Bob <sip:billy-bob@homedomain>;sescase=term;regstate=unreg\n");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("sip:billy-bob@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata));
  EXPECT_EQ("sip:5755550099@testnode", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata));

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@testnode"),
                                "$2", "P-Served-User: sip:billy-bob@homedomain;sescase=term;regstate=reg\n");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("sip:billy-bob@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata));
  EXPECT_EQ("sip:5755550099@testnode", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata));

  // Should ignore (with warning) if URI is unparseable.
  FakeLogger log;
  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@testnode"),
                                "$2", "P-Served-User: <sip:billy-bob@homedomain;sescase=term;regstate=reg\n");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("sip:5755550018@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata));
  EXPECT_TRUE(log.contains("Unable to parse P-Served-User header"));
}

/// Test an iFC.
void IfcHandlerTest::doBaseTest(string description,
                                string ifc,
                                pjsip_msg* msg,
                                string served_user,
                                bool reg,
                                const SessionCase& sescase,
                                bool expected,
                                bool third_party_reg)
{
  SCOPED_TRACE(description);
  if (ifc != "")
  {
    _hss_connection->set_user_ifc("sip:5755550033@homedomain",
                                  ifc);
  }
  std::vector<AsInvocation> application_servers;
  _store->flush_all();  // start from a clean slate on each test
  _ifc_handler->lookup_ifcs(sescase,
                            served_user,
                            reg,
                            msg,
                            0,
                            application_servers);
  EXPECT_EQ(expected ? 1u : 0u, application_servers.size());
  if (application_servers.size())
  {
    EXPECT_EQ("sip:1.2.3.4:56789;transport=UDP", application_servers[0].server_name);
    EXPECT_EQ(0, application_servers[0].default_handling);
    if (third_party_reg)
    {
      EXPECT_EQ("banana", application_servers[0].service_info);
      EXPECT_TRUE(application_servers[0].include_register_request);
      EXPECT_FALSE(application_servers[0].include_register_response);
    } else {
      EXPECT_EQ("", application_servers[0].service_info);
      EXPECT_FALSE(application_servers[0].include_register_request);
      EXPECT_FALSE(application_servers[0].include_register_response);
    }
  }
}

TEST_F(IfcHandlerTest, ProfilePart)
{
  for (int profilepart = 0; profilepart <= 1; profilepart++)
  {
    SCOPED_TRACE(profilepart);
    for (int reg = 0; reg <= 1; reg++)
    {
      bool is_reg = !!reg;
      SCOPED_TRACE(is_reg);

      doBaseTest("",
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                 "<ServiceProfile>\n"
                 "  <InitialFilterCriteria>\n"
                 "    <Priority>1</Priority>\n"
                 "    <ApplicationServer>\n"
                 "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                 "      <DefaultHandling>0</DefaultHandling>\n"
                 "    </ApplicationServer>\n"
                 "    <ProfilePartIndicator>" + boost::lexical_cast<std::string>(profilepart) + "</ProfilePartIndicator>\n"
                 "  </InitialFilterCriteria>\n"
                 "</ServiceProfile>",
                 TEST_MSG,
                 "sip:5755550033@homedomain",
                 is_reg,
                 SessionCase::Originating,
                 (profilepart == 0) ? is_reg : !is_reg,
                 false);
    }
  }
}

TEST_F(IfcHandlerTest, NoIfc)
{
  doBaseTest("",
             "",
             TEST_MSG,
             "sip:5755550033@homedomain",
             true,
             SessionCase::Originating,
             false,
             false);
  EXPECT_TRUE(_log.contains("No iFC found"));
}

TEST_F(IfcHandlerTest, NoPriority)
{
  doBaseTest("",
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ServiceProfile>\n"
             "  <InitialFilterCriteria>\n"
             "    <ApplicationServer>\n"
             "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
             "      <DefaultHandling>0</DefaultHandling>\n"
             "    </ApplicationServer>\n"
             "  </InitialFilterCriteria>\n"
             "</ServiceProfile>",
             TEST_MSG,
             "sip:5755550033@homedomain",
             true,
             SessionCase::Originating,
             false,
             false);
  EXPECT_TRUE(_log.contains("Missing mandatory value for iFC priority"));
}

TEST_F(IfcHandlerTest, ThirdPartyRegistration)
{
      doBaseTest("",
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                 "<ServiceProfile>\n"
                 "  <InitialFilterCriteria>\n"
                 "    <Priority>1</Priority>\n"
                 "    <ApplicationServer>\n"
                 "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
                 "      <DefaultHandling>0</DefaultHandling>\n"
                 "      <ServiceInfo>banana</ServiceInfo>\n"
                 "      <Extension>\n"
                 "        <IncludeRegisterRequest />\n"
                 "      </Extension>\n"
                 "    </ApplicationServer>\n"
                 "  </InitialFilterCriteria>\n"
                 "</ServiceProfile>",
                 TEST_MSG,
                 "sip:5755550033@homedomain",
                 true,
                 SessionCase::Originating,
                 true,
                 true);
}


/// Test an individual TriggerPoint.
void IfcHandlerTest::doTest(string description,
                            string frag,
                            bool reg,
                            const SessionCase& sescase,
                            bool expected)
{
  doBaseTest(description,
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ServiceProfile>\n"
             "  <InitialFilterCriteria>\n"
             "    <Priority>1</Priority>\n"
             + frag +
             "  <ApplicationServer>\n"
             "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
             "    <DefaultHandling>0</DefaultHandling>\n"
             "  </ApplicationServer>\n"
             "  </InitialFilterCriteria>\n"
             "</ServiceProfile>",
             TEST_MSG,
             "sip:5755550033@homedomain",
             reg,
             sescase,
             expected,
             false);
}

TEST_F(IfcHandlerTest, MethodMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, NoTrigger)
{
  Log::setLoggingLevel(5);
  doTest("",
         "",
         true,
         SessionCase::Originating,
         true);
  EXPECT_TRUE(_log.contains("has no trigger point"));
}

TEST_F(IfcHandlerTest, ParseError)
{
  doTest("",
         "<shrdlu ",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(_log.contains("iFCs parse error"));
}

TEST_F(IfcHandlerTest, NoClass1)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(_log.contains("Missing class"));
}

TEST_F(IfcHandlerTest, NoClass2)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(_log.contains("Missing class"));
}

TEST_F(IfcHandlerTest, NoType)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(_log.contains("Missing mandatory value for ConditionTypeCNF"));
}

TEST_F(IfcHandlerTest, Unimplemented)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SuperDuperNewThingy>ehwot</SuperDuperNewThingy>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(_log.contains("Unimplemented"));
  EXPECT_TRUE(_log.contains("SuperDuperNewThingy"));
}

TEST_F(IfcHandlerTest, MethodCase)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <Method>invite</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, MethodNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <Method>MESSAGE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

/// Test an individual TriggerPoint under all session case conditions.
void IfcHandlerTest::doCaseTest(string description,
                                string frag, //< TriggerPoint element
                                bool test[]) //< Should it trigger? orig/term/origcdiv * unreg/reg
{
  for (int i = 0; i < 6; i++)
  {
    SCOPED_TRACE(i);
    bool reg = i % 2;
    const SessionCase& sescase = ((i/2) == 0) ? SessionCase::Originating :
                                 ((i/2) == 1) ? SessionCase::Terminating :
                                               SessionCase::OriginatingCdiv;
    string desc = description;
    desc.append(reg ? " reg " : " unreg ");
    desc.append(sescase.to_string());
    doTest(desc, frag, reg, sescase, test[i]);
  }
}

TEST_F(IfcHandlerTest, SesCase0)
{
  bool results[] = {false, true, false, false, false, false};
  doCaseTest("",
             "    <TriggerPoint>\n"
             "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
             "    <SPT>\n"
             "      <ConditionNegated>0</ConditionNegated>\n"
             "      <Group>0</Group>\n"
             "      <SessionCase>0</Method>\n"
             "      <Extension></Extension>\n"
             "    </SPT>\n"
             "  </TriggerPoint>\n",
             results);
}

TEST_F(IfcHandlerTest, SesCase1)
{
  bool results[] = {false, false, false, true, false, false};
  doCaseTest("",
             "    <TriggerPoint>\n"
             "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
             "    <SPT>\n"
             "      <ConditionNegated>0</ConditionNegated>\n"
             "      <Group>0</Group>\n"
             "      <SessionCase>1</Method>\n"
             "      <Extension></Extension>\n"
             "    </SPT>\n"
             "  </TriggerPoint>\n",
             results);
}

TEST_F(IfcHandlerTest, SesCase2)
{
  bool results[] = {false, false, true, false, false, false};
  doCaseTest("",
             "    <TriggerPoint>\n"
             "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
             "    <SPT>\n"
             "      <ConditionNegated>0</ConditionNegated>\n"
             "      <Group>0</Group>\n"
             "      <SessionCase>2</Method>\n"
             "      <Extension></Extension>\n"
             "    </SPT>\n"
             "  </TriggerPoint>\n",
             results);
}

TEST_F(IfcHandlerTest, SesCase3)
{
  bool results[] = {true, false, false, false, false, false};
  doCaseTest("",
             "    <TriggerPoint>\n"
             "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
             "    <SPT>\n"
             "      <ConditionNegated>0</ConditionNegated>\n"
             "      <Group>0</Group>\n"
             "      <SessionCase>3</Method>\n"
             "      <Extension></Extension>\n"
             "    </SPT>\n"
             "  </TriggerPoint>\n",
             results);
}

TEST_F(IfcHandlerTest, SesCase4)
{
  bool results[] = {false, false, false, false, true, true};
  doCaseTest("",
             "    <TriggerPoint>\n"
             "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
             "    <SPT>\n"
             "      <ConditionNegated>0</ConditionNegated>\n"
             "      <Group>0</Group>\n"
             "      <SessionCase>4</Method>\n"
             "      <Extension></Extension>\n"
             "    </SPT>\n"
             "  </TriggerPoint>\n",
             results);
}

TEST_F(IfcHandlerTest, SesCaseGarbage)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionCase>ORIGINATING_REGISTERED</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(_log.contains("Can't parse session case"));
}

TEST_F(IfcHandlerTest, SesCaseRange1)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionCase>-1</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(_log.contains("session case out of allowable range"));
}

TEST_F(IfcHandlerTest, SesCaseRange2)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionCase>5</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(_log.contains("session case out of allowable range"));
}

TEST_F(IfcHandlerTest, Negation)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, And1)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>99</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SubOr1)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, And2)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>99</Group>\n"
         "      <SessionCase>0</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, AndSubOr1)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>99</Group>\n"
         "      <SessionCase>0</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, Or1)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>99</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SubAnd1)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, MultipleOccurrences)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>4</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Group>4</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, Or2)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>99</Group>\n"
         "      <SessionCase>0</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, OrSubAnd1)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>3</Group>\n"
         "      <Method>INVITE</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>99</Group>\n"
         "      <SessionCase>0</Method>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}


// @@@ iFC XML parse error
// @@@ lookup_ifcs gets no served user
// @@@ lookup_ifcs finds empty iFCs
// ++@@@ served_user_from_msg: URI is not home domain, but is local; URI is not home domain or local
