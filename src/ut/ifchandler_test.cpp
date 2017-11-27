/**
 * @file ifchandler_test.cpp UT for Sprout IfcHandler module
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include "gtest/gtest.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>

#include "stack.h"
#include "utils.h"
#include "siptest.hpp"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"

#include "ifchandler.h"
#include "registration_utils.h"

using namespace std;

/// Fixture for IfcHandlerTest
class IfcHandlerTest : public SipTest
{
public:
  static FakeChronosConnection* _chronos_connection;
  static FakeHSSConnection* _hss_connection;
  static AstaireAoRStore* _local_aor_store;
  static LocalStore* _local_data_store;
  static SubscriberDataManager* _sdm;
  static IfcHandler* _ifc_handler;
  pjsip_msg* TEST_MSG;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    _chronos_connection = new FakeChronosConnection();
    _hss_connection = new FakeHSSConnection();
    _local_data_store = new LocalStore();
    _local_aor_store = new AstaireAoRStore(_local_data_store);
    _sdm = new SubscriberDataManager((AoRStore*)_local_aor_store, _chronos_connection, NULL, true);
    _ifc_handler = new IfcHandler();
  }

  static void TearDownTestCase()
  {
    delete _sdm; _sdm = NULL;
    delete _local_aor_store; _local_aor_store = NULL;
    delete _local_data_store; _local_data_store = NULL;
    delete _ifc_handler; _ifc_handler = NULL;
    delete _hss_connection; _hss_connection = NULL;
    delete _chronos_connection; _chronos_connection = NULL;

    SipTest::TearDownTestCase();
  }

  IfcHandlerTest() : SipTest(NULL)
  {
    _local_data_store->flush_all();  // start from a clean slate on each test
    if (_hss_connection)
    {
      _hss_connection->flush_all();
    }

    string str("INVITE sip:5755550033@homedomain:3443 SIP/2.0\n"
               "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
               "Max-Forwards: 69\n"
               "From: <sip:5755550033@homedomain>;tag=13919SIPpTag0011234\n"
               "To: <sip:5755550033@homedomain>\n"
               "Contact: <sip:5755550018@10.16.62.109:58309;transport=TCP;ob>\n"
               "Call-ID: 1-13919@10.151.20.48\n"
               "CSeq: 4 INVITE\n"
               "Route: <sip:127.0.0.1;transport=TCP;lr;orig>\n"
               "Call-Info    : foo,\n"
               "               bar\n"
               "Accept: baz\n"
               "Accept: quux, foo\n"
               "Content-Type: application/sdp\n"
               "Content-Length: 242\n\n"
               "o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\n"
               "s=SDP Seminar\n"
               "b=X-YZ:128\n"
               "a=recvonly\n"
               "c=IN IP4 224.2.17.12\n"
               "t=2873397496 2873404696\n"
               "m=audio 49170/5 RTP/AVP 0\n"
               "m=video 51372 RTP/AVP 99\n"
               "b=Z-YZ:126\n"
               "c=IN IP4 225.2.17.14\n"
               "einvalidline\n"
               "a=rtpmap:99 h263-1998/90000\n");
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
                  bool third_party_reg,
                  bool initial_registration=false);
  void doTest(string description,
              string frag,
              bool reg,
              const SessionCase& sescase,
              bool expected);
  void doCaseTest(string description, string frag, bool test[]);
  void doRegTest(string description,
                 string frag,
                 bool reg,
                 pjsip_msg* msg,
                 bool expected,
                 bool initial_registration=false);
};

FakeChronosConnection* IfcHandlerTest::_chronos_connection;
FakeHSSConnection* IfcHandlerTest::_hss_connection;
LocalStore* IfcHandlerTest::_local_data_store;
AstaireAoRStore* IfcHandlerTest::_local_aor_store;
SubscriberDataManager* IfcHandlerTest::_sdm;
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
              "Route: <sip:127.0.0.1;transport=TCP;lr;orig>\n"
              "Content-Length: 0\n$2\n");
  string str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@homedomain"), "$2", "");
  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);

  EXPECT_EQ("sip:5755550018@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata->msg_info.msg, rdata->tp_info.pool));
  EXPECT_EQ("sip:5755550018@homedomain", IfcHandler::served_user_from_msg(SessionCase::OriginatingCdiv, rdata->msg_info.msg, rdata->tp_info.pool));
  EXPECT_EQ("sip:5755550099@homedomain", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata->msg_info.msg, rdata->tp_info.pool));

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@127.0.0.1"), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("sip:5755550099@127.0.0.1", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata->msg_info.msg, rdata->tp_info.pool));

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@remotenode"), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata->msg_info.msg, rdata->tp_info.pool));

  // Should obey P-Served-User URI and ignore other fields (and also ignore sescase and regstate on P-S-U), but only on originating sessions.
  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@127.0.0.1"),
                                "$2", "P-Served-User: \"Billy Bob\" <sip:billy-bob@homedomain>\n");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("sip:billy-bob@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata->msg_info.msg, rdata->tp_info.pool));
  EXPECT_EQ("sip:5755550099@127.0.0.1", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata->msg_info.msg, rdata->tp_info.pool));

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@127.0.0.1"),
                                "$2", "P-Served-User: sip:billy-bob@homedomain;sescase=term;regstate=reg\n");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("sip:billy-bob@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata->msg_info.msg, rdata->tp_info.pool));
  EXPECT_EQ("sip:5755550099@127.0.0.1", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata->msg_info.msg, rdata->tp_info.pool));


  // If no P-Served-User, try P-Asserted-Identity.
  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "sip:5755550099@127.0.0.1"),
                                "$2", "P-Asserted-Identity: \"Billy Bob\" <sip:billy-bob@homedomain>\n");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("sip:billy-bob@homedomain", IfcHandler::served_user_from_msg(SessionCase::Originating, rdata->msg_info.msg, rdata->tp_info.pool));
  EXPECT_EQ("sip:5755550099@127.0.0.1", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata->msg_info.msg, rdata->tp_info.pool));

  // TEL uri in INVITE
  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", "tel:5755550099"), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  EXPECT_EQ("tel:5755550099", IfcHandler::served_user_from_msg(SessionCase::Terminating, rdata->msg_info.msg, rdata->tp_info.pool));
}

/// Test an iFC.
void IfcHandlerTest::doBaseTest(string description,
                                string ifc,
                                pjsip_msg* msg,
                                string served_user,
                                bool reg,
                                const SessionCase& sescase,
                                bool expected,
                                bool third_party_reg,
                                bool initial_registration)
{
  SCOPED_TRACE(description);
  std::vector<AsInvocation> application_servers;
  _local_data_store->flush_all();  // start from a clean slate on each test
  std::shared_ptr<rapidxml::xml_document<> > root (new rapidxml::xml_document<>);
  char* cstr_ifc = strdup(ifc.c_str());
  root->parse<0>(cstr_ifc);
  Ifcs* ifcs = new Ifcs(root, root->first_node("ServiceProfile"), NULL, 0);
  bool found_match;
  RegistrationUtils::interpret_ifcs(*ifcs,
                                    {},
                                    IFCConfiguration(false,false,"",NULL,NULL),
                                    sescase,
                                    reg,
                                    initial_registration,
                                    msg,
                                    application_servers,
                                    found_match,
                                    0);
  delete ifcs;
  free(cstr_ifc);
  EXPECT_EQ(expected ? 1u : 0u, application_servers.size());
  if (application_servers.size())
  {
    EXPECT_EQ("sip:1.2.3.4:56789;transport=UDP", application_servers[0].server_name);
    EXPECT_EQ(0, application_servers[0].default_handling);
    if (third_party_reg)
    {
      // Verify that no XML entities are translated within a CDATA block
      EXPECT_EQ("&lt;banana&amp;gt;", application_servers[0].service_info);
      EXPECT_TRUE(application_servers[0].include_register_request);
      EXPECT_FALSE(application_servers[0].include_register_response);
    }
    else
    {
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
  CapturingTestLogger log;
  doBaseTest("",
             "",
             TEST_MSG,
             "sip:5755550033@homedomain",
             true,
             SessionCase::Originating,
             false,
             false);
  EXPECT_TRUE(log.contains("No ServiceProfile node in iFC!"));
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
             true,
             false);
}

TEST_F(IfcHandlerTest, GarbagePriority)
{
  CapturingTestLogger log;
  doBaseTest("",
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ServiceProfile>\n"
             "  <InitialFilterCriteria>\n"
             "    <Priority>Mu</Priority>\n"
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
  EXPECT_TRUE(log.contains("Can't parse iFC priority as integer"));
}

TEST_F(IfcHandlerTest, NoAS)
{
  CapturingTestLogger log;
  doBaseTest("",
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ServiceProfile>\n"
             "  <InitialFilterCriteria>\n"
             "    <Priority>1</Priority>\n"
             "    <XapplicationServer>\n"
             "      <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
             "      <DefaultHandling>0</DefaultHandling>\n"
             "    </XapplicationServer>\n"
             "  </InitialFilterCriteria>\n"
             "</ServiceProfile>",
             TEST_MSG,
             "sip:5755550033@homedomain",
             true,
             SessionCase::Originating,
             false,
             false);
  EXPECT_TRUE(log.contains("missing ApplicationServer element"));
}

TEST_F(IfcHandlerTest, NoServerName1)
{
  CapturingTestLogger log;
  doBaseTest("",
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ServiceProfile>\n"
             "  <InitialFilterCriteria>\n"
             "    <Priority>1</Priority>\n"
             "    <ApplicationServer>\n"
             "      <ServerName></ServerName>\n"
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
  EXPECT_TRUE(log.contains("has no ServerName"));
}

TEST_F(IfcHandlerTest, NoServerName2)
{
  CapturingTestLogger log;
  doBaseTest("",
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ServiceProfile>\n"
             "  <InitialFilterCriteria>\n"
             "    <Priority>1</Priority>\n"
             "    <ApplicationServer>\n"
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
  EXPECT_TRUE(log.contains("has no ServerName"));
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
             "      <ServiceInfo>\n"
             "        <![CDATA[&lt;banana&amp;gt;]]></ServiceInfo>\n"
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
  CapturingTestLogger log(5);
  doTest("",
         "",
         true,
         SessionCase::Originating,
         true);
  EXPECT_TRUE(log.contains("has no trigger point"));
}

TEST_F(IfcHandlerTest, NoSPT)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>0</ConditionTypeCNF>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, NoSPTNeg)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, NoClass1)
{
  CapturingTestLogger log;
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
  EXPECT_TRUE(log.contains("Missing class"));
}

TEST_F(IfcHandlerTest, NoClass2)
{
  CapturingTestLogger log;
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
  EXPECT_TRUE(log.contains("Missing class"));
}

TEST_F(IfcHandlerTest, NoType)
{
  CapturingTestLogger log;
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
  EXPECT_TRUE(log.contains("Missing mandatory value for ConditionTypeCNF"));
}

TEST_F(IfcHandlerTest, UnusualRequestURI)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <RequestURI>sip:homedomain:3443</RequestURI>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("Continue processing unusual iFC"));
}

TEST_F(IfcHandlerTest, Unimplemented)
{
  CapturingTestLogger log;
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
  EXPECT_TRUE(log.contains("Unimplemented"));
  EXPECT_TRUE(log.contains("SuperDuperNewThingy"));
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
             "      <SessionCase>0</SessionCase>\n"
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
             "      <SessionCase>1</SessionCase>\n"
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
             "      <SessionCase>2</SessionCase>\n"
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
             "      <SessionCase>3</SessionCase>\n"
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
             "      <SessionCase>4</SessionCase>\n"
             "      <Extension></Extension>\n"
             "    </SPT>\n"
             "  </TriggerPoint>\n",
             results);
}

TEST_F(IfcHandlerTest, SesCaseGarbage)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionCase>ORIGINATING_REGISTERED</SessionCase>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("Can't parse session case"));
}

TEST_F(IfcHandlerTest, SesCaseRange1)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionCase>-1</SessionCase>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("session case out of allowable range"));
}

TEST_F(IfcHandlerTest, SesCaseRange2)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionCase>5</SessionCase>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("session case out of allowable range"));
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
         "      <SessionCase>0</SessionCase>\n"
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
         "      <SessionCase>0</SessionCase>\n"
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
         "      <SessionCase>0</SessionCase>\n"
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
         "      <SessionCase>0</SessionCase>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, HeaderMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Contact</Header></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, HeaderMatchCaseInsensitive)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>contact</Header></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, NegatedHeaderMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Contact</Header></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, HeaderMismatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Contaaaaaact</Header></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, NegatedHeaderMismatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>1</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Contaaaaaact</Header></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, RegexContentMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Contact</Header><Content>.*5755550018.*</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, ContentMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Call-ID</Header><Content>1-13919@10.151.20.48</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, ContentMismatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Contact</Header><Content>.*111111.*</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, HeaderMismatchContentMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Contaaaaact</Header><Content>.*5755550018.*</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, TerminatingHeaderMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Contact</Header><Content>&lt;sip:5755550018@10.16.62.109:58309;transport=TCP;ob&gt;</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         true);
}

TEST_F(IfcHandlerTest, CDataHeaderMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header><![CDATA[Contact]]></Header><Content><![CDATA[<sip:5755550018@10.16.62.109:58309;transport=TCP;ob]]></Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         true);
}


TEST_F(IfcHandlerTest, CommaContentMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Call-Info</Header><Content>foo, bar</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         true);
}


TEST_F(IfcHandlerTest, MultilineHeaderContentMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Accept</Header><Content>baz</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         true);

  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Accept</Header><Content>quux</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         true);
}

TEST_F(IfcHandlerTest, HeaderContentSubstring)
{
  doTest("Test that requiring the substring 'qu' succeeds",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Accept</Header><Content>qu</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         true);

  doTest("Test that requiring the word 'qu' fails",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Accept</Header><Content>\\bqu\\b</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         false);

  doTest("Test that requiring the word 'quux' succeeds",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Accept</Header><Content>\\bquux\\b</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         true);
}


TEST_F(IfcHandlerTest, MultilineHeaderContentMismatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Accept</Header><Content>null</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         false);
}

TEST_F(IfcHandlerTest, SIPHeaderExtensionIgnored)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>Accept</Header><Extension>words</Extension></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         true);
}

TEST_F(IfcHandlerTest, SIPHeaderNoHeader)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Extension>words</Extension></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         false);
  EXPECT_TRUE(log.contains("Missing Header element for SIPHeader service point trigger"));
}

TEST_F(IfcHandlerTest, SIPHeaderBadRegex)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>*</Header></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         false);

  EXPECT_TRUE(log.contains("Invalid regular expression in Header element for SIPHeader service point trigger"));

  CapturingTestLogger log2;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SIPHeader><Header>.*</Header><Content>?</Content></SIPHeader>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Terminating,
         false);
  EXPECT_TRUE(log2.contains("Invalid regular expression in Content element for SIPHeader service point trigger"));
}

TEST_F(IfcHandlerTest, ReqURIMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <RequestURI>homedomain:3443</RequestURI>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, ReqURIMatchUrnURI)
{
  string str0("MESSAGE urn:service:sos SIP/2.0\n"
              "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
              "Max-Forwards: 69\n"
              "From: <sip:5755550033@homedomain>;tag=13919SIPpTag0011234\n"
              "To: <urn:service:sos>\n"
              "Call-ID: 1-13919@10.151.20.48\n"
              "CSeq: 4 MESSAGE\n"
              "Route: <sip:127.0.0.1;transport=TCP;lr;orig>\n"
              "Content-Type: application/sdp\n"
              "Content-Length: 0\n\n");

  string str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ""), "$2", "");
  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);
  pjsip_msg* msg = rdata->msg_info.msg;

  doBaseTest("",
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ServiceProfile>\n"
             "  <InitialFilterCriteria>\n"
             "    <Priority>1</Priority>\n"
             "  <TriggerPoint>\n"
             "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
             "    <SPT>\n"
             "      <ConditionNegated>0</ConditionNegated>\n"
             "      <Group>0</Group>\n"
             "      <RequestURI>service:sos</RequestURI>\n"
             "      <Extension></Extension>\n"
             "    </SPT>\n"
             "  </TriggerPoint>\n"
             "  <ApplicationServer>\n"
             "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
             "    <DefaultHandling>0</DefaultHandling>\n"
             "  </ApplicationServer>\n"
             "  </InitialFilterCriteria>\n"
             "</ServiceProfile>",
             msg,
             "sip:5755550033@homedomain",
             true,
             SessionCase::Originating,
             true,
             false);
}

TEST_F(IfcHandlerTest, ReqURIMatchTelURI)
{
  string str0("INVITE tel:5755550033 SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 69\n"
             "From: <sip:5755550033@homedomain>;tag=13919SIPpTag0011234\n"
             "To: <tel:5755550033>\n"
             "Contact: <sip:5755550018@10.16.62.109:58309;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 4 INVITE\n"
             "Route: <sip:127.0.0.1;transport=TCP;lr;orig>\n"
             "Call-Info    : foo,\n"
             "               bar\n"
             "Accept: baz\n"
             "Accept: quux, foo\n"
             "Content-Type: application/sdp\n"
             "Content-Length: 242\n\n"
             "o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\n"
             "s=SDP Seminar\n"
             "b=X-YZ:128\n"
             "a=recvonly\n"
             "c=IN IP4 224.2.17.12\n"
             "t=2873397496 2873404696\n"
             "m=audio 49170/5 RTP/AVP 0\n"
             "m=video 51372 RTP/AVP 99\n"
             "b=Z-YZ:126\n"
             "c=IN IP4 225.2.17.14\n"
             "einvalidline\n"
             "a=rtpmap:99 h263-1998/90000\n");

  string str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ""), "$2", "");
  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);
  pjsip_msg* msg = rdata->msg_info.msg;

  doBaseTest("",
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ServiceProfile>\n"
             "  <InitialFilterCriteria>\n"
             "    <Priority>1</Priority>\n"
             "  <TriggerPoint>\n"
             "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
             "    <SPT>\n"
             "      <ConditionNegated>0</ConditionNegated>\n"
             "      <Group>0</Group>\n"
             "      <RequestURI>5755550033</RequestURI>\n"
             "      <Extension></Extension>\n"
             "    </SPT>\n"
             "  </TriggerPoint>\n"
             "  <ApplicationServer>\n"
             "    <ServerName>sip:1.2.3.4:56789;transport=UDP</ServerName>\n"
             "    <DefaultHandling>0</DefaultHandling>\n"
             "  </ApplicationServer>\n"
             "  </InitialFilterCriteria>\n"
             "</ServiceProfile>",
             msg,
             "sip:5755550033@homedomain",
             true,
             SessionCase::Originating,
             true,
             false);
}

TEST_F(IfcHandlerTest, ReqURINoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <RequestURI>hoomedomain</RequestURI>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, ReqURIBadRegex)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <RequestURI>*</RequestURI>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("Invalid regular expression in Request URI service point trigger"));
}

TEST_F(IfcHandlerTest, RegTypeMethodNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <Method>REGISTER</Method>\n"
         "      <Extension>\n"
         "        <RegistrationType>0</RegistrationType>\n"
         "      </Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

void IfcHandlerTest::doRegTest(string description,
                               string frag,
                               bool reg,
                               pjsip_msg* msg,
                               bool expected,
                               bool initial_registration)
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
             msg,
             "sip:5755550033@homedomain",
             reg,
             SessionCase::Originating,
             expected,
             false,
             initial_registration);
}

TEST_F(IfcHandlerTest, RegTypes)
{
  string str0("REGISTER sip:5755550033@homedomain SIP/2.0\n"
              "Via: SIP/2.0/TCP 10.64.90.97:50693;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
              "Max-Forwards: 69\n"
              "From: <sip:5755550033@homedomain>;tag=13919SIPpTag0011234\n"
              "To: <sip:5755550033@homedomain>\n"
              "Contact: <sip:5755550018@10.16.62.109:58309;transport=TCP;ob>$1\n"
              "Call-ID: 1-13919@10.151.20.48\n"
              "CSeq: 4 REGISTER$2\n"
              "Content-Length: 0\n\n");

  string str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ""), "$2", "");
  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);
  pjsip_msg* msg = rdata->msg_info.msg;

  doRegTest("Match initial register",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>0</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            true,
            true);

  doRegTest("Match reregister",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>1</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            true,
            false);

  doRegTest("Match on second specified RegistrationType",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>1</RegistrationType>\n"
            "        <RegistrationType>0</RegistrationType>\n"
            "        <RegistrationType>1</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            true,
            true);

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ";expires=0"), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  msg = rdata->msg_info.msg;

  doRegTest("Match unregister with expiry time in contact header",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>2</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            true);

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ""), "$2", "\nExpires: 0");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  msg = rdata->msg_info.msg;

  doRegTest("Match unregister with expiry header",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>2</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            true);

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ""), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  msg = rdata->msg_info.msg;

  doRegTest("Illegal registration type",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>3</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false);

  doRegTest("No match for initial register when already registered",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>0</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false,
            false);

  doRegTest("No match for reregister on initial registration",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>1</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false,
            true);

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ";expires=0"), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  msg = rdata->msg_info.msg;

  doRegTest("No match for initial register with expires in contact header set to 0",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>0</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            false,
            msg,
            false,
            true);

  doRegTest("No match for reregister with expires in contact header set to 0",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>1</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false,
            false);

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ""), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  msg = rdata->msg_info.msg;

  doRegTest("No match for unregister with no expires information",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>2</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false);

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ";expires=3600"), "$2", "");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  msg = rdata->msg_info.msg;

  doRegTest("No match for unregister with expires in contact header non 0",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>2</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false);

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ""), "$2", "\nExpires: 3600");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  msg = rdata->msg_info.msg;

  doRegTest("No match for unregister with expires header non 0",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>2</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false);

  str = boost::replace_all_copy(boost::replace_all_copy(str0, "$1", ""), "$2", "\nExpires: 0");
  rdata = build_rxdata(str);
  parse_rxdata(rdata);
  msg = rdata->msg_info.msg;

  doRegTest("No match for initial register with expires header set to 0",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>0</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false,
            true);

  doRegTest("No match for reregister with expires header set to 0",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>1</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false,
            false);

  doRegTest("No match for register or reregister with expires header set to 0",
            "    <TriggerPoint>\n"
            "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
            "    <SPT>\n"
            "      <ConditionNegated>0</ConditionNegated>\n"
            "      <Group>0</Group>\n"
            "      <Method>REGISTER</Method>\n"
            "      <Extension>\n"
            "        <RegistrationType>0</RegistrationType>\n"
            "        <RegistrationType>1</RegistrationType>\n"
            "      </Extension>\n"
            "    </SPT>\n"
            "  </TriggerPoint>\n",
            true,
            msg,
            false,
            false);
}

TEST_F(IfcHandlerTest, SDPOriginMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>o</Line><Content>jdoe 2890844526 2890842807 IN IP4 10.47.16.5</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPConnMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>c</Line><Content>IN IP4 224.2.17.12</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPTimerMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>t</Line><Content>2873397496 2873404696</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPBandwMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>b</Line><Content>X-YZ:128</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPSubjectMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>s</Line><Content>SDP Seminar</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPAttrMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>a</Line><Content>recvonly</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPMediaMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>m</Line><Content>audio 49170/5 RTP/AVP 0</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPMediaAttrMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>a</Line><Content>rtpmap:99 h263-1998/90000</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPMediaConnMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>c</Line><Content>IN IP4 225.2.17.14</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPMediaBandwMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>b</Line><Content>Z-YZ:126</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPNoLine)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Content>Z-YZ:126</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("Missing Line element for SessionDescription service point trigger"));
}

TEST_F(IfcHandlerTest, SDPBadLineRegex)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>*</Line><Content>Z-YZ:126</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("Invalid regular expression in Line element for Session Description service point trigger"));
}

TEST_F(IfcHandlerTest, SDPBadContentRegex)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>a</Line><Content>*</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("Invalid regular expression in Content element for Session Description service point trigger"));
}

TEST_F(IfcHandlerTest, SDPNoContentMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>a</Line></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         true);
}

TEST_F(IfcHandlerTest, SDPLineNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>v</Line><Content>content</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SDPAttrContentNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>a</Line><Content>nomatch</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SDPConnContentNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>c</Line><Content>nomatch</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SDPBandwContentNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>b</Line><Content>nomatch</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SDPTimerContentNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>t</Line><Content>nomatch</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SDPSubjectContentNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>s</Line><Content>nomatch</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SDPMediaNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>m</Line><Content>nomatch</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SDPOriginContentNoMatch)
{
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>o</Line><Content>nomatch</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
}

TEST_F(IfcHandlerTest, SDPNoEqualsSign)
{
  CapturingTestLogger log;
  doTest("",
         "    <TriggerPoint>\n"
         "    <ConditionTypeCNF>1</ConditionTypeCNF>\n"
         "    <SPT>\n"
         "      <ConditionNegated>0</ConditionNegated>\n"
         "      <Group>0</Group>\n"
         "      <SessionDescription><Line>e</Line><Content>invalidline</Content></SessionDescription>\n"
         "      <Extension></Extension>\n"
         "    </SPT>\n"
         "  </TriggerPoint>\n",
         true,
         SessionCase::Originating,
         false);
  EXPECT_TRUE(log.contains("Found badly formatted SDP line: einvalidline"));
}


// @@@ iFC XML parse error
// @@@ lookup_ifcs gets no served user
// @@@ lookup_ifcs finds empty iFCs
// ++@@@ served_user_from_msg: URI is not home domain, but is local; URI is not home domain or local
