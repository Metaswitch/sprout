/**
 * @file authentication_test.cpp UT for Sprout authentication module.
 *
 * Copyright (C) Metaswitch Networks 2017
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
#include <sstream>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "siptest.hpp"
#include "utils.h"
#include "stack.h"
#include "analyticslogger.h"
#include "localstore.h"
#include "astaire_impistore.h"
#include "sproutletproxy.h"
#include "hssconnection.h"
#include "authenticationsproutlet.h"
#include "fakehssconnection.hpp"
#include "fakechronosconnection.hpp"
#include "mock_chronos_connection.h"
#include "test_interposer.hpp"
#include "md5.h"
#include "fakesnmp.hpp"
#include "mock_sas.h"

using namespace std;
using namespace std;
using testing::StrEq;
using testing::ElementsAre;
using testing::MatchesRegex;
using testing::HasSubstr;
using testing::Not;

/// Common fixture for all authentication tests.
class BaseAuthenticationTest : public SipTest
{
public:
  int ICSCF_PORT = 5052;

  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();

    _local_data_store = new LocalStore();
    _impi_store = new AstaireImpiStore(_local_data_store);
    _remote_data_stores.push_back(new LocalStore());
    _remote_impi_stores.push_back(new AstaireImpiStore(_remote_data_stores[0]));
    _hss_connection = new FakeHSSConnection();
    _analytics = new AnalyticsLogger();
    _acr_factory = new ACRFactory();
  }

  static void TearDownTestCase()
  {
    delete _acr_factory;
    delete _hss_connection;
    delete _analytics;
    delete _impi_store;
    delete _local_data_store;

    for (ImpiStore* store: _remote_impi_stores) { delete store; }
    _remote_impi_stores.clear();

    for (LocalStore* store: _remote_data_stores) { delete store; }
    _remote_data_stores.clear();

    SipTest::TearDownTestCase();
  }

  // Hook to allow subclasses to set up the auth sproutlet how they want.
  virtual AuthenticationSproutlet* create_auth_sproutlet() = 0;

  void SetUp()
  {
    _log_traffic = PrintingTestLogger::DEFAULT.isPrinting(); // true to see all traffic

    _current_cseq = 1;

    _auth_sproutlet = create_auth_sproutlet();

    std::list<Sproutlet*> sproutlets;
    sproutlets.push_back(_auth_sproutlet);
    std::unordered_set<std::string> additional_home_domains;
    additional_home_domains.insert("sprout-site2.homedomain");

    _sproutlet_proxy = new SproutletProxy(stack_data.endpt,
                                          PJSIP_MOD_PRIORITY_UA_PROXY_LAYER,
                                          "sprout.homedomain",
                                          additional_home_domains,
                                          sproutlets,
                                          std::set<std::string>());

    _tp = new TransportFlow(TransportFlow::Protocol::TCP,
                            stack_data.scscf_port,
                            "0.0.0.0",
                            5060);

    mock_sas_collect_messages(true);
  }

  void TearDown()
  {
    mock_sas_collect_messages(false);

    pjsip_tsx_layer_dump(true);

    // Terminate all transactions
    list<pjsip_transaction*> tsxs = get_all_tsxs();
    for (list<pjsip_transaction*>::iterator it2 = tsxs.begin();
         it2 != tsxs.end();
         ++it2)
    {
      pjsip_tsx_terminate(*it2, PJSIP_SC_SERVICE_UNAVAILABLE);
    }

    // PJSIP transactions aren't actually destroyed until a zero ms
    // timer fires (presumably to ensure destruction doesn't hold up
    // real work), so poll for that to happen. Otherwise we leak!
    // Allow a good length of time to pass too, in case we have
    // transactions still open. 32s is the default UAS INVITE
    // transaction timeout, so we go higher than that.
    cwtest_advance_time_ms(33000L);
    poll();
    // Stop and restart the transaction layer just in case
    pjsip_tsx_layer_instance()->stop();
    pjsip_tsx_layer_instance()->start();

    delete _auth_sproutlet; _auth_sproutlet = NULL;
    delete _sproutlet_proxy; _sproutlet_proxy = NULL;
    delete _tp; _tp = NULL;

    // Clear out transactions
    cwtest_advance_time_ms(33000L);
    poll();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->reset_count();
    ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.non_register_auth_tbl)->reset_count();

    // Make sure the fake connections have their results cleaned out.
    _hss_connection->flush_all();

    // All the AKA tests use the same challenge so flush the data store after
    // each test to avoid tests interacting.
    _local_data_store->flush_all();
  }

  /// Check that we logged a GENERIC_CORRELATOR to SAS.
  void check_sas_correlator(std::string value, bool present=true)
  {
    bool found_value = false;
    std::vector<MockSASMessage*> markers = mock_sas_find_marker_multiple(MARKED_ID_GENERIC_CORRELATOR);
    for (MockSASMessage* marker : markers)
    {
      EXPECT_EQ(marker->var_params.size(), 1u);
      if (marker->var_params[0] == value)
      {
        found_value = true;
        break;
      }
    }
    EXPECT_EQ(found_value, present);
  }

  // Chech that the AV for an IMPI in the ImpiStore has a particular stored
  // correlator.
  void check_impi_store_correlator(std::string impi_id, std::string nonce, std::string expected_correlator)
  {
    ImpiStore::Impi* impi = _impi_store->get_impi(impi_id, 0L);
    ImpiStore::AuthChallenge* challenge = impi->get_auth_challenge(nonce);
    EXPECT_NE(challenge, nullptr);
    std::string correlator = challenge->get_correlator();
    EXPECT_EQ(correlator, expected_correlator);
    delete impi;
  }

  /// Parses a WWW-Authenticate header to the list of parameters.
  void parse_www_authenticate(const std::string& www_auth_hdr,
                              std::map<std::string, std::string>& params)
  {
    std::string hdr = www_auth_hdr;
    ASSERT_THAT(hdr, MatchesRegex("(Proxy|WWW)-Authenticate *: *Digest *.*"));
    hdr = hdr.substr(hdr.find_first_of(':') + 1);
    hdr = hdr.substr(hdr.find("Digest") + 6);

    // Should now be at the start of the parameter list (barring white-space).
    while (!hdr.empty())
    {
      std::string p;
      size_t i = hdr.find_first_of(',');
      if (i != string::npos)
      {
        p = hdr.substr(0, i);
        hdr = hdr.substr(i+1);
      }
      else
      {
        p = hdr;
        hdr = "";
      }

      i = p.find_first_of('=');
      if (i != string::npos)
      {
        std::string pname = p.substr(0,i);
        std::string pvalue = p.substr(i+1);
        Utils::trim(pname);
        Utils::trim(pvalue);
        if ((pvalue[0] == '"') && (pvalue[pvalue.length()-1] == '"'))
        {
          // Remove quotes around parameter.
          pvalue = pvalue.substr(1, pvalue.length()-2);
        }
        params[pname] = pvalue;
      }
      else
      {
        std::string pname = p;
        Utils::trim(pname);
        params[pname] = "";
      }
    }
  }

  void auth_sproutlet_allows_request(bool expect_100_trying = false,
                                     bool free_200_ok = true)
  {
    if (expect_100_trying)
    {
      ASSERT_EQ(2, txdata_count());
      RespMatcher(100).matches(current_txdata()->msg);
      free_txdata();
    }

    ASSERT_EQ(1, txdata_count());
    EXPECT_EQ(current_txdata()->msg->type, PJSIP_REQUEST_MSG);

    // Respond to the request. If it's a REGISTER add a Service-Route.
    bool is_register = (current_txdata()->msg->line.req.method.id == PJSIP_REGISTER_METHOD);
    std::string rsp = respond_to_current_txdata(200);
    if (is_register)
    {
      rsp.replace(rsp.find("\r\n\r\n"), 4,
                  ("\r\nService-Route: <sip:scscf.sprout.example.com;orig>\r\n\r\n"));
    }
    inject_msg(rsp);

    ASSERT_EQ(1, txdata_count());
    RespMatcher(200).matches(current_txdata()->msg);

    if (free_200_ok)
    {
      free_txdata();
    }
  }

  void TestAKAAuthSuccess(char* key);

protected:
  static LocalStore* _local_data_store;
  static ImpiStore* _impi_store;
  static ACRFactory* _acr_factory;
  static FakeHSSConnection* _hss_connection;
  static AnalyticsLogger* _analytics;
  static int _current_cseq;
  static std::vector<LocalStore*> _remote_data_stores;
  static std::vector<ImpiStore*> _remote_impi_stores;

  AuthenticationSproutlet* _auth_sproutlet;
  SproutletProxy* _sproutlet_proxy;
  TransportFlow* _tp;
};

LocalStore* BaseAuthenticationTest::_local_data_store;
ImpiStore* BaseAuthenticationTest::_impi_store;
ACRFactory* BaseAuthenticationTest::_acr_factory;
FakeHSSConnection* BaseAuthenticationTest::_hss_connection;
AnalyticsLogger* BaseAuthenticationTest::_analytics;
int BaseAuthenticationTest::_current_cseq;
std::vector<LocalStore*> BaseAuthenticationTest::_remote_data_stores;
std::vector<ImpiStore*> BaseAuthenticationTest::_remote_impi_stores;

/// A test fixture that is templated over a configuration class. This allows the
/// authentication sproutlet to be set up in different ways without lots of
/// boilerplate code.
template<class C, class ChronosHelper>
class AuthenticationTestTemplate : public BaseAuthenticationTest
{
  static void SetUpTestCase()
  {
    ChronosHelper::create_chronos_connection();
    BaseAuthenticationTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    BaseAuthenticationTest::TearDownTestCase();
    ChronosHelper::destroy_chronos_connection();
  }

  AuthenticationSproutlet* create_auth_sproutlet()
  {
    AuthenticationSproutlet* auth_sproutlet =
      new AuthenticationSproutlet("authentication",
                                  stack_data.scscf_port,
                                  "sip:authentication.homedomain",
                                  { "scscf" },
                                  "scscf",
                                  "registrar",
                                  "homedomain",
                                  _impi_store,
                                  _remote_impi_stores,
                                  _hss_connection,
                                  ChronosHelper::get_chronos_connection(),
                                  _acr_factory,
                                  C::non_reg_auth(),
                                  _analytics,
                                  &SNMP::FAKE_AUTHENTICATION_STATS_TABLES,
                                  C::nonce_count_supported(),
                                  300);
    EXPECT_TRUE(auth_sproutlet->init());
    return auth_sproutlet;
  }
};

class FakeChronosConnectionHelper
{
  static void create_chronos_connection()
  {
    _chronos_connection = new FakeChronosConnection();
    // Set up the basic expected results
    _chronos_connection->set_result("", HTTP_OK);
    _chronos_connection->set_result("post_identity", HTTP_OK);
  }

  static ChronosConnection* get_chronos_connection()
  {
    return _chronos_connection;
  }

  static void destroy_chronos_connection()
  {
    _chronos_connection->flush_all();
    delete _chronos_connection;
  }

protected:
  static FakeChronosConnection* _chronos_connection;
};

/// Test fixture for the timer tests. This is the same as the Authenticaiton
/// tests, but we want to use a MockChronosConnection, not a FakeChronosConnection
class MockChronosConnectionHelper
{
  static void create_chronos_connection()
  {
    _mock_chronos_connection = new MockChronosConnection("localhost");
  }

  static MockChronosConnection* get_chronos_connection()
  {
    return _mock_chronos_connection;
  }

  static void destroy_chronos_connection()
  {
    delete _mock_chronos_connection;
  }

protected:
  static MockChronosConnection* _mock_chronos_connection;
};

FakeChronosConnection* FakeChronosConnectionHelper::_chronos_connection;
MockChronosConnection* MockChronosConnectionHelper::_mock_chronos_connection;

/// Templated configuration class for use with the above fixture.
template<uint32_t A, bool N>
class AuthenticationTestConfig
{
  static uint32_t non_reg_auth() { return A; }
  static uint32_t nonce_count_supported() { return N; }
};

class AuthenticationMessage
{
public:
  string _method;
  string _user;
  string _domain;
  int _cseq;
  bool _auth_hdr;
  bool _proxy_auth_hdr;
  string _auth_user;
  string _auth_realm;
  string _nonce;
  string _nc;
  string _cnonce;
  string _qop;
  string _uri;
  string _response;
  string _algorithm;
  string _opaque;
  string _integ_prot;
  string _auts;
  string _key;
  bool _sos;
  string _extra_contact;
  string _to_tag;
  bool _force_aka;
  string _route_uri;

  AuthenticationMessage(std::string method) :
    _method(method),
    _user("6505550001"),
    _domain("homedomain"),
    _cseq(0),
    _auth_hdr(true),
    _proxy_auth_hdr(false),
    _auth_user("6505550001@homedomain"),
    _auth_realm("homedomain"),
    _nonce(""),
    _nc(""),
    _cnonce(""),
    _uri("sip:homedomain"),
    _response(""),
    _algorithm("MD5"),
    _opaque(""),
    _integ_prot(""),
    _auts(""),
    _key(""),
    _sos(false),
    _extra_contact(""),
    _to_tag(""),
    _force_aka(false),
    _route_uri("sip:authentication.sprout.homedomain:5058;transport=TCP;orig")
  {
  }

  static std::string hash2str(md5_byte_t* hash);

  string get();

  static string calculate_digest_response(
      const string& algorithm, bool force_aka,
      const string& auth_user, const string& key,
      const string& method, const string& uri,
      const string& nonce, const string& nc,
      const string& cnonce, const string& qop,
      const string& auth_realm);

};


std::string AuthenticationMessage::hash2str(md5_byte_t* hash)
{
  std::stringstream ss;
  for (int i = 0; i < 16; ++i)
  {
    ss << std::hex << std::setfill('0') << std::setw(2) << (unsigned short)hash[i];
  }
  return ss.str();
}

string AuthenticationMessage::calculate_digest_response(
    const string& algorithm, const bool force_aka,
    const string& auth_user, const string& key,
    const string& method, const string& uri,
    const string& nonce, const string& nc,
    const string& cnonce, const string& qop,
    const string& auth_realm)
{
  md5_state_t md5;
  md5_byte_t resp[16];

  std::string ha1;
  if (algorithm == "AKAv1-MD5" || force_aka)
  {
    // Key is a plain text password, so convert to HA1
    md5_init(&md5);
    md5_append(&md5, (md5_byte_t*)auth_user.data(), auth_user.length());
    md5_append(&md5, (md5_byte_t*)":", 1);
    md5_append(&md5, (md5_byte_t*)auth_realm.data(), auth_realm.length());
    md5_append(&md5, (md5_byte_t*)":", 1);
    for (size_t ii = 0; ii < key.length(); ii += 2)
    {
      md5_byte_t byte = pj_hex_digit_to_val(key[ii]) * 16 +
                        pj_hex_digit_to_val(key[ii+1]);
      md5_append(&md5, &byte, 1);
    }
    md5_finish(&md5, resp);
    ha1 = hash2str(resp);
  }
  else
  {
    // Key is already HA1.
    ha1 = key;
  }

  // Calculate HA2
  md5_init(&md5);
  md5_append(&md5, (md5_byte_t*)method.data(), method.length());
  md5_append(&md5, (md5_byte_t*)":", 1);
  md5_append(&md5, (md5_byte_t*)uri.data(), uri.length());
  md5_finish(&md5, resp);
  std::string ha2 = hash2str(resp);

  // Calculate the response.
  md5_init(&md5);
  md5_append(&md5, (md5_byte_t*)ha1.data(), ha1.length());
  md5_append(&md5, (md5_byte_t*)":", 1);
  md5_append(&md5, (md5_byte_t*)nonce.data(), nonce.length());
  md5_append(&md5, (md5_byte_t*)":", 1);
  md5_append(&md5, (md5_byte_t*)nc.data(), nc.length());
  md5_append(&md5, (md5_byte_t*)":", 1);
  md5_append(&md5, (md5_byte_t*)cnonce.data(), cnonce.length());
  md5_append(&md5, (md5_byte_t*)":", 1);
  md5_append(&md5, (md5_byte_t*)qop.data(), qop.length());
  md5_append(&md5, (md5_byte_t*)":", 1);
  md5_append(&md5, (md5_byte_t*)ha2.data(), ha2.length());
  md5_finish(&md5, resp);
  return hash2str(resp);
}

string AuthenticationMessage::get()
{
  char buf[16384];

  if ((_response.empty()) &&
      (!_key.empty()))
  {
    // No response provided, but a key is provided, so calculate the response.
    _response = calculate_digest_response(
        _algorithm, _force_aka,
        _auth_user, _key,
        _method, _uri,
        _nonce, _nc,
        _cnonce, _qop,
        _auth_realm);
  }

  if (_cseq == 0)
  {
    _cseq = BaseAuthenticationTest::_current_cseq;

    // Increment the shared counter, allowing room for manual increments.
    BaseAuthenticationTest::_current_cseq += 10;
  }

  int n = snprintf(buf, sizeof(buf),
                   "%1$s sip:%3$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP 10.83.18.38:36530;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY5e9kSPI+cseq%8$d\r\n"
                   "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n"
                   "Max-Forwards: 68\r\n"
                   "Supported: outbound, path\r\n"
                   "To: <sip:%2$s@%3$s>%9$s\r\n"
                   "From: <sip:%2$s@%3$s>;tag=fc614d9c\r\n"
                   "Call-ID: OWZiOGFkZDQ4MGI1OTljNjlkZDkwNTdlMTE0NmUyOTY.\r\n"
                   "CSeq: %8$d %1$s\r\n"
                   "Expires: 300\r\n"
                   "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n"
                   "User-Agent: X-Lite release 5.0.0 stamp 67284\r\n"
                   "Contact: <sip:%2$s@uac.example.com:5060;rinstance=f0b20987985b61df;transport=TCP%4$s>\r\n"
                   "%5$s"
                   "Route: <%10$s>\r\n"
                   "%6$s"
                   "%7$s"
                   "Content-Length: 0\r\n"
                   "\r\n",
                   /*  1 */ _method.c_str(),
                   /*  2 */ _user.c_str(),
                   /*  3 */ _domain.c_str(),
                   /*  4 */ (_sos) ? ";sos" : "",
                   /*  5 */ _extra_contact.empty() ? "" : _extra_contact.append("\r\n").c_str(),
                   /*  6 */ _auth_hdr ?
                              string("Authorization: Digest ")
                                .append((!_auth_user.empty()) ? string("username=\"").append(_auth_user).append("\"") : "")
                                .append((!_auth_realm.empty()) ? string(", realm=\"").append(_auth_realm).append("\"") : "")
                                .append((!_nonce.empty()) ? string(", nonce=\"").append(_nonce).append("\"") : "")
                                .append((!_uri.empty()) ? string(", uri=\"").append(_uri).append("\"") : "")
                                .append((!_response.empty()) ? string(", response=\"").append(_response).append("\"") : "")
                                .append((!_opaque.empty()) ? string(", opaque=\"").append(_opaque).append("\"") : "")
                                .append((!_nc.empty()) ? string(", nc=").append(_nc).append("") : "")
                                .append((!_cnonce.empty()) ? string(", cnonce=\"").append(_cnonce).append("\"") : "")
                                .append((!_qop.empty()) ? string(", qop=").append(_qop).append("") : "")
                                .append((!_auts.empty()) ? string(", auts=\"").append(_auts).append("\"") : "")
                                .append((!_integ_prot.empty()) ? string(", integrity-protected=\"").append(_integ_prot).append("\"") : "")
                                .append((!_algorithm.empty()) ? string(", algorithm=").append(_algorithm) : "")
                                .append("\r\n").c_str() :
                                "",
                    /*  7 */ _proxy_auth_hdr ?
                              string("Proxy-Authorization: Digest ")
                                .append((!_auth_user.empty()) ? string("username=\"").append(_auth_user).append("\", ") : "")
                                .append((!_auth_realm.empty()) ? string("realm=\"").append(_auth_realm).append("\", ") : "")
                                .append((!_nonce.empty()) ? string("nonce=\"").append(_nonce).append("\", ") : "")
                                .append((!_uri.empty()) ? string("uri=\"").append(_uri).append("\", ") : "")
                                .append((!_response.empty()) ? string("response=\"").append(_response).append("\", ") : "")
                                .append((!_opaque.empty()) ? string("opaque=\"").append(_opaque).append("\", ") : "")
                                .append((!_nc.empty()) ? string("nc=").append(_nc).append(", ") : "")
                                .append((!_cnonce.empty()) ? string("cnonce=\"").append(_cnonce).append("\", ") : "")
                                .append((!_qop.empty()) ? string("qop=").append(_qop).append(", ") : "")
                                .append((!_auts.empty()) ? string("auts=\"").append(_auts).append("\", ") : "")
                                .append((!_integ_prot.empty()) ? string("integrity-protected=\"").append(_integ_prot).append("\", ") : "")
                                .append((!_algorithm.empty()) ? string("algorithm=").append(_algorithm) : "")
                                .append("\r\n").c_str() :
                              "",
                    /* 8 */ _cseq,
                    /* 9 */ _to_tag.c_str(),
                    /* 10 */ _route_uri.c_str()
    );

  EXPECT_LT(n, (int)sizeof(buf));

  string ret(buf, n);
  return ret;
}


//
// Authentication tests that use the default configuration settings for the
// authentication sproutlet.
//

/// Test fixture for these tests. This is just a typedef of the test template +
/// a particular configuration.
typedef AuthenticationTestTemplate<
  AuthenticationTestConfig<NonRegisterAuthentication::NEVER, true>,
  FakeChronosConnectionHelper
> AuthenticationTest;


TEST_F(AuthenticationTest, NoAuthorizationNonReg)
{
  // Test that the authentication module lets through non-REGISTER requests
  // with no authorization header.
  AuthenticationMessage msg("PUBLISH");
  msg._auth_hdr = false;
  inject_msg(msg.get());
  auth_sproutlet_allows_request();
}

// This test results in a routing loop because the authentication sproutlet
// tries to route the registrar (by adding a service parameter). The registrar
// doesn't exist in this test, so we match on the user part again an enter a
// routing loop.
TEST_F(AuthenticationTest, DISABLED_NoAuthorizationNonRegUserPart)
{
  // Test that the the authentication sproutlet can call forward a request when
  // the original route contains a user part. See issue 1696.
  AuthenticationMessage msg("PUBLISH");
  msg._auth_hdr = false;
  msg._route_uri = "sip:authentication@sprout.homedomain:5058;transport=TCP";
  inject_msg(msg.get());
  auth_sproutlet_allows_request();
}


TEST_F(AuthenticationTest, NoAuthorizationNonRegWithPxyAuthHdr)
{
  // Test that the authentication module lets through non-REGISTER requests
  // with no authorization header.
  AuthenticationMessage msg("PUBLISH");
  msg._auth_hdr = false;
  msg._proxy_auth_hdr = true;
  inject_msg(msg.get());
  auth_sproutlet_allows_request();
}

TEST_F(AuthenticationTest, NoAuthorizationInDialog)
{
  // Test that the authentication module lets through non-REGISTER requests
  // with no authorization header.
  AuthenticationMessage msg("PUBLISH");
  msg._auth_hdr = false;
  msg._proxy_auth_hdr = true;
  msg._to_tag = ";tag=abcde";
  inject_msg(msg.get());
  auth_sproutlet_allows_request();
}

TEST_F(AuthenticationTest, NoAuthorizationEmergencyReg)
{
  // Test that the authentication module lets through emergency REGISTER requests
  AuthenticationMessage msg("REGISTER");
  msg._auth_hdr = false;
  msg._sos = true;
  inject_msg(msg.get());
  auth_sproutlet_allows_request();
}

TEST_F(AuthenticationTest, NoAuthorizationDigest)
{
  // Test that the authentication module lets through non-REGISTER requests that
  // comes from a digest UE.
  AuthenticationMessage msg("INVITE");
  msg._auth_hdr = false;
  msg._route_uri += ";username=Alice;nonce=123456";
  inject_msg(msg.get());
  auth_sproutlet_allows_request(true);
}

TEST_F(AuthenticationTest, IntegrityProtected)
{
  // Test that the authentication module lets through REGISTER requests
  // with authorization headers indicating the request has been integrity
  // protected at the P-CSCF.  Note that, in the AKA case (yes), the requests
  // must not have a response field in the authorization header, otherwise
  // this will be checked.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = true;
  msg1._integ_prot = "yes";
  inject_msg(msg1.get());
  auth_sproutlet_allows_request();

  AuthenticationMessage msg2("REGISTER");
  msg2._auth_hdr = true;
  msg2._integ_prot = "yes";
  inject_msg(msg2.get());
  auth_sproutlet_allows_request();

  AuthenticationMessage msg3("REGISTER");
  msg3._auth_hdr = true;
  msg3._integ_prot = "tls-yes";
  inject_msg(msg3.get());
  auth_sproutlet_allows_request();
  msg3._response = "12341234123412341234123412341234";
  msg3._cseq++;
  inject_msg(msg3.get());
  auth_sproutlet_allows_request();

  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
}

TEST_F(AuthenticationTest, IntegrityProtectedIpAssocYes)
{
  // Test that the authentication module challenges requests with an integrity
  // protected value of ip-assoc-yes.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  AuthenticationMessage msg("REGISTER");
  msg._auth_hdr = true;
  msg._integ_prot = "ip-assoc-yes";
  inject_msg(msg.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

// Tests that authentication is needed on registers that have at least one non
// emergency contact
TEST_F(AuthenticationTest, AuthorizationEmergencyReg)
{
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Test that the authentication is required for REGISTER requests with one non-emergency contact
  AuthenticationMessage msg("REGISTER");
  msg._auth_hdr = false;
  msg._sos = true;
  msg._extra_contact = "Contact: <sip:6505550001@uac.example.com:5060;rinstance=a0b20987985b61df;transport=TCP>";
  inject_msg(msg.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  pjsip_tx_data* tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestAuthSuccess)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value to SAS as a GENERIC_CORRELATOR.
  // This is needed so that SAS can correlate this transaction with the
  // subsequent challenge response below.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_successes);

  // Check that we logged the same opaque value to SAS as on the challenge so
  // that the transactions get correlated in SAS.
  check_sas_correlator(auth_params["opaque"]);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, DigestAuthSuccessRemoteSite)
{
  add_host_mapping("sprout-site2.homedomain", "5.6.7.8");

  // Test a successful SIP Digest authentication flow where the route header is
  // different from the configured S-CSCF URI.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  // Set the server_name to contain the local hostname part of the Route header.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout-site2.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  msg1._route_uri = "sip:sprout-site2.homedomain;transport=TCP;service=authentication";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  msg2._route_uri = "sip:sprout-site2.homedomain;transport=TCP;service=authentication";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout-site2.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, NoAlgorithmDigestAuthSuccess)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_successes);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, DigestAuthSuccessWithNonceCount)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Advance time to just before the binding is due to expire. The auth module
  // should still know about the challenge so a re-REGISTER with a higher nonce
  // count should be accepted.
  cwtest_advance_time_ms(270 * 1000);

  // Send a new REGISTER request but using a higher nonce count.
  AuthenticationMessage msg3("REGISTER");
  msg3._algorithm = "MD5";
  msg3._key = "12345678123456781234567812345678";
  msg3._nonce = auth_params["nonce"];
  msg3._opaque = auth_params["opaque"];
  msg3._nc = "00000002";
  msg3._cnonce = "8765432187654321";
  msg3._qop = "auth";
  msg3._integ_prot = "ip-assoc-pending";
  inject_msg(msg3.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestAuthSuccessNonceCountJump)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response. Jump the nonce count by quite a lot - this should still work.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "0000000A";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


// Test the case where:
//  - we have no algorithm parameter in a REGISTER
//  - we have an invalid nonce, so can't look up the AV
//
// This tests behaviour when we can't work out whether to track this in the digest auth or AKA auth
// statistics - we should use digest as a default.
TEST_F(AuthenticationTest, NoAlgorithmBadNonceDigestAuthFailure)
{
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = "abab";
  msg2._opaque = "bcbc";
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  inject_msg(msg2.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);
  free_txdata();

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_failures);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestAuthFailBadResponse)
{
  // Test a failed SIP Digest authentication flow where the response is wrong.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with an authentication header, but with no
  // integrity protected parameter.  This triggers Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value to SAS as a GENERIC_CORRELATOR.
  // This is needed so that SAS can correlate this transaction with the
  // subsequent challenge response below.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Send a new REGISTER request with an authentication header including a
  // bad response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  msg2._response = "00000000000000000000000000000000";
  inject_msg(msg2.get());

  // Check 403 forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_failures);
  free_txdata();

  // Check that we logged the same opaque value to SAS as on the challenge so
  // that the transactions get correlated in SAS.
  check_sas_correlator(auth_params["opaque"]);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestAuthFailBadIMPI)
{
  // Test a failed SIP Digest authentication flow where the IMPI is not found
  // in the database.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with an authentication header with a bad IMPI.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = true;
  msg1._auth_user = "unknown@homedomain";
  inject_msg(msg1.get());

  // Expect a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);
  EXPECT_EQ(0, ((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestAuthFailStale)
{
  // Test a failed SIP Digest authentication flow where the response is stale.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query the default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with an authentication header with a response
  // to an old challenge.  The content of the challenge doesn't matter,
  // provided it has a response and a nonce that won't be found in the AV
  // store.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = true;
  msg1._algorithm = "MD5";
  msg1._key = "12345678123456781234567812345678";
  msg1._nonce = "abcdefabcdefabcdefabcdefabcdef";
  msg1._opaque = "123123";
  msg1._nc = "00000001";
  msg1._cnonce = "8765432187654321";
  msg1._qop = "auth";
  msg1._integ_prot = "ip-assoc-pending";
  msg1._response = "00000000000000000000000000000000";
  inject_msg(msg1.get());

  // The authentication module should recognise this as a stale request and
  // respond with a challenge.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_failures);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  EXPECT_EQ("true", auth_params["stale"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_successes);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestAuthFailWrongRealm)
{
  // Test a failed SIP Digest authentication flow where the response contains the wrong realm.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response but the wrong realm.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  msg2._auth_realm = "otherdomain";
  inject_msg(msg2.get());

  // Check 401 Unauthorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_failures);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestAuthFailTimeout)
{
  // Test a failed SIP Digest authentication flows where homestead is overloaded,
  // and when it reports the HSS is overloaded
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_rc("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                          503);
  _hss_connection->set_rc("/impi/6505550002%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                          504);

  // Send in a REGISTER request.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = true;
  msg1._auth_user = "6505550001@homedomain";
  inject_msg(msg1.get());

  // Expect a 504 Server Timeout response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(504).matches(tdata->msg);
  free_txdata();

  AuthenticationMessage msg2("REGISTER");
  msg2._auth_hdr = true;
  msg2._auth_user = "6505550002@homedomain";
  inject_msg(msg2.get());

  // Expect a 504 Server Timeout response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(504).matches(tdata->msg);
  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  free_txdata();

  _hss_connection->delete_rc("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
  _hss_connection->delete_rc("/impi/6505550002%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestNonceCountTooLow)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Resubmit the same register. This should be re-challenged.
  msg2._cseq++;
  inject_msg(msg2.get());
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Check this is a new challenge, and that stale=true.
  std::string new_auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> new_auth_params;
  parse_www_authenticate(new_auth, new_auth_params);
  EXPECT_EQ("true", new_auth_params["stale"]);
  EXPECT_NE(auth_params["nonce"], new_auth_params["nonce"]);
  free_txdata();

  // A REGISTER with an acceptable nonce count should still work.
  AuthenticationMessage msg3("REGISTER");
  msg3._algorithm = "MD5";
  msg3._key = "12345678123456781234567812345678";
  msg3._nonce = auth_params["nonce"];
  msg3._opaque = auth_params["opaque"];
  msg3._nc = "00000002";
  msg3._cnonce = "8765432187654321";
  msg3._qop = "auth";
  msg3._integ_prot = "ip-assoc-pending";
  inject_msg(msg3.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestChallengeExpired)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Advance time to after the binding will have expired. An attempt to
  // REGISTER with this challenge should be re-challenged.
  cwtest_advance_time_ms(330 * 1000);

  // Send a new REGISTER request but using a higher nonce count.
  AuthenticationMessage msg3("REGISTER");
  msg3._algorithm = "MD5";
  msg3._key = "12345678123456781234567812345678";
  msg3._nonce = auth_params["nonce"];
  msg3._opaque = auth_params["opaque"];
  msg3._nc = "00000002";
  msg3._cnonce = "8765432187654321";
  msg3._qop = "auth";
  msg3._integ_prot = "ip-assoc-pending";
  inject_msg(msg3.get());

  // The authentication module has generated a fresh challenge.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Check this is a new challenge, and that stale=true.
  std::string new_auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> new_auth_params;
  parse_www_authenticate(new_auth, new_auth_params);
  EXPECT_EQ("true", new_auth_params["stale"]);
  EXPECT_NE(auth_params["nonce"], new_auth_params["nonce"]);

  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

void BaseAuthenticationTest::TestAKAAuthSuccess(char* key)
{
  // Test a successful AKA authentication flow.
  pjsip_tx_data* tdata;

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._integ_prot = "no";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("87654321876543218765432187654321", auth_params["nonce"]);
  EXPECT_EQ("0123456789abcdef", auth_params["ck"]);
  EXPECT_EQ("fedcba9876543210", auth_params["ik"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv1-MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value to SAS as a GENERIC_CORRELATOR.
  // This is needed so that SAS can correlate this transaction with the
  // subsequent challenge response below.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "AKAv1-MD5";
  msg2._key = key;
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "yes";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_successes);

  // Check that we logged the same opaque value to SAS as on the challenge so
  // that the transactions get correlated in SAS.
  check_sas_correlator(auth_params["opaque"]);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

// Test that a normal AKA authenticated registration succeeds.
TEST_F(AuthenticationTest, AKAAuthSuccess)
{
  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are not consistent, but that won't matter for
  // the purposes of the test as Clearwater never itself runs the MILENAGE
  // algorithms to generate or extract keys.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                              "\"response\":\"12345678123456781234567812345678\","
                              "\"cryptkey\":\"0123456789abcdef\","
                              "\"integritykey\":\"fedcba9876543210\"}}");

  BaseAuthenticationTest::TestAKAAuthSuccess("12345678123456781234567812345678");
}

// Test that a normal AKA authenticated registration succeeds, when the response
// contains null bytes. This was previously seen to cause incorrect behaviour
// when the null bytes were hex decoded and placed in a string.
TEST_F(AuthenticationTest, AKAAuthSuccessWithNullBytes)
{
  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are not consistent, but that won't matter for
  // the purposes of the test as Clearwater never itself runs the MILENAGE
  // algorithms to generate or extract keys.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                              "\"response\":\"12345678000000000000000012345678\","
                              "\"cryptkey\":\"0123456789abcdef\","
                              "\"integritykey\":\"fedcba9876543210\"}}");

  BaseAuthenticationTest::TestAKAAuthSuccess("12345678000000000000000012345678");
}

TEST_F(AuthenticationTest, AKAv2AuthSuccess)
{
  // Test a successful AKA authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are precalculated to ensure that the eventual
  // Digest response matches the one generated by hashing the
  // response/cryptkey/integritykey.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka2?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                              "\"response\":\"2f46a9d4aa4fae35\","
                              "\"version\":2,"
                              "\"cryptkey\":\"f36f63b242d502ba520f9504bed2366b\","
                              "\"integritykey\":\"42a43ceb1964f201564469fc2a27c305\"}}");

  // Send in a REGISTER request with an authentication header with
  // algorithm=AKAv2-MD5.  This triggers AKAv2 authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._algorithm = "AKAv2-MD5";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv2-MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value to SAS as a GENERIC_CORRELATOR.
  // This is needed so that SAS can correlate this transaction with the
  // subsequent challenge response below.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "AKAv2-MD5";
  msg2._response = "d1cae23f19f19ec19357749c4e16e811";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "897a977118d3092e88d574e833f7e3a3";
  msg2._qop = "auth";
  msg2._integ_prot = "yes";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_successes);

  // Check that we logged the same opaque value to SAS as on the challenge so
  // that the transactions get correlated in SAS.
  check_sas_correlator(auth_params["opaque"]);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka2?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, NoAlgorithmAKAAuthSuccess)
{
  // Test a successful AKA authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are not consistent, but that won't matter for
  // the purposes of the test as Clearwater never itself runs the MILENAGE
  // algorithms to generate or extract keys.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                              "\"response\":\"12345678123456781234567812345678\","
                              "\"cryptkey\":\"0123456789abcdef\","
                              "\"integritykey\":\"fedcba9876543210\"}}");

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._integ_prot = "no";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("87654321876543218765432187654321", auth_params["nonce"]);
  EXPECT_EQ("0123456789abcdef", auth_params["ck"]);
  EXPECT_EQ("fedcba9876543210", auth_params["ik"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv1-MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value to SAS as a GENERIC_CORRELATOR.
  // This is needed so that SAS can correlate this transaction with the
  // subsequent challenge response below.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "";
  msg2._force_aka = true;
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "yes";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_successes);

  // Check that we logged the same opaque value to SAS as on the challenge so
  // that the transactions get correlated in SAS.
  check_sas_correlator(auth_params["opaque"]);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, AKAAuthSuccessWithNonceCount)
{
  // Test a successful AKA authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are not consistent, but that won't matter for
  // the purposes of the test as Clearwater never itself runs the MILENAGE
  // algorithms to generate or extract keys.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                              "\"response\":\"12345678123456781234567812345678\","
                              "\"cryptkey\":\"0123456789abcdef\","
                              "\"integritykey\":\"fedcba9876543210\"}}");

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._integ_prot = "no";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("87654321876543218765432187654321", auth_params["nonce"]);
  EXPECT_EQ("0123456789abcdef", auth_params["ck"]);
  EXPECT_EQ("fedcba9876543210", auth_params["ik"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv1-MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value to SAS as a GENERIC_CORRELATOR.
  // This is needed so that SAS can correlate this transaction with the
  // subsequent challenge response below.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "AKAv1-MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "yes";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Check that we logged the same opaque value to SAS as on the challenge so
  // that the transactions get correlated in SAS.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Advance time to just before the binding is due to expire. The auth module
  // should still know about the challenge so a re-REGISTER with a higher nonce
  // count should be accepted.
  cwtest_advance_time_ms(270 * 1000);

  // Send a new REGISTER request but increase the nonce count. This should also
  // pass authentication.
  AuthenticationMessage msg3("REGISTER");
  msg3._algorithm = "AKAv1-MD5";
  msg3._key = "12345678123456781234567812345678";
  msg3._nonce = auth_params["nonce"];
  msg3._opaque = auth_params["opaque"];
  msg3._nc = "00000002";
  msg3._cnonce = "8765432187654321";
  msg3._qop = "auth";
  msg3._integ_prot = "yes";
  inject_msg(msg3.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Check that we didn't log the opaque value to SAS.  We only want the first
  // challenge response to get correlated with the challenge.
  check_sas_correlator(auth_params["opaque"], false);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, AKAAuthFailBadResponse)
{
  // Test a failed AKA authentication flow where the response is wrong.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are not consistent, but that won't matter for
  // the purposes of the test as Clearwater never itself runs the MILENAGE
  // algorithms to generate or extract keys.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                              "\"response\":\"12345678123456781234567812345678\","
                              "\"cryptkey\":\"0123456789abcdef\","
                              "\"integritykey\":\"fedcba9876543210\"}}");

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._integ_prot = "no";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("87654321876543218765432187654321", auth_params["nonce"]);
  EXPECT_EQ("0123456789abcdef", auth_params["ck"]);
  EXPECT_EQ("fedcba9876543210", auth_params["ik"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv1-MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value to SAS as a GENERIC_CORRELATOR.
  // This is needed so that SAS can correlate this transaction with the
  // subsequent challenge response below.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Send a new REGISTER request with an authentication header with an incorrect
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "AKAv1-MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._response = "00000000000000000000000000000000";
  msg2._integ_prot = "yes";
  inject_msg(msg2.get());

  // Check 403 forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_failures);
  free_txdata();

  // Check that we logged the same opaque value to SAS as on the challenge so
  // that the transactions get correlated in SAS.
  check_sas_correlator(auth_params["opaque"]);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, AKAAuthFailStale)
{
  // Test a failed AKA authentication flow where the response is stale.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query the default private user identity.

  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"12345678123456781234567812345678\","
                              "\"response\":\"87654321876543218765432187654321\","
                              "\"cryptkey\":\"fedcba9876543210\","
                              "\"integritykey\":\"0123456789abcdef\"}}");
  // Send in a REGISTER request with an authentication header with a response
  // to an old challenge.  The content of the challenge doesn't matter,
  // provided it has a response and a nonce that won't be found in the AV
  // store.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = true;
  msg1._algorithm = "AKAv1-MD5";
  msg1._key = "12345678123456781234567812345678";
  msg1._nonce = "abcdefabcdefabcdefabcdefabcdef";
  msg1._opaque = "123123";
  msg1._nc = "00000001";
  msg1._cnonce = "8765432187654321";
  msg1._qop = "auth";
  msg1._integ_prot = "ip-assoc-pending";
  msg1._response = "00000000000000000000000000000000";
  inject_msg(msg1.get());

  // The authentication module should recognise this as a stale request and
  // respond with a challenge.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Check that we logged the opaque value from the new challenge to SAS as
  // GENERIC CORRELATORS, but NOT the opaque value from the response -- this
  // had the wrong nonce and so we don't consider it to correlate with a
  // previous challenge.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  check_sas_correlator(auth_params["opaque"]);
  check_sas_correlator("123123", false);

  // Also check that we wrote the opaque value from the challenge to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_failures);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, AKAAuthResyncSuccess)
{
  // Test an AKA authentication flow that initially fails because the client
  // sequence number if out of sync with the HSS sequence number.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are not consistent, but that won't matter for
  // the purposes of the test as Clearwater never itself runs the MILENAGE
  // algorithms to generate or extract keys.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"8765432187654321876543218765432187654321432=\","
                              "\"response\":\"12345678123456781234567812345678\","
                              "\"cryptkey\":\"0123456789abcdef\","
                              "\"integritykey\":\"fedcba9876543210\"}}");

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._integ_prot = "no";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("8765432187654321876543218765432187654321432=", auth_params["nonce"]);
  EXPECT_EQ("0123456789abcdef", auth_params["ck"]);
  EXPECT_EQ("fedcba9876543210", auth_params["ik"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv1-MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value to SAS as a GENERIC_CORRELATOR.
  // This is needed so that SAS can correlate this transaction with the
  // subsequent challenge response below.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Set up a second HSS response for the resync query from the authentication
  // module.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&resync-auth=87654321876543218765499td9td9td9td9td9td&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"1234567812345678123456781234567812345678123=\","
                              "\"response\":\"87654321876543218765432187654321\","
                              "\"cryptkey\":\"fedcba9876543210\","
                              "\"integritykey\":\"0123456789abcdef\"}}");

  // Send a new REGISTER request with an authentication header with a correct
  // response, but with an auts parameter indicating the sequence number in
  // the nonce was out of sync.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "AKAv1-MD5";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._auts = "3213213213213213213=";
  msg2._integ_prot = "yes";
  msg2._response = AuthenticationMessage::calculate_digest_response(
    msg2._algorithm, msg2._force_aka,
    msg2._auth_user, "",
    msg2._method, msg2._uri,
    msg2._nonce, msg2._nc,
    msg2._cnonce, msg2._qop,
    msg2._auth_realm);
  inject_msg(msg2.get());

  // Expect another 401 Not Authorized response with a new challenge.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_successes);

  // Check that we logged the opaque value from the request to SAS as a
  // GENERIC_CORRELATOR marker.
  check_sas_correlator(auth_params["opaque"]);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  auth = get_headers(tdata->msg, "WWW-Authenticate");
  auth_params.clear();
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("1234567812345678123456781234567812345678123=", auth_params["nonce"]);
  EXPECT_EQ("fedcba9876543210", auth_params["ck"]);
  EXPECT_EQ("0123456789abcdef", auth_params["ik"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv1-MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value from the new challenge to SAS as a
  // GENERIC_CORRELATOR too.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);

  // Send a new REGISTER request with an authentication header with a correct
  // response to the second challenge.
  AuthenticationMessage msg3("REGISTER");
  msg3._algorithm = "AKAv1-MD5";
  msg3._key = "87654321876543218765432187654321";
  msg3._nonce = auth_params["nonce"];
  msg3._opaque = auth_params["opaque"];
  msg3._nc = "00000001";
  msg3._cnonce = "8765432187654321";
  msg3._qop = "auth";
  msg3._integ_prot = "yes";
  inject_msg(msg3.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Check that we logged the opaque value from the response to SAS as a
  // GENERIC_CORRELATOR marker.
  check_sas_correlator(auth_params["opaque"]);

  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  EXPECT_EQ(2,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_successes);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&resync-auth=f3beb9e37db5f3beb9e37db5f3beb9e3df6d77db5df6d77db5df6d77db5d&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, AKAAuthResyncFail)
{
  // Test an AKA authentication flow that initially fails because the client
  // sequence number if out of sync with the HSS sequence number.  The resync
  // fails because the auts parameter is malformed.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are not consistent, but that won't matter for
  // the purposes of the test as Clearwater never itself runs the MILENAGE
  // algorithms to generate or extract keys.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                                        "\"response\":\"12345678123456781234567812345678\","
                                        "\"cryptkey\":\"0123456789abcdef\","
                                        "\"integritykey\":\"fedcba9876543210\"}}");

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._integ_prot = "no";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("87654321876543218765432187654321", auth_params["nonce"]);
  EXPECT_EQ("0123456789abcdef", auth_params["ck"]);
  EXPECT_EQ("fedcba9876543210", auth_params["ik"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv1-MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header with a correct
  // response, but with an auts parameter indicating the sequence number in
  // the nonce was out of sync.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "AKAv1-MD5";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._auts = "321321321321";    // Too short
  msg2._response = AuthenticationMessage::calculate_digest_response(
    msg2._algorithm, msg2._force_aka,
    msg2._auth_user, "",
    msg2._method, msg2._uri,
    msg2._nonce, msg2._nc,
    msg2._cnonce, msg2._qop,
    msg2._auth_realm);
  inject_msg(msg2.get());

  // Expect a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_failures);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, AuthCorruptAV)
{
  // Test a handling of corrupt Authentication Vectors from Homestead.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user
  // identity, with no aka or digest body.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{}");

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._integ_prot = "no";
  inject_msg(msg1.get());

  // Expect a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");

  // Set up the HSS response for the AV query using a default private user
  // identity, with a malformed aka body.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                                        "\"cryptkey\":\"0123456789abcdef\","
                                        "\"integritykey\":\"fedcba9876543210\"}}");

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg2("REGISTER");
  msg2._integ_prot = "no";
  inject_msg(msg2.get());

  // Expect a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");

  // Set up the HSS response for the AV query the default private user identity,
  // with a malformed digest body.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\","
                                           "\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg3("REGISTER");
  msg3._auth_hdr = false;
  inject_msg(msg3.get());

  // Expect a 403 Forbidden response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(403).matches(tdata->msg);
  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.sip_digest_auth_tbl)->_attempts);
  EXPECT_EQ(0,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.ims_aka_auth_tbl)->_attempts);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, AuthSproutletCanRegisterForAliases)
{
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  msg1._route_uri = "sip:authentication.sprout.homedomain:5058;transport=TCP";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  msg1._route_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, ServiceRouteWithMD5Algorithm)
{
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  msg1._route_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
  inject_msg(msg2.get());

  // The authentication module lets the request through. Keep the 200 OK around
  // for future checking.
  auth_sproutlet_allows_request(false, false);

  // Check that the Service-Route contains username and nonce parameters.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Service-Route"),
            "Service-Route: <sip:scscf.sprout.example.com;"
              "orig;username=6505550001%40homedomain;nonce=" + auth_params["nonce"] + ">");
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, ServiceRouteWithAKAAlgorithm)
{
  // Test a successful AKA authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  // The keys in this test case are not consistent, but that won't matter for
  // the purposes of the test as Clearwater never itself runs the MILENAGE
  // algorithms to generate or extract keys.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"aka\":{\"challenge\":\"87654321876543218765432187654321\","
                              "\"response\":\"12345678123456781234567812345678\","
                              "\"cryptkey\":\"0123456789abcdef\","
                              "\"integritykey\":\"fedcba9876543210\"}}");

  // Send in a REGISTER request with an authentication header with
  // integrity-protected=no.  This triggers aka authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._integ_prot = "no";
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_EQ("87654321876543218765432187654321", auth_params["nonce"]);
  EXPECT_EQ("0123456789abcdef", auth_params["ck"]);
  EXPECT_EQ("fedcba9876543210", auth_params["ik"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("AKAv1-MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "AKAv1-MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "yes";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request(false, false);

  // Check that the Service-Route does not contain username and nonce parameters
  // - these are only added when the user authenticates using Digest
  // authentication.
  EXPECT_EQ(get_headers(current_txdata()->msg, "Service-Route"),
            "Service-Route: <sip:scscf.sprout.example.com;orig>");
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av/aka?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, StoreFailsWhenCheckingAuthResponse)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we logged the opaque value from the challenge to SAS as a
  // GENERIC_CORRELATOR.
  check_sas_correlator(auth_params["opaque"]);
  mock_sas_discard_messages();

  // Also check that we wrote the opaque value to the IMPI Store as the
  // correlator.
  check_impi_store_correlator("6505550001@homedomain", auth_params["nonce"], auth_params["opaque"]);


  // Send a new REGISTER request with an authentication header including the
  // response. Simulate a store failure during this request.
  _local_data_store->force_error();
  _local_data_store->force_get_error();

  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // Expect a 500 Server Internal Error
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(500).matches(tdata->msg);

  // Check that we logged the same opaque value to SAS as on the challenge so
  // that the transactions get correlated in SAS.
  check_sas_correlator(auth_params["opaque"]);

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

//
// Tests involving triggering authentication based on a Proxy-Authorization
// header.
//
// These are typed tests, parameterized over different settings for the
// non-REGISTER authentication mode config parameter.
//

typedef ::testing::Types <
  AuthenticationTestConfig<NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT, true>,
  AuthenticationTestConfig<NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT |
                             NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT, true>
> PxyAuthHdrTypes;

// Need to define a new type so the parameterization works.
template <class T> using AuthenticationPxyAuthHdrTest = AuthenticationTestTemplate<T,
                                                         FakeChronosConnectionHelper>;
TYPED_TEST_CASE(AuthenticationPxyAuthHdrTest, PxyAuthHdrTypes);

TYPED_TEST(AuthenticationPxyAuthHdrTest, ProxyAuthorizationSuccess)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  this->_hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                                    "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg("INVITE");
  msg._auth_hdr = false;
  msg._proxy_auth_hdr = true;
  msg._route_uri += ";auto-reg";
  this->inject_msg(msg.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  std::string auth = get_headers(tdata->msg, "Proxy-Authenticate");
  std::map<std::string, std::string> auth_params;
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = 1;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg2("INVITE");
  msg2._auth_hdr = false;
  msg2._proxy_auth_hdr = true;
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  msg2._route_uri += ";auto-reg";

  // Inject the request into the auth module. Check that it passes the request
  // through, and strips the Proxy-Authorization header.
  this->inject_msg(msg2.get());

  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();

  ASSERT_EQ(1, this->txdata_count());
  EXPECT_EQ(this->current_txdata()->msg->type, PJSIP_REQUEST_MSG);
  EXPECT_EQ(get_headers(this->current_txdata()->msg, "Proxy-Authorization"), "");
  this->inject_msg(this->respond_to_current_txdata(200));

  ASSERT_EQ(1, this->txdata_count());
  RespMatcher(200).matches(this->current_txdata()->msg);
  this->free_txdata();

  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.non_register_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.non_register_auth_tbl)->_successes);

  this->_hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TYPED_TEST(AuthenticationPxyAuthHdrTest, ProxyAuthorizationOneResponsePerChallenge)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  this->_hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                                    "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg("INVITE");
  msg._auth_hdr = false;
  msg._proxy_auth_hdr = true;
  msg._route_uri += ";auto-reg";
  this->inject_msg(msg.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  std::string auth = get_headers(tdata->msg, "Proxy-Authenticate");
  std::map<std::string, std::string> auth_params;
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = 1;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg2("INVITE");
  msg2._auth_hdr = false;
  msg2._proxy_auth_hdr = true;
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  msg2._route_uri += ";auto-reg";
  this->inject_msg(msg2.get());

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request(true);

  //
  // Send another request that tries to use the same nonce as the first request.
  //
  // Note that because all challenges are stored for at least 40s (to allow the
  // initial auth response flow to complete) we advance time by 60s first which
  // makes the challenge expire and causes the request to be challenged.
  //
  cwtest_advance_time_ms(60 * 1000);

  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = true;
  msg3._algorithm = "MD5";
  msg3._key = "12345678123456781234567812345678";
  msg3._nonce = auth_params["nonce"];
  msg3._opaque = auth_params["opaque"];
  msg3._nc = "00000002";
  msg3._cnonce = "8765432187654321";
  msg3._qop = "auth";
  msg3._integ_prot = "ip-assoc-pending";
  msg3._route_uri += ";auto-reg";
  this->inject_msg(msg3.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  std::string auth2 = get_headers(tdata->msg, "Proxy-Authenticate");
  std::map<std::string, std::string> auth_params2;
  this->parse_www_authenticate(auth2, auth_params2);
  EXPECT_EQ("true", auth_params2["stale"]);
  EXPECT_NE(auth_params["nonce"], auth_params2["nonce"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack2("ACK");
  ack2._cseq = msg3._cseq;
  this->inject_msg(ack2.get());

  // Submit a same request with the same authentication response. Check it is
  // rejected.
  AuthenticationMessage msg4("INVITE");
  msg4._auth_hdr = false;
  msg4._proxy_auth_hdr = true;
  msg4._algorithm = "MD5";
  msg4._key = "12345678123456781234567812345678";
  msg4._nonce = auth_params2["nonce"];
  msg4._opaque = auth_params2["opaque"];
  msg4._nc = "00000002";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  msg4._route_uri += ";auto-reg";
  this->inject_msg(msg4.get());

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request(true);

  this->_hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TYPED_TEST(AuthenticationPxyAuthHdrTest, ProxyAuthorizationFailure)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  this->_hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                                    "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg("INVITE");
  msg._auth_hdr = false;
  msg._proxy_auth_hdr = true;
  msg._route_uri += ";auto-reg";
  this->inject_msg(msg.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  std::string auth = get_headers(tdata->msg, "Proxy-Authenticate");
  std::map<std::string, std::string> auth_params;
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = 1;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header - the nonce should match but the password
  // should be wrong.
  AuthenticationMessage msg2("INVITE");
  msg2._auth_hdr = false;
  msg2._proxy_auth_hdr = true;
  msg2._algorithm = "MD5";
  msg2._key = "wrong";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  msg2._route_uri += ";auto-reg";
  this->inject_msg(msg2.get());

  // Expect a 403 Forbidden response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(403).matches(tdata->msg);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.non_register_auth_tbl)->_attempts);
  EXPECT_EQ(1,((SNMP::FakeSuccessFailCountTable*)SNMP::FAKE_AUTHENTICATION_STATS_TABLES.non_register_auth_tbl)->_failures);
  this->free_txdata();

  this->_hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TYPED_TEST(AuthenticationPxyAuthHdrTest, NoProxyAuthorization)
{
  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg("INVITE");
  msg._auth_hdr = false;
  msg._proxy_auth_hdr = false;
  this->inject_msg(msg.get());

  this->auth_sproutlet_allows_request(true);
}


//
// Tests when nonce count support is disabled.
//

typedef AuthenticationTestTemplate<
  AuthenticationTestConfig<NonRegisterAuthentication::NEVER, false>,
  FakeChronosConnectionHelper
> AuthenticationNonceCountDisabledTest;

TEST_F(AuthenticationNonceCountDisabledTest, DigestAuthSuccessWithNonceCount)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Send a new REGISTER request but using a higher nonce count.
  AuthenticationMessage msg3("REGISTER");
  msg3._algorithm = "MD5";
  msg3._key = "12345678123456781234567812345678";
  msg3._nonce = auth_params["nonce"];
  msg3._opaque = auth_params["opaque"];
  msg3._nc = "00000002";
  msg3._cnonce = "8765432187654321";
  msg3._qop = "auth";
  msg3._integ_prot = "ip-assoc-pending";
  inject_msg(msg3.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Check a new challenge has been issued.
  std::string auth2 = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params2;
  parse_www_authenticate(auth2, auth_params2);
  EXPECT_EQ("true", auth_params2["stale"]);
  EXPECT_NE(auth_params["nonce"], auth_params2["nonce"]);
  free_txdata();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

TEST_F(AuthenticationTest, DigestAuthSuccessWithDataContention)
{
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Do an initial registration flow (REGISTER, 401, REGISTER, 200) so that we
  // get an IMPI into the store.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  free_txdata();

  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Simulate data contention. This means that the second registration flow
  // will fail.
  _local_data_store->force_contention();

  // Do a second initial registration flow (REGISTER, 401, REGISTER, 200). The
  // first attempt to write the challenge back fails, but the second succeeds.
  AuthenticationMessage msg3("REGISTER");
  msg3._auth_hdr = false;
  inject_msg(msg3.get());

  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  auth = get_headers(tdata->msg, "WWW-Authenticate");
  parse_www_authenticate(auth, auth_params);
  free_txdata();

  AuthenticationMessage msg4("REGISTER");
  msg4._algorithm = "MD5";
  msg4._key = "12345678123456781234567812345678";
  msg4._nonce = auth_params["nonce"];
  msg4._opaque = auth_params["opaque"];
  msg4._nc = "00000001";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  inject_msg(msg4.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Check that the first challenge can still be used to authenticate with.
  AuthenticationMessage msg5("REGISTER");
  msg5._algorithm = "MD5";
  msg5._key = "12345678123456781234567812345678";
  msg5._nonce = msg2._nonce;
  msg5._opaque = auth_params["opaque"];
  msg5._nc = "00000002";
  msg5._cnonce = "8765432187654321";
  msg5._qop = "auth";
  msg5._integ_prot = "ip-assoc-pending";
  inject_msg(msg5.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Check that the second challenge can still be used to authenticate with.
  AuthenticationMessage msg6("REGISTER");
  msg6._algorithm = "MD5";
  msg6._key = "12345678123456781234567812345678";
  msg6._nonce = msg4._nonce;
  msg6._opaque = auth_params["opaque"];
  msg6._nc = "00000002";
  msg6._cnonce = "8765432187654321";
  msg6._qop = "auth";
  msg6._integ_prot = "ip-assoc-pending";
  inject_msg(msg6.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}


TEST_F(AuthenticationTest, DigestAuthFailureWithSetError)
{
  // Test an unsuccessful SIP Digest authentication flow.  A failure occurs
  // because we fail to write to memcached.
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Force an error on the SET.  This means that we'll respond with a 500
  // Server Internal Error.
  _local_data_store->force_error();

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 500 Server Internal Error response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(500).matches(tdata->msg);
}

//
// Tests for auth_challenge timer creation and deletion
//

/// Test fixture for these tests. This is just a typedef of the test template +
/// a particular configuration.
typedef AuthenticationTestTemplate<
  AuthenticationTestConfig<NonRegisterAuthentication::NEVER, true>,
  MockChronosConnectionHelper
> AuthenticationTimerTest;


// Basic Authentication flow, but checking that we create and delete the timer correctly.
TEST_F(AuthenticationTimerTest, AuthSuccessTimerDelete)
{
  pjsip_tx_data* tdata;
  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Check we're sending a timer out, and return a timer id
  EXPECT_CALL(*MockChronosConnectionHelper::get_chronos_connection(), send_post(_,_,"/authentication-timeout",_,_,_))
              .WillOnce(DoAll(SetArgReferee<0>("timer-id"),
                              Return(HTTP_OK)));

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Check that we delete the timer id we were given earlier.
  EXPECT_CALL(*MockChronosConnectionHelper::get_chronos_connection(), send_delete("timer-id",_))
              .WillOnce(Return(HTTP_OK));

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Verify the chronos_connection expectations here, as otherwise they wait until the test class is deleted
  testing::Mock::VerifyAndClear(MockChronosConnectionHelper::get_chronos_connection());
  // clean up
  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

// Assert that we don't send a delete if the timer creation failed.
TEST_F(AuthenticationTimerTest, AuthSuccessTimerCreationFail)
{

  pjsip_tx_data* tdata;
  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Set up the timer creation to return an error, simulating timer creation failure.
  EXPECT_CALL(*MockChronosConnectionHelper::get_chronos_connection(), send_post(_,_,"/authentication-timeout",_,_,_))
              .WillOnce(Return(HTTP_BAD_REQUEST));

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 401 Not Authorized response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(401).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
  std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
  std::map<std::string, std::string> auth_params;
  parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  free_txdata();

  // Assert that we do not attempt to delete any timers, as we didn't create one
  EXPECT_CALL(*MockChronosConnectionHelper::get_chronos_connection(), send_delete(_,_)).Times(0);

  // Send a new REGISTER request with an authentication header including the
  // response.
  AuthenticationMessage msg2("REGISTER");
  msg2._algorithm = "MD5";
  msg2._key = "12345678123456781234567812345678";
  msg2._nonce = auth_params["nonce"];
  msg2._opaque = auth_params["opaque"];
  msg2._nc = "00000001";
  msg2._cnonce = "8765432187654321";
  msg2._qop = "auth";
  msg2._integ_prot = "ip-assoc-pending";
  inject_msg(msg2.get());

  // The authentication module lets the request through.
  auth_sproutlet_allows_request();

  // Verify the chronos_connection expectations here, as otherwise they wait until the test class is deleted
  testing::Mock::VerifyAndClear(MockChronosConnectionHelper::get_chronos_connection());
  // clean up
  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

// Check that we attempt to delete the timer if the auth_challenge store failed.
TEST_F(AuthenticationTimerTest, AuthStoreFailTimerDeleted)
{
  pjsip_tx_data* tdata;

  // Set up the HSS response for the AV query using a default private user identity.
  _hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                              "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

  // Check that we create the timer, but then delete it following the failure
  // to set the auth_challenge into the store.

  EXPECT_CALL(*MockChronosConnectionHelper::get_chronos_connection(), send_post(_,_,"/authentication-timeout",_,_,_))
              .WillOnce(DoAll(SetArgReferee<0>("timer-id"),
                              Return(HTTP_OK)));

  EXPECT_CALL(*MockChronosConnectionHelper::get_chronos_connection(), send_delete("timer-id",_))
              .WillOnce(Return(HTTP_OK));

  // Force an error on the SET.  This means that we'll respond with a 500
  // Server Internal Error.
  _local_data_store->force_error();

  // Send in a REGISTER request with no authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg1("REGISTER");
  msg1._auth_hdr = false;
  inject_msg(msg1.get());

  // Expect a 500 Server Internal Error response.
  ASSERT_EQ(1, txdata_count());
  tdata = current_txdata();
  RespMatcher(500).matches(tdata->msg);

  // Verify the chronos_connection expectations here, as otherwise they wait until the test class is deleted
  testing::Mock::VerifyAndClear(MockChronosConnectionHelper::get_chronos_connection());
  // clean up
  _hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");
}

//
// Tests for authenticating non-REGISTER messages from a UE that authenticates
// using SIP Digest.
//
// This is a typed test, parameterized over different values of the non-REGISTER
// auth mode flag.
//

typedef ::testing::Types<
  AuthenticationTestConfig<NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT, false>,
  AuthenticationTestConfig<NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT |
                             NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT, false>
> DigestUEsTypes;

template <class T>
class AuthenticationDigestUEsTest : public AuthenticationTestTemplate<T, FakeChronosConnectionHelper>
{
public:
  std::map<std::string, std::string> _reg_auth_params;

  static void SetUpTestCase() { AuthenticationTestTemplate<T, FakeChronosConnectionHelper>::SetUpTestCase(); }
  static void TearDownTestCase() { AuthenticationTestTemplate<T, FakeChronosConnectionHelper>::TearDownTestCase(); }

  // Start this test with a subscriber registered.
  virtual void SetUp()
  {
    AuthenticationTestTemplate<T, FakeChronosConnectionHelper>::SetUp();

    // Test a successful SIP Digest authentication flow.
    pjsip_tx_data* tdata;

    // Set up the HSS response for the AV query using a default private user identity.
    this->_hss_connection->set_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP",
                                      "{\"digest\":{\"realm\":\"homedomain\",\"qop\":\"auth\",\"ha1\":\"12345678123456781234567812345678\"}}");

    // Send in a REGISTER request with no authentication header.  This triggers
    // Digest authentication.
    AuthenticationMessage msg1("REGISTER");
    msg1._auth_hdr = false;
    this->inject_msg(msg1.get());

    // Expect a 401 Not Authorized response.
    ASSERT_EQ(1, this->txdata_count());
    tdata = this->current_txdata();
    RespMatcher(401).matches(tdata->msg);

    // Extract the nonce, nc, cnonce and qop fields from the WWW-Authenticate header.
    std::string auth = get_headers(tdata->msg, "WWW-Authenticate");
    this->parse_www_authenticate(auth, _reg_auth_params);
    this->free_txdata();

    // Send a new REGISTER request with an authentication header including the
    // response.
    AuthenticationMessage msg2("REGISTER");
    msg2._algorithm = "MD5";
    msg2._key = "12345678123456781234567812345678";
    msg2._nonce = _reg_auth_params["nonce"];
    msg2._opaque = _reg_auth_params["opaque"];
    msg2._nc = "00000001";
    msg2._cnonce = "8765432187654321";
    msg2._qop = "auth";
    msg2._integ_prot = "ip-assoc-pending";
    this->inject_msg(msg2.get());

    // The authentication module lets the request through.
    this->auth_sproutlet_allows_request();

    // Delete the result from the HSS. This makes sure that when authenticating
    // the following INVITE we aren't accidentally querying the HSS.
    this->_hss_connection->delete_result("/impi/6505550001%40homedomain/av?impu=sip%3A6505550001%40homedomain&server-name=sip%3Ascscf.sprout.homedomain%3A5058%3Btransport%3DTCP");

    // Advance time by 1 minute to check that the challenge has not been written
    // with too-short a timeout.
    cwtest_advance_time_ms(60000);

  }
};

TYPED_TEST_CASE(AuthenticationDigestUEsTest, DigestUEsTypes);

TYPED_TEST(AuthenticationDigestUEsTest, SuccessFlow)
{
  pjsip_tx_data* tdata;
  std::map<std::string, std::string> auth_params;
  std::string auth;

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg3.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = msg3._cseq;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg4("INVITE");
  msg4._auth_hdr = false;
  msg4._proxy_auth_hdr = true;
  msg4._algorithm = "MD5";
  msg4._key = "12345678123456781234567812345678";
  msg4._nonce = auth_params["nonce"];
  msg4._opaque = auth_params["opaque"];
  msg4._nc = "00000001";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  msg4._route_uri = msg3._route_uri;
  this->inject_msg(msg4.get());

  // Eat the 100 trying.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();

  ReqMatcher invite_matcher("INVITE");
  invite_matcher.matches(this->current_txdata()->msg);
  EXPECT_EQ(get_headers(this->current_txdata()->msg, "Proxy-Authorization"), "");

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request();
}

TYPED_TEST(AuthenticationDigestUEsTest, NonDigestSubscriberMakesCall)
{
  // Send in a request from an unregistered digest endpoint. Note that this will
  // not have a real nonce.
  AuthenticationMessage msg("INVITE");
  msg._auth_hdr = false;
  msg._proxy_auth_hdr = false;
  this->inject_msg(msg.get());

  this->auth_sproutlet_allows_request(true);
}

TYPED_TEST(AuthenticationDigestUEsTest, UnregSubscriberMakesCall)
{
  // Test a successful SIP Digest authentication flow.
  pjsip_tx_data* tdata;

  // Send in an INVITE that looks like it's from a digest UE, but the UE isn't
  // actually registered.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=9995550002%40homedomain;nonce=123456";
  this->inject_msg(msg3.get());

  // Expect a 403 Forbidden response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(403).matches(tdata->msg);
  this->free_txdata();

  // Tidy up the transaction by sending the ACK.
  AuthenticationMessage ack("ACK");
  ack._cseq = msg3._cseq;
  this->inject_msg(ack.get());
}

TYPED_TEST(AuthenticationDigestUEsTest, NoAuthorizationTermRequest)
{
  // Test that the authentication module lets through terminating requests, even
  // if the rest of the message means it would be challenged.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri.erase(msg3._route_uri.find(";orig"));
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=123456";
  this->inject_msg(msg3.get());

  this->auth_sproutlet_allows_request(true);
}

TYPED_TEST(AuthenticationDigestUEsTest, NoAuthorizationInDialogRequest)
{
  // Test that the authentication module lets through terminating requests, even
  // if the rest of the message means it would be challenged.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=123456";
  msg3._to_tag = ";tag=kermit";
  this->inject_msg(msg3.get());

  this->auth_sproutlet_allows_request(true);
}

TYPED_TEST(AuthenticationDigestUEsTest, StoreFailsWhenGeneratingChallenge)
{
  pjsip_tx_data* tdata;
  std::map<std::string, std::string> auth_params;
  std::string auth;

  // Send in an INVITE but fail the store lookup.
  this->_local_data_store->force_get_error();

  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg3.get());

  // Expect a 504 response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(504).matches(tdata->msg);

  AuthenticationMessage ack("ACK");
  ack._cseq = msg3._cseq;
  this->inject_msg(ack.get());
}

TYPED_TEST(AuthenticationDigestUEsTest, BadAuthResponse)
{
  pjsip_tx_data* tdata;
  std::map<std::string, std::string> auth_params;
  std::string auth;

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg3.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = msg3._cseq;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg4("INVITE");
  msg4._auth_hdr = false;
  msg4._proxy_auth_hdr = true;
  msg4._algorithm = "MD5";
  msg4._key = "thisisclearlywrong";
  msg4._nonce = auth_params["nonce"];
  msg4._opaque = auth_params["opaque"];
  msg4._nc = "00000001";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  msg4._route_uri = msg3._route_uri;
  this->inject_msg(msg4.get());

  // Expect a 403 Forbidden response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(403).matches(tdata->msg);

  // ACK that response
  AuthenticationMessage ack2("ACK");
  ack2._cseq = msg4._cseq;
  this->inject_msg(ack2.get());
}

TYPED_TEST(AuthenticationDigestUEsTest, NonceCountAttemptCausesRechallenge)
{
  pjsip_tx_data* tdata;
  std::map<std::string, std::string> auth_params;
  std::string auth;

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg3.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = msg3._cseq;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg4("INVITE");
  msg4._auth_hdr = false;
  msg4._proxy_auth_hdr = true;
  msg4._algorithm = "MD5";
  msg4._key = "12345678123456781234567812345678";
  msg4._nonce = auth_params["nonce"];
  msg4._opaque = auth_params["opaque"];
  msg4._nc = "00000001";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  msg4._route_uri = msg3._route_uri;
  this->inject_msg(msg4.get());

  // Eat the 100 trying.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();

  ReqMatcher invite_matcher("INVITE");
  invite_matcher.matches(this->current_txdata()->msg);
  EXPECT_EQ(get_headers(this->current_txdata()->msg, "Proxy-Authorization"), "");

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request();

  //
  // Send another request that tries to use the same nonce as the first request.
  //

  // Send a new request with a nonce count of 2.
  AuthenticationMessage msg5("INVITE");
  msg5._auth_hdr = false;
  msg5._proxy_auth_hdr = true;
  msg5._algorithm = "MD5";
  msg5._key = "12345678123456781234567812345678";
  msg5._nonce = auth_params["nonce"];
  msg5._opaque = auth_params["opaque"];
  msg5._nc = "00000002";
  msg5._cnonce = "8765432187654321";
  msg5._qop = "auth";
  msg5._integ_prot = "ip-assoc-pending";
  msg5._route_uri = msg4._route_uri;
  this->inject_msg(msg5.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack2("ACK");
  ack2._cseq = msg5._cseq;
  this->inject_msg(ack2.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg6("INVITE");
  msg6._auth_hdr = false;
  msg6._proxy_auth_hdr = true;
  msg6._algorithm = "MD5";
  msg6._key = "12345678123456781234567812345678";
  msg6._nonce = auth_params["nonce"];
  msg6._opaque = auth_params["opaque"];
  msg6._nc = "00000001";
  msg6._cnonce = "8765432187654321";
  msg6._qop = "auth";
  msg6._integ_prot = "ip-assoc-pending";
  msg6._route_uri = msg5._route_uri;
  this->inject_msg(msg6.get());

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request(true);
}

TYPED_TEST(AuthenticationDigestUEsTest, GrTest)
{
  pjsip_tx_data* tdata;
  std::map<std::string, std::string> auth_params;
  std::string auth;

  // Start off by simulating a GR failure. To do this:
  // - Swap the local store and the remote store's contents.
  // - Delete the data from the backup store.
  //
  // After this point, it's like we're acting in the remote site.
  this->_local_data_store->swap_dbs(this->_remote_data_stores[0]);
  this->_remote_data_stores[0]->flush_all();

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg3.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = msg3._cseq;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg4("INVITE");
  msg4._auth_hdr = false;
  msg4._proxy_auth_hdr = true;
  msg4._algorithm = "MD5";
  msg4._key = "12345678123456781234567812345678";
  msg4._nonce = auth_params["nonce"];
  msg4._opaque = auth_params["opaque"];
  msg4._nc = "00000001";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  msg4._route_uri = msg3._route_uri;
  this->inject_msg(msg4.get());

  // Eat the 100 trying.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();

  ReqMatcher invite_matcher("INVITE");
  invite_matcher.matches(this->current_txdata()->msg);
  EXPECT_EQ(get_headers(this->current_txdata()->msg, "Proxy-Authorization"), "");

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request();
}

TYPED_TEST(AuthenticationDigestUEsTest, GrTestReadRepair)
{
  pjsip_tx_data* tdata;
  std::map<std::string, std::string> auth_params;
  std::string auth;

  // Start off by pretending that this site was not available when the UE
  // registered (by flushing the local store).
  this->_local_data_store->flush_all();

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg3.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = msg3._cseq;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg4("INVITE");
  msg4._auth_hdr = false;
  msg4._proxy_auth_hdr = true;
  msg4._algorithm = "MD5";
  msg4._key = "12345678123456781234567812345678";
  msg4._nonce = auth_params["nonce"];
  msg4._opaque = auth_params["opaque"];
  msg4._nc = "00000001";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  msg4._route_uri = msg3._route_uri;
  this->inject_msg(msg4.get());

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request(true);

  // Flush the remote database and run another request through to check
  // everything is still working.
  this->_remote_data_stores[0]->flush_all();

  AuthenticationMessage msg5("INVITE");
  msg5._auth_hdr = false;
  msg5._proxy_auth_hdr = false;
  msg5._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg5.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack2("ACK");
  ack2._cseq = msg5._cseq;
  this->inject_msg(ack2.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg6("INVITE");
  msg6._auth_hdr = false;
  msg6._proxy_auth_hdr = true;
  msg6._algorithm = "MD5";
  msg6._key = "12345678123456781234567812345678";
  msg6._nonce = auth_params["nonce"];
  msg6._opaque = auth_params["opaque"];
  msg6._nc = "00000001";
  msg6._cnonce = "8765432187654321";
  msg6._qop = "auth";
  msg6._integ_prot = "ip-assoc-pending";
  msg6._route_uri = msg5._route_uri;
  this->inject_msg(msg6.get());

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request(true);

}

//
// Tests for authenticating non-REGISTER messages from a UE that authenticates
// using SIP Digest, but with nonce counts supported.
//
// This is a typed test, parameterized over different values of the non-REGISTER
// auth mode flag.
//

typedef ::testing::Types<
  AuthenticationTestConfig<NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT, true>,
  AuthenticationTestConfig<NonRegisterAuthentication::INITIAL_REQ_FROM_REG_DIGEST_ENDPOINT |
                             NonRegisterAuthentication::IF_PROXY_AUTHORIZATION_PRESENT, true>
> DigestUEsNonceCountSupportedTypes;

template <class T>
using AuthenticationDigestUEsNonceCountSupportedTest = AuthenticationDigestUEsTest<T>;

TYPED_TEST_CASE(AuthenticationDigestUEsNonceCountSupportedTest,
                DigestUEsNonceCountSupportedTypes);

// Check that a non-REGISTER request can be authenticated against the REGISTER
// challenge.
TYPED_TEST(AuthenticationDigestUEsNonceCountSupportedTest, NonRegAuthAgainstRegChallenge)
{
  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg4("INVITE");
  msg4._auth_hdr = false;
  msg4._proxy_auth_hdr = true;
  msg4._algorithm = "MD5";
  msg4._key = "12345678123456781234567812345678";
  msg4._nonce = this->_reg_auth_params["nonce"];
  msg4._opaque = this->_reg_auth_params["opaque"];
  msg4._nc = "00000002";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  msg4._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg4.get());

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request(true);
}


// Test making two non-REGISTER requests a long time apart (where the second
// has incremented the nonce count). The second SHOULD be challenged as
// the challenge will have expired.
TYPED_TEST(AuthenticationDigestUEsNonceCountSupportedTest, NonRegChalNotStored)
{
  pjsip_tx_data* tdata;
  std::map<std::string, std::string> auth_params;
  std::string auth;

  // Send in a request with a Proxy-Authentication header.  This triggers
  // Digest authentication.
  AuthenticationMessage msg3("INVITE");
  msg3._auth_hdr = false;
  msg3._proxy_auth_hdr = false;
  msg3._route_uri += ";username=6505550001%40homedomain;nonce=" + this->_reg_auth_params["nonce"];
  this->inject_msg(msg3.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  EXPECT_NE("", auth_params["nonce"]);
  EXPECT_EQ("auth", auth_params["qop"]);
  EXPECT_EQ("MD5", auth_params["algorithm"]);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack("ACK");
  ack._cseq = msg3._cseq;
  this->inject_msg(ack.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg4("INVITE");
  msg4._auth_hdr = false;
  msg4._proxy_auth_hdr = true;
  msg4._algorithm = "MD5";
  msg4._key = "12345678123456781234567812345678";
  msg4._nonce = auth_params["nonce"];
  msg4._opaque = auth_params["opaque"];
  msg4._nc = "00000001";
  msg4._cnonce = "8765432187654321";
  msg4._qop = "auth";
  msg4._integ_prot = "ip-assoc-pending";
  msg4._route_uri = msg3._route_uri;
  this->inject_msg(msg4.get());

  // Eat the 100 trying.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();

  ReqMatcher invite_matcher("INVITE");
  invite_matcher.matches(this->current_txdata()->msg);
  EXPECT_EQ(get_headers(this->current_txdata()->msg, "Proxy-Authorization"), "");

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request();

  //
  // Send another request that tries to use the same nonce as the first request.
  //
  // Note that because all challenges are stored for at least 40s (to allow the
  // initial auth response flow to complete) we advance time by 60s first which
  // makes the challenge expire and causes the request to be challenged.
  //
  cwtest_advance_time_ms(60 * 1000);

  // Send a new request with a nonce count of 2.
  AuthenticationMessage msg5("INVITE");
  msg5._auth_hdr = false;
  msg5._proxy_auth_hdr = true;
  msg5._algorithm = "MD5";
  msg5._key = "12345678123456781234567812345678";
  msg5._nonce = auth_params["nonce"];
  msg5._opaque = auth_params["opaque"];
  msg5._nc = "00000002";
  msg5._cnonce = "8765432187654321";
  msg5._qop = "auth";
  msg5._integ_prot = "ip-assoc-pending";
  msg5._route_uri = msg4._route_uri;
  this->inject_msg(msg5.get());

  // Expect a 407 Proxy Authorization Required response.
  ASSERT_EQ(2, this->txdata_count());
  RespMatcher(100).matches(this->current_txdata()->msg);
  this->free_txdata();
  tdata = this->current_txdata();
  RespMatcher(407).matches(tdata->msg);

  // Extract the nonce, nc, cnonce and qop fields from the header.
  auth = get_headers(tdata->msg, "Proxy-Authenticate");
  auth_params.clear();
  this->parse_www_authenticate(auth, auth_params);
  this->free_txdata();

  // ACK that response
  AuthenticationMessage ack2("ACK");
  ack2._cseq = msg5._cseq;
  this->inject_msg(ack2.get());

  // Send a new request with an authentication header including the response.
  AuthenticationMessage msg6("INVITE");
  msg6._auth_hdr = false;
  msg6._proxy_auth_hdr = true;
  msg6._algorithm = "MD5";
  msg6._key = "12345678123456781234567812345678";
  msg6._nonce = auth_params["nonce"];
  msg6._opaque = auth_params["opaque"];
  msg6._nc = "00000001";
  msg6._cnonce = "8765432187654321";
  msg6._qop = "auth";
  msg6._integ_prot = "ip-assoc-pending";
  msg6._route_uri = msg5._route_uri;
  this->inject_msg(msg6.get());

  // The authentication module lets the request through.
  this->auth_sproutlet_allows_request(true);
}
