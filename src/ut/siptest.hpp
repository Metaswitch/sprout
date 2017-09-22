/**
 * @file siptest.hpp UT class header for Sprout PJSIP modules.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */
#ifndef SIPTEST_H__
#define SIPTEST_H__

#include <string>
#include <sstream>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "utils.h"
#include "constants.h"
#include "dnscachedresolver.h"
#include "localstore.h"
#include "subscriber_data_manager.h"
#include "fakelogger.h"
#include "fakehssconnection.hpp"

using std::string;
using testing::MatchesRegex;

/// Helper: to_string method using ostringstream.
template <class T>
std::string to_string(T t,                                 ///< datum to convert
                      std::ios_base & (*f)(std::ios_base&) ///< modifier to apply
                     )
{
  std::ostringstream oss;
  oss << f << t;
  return oss.str();
}

/// ABC for SIP unit tests.
class SipTest : public ::testing::Test
{
public:
  SipTest(pjsip_module* module = NULL);
  virtual ~SipTest();

  /// Call this to set up the test case.
  static void SetUpTestCase();

  static void SIPResolverNoGraylist();

  static void SetScscfUri(const std::string& scscf_uri);

  static void TearDownTestCase();

protected:

  /// Class containing transport factories for the various ports.
  class TransportFactory
  {
  public:
    TransportFactory();
    ~TransportFactory();

  };

  /// Abstraction of a transport flow used for injecting or receiving SIP
  /// messages.
  class TransportFlow
  {
  public:
    typedef enum {TCP, UDP} Protocol;

    TransportFlow(Protocol protocol,
                  int local_port,
                  const char* addr,
                  int port);
    ~TransportFlow();

    /// Returns the type of the transport.
    std::string type_name();

    /// Returns the local port of the transport.
    int local_port();

    /// Returns the transport itself.
    pjsip_transport* transport();

    /// Returns a string rendering of the flow, with or without the
    /// transport name.
    std::string to_string(bool transport);

    /// Checks that the message was sent to this transport flow.
    void expect_target(const pjsip_tx_data* tdata,
                       bool strict = true);  //< Exact same transport (true) or just same address (false)

    static void reset();

    static pjsip_transport* udp_transport(int port);
    static pjsip_tpfactory* tcp_factory(int port);

  private:
    static std::map<int, pjsip_transport*> _udp_transports;
    static std::map<int, pjsip_tpfactory*> _tcp_factories;

    pjsip_transport* _transport;
    pj_sockaddr _rem_addr;
  };

  /// Terminate a TCP transport immediately.
  void terminate_tcp_transport(pjsip_transport* tp);

  /// Add DNS A records to map hostname to a set of IP addresses.  The
  /// list of addresses should be comma separated.
  static void add_host_mapping(const string& hostname, const string& addresses);

  /// Inject an inbound SIP message by passing it into the stack.
  void inject_msg(const string& msg, TransportFlow* tp = _tp_default);

  /// Inject an inbound SIP message structure by passing it into the
  /// stack.
  void inject_msg(pjsip_msg* msg, TransportFlow* tp = _tp_default);

  /// Inject an inbound SIP message by passing it into the stack but expect it
  /// to fail message parsing.
  void inject_msg_failure(const string& msg, TransportFlow* tp = _tp_default, int expected = -1);

  /// Inject message directly into the specified module, bypassing other
  /// layers.  Allows testing which messages we accept into the module.
  pj_bool_t inject_msg_direct(const std::string& msg, pjsip_module* module);

  /// Inject message directly into the default module, bypassing other
  /// layers.  Allows testing which messages we accept into the module.
  pj_bool_t inject_msg_direct(const std::string& msg) { return inject_msg_direct(msg, _module); };

  /// Examine the current outbound message.  This does not copy the
  /// message - do not use it after it has been removed!  Returns NULL
  /// if there is none.
  pjsip_tx_data* current_txdata();

  /// Free the current txdata and move on to the next.  Ignored if
  /// there is no current txdata.
  void free_txdata();

  /// Pop the current txdata without freeing it.  Ignored if there is
  /// no current txdata.
  pjsip_tx_data* pop_txdata();

  /// How many txdata messages are in the queue?
  int txdata_count();

  static SipTest* _current_instance;

  /// Register the specified URI.
  void register_uri(SubscriberDataManager* sdm,
                    FakeHSSConnection* hss,
                    const string& user,
                    const string& domain,
                    const string& contact,
                    int lifetime = 3600,
                    string instance_id="",
                    bool emergency=false);

  /// Build an incoming SIP packet.
  pjsip_rx_data* build_rxdata(const string& msg, TransportFlow* tp = _tp_default, pj_pool_t* rdata_pool = NULL);

  /// Parse an incoming SIP message.  Used by subclasses which wish
  /// to inject messages directly into modules, bypassing the
  /// transport layer.
  void parse_rxdata(pjsip_rx_data* rdata);

  /// Parse a string containing a SIP message into a pjsip_msg.  Used by
  /// subclasses that don't actually use PJSIP modules.
  pjsip_msg* parse_msg(const std::string& msg);

  /// Should we log all SIP traffic as it passes?
  bool _log_traffic;

  /// Log SIP traffic if enabled - pjsip_msg.
  void log_pjsip_msg(const char* description, pjsip_msg* msg);

  /// Log SIP traffic if enabled - buffer.
  void log_pjsip_buf(const char* description, const char* buf, int len);

  /// Create a minimal response message.  Only the msg member of the
  /// returned value is interesting, but the rest is included so that
  /// it can be properly freed.
  pjsip_tx_data* create_response(pjsip_tx_data* tdata, int st_code, const pj_str_t* st_text);

  /// Create a minimal response message to the current txdata message,
  /// and free that message.
  string respond_to_current_txdata(int st_code, string body = "", string extra = "");

  /// Create a minimal response message to the current txdata message.
  /// Doesn't free anything.
  string respond_to_txdata(pjsip_tx_data* tdata, int st_code, string body = "", string extra = "");

  /// Wait briefly for any pending events.
  static void poll();

  /// Get current time, formatted for display.
  string timestamp();

  /// Assert all transactions completed.
  void expect_all_tsx_done();

  /// Get a list of all current transactions.
  std::list<pjsip_transaction*> get_all_tsxs();

  /// Terminate all unterminated transactions.
  void terminate_all_tsxs(int status_code);

  /// Expect that the given message is sent on the expected transport
  /// type/address/port.  The address is specified as a numeric string
  /// (e.g., dotted-decimal).
  static void expect_target(const char* type_name, const char* addr, int port, pjsip_tx_data* tdata);

  /// Trusted TCP factory and UDP transport
  static pjsip_tpfactory* _tcp_tpfactory_trusted;
  static pjsip_transport* _udp_tp_trusted;

  /// Untrusted TCP factory and UDP transport
  static pjsip_tpfactory* _tcp_tpfactory_untrusted;
  static pjsip_transport* _udp_tp_untrusted;

private:
  static pj_status_t on_tx_msg(pjsip_tx_data* tdata);

  /// Handle an outbound SIP message.
  void handle_txdata(pjsip_tx_data* tdata);

  /// The transport we usually use when injecting messages.
  static TransportFlow* _tp_default;

  /// Default module to test in inject_msg_direct.
  pjsip_module* _module;

  std::list<pjsip_tx_data*> _out;

  // The DNS resolver.
  static DnsCachedResolver _dnsresolver;

};

/// Helper to print pj_status_t to ostream.
class PjStatus
{
public:
  PjStatus(pj_status_t rc) : _rc(rc)
  {
  }
  friend std::ostream& operator<<(std::ostream& os, const PjStatus& pj);
private:
  pj_status_t _rc;
};


/// Helper to print pjsip_msg to ostream.
class PjMsg
{
public:
  PjMsg(pjsip_msg* msg) : _msg(msg)
  {
  }
  friend std::ostream& operator<<(std::ostream& os, const PjMsg& pj);
private:
  pjsip_msg* _msg;
};

class MsgMatcher
{
public:
  MsgMatcher(string expected_body="",
             string body_regex="") :
    _expected_body(expected_body),
    _body_regex(body_regex)
  {
  }

  void matches(pjsip_msg* msg);
  void body_regex_matches(pjsip_msg* msg);

private:
  string _expected_body;
  string _body_regex;
};

/// Checker that asserts a PJSIP message is of the expected type,
/// expects that it has the expected method, and parses other data
/// from it for separate inspection.
class ReqMatcher : public MsgMatcher
{
public:
  ReqMatcher(const string& method) :
    MsgMatcher(),
    _method(method)
  {
  }

  ReqMatcher(const string& method,
             string expected_body,
             string body_regex="") :
    MsgMatcher(expected_body,
               body_regex),
    _method(method)
  {
  }

  void matches(pjsip_msg* msg);

  string uri()
  {
    return _uri;
  }

private:
  string _method;
  string _uri;
};

class RespMatcher : public MsgMatcher
{
  RespMatcher(int status, string body="", string reason="") :
    MsgMatcher(body),
    _status(status),
    _reason(reason)
  {
    if (_reason == "")
    {
      // No reason specified, so use the default from PJSIP.
      const pj_str_t* reason = (status != SIP_STATUS_FLOW_FAILED) ?
                                  pjsip_get_status_text(status) :
                                  &SIP_REASON_FLOW_FAILED;
      _reason.assign(reason->ptr, reason->slen);
    }
  }

  void matches(pjsip_msg* msg);

private:
  int _status;
  std::string _reason;
};

/// Convert a PJ string to a C++ string.
inline string str_pj(pj_str_t& str)
{
  return string(str.ptr, str.slen);
}

/// Extract a named header as a C++ string.
string get_headers(pjsip_msg* msg, string name);

/// Extract the URI as a C++ string.
inline string str_uri(pjsip_uri* uri, pjsip_uri_context_e context = PJSIP_URI_IN_REQ_URI)
{
  char buf[1000];
  int n = pjsip_uri_print(context, uri, buf, sizeof(buf));
  return string(buf, n);
}

/// Helper to print list to ostream.
class DumpList
{
public:
  DumpList(const string& title, std::list<string> list) :
    _title(title), _list(list)
  {
  }
  friend std::ostream& operator<<(std::ostream& os, const DumpList& that);
private:
  string _title;
  std::list<string> _list;
};

class HeaderMatcher
{
public:
  HeaderMatcher(string header) :
    _header(header)
  {
  }

  HeaderMatcher(string header, string regex1) :
    _header(header)
  {
    _regexes.push_back(regex1);
  }

  HeaderMatcher(string header, string regex1, string regex2) :
    _header(header)
  {
    _regexes.push_back(regex1);
    _regexes.push_back(regex2);
  }

  void match(pjsip_msg* msg)
  {
    pj_str_t name_str = { const_cast<char*>(_header.data()), (unsigned int)_header.length() };
    pjsip_hdr* hdr = NULL;
    std::list<string> values;

    while (NULL != (hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(msg, &name_str, hdr)))
    {
      char buf[1024];
      int n = pjsip_hdr_print_on(hdr, buf, sizeof(buf));
      EXPECT_LT(n, (int)sizeof(buf));
      values.push_back(string(buf,n));
      hdr = hdr->next;
    }

    ASSERT_EQ(_regexes.size(), values.size()) << DumpList("Expected", _regexes) << DumpList("Actual", values);
    std::list<string>::iterator itv = values.begin();
    std::list<string>::iterator itr = _regexes.begin();

    for (unsigned i = 0; i < _regexes.size(); i++)
    {
      EXPECT_THAT(*itv, testing::MatchesRegex(*itr));
      ++itv;
      ++itr;
    }
  }

private:
  string _header;
  std::list<string> _regexes;
};

#endif
