/**
 * @file siptest.cpp UT class for Sprout PJSIP modules.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#include <string>
#include <stdexcept>
#include "gtest/gtest.h"
#include "arpa/inet.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <boost/lexical_cast.hpp>

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "stack.h"
#include "statistic.h"
#include "faketransport_udp.hpp"
#include "faketransport_tcp.hpp"
#include "pjutils.h"
#include "test_interposer.hpp"
#include "siptest.hpp"

using namespace std;

static pjsip_module mod_siptest =
{
  NULL, NULL,                         /* prev, next.          */
  pj_str("mod-siptest"),              /* Name.                */
  -1,                                 /* Id                   */
  PJSIP_MOD_PRIORITY_TRANSPORT_LAYER + 1,  /* Priority        */
  NULL,                               /* load()               */
  NULL,                               /* start()              */
  NULL,                               /* stop()               */
  NULL,                               /* unload()             */
  NULL,                               /* on_rx_request()      */
  NULL,                               /* on_rx_response()     */
  &SipTest::on_tx_msg,                /* on_tx_request()      */
  &SipTest::on_tx_msg,                /* on_tx_response()     */
  NULL,                               /* on_tsx_state()       */
};

/// Runs before each test.
SipTest::SipTest(pjsip_module* module) :
  _log_traffic(false)
{
  EXPECT_TRUE(_current_instance == NULL) << "Can't run two SipTests in parallel";
  _current_instance = this;
  _module = module;

  // Call cwtest_completely_control_time to freeze time unless explicitly moved
  // forwards - this prevents spurious failures like, for example, a test taking
  // 1s longer than expected, getting "expires=299" in a Contact header rather
  // than "expires=300", and failing the match.
  cwtest_completely_control_time();
}

/// Runs after each test.
SipTest::~SipTest()
{
  _current_instance = NULL;
  for_each(_out.begin(), _out.end(), pjsip_tx_data_dec_ref);
  // This ensures the UTs clean up: that no test carries over any time it has
  // advanced and that any servers that have been added to the blacklist are
  // removed (and hence operational) by the next test.
  cwtest_reset_time();
  stack_data.sipresolver->clear_blacklist();
}


SipTest::TransportFlow* SipTest::_tp_default;
SipTest* SipTest::_current_instance;
pj_str_t scscf_domain = pj_str("scscf.proxy1.homedomain");
pj_str_t sprout_hostname = pj_str("sprout.homedomain");
pj_str_t sprout_site2_hostname = pj_str("sprout-site2.homedomain");

/// Automatically run once, before the first test.
void SipTest::SetUpTestCase()
{
  // Add the required records to the cache.
  add_host_mapping("sprout.homedomain", "127.0.0.1");
  add_host_mapping("homedomain", "10.6.6.1");
  add_host_mapping("bono1.homedomain", "10.6.6.200");

  stack_data.scscf_uri_str = {NULL, 0};
  stack_data.scscf_uri = NULL;
  stack_data.scscf_contact = {NULL, 0};
  stack_data.pcscf_untrusted_port = 5060;
  stack_data.pcscf_trusted_port = 5058; // NB - pcscf trusted port must be the
  stack_data.scscf_port = 5058;         // same as the scscf port for the UTs
  stack_data.local_host = pj_str("127.0.0.1");
  stack_data.public_host = pj_str("127.0.0.1");
  stack_data.home_domains.insert("homedomain");
  stack_data.home_domains.insert("sprout.homedomain");
  stack_data.home_domains.insert("sprout-site2.homedomain");
  stack_data.default_home_domain = pj_str("homedomain");
  stack_data.enable_orig_sip_to_tel_coerce = true;
  URIClassifier::home_domains.push_back(&stack_data.default_home_domain);
  URIClassifier::home_domains.push_back(&sprout_hostname);
  URIClassifier::home_domains.push_back(&sprout_site2_hostname);
  URIClassifier::home_domains.push_back(&scscf_domain);
  stack_data.cdf_domain = pj_str("cdfdomain");
  stack_data.name = {stack_data.local_host, stack_data.public_host, pj_str("sprout.homedomain")};
  stack_data.record_route_on_initiation_of_originating = true;
  stack_data.record_route_on_completion_of_terminating = true;
  stack_data.default_session_expires = 60 * 10;
  stack_data.max_session_expires = 90 * 10;
  stack_data.addr_family = AF_INET;
  stack_data.sipresolver = new SIPResolver(&_dnsresolver);
  stack_data.sprout_hostname = "sprout.homedomain";

  // Sort out logging.
  init_pjsip_logging(99, false, "");

  // Initialise PJSIP and associated resources.
  init_pjsip();

  // Initialize the PJUtils module.
  PJUtils::init();

  // Set up default UDP transports.
  TransportFlow::udp_transport(stack_data.pcscf_trusted_port);
  TransportFlow::udp_transport(stack_data.pcscf_untrusted_port);
  TransportFlow::udp_transport(stack_data.scscf_port);

  // Get a default TCP transport flow to use for injection.  Give it a dummy address.
  _tp_default = new TransportFlow(TransportFlow::Protocol::TCP,
                                  stack_data.pcscf_trusted_port,
                                  "0.0.0.0",
                                  5060);

  pjsip_endpt_register_module(stack_data.endpt, &mod_siptest);

  // Now we have a pool with PJSIP, we can parse the S-CSCF URI.
  SipTest::SetScscfUri("sip:scscf.sprout.homedomain:5058;transport=TCP");
}

// Replaces the SIP Resolver with one without a graylist. Used by bono_test,
// as bono does not currently support graylisting.
void SipTest::SIPResolverNoGraylist()
{
  delete stack_data.sipresolver;
  stack_data.sipresolver = new SIPResolver(&_dnsresolver, 30, 0);
}

void SipTest::SetScscfUri(const std::string& scscf_uri)
{
  if (stack_data.scscf_uri_str.ptr)
  {
    free(stack_data.scscf_uri_str.ptr);
  }

  stack_data.scscf_uri_str = pj_str(strdup(scscf_uri.c_str()));

  stack_data.scscf_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(scscf_uri.c_str(),
                                                                  stack_data.pool);

  // Need a version of the SCSCF URI in angle brackets for use as contact header.
  if (stack_data.scscf_contact.ptr)
  {
    free(stack_data.scscf_contact.ptr);
  }

  std::string contact_str = "<"+scscf_uri+">";
  stack_data.scscf_contact = pj_str(strdup(contact_str.c_str()));
}

/// Automatically run once, after the last test.
void SipTest::TearDownTestCase()
{
  // Delete the default TCP transport flow.
  delete _tp_default;

  // Terminate the PJUtils module.
  PJUtils::term();

  // Terminate PJSIP
  term_pjsip();

  // Clear out any UDP transports and TCP factories that have been created.
  TransportFlow::reset();

  delete stack_data.sipresolver;

  if (stack_data.scscf_uri_str.ptr)
  {
    free(stack_data.scscf_uri_str.ptr);
  }
  if (stack_data.scscf_contact.ptr)
  {
    free(stack_data.scscf_contact.ptr);
  }
}


DnsCachedResolver SipTest::_dnsresolver("0.0.0.0");
std::map<int, pjsip_transport*> SipTest::TransportFlow::_udp_transports;
std::map<int, pjsip_tpfactory*> SipTest::TransportFlow::_tcp_factories;


void SipTest::TransportFlow::reset()
{
  _udp_transports.clear();
  _tcp_factories.clear();
}

pjsip_transport* SipTest::TransportFlow::udp_transport(int port)
{
  if (_udp_transports[port] == NULL)
  {
    pj_status_t status;
    pj_sockaddr_in addr;
    pjsip_host_port published_name;
    pjsip_transport* udp_tp;

    memset(&addr, 0, sizeof(pj_sockaddr_in));
    addr.sin_family = pj_AF_INET();
    addr.sin_addr.s_addr = 0;
    addr.sin_port = pj_htons((pj_uint16_t)port);

    published_name.host = stack_data.local_host;
    published_name.port = port;

    status = pjsip_fake_udp_transport_start(stack_data.endpt,
                                            &addr,
                                            &published_name,
                                            50,
                                            &udp_tp);
    assert(status == PJ_SUCCESS);
    _udp_transports[port] = udp_tp;
  }

  return _udp_transports[port];
}


pjsip_tpfactory* SipTest::TransportFlow::tcp_factory(int port)
{
  if (_tcp_factories[port] == NULL)
  {
    pj_status_t status;
    pj_sockaddr_in addr;
    pjsip_host_port published_name;
    pjsip_tpfactory* tcp_factory;

    memset(&addr, 0, sizeof(pj_sockaddr_in));
    addr.sin_family = pj_AF_INET();
    addr.sin_addr.s_addr = 0;
    addr.sin_port = pj_htons((pj_uint16_t)port);

    published_name.host = stack_data.local_host;
    published_name.port = port;

    status = pjsip_fake_tcp_transport_start2(stack_data.endpt,
                                             &addr,
                                             &published_name,
                                             50,
                                             &tcp_factory);
    assert(status == PJ_SUCCESS);
    _tcp_factories[port] = tcp_factory;
  }

  return _tcp_factories[port];
}


SipTest::TransportFlow::TransportFlow(Protocol protocol, int local_port, const char* addr, int port)
{
  pj_str_t addr_str = pj_str(const_cast<char*>(addr));
  pj_sockaddr_init(PJ_AF_INET, &_rem_addr, &addr_str, port);

  if (protocol == UDP)
  {
    _transport = udp_transport(local_port);
  }
  else
  {
    pj_status_t status;
    pjsip_tpfactory *factory = tcp_factory(local_port);
    status = pjsip_fake_tcp_accept(factory,
                                   (pj_sockaddr_t*)&_rem_addr,
                                   sizeof(pj_sockaddr_in),
                                   &_transport);
    pjsip_transport_add_ref(_transport);
    EXPECT_EQ(PJ_SUCCESS, status);
  }
}


SipTest::TransportFlow::~TransportFlow()
{
  if (!strcmp(_transport->type_name, "TCP"))
  {
    pjsip_transport_dec_ref(_transport);
    fake_tcp_init_shutdown((fake_tcp_transport*)_transport, PJ_EEOF);
  }
}


std::string SipTest::TransportFlow::type_name()
{
  return std::string(_transport->type_name);
}


int SipTest::TransportFlow::local_port()
{
  return _transport->local_name.port;
}


pjsip_transport* SipTest::TransportFlow::transport()
{
  return _transport;
}


std::string SipTest::TransportFlow::to_string(bool transport)
{
  char buf[100];
  pj_sockaddr_print(&_rem_addr, buf, sizeof(buf), 3);
  if (transport)
  {
    strcat(buf, ";transport=");
    strcat(buf, _transport->type_name);
  }
  return std::string(buf);
}


void SipTest::TransportFlow::expect_target(const pjsip_tx_data* tdata, bool strict)
{
  if (strict)
  {
    EXPECT_EQ(_transport, tdata->tp_info.transport)
      << "Wrong transport: expected " << to_string(true)
      << " / actual " << tdata->tp_info.transport->obj_name
      << " " << tdata->tp_info.transport->info;
  }

  if (!strcmp(_transport->type_name, "UDP"))
  {
    bool remote_addr_eq = (pj_sockaddr_cmp(&_rem_addr, &tdata->tp_info.dst_addr) == 0);
    EXPECT_EQ(remote_addr_eq, true) << "Wrong destination address";
  }
}

void SipTest::terminate_tcp_transport(pjsip_transport* tp)
{
  fake_tcp_init_shutdown((struct fake_tcp_transport*)tp, PJ_SUCCESS);
}

void SipTest::add_host_mapping(const string& hostname, const string& addresses)
{
  // Add the required records to the cache.  Records are added with a very,
  // very long expiry time to avoid test cases that advance time causing
  // problems.
  std::list<string> address_list;
  Utils::split_string(addresses, ',', address_list);
  std::vector<DnsRRecord*> records;
  while (!address_list.empty())
  {
    cwtest_add_host_mapping(hostname, address_list.front());
    struct in_addr addr;
    inet_pton(AF_INET, address_list.front().c_str(), &addr);
    records.push_back((DnsRRecord*)new DnsARecord(hostname, 36000000, addr));
    address_list.pop_front();
  }
  _dnsresolver.add_to_cache(hostname, ns_t_a, records);
}

void SipTest::inject_msg(const string& msg, TransportFlow* tp)
{
  pj_pool_t *rdata_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);
  pjsip_rx_data* rdata = build_rxdata(msg, tp, rdata_pool);
  set_trail(rdata, SAS::new_trail());
  char buf[100];
  snprintf(buf, sizeof(buf), "inject_msg on %p (transport %p)", tp, tp->_transport);
  log_pjsip_buf(buf, rdata->pkt_info.packet, rdata->pkt_info.len);
  pj_size_t size_eaten = pjsip_tpmgr_receive_packet(rdata->tp_info.transport->tpmgr,
                                                    rdata);
  EXPECT_EQ((pj_size_t)rdata->pkt_info.len, size_eaten);
  pj_pool_reset(rdata_pool);
  pj_pool_release(rdata_pool);
}

void SipTest::inject_msg(pjsip_msg* msg, TransportFlow* tp)
{
  char buf[16384];
  pj_ssize_t len = pjsip_msg_print(msg, buf, sizeof(buf));
  inject_msg(string(buf, len), tp);
}

void SipTest::inject_msg_failure(const string& msg, TransportFlow* tp, int expected)
{
  pj_pool_t *rdata_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);
  pjsip_rx_data* rdata = build_rxdata(msg, tp, rdata_pool);
  set_trail(rdata, SAS::new_trail());
  char buf[100];
  snprintf(buf, sizeof(buf), "inject_msg on %p (transport %p)", tp, tp->_transport);
  log_pjsip_buf(buf, rdata->pkt_info.packet, rdata->pkt_info.len);
  pj_size_t size_eaten = pjsip_tpmgr_receive_packet(rdata->tp_info.transport->tpmgr,
                                                    rdata);
  EXPECT_EQ((pj_size_t)expected, size_eaten);
  pj_pool_reset(rdata_pool);
  pj_pool_release(rdata_pool);
}


/// Inject message directly into the registrar module, bypassing other
/// layers.  Allows testing which messages we accept into the module.
pj_bool_t SipTest::inject_msg_direct(const string& msg, pjsip_module* module)
{
  pjsip_rx_data* rdata = build_rxdata(msg);
  parse_rxdata(rdata);
  pj_bool_t ret = module->on_rx_request(rdata);
  return ret;
}

pjsip_rx_data* SipTest::build_rxdata(const string& msg, TransportFlow* tp, pj_pool_t* rdata_pool)
{
  pjsip_rx_data* rdata = PJ_POOL_ZALLOC_T(stack_data.pool, pjsip_rx_data);

  if (rdata_pool == NULL)
  {
    rdata_pool = stack_data.pool;
  }

  // Init transport info part.
  rdata->tp_info.pool = rdata_pool;
  rdata->tp_info.transport = tp->_transport;
  rdata->tp_info.tp_data = NULL;
  rdata->tp_info.op_key.rdata = rdata;
  pj_ioqueue_op_key_init(&rdata->tp_info.op_key.op_key,
                         sizeof(pj_ioqueue_op_key_t));

  // Copy in message bytes.
  rdata->pkt_info.packet = (char*)pj_pool_alloc(rdata->tp_info.pool, strlen(msg.data()) + 1);
  strcpy(rdata->pkt_info.packet, msg.data());
  rdata->pkt_info.len = msg.length();

  // Fill in packet info part.
  rdata->pkt_info.src_addr = tp->_rem_addr;
  rdata->pkt_info.src_addr_len = sizeof(rdata->pkt_info.src_addr);
  pj_sockaddr* rem_addr = &tp->_rem_addr;
  pj_sockaddr_print(rem_addr, rdata->pkt_info.src_name,
                    sizeof(rdata->pkt_info.src_name), 0);
  rdata->pkt_info.src_port = pj_sockaddr_get_port(rem_addr);

  pj_gettimeofday(&rdata->pkt_info.timestamp);

  return rdata;
}

void SipTest::parse_rxdata(pjsip_rx_data* rdata)
{
  // Parse message.
  pj_bzero(&rdata->msg_info, sizeof(rdata->msg_info));
  pj_list_init(&rdata->msg_info.parse_err);
  rdata->msg_info.msg = pjsip_parse_rdata(rdata->pkt_info.packet, rdata->pkt_info.len, rdata);
  if (!pj_list_empty(&rdata->msg_info.parse_err))
  {
    // Parse error!  See sip_transport.c
    /* Gather syntax error information */
    pjsip_parser_err_report* err = rdata->msg_info.parse_err.next;
    while (err != &rdata->msg_info.parse_err)
    {
      printf("%s exception when parsing '%.*s' "
             "header on line %d col %d\n",
             pj_exception_id_name(err->except_code),
             (int)err->hname.slen, err->hname.ptr,
             err->line, err->col);
      err = err->next;
    }
    throw runtime_error("PJSIP parse error");
  }

  if (rdata->msg_info.msg == NULL)
  {
    throw runtime_error("PJSIP parse failed");
  }

  // Perform basic header checking.
  EXPECT_FALSE(rdata->msg_info.cid == NULL ||
               rdata->msg_info.cid->id.slen == 0 ||
               rdata->msg_info.from == NULL ||
               rdata->msg_info.to == NULL ||
               rdata->msg_info.via == NULL ||
               rdata->msg_info.cseq == NULL);

  // Fill in VIA.
  if (rdata->msg_info.msg->type == PJSIP_REQUEST_MSG)
  {
    pj_strdup2(rdata->tp_info.pool,
               &rdata->msg_info.via->recvd_param,
               rdata->pkt_info.src_name);

    if (rdata->msg_info.via->rport_param == 0)
    {
      rdata->msg_info.via->rport_param = rdata->pkt_info.src_port;
    }
  }
  else
  {
    EXPECT_FALSE(rdata->msg_info.msg->line.status.code < 100 ||
                 rdata->msg_info.msg->line.status.code >= 700) << rdata->msg_info.msg->line.status.code;
  }
}

pjsip_msg* SipTest::parse_msg(const std::string& msg)
{
  pjsip_rx_data* rdata = build_rxdata(msg);
  parse_rxdata(rdata);
  return rdata->msg_info.msg;
}

pj_status_t SipTest::on_tx_msg(pjsip_tx_data* tdata)
{
  _current_instance->handle_txdata(tdata);
  return PJ_SUCCESS;
}

void SipTest::handle_txdata(pjsip_tx_data* tdata)
{
  pjsip_tx_data_add_ref(tdata);
  _out.push_back(tdata);
  char buf[100];
  snprintf(buf, sizeof(buf), "handle_txdata on %p", tdata->tp_info.transport);
  log_pjsip_msg(buf, tdata->msg);
}

/// Extract a named header as a C++ string.
std::string get_headers(pjsip_msg* msg, std::string name)
{
  pj_str_t name_str = { const_cast<char*>(name.data()), (unsigned int)name.length() };
  std::string ret;
  pjsip_hdr* hdr = NULL;

  while (NULL != (hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(msg, &name_str, hdr)))
  {
    char buf[1024];
    int n = pjsip_hdr_print_on(hdr, buf, sizeof(buf));
    EXPECT_LT(n, (int)sizeof(buf));
    if (!ret.empty())
    {
      ret.append("\r\n");
    }
    ret.append(buf, n);
    hdr = hdr->next;
  }

  return ret;
}

void SipTest::log_pjsip_buf(const char* description, const char* buf, int len)
{
  if (_log_traffic)
  {
    printf("== %s:\n%.*s==\n", description, len, buf);
  }
}

void SipTest::log_pjsip_msg(const char* description, pjsip_msg* msg)
{
  if (_log_traffic)
  {
    char buf[16384];
    if (msg)
    {
      pj_ssize_t len = pjsip_msg_print(msg, buf, sizeof(buf));
      buf[len] = '\0';
    }
    else
    {
      strcpy(buf, "(null)\n");
    }
    printf("== %s:\n%s==\n", description, buf);
  }
}

void SipTest::register_uri(SubscriberDataManager* sdm,
                           FakeHSSConnection* hss,
                           const std::string& user,
                           const std::string& domain,
                           const std::string& contact,
                           int lifetime,
                           std::string instance_id,
                           bool emergency)
{
  string uri("sip:");
  uri.append(user).append("@").append(domain);
  if (hss)
  {
    hss->set_impu_result(uri, "call", RegDataXMLUtils::STATE_REGISTERED, "");
  }
  AoRPair* aor = sdm->get_aor_data(uri, 0);
  AoR::Binding* binding = aor->get_current()->get_binding(contact);
  binding->_uri = contact;
  binding->_cid = "1";
  binding->_cseq = 1;
  binding->_expires = time(NULL) + lifetime;
  binding->_priority = 1000;
  binding->_emergency_registration = emergency;
  if (!instance_id.empty())
  {
    binding->_params["+sip.instance"] = instance_id;
  }
  AssociatedURIs associated_uris = {};
  associated_uris.add_uri(uri, false);
  bool ret = sdm->set_aor_data(uri, SubscriberDataManager::EventTrigger::ADMIN, aor, 0);
  delete aor;
  EXPECT_TRUE(ret);
};

pjsip_tx_data* SipTest::current_txdata()
{
  return _out.empty() ? NULL : _out.front();
}

void SipTest::free_txdata()
{
  if (!_out.empty())
  {
    pjsip_tx_data_dec_ref(_out.front());
    _out.pop_front();
  }
}

pjsip_tx_data* SipTest::pop_txdata()
{
  pjsip_tx_data* tdata = NULL;
  if (!_out.empty())
  {
    tdata = _out.front();
    _out.pop_front();
  }
  return tdata;
}

int SipTest::txdata_count()
{
  return _out.size();
}

pjsip_tx_data* SipTest::create_response(pjsip_tx_data* tdata, int st_code, const pj_str_t* st_text)
{
  // First, turn the message around to become a received message.
  pjsip_rx_data* rdata = PJ_POOL_ZALLOC_T(stack_data.pool, pjsip_rx_data);

  /* Initialize rdata. */
  rdata->tp_info.pool = stack_data.pool;
  rdata->tp_info.transport = tdata->tp_info.transport;

  /* Copy the packet. */
  rdata->pkt_info.len = tdata->buf.cur - tdata->buf.start;
  rdata->pkt_info.packet = (char*)pj_pool_alloc(rdata->tp_info.pool, rdata->pkt_info.len + 1);
  pj_memcpy(rdata->pkt_info.packet, tdata->buf.start, rdata->pkt_info.len);

  /* the source address */
  rdata->pkt_info.src_addr = tdata->tp_info.dst_addr;

  /* "Source address" info. */
  rdata->pkt_info.src_addr_len = tdata->tp_info.dst_addr_len;
  memcpy(rdata->pkt_info.src_name, tdata->tp_info.dst_name, sizeof(tdata->tp_info.dst_name));
  rdata->pkt_info.src_port = tdata->tp_info.dst_port;

  /* When do we need to "deliver" this packet. */
  pj_gettimeofday(&rdata->pkt_info.timestamp);

  // Parse it.
  parse_rxdata(rdata);

  // Now, create a response.
  pjsip_tx_data* tdata_out;
  pjsip_endpt_create_response(stack_data.endpt, rdata, st_code, st_text, &tdata_out);
  pjsip_tx_data_add_ref(tdata_out);

  // Now, return the resulting message.
  return tdata_out;
}

string SipTest::respond_to_current_txdata(int st_code, string body, string extra)
{
  string ret = respond_to_txdata(current_txdata(), st_code, body, extra);
  free_txdata();
  return ret;
}

std::string SipTest::respond_to_txdata(pjsip_tx_data* tdata, int st_code, string body, string extra)
{
  char buf[16384];
  pjsip_tx_data* resp = (st_code != SIP_STATUS_FLOW_FAILED) ?
                         create_response(tdata, st_code, NULL) :
                         create_response(tdata, st_code, &SIP_REASON_FLOW_FAILED);
  pj_ssize_t len = pjsip_msg_print(resp->msg, buf, sizeof(buf));
  string ret(buf, len - 2);
  pjsip_tx_data_dec_ref(resp);

  if (!extra.empty())
  {
    ret.append(extra).append("\r\n");
  }

  if (!body.empty())
  {
    ret.resize(ret.size() - string("Content-Length:  0\r\n").size());
    ret.append("Content-Type: text/plain\r\n");
    ret.append("Content-Length:  ").append(boost::lexical_cast<string>(body.size())).append("\r\n");
  }
  ret.append("\r\n");
  ret.append(body);

  return ret;
}

void SipTest::poll()
{
  pj_time_val delay = { 0, 1 }; // one millisecond (zero seems to open up some
                                // race conditions that result in double memory
                                // free errors/corruption).
  unsigned count;
  do
  {
    pj_status_t status = pjsip_endpt_handle_events2(stack_data.endpt, &delay, &count);
    TRC_INFO("Poll found %d events, status %d", (int)count, (int)status);
  }
  while (count != 0);
}


string SipTest::timestamp()
{
  pj_time_val tv;
  pj_gettimeofday(&tv);
  pj_parsed_time pt;
  pj_time_decode(&tv, &pt);
  char buf[1000];
  snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d", pt.hour, pt.min, pt.sec, pt.msec);
  return buf;
}


/// Copy of structure from sip_transaction.c. Nasty but required.
struct mod_tsx_layer_t {
  struct pjsip_module  mod;
  pj_pool_t           *pool;
  pjsip_endpoint      *endpt;
  pj_mutex_t          *mutex;
  pj_hash_table_t     *htable;
};

void SipTest::expect_all_tsx_done()
{
  list<pjsip_transaction*> tsxs = get_all_tsxs();
  for (list<pjsip_transaction*>::iterator it = tsxs.begin();
       it != tsxs.end();
       ++it)
  {
    EXPECT_GE((*it)->state, PJSIP_TSX_STATE_COMPLETED);
  }
}

list<pjsip_transaction*> SipTest::get_all_tsxs()
{
  list<pjsip_transaction*> ret;

  mod_tsx_layer_t* mod_tsx_layer = (mod_tsx_layer_t*)pjsip_tsx_layer_instance();
  pj_hash_table_t* htable = mod_tsx_layer->htable;
  pj_hash_iterator_t itbuf, *it;
  pj_mutex_lock(mod_tsx_layer->mutex);
  it = pj_hash_first(htable, &itbuf);
  while (it != NULL)
  {
    pjsip_transaction* tsx = (pjsip_transaction*)pj_hash_this(htable, it);
    ret.push_back(tsx);
    it = pj_hash_next(htable, it);
  }
  pj_mutex_unlock(mod_tsx_layer->mutex);
  return ret;
}

void SipTest::terminate_all_tsxs(int status_code)
{
  // Terminates all the unterminated transactions.  This has to be done
  // by scanning for the first unterminated transaction and terminating it,
  // until there are no unterminated transactions left in the list.  This is
  // because it is possible for terminating one transaction to kick off a
  // retry.
  TRC_DEBUG("Terminate outstanding transactions");
  mod_tsx_layer_t* mod_tsx_layer = (mod_tsx_layer_t*)pjsip_tsx_layer_instance();
  pj_hash_table_t* htable = mod_tsx_layer->htable;

  while (true)
  {
    // Scan through the list of transactions until we find an unterminated one.
    pj_hash_iterator_t itbuf;
    pj_mutex_lock(mod_tsx_layer->mutex);
    pjsip_transaction* tsx = NULL;
    for (pj_hash_iterator_t* it = pj_hash_first(htable, &itbuf);
         it != NULL;
         it = pj_hash_next(htable, it))
    {
      tsx = (pjsip_transaction*)pj_hash_this(htable, it);
      if ((tsx->state != PJSIP_TSX_STATE_TERMINATED) &&
          (tsx->state != PJSIP_TSX_STATE_DESTROYED))
      {
        break;
      }
      tsx = NULL;
    }
    pj_mutex_unlock(mod_tsx_layer->mutex);

    if (tsx == NULL)
    {
      // No more unterminated transactions.
      break;
    }

    pjsip_tsx_terminate(tsx, status_code);
  }
  pj_mutex_unlock(mod_tsx_layer->mutex);
}


void SipTest::expect_target(const char* type_name, const char* addr, int port, pjsip_tx_data* tdata)
{
  // Goes to the right place.  It's OK to test the remote host like
  // this because our fake TCP transport (like the real PJSIP one)
  // gets the sockaddr from the socket and converts it to a string for
  // this PJSIP field.
  pjsip_transport* tp = tdata->tp_info.transport;
  EXPECT_STREQ(type_name, tp->type_name) << "Wrong transport type " << tp;
  EXPECT_EQ(addr, str_pj(tp->remote_name.host)) << "Wrong transport address " << tp;
  EXPECT_EQ(port, tp->remote_name.port) << "Wrong transport port " << tp;
}

std::ostream& operator<<(std::ostream& os, const PjStatus& pj)
{
  char buf[256];
  pj_str_t err = pj_strerror(pj._rc, buf, sizeof(buf));
  os << str_pj(err);
  return os;
}

std::ostream& operator<<(std::ostream& os, const PjMsg& msg)
{
  char buf[16384];
  pj_ssize_t len = pjsip_msg_print(msg._msg, buf, sizeof(buf));
  os << string(buf,len);
  return os;
}

std::ostream& operator<<(std::ostream& os, const DumpList& that)
{
  os << that._title << std::endl;
  for (std::list<string>::const_iterator iter = that._list.begin(); iter != that._list.end(); ++iter)
  {
    os << "  " << *iter << std::endl;
  }
  return os;
}

void MsgMatcher::matches(pjsip_msg* msg)
{
  if (_expected_body != "")
  {
    char buf[16384];
    int n = msg->body->print_body(msg->body, buf, sizeof(buf));
    string body(buf, n);
    EXPECT_EQ(_expected_body, body) << PjMsg(msg);
  }
}

void MsgMatcher::body_regex_matches(pjsip_msg* msg)
{
  if (_body_regex != "")
  {
    char buf[16384];
    int n = msg->body->print_body(msg->body, buf, sizeof(buf));
    string body(buf, n);
    EXPECT_THAT(body, testing::MatchesRegex(_body_regex));
  }
}

void ReqMatcher::matches(pjsip_msg* msg)
{
  ASSERT_EQ(PJSIP_REQUEST_MSG, msg->type) << PjMsg(msg);
  EXPECT_EQ(_method, str_pj(msg->line.req.method.name)) << PjMsg(msg);
  MsgMatcher::matches(msg);
  _uri = str_uri(msg->line.req.uri);
}

void RespMatcher::matches(pjsip_msg* msg)
{
  ASSERT_EQ(PJSIP_RESPONSE_MSG, msg->type);
  EXPECT_EQ(_status, msg->line.status.code);
  std::string reason(msg->line.status.reason.ptr, msg->line.status.reason.slen);
  EXPECT_EQ(_reason, reason);

  MsgMatcher::matches(msg);
}
