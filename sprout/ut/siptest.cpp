/**
 * @file siptest.cpp UT class for Sprout PJSIP modules.
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
#include "zmq_lvc.h"
#include "statistic.h"
#include "faketransport_udp.hpp"
#include "faketransport_tcp.hpp"
#include "fakelogger.hpp"
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
}

/// Runs after each test.
SipTest::~SipTest()
{
  _current_instance = NULL;
  for_each(_out.begin(), _out.end(), pjsip_tx_data_dec_ref);
}

pjsip_tpfactory* SipTest::_tcp_tpfactory_trusted;
pjsip_transport* SipTest::_udp_tp_trusted;
pjsip_tpfactory* SipTest::_tcp_tpfactory_untrusted;
pjsip_transport* SipTest::_udp_tp_untrusted;
SipTest::TransportFlow* SipTest::_tp_default;
SipTest* SipTest::_current_instance;

/// Automatically run once, before the first test.
void SipTest::SetUpTestCase(bool clear_host_mapping)
{
  FakeLogger _log(false);  // swallow logs during this method

  // Add what we need to the resolver map.
  if (clear_host_mapping)
  {
    cwtest_clear_host_mapping();
  }
  cwtest_add_host_mapping("testnode", "localhost");
  cwtest_add_host_mapping("homedomain", "10.6.6.1");

  stack_data.untrusted_port = 5060;
  stack_data.trusted_port = 5058;
  stack_data.local_host = pj_str("testnode");
  stack_data.home_domain = pj_str("homedomain");
  stack_data.name_cnt = 0;
  stack_data.name[stack_data.name_cnt] = stack_data.local_host;
  stack_data.name_cnt++;

  init_pjsip();

  stack_data.stats_aggregator = new LastValueCache(Statistic::known_stats_count(),
                                                   Statistic::known_stats(),
                                                   10);  // Short period to reduce shutdown delays.

  pjsip_endpt_register_module(stack_data.endpt, &mod_siptest);
}

/// Automatically run once, after the last test.
void SipTest::TearDownTestCase()
{
  FakeLogger _log(false);  // swallow logs during this method
  delete stack_data.stats_aggregator;
  stack_data.stats_aggregator = NULL;
  term_pjsip();
}


/// Initialises a SIP port for both UDP and TCP transports.
void SipTest::init_port(int port, pjsip_transport** udp_tp, pjsip_tpfactory** tcp_factory)
{
  pj_status_t status;
  pj_sockaddr_in addr;
  pjsip_host_port published_name;

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
                                          udp_tp);
  ASSERT_EQ(PJ_SUCCESS, status);

  status = pjsip_fake_tcp_transport_start2(stack_data.endpt,
                                           &addr,
                                           &published_name,
                                           50,
                                           tcp_factory);
  ASSERT_EQ(PJ_SUCCESS, status);
}

void SipTest::init_pjsip()
{
  // Sort out logging:
  init_pjsip_logging(99, false, "");

  // Must init PJLIB first:
  pj_status_t status = pj_init();
  ASSERT_EQ(PJ_SUCCESS, status);

  // Then init PJLIB-UTIL:
  status = pjlib_util_init();
  ASSERT_EQ(PJ_SUCCESS, status);

  // Must create a pool factory before we can allocate any memory.
  pj_caching_pool_init(&stack_data.cp, &pj_pool_factory_default_policy, 0);
  stack_data.pool = pj_pool_create(&stack_data.cp.factory, "unit_test", 4000, 4000, NULL);

  // Create the endpoint.
  status = pjsip_endpt_create(stack_data.pool->factory, NULL, &stack_data.endpt);
  ASSERT_EQ(PJ_SUCCESS, status);

  // Init transaction layer.
  status = pjsip_tsx_layer_init_module(stack_data.endpt);
  ASSERT_EQ(PJ_SUCCESS, status);

  // Initialise the trusted port.
  init_port(stack_data.trusted_port, &_udp_tp_trusted, &_tcp_tpfactory_trusted);

  // Initialise the untrusted port.
  init_port(stack_data.untrusted_port, &_udp_tp_untrusted, &_tcp_tpfactory_untrusted);

  // Set the TCP factory used by Bono to create connections to Sprout.
  stack_data.tcp_factory = _tcp_tpfactory_trusted;

  // Get a default TCP transport flow to use for injection.  Give it a dummy address.
  _tp_default = new TransportFlow(TransportFlow::Protocol::TCP,
                                  TransportFlow::Trust::TRUSTED,
                                  "0.0.0.0",
                                  5060);
}

void SipTest::term_pjsip()
{
  delete _tp_default;
  pjsip_endpt_destroy(stack_data.endpt);
  pj_pool_release(stack_data.pool);
  pj_caching_pool_destroy(&stack_data.cp);
  pj_shutdown();
}

SipTest::TransportFlow::TransportFlow(Protocol protocol, Trust trust, const char* addr, int port)
{
  pj_str_t addr_str = pj_str(const_cast<char*>(addr));
  pj_sockaddr_init(PJ_AF_INET, &_rem_addr, &addr_str, port);

  if (protocol == UDP)
  {
    _transport = (trust == TRUSTED) ? _udp_tp_trusted : _udp_tp_untrusted;
  }
  else
  {
    pj_status_t status;
    pjsip_tpfactory *factory = (trust == TRUSTED) ? _tcp_tpfactory_trusted : _tcp_tpfactory_untrusted;
    status = pjsip_fake_tcp_accept(factory,
                                   (pj_sockaddr_t*)&_rem_addr,
                                   sizeof(pj_sockaddr_in),
                                   &_transport);
    EXPECT_EQ(PJ_SUCCESS, status);
  }
}

SipTest::TransportFlow::~TransportFlow()
{
  if (!strcmp(_transport->type_name, "TCP"))
  {
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

void SipTest::inject_msg(const string& msg, TransportFlow* tp)
{
  pjsip_rx_data* rdata = build_rxdata(msg, tp);
  char buf[100];
  snprintf(buf, sizeof(buf), "inject_msg on %p", tp);
  log_pjsip_buf(buf, rdata->pkt_info.packet, rdata->pkt_info.len);
  pj_size_t size_eaten = pjsip_tpmgr_receive_packet(rdata->tp_info.transport->tpmgr,
                                                    rdata);
  EXPECT_EQ((pj_size_t)rdata->pkt_info.len, size_eaten);
}

void SipTest::inject_msg(pjsip_msg* msg, TransportFlow* tp)
{
  char buf[16384];
  pj_ssize_t len = pjsip_msg_print(msg, buf, sizeof(buf));
  inject_msg(string(buf, len), tp);
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

pjsip_rx_data* SipTest::build_rxdata(const string& msg, TransportFlow* tp)
{
  pjsip_rx_data* rdata = PJ_POOL_ZALLOC_T(stack_data.pool, pjsip_rx_data);

  // Init transport info part.
  rdata->tp_info.pool = stack_data.pool;
  rdata->tp_info.transport = tp->_transport;
  rdata->tp_info.tp_data = NULL;
  rdata->tp_info.op_key.rdata = rdata;
  pj_ioqueue_op_key_init(&rdata->tp_info.op_key.op_key,
                         sizeof(pj_ioqueue_op_key_t));

  // Copy in message bytes.
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
  pj_str_t name_str = { const_cast<char*>(name.data()), name.length() };
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

void SipTest::register_uri(RegData::Store* store, const std::string& user, const std::string& domain, const std::string& contact, int lifetime)
{
  string uri("sip:");
  uri.append(user).append("@").append(domain);
  RegData::AoR* aor = store->get_aor_data(uri);
  RegData::AoR::Binding* binding = aor->get_binding(contact);
  binding->_uri = contact;
  binding->_cid = "1";
  binding->_cseq = 1;
  binding->_expires = time(NULL) + lifetime;
  binding->_priority = 1000;
  bool ret = store->set_aor_data(uri, aor);
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
  pj_memcpy(rdata->pkt_info.packet, tdata->buf.start,
            tdata->buf.cur - tdata->buf.start);
  rdata->pkt_info.len = tdata->buf.cur - tdata->buf.start;

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
  pjsip_tx_data* resp = create_response(tdata, st_code, NULL);
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
  pj_time_val delay = { 0, 0 }; // zero milliseconds
  unsigned count;
  pj_status_t status = pjsip_endpt_handle_events2(stack_data.endpt, &delay, &count);
  LOG_INFO("Poll found %d events, status %d\n", (int)count, (int)status);
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

void MsgMatcher::matches(pjsip_msg* msg)
{
  if (_match_body)
  {
    char buf[16384];
    int n = msg->body->print_body(msg->body, buf, sizeof(buf));
    string body(buf, n);
    EXPECT_EQ(_expected_body, body) << PjMsg(msg);
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
  MsgMatcher::matches(msg);
}
