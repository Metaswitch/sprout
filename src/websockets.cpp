/**
 * @file websockets.cpp WebSockets class methods.
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <string>
#include <cstring>

#include "stack.h"
#include "log.h"
#include "pjutils.h"
#include "websockets.h"

using websocketpp::server;

static unsigned short ws_port;

//
// mod_ws_transport is the module implementing websockets
//
static pj_bool_t ws_transport_on_start();

pjsip_module mod_ws_transport =
{
  NULL, NULL,                         // prev, next
  pj_str("mod-ws-transport"),         // Name
  -1,                                 // Id
  PJSIP_MOD_PRIORITY_TRANSPORT_LAYER, // Priority
  NULL,                               // load()
  &ws_transport_on_start,             // start()
  NULL,                               // stop()
  NULL,                               // unload()
  NULL,                               // on_rx_request()
  NULL,                               // on_rx_response()
  NULL,                               // on_tx_request()
  NULL,                               // on_tx_response()
  NULL,                               // on_tsx_state()
};

/* Struct ws_transport "inherits" struct pjsip_transport */
struct ws_transport
{
  pjsip_transport	base;
  server::handler::connection_ptr con;
  pjsip_rx_data rdata;
  int			is_closing;
  pj_bool_t		is_paused;
};

/*
 * This callback is called by transport manager to send SIP message
 */
static pj_status_t ws_send_msg(pjsip_transport *transport,
                               pjsip_tx_data *tdata,
                               const pj_sockaddr_t *rem_addr,
                               int addr_len,
                               void *token,
                               pjsip_transport_callback callback)
{
  std::string body(tdata->buf.start);
  TRC_DEBUG("Sending message over WS");

  struct ws_transport *ws = (struct ws_transport*)transport;
  server::handler::connection_ptr con = ws->con;
  con->send(body, websocketpp::frame::opcode::TEXT);

  return PJ_SUCCESS;
}

/*
 * Called by transport manager to shutdown and destroy this transport
 */
static pj_status_t ws_shutdown_transport(pjsip_transport *transport);
static pj_status_t ws_destroy_transport(pjsip_transport *transport);

/*
 * ws_transport_register_type()
 *
 * Register the websocket transport type with PJSIP
 */
int PJSIP_TRANSPORT_WS = -1;
static int ws_transport_register_type(int port)
{
  int type;
  pjsip_transport_register_type(PJSIP_TRANSPORT_RELIABLE,
                                "WS",
                                port,
                                &type);
  return type;
}

/*
 * ws_transport_create()
 *
 * Create pjsip transport object for given websocket connection
 */
static pj_status_t ws_transport_create(pjsip_endpoint *endpt,
                                       server::handler::connection_ptr con,
                                       unsigned async_cnt,
                                       pjsip_transport **p_transport)
{
  pj_pool_t *pool;
  struct ws_transport *tp;
  const char *format;
  pj_status_t status;
  boost::asio::ip::tcp::endpoint remote_endpoint;
  boost::asio::ip::tcp::endpoint local_endpoint;

  /* Object name. */
  format = "ws";

  /* Create pool. */
  pool = pjsip_endpt_create_pool(endpt, format, PJSIP_POOL_LEN_TRANSPORT,
      PJSIP_POOL_INC_TRANSPORT);
  if (!pool)
  {
    return PJ_ENOMEM;
  }

  /* Create the WS transport object. */
  tp = PJ_POOL_ZALLOC_T(pool, struct ws_transport);

  /* Save pool. */
  tp->base.pool = pool;

  pj_memcpy(tp->base.obj_name, pool->obj_name, PJ_MAX_OBJ_NAME);

  /* Init reference counter. */
  status = pj_atomic_create(pool, 0, &tp->base.ref_cnt);
  if (status != PJ_SUCCESS)
  {
    goto on_error;
  }

  /* Init lock. */
  status = pj_lock_create_recursive_mutex(pool, pool->obj_name,
      &tp->base.lock);
  if (status != PJ_SUCCESS)
  {
    goto on_error;
  }

  /* Type name. */
  tp->base.type_name = "WS";
  tp->base.key.type = PJSIP_TRANSPORT_WS;

  /* Keep reference to ws connection */
  tp->con = con;

  ///* Remote address is left zero (except the family) */
  //tp->base.key.rem_addr.addr.sa_family = (pj_uint16_t)pj_AF_INET();

  // Get local and remote IP addresses and ports.  con->get_socket() gets a
  // reference to the underlying boost asio socket object.
  remote_endpoint = con->get_socket().remote_endpoint();
  pj_strdup2(pool, &tp->base.remote_name.host, remote_endpoint.address().to_string().c_str());
  tp->base.remote_name.port = remote_endpoint.port();
  local_endpoint = con->get_socket().local_endpoint();
  pj_strdup2(pool, &tp->base.local_name.host, local_endpoint.address().to_string().c_str());
  tp->base.local_name.port = local_endpoint.port();

  TRC_DEBUG("Incoming connection from %.*s:%d",
            tp->base.remote_name.host.slen,
            tp->base.remote_name.host.ptr,
            tp->base.remote_name.port);

  /* Set up the remote address in the key. */
  /* Don't use pj_sockaddr_init(pj_AF_UNSPEC() ... as it asserts             */
  status = pj_sockaddr_parse(pj_AF_UNSPEC(),
                             0,
                             &tp->base.remote_name.host,
                             &tp->base.key.rem_addr);

  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Failed to parse remote address for transport key");
    goto on_error;
  }

  status = pj_sockaddr_set_port(&tp->base.key.rem_addr, tp->base.remote_name.port);

  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Failed to set port in transport key");
    goto on_error;
  }

  /* Transport flag */
  tp->base.flag = PJSIP_TRANSPORT_RELIABLE;

  /* Length of addressess. */
  tp->base.addr_len = sizeof(tp->base.local_addr);

  /* Init direction */
  tp->base.dir = PJSIP_TP_DIR_NONE;

  /* Set endpoint. */
  tp->base.endpt = endpt;

  /* Transport manager and timer will be initialized by tpmgr */

  /* Set functions. */
  tp->base.send_msg = &ws_send_msg;
  tp->base.do_shutdown = &ws_shutdown_transport;
  tp->base.destroy = &ws_destroy_transport;

  /* This is a permanent transport, so we initialize the ref count
   * to one so that transport manager don't destroy this transport
   * when there's no user!
   */
  pj_atomic_inc(tp->base.ref_cnt);

  /* Register to transport manager. */
  tp->base.tpmgr = pjsip_endpt_get_tpmgr(endpt);
  status = pjsip_transport_register( tp->base.tpmgr, (pjsip_transport*)tp);
  if (status != PJ_SUCCESS)
  {
    goto on_error;
  }

  /* Done. */
  if (p_transport)
  {
    *p_transport = &tp->base;
  }

  PJ_LOG(4,(tp->base.obj_name,
        "Websockets %s started, published address is %.*s:%d",
        pjsip_transport_get_type_desc((pjsip_transport_type_e)tp->base.key.type),
        (int)tp->base.local_name.host.slen,
        tp->base.local_name.host.ptr,
        tp->base.local_name.port));

  return PJ_SUCCESS;

on_error:
  ws_destroy_transport((pjsip_transport*)tp);
  return status;
}

/*
 * Called when we receive a web socket message
 */
static pj_bool_t on_ws_data(ws_transport *ws,
                            server::handler::message_ptr msg)
{
  enum { MAX_IMMEDIATE_PACKET = 10 };

  /* Don't do anything if transport is closing. */
  if (ws->is_closing) {
    ws->is_closing++;
    return PJ_FALSE;
  }

  /* Initialize rdata */
  pj_pool_t *pool;
  pj_sockaddr *rem_addr;

  /* Init rdata */
  pool = pjsip_endpt_create_pool(ws->base.endpt,
      "rtd%p",
      PJSIP_POOL_RDATA_LEN,
      PJSIP_POOL_RDATA_INC);
  if (!pool) {
    TRC_ERROR("Unable to create pool");
    return PJ_ENOMEM;
  }

  ws->rdata.tp_info.pool = pool;

  ws->rdata.tp_info.transport = &ws->base;
  ws->rdata.tp_info.tp_data = ws;
  ws->rdata.tp_info.op_key.rdata = &ws->rdata;

  ws->rdata.pkt_info.src_addr = ws->base.key.rem_addr;
  ws->rdata.pkt_info.src_addr_len = sizeof(ws->rdata.pkt_info.src_addr);
  rem_addr = &ws->base.key.rem_addr;
  pj_sockaddr_print(rem_addr, ws->rdata.pkt_info.src_name,
      sizeof(ws->rdata.pkt_info.src_name), 0);
  ws->rdata.pkt_info.src_port = pj_sockaddr_get_port(rem_addr);

  const char *msg_str = msg->get_payload().c_str();

  if (strlen(msg_str) <= PJSIP_MAX_PKT_LEN)
  {
    ws->rdata.pkt_info.packet = (char*)pj_pool_alloc(ws->rdata.tp_info.pool, strlen(msg_str) + 1);
    size_t p_size = strlen(msg_str) + 1;
    size_t m_size = sizeof(ws->rdata.pkt_info.packet);
    size_t max_chars = std::min(p_size, m_size);
    strncpy(ws->rdata.pkt_info.packet, msg_str, max_chars);
  }
  else
  {
    TRC_ERROR("Dropping incoming websocket message as it is larger than PJSIP_MAX_PKT_LEN, %d", strlen(msg_str));
    return PJ_FALSE;
  }

  pjsip_rx_data *rdata;
  rdata = &ws->rdata;

  /* Init pkt_info part. */
  rdata->pkt_info.len = strlen(msg_str);
  rdata->pkt_info.zero = 0;
  pj_gettimeofday(&rdata->pkt_info.timestamp);

  /* Report the packet to transport manager to be parsed. */
  pj_size_t size_eaten;

  /* Report to transport manager.
   * The transport manager will tell us how many bytes of the packet
   * have been processed (as valid SIP message).
   */
  size_eaten =
    pjsip_tpmgr_receive_packet(rdata->tp_info.transport->tpmgr,
        rdata);

  /* Expect the web socket to pass us complete messages,
   * so transport manager should consume entire message
   */
  pj_assert(size_eaten == (pj_size_t)rdata->pkt_info.len);

  /* Reset pool. */
  pj_pool_reset(rdata->tp_info.pool);

  return PJ_TRUE;
}

static pj_status_t ws_shutdown_transport(pjsip_transport *transport)
{
  TRC_DEBUG("Shutting down WS transport...");
  return PJ_SUCCESS;
}

static pj_status_t ws_destroy_transport(pjsip_transport *transport)
{
  TRC_DEBUG("Destroying WS transport...");
  struct ws_transport *ws = (struct ws_transport*)transport;

  if (ws->rdata.tp_info.pool) {
    pj_pool_release(ws->rdata.tp_info.pool);
    ws->rdata.tp_info.pool = NULL;
  }

  if (ws->base.lock) {
    pj_lock_destroy(ws->base.lock);
    ws->base.lock = NULL;
  }

  if (ws->base.ref_cnt) {
    pj_atomic_destroy(ws->base.ref_cnt);
    ws->base.ref_cnt = NULL;
  }

  if (ws->base.pool) {
    pj_pool_t *pool;
    pool = ws->base.pool;
    ws->base.pool = NULL;
    pj_pool_release(pool);
  }

  PJ_LOG(4,(ws->base.obj_name, "WS transport destroyed normally"));
  return PJ_SUCCESS;
}

/* Setup callbacks for WebSockets events */
class sip_server_handler : public server::handler {
  public:

    void validate(connection_ptr con)
    {
      // The key validation step we need to do is on the subprotocols the
      // client requested.  This should include "sip", in which case we'll
      // select "sip" too.  If "sip" was not offered, we offer nothing and the
      // connection will probably fail.
      TRC_DEBUG("Validating incoming web socket connection");
      const std::vector<std::string>& subprotocols = con->get_subprotocols();
      if (std::find(subprotocols.begin(), subprotocols.end(), SUBPROTOCOL) != subprotocols.end())
      {
        TRC_DEBUG("Client requested subprotocol sip - agreeing");
        con->select_subprotocol("sip");
      }
      else
      {
        // Build a comma-separated list of subprotocols ready to log.
        std::stringstream ss;
        std::copy(subprotocols.begin(), subprotocols.end(), std::ostream_iterator<std::string>(ss, ","));
        std::string str = ss.str();
        if (!str.empty())
        {
          // The above added a trailing comma.  Strip it.
          str = str.substr(0, str.length() - 1);
        }
        TRC_INFO("Client requested subprotocols %s - connection will probably fail", str.c_str());
      }
    }

    void on_open(connection_ptr con) {
      TRC_DEBUG("New web socket connection, creating PJSIP transport");
      pjsip_transport *transport;
      pj_status_t status = ws_transport_create(stack_data.endpt,
          con,
          50,
          &transport);
      if (status == PJ_SUCCESS){
        TRC_DEBUG("Created WS transport");
      }
      else{
        TRC_DEBUG("Failed to create WS transport");
      }

      connectionMap.insert(
          std::pair<connection_ptr, struct ws_transport*>(con, (struct ws_transport*)transport));
    }

    void on_message(connection_ptr con, message_ptr msg) {
      ws_transport *transport;

      TRC_DEBUG("Received message from websockets");

      transport = connectionMap.find(con)->second;
      TRC_DEBUG("Sending message to PJSIP...");
      pj_status_t status = on_ws_data(transport, msg);
      if (status == PJ_TRUE){
        TRC_DEBUG("Passed message to PJSIP successfully");
      }
      else{
        TRC_DEBUG("Failed to pass message to PJSIP");
      }
    }

    void on_close(connection_ptr con) {
      ws_transport *transport;
      pjsip_tp_state_callback state_cb;

      TRC_DEBUG("Closing websocket...");
      transport = connectionMap.find(con)->second;

      /* Notify application of transport disconnected state */
      state_cb = pjsip_tpmgr_get_state_cb(transport->base.tpmgr);
      if (state_cb) {
        pjsip_transport_state_info state_info;
        pj_bzero(&state_info, sizeof(state_info));
        state_info.status = PJSIP_ESESSIONTERMINATED;
        (*state_cb)(&transport->base, PJSIP_TP_STATE_DISCONNECTED, &state_info);
      }

      /* Instruct transport manager to gracefully shut down transport */
      pjsip_transport_shutdown(&transport->base);

      /* Finally decrement ref count (to balance initial inc_ref at start of
       * day) to destroy transport
       */
      pjsip_transport_dec_ref(&transport->base);
    }

  private:
    static std::string SUBPROTOCOL;
    std::map<connection_ptr, struct ws_transport*> connectionMap;
};

std::string sip_server_handler::SUBPROTOCOL = "sip";

static int websocket_thread(void* p)
{
  TRC_DEBUG("Started Websockets thread");

  PJSIP_TRANSPORT_WS = ws_transport_register_type(ws_port);
  TRC_DEBUG("Registered websockets transport with PJSIP, type %d", PJSIP_TRANSPORT_WS);
  try {
    server::handler::ptr h(new sip_server_handler());
    server sip_endpoint(h);

    sip_endpoint.alog().unset_level(websocketpp::log::alevel::ALL);
    sip_endpoint.elog().unset_level(websocketpp::log::elevel::ALL);
    sip_endpoint.alog().set_level(websocketpp::log::alevel::CONNECT);
    sip_endpoint.alog().set_level(websocketpp::log::alevel::DISCONNECT);
    sip_endpoint.elog().set_level(websocketpp::log::elevel::RERROR);
    sip_endpoint.elog().set_level(websocketpp::log::elevel::FATAL);

    TRC_DEBUG("Starting WebSocket SIP server on port %hu", ws_port);
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), ws_port);
    sip_endpoint.listen(ep);
  } catch (std::exception& e) {
    TRC_ERROR("Exception: %s", e.what());
  }

  return 0;
}

static pj_bool_t ws_transport_on_start()
{
  // Create thread for websockets and start
  pj_thread_t* thread;
  pj_status_t status;
  status = pj_thread_create(stack_data.pool, "websockets", &websocket_thread,
      NULL, 0, 0, &thread);
  if (status != PJ_SUCCESS)
  {
    TRC_ERROR("Error creating Websockets thread, %s",
        PJUtils::pj_status_to_string(status).c_str());
    return status;
  }

  return PJ_SUCCESS;
}

pj_status_t init_websockets(unsigned short port)
{
  ws_port = port;

  pj_status_t status;
  status = pjsip_endpt_register_module(stack_data.endpt, &mod_ws_transport);
  PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

  return status;
}

void destroy_websockets()
{
  pjsip_endpt_unregister_module(stack_data.endpt, &mod_ws_transport);
}

