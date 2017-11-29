/**
 * @file sproutletappserver.h  Implementation of the AppServer API based
 *                             on a Sproutlet backend
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SPROUTLETAPPSERVER_H__
#define SPROUTLETAPPSERVER_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "sas.h"
#include "stack.h"
#include "appserver.h"
#include "sproutlet.h"

class SproutletAppServerTsxHelper : public AppServerTsxHelper
{
public:
  /// Constructor.
  SproutletAppServerTsxHelper(SproutletTsxHelper* helper);

  /// Destructor.
  virtual ~SproutletAppServerTsxHelper();

  /// Stores the onward route for this transaction ready to apply to
  /// transaction.
  void store_onward_route(pjsip_msg* req);

  /// Stores the dialog_id from the top Route header, if it is present.
  void store_dialog_id(pjsip_msg* req);

  /// Returns a mutable clone of the original request.  This can be modified
  /// and sent by the application using the send_request call.
  ///
  /// @returns             - A clone of the original request message.
  ///
  virtual pjsip_msg* original_request();

  /// Returns the top Route header from the original incoming request.  This
  /// can be inpsected by the app server, but should not be modified.  Note that
  /// this Route header is removed from the request passed to the app server on
  /// the on_*_request calls.
  ///
  /// @returns             - A pointer to a read-only copy of the top Route
  ///                        header from the received request.
  ///
  virtual const pjsip_route_hdr* route_hdr() const;

  /// Adds the service to the underlying SIP dialog with the specified dialog
  /// identifier.
  ///
  /// @param  dialog_id    - The dialog identifier to be used for this service.
  ///                        If omitted, a default unique identifier is created
  ///                        using parameters from the SIP request.
  ///
  virtual void add_to_dialog(const std::string& dialog_id="");

  /// Returns the dialog identifier for this service.
  ///
  /// @returns             - The dialog identifier attached to this service,
  ///                        either by this ServiceTsx instance
  ///                        or by an earlier transaction in the same dialog.
  virtual const std::string& dialog_id() const;

  /// Creates a new, blank request.  This is typically used when creating
  /// a downstream request to another SIP server as part of handling a
  /// request.
  ///
  /// @returns             - A new, blank request message.
  ///
  virtual pjsip_msg* create_request();

  /// Clones the request.  This is typically used when forking a request if
  /// different request modifications are required on each fork or for storing
  /// off to handle late forking.
  ///
  /// @returns             - The cloned request message.
  /// @param  req          - The request message to clone.
  virtual pjsip_msg* clone_request(pjsip_msg* req);

  /// Clones the message.  This is typically used when we want to keep a
  /// message after calling a destructive method on it.
  ///
  /// @returns             - The cloned message.
  /// @param  msg          - The message to clone.
  virtual pjsip_msg* clone_msg(pjsip_msg* msg);

  /// Create a response from a given request, this response can be passed to
  /// send_response or stored for later.  It may be freed again by passing
  /// it to free_message.
  ///
  /// @returns             - The new response message.
  /// @param  req          - The request to build a response for.
  /// @param  status_code  - The SIP status code for the response.
  /// @param  status_text  - The text part of the status line.
  virtual pjsip_msg* create_response(pjsip_msg* req,
                                     pjsip_status_code status_code,
                                     const std::string& status_text="");

  /// Indicate that the request should be forwarded following standard routing
  /// rules.  Note that, even if other Route headers are added by this AS, the
  /// request will be routed back to the S-CSCF that sent the request in the
  /// first place after all those routes have been visited.
  ///
  /// This function may be called repeatedly to create downstream forks of an
  /// original upstream request and may also be called during response processing
  /// or an original request to create a late fork.  When processing an in-dialog
  /// request this function may only be called once.
  ///
  /// This function may be called while processing initial requests,
  /// in-dialog requests and cancels but not during response handling.
  ///
  /// @returns             - The ID of this forwarded request
  /// @param  req          - The request message to use for forwarding.
  virtual int send_request(pjsip_msg*& req);

  /// Indicate that the response should be forwarded following standard routing
  /// rules.  Note that, if this service created multiple forks, the responses
  /// will be aggregated before being sent downstream.
  ///
  /// This function may be called while handling any response.
  ///
  /// @param  rsp          - The response message to use for forwarding.
  virtual void send_response(pjsip_msg*& rsp);

  /// Cancels a forked INVITE request by sending a CANCEL request.
  ///
  /// @param fork_id       - The identifier of the fork to CANCEL.
  virtual void cancel_fork(int fork_id, int st_code = 0, std::string reason = "");

  /// Frees the specified message.  Received responses or messages that have
  /// been cloned with add_target are owned by the AppServerTsx.  It must
  /// call into ServiceTsx either to send them on or to free them (via this
  /// API).
  ///
  /// @param  msg          - The message to free.
  virtual void free_msg(pjsip_msg*& msg);

  /// Returns the pool corresponding to a message.  This pool can then be used
  /// to allocate further headers or bodies to add to the message.
  ///
  /// @returns             - The pool corresponding to this message.
  /// @param  msg          - The message.
  virtual pj_pool_t* get_pool(const pjsip_msg* msg);

  /// Schedules a timer with the specified identifier and expiry period.
  /// The on_timer_expiry callback will be called back with the timer identity
  /// and context parameter when the timer expires.  If the identifier
  /// corresponds to a timer that is already running, the timer will be stopped
  /// and restarted with the new duration and context parameter.
  ///
  /// @returns             - true/false indicating when the timer is programmed.
  /// @param  context      - Context parameter returned on the callback.
  /// @param  id           - A unique identifier for the timer.
  /// @param  duration     - Timer duration in milliseconds.
  virtual bool schedule_timer(void* context, TimerID& id, int duration);

  /// Cancels the timer with the specified identifier.  This is a no-op if
  /// there is no timer with this identifier running.
  ///
  /// @param  id           - The unique identifier for the timer.
  virtual void cancel_timer(TimerID id);

  /// Queries the state of a timer.
  ///
  /// @returns             - true if the timer is running, false otherwise.
  /// @param  id           - The unique identifier for the timer.
  virtual bool timer_running(TimerID id);

  /// Returns the SAS trail identifier that should be used for any SAS events
  /// related to this service invocation.
  virtual SAS::TrailId trail() const;

private:

  /// Get a URI that routes to this App Server.
  pjsip_sip_uri* get_reflexive_uri(pj_pool_t* pool) const;

  SproutletTsxHelper* _helper;
  pj_pool_t* _pool;
  pjsip_route_hdr _route_set;
  bool _record_routed;
  std::string _rr_param_value;
};

class SproutletAppServerShim : public Sproutlet
{
public:
  /// Called when the system determines the app-server should be invoked for a
  /// received request. The Sproutlet can either return NULL indicating it does
  /// not want to process the request, or create a suitable objext derived from
  /// the SproutletTsx to process the request.
  ///
  /// @param  proxy         - The Sproutlet helper.
  /// @param  alias         - Ignored.
  /// @param  req           - The received request message.
  /// @param  next_hop      - The Sproutlet can use this field to specify a
  ///                         next hop URI when it returns a NULL Tsx.
  /// @param  pool          - The pool for creating the next_hop uri.
  /// @param  trail         - The SAS trail id for the message.
  virtual SproutletTsx* get_tsx(SproutletHelper* helper,
                                const std::string& alias,
                                pjsip_msg* req,
                                pjsip_sip_uri*& next_hop,
                                pj_pool_t* pool,
                                SAS::TrailId trail);

  /// Constructor.
  SproutletAppServerShim(AppServer* app,
                         const int port,
                         const std::string& uri,
                         SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl = NULL,
                         SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl = NULL,
                         const std::string& service_host="");

private:
  AppServer* _app;
};

class SproutletAppServerShimTsx : public SproutletTsx
{
public:
  /// Constructor
  SproutletAppServerShimTsx(SproutletAppServerShim* sproutlet,
                            AppServerTsx* app_tsx);

  /// Destructor
  virtual ~SproutletAppServerShimTsx();

  /// Set the SproutletTsxHelper on the SproutletTsx.
  void set_helper(SproutletTsxHelper* sproutlet_helper);

  /// Called for an initial request (dialog-initiating or out-of-dialog) with
  /// the original received request for the transaction.
  ///
  /// This function stores all but the top Route header from the request, so
  /// they can be restored on any requests sent onward by the AS.
  virtual void on_rx_initial_request(pjsip_msg* req);

  /// Called for an in-dialog request with the original received request for
  /// the transaction.
  virtual void on_rx_in_dialog_request(pjsip_msg* req);

  /// Called with all responses received on the transaction.  If a transport
  /// error or transaction timeout occurs on a downstream leg, this method is
  /// called with a 408 response.
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id);

  /// Called if the original request is cancelled (either by a received
  /// CANCEL request or an error on the inbound transport).
  virtual void on_rx_cancel(int status_code, pjsip_msg* cancel_req);

  /// Called if a programmed timer expires.
  virtual void on_timer_expiry(void* context);

private:
  SproutletAppServerTsxHelper* _app_server_helper;
  AppServerTsx* _app_tsx;
};

#endif

