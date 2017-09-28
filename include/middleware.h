/**
 * @file middleware.h  Base middleware class definition.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MIDDLEWARE_H__
#define MIDDLEWARE_H__

extern "C" {
#include <pjsip.h>
}

#include "sproutlet.h"

/// The Middleware class is a base-class designed to be extended by any class
/// wishing to manipulate SIP messages passing between the SproutletWrapper and
/// an applicatio-specific child of SproutletTsx.  The presence of one or more
/// Middleware classes is transparent to both the SproutletWrapper and the
/// SproutletTsx.  This class represents a no-op implementation of a Middleware
/// class, simply passing all calls made against the SproutletTsx interface up
/// to the SproutletTsx object above it, and passing all calls made against the
/// SproutletTsxHelper interface down to the SproutletTsxHelper object below
/// it.  A given Middleware object cannot tell whether the objects above and
/// below it are actually the real SproutletTsx and the SproutletWrapper, or
/// just other Middleware objects, as both present exactly the same interfaces.
///
/// TODO - Should we prevent some of these methods from being overriden?  It
/// isn't obvious why it should be OK to intercept some of these (non-SIP)
/// requests.
///
/// TODO - If we notify a modified initial request up to the SproutletTsx, then
/// we really ought to return copies of this when original_request() is later
/// called.  Seems like this would be easy to get wrong when writing a new
/// middleware layer that modifies initial requests...
///
/// TODO - I've repeated the comments from sproutlet.h against each of the
/// methods from the SproutletTsx and SproutletTsxHelper interfaces.  Probably
/// shouldn't do that.
class Middleware : public SproutletTsx, SproutletTsxHelper
{
public:
  /// Constructor.
  ///
  /// Save off the pointer to the SproutletTsx above this object, and the
  /// SproutletTsxHelper object below it.  Either (or both) may actually be
  /// other Middleware objects.
  Middleware(Sproutlet* sproutlet, SproutletTsx* sproutlet_tsx) :
    SproutletTsx(sproutlet),
    SproutletTsxHelper(),
    _sproutlet(sproutlet),
    _sproutlet_tsx(sproutlet_tsx)
  {
    _sproutlet_tsx->set_helper(this);
  }

  /// Virtual destructor
  virtual ~Middleware() {}

  /////////////////////////////////////////////////////////////////////////////
  //
  // Methods inherited from SproutletTsx
  //
  /////////////////////////////////////////////////////////////////////////////

  /// Called when an initial request (dialog-initiating or out-of-dialog) is
  /// received for the transaction.
  ///
  /// During this function, exactly one of the following functions must be
  /// called, otherwise the request will be rejected with a 503 Server Internal
  /// Error:
  ///
  /// * forward_request() - May be called multiple times
  /// * reject()
  /// * defer_request()
  ///
  /// @param req           - The received initial request.
  virtual void on_rx_initial_request(pjsip_msg* req) override
                                { _sproutlet_tsx->on_rx_initial_request(req); }

  /// Called when an in-dialog request is received for the transaction.
  ///
  /// During this function, exactly one of the following functions must be
  /// called, otherwise the request will be rejected with a 503 Server Internal
  /// Error:
  ///
  /// * forward_request()
  /// * reject()
  /// * defer_request()
  ///
  /// @param req           - The received in-dialog request.
  virtual void on_rx_in_dialog_request(pjsip_msg* req) override
                              { _sproutlet_tsx->on_rx_in_dialog_request(req); }

  /// Called when a request has been transmitted on the transaction (usually
  /// because the service has previously called forward_request() with the
  /// request message.
  ///
  /// @param req           - The transmitted request
  /// @param fork_id       - The identity of the downstream fork on which the
  ///                        request was sent.
  virtual void on_tx_request(pjsip_msg* req, int fork_id) override
                               { _sproutlet_tsx->on_tx_request(req, fork_id); }

  /// Called with all responses received on the transaction.  If a transport
  /// error or transaction timeout occurs on a downstream leg, this method is
  /// called with a 408 response.
  ///
  /// @param  rsp          - The received request.
  /// @param  fork_id      - The identity of the downstream fork on which
  ///                        the response was received.
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id) override
                              { _sproutlet_tsx->on_rx_response(rsp, fork_id); }

  /// Called when a response has been transmitted on the transaction.
  ///
  /// @param  rsp          - The transmitted response.
  virtual void on_tx_response(pjsip_msg* rsp) override
                                       { _sproutlet_tsx->on_tx_response(rsp); }

  /// Called if the original request is cancelled (either by a received
  /// CANCEL request, an error on the inbound transport or a transaction
  /// timeout).  On return from this method the transaction (and any remaining
  /// downstream legs) will be cancelled automatically.  No further methods
  /// will be called for this transaction.
  ///
  /// @param  status_code  - Indicates the reason for the cancellation
  ///                        (487 for a CANCEL, 408 for a transport error
  ///                        or transaction timeout)
  /// @param  cancel_req   - The received CANCEL request or NULL if
  ///                        cancellation was triggered by an error or timeout.
  virtual void on_rx_cancel(int status_code, pjsip_msg* cancel_req) override
                     { _sproutlet_tsx->on_rx_cancel(status_code, cancel_req); }

  /// Called when a timer programmed by the SproutletTsx expires.
  ///
  /// @param  context      - The context parameter specified when the timer
  ///                        was scheduled.
  virtual void on_timer_expiry(void* context) override
                                  { _sproutlet_tsx->on_timer_expiry(context); }

  /////////////////////////////////////////////////////////////////////////////
  //
  // Methods inherited from SproutletTsxHelper
  //
  /////////////////////////////////////////////////////////////////////////////

  /// Set the SproutletTsxHelper below this Middleware object.
  ///
  /// @param  helper       - The sproutlet helper.
  virtual void set_helper(SproutletTsxHelper* helper) override
                                                          { _helper = helper; }

  /// Returns a mutable clone of the original request.  This can be modified
  /// and sent by the Sproutlet using the send_request call.
  ///
  /// @returns             - A clone of the original request message.
  ///
  virtual pjsip_msg* original_request() override
                                        { return _helper->original_request(); }

  /// Sets the transport on the given message to be the same as on the
  /// original incoming request.
  ///
  /// @param  req          - The request message on which to set the
  //                         transport.
  virtual void copy_original_transport(pjsip_msg* req) override
                                     { _helper->copy_original_transport(req); }

  /// Returns the top Route header from the original incoming request.  This
  /// can be inpsected by the Sproutlet, but should not be modified.  Note that
  /// this Route header is removed from the request passed to the Sproutlet on
  /// the on_rx_*_request calls.
  ///
  /// @returns             - A pointer to a read-only copy of the top Route
  ///                        header from the received request.
  ///
  virtual const pjsip_route_hdr* route_hdr() const override
                                               { return _helper->route_hdr(); }

  /// Returns a URI that could be used to route back to the current Sproutlet.
  /// This URI may contain pre-loaded parameters that should not be modified
  /// by the calling code (or the URI may cease to route as expected).
  ///
  /// @returns             - The SIP URI.
  /// @param  pool         - A pool to allocate the URI from.
  virtual pjsip_sip_uri* get_reflexive_uri(pj_pool_t* pool) const override
                                   { return _helper->get_reflexive_uri(pool); }

  /// Check if a given URI would be routed to the current Sproutlet if it was
  /// recieved as the top Route header on a request.  This can be used to
  /// locate a Sproutlet in a Route set.
  ///
  /// If the URI is not a SIP URI, this function returns FALSE.
  ///
  /// @returns             - Whether the URI is reflexive.
  /// @param  uri          - The URI to check.
  virtual bool is_uri_reflexive(const pjsip_uri* uri) const override
                                     { return _helper->is_uri_reflexive(uri); }

  /// Creates a new, blank request.  This is typically used when creating
  /// a downstream request to another SIP server as part of handling a
  /// request.
  ///
  /// @returns             - A new, blank request message.
  ///
  virtual pjsip_msg* create_request() override
                                          { return _helper->create_request(); }

  /// Clones the request.  This is typically used when forking a request if
  /// different request modifications are required on each fork or for storing
  /// off to handle late forking.
  ///
  /// @returns             - The cloned request message.
  /// @param  req          - The request message to clone.
  ///
  virtual pjsip_msg* clone_request(pjsip_msg* req) override
                                        { return _helper->clone_request(req); }

  /// Clones the message.  This is typically used when we want to keep a
  /// message after calling a mutating method on it.
  ///
  /// @returns             - The cloned message.
  /// @param  msg          - The message to clone.
  ///
  virtual pjsip_msg* clone_msg(pjsip_msg* msg) override
                                            { return _helper->clone_msg(msg); }

  /// Create a response from a given request, this response can be passed to
  /// send_response or stored for later.  It may be freed again by passing
  /// it to free_message.
  ///
  /// @returns             - The new response message.
  /// @param  req          - The request to build a response for.
  /// @param  status_code  - The SIP status code for the response.
  /// @param  status_text  - The text part of the status line.
  ///
  virtual pjsip_msg* create_response(pjsip_msg* req,
                                     pjsip_status_code status_code,
                                     const std::string& status_text="") override
  {
    return _helper->create_response(req, status_code, status_text);
  }

  /// Indicate that the request should be forwarded following standard routing
  /// rules.
  ///
  /// This function may be called repeatedly to create downstream forks of an
  /// original upstream request and may also be called during response
  /// processing or an original request to create a late fork.  When processing
  /// an in-dialog request this function may only be called once.
  ///
  /// This function may be called while processing initial requests,
  /// in-dialog requests and cancels but not during response handling
  ///
  /// @param  req          - The request message to use for forwarding.  If
  ///                        NULL the original request message is used.
  /// @param  allowed_host_state
  ///                        Permitted state of hosts when resolving
  ///                        addresses. Values are defined in BaseResolver.
  ///
  virtual int send_request(pjsip_msg*& req, int allowed_host_state) override
                     { return _helper->send_request(req, allowed_host_state); }

  /// Indicate that the response should be forwarded following standard routing
  /// rules.  Note that, if this service created multiple forks, the responses
  /// will be aggregated before being sent downstream.
  ///
  /// This function may be called while handling any response.
  ///
  /// @param  rsp          - The response message to use for forwarding.
  ///
  virtual void send_response(pjsip_msg*& rsp) override
                                               { _helper->send_response(rsp); }

  /// Cancels a forked request.  For INVITE requests, this causes a CANCEL
  /// to be sent, so the Sproutlet must wait for the final response.  For
  /// non-INVITE requests the fork is terminated immediately.
  ///
  /// @param fork_id       - The identifier of the fork to cancel.
  ///
  virtual void cancel_fork(int fork_id, int reason=0) override
                                     { _helper->cancel_fork(fork_id, reason); }

  /// Cancels all pending forked requests by either sending a CANCEL request
  /// (for INVITE requests) or terminating the transaction (for non-INVITE
  /// requests).
  ///
  virtual void cancel_pending_forks(int reason=0) override
                                     { _helper->cancel_pending_forks(reason); }

  /// Returns the current status of a downstream fork, including the
  /// transaction state and whether a timeout or transport error has been
  /// detected on the fork.
  ///
  /// @returns             - ForkState structure containing transaction and
  ///                        error status for the fork.
  /// @param  fork_id      - The identifier of the fork.
  ///
  virtual const ForkState& fork_state(int fork_id) override
                                       { return _helper->fork_state(fork_id); }

  /// Frees the specified message.  Received responses or messages that have
  /// been cloned with add_target are owned by the AppServerTsx.  It must
  /// call into SproutletTsx either to send them on or to free them (via this
  /// API).
  ///
  /// @param  msg          - The message to free.
  ///
  virtual void free_msg(pjsip_msg*& msg) override { _helper->free_msg(msg); }

  /// Returns the pool corresponding to a message.  This pool can then be used
  /// to allocate further headers or bodies to add to the message.
  ///
  /// @returns             - The pool corresponding to this message.
  /// @param  msg          - The message.
  ///
  virtual pj_pool_t* get_pool(const pjsip_msg* msg) override
                                             { return _helper->get_pool(msg); }

  /// Returns a brief one line summary of the message.
  ///
  /// @returns             - Message information
  /// @param  msg          - The message
  ///
  virtual const char* msg_info(pjsip_msg* msg) override
                                             { return _helper->msg_info(msg); }

  /// Schedules a timer with the specified identifier and expiry period.
  /// The on_timer_expiry callback will be called back with the timer identity
  /// and context parameter when the timer expires.  If the identifier
  /// corresponds to a timer that is already running, the timer will be stopped
  /// and restarted with the new duration and context parameter.
  ///
  /// @returns             - true/false indicating when the timer is programmed.
  /// @param  context      - Context parameter returned on the callback.
  /// @param  id           - The unique identifier for the timer.
  /// @param  duration     - Timer duration in milliseconds.
  ///
  virtual bool schedule_timer(void* context, TimerID& id, int duration) override
                     { return _helper->schedule_timer(context, id, duration); }

  /// Cancels the timer with the specified identifier.  This is a no-op if
  /// there is no timer with this identifier running.
  ///
  /// @param  id           - The unique identifier for the timer.
  ///
  virtual void cancel_timer(TimerID id) override { _helper->cancel_timer(id); }

  /// Queries the state of a timer.
  ///
  /// @returns             - true if the timer is running, false otherwise.
  /// @param  id           - The unique identifier for the timer.
  ///
  virtual bool timer_running(TimerID id) override
                                         { return _helper->timer_running(id); }

  /// Returns the SAS trail identifier that should be used for any SAS events
  /// related to this service invocation.
  ///
  virtual SAS::TrailId trail() const override { return _helper->trail(); }

  /// Get the URI that caused us to be routed to this Sproutlet.
  ///
  /// @returns            - The URI that routed to this Sproutlet.
  ///
  /// @param req          - The request we are handling.
  virtual pjsip_sip_uri* get_routing_uri(const pjsip_msg* req) const override
                                      { return _helper->get_routing_uri(req); }

  /// Get a URI that routes to the given named service.
  ///
  /// @returns            - The new URI.
  ///
  /// @param service      - Name of the service to route to.
  /// @param base_uri     - The URI to use as a base when building the next hop
  ///                       URI.
  /// @param pool         - Pool to allocate the URI in.
  virtual pjsip_sip_uri* next_hop_uri(const std::string& service,
                                      const pjsip_sip_uri* base_uri,
                                      pj_pool_t* pool) const override
                     { return _helper->next_hop_uri(service, base_uri, pool); }

  /// Get the local hostname part of a SIP URI.
  ///
  /// @returns            - The local hostname part of the URI.
  ///
  /// @param uri          - The SIP URI.
  virtual std::string get_local_hostname(const pjsip_sip_uri* uri) const override
                                   { return _helper->get_local_hostname(uri); }

protected:
  Sproutlet* _sproutlet;
  SproutletTsx* _sproutlet_tsx;
};

#endif
