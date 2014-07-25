/**
 * @file sproutletappserver.h  Implementation of the AppServer API based
 *                             on a Sproutlet backend
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

#ifndef SPROUTLETAPPSERVER_H__
#define SPROUTLETAPPSERVER_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "sas.h"
#include "appserver.h"
#include "sproutlet.h"

class SproutletAppServerTsxHelper : public AppServerTsxHelper
{
public:
  /// Constructor
  SproutletAppServerTsxHelper(SproutletTsxHelper* helper) :
                              _helper(helper),
                              _fixed_route(NULL)
  {
  }

  /// Set the Route: header to re-insert on forwarded requests for this
  /// transaction.  May be NULL (e.g. for in-dialog requests).
  inline void set_fixed_route(pjsip_hdr* route)
  {
    _fixed_route = route;
  }

  /// Adds the service to the underlying SIP dialog with the specified dialog
  /// identifier.
  ///
  /// @param  dialog_id    - The dialog identifier to be used for this service.
  ///                        If omitted, a default unique identifier is created
  ///                        using parameters from the SIP request.
  ///
  virtual void add_to_dialog(const std::string& dialog_id="")
  {
    _helper->add_to_dialog(dialog_id);
  }

  /// Returns the dialog identifier for this service.
  ///
  /// @returns             - The dialog identifier attached to this service,
  ///                        either by this ServiceTsx instance
  ///                        or by an earlier transaction in the same dialog.
  virtual const std::string& dialog_id() const
  {
    return _helper->dialog_id();
  }

  /// Clones the request.  This is typically used when forking a request if
  /// different request modifications are required on each fork or for storing
  /// off to handle late forking.
  ///
  /// @returns             - The cloned request message.
  /// @param  req          - The request message to clone.
  virtual pjsip_msg* clone_request(pjsip_msg* req)
  {
    return _helper->clone_request(req);
  }

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
                                     const std::string& status_text="")
  {return _helper->create_response(req, status_code, status_text);}

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
  virtual void send_response(pjsip_msg*& rsp)
  {
    _helper->send_response(rsp);
  }

  /// Frees the specified message.  Received responses or messages that have
  /// been cloned with add_target are owned by the AppServerTsx.  It must
  /// call into ServiceTsx either to send them on or to free them (via this
  /// API).
  ///
  /// @param  msg          - The message to free.
  virtual void free_msg(pjsip_msg*& msg)
  {
    _helper->free_msg(msg);
  }

  /// Returns the pool corresponding to a message.  This pool can then be used
  /// to allocate further headers or bodies to add to the message.
  ///
  /// @returns             - The pool corresponding to this message.
  /// @param  msg          - The message.
  virtual pj_pool_t* get_pool(const pjsip_msg* msg)
  {
    return _helper->get_pool(msg);
  }

  /// Returns the SAS trail identifier that should be used for any SAS events
  /// related to this service invocation.
  virtual SAS::TrailId trail() const
  {
    return _helper->trail();
  }

private:
  SproutletTsxHelper* _helper;
  pjsip_hdr* _fixed_route;
};

class SproutletAppServerShim : public Sproutlet
{
public:
  /// Called when the system determines the app-server should be invoked for a
  /// received request.
  ///
  /// @param  helper        - The service helper to use to perform
  ///                         the underlying service-related processing.
  /// @param  req           - The received request message.
  virtual SproutletTsx* get_tsx(SproutletTsxHelper* helper,
                                pjsip_msg* req);

  /// Constructor.
  SproutletAppServerShim(AppServer* app) :
    Sproutlet("shim-" + app->service_name()),
    _app(app)
  {
  }

private:
  AppServer* _app;
};

class SproutletAppServerShimTsx : public SproutletTsx
{
public:
  /// Constructor
  SproutletAppServerShimTsx(SproutletTsxHelper* sproutlet_helper,
                            SproutletAppServerTsxHelper*& app_server_helper,
                            AppServerTsx* app_tsx) : 
    SproutletTsx(sproutlet_helper),
    _app_server_helper(app_server_helper),
    _app_tsx(app_tsx)
  {
    app_server_helper = NULL;
  }

  /// Destructor
  virtual ~SproutletAppServerShimTsx()
  {
    delete _app_server_helper;
  }

  /// Called for an initial request (dialog-initiating or out-of-dialog) with
  /// the original received request for the transaction.
  ///
  /// This function removes the ODI route header from the request before
  /// passing it to the app server's TsxObject.  The ODI token is passed
  /// to the TsxHelper so that it can put the header back on after the 
  /// message has been processed by the app server.
  virtual void on_initial_request(pjsip_msg* req);

  /// Called for an in-dialog request with the original received request for
  /// the transaction.
  virtual void on_in_dialog_request(pjsip_msg* req)
  {
    _app_tsx->on_initial_request(req);
  }

  /// Called with all responses received on the transaction.  If a transport
  /// error or transaction timeout occurs on a downstream leg, this method is
  /// called with a 408 response.
  virtual void on_response(pjsip_msg* rsp, int fork_id)
  {
    _app_tsx->on_response(rsp, fork_id);
  }

  /// Called if the original request is cancelled (either by a received
  /// CANCEL request or an error on the inbound transport).
  virtual void on_cancel(int status_code)
  {
    _app_tsx->on_cancel(status_code);
  }

private:
  SproutletAppServerTsxHelper* _app_server_helper;
  AppServerTsx* _app_tsx;
};

#endif

