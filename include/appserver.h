/**
 * @file appserver.h  Application Server interface definition
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "sas.h"

/// The AppServer class is an abstract base class used to implement services.                                                                                                                    
/// Derived classes are instantiated during system initialization and 
/// register a service name with Sprout.  Sprout calls the get_context method
/// on an AppServer derived class when
///
/// -  an IFC triggers with ServiceName containing a host name of the form
///    <service_name>.<homedomain>
/// -  a request is received for a dialog where the service previously called
///    add_to_dialog.
///
class AppServer
{
public:
  /// Virtual destructor.
  virtual ~AppServer();

  /// Called when the system determines the service should be invoked for
  /// a received request.  The AppServer can either return NULL indicating it
  /// does not want to process the request, or create a suitable object
  /// derived from the ServiceTransactionContext class to process the request.
  ///
  /// @param  req           - The received request message.
  virtual ServiceTransactionContext* get_context(pjsip_msg* req,
                                                 const std::string& dialog_id) = 0;

protected:
  /// Constructor.
  AppServer(const std::string& service_name);

private:
  /// The name of this service.
  std::string _service_name;
};




/// The ServiceTransactionContext class is an abstract base class used to
/// handle the service-related processing of a single transaction.
///
class ServiceTransactionContext
{
public:
  /// Virtual destructor.
  virtual ~ServiceTransactionContext();

  /// Called with the original received request for the transaction.  Unless
  /// the reject method is called, on return from this method the request will
  /// be forwarded to all targets added using the add_target API, or to
  /// the existing RequestURI if no targets were added.
  ///
  /// @param req           - The received request.
  virtual void on_request(pjsip_msg* req) = 0;

  /// Called with all responses received on the transaction.  If a transport
  /// error or transaction timeout occurs on a downstream leg, this method is
  /// called with a 408 response.  The return value indicates whether the 
  /// response should be forwarded upstream (after suitable consolidation if
  /// the request was forked).
  ///
  /// @returns             - true if the response should be forwarded upstream
  ///                        false if the response should be dropped
  /// @param  rsp          - The received request.
  /// @param  fork_id      - The identity of the downstream fork on which
  ///                        the response was received.
  virtual bool on_response(pjsip_msg* rsp, int fork_id);

  /// Called if the original request is cancelled (either by a received
  /// CANCEL request or an error on the inbound transport).  On return from 
  /// this method the transaction (and any remaining downstream legs) will be
  /// cancelled automatically.
  ///
  /// @param  status_code  - Indicates the reason for the cancellation 
  ///                        (487 for a CANCEL, 408 for a transport error
  ///                        or transaction timeout)
  virtual void on_cancel(int status_code);

protected:
  /// Constructor.
  ServiceTransacionContext(const std::string& service_name,
                           const std::string& dialog_id);

  /// Adds the service to the underlying SIP dialog with the specified dialog
  /// identifier.
  ///
  /// @param  dialog_id    - The dialog identifier to be used for this service.
  ///                        If omitted, a default unique identifier is created
  ///                        using parameters from the SIP request.
  ///
  void add_to_dialog(const std::string& dialog_id="");

  /// Returns the dialog identifier for this service.
  ///
  /// @returns             - The dialog identifier attached to this service,
  ///                        either by this ServiceTransactionContext instance
  ///                        or by an earlier transaction in the same dialog.
  const std::string& dialog_id() const;

  /// Clones the request.  This is typically used when forking a request if
  /// different request modifications are required on each fork.
  ///
  /// @returns             - The cloned request message.
  /// @param  req          - The request message to clone.
  pjsip_msg* clone_request(pjsip_msg* req);

  /// Adds the specified URI as a new target for the request.  If no request
  /// is specified, the originally received request is used.  Each target is
  /// assigned a unique fork identifier, which is passed in with any subsequent
  /// received responses.
  ///
  /// @returns             - The identity of this fork.
  /// @param               - The URI for the new target.
  /// @param               - The request message to use for this fork.  If NULL
  ///                        the original request message is used.
  int add_target(pjsip_uri* request_uri,
                 pjsip_msg* req=NULL);

  /// Rejects the original request with the specified status code and text.
  /// This method can only be called when handling the original request.
  /// Any subsequent rejection of the request must be done by sending a final
  /// response using the send_response method.
  ///
  /// @param  status_code  - The SIP status code to send on the response.
  /// @param  status_text  - The SIP status text to send on the response.  If 
  ///                        omitted, the default status text for the code is
  ///                        used (if this is a standard SIP status code).
  void reject(int status_code,
              const std::string& status_text="");

  /// Sends a provisional or final response to the transaction.  If a final
  /// response is sent on an INVITE transaction that was forked, all forks 
  /// which have not yet responded are cancelled.
  ///
  /// @param  rsp          - The response message to send.
  void send_response(pjsip_msg* rsp);

  /// Returns the SAS trail identifier that should be used for any SAS events
  /// related to this service invocation.
  SAS::TrailId trail() const;

private:

};
