/**
 * @file sproutletproxy.h  BasicProxy-backed Sproutlet interface definition
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

#ifndef SPROUTLETPROXY_H__
#define SPROUTLETPROXY_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "sas.h"
#include "sproutlet.h"

#include <unordered_map>
#include <list>

class SproutletProxyTsxHelper : public SproutletTsxHelper
{
  typedef uint32_t ForkID;
  typedef std::unordered_map<const pjsip_msg*, pjsip_tx_data*> Clones;
  typedef std::unordered_map<ForkID, pjsip_tx_data*> Requests;
  typedef std::list<pjsip_tx_data*> Responses;

public:
  /// Constructor
  SproutletProxyTsxHelper(pjsip_tx_data* inbound_request,
                          SAS::TrailId trail_id);

  /// Virtual destructor.
  virtual ~SproutletProxyTsxHelper();

  /// Get the dialog ID that should be used for Record-Routing this request.
  /// This value is persisted in the Tsx between calls.
  ///
  /// @returns                 - True if this Sproutlet should be Routed in
  /// @param dialog_id         - The dialog ID to use
  bool record_route_requested(std::string& dialog_id);

  /// Get the collection of forwarded messages.  The items in the collection
  /// are passed to the caller who becomes responsible for their lifetime.
  ///
  /// @param request           - A map of fork_id to tdata for each message.
  void requests(Requests& requests);

  /// Get the list of reponse messages, these responses are in the order they 
  /// should be sent downstream.  The items in the collection are passed to the
  /// caller who becomes responsible for their lifetime.
  ///
  /// Only the last message on this list can be a final response (>=200), if it is
  /// then the requests() set will be empty, if not there will be at least one
  /// request on the list.
  ///
  /// @param response          - The tdata of the response to send.
  void responses(Responses& responses);

  /// This implementation has concrete implementations for all of the virtual
  /// functions from SproutletTsxHelper.  See there for function comments for
  /// the following.
  void add_to_dialog(const std::string& dialog_id="");
  const std::string& dialog_id() const;
  pjsip_msg* clone_request(pjsip_msg* req);
  pjsip_msg* create_response(pjsip_msg* req,
                             pjsip_status_code status_code,
                             const std::string& status_text="");
  int send_request(pjsip_msg*& req);
  void send_response(pjsip_msg*& rsp); 
  void free_msg(pjsip_msg*& msg);
  pj_pool_t* get_pool(const pjsip_msg* msg);
  SAS::TrailId trail() const;

private:
  Clones _clones;
  Requests _requests;
  Responses _responses;
  std::string _dialog_id;
  bool _record_routed;
  bool _final_response_sent;
  ForkID _unique_id;
  SAS::TrailId _trail_id;
};

#endif
