/**
 * @file sproutletproxy.cpp Sproutlet implementation based on BasicProxy
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

#include "sproutletproxy.h"
#include "pjutils.h"
#include "log.h"

/*****************************************************************************/
/* SproutletProxyTsxHelper specific functions.                               */
/*****************************************************************************/

SproutletProxyTsxHelper::SproutletProxyTsxHelper(pjsip_tx_data* inbound_request,
                                                 SAS::TrailId trail_id) :
  _dialog_id(""),
  _record_routed(false),
  _final_response_sent(false),
  _unique_id(0),
  _trail_id(trail_id)
{
  _clones[inbound_request->msg] = inbound_request;
}

SproutletProxyTsxHelper::~SproutletProxyTsxHelper()
{
  assert(_clones.empty());
  assert(_requests.empty());
  assert(_responses.empty());
}

bool SproutletProxyTsxHelper::record_route_requested(std::string& dialog_id)
{
  if (_record_routed)
  {
    dialog_id = _dialog_id;
    return true;
  }
  else
  {
    return false;
  }
}

void SproutletProxyTsxHelper::requests(std::unordered_map<ForkID, pjsip_tx_data*>& requests)
{
  requests = _requests;
  _requests.clear();
}

void SproutletProxyTsxHelper::responses(std::list<pjsip_tx_data*>& responses)
{
  responses = _responses;
  _responses.clear();
}

/*****************************************************************************/
/* SproutletTsxHelper overloads.                                             */
/*****************************************************************************/

void SproutletProxyTsxHelper::add_to_dialog(const std::string& dialog_id)
{
  if (_record_routed)
  {
    LOG_WARNING("A sproutlet has attempted to add itself to the dialog multiple times, only the last dialog_id will be used");
  }

  _record_routed = true;
  _dialog_id = dialog_id;
}

const std::string& SproutletProxyTsxHelper::dialog_id() const
{
  return _dialog_id;
}

pjsip_msg* SproutletProxyTsxHelper::clone_request(pjsip_msg* req)
{
  // Get the old tdata from the map of clones
  Clones::iterator it = _clones.find(req);
  if (it == _clones.end())
  {
    LOG_WARNING("Sproutlet attempted to clone an unrecognised request");
    return NULL;
  }

  // Clone the tdata and put it back into the map
  pjsip_tx_data* new_tdata = PJUtils::clone_tdata(it->second);
  _clones[new_tdata->msg] = new_tdata;

  return new_tdata->msg;
}

pjsip_msg* SproutletProxyTsxHelper::create_response(pjsip_msg* req,
                                                    pjsip_status_code status_code,
                                                    const std::string& status_text)
{
  // Get the request's tdata from the map of clones
  Clones::iterator it = _clones.find(req);
  if (it == _clones.end())
  {
    LOG_WARNING("Sproutlet attempted to create a response from an unrecognised request");
    return NULL;
  }

  // Clone the tdata and put it back into the map.

  // TODO - This needs the new create_response API that Mike's added to
  // PJUtils, it should fill in the status line with values from the arguments.
#if MIKE_TODO
  pjsip_tx_data* new_tdata = PJUtils::create_response(it->second,
                                                      status_code,
                                                      status_text);

  _clones[new_tdata->msg] = new_tdata;

  return new_tdata->msg;
#endif
  return NULL;
}

int SproutletProxyTsxHelper::send_request(pjsip_msg*& req)
{
  // Check that this actually is a request
  if (req->type != PJSIP_REQUEST_MSG)
  {
    LOG_ERROR("Sproutlet attempted to forward a response as a request");
    return -1;
  }

  // Get the tdata from the map of clones
  Clones::iterator it = _clones.find(req);
  if (it == _clones.end())
  {
    LOG_ERROR("Sproutlet attempted to forward an unrecognised request");
    return -1;
  }

  // If we've already forwarded a final response, we should not forward a
  // request too.
  if (req->line.status.code >= PJSIP_SC_OK)
  {
    _final_response_sent = true;
    if (!_requests.empty())
    {
      LOG_ERROR("Sproutlet sent a final response as well as forwarding downstream");
    }
  }

  // Move the clone out of the clones list.
  _clones.erase(req);

  // We've found the tdata, move it to _requests under a new unique ID.
  ForkID fork_id = _unique_id++;
  _requests[fork_id] = it->second;

  // Finish up
  req = NULL;
  return fork_id;
}

void SproutletProxyTsxHelper::send_response(pjsip_msg*& rsp)
{
  // Check that this actually is a response
  if (rsp->type != PJSIP_RESPONSE_MSG)
  {
    LOG_ERROR("Sproutlet attempted to forward a request as a response");
    return;
  }

  // Get the tdata from the map of clones
  Clones::iterator it = _clones.find(rsp);
  if (it == _clones.end())
  {
    LOG_ERROR("Sproutlet attempted to clone an unrecognised request");
    return;
  }

  // If this is a final response, we should not have a request forwarded too.
  if (rsp->line.status.code >= PJSIP_SC_OK)
  {
    _final_response_sent = true;
    if (!_requests.empty())
    {
      LOG_ERROR("Sproutlet sent a final response as well as forwarding downstream");
    }
  }

  // Move the clone out of the clones list.
  _clones.erase(rsp);

  // We've found the tdata, move it to _responses.
  _responses.push_back(it->second);

  // Finish up
  rsp = NULL;
}

void SproutletProxyTsxHelper::free_msg(pjsip_msg*& msg)
{
  // Get the tdata from the map of clones
  Clones::iterator it = _clones.find(msg);
  if (it == _clones.end())
  {
    LOG_ERROR("Sproutlet attempted to free an unrecognised message");
    return;
  }

  _clones.erase(msg);
  pjsip_tx_data_dec_ref(it->second);

  // Finish up
  msg = NULL;
}

pj_pool_t* SproutletProxyTsxHelper::get_pool(const pjsip_msg* msg)
{
  // Get the tdata from the map of clones
  Clones::iterator it = _clones.find(msg);
  if (it == _clones.end())
  {
    LOG_ERROR("Sproutlet attempted to get the pool for an unrecognised message");
    return NULL;
  }

  return it->second->pool;
}

SAS::TrailId SproutletProxyTsxHelper::trail() const
{
  return _trail_id;
}
