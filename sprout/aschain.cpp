/**
 * @file aschain.cpp The AS chain data type.
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


#include "log.h"
#include "pjutils.h"

#include "constants.h"
#include "stateful_proxy.h"
#include "aschain.h"

AsChain::AsChain(AsChainTable* as_chain_table,
                 const SessionCase& session_case,
                 std::string served_user,
                 bool is_registered,
                 std::vector<std::string> application_servers) :
  _as_chain_table(as_chain_table),
  _odi_token(_as_chain_table->register_(this)),
  _session_case(session_case),
  _served_user(served_user),
  _is_registered(is_registered),
  _application_servers(application_servers)
{
}

AsChain::~AsChain()
{
  _as_chain_table->unregister(_odi_token);
}

std::string AsChain::to_string() const
{
  return _session_case.to_string();
}

/// @returns the session case
const SessionCase& AsChain::session_case() const
{
  return _session_case;
}

std::string AsChain::odi_token() const
{
  return _odi_token;
}

/// Apply first AS (if any) to initial request.
//
// @Returns whether processing should stop, continue, or skip to the end.
AsChain::Disposition AsChain::on_initial_request(CallServices* call_services,
                                                 UASTransaction* uas_data,
                                                 pjsip_msg* msg,
                                                 pjsip_tx_data* tdata,
                                                 // OUT: target to
                                                 // use, if
                                                 // disposition is
                                                 // Skip. Dynamically
                                                 // allocated, to be
                                                 // freed by caller.
                                                 target** pre_target)
{
  // @@@ KSW do the indexed AS, and advance the index. Assert that we
  // are never called if complete().

  if (call_services && is_mmtel(call_services))
  {
    // LCOV_EXCL_START No test coverage for MMTEL AS yet.
    if (_session_case.is_originating())
    {
      LOG_DEBUG("Invoke originating MMTEL services");
      CallServices::Originating originating(call_services, uas_data, msg, served_user());
      bool proceed = originating.on_initial_invite(tdata);
      return proceed ? AsChain::Disposition::Next : AsChain::Disposition::Stop;
    }
    else
    {
      // MMTEL terminating call services need to insert themselves into
      // the signalling path.
      LOG_DEBUG("Invoke terminating MMTEL services");
      CallServices::Terminating* terminating =
        new CallServices::Terminating(call_services, uas_data, msg, served_user());
      uas_data->register_proxy(terminating);
      bool proceed = terminating->on_initial_invite(tdata);
      return proceed ? AsChain::Disposition::Next : AsChain::Disposition::Stop;
    }
    // LCOV_EXCL_STOP
  }
  else if (!_application_servers.empty())
  {
    // Temporary code, supporting only one application server.
    std::string as_uri_str = _application_servers[0];

    // @@@ KSW This parsing, and ensuring it succeeds, should happen in ifchandler.
    pjsip_sip_uri* as_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(as_uri_str, tdata->pool);
    LOG_DEBUG("Invoking external AS %s", PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)as_uri).c_str());

    // Basic support for P-Asserted-Identity: strip any header(s) we've
    // received, and set up to be the same as the From header. Full support will
    // be added under sto125.
    pj_str_t pai_str = PJUtils::uri_to_pj_str(PJSIP_URI_IN_FROMTO_HDR,
                                              PJSIP_MSG_FROM_HDR(tdata->msg)->uri,
                                              tdata->pool);
    PJUtils::set_generic_header(tdata, &STR_P_ASSERTED_IDENTITY, &pai_str);

    // Set P-Served-User, including session case and registration
    // state, per RFC5502 and the extension in 3GPP TS 24.229
    // s7.2A.15, following the description in 3GPP TS 24.229 5.4.3.2
    // step 5 s5.4.3.3 step 4c.
    std::string psu_string = "<" + _served_user + ">;sescase=" + _session_case.to_string();
    if (_session_case != SessionCase::OriginatingCdiv)
    {
      psu_string.append(";regstate=");
      psu_string.append(_is_registered ? "reg" : "unreg");
    }
    pj_str_t psu_str = pj_strdup3(tdata->pool, psu_string.c_str());
    PJUtils::set_generic_header(tdata, &STR_P_SERVED_USER, &psu_str);

    // Unless this is the last AS in the chain, we don't want to allow
    // the AS to fork the request - otherwise things will get very
    // confused! Not required by 3GPP TS 24.229, but appears in
    // MSF-IA-SIP.017 s3.2.17.
    // @@@ KSW only do this if we're not the last in the chain.
    PJUtils::set_generic_header(tdata, &STR_REQUEST_DISPOSITION, &STR_NO_FORK);

    // Start defining the new target.
    target* as_target = new target;
    as_target->from_store = false;
    as_target->transport = NULL;

    // Request-URI should remain unchanged
    as_target->uri = tdata->msg->line.req.uri;

    // Set the AS URI as the topmost route header.  Set loose-route,
    // otherwise the headers get mucked up.
    as_uri->lr_param = 1;
    as_target->paths.push_back((pjsip_uri*)as_uri);

    // Insert route header below it with an ODI in it.
    pjsip_sip_uri* self_uri = pjsip_sip_uri_create(tdata->pool, false);  // sip: not sips:
    std::string odi_value = PJUtils::pj_str_to_string(&STR_ODI_PREFIX) + _odi_token;
    pj_strdup2(tdata->pool, &self_uri->user, odi_value.c_str());
    self_uri->host = stack_data.local_host;
    self_uri->port = stack_data.trusted_port;
    self_uri->transport_param = as_uri->transport_param;  // Use same transport as AS, in case it can only cope with one.
    self_uri->lr_param = 1;

    if (_session_case.is_originating())
    {
      // @@@ Until we have proper AS chain processing, we need to put
      // the session case into the ODI URI.
      pjsip_param *orig_param = PJ_POOL_ALLOC_T(tdata->pool, pjsip_param);
      pj_strdup(tdata->pool, &orig_param->name, &STR_ORIG);
      pj_strdup2(tdata->pool, &orig_param->value, "");
      pj_list_insert_after(&self_uri->other_param, orig_param);
    }

    as_target->paths.push_back((pjsip_uri*)self_uri);

    // Stop processing the chain and send the request out to the AS.
    *pre_target = as_target;
    return AsChain::Disposition::Skip;
  }
  else
  {
    LOG_DEBUG("No application servers configured");
    return AsChain::Disposition::Next;
  }
}


/// See if we should be invoking our MMTEL AS.
// @returns true if we should invoke MMTEL, false if not.
bool AsChain::is_mmtel(CallServices* call_services)
{
  // Check if we're supposed to be supplying local MMTel services
  bool local_mmtel = false;
  for (std::vector<std::string>::const_iterator ii = _application_servers.begin();
       ii < _application_servers.end();
       ii++)
  {
    if (call_services->is_mmtel(*ii))
    {
      LOG_DEBUG("Got local MMTel services");
      local_mmtel = true;
      break;
    }
  }

  return local_mmtel;
}

/// @returns the served user.
std::string AsChain::served_user() const
{
  return _served_user;
}


/// @returns true if this AS chain has been completed (no ASs left), false otherwise.
bool AsChain::complete() const
{
  return _application_servers.empty();
}


std::string AsChainTable::register_(AsChain* as_chain)
{
  std::string token;
  PJUtils::create_random_token(TOKEN_LENGTH, token);
  _t2c_map[token] = as_chain;
  return token;
}


void AsChainTable::unregister(const std::string& token)
{
  _t2c_map.erase(token);
}


AsChain* AsChainTable::lookup(const std::string& token) const
{
  std::map<std::string, AsChain*>::const_iterator it = _t2c_map.find(token);
  return (it == _t2c_map.end()) ? NULL : it->second;
}
