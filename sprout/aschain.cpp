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

#include <boost/lexical_cast.hpp>

#include "log.h"
#include "pjutils.h"

#include "constants.h"
#include "stateful_proxy.h"
#include "aschain.h"
#include "ifchandler.h"

AsChain::AsChain(AsChainTable* as_chain_table,
                 const SessionCase& session_case,
                 const std::string& served_user,
                 bool is_registered,
                 std::vector<AsInvocation> application_servers) :
  _as_chain_table(as_chain_table),
  _odi_tokens(),
  _session_case(session_case),
  _served_user(served_user),
  _is_registered(is_registered),
  _application_servers(application_servers)
{
  LOG_DEBUG("Creating AsChain %p", this);
  _as_chain_table->register_(this, _odi_tokens);
}


AsChain::~AsChain()
{
  LOG_DEBUG("Destroying AsChain %p", this);
  _as_chain_table->unregister(_odi_tokens);
}


std::string AsChain::to_string(size_t index) const
{
  return ("AsChain-" + _session_case.to_string() +
          "[" + boost::lexical_cast<std::string>((void*)this) + "]:" +
          boost::lexical_cast<std::string>(index + 1) + "/" + boost::lexical_cast<std::string>(_application_servers.size()));
}


/// @returns the session case
const SessionCase& AsChain::session_case() const
{
  return _session_case;
}


/// @returns the number of elements in this chain
size_t AsChain::size() const
{
  return _application_servers.size();
}


/// @returns whether the given message has the same target as the
// chain.  Used to detect the orig-cdiv case.  Only valid for
// terminating chains.
bool AsChain::matches_target(pjsip_rx_data* rdata) const
{
  pj_assert(_session_case == SessionCase::Terminating);

  // We do not support alias URIs per 3GPP TS 24.229 s3.1 and 29.228
  // sB.2.1. This is an explicit limitation.  So this step reduces to
  // simple syntactic canonicalization.
  //
  // 3GPP TS 24.229 s5.4.3.3 note 3 says "The canonical form of the
  // Request-URI is obtained by removing all URI parameters (including
  // the user-param), and by converting any escaped characters into
  // unescaped form.".
  const std::string& orig_uri = _served_user;
  const std::string msg_uri = IfcHandler::served_user_from_msg(SessionCase::Terminating,
                                                               rdata);
  return (orig_uri == msg_uri);
}


/// Apply first AS (if any) to initial request.
//
// @Returns whether processing should stop, continue, or skip to the end.
AsChainLink::Disposition
AsChainLink::on_initial_request(CallServices* call_services,
                                UASTransaction* uas_data,
                                pjsip_msg* msg,
                                pjsip_tx_data* tdata,
                                // OUT: target to use, if disposition
                                // is Skip. Dynamically allocated, to
                                // be freed by caller.
                                target** pre_target)
{
  if (complete())
  {
    LOG_DEBUG("No ASs left in chain");
    return AsChainLink::Disposition::Next;
  }

  AsInvocation application_server = _as_chain->_application_servers[_index];
  std::string odi_value = PJUtils::pj_str_to_string(&STR_ODI_PREFIX) + next_odi_token();

  if (call_services && call_services->is_mmtel(application_server.server_name))
  {
    // LCOV_EXCL_START No test coverage for MMTEL AS yet.
    if (_as_chain->_session_case.is_originating())
    {
      LOG_DEBUG("Invoke originating MMTEL services");
      CallServices::Originating originating(call_services, uas_data, msg, _as_chain->_served_user);
      bool proceed = originating.on_initial_invite(tdata);
      return proceed ? AsChainLink::Disposition::Next : AsChainLink::Disposition::Stop;
    }
    else
    {
      // MMTEL terminating call services need to insert themselves into
      // the signalling path.
      LOG_DEBUG("Invoke terminating MMTEL services");
      CallServices::Terminating* terminating =
        new CallServices::Terminating(call_services, uas_data, msg,_as_chain->_served_user);
      uas_data->register_proxy(terminating);
      bool proceed = terminating->on_initial_invite(tdata);
      return proceed ? AsChainLink::Disposition::Next : AsChainLink::Disposition::Stop;
    }
    // LCOV_EXCL_STOP
  }
  else
  {
    std::string as_uri_str = application_server.server_name;

    // @@@ KSW This parsing, and ensuring it succeeds, should happen in ifchandler.
    pjsip_sip_uri* as_uri = (pjsip_sip_uri*)PJUtils::uri_from_string(as_uri_str, tdata->pool);
    LOG_DEBUG("Invoking external AS %s with token %s for %s",
              PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR, (pjsip_uri*)as_uri).c_str(),
              odi_value.c_str(),
              to_string().c_str());

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
    std::string psu_string = "<" + _as_chain->_served_user +
                             ">;sescase=" + _as_chain->_session_case.to_string();
    if (_as_chain->_session_case != SessionCase::OriginatingCdiv)
    {
      psu_string.append(";regstate=");
      psu_string.append(_as_chain->_is_registered ? "reg" : "unreg");
    }
    pj_str_t psu_str = pj_strdup3(tdata->pool, psu_string.c_str());
    PJUtils::set_generic_header(tdata, &STR_P_SERVED_USER, &psu_str);

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
    pj_strdup2(tdata->pool, &self_uri->user, odi_value.c_str());
    self_uri->host = stack_data.local_host;
    self_uri->port = stack_data.trusted_port;
    self_uri->transport_param = as_uri->transport_param;  // Use same transport as AS, in case it can only cope with one.
    self_uri->lr_param = 1;

    as_target->paths.push_back((pjsip_uri*)self_uri);

    // Stop processing the chain and send the request out to the AS.
    *pre_target = as_target;
    return AsChainLink::Disposition::Skip;
  }
}


AsChainTable::AsChainTable()
{
  pthread_mutex_init(&_lock, NULL);
}


AsChainTable::~AsChainTable()
{
  pthread_mutex_destroy(&_lock);
}


/// Create the tokens for the given AsChain, and register them to
/// point at the next step in each case.
void AsChainTable::register_(AsChain* as_chain, std::vector<std::string>& tokens)
{
  size_t len = as_chain->size();
  pthread_mutex_lock(&_lock);

  for (size_t i = 0; i < len; i++)
  {
    std::string token;
    PJUtils::create_random_token(TOKEN_LENGTH, token);
    tokens.push_back(token);
    _t2c_map[token] = AsChainLink(as_chain, i + 1);
  }

  pthread_mutex_unlock(&_lock);
}


void AsChainTable::unregister(std::vector<std::string>& tokens)
{
  pthread_mutex_lock(&_lock);

  for (std::vector<std::string>::iterator it = tokens.begin();
       it != tokens.end();
       ++it)
  {
    _t2c_map.erase(*it);
  }

  pthread_mutex_unlock(&_lock);
}


AsChainLink AsChainTable::lookup(const std::string& token)
{
  pthread_mutex_lock(&_lock);
  std::map<std::string, AsChainLink>::const_iterator it = _t2c_map.find(token);
  AsChainLink ret = (it == _t2c_map.end()) ? AsChainLink(NULL, 0) : it->second;
  pthread_mutex_unlock(&_lock);

  return ret;
}
