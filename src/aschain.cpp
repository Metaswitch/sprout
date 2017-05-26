/**
 * @file aschain.cpp The AS chain data type.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <boost/lexical_cast.hpp>

#include "log.h"
#include "pjutils.h"

#include "constants.h"
#include "aschain.h"
#include "ifchandler.h"
#include "sproutsasevent.h"

/// Create an AsChain.
//
// Ownership of `ifcs` passes to this object.
//
// See `AsChainLink::create_as_chain` for rules re releasing the
// created references.
AsChain::AsChain(AsChainTable* as_chain_table,
                 const SessionCase& session_case,
                 const std::string& served_user,
                 bool is_registered,
                 SAS::TrailId trail,
                 Ifcs& ifcs,
                 ACR* acr,
                 DIFCService* difc_service,
                 IFCConfiguration ifc_configuration) :
  _as_chain_table(as_chain_table),
  _refs(1),  // for the initial chain link being returned
  _as_info(ifcs.size() + 1),
  _odi_tokens(),
  _responsive(ifcs.size() + 1),
  _session_case(session_case),
  _served_user(served_user),
  _is_registered(is_registered),
  _trail(trail),
  _ifcs(ifcs),
  _acr(acr),
  _default_ifcs({}),
  _ifc_configuration(ifc_configuration),
  _using_standard_ifcs(true),
  _root(NULL)
{
  TRC_DEBUG("Creating AsChain %p with %d IFCs and adding to map", this, ifcs.size());
  _as_chain_table->register_(this, _odi_tokens);
  TRC_DEBUG("Attached ACR (%p) to chain", _acr);

  // We need to initialize `_responsive` as bools are PODs which are not
  // initialized.
  for(std::vector<bool>::iterator it = _responsive.begin();
      it != _responsive.end();
      ++it)
  {
    *it = false;
  }

  if ((difc_service) && (_ifc_configuration._apply_default_ifcs))
  {
    _root = new rapidxml::xml_document<>;
    _default_ifcs = difc_service->get_default_ifcs(_root);
  }
}


AsChain::~AsChain()
{
  TRC_DEBUG("Destroying AsChain %p", this);

  if (_acr != NULL)
  {
    // Apply application server information to the ACR.
    for (size_t ii = 0; ii < _as_info.size() - 1; ++ii)
    {
      if (!_as_info[ii].as_uri.empty())
      {
        _acr->as_info(_as_info[ii].as_uri,
                      (_as_info[ii+1].request_uri != _as_info[ii].request_uri) ?
                            _as_info[ii+1].request_uri : "",
                      _as_info[ii].status_code,
                      _as_info[ii].timeout);
      }
    }

    // Send the ACR for this chain and destroy the ACR.
    TRC_DEBUG("Sending ACR (%p) from AS chain", _acr);
    _acr->send();
    delete _acr;
  }

  _as_chain_table->unregister(_odi_tokens);

  delete _root; _root = NULL;
}


std::string AsChain::to_string(size_t index) const
{
  return ("AsChain-" + _session_case.to_string() +
          "[" + boost::lexical_cast<std::string>((void*)this) + "]:" +
          boost::lexical_cast<std::string>(index + 1) + "/" + boost::lexical_cast<std::string>(size()));
}


/// @returns the session case
const SessionCase& AsChain::session_case() const
{
  return _session_case;
}


/// @returns the number of elements in this chain
size_t AsChain::size() const
{
  return _using_standard_ifcs ? _ifcs.size() : _default_ifcs.size();
}


/// @returns a pointer to the ACR attached to the AS chain if Rf is enabled.
ACR* AsChain::acr() const
{
  // LCOV_EXCL_START
  return _acr;
  // LCOV_EXCL_STOP
}


SAS::TrailId AsChain::trail() const
{
  return _trail;
}

/// Create a new AsChain and return a link pointing at the start of
// it. Caller MUST eventually call release() when it is finished with the
// AsChainLink.
//
// Ownership of `ifcs` passes to this object.
AsChainLink AsChainLink::create_as_chain(AsChainTable* as_chain_table,
                                         const SessionCase& session_case,
                                         const std::string& served_user,
                                         bool is_registered,
                                         SAS::TrailId trail,
                                         Ifcs& ifcs,
                                         ACR* acr,
                                         DIFCService* difc_service,
                                         IFCConfiguration ifc_configuration)
{
  AsChain* as_chain = new AsChain(as_chain_table,
                                  session_case,
                                  served_user,
                                  is_registered,
                                  trail,
                                  ifcs,
                                  acr,
                                  difc_service,
                                  ifc_configuration);
  return AsChainLink(as_chain, 0u);
}

/// Apply first AS (if any) to initial request.
//
// See 3GPP TS 23.218, especially s5.2 and s6, for an overview of how
// this works, and 3GPP TS 24.229 s5.4.3.2 and s5.4.3.3 for
// step-by-step details.
//
// @Returns whether processing should stop, continue, or skip to the end.
pjsip_status_code AsChainLink::on_initial_request(pjsip_msg* msg,
                                                  std::string& server_name,
                                                  SAS::TrailId msg_trail)
{
  pjsip_status_code rc = PJSIP_SC_OK;
  server_name = "";

  if (_as_chain->trail() != msg_trail)
  {
    // Associate the two trails in SAS so B2BUA calls are displayed properly
    TRC_DEBUG("Asssociating original SAS trail %ld with new message SAS trail %ld",
              _as_chain->trail(), msg_trail);
    SAS::associate_trails(_as_chain->trail(), msg_trail);
  }

  // Check if this is our first passthrough this function.
  bool first_pass_through_ifcs = (_index == 0) &&
                                 (_as_chain->_using_standard_ifcs);

  // Attempt to get the next application server. This uses either the standard
  // IFCs or the default IFCs depending on what's happened when we went through
  // this function previously.
  bool got_dummy_as = false;
  get_next_application_server(msg,
                              server_name,
                              got_dummy_as,
                              msg_trail);

  // Check if we should apply any default IFCs. We do this if:
  //   - We haven't found any matching IFC (true if server_name is empty, and
  //     got_dummy_as is false.
  //   - It's our first time through this function and we've run through
  //     every available standard IFC to check for a match
  //   - The config option to apply default IFCs is set.
  if ((!(got_dummy_as) || (server_name != "")) &&
      ((first_pass_through_ifcs) && (complete())) &&
      (_as_chain->_ifc_configuration._apply_default_ifcs))
  {
    // Reset the AsChain IFCs given we've moving onto the default IFCs
    _as_chain->_using_standard_ifcs = false;
    _index = 0;
    get_next_application_server(msg,
                                server_name,
                                got_dummy_as,
                                msg_trail);
  }

  // Check if we should have applied default IFCs, but didn't find any. We
  // SAS log this, and increment a statistic (TODO - waiting on spec finalization).
  // We're in this case if:
  //   - We haven't found any matching IFC (true if server_name is empty, and
  //     got_dummy_as is false.
  //   - We're using default IFCs
  if ((!(got_dummy_as) || (server_name != "")) &&
      ((!_as_chain->_using_standard_ifcs) &&
       (_as_chain->_ifc_configuration._apply_default_ifcs)))
  {
    TRC_DEBUG("Unable to apply default IFCs as no matching IFCs available");
    SAS::Event event(msg_trail, SASEvent::NO_DEFAULT_IFCS, 0);
    SAS::report_event(event);
  }

  // Now check if we should reject the request. We do this if:
  //   - We haven't found any matching IFC (true if server_name is empty, and
  //     got_dummy_as is false.
  //   - It's our first time through this function and we've run through
  //     every available IFC to check for a match
  //   - The config option to reject when there are no matching IFCs is set.
  if ((!(got_dummy_as) || (server_name != "")) &&
      ((first_pass_through_ifcs) && (complete())) &&
      (_as_chain->_ifc_configuration._reject_if_no_matching_ifcs))
  {
    rc = PJSIP_SC_BAD_REQUEST;
  }

  return rc;
}

void AsChainLink::get_next_application_server(pjsip_msg* msg,
                                              std::string& server_name,
                                              bool& got_dummy_as,
                                              SAS::TrailId msg_trail)
{
  std::vector<Ifc> ifcs = _as_chain->_using_standard_ifcs ?
                          _as_chain->_ifcs.ifcs_list() :
                          _as_chain->_default_ifcs;
  got_dummy_as = false;

  while (!complete())
  {
    const Ifc& ifc = ifcs[_index];
    if (ifc.filter_matches(_as_chain->session_case(),
                           _as_chain->_is_registered,
                           false,
                           msg,
                           trail()))
    {
      TRC_DEBUG("Matched iFC %s", to_string().c_str());
      AsInvocation application_server = ifc.as_invocation();

      if (_as_chain->_ifc_configuration._dummy_as != application_server.server_name)
      {
        server_name = application_server.server_name;

        // Store the RequestURI and application server name in the AsInformation
        // structure for this link.
        _as_chain->_as_info[_index].request_uri =
              PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, msg->line.req.uri);
        _as_chain->_as_info[_index].as_uri = server_name;

        // Store the default handling as we may need it later.
        _default_handling = application_server.default_handling;

        break;
      }
      else
      {
        TRC_DEBUG("Ignoring this IFC as it matches a dummy AS (%s)",
                  application_server.server_name.c_str());
        SAS::Event event(msg_trail, SASEvent::IFC_MATCHED_DUMMY_AS, 0);
        event.add_var_param(_as_chain->_ifc_configuration._dummy_as);
        SAS::report_event(event);
        got_dummy_as = true;
      }
    }
    ++_index;
  }
}

void AsChainLink::on_response(int status_code)
{
  if (status_code == PJSIP_SC_TRYING)
  {
    // Intentionally do nothing on a 100 trying.
  }
  else if (status_code < PJSIP_SC_OK)
  {
    // A 1xx response (which does *not* include 100 - see TS 24.229 section 3.2)
    // means that the AS should be treated as responsive.
    _as_chain->_responsive[_index] = true;
  }
  else
  {
    // Final response. Store the status code returned by the AS.
    _as_chain->_as_info[_index].status_code = status_code;
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
  size_t len = as_chain->size() + 1;
  pthread_mutex_lock(&_lock);

  for (size_t i = 0; i < len; i++)
  {
    std::string token;
    Utils::create_random_token(TOKEN_LENGTH, token);
    tokens.push_back(token);
    _odi_token_map[token] = AsChainLink(as_chain, i);
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
    _odi_token_map.erase(*it);
  }

  pthread_mutex_unlock(&_lock);
}


/// Retrieve an existing AsChainLink based on ODI token.
//
// If the returned link is_set(), caller MUST call release() when it
// is finished with the link.
AsChainLink AsChainTable::lookup(const std::string& token)
{
  pthread_mutex_lock(&_lock);
  std::map<std::string, AsChainLink>::const_iterator it =
                                                    _odi_token_map.find(token);
  if (it == _odi_token_map.end())
  {
    pthread_mutex_unlock(&_lock);
    return AsChainLink(NULL, 0);
  }
  else
  {
    // Found the AsChainLink.  Add a reference to the AsChain.
    const AsChainLink& as_chain_link = it->second;
    if (as_chain_link._as_chain->inc_ref())
    {
      // Flag that the AS corresponding to the previous link in the chain has
      // effectively responded.
      as_chain_link._as_chain->_responsive[as_chain_link._index - 1] = true;
      pthread_mutex_unlock(&_lock);
      return as_chain_link;
    } else {
      // Failed to increment the count - AS chain must be in the process of
      // being destroyed.  Pretend we didn't find it.
      // LCOV_EXCL_START - Can't hit this window condition in UT.
      pthread_mutex_unlock(&_lock);
      return AsChainLink(NULL, 0);
      // LCOV_EXCL_STOP
    }
  }
}
