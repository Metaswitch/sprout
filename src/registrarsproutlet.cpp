/**
 *
 * @file registrarproutlet.cpp
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2016  Metaswitch Networks Ltd
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

#include <time.h>

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>

#include "pjutils.h"
#include "utils.h"
#include "sproutsasevent.h"
#include "memcachedstore.h"
#include "hss_sip_mapping.h"
#include "registrarsproutlet.h"
#include "registration_utils.h"
#include "constants.h"
#include "custom_headers.h"
#include "log.h"
#include "notify_utils.h"
#include "uri_classifier.h"

// RegistrarSproutlet constructor.
RegistrarSproutlet::RegistrarSproutlet(const std::string& name,
                                       int port,
                                       const std::string& uri,
                                       const std::string& next_hop_service,
                                       SubscriberDataManager* reg_sdm,
                                       std::vector<SubscriberDataManager*> reg_remote_sdms,
                                       HSSConnection* hss_connection,
                                       ACRFactory* rfacr_factory,
                                       int cfg_max_expires,
                                       bool force_original_register_inclusion,
                                       SNMP::RegistrationStatsTables* reg_stats_tbls,
                                       SNMP::RegistrationStatsTables* third_party_reg_stats_tbls):
  Sproutlet(name, port, uri, ""),
  _sdm(reg_sdm),
  _remote_sdms(reg_remote_sdms),
  _hss(hss_connection),
  _acr_factory(rfacr_factory),
  _max_expires(cfg_max_expires),
  _force_original_register_inclusion(force_original_register_inclusion),
  _reg_stats_tbls(reg_stats_tbls),
  _third_party_reg_stats_tbls(third_party_reg_stats_tbls),
  _next_hop_service(next_hop_service)
{
}

//RegistrarSproutlet destructor.
RegistrarSproutlet::~RegistrarSproutlet()
{
}

bool RegistrarSproutlet::init()
{
  bool init_success = true;

  RegistrationUtils::init(_third_party_reg_stats_tbls, _force_original_register_inclusion);

  // Construct a Service-Route header pointing at the S-CSCF ready to be added
  // to REGISTER 200 OK response.
  pjsip_sip_uri* service_route_uri = NULL;

  if (stack_data.scscf_uri != NULL)
  {
    service_route_uri = (pjsip_sip_uri*)pjsip_uri_clone(stack_data.pool, stack_data.scscf_uri);
  }

  if (service_route_uri != NULL)
  {
    service_route_uri->lr_param = 1;

    // Add the orig parameter.  The UE must provide this back on future messages
    // to ensure we perform originating processing.
    pjsip_param *orig_param = PJ_POOL_ALLOC_T(stack_data.pool, pjsip_param);
    pj_strdup(stack_data.pool, &orig_param->name, &STR_ORIG);
    pj_strdup2(stack_data.pool, &orig_param->value, "");
    pj_list_insert_after(&service_route_uri->other_param, orig_param);

    _service_route = pjsip_route_hdr_create(stack_data.pool);
    _service_route->name = STR_SERVICE_ROUTE;
    _service_route->sname = pj_str((char *)"");
    _service_route->name_addr.uri = (pjsip_uri*)service_route_uri;
  }
  else
  {
    // LCOV_EXCL_START - Start up failures not tested in UT
    TRC_ERROR("Unable to set up Service-Route header for the registrar from %.*s",
              stack_data.scscf_uri_str.slen, stack_data.scscf_uri_str.ptr);
    init_success = false;
    // LCOV_EXCL_STOP
  }

  return init_success;
}

SproutletTsx* RegistrarSproutlet::get_tsx(SproutletTsxHelper* helper,
                                          const std::string& alias,
                                          pjsip_msg* req)
{
  return (SproutletTsx*)new RegistrarSproutletTsx(helper, _next_hop_service, this);
}

RegistrarSproutletTsx::RegistrarSproutletTsx(SproutletTsxHelper* helper,
                                             const std::string& next_hop_service,
                                             RegistrarSproutlet* sproutlet):
  ForwardingSproutletTsx(helper, next_hop_service),
  _sproutlet(sproutlet)
{
  TRC_DEBUG("Registrar Transaction (%p) created", this);
}

RegistrarSproutletTsx::~RegistrarSproutletTsx()
{
  TRC_DEBUG("Registrar Transaction (%p) destroyed", this);
}

void RegistrarSproutletTsx::on_rx_initial_request(pjsip_msg *req)
{
  TRC_INFO("Registrar sproutlet received initial request");

  URIClass uri_class = URIClassifier::classify_uri(req->line.req.uri);
  if ((req->line.req.method.id == PJSIP_REGISTER_METHOD) &&
      ((uri_class == NODE_LOCAL_SIP_URI) ||
       (uri_class == HOME_DOMAIN_SIP_URI)) &&
      (PJUtils::check_route_headers(req)))
  {
    // REGISTER request targeted at the home domain or specifically at this node.
    process_register_request(req);
  }
  else
  {
    forward_request(req);
  }
}

void RegistrarSproutletTsx::process_register_request(pjsip_msg *req)
{
  pjsip_status_code st_code = PJSIP_SC_OK;

  // Get the system time in seconds for calculating absolute expiry times.
  int now = time(NULL);
  int expiry = 0;
  bool is_initial_registration;

  // Loop through headers as early as possible so that we know the expiry time
  // and which registration statistics to update.
  // Loop through each contact header. If every registration is an emergency
  // registration and its expiry is 0 then reject with a 501.
  // If there are valid registration updates to make then attempt to write to
  // store, which also stops emergency registrations from being deregistered.
  int num_contacts = 0;
  int num_emergency_bindings = 0;
  int num_emergency_deregisters = 0;
  bool reject_with_400 = false;
  pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);

  while (contact_hdr != NULL)
  {
    num_contacts++;
    pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);
    expiry = _sproutlet->expiry_for_binding(contact_hdr, expires);

    if ((contact_hdr->star) && (expiry != 0))
    {
      // Wildcard contact, which can only be used if the expiry is 0
      TRC_ERROR("Attempted to deregister all bindings, but expiry value wasn't 0");
      reject_with_400 = true;
      break;
    }

    if (PJUtils::is_emergency_registration(contact_hdr))
    {
      num_emergency_bindings++;
      if (expiry == 0)
      {
        num_emergency_deregisters++;
      }
    }

    contact_hdr = (pjsip_contact_hdr*) pjsip_msg_find_hdr(req,
                                                          PJSIP_H_CONTACT,
                                                          contact_hdr->next);
  }

  // Get the URI from the To header and check it is a SIP or SIPS URI.
  pjsip_uri* uri = (pjsip_uri*)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(req)->uri);

  if ((!PJSIP_URI_SCHEME_IS_SIP(uri)) && (!PJSIP_URI_SCHEME_IS_TEL(uri)))
  {
    // Reject a non-SIP/TEL URI with 404 Not Found (RFC3261 isn't clear
    // whether 404 is the right status code - it says 404 should be used if
    // the AoR isn't valid for the domain in the RequestURI).
    TRC_ERROR("Rejecting register request using invalid URI scheme");

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_INVALIDURISCHEME, 0);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_FOUND);
    send_response(rsp);
    free_msg(req);

    // Only update statistics if this is going to change the state of the
    // IRS (i.e. if the number of contact headers is non-zero)
    if (num_contacts > 0)
    {
      if (expiry == 0)
      {
        _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_attempts();
        _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else
      // Invalid URI means this cannot be a re-register request, so if not
      // a de-register request, then treat as an initial register request.
      {
        _sproutlet->_reg_stats_tbls->init_reg_tbl->increment_attempts();
        _sproutlet->_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
    }
    return;
  }

  // Allocate an ACR for this transaction and pass the request to it.  Node
  // role is always considered originating for REGISTER requests.
  ACR* acr = _sproutlet->_acr_factory->get_acr(trail(),
                                               ACR::CALLING_PARTY,
                                               ACR::NODE_ROLE_ORIGINATING);
  acr->rx_request(req);

  // Canonicalize the public ID from the URI in the To header.
  std::string public_id = PJUtils::public_id_from_uri(uri);
  TRC_DEBUG("Process REGISTER for public ID %s", public_id.c_str());

  // Get the call identifier and the cseq number from the respective headers.
  std::string cid = PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id);;

  // Add SAS markers to the trail attached to the message so the trail
  // becomes searchable.
  TRC_DEBUG("Report SAS start marker - trail (%llx)", trail());
  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  // Query the HSS for the associated URIs.
  std::vector<std::string> uris;
  std::map<std::string, Ifcs> ifc_map;
  std::string private_id;
  std::string private_id_for_binding;
  bool success = get_private_id(req, private_id);
  if (!success)
  {
    // There are legitimate cases where we don't have a private ID
    // here (for example, on a re-registration where Bono has set the
    // Integrity-Protected header), so this is *not* a failure
    // condition.

    // We want the private ID here so that Homestead can use it to
    // subscribe for updates from the HSS - but on a re-registration,
    // Homestead should already have subscribed for updates during the
    // initial registration, so we can just make a request using our
    // public ID.
    private_id = "";

    // IMS compliant clients will always have the Auth header on all REGISTERs,
    // including reREGISTERS. Non-IMS clients won't, but their private ID
    // will always be the public ID with the sip: removed.
    private_id_for_binding = PJUtils::default_private_id_from_uri(uri);
  }
  else
  {
    private_id_for_binding = private_id;
  }

  SAS::Event event(trail(), SASEvent::REGISTER_START, 0);
  event.add_var_param(public_id);
  event.add_var_param(private_id);
  SAS::report_event(event);

  if (num_contacts == 0)
  {
    SAS::Event event(trail(), SASEvent::REGISTER_NO_CONTACTS, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);
  }

  std::string regstate;
  std::deque<std::string> ccfs;
  std::deque<std::string> ecfs;
  HTTPCode http_code = _sproutlet->_hss->update_registration_state(public_id,
                                                                   private_id,
                                                                   HSSConnection::REG,
                                                                   regstate,
                                                                   ifc_map,
                                                                   uris,
                                                                   ccfs,
                                                                   ecfs,
                                                                   trail());

  st_code = determine_hss_sip_response(http_code, regstate, "REGISTER");

  if (st_code != PJSIP_SC_OK)
  {
    pjsip_msg* rsp = create_response(req, st_code);
    send_response(rsp);
    free_msg(req);

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_INVALIDPUBPRIV, 0);
    event.add_var_param(public_id);
    event.add_var_param(private_id);
    SAS::report_event(event);

    acr->send();
    delete acr;

    if (num_contacts > 0)
    {
      if (expiry == 0)
      {
        _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_attempts();
        _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else
      // Invalid public/private identity means this cannot be a re-register request,
      // so if not a de-register request, then treat as an initial register request.
      {
        _sproutlet->_reg_stats_tbls->init_reg_tbl->increment_attempts();
        _sproutlet->_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
    }
    return;
  }

  // Determine the AOR from the first entry in the uris array.
  std::string aor = uris.front();
  TRC_DEBUG("REGISTER for public ID %s uses AOR %s", public_id.c_str(), aor.c_str());

  if (reject_with_400)
  {
    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_INVALIDCONTACT, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_BAD_REQUEST);
    send_response(rsp);
    free_msg(req);

    acr->send();
    delete acr;

    if (num_contacts > 0)
    {
      _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_attempts();
      _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_failures();
    }

    return;
  }

  if ((num_emergency_deregisters > 0) && (num_emergency_deregisters == num_contacts))
  {
    TRC_ERROR("Rejecting register request as attempting to deregister an emergency registration");

    SAS::Event event(trail(), SASEvent::DEREGISTER_FAILED_EMERGENCY, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    pjsip_msg* rsp = create_response(req, PJSIP_SC_NOT_IMPLEMENTED);
    send_response(rsp);
    free_msg(req);

    acr->send();
    delete acr;

    if (num_contacts > 0)
    {
      _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_attempts();
      _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_failures();
    }

    return;
  }

  // Write to the local store, checking the remote stores if there is no entry locally.
  bool all_bindings_expired;
  SubscriberDataManager::AoRPair* aor_pair =
                                 write_to_store(_sproutlet->_sdm,
                                                aor,
                                                uris,
                                                req,
                                                now,
                                                expiry,
                                                is_initial_registration,
                                                NULL,
                                                _sproutlet->_remote_sdms,
                                                private_id_for_binding,
                                                all_bindings_expired);
  if (all_bindings_expired)
  {
    TRC_DEBUG("All bindings have expired - triggering deregistration at the HSS");
    _sproutlet->_hss->update_registration_state(aor,
                                                "",
                                                HSSConnection::DEREG_USER,
                                                trail());
  }

  if ((aor_pair != NULL) && (aor_pair->get_current() != NULL))
  {
    // Log the bindings.
    log_bindings(aor, aor_pair->get_current());

    // If we have any remote stores, try to store this in them too.  We don't worry
    // about failures in this case.
    for (std::vector<SubscriberDataManager*>::iterator it = _sproutlet->_remote_sdms.begin();
         it != _sproutlet->_remote_sdms.end();
         ++it)
    {
      if ((*it)->has_servers())
      {
        int tmp_expiry = 0;
        bool ignored;
        SubscriberDataManager::AoRPair* remote_aor_pair =
          write_to_store(*it,
                         aor,
                         uris,
                         req,
                         now,
                         tmp_expiry,
                         ignored,
                         aor_pair,
                         {},
                         private_id_for_binding,
                         ignored);
        delete remote_aor_pair;
      }
    }
  }
  else
  {
    // Failed to connect to the local store.  Reject the register with a 500
    // response.
    // LCOV_EXCL_START - the can't fail to connect to the store we use for UT
    st_code = PJSIP_SC_INTERNAL_SERVER_ERROR;

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_REGSTORE, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    // LCOV_EXCL_STOP
  }

  if (num_contacts > 0)
  {
    if (expiry == 0)
    {
      _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_attempts();
    }
    else if (is_initial_registration)
    {
      _sproutlet->_reg_stats_tbls->init_reg_tbl->increment_attempts();
    }
    else
    {
      _sproutlet->_reg_stats_tbls->re_reg_tbl->increment_attempts();
    }
  }

  // Build and send the reply.
  pjsip_msg* rsp = create_response(req, st_code);

  if (st_code != PJSIP_SC_OK)
  {
    // LCOV_EXCL_START - we only reject REGISTER if something goes wrong, and
    // we aren't covering any of those paths so we can't hit this either
    acr->tx_response(rsp);

    send_response(rsp);
    free_msg(req);

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED, 0);
    event.add_var_param(public_id);
    std::string error_msg = "REGISTER failed with status code: " + std::to_string(st_code);
    event.add_var_param(error_msg);
    SAS::report_event(event);

    acr->send();
    delete acr;
    delete aor_pair;

    if (num_contacts > 0)
    {
      if (is_initial_registration)
      {
        _sproutlet->_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
      else if (expiry == 0)
      {
        _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else
      {
        _sproutlet->_reg_stats_tbls->re_reg_tbl->increment_failures();
      }
    }

    return;
    // LCOV_EXCL_STOP
  }

  // Add supported and require headers for RFC5626.
  pjsip_generic_string_hdr* gen_hdr;
  gen_hdr = pjsip_generic_string_hdr_create(get_pool(rsp),
                                            &STR_SUPPORTED,
                                            &STR_OUTBOUND);
  if (gen_hdr == NULL)
  {
    // LCOV_EXCL_START - can't see how this could ever happen
    TRC_ERROR("Failed to add RFC 5626 headers");

    SAS::Event event(trail(), SASEvent::REGISTER_FAILED_5636, 0);
    event.add_var_param(public_id);
    SAS::report_event(event);

    rsp->line.status.code = PJSIP_SC_INTERNAL_SERVER_ERROR;

    acr->tx_response(rsp);

    send_response(rsp);
    free_msg(req);

    acr->send();
    delete acr;
    delete aor_pair;

    if (num_contacts > 0)
    {
      if (is_initial_registration)
      {
        _sproutlet->_reg_stats_tbls->init_reg_tbl->increment_failures();
      }
      else if (expiry == 0)
      {
        _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_failures();
      }
      else
      {
        _sproutlet->_reg_stats_tbls->re_reg_tbl->increment_failures();
      }
    }

    return;
    // LCOV_EXCL_STOP
  }

  pjsip_msg_add_hdr(rsp, (pjsip_hdr*)gen_hdr);

  // Add contact headers for all active bindings.
  for (SubscriberDataManager::AoR::Bindings::const_iterator i =
          aor_pair->get_current()->bindings().begin();
       i != aor_pair->get_current()->bindings().end();
       ++i)
  {
    SubscriberDataManager::AoR::Binding* binding = i->second;
    if (binding->_expires > now)
    {
      // The binding hasn't expired.  Parse the Contact URI from the store,
      // making sure it is formatted as a name-address.
      pjsip_uri* uri = PJUtils::uri_from_string(binding->_uri, get_pool(rsp), PJ_TRUE);
      if (uri != NULL)
      {
        // Contact URI is well formed, so include this in the response.
        pjsip_contact_hdr* contact = pjsip_contact_hdr_create(get_pool(rsp));
        contact->star = 0;
        contact->uri = uri;
        contact->q1000 = binding->_priority;
        contact->expires = binding->_expires - now;
        pj_list_init(&contact->other_param);
        for (std::map<std::string, std::string>::iterator j = binding->_params.begin();
             j != binding->_params.end();
             ++j)
        {
          pjsip_param *new_param = PJ_POOL_ALLOC_T(get_pool(rsp), pjsip_param);
          pj_strdup2(get_pool(rsp), &new_param->name, j->first.c_str());
          pj_strdup2(get_pool(rsp), &new_param->value, j->second.c_str());
          pj_list_insert_before(&contact->other_param, new_param);
        }

        // Add a GRUU if the UE supports GRUUs and the contact header contains
        // a +sip.instance parameter.
        if (PJUtils::msg_supports_extension(req, "gruu"))
        {
          // The pub-gruu parameter on the Contact header is calculated
          // from the instance-id, to avoid unnecessary storage in
          // memcached.
          std::string gruu = binding->pub_gruu_quoted_string(get_pool(rsp));
          if (!gruu.empty())
          {
            pjsip_param *new_param = PJ_POOL_ALLOC_T(get_pool(rsp), pjsip_param);
            pj_strdup2(get_pool(rsp), &new_param->name, "pub-gruu");
            pj_strdup2(get_pool(rsp), &new_param->value, gruu.c_str());
            pj_list_insert_before(&contact->other_param, new_param);
          }
        }

        pjsip_msg_add_hdr(rsp, (pjsip_hdr*)contact);
      }
      else
      {
        // Contact URI is malformed.  Log an error, but otherwise don't try and
        // fix it.
        // LCOV_EXCL_START hard to hit - needs bad data in the store
        TRC_WARNING("Badly formed contact URI %s for address of record %s",
                    binding->_uri.c_str(), aor.c_str());

        SAS::Event event(trail(), SASEvent::REGISTER_FAILED, 0);
        event.add_var_param(public_id);
        std::string error_msg = "Badly formed contact URI - " + binding->_uri;
        event.add_var_param(error_msg);
        SAS::report_event(event);
        // LCOV_EXCL_STOP
      }
    }
  }

  SAS::Event reg_Accepted(trail(), SASEvent::REGISTER_ACCEPTED, 0);
  SAS::report_event(reg_Accepted);

  if (num_contacts > 0)
  {
    if (expiry == 0)
    {
      _sproutlet->_reg_stats_tbls->de_reg_tbl->increment_successes();
    }
    else if (is_initial_registration)
    {
      _sproutlet->_reg_stats_tbls->init_reg_tbl->increment_successes();
    }
    else
    {
      _sproutlet->_reg_stats_tbls->re_reg_tbl->increment_successes();
    }
  }

  // Deal with path header related fields in the response.
  pjsip_routing_hdr* path_hdr = (pjsip_routing_hdr*)
                              pjsip_msg_find_hdr_by_name(req, &STR_PATH, NULL);
  if ((path_hdr != NULL) &&
      (!aor_pair->get_current()->bindings().empty()))
  {
    // We have bindings with path headers so we must require outbound.
    pjsip_require_hdr* require_hdr = pjsip_require_hdr_create(get_pool(rsp));
    require_hdr->count = 1;
    require_hdr->values[0] = STR_OUTBOUND;
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)require_hdr);
  }

  // Echo back any Path headers as per RFC 3327, section 5.3.  We take these
  // from the request as they may not exist in the bindings any more if the
  // bindings have expired.
  while (path_hdr)
  {
    pjsip_msg_add_hdr(rsp,
                      (pjsip_hdr*)pjsip_hdr_clone(get_pool(rsp), path_hdr));
    path_hdr = (pjsip_routing_hdr*)
                    pjsip_msg_find_hdr_by_name(req, &STR_PATH, path_hdr->next);
  }

  // Add the Service-Route header.  It isn't safe to do this with the
  // pre-built header from the global pool because the chaining data
  // structures in the header may get overwritten, but it is safe to do a
  // shallow clone.
  pjsip_hdr* clone = (pjsip_hdr*)
                          pjsip_hdr_shallow_clone(get_pool(rsp), _sproutlet->_service_route);
  pjsip_msg_insert_first_hdr(rsp, clone);

  // Add P-Associated-URI headers for all of the associated URIs.
  for (std::vector<std::string>::iterator it = uris.begin();
       it != uris.end();
       it++)
  {
    pjsip_routing_hdr* pau =
                        identity_hdr_create(get_pool(rsp), STR_P_ASSOCIATED_URI);
    pau->name_addr.uri = PJUtils::uri_from_string(*it, get_pool(rsp));
    pjsip_msg_add_hdr(rsp, (pjsip_hdr*)pau);
  }

  // Add a PCFA header.
  PJUtils::add_pcfa_header(rsp, get_pool(rsp), ccfs, ecfs, true);

  // Pass the response to the ACR.
  acr->tx_response(rsp);

  // Clone the response so that we can use it to inform ASes of the 200 OK response we send.
  pjsip_msg* clone_rsp = clone_msg(rsp);
  send_response(rsp);

  // Send the ACR and delete it.
  acr->send();
  delete acr;

  // TODO in sto397: we should do third-party registration once per
  // service profile (i.e. once per iFC, using an arbitrary public
  // ID). hss->get_subscription_data should be enhanced to provide an
  // appropriate data structure (representing the ServiceProfile
  // nodes) and we should loop through that. Don't send any register that
  // contained emergency registrations to the application servers.

  if (num_emergency_bindings == 0)
  {
    RegistrationUtils::register_with_application_servers(ifc_map[public_id],
                                                         _sproutlet->_sdm,
                                                         _sproutlet->_remote_sdms,
                                                         _sproutlet->_hss,
                                                         req,
                                                         clone_rsp,
                                                         expiry,
                                                         is_initial_registration,
                                                         public_id,
                                                         trail());
  }

  // Now we can free the messages.
  free_msg(clone_rsp);
  free_msg(req);

  TRC_DEBUG("Report SAS end marker - trail (%llx)", trail());
  SAS::Marker end_marker(trail(), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);
  delete aor_pair;
}

/// Write to the registration store. If we can't find the AoR pair in the
/// primary SDM, we will either use the backup_aor or we will try and look up
/// the AoR pair in the backup SDMs. Therefore either the backup_aor should be
/// NULL, or backup_sdms should be empty.
SubscriberDataManager::AoRPair* RegistrarSproutletTsx::write_to_store(
                   SubscriberDataManager* primary_sdm,         ///<store to write to
                   std::string aor,                            ///<address of record to write to
                   std::vector<std::string> irs_impus,         ///<IMPUs in Implicit Registration Set
                   pjsip_msg* req,                             ///<received request to read headers from
                   int now,                                    ///<time now
                   int& expiry,                                ///<[out] longest expiry time
                   bool& out_is_initial_registration,
                   SubscriberDataManager::AoRPair* backup_aor, ///<backup data if no entry in store
                   std::vector<SubscriberDataManager*> backup_sdms,
                                                               ///<backup stores to read from if no entry in store and no backup data
                   std::string private_id,                     ///<private id that the binding was registered with
                   bool& out_all_bindings_expired)
{
  // Get the call identifier and the cseq number from the respective headers.
  std::string cid = PJUtils::pj_str_to_string(&PJSIP_MSG_CID_HDR(req)->id);
  int cseq = ((pjsip_cseq_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CSEQ, NULL))->cseq;

  // Find the expire headers in the message.
  pjsip_expires_hdr* expires = (pjsip_expires_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_EXPIRES, NULL);

  // The registration service uses optimistic locking to avoid concurrent
  // updates to the same AoR conflicting.  This means we have to loop
  // reading, updating and writing the AoR until the write is successful.
  SubscriberDataManager::AoRPair* aor_pair = NULL;
  bool backup_aor_alloced = false;
  bool is_initial_registration = true;
  bool all_bindings_expired = false;
  Store::Status set_rc;

  do
  {
    // delete NULL is safe, so we can do this on every iteration.
    delete aor_pair;

    // Find the current bindings for the AoR.
    aor_pair = primary_sdm->get_aor_data(aor, trail());
    TRC_DEBUG("Retrieved AoR data %p", aor_pair);

    if ((aor_pair == NULL) ||
        (aor_pair->get_current() == NULL))
    {
      // Failed to get data for the AoR because there is no connection
      // to the store.
      TRC_ERROR("Failed to get AoR binding for %s from store", aor.c_str());
      break;
    }

    // If we don't have any bindings, try the backup AoR and/or stores.
    if (aor_pair->get_current()->bindings().empty())
    {
      bool found_binding = false;

      if ((backup_aor != NULL) &&
          (backup_aor->current_contains_bindings()))
      {
        found_binding = true;
      }
      else
      {
        std::vector<SubscriberDataManager*>::iterator it = backup_sdms.begin();
        SubscriberDataManager::AoRPair* local_backup_aor = NULL;

        while ((it != backup_sdms.end()) && (!found_binding))
        {
          if ((*it)->has_servers())
          {
            local_backup_aor = (*it)->get_aor_data(aor, trail());

            if ((local_backup_aor != NULL) &&
                (local_backup_aor->current_contains_bindings()))
            {
              found_binding = true;
              backup_aor = local_backup_aor;

              // Flag that we have allocated the memory for the backup pair so
              // that we can tidy it up later.
              backup_aor_alloced = true;
            }
          }

          if (!found_binding)
          {
            ++it;

            if (local_backup_aor != NULL)
            {
              delete local_backup_aor;
              local_backup_aor = NULL;
            }
          }
        }
      }

      if (found_binding)
      {
        aor_pair->get_current()->copy_subscriptions_and_bindings(backup_aor->get_current());
      }
    }

    is_initial_registration = is_initial_registration && aor_pair->get_current()->bindings().empty();

    // Now loop through all the contacts.  If there are multiple contacts in
    // the contact header in the SIP message, pjsip parses them to separate
    // contact header structures.
    pjsip_contact_hdr* contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, NULL);
    int changed_bindings = 0;

    while (contact != NULL)
    {
      changed_bindings++;
      expiry = _sproutlet->expiry_for_binding(contact, expires);

      if (contact->star)
      {
        // Wildcard contact, which can only be used to clear all bindings for
        // the AoR (and only if the expiry is 0). It won't clear any emergency
        // bindings
        aor_pair->get_current()->clear(false);
        break;
      }

      pjsip_uri* uri = (contact->uri != NULL) ?
                           (pjsip_uri*)pjsip_uri_get_uri(contact->uri) :
                           NULL;

      if ((uri != NULL) &&
          (PJSIP_URI_SCHEME_IS_SIP(uri)))
      {
        // The binding identifier is based on the +sip.instance parameter if
        // it is present.  If not the contact URI is used instead.
        std::string contact_uri = PJUtils::uri_to_string(PJSIP_URI_IN_CONTACT_HDR, uri);
        std::string binding_id = get_binding_id(contact);

        if (binding_id == "")
        {
          binding_id = contact_uri;
        }

        TRC_DEBUG("Binding identifier for contact = %s", binding_id.c_str());

        // Find the appropriate binding in the bindings list for this AoR.
        SubscriberDataManager::AoR::Binding* binding = aor_pair->get_current()->get_binding(binding_id);

        if ((cid != binding->_cid) ||
            (cseq > binding->_cseq))
        {
          // Either this is a new binding, has come from a restarted device, or
          // is an update to an existing binding.
          binding->_uri = contact_uri;

          // TODO Examine Via header to see if we're the first hop
          // TODO Only if we're not the first hop, check that the top path header has "ob" parameter

          // Get the Path headers, if present.  RFC 3327 allows us the option of
          // rejecting a request with a Path header if there is no corresponding
          // "path" entry in the Supported header but we don't do so on the assumption
          // that the edge proxy knows what it's doing.
          //
          // We store the full path header in the _path_headers field. For
          // backwards compatibility, we also store the URI part of the path
          // header in the _path_uris field.
          binding->_path_headers.clear();
          binding->_path_uris.clear();
          pjsip_routing_hdr* path_hdr = (pjsip_routing_hdr*)
                              pjsip_msg_find_hdr_by_name(req, &STR_PATH, NULL);

          while (path_hdr)
          {
            std::string path = PJUtils::get_header_value((pjsip_hdr*)path_hdr);
            std::string path_uri = PJUtils::uri_to_string(PJSIP_URI_IN_ROUTING_HDR,
                                                          path_hdr->name_addr.uri);
            TRC_DEBUG("Path header %s", path.c_str());

            // Extract all the paths from this header.
            binding->_path_headers.push_back(path);
            binding->_path_uris.push_back(path_uri);

            // Look for the next header.
            path_hdr = (pjsip_routing_hdr*)
                    pjsip_msg_find_hdr_by_name(req, &STR_PATH, path_hdr->next);
          }

          binding->_cid = cid;
          binding->_cseq = cseq;
          binding->_priority = contact->q1000;
          binding->_params.clear();
          pjsip_param* p = contact->other_param.next;

          while ((p != NULL) && (p != &contact->other_param))
          {
            std::string pname = PJUtils::pj_str_to_string(&p->name);
            std::string pvalue = PJUtils::pj_str_to_string(&p->value);
            // Skip parameters that must not be user-specified
            if (pname != "pub-gruu")
            {
              binding->_params[pname] = pvalue;
            }
            p = p->next;
          }

          binding->_private_id = private_id;
          binding->_emergency_registration = PJUtils::is_emergency_registration(contact);

          // If the new expiry is less than the current expiry, and it's an emergency registration,
          // don't update the expiry time
          if ((binding->_expires >= now + expiry) && (binding->_emergency_registration))
          {
            TRC_DEBUG("Don't reduce expiry time for an emergency registration");
          }
          else
          {
            binding->_expires = now + expiry;
          }
        }
      }
      contact = (pjsip_contact_hdr*)pjsip_msg_find_hdr(req, PJSIP_H_CONTACT, contact->next);
    }

    if (changed_bindings > 0)
    {
      set_rc = primary_sdm->set_aor_data(aor,
                                         irs_impus,
                                         aor_pair,
                                         trail(),
                                         all_bindings_expired);
    }
    else
    {
      // No bindings changed (because we had no contact headers).  However, we
      // may need to deregister the subscriber (because we will have registered
      // the sub in the calling routine), so set all_bindings_expired based on
      // whether we found any bindings to report.
      set_rc = Store::OK;
      all_bindings_expired = aor_pair->get_current()->bindings().empty();
    }

    if (set_rc != Store::OK)
    {
      delete aor_pair; aor_pair = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  // If we allocated the backup AoR, tidy up.
  if (backup_aor_alloced)
  {
    delete backup_aor; // LCOV_EXCL_LINE
  }

  out_is_initial_registration = is_initial_registration;
  out_all_bindings_expired = all_bindings_expired;

  return aor_pair;
}

/// Get private ID from a received message by checking the Authorization
/// header. If that uses the Digest scheme and contains a non-empty
/// username, it puts that username into id and returns true;
/// otherwise returns false.
bool RegistrarSproutletTsx::get_private_id(pjsip_msg* req, std::string& id)
{
  bool success = false;

  pjsip_authorization_hdr* auth_hdr = (pjsip_authorization_hdr*)
    pjsip_msg_find_hdr(req, PJSIP_H_AUTHORIZATION, NULL);
  if (auth_hdr != NULL)
  {
    if (pj_stricmp2(&auth_hdr->scheme, "digest") == 0)
    {
      id = PJUtils::pj_str_to_string(&auth_hdr->credential.digest.username);
      if (!id.empty())
      {
        success = true;
      }
    }
    else
    {
      // LCOV_EXCL_START
      TRC_WARNING("Unsupported scheme \"%.*s\" in Authorization header when determining private ID - ignoring",
                  auth_hdr->scheme.slen, auth_hdr->scheme.ptr);
      // LCOV_EXCL_STOP
    }
  }
  return success;
}

std::string RegistrarSproutletTsx::get_binding_id(pjsip_contact_hdr *contact)
{
  // Get a suitable binding string from +sip.instance and reg_id parameters
  // if they are supplied.
  std::string id = "";
  pj_str_t *instance = NULL;
  pj_str_t *reg_id = NULL;

  pjsip_param *p = contact->other_param.next;

  while ((p != NULL) && (p != &contact->other_param))
  {
    if (pj_stricmp(&p->name, &STR_SIP_INSTANCE) == 0)
    {
      instance = &p->value;
    }
    else if (pj_stricmp(&p->name, &STR_REG_ID) == 0)
    {
      reg_id = &p->value;
    }
    p = p->next;
  }

  if ((instance != NULL) && (pj_strlen(instance) >= 2))
  {
    // The contact a +sip.instance parameters, so form a suitable binding
    // string.
    id = PJUtils::pj_str_to_string(instance);
    id = id.substr(1, id.size() - 2); // Strip quotes

    if (reg_id != NULL)
    {
      id = id + ":" + PJUtils::pj_str_to_string(reg_id);
    }

    if (PJUtils::is_emergency_registration(contact))
    {
      id = "sos" + id;
    }

  }

  return id;
}

void RegistrarSproutletTsx::log_bindings(const std::string& aor_name,
                                         SubscriberDataManager::AoR* aor_data)
{
  TRC_DEBUG("Bindings for %s, timer ID %s", aor_name.c_str(), aor_data->_timer_id.c_str());
  for (SubscriberDataManager::AoR::Bindings::const_iterator i =
         aor_data->bindings().begin();
       i != aor_data->bindings().end();
       ++i)
  {
    SubscriberDataManager::AoR::Binding* binding = i->second;
    TRC_DEBUG("  %s URI=%s expires=%d q=%d from=%s cseq=%d timer=%s private_id=%s emergency_registration=%s",
              i->first.c_str(),
              binding->_uri.c_str(),
              binding->_expires, binding->_priority,
              binding->_cid.c_str(), binding->_cseq,
              binding->_timer_id.c_str(),
              binding->_private_id.c_str(),
              (binding->_emergency_registration ? "true" : "false"));
  }
}

int RegistrarSproutlet::expiry_for_binding(pjsip_contact_hdr* contact,
                                           pjsip_expires_hdr* expires)
{
  int expiry = (contact->expires != -1) ? contact->expires :
               (expires != NULL) ? expires->ivalue :
               _max_expires;
  if (expiry > _max_expires)
  {
    // Expiry is too long, set it to the maximum.
    expiry = _max_expires;
  }

  return expiry;
}
