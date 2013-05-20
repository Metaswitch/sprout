/**
 * @file registration_utils.cpp Registration and deregistration functions
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

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}


#include <string>
#include <cassert>
#include "regdata.h"
#include "constants.h"
#include "ifchandler.h"
#include "pjutils.h"
#include "stack.h"
#include "registrar.h"
#include "registration_utils.h"
#include "log.h"
#include <boost/lexical_cast.hpp>

#define MAX_SIP_MSG_SIZE 65535

void send_register_to_as(pjsip_rx_data* received_register, pjsip_tx_data* ok_response, AsInvocation& as, int expires, const std::string&);
void deregister_with_application_servers(IfcHandler*, RegData::Store* store, const std::string&, int);

void deregister_with_application_servers(IfcHandler *ifchandler,
                                         RegData::Store* store,
                                         const std::string& aor)
{
  RegistrationUtils::register_with_application_servers(ifchandler, store, NULL, NULL, aor);
}

void RegistrationUtils::register_with_application_servers(IfcHandler *ifchandler,
                                       RegData::Store* store,
                                       pjsip_rx_data *received_register,
                                       pjsip_tx_data *ok_response, // Can only be NULL if received_register is
                                       const std::string& aor) // Should be empty if we have a received_register
{
  // Function preconditions
  if (received_register == NULL) {
    // We should have both messages or neither
    assert(ok_response == NULL);
    // This shouldn't be defined if we have a message to build it from
    assert(aor.compare("") != 0);
  } else {
    // This should be defined if we don't have a message to build it from
    assert(aor.compare("") == 0);
    // We should have both messages or neither
    assert(ok_response != NULL);
  }

  std::string served_user = aor;

  std::vector<AsInvocation> as_list;
  LOG_INFO("Looking up list of Application Servers");
  if (received_register == NULL) {
    LOG_INFO("Generating a fake REGISTER to send to IfcHandler using AOR %s", aor.c_str());
    pj_status_t status;
    pjsip_method method;
    pjsip_method_set(&method, PJSIP_REGISTER_METHOD);
    pjsip_tx_data *tdata;
    std::string bono_uri_string = "<sip:"+std::string(pj_strbuf(&stack_data.home_domain), pj_strlen(&stack_data.home_domain))+">";
    const pj_str_t bono_uri = pj_str(const_cast<char *>(bono_uri_string.c_str()));
    std::string aor_uri_string = "<"+aor+">";
    const pj_str_t aor_uri = pj_str(const_cast<char *>(aor_uri_string.c_str()));
    status = pjsip_endpt_create_request(stack_data.endpt,
                               &method,       // Method
                               &bono_uri,     // Target
                               &aor_uri,      // From
                               &aor_uri,      // To
                               &aor_uri,      // Contact
                               NULL,          // Auto-generate Call-ID
                               1,             // CSeq
                               NULL,          // No body
                               &tdata);       // OUT

    assert(status == PJ_SUCCESS);

    // Choice of SessionCase::Originating is not arbitrary - we don't expect iFCs to specify SessionCase
    // constraints for REGISTER messages, but we only get the served user from the From address in an
    // Originating message, otherwise we use the Request-URI. We need to use the From for REGISTERs.
    SAS::TrailId trail = SAS::new_trail(1);
    ifchandler->lookup_ifcs(SessionCase::Originating, served_user, true, tdata->msg, trail, as_list);
    status = pjsip_tx_data_dec_ref(tdata);
    assert(status == PJSIP_EBUFDESTROYED);
  } else {
    SAS::TrailId trail = get_trail(ok_response);
    served_user = ifchandler->served_user_from_msg(SessionCase::Originating, received_register);
    ifchandler->lookup_ifcs(SessionCase::Originating, served_user, true, received_register->msg_info.msg, trail, as_list);
  }
  LOG_INFO("Found %d Application Servers", as_list.size());

  // Expire all outstanding bindings for this AoR, and get the time this AoR still has remaining - this
  // is the most sensible value to pass to an AS, as they don't have any per-binding information.
  RegData::AoR *aor_data = store->get_aor_data(served_user);
  if (aor_data)
  {
    int now = time(NULL);
    int expires = store->expire_bindings(aor_data, now) - now;
    delete aor_data;

    // Loop through the as_list
    for(std::vector<AsInvocation>::iterator as_iter = as_list.begin(); as_iter != as_list.end(); as_iter++) {
      send_register_to_as(received_register, ok_response, *as_iter, expires, aor);
    }
  }
}

void send_register_to_as(pjsip_rx_data *received_register, pjsip_tx_data *ok_response, AsInvocation& as, int expires, const std::string& aor)
{
  pj_status_t status;
  pjsip_tx_data *tdata;
  pjsip_transaction *tsx;
  pjsip_method method;
  pjsip_method_set(&method, PJSIP_REGISTER_METHOD);
  std::string user_uri_string = aor;

  if (received_register) {
    user_uri_string = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR,
                                             (pjsip_uri *)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(received_register->msg_info.msg)->uri));
  }

  pj_str_t user_uri = pj_str(const_cast<char *>(user_uri_string.c_str()));
  std::string scscf_uri_string = "<sip:" + PJUtils::pj_str_to_string(&stack_data.sprout_cluster_domain) + ":" + boost::lexical_cast<std::string>(stack_data.trusted_port) + ">";
  pj_str_t scscf_uri = pj_str(const_cast<char *>(scscf_uri_string.c_str()));
  pj_str_t as_uri = pj_str(const_cast<char *>(as.server_name.c_str()));

  status = pjsip_endpt_create_request(stack_data.endpt,
                             &method,      // Method
                             &as_uri,      // Target
                             &scscf_uri,   // From
                             &user_uri,    // To
                             &scscf_uri,   // Contact
                             NULL,         // Auto-generate Call-ID
                             1,            // CSeq
                             NULL,         // No body
                             &tdata);      // OUT

  assert(status == PJ_SUCCESS);

  // Expires header based on 200 OK response
  //
  pjsip_expires_hdr_create(tdata->pool, expires);
  pjsip_expires_hdr* expires_hdr = pjsip_expires_hdr_create(tdata->pool, expires);
  pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)expires_hdr);

  // TODO: modify orig-ioi of P-Charging-Vector and remove term-ioi
  // TODO: Set P-Charging-Function-Addresses header based on HSS values

  if (received_register && ok_response) {
    // Copy P-Access-Network-Info and P-Visited-Network-Id from original message
    PJUtils::clone_header(&STR_P_A_N_I, received_register->msg_info.msg, tdata->msg, tdata->pool);
    PJUtils::clone_header(&STR_P_V_N_I, received_register->msg_info.msg, tdata->msg, tdata->pool);

    // Generate a message body based on Filter Criteria values
    char buf[MAX_SIP_MSG_SIZE];
    pj_str_t sip_type = pj_str("message");
    pj_str_t sip_subtype = pj_str("sip");
    pj_str_t xml_type = pj_str("application");
    pj_str_t xml_subtype = pj_str("3gpp-ims+xml");

    // Build up this multipart body incrementally, based on the ServiceInfo, IncludeRegisterRequest and IncludeRegisterResponse fields
    pjsip_msg_body *final_body = pjsip_multipart_create(tdata->pool, NULL, NULL);

    // If we only have one part, we don't want a multipart MIME body - store the reference to each one here to use instead
    pjsip_msg_body *possible_final_body = NULL;
    int multipart_parts = 0;

    if (!as.service_info.empty()) {
      pjsip_multipart_part *xml_part = pjsip_multipart_create_part(tdata->pool);
      std::string xml_str = "<ims-3gpp><service-info>"+as.service_info+"</service-info></ims-3gpp>";
      pj_str_t xml_pj_str;
      pj_cstr(&xml_pj_str, xml_str.c_str());
      xml_part->body = pjsip_msg_body_create(tdata->pool, &xml_type, &xml_subtype, &xml_pj_str),
      possible_final_body = xml_part->body;
      multipart_parts++;
      pjsip_multipart_add_part(tdata->pool,
                               final_body,
                               xml_part);
    }

    if (as.include_register_request) {
      pjsip_multipart_part *request_part = pjsip_multipart_create_part(tdata->pool);
      pjsip_msg_print(received_register->msg_info.msg, buf, sizeof(buf));
      pj_str_t request_str = pj_str(buf);
      request_part->body = pjsip_msg_body_create(tdata->pool, &sip_type, &sip_subtype, &request_str),
      possible_final_body = request_part->body;
      multipart_parts++;
      pjsip_multipart_add_part(tdata->pool,
                               final_body,
                               request_part);
    };

    if (as.include_register_response) {
      pjsip_multipart_part *response_part = pjsip_multipart_create_part(tdata->pool);
      pjsip_msg_print(ok_response->msg, buf, sizeof(buf));
      pj_str_t response_str = pj_str(buf);
      response_part->body = pjsip_msg_body_create(tdata->pool, &sip_type, &sip_subtype, &response_str),
      possible_final_body = response_part->body;
      multipart_parts++;
      pjsip_multipart_add_part(tdata->pool,
                               final_body,
                               response_part);
    };

    if (multipart_parts == 0) {
      final_body = NULL;
    } else if (multipart_parts == 1) {
      final_body = possible_final_body;
    } else {
      // Just use the multipart MIME body you've built up
    };

    tdata->msg->body = final_body;

  }

  // Associate this transaction with mod_registrar, so that registrar_on_tsx_state_change gets called
  // if it fails
  status = pjsip_tsx_create_uac(&mod_registrar, tdata, &tsx);
  // DefaultHandling has a value of 0 or 1, so we can store it directly in the pointer. Not perfect, but
  // harmless if done right.
  tsx->mod_data[0] = (void*)as.default_handling;
  status = pjsip_tsx_send_msg(tsx, tdata);
}

void notify_application_servers() {
  LOG_DEBUG("In dummy notify_application_servers function");
  // TODO: implement as part of reg events package
}

static void expire_bindings(RegData::Store *store, const std::string& aor, const std::string& binding_id)
{
  //We need the retry loop to handle the store's compare-and-swap.
  for (;;)  // LCOV_EXCL_LINE No UT for retry loop.
  {
    RegData::AoR* aor_data = store->get_aor_data(aor);
    if (aor_data == NULL)
    {
      break;  // LCOV_EXCL_LINE No UT for lookup failure.
    }

    if (binding_id == "*") {
      // We only use this when doing some network-initiated deregistrations;
      // when the user deregisters all bindings another code path clears them
      LOG_INFO("Clearing all bindings!");
      aor_data->clear();
    } else {
      aor_data->remove_binding(binding_id);
    }

    bool ok = store->set_aor_data(aor, aor_data);
    delete aor_data;
    if (ok)
    {
      break;
    }
  }
};

void RegistrationUtils::network_initiated_deregistration(IfcHandler *ifchandler, RegData::Store *store, const std::string& aor, const std::string& binding_id)
{
  expire_bindings(store, aor, binding_id);

  // Note that 3GPP TS 24.229 V12.0.0 (2013-03) 5.4.1.7 doesn't specify that any binding information
  // should be passed on the REGISTER message, so we don't need the binding ID.
  deregister_with_application_servers(ifchandler, store, aor);
  notify_application_servers();
};

void RegistrationUtils::user_initiated_deregistration(IfcHandler *ifchandler, RegData::Store *store, const std::string& aor, const std::string& binding_id)
{
  expire_bindings(store, aor, binding_id);
  // No need to send a REGISTER message to the ASes - we hit this because we've received a REGISTER
  // from the user with an expiry time of 0, and we'll have forwarded that on.
};
