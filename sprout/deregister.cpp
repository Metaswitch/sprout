/**
 * @file deregister.cpp Deregistration functions
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
#include "regdata.h"
#include "ifchandler.h"
#include "pjutils.h"
#include "stack.h"
#include "registrar.h"
#include "deregister.h"
#include "log.h"

void deregister_with_application_servers(IfcHandler *ifchandler,
    const std::string aor)
{
  register_with_application_servers(ifchandler, NULL, NULL, 0, aor);
}

void register_with_application_servers(IfcHandler *ifchandler,
                                       pjsip_rx_data *received_register,
                                       pjsip_tx_data *ok_response,
                                       int expires,
                                       const std::string aor)
{
  std::vector<AsInvocation> as_list;
  std::vector<AsInvocation>::iterator as_iter;
  //SAS::TrailId trail = get_trail(ok_response);
  SAS::TrailId trail;
  LOG_INFO("Looking up list of Application Servers");
  if (received_register == NULL && expires == 0) {
    LOG_INFO("Expires is 0: generating a fake REGISTER to send to IfcHandler using AOR %s", aor.c_str());
    pjsip_method method;
    pjsip_method_set(&method, PJSIP_REGISTER_METHOD);
    pjsip_tx_data *tdata;
    pj_str_t bono_uri = pj_str(strdup(std::string("<sip:"+std::string(pj_strbuf(&stack_data.home_domain), pj_strlen(&stack_data.home_domain))+">").c_str()));
    pj_str_t aor_uri = pj_str(strdup(std::string("<"+aor+">").c_str()));
    pjsip_endpt_create_request(stack_data.endpt,
                               &method,       // Method
                               &bono_uri,     // Target
                               &aor_uri,      // From
                               &aor_uri,      // To
                               &aor_uri,      // Contact
                               NULL,          // Auto-generate Call-ID
                               1,             // CSeq
                               NULL,          // No body
                               &tdata);       // OUT
    std::string served_user = ifchandler->served_user_from_msg(SessionCase::Terminating, tdata->msg);
    ifchandler->lookup_ifcs(SessionCase::Terminating, served_user, true, tdata->msg, trail, as_list);
    pj_status_t status = pjsip_tx_data_dec_ref(tdata);
    assert(status == PJSIP_EBUFDESTROYED);
  } else {
    std::string served_user = ifchandler->served_user_from_msg(SessionCase::Terminating, received_register->msg_info.msg);
    ifchandler->lookup_ifcs(SessionCase::Terminating, served_user, true, received_register->msg_info.msg, trail, as_list);
  }
  LOG_INFO("Found %d Application Servers", as_list.size());

  // Loop through the as_list
  for(as_iter = as_list.begin(); as_iter != as_list.end(); as_iter++) {
    send_register_to_as(received_register, ok_response, &*as_iter, expires, aor);
  }

}

void send_register_to_as(pjsip_rx_data *received_register, pjsip_tx_data *ok_response, AsInvocation *as, int expires, std::string aor)
{
  pj_status_t status;
  pjsip_tx_data *tdata;
  pjsip_transaction *tsx;

  pjsip_method method;
  pjsip_method_set(&method, PJSIP_REGISTER_METHOD);

  std::string user_uri_string;
  char trusted_port[6] = "";
  snprintf(trusted_port, sizeof(trusted_port), "%d", stack_data.trusted_port);
  if (received_register) {
    user_uri_string = PJUtils::uri_to_string(PJSIP_URI_IN_FROMTO_HDR, (pjsip_uri *)pjsip_uri_get_uri(PJSIP_MSG_TO_HDR(received_register->msg_info.msg)->uri));
  } else {
    user_uri_string = aor;
  }
  pj_str_t user_uri = pj_str(strdup(user_uri_string.c_str()));

  pj_str_t scscf_uri = pj_str(strdup(std::string(
                                       "<sip:" +
                                       PJUtils::pj_str_to_string(&stack_data.sprout_cluster_domain) +
                                       ":" + std::string(trusted_port) + ">").c_str()));
  pj_str_t as_uri = pj_str(strdup(as->server_name.c_str()));

  pjsip_endpt_create_request(stack_data.endpt,
                             &method,      // Method
                             &as_uri,      // Target
                             &scscf_uri,   // From
                             &user_uri,      // To
                             &scscf_uri,   // Contact
                             NULL,         // Auto-generate Call-ID
                             1,            // CSeq
                             NULL,         // No body
                             &tdata);      // OUT

  // Expires header based on 200 OK response
  pj_str_t expires_pjstr = pj_str("Expires");
  pjsip_hdr *expires_hdr = (pjsip_hdr *)pjsip_generic_int_hdr_create(tdata->pool, &expires_pjstr, expires);
  pjsip_msg_add_hdr(tdata->msg, expires_hdr);

  // TODO: modify orig-ioi of P-Charging-Vector and remove term-ioi
  // TODO: Set P-Charging-Function-Addresses header based on HSS values

  if (received_register && ok_response) {

    pj_str_t pani_pjstr = pj_str("P-Access-Network-Info");
    pj_str_t pvni_pjstr = pj_str("P-Visited-Network-Id");
    pjsip_hdr *original_pani_hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(received_register->msg_info.msg, &pani_pjstr, NULL);
    if (original_pani_hdr) {
      pjsip_hdr *pani_hdr = (pjsip_hdr *)pjsip_hdr_clone(tdata->pool, original_pani_hdr);
      pjsip_msg_add_hdr(tdata->msg, pani_hdr);
    };

    pjsip_hdr *original_pvni_hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(received_register->msg_info.msg, &pvni_pjstr, NULL);
    if (original_pvni_hdr) {
      pjsip_hdr *pvni_hdr = (pjsip_hdr *)pjsip_hdr_clone(tdata->pool, original_pvni_hdr);
      pjsip_msg_add_hdr(tdata->msg, pvni_hdr);
    };

    // Body based on Filter Criteria
    char buf[8196];
    pj_str_t sip_type = pj_str("message");
    pj_str_t sip_subtype = pj_str("sip");
    pj_str_t xml_type = pj_str("application");
    pj_str_t xml_subtype = pj_str("3gpp-ims+xml");

    // Build up this multipart body incrementally, based on the ServiceInfo, IncludeRegisterRequest and IncludeRegisterResponse fields
    pjsip_msg_body *final_body = pjsip_multipart_create(tdata->pool, NULL, NULL);

    // If we only have one, we don't want a multipart MIME body - store the reference to each one here to use instead
    pjsip_msg_body *possible_final_body;
    int multipart_parts = 0;

    if (!as->service_info.empty()) {
      pjsip_multipart_part *xml_part = pjsip_multipart_create_part(tdata->pool);
      std::string xml_str = "<ims-3gpp><service-info>"+as->service_info+"</service-info></ims-3gpp>";
      pj_str_t xml_pj_str = pj_str(strdup(xml_str.c_str()));
      xml_part->body = pjsip_msg_body_create(tdata->pool, &xml_type, &xml_subtype, &xml_pj_str),
      possible_final_body = xml_part->body;
      multipart_parts++;
      pjsip_multipart_add_part(tdata->pool,
                               final_body,
                               xml_part);
    }

    if (as->include_register_request) {
      pjsip_multipart_part *request_part = pjsip_multipart_create_part(tdata->pool);
      pjsip_msg_print(received_register->msg_info.msg, buf, 8196);
      pj_str_t request_str = pj_str(buf);
      request_part->body = pjsip_msg_body_create(tdata->pool, &sip_type, &sip_subtype, &request_str),
      possible_final_body = request_part->body;
      multipart_parts++;
      pjsip_multipart_add_part(tdata->pool,
                               final_body,
                               request_part);
    };

    if (as->include_register_response) {
      pjsip_multipart_part *response_part = pjsip_multipart_create_part(tdata->pool);
      pjsip_msg_print(ok_response->msg, buf, 8196);
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

  char for_printing[8196];
  pjsip_msg_print(tdata->msg, for_printing, 8186);
  LOG_DEBUG("Outgoing REGISTER request to AS: %s\n", for_printing);

  status = pjsip_tsx_create_uac(&mod_registrar, tdata, &tsx);
  status = pjsip_tsx_send_msg(tsx, tdata);
}

void notify_application_servers() {}

void expire_bindings(RegData::Store *store, const std::string aor, const std::string binding_id)
{
  //We need the retry loop to handle the store's compare-and-swap.
  RegData::AoR *aor_data;
  do {
    aor_data = store->get_aor_data(aor);
    if (binding_id == "*") {
      LOG_INFO("Clearing all bindings!");
      aor_data->clear();
    } else {
      aor_data->remove_binding(binding_id);
    }
  } while (!store->set_aor_data(aor, aor_data));

  delete aor_data;
};

void network_initiated_deregistration(IfcHandler *ifchandler, RegData::Store *store, const std::string aor, const std::string binding_id)
{
  expire_bindings(store, aor, binding_id);
  deregister_with_application_servers(ifchandler, aor);
  notify_application_servers();
};

void user_initiated_deregistration(IfcHandler *ifchandler, RegData::Store *store, const std::string aor, const std::string binding_id)
{
  expire_bindings(store, aor, binding_id);
};
