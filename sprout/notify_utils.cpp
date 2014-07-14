/**
 * @file notify_utils.cpp
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
#include "pjsip-simple/evsub.h"
#include <pjsip-simple/evsub_msg.h>
}

#include <string>
#include "pjutils.h"
#include "stack.h"
#include "notify_utils.h"
#include "log.h"
#include "constants.h"

// Return a XML registration node with the attributes populated
pj_xml_node* create_reg_node(pj_pool_t *pool,
                             pj_str_t *aor,
                             pj_str_t *id,
                             pj_str_t *state)
{
  LOG_DEBUG("Create registration node");

  pj_xml_node *reg_node;
  pj_xml_attr *attr;

  reg_node = pj_xml_node_new(pool, &STR_REGISTRATION);

  // Registration node requires a aor, id and state
  attr = pj_xml_attr_new(pool, &STR_AOR, aor);
  pj_xml_add_attr(reg_node, attr);
  attr = pj_xml_attr_new(pool, &STR_ID, id);
  pj_xml_add_attr(reg_node, attr);
  attr = pj_xml_attr_new(pool, &STR_STATE, state);
  pj_xml_add_attr(reg_node, attr);

  return reg_node;
}

// Return a XML contact node with the attributes populated
pj_xml_node* create_contact_node(pj_pool_t *pool,
                                 pj_str_t *id,
                                 pj_str_t *state,
                                 pj_str_t *event)
{
  LOG_DEBUG("Create contact node");

  pj_xml_node *contact_node;
  pj_xml_attr *attr;

  contact_node = pj_xml_node_new(pool, &STR_CONTACT);

  // Contact node requires an id, state and event
  attr = pj_xml_attr_new(pool, &STR_ID, id);
  pj_xml_add_attr(contact_node, attr);
  attr = pj_xml_attr_new(pool, &STR_STATE, state);
  pj_xml_add_attr(contact_node, attr);
  attr = pj_xml_attr_new(pool, &STR_EVENT, event);
  pj_xml_add_attr(contact_node, attr);

  return contact_node;
}

// Create complete XML body for a NOTIFY
pj_xml_node* notify_create_reg_state_xml(
                         pj_pool_t *pool,
                         std::string& aor,
                         RegStore::AoR::Subscription* subscription,
                         std::map<std::string, RegStore::AoR::Binding> bindings,
                         NotifyUtils::DocState doc_state,
                         NotifyUtils::RegContactSubState reg_state,
                         NotifyUtils::RegContactSubState contact_state,
                         NotifyUtils::ContactEvent contact_event)
{
  LOG_DEBUG("Create the XML body for a SIP NOTIFY");

  pj_xml_node *doc, *reg_node, *contact_node, *uri_node;
  pj_xml_attr *attr;

  // Create the root document
  doc = pj_xml_node_new(pool, &STR_REGINFO);

  // Add attributes to the doc
  attr = pj_xml_attr_new(pool, &STR_XMLNS_NAME, &STR_XMLNS_VAL);
  pj_xml_add_attr(doc, attr);
  attr = pj_xml_attr_new(pool, &STR_XMLNS_XSI_NAME, &STR_XMLNS_XSI_VAL);
  pj_xml_add_attr(doc, attr);
  attr = pj_xml_attr_new(pool, &STR_VERSION, &STR_VERSION_VAL);
  pj_xml_add_attr(doc, attr);

  // Add the state - this will be partial except on an initial subscription
  const pj_str_t* state_str = (doc_state == NotifyUtils::FULL) ?
                                                       &STR_FULL : &STR_PARTIAL;
  attr = pj_xml_attr_new(pool, &STR_STATE, state_str);
  pj_xml_add_attr(doc, attr);

  // Create the registration node
  pj_str_t reg_aor;
  pj_str_t reg_id;
  pj_str_t reg_state_str;

  pj_cstr(&reg_aor, aor.c_str());
  pj_cstr(&reg_id, subscription->_to_tag.c_str());
  reg_state_str = (reg_state == NotifyUtils::ACTIVE)
                                                  ? STR_ACTIVE : STR_TERMINATED;
  reg_node = create_reg_node(pool, &reg_aor, &reg_id, &reg_state_str);

  // Create the contact nodes
  // For each binding, add a contact node to the registration node
  for (std::map<std::string, RegStore::AoR::Binding>::const_iterator binding = bindings.begin();
       binding != bindings.end();
       ++binding)
  {
    // for each attribute, correctly populate
    pj_str_t c_id;
    pj_str_t c_state;
    pj_str_t c_event;

    pj_cstr(&c_id, binding->first.c_str());
    c_state = (contact_state == NotifyUtils::ACTIVE)
                                                  ? STR_ACTIVE : STR_TERMINATED;

    switch (contact_event)
    {
      case NotifyUtils::REGISTERED:
        c_event = STR_REGISTERED;
        break;
      case NotifyUtils::CREATED:
        c_event = STR_CREATED;
        break;
      // LCOV_EXCL_START
      case NotifyUtils::DEACTIVATED:
        c_event = STR_DEACTIVATED;
        break;
      // LCOV_EXCL_STOP
      case NotifyUtils::REFRESHED:
        c_event = STR_REFRESHED;
        break;
      case NotifyUtils::EXPIRED:
        c_event = STR_EXPIRED;
        break;
    }

    contact_node = create_contact_node(pool,
                                       &c_id,
                                       &c_state,
                                       &c_event);

    // Create and add URI element
    pj_str_t c_uri;

    if (binding->second._uri.size() > 0)
    {
      pj_cstr(&c_uri, binding->second._uri.c_str());
    }

    uri_node = pj_xml_node_new(pool, &STR_URI);
    pj_strdup(pool, &uri_node->content, &c_uri);
    pj_xml_add_node(contact_node, uri_node);

    // Add the contact node to the registration node
    pj_xml_add_node(reg_node, contact_node);
  }

  pj_xml_add_node(doc, reg_node);

  return doc;
}

// Print XML message body.
static int xml_print_body( struct pjsip_msg_body *msg_body,
                         char *buf, pj_size_t size)
{
  return pj_xml_print((const pj_xml_node*)msg_body->data, buf, size,
                       PJ_TRUE);
}

// Create the body of a SIP NOTIFY
pj_status_t notify_create_body(pjsip_msg_body* body,
                               pj_pool_t *pool,
                               std::string& aor,
                               RegStore::AoR::Subscription* subscription,
                               std::map<std::string, RegStore::AoR::Binding> bindings,
                               NotifyUtils::DocState doc_state,
                               NotifyUtils::RegContactSubState reg_state,
                               NotifyUtils::RegContactSubState contact_state,
                               NotifyUtils::ContactEvent contact_event)
{
  LOG_DEBUG("Create body of a SIP NOTIFY");

  pj_xml_node *doc;
  doc = notify_create_reg_state_xml(pool,
                                    aor,
                                    subscription,
                                    bindings,
                                    doc_state,
                                    reg_state,
                                    contact_state,
                                    contact_event);

  if (doc == NULL)
  {
    // LCOV_EXCL_START
    LOG_DEBUG("Failed to create body");
    return PJ_FALSE;
    // LCOV_EXCL_STOP
  }

  body->content_type.type = STR_MIME_TYPE;
  body->content_type.subtype = STR_MIME_SUBTYPE;

  body->data = doc;
  body->len = 0;

  body->print_body = &xml_print_body;

  return PJ_SUCCESS;
}

pj_status_t create_request_from_subscription(
                                     pjsip_tx_data** p_tdata,
                                     RegStore::AoR::Subscription* subscription,
                                     int cseq,
                                     pj_str_t* body)
{
  pj_str_t from;
  pj_str_t to;
  pj_str_t uri;
  pj_str_t cid;
  pj_cstr(&from, subscription->_to_uri.c_str());
  pj_cstr(&to, subscription->_from_uri.c_str());
  pj_cstr(&uri, subscription->_req_uri.c_str());
  pj_cstr(&cid, subscription->_cid.c_str());

  LOG_DEBUG("Create NOTIFY request");
  pj_status_t status = pjsip_endpt_create_request(stack_data.endpt,
                                                  pjsip_get_notify_method(),
                                                  &uri,
                                                  &from,
                                                  &to,
                                                  &stack_data.scscf_uri,
                                                  &cid,
                                                  cseq,
                                                  body,
                                                  p_tdata);

  return status;
}

// Create the request with to and from headers and a null body string, then add the body.
pj_status_t NotifyUtils::create_notify(
                                    pjsip_tx_data** tdata_notify,
                                    RegStore::AoR::Subscription* subscription,
                                    std::string aor,
                                    int cseq,
                                    std::map<std::string, RegStore::AoR::Binding> bindings,
                                    NotifyUtils::DocState doc_state,
                                    NotifyUtils::RegContactSubState reg_state,
                                    NotifyUtils::RegContactSubState contact_state,
                                    NotifyUtils::ContactEvent contact_event,
                                    NotifyUtils::RegContactSubState subscription_state,
                                    int expiry)
{
  pj_status_t status = create_request_from_subscription(tdata_notify,
                                                        subscription,
                                                        cseq,
                                                        NULL);
  if (status == PJ_SUCCESS)
  {

    // write tags to to and from headers
    pjsip_to_hdr *to;
    to = (pjsip_to_hdr*) pjsip_msg_find_hdr((*tdata_notify)->msg,
                                            PJSIP_H_TO,
                                            NULL);
    pj_str_t to_tag;
    pj_cstr(&to_tag, subscription->_from_tag.c_str());
    pj_strdup((*tdata_notify)->pool, &to->tag, &to_tag);

    pjsip_to_hdr *from;
    from = (pjsip_from_hdr*) pjsip_msg_find_hdr((*tdata_notify)->msg,
                                                PJSIP_H_FROM,
                                                NULL);
    pj_str_t from_tag;
    pj_cstr(&from_tag, subscription->_to_tag.c_str());
    pj_strdup((*tdata_notify)->pool, &from->tag, &from_tag);


    // populate route headers
    for (std::list<std::string>::const_iterator i = subscription->_route_uris.begin();
         i != subscription->_route_uris.end();
         ++i)
    {
      pjsip_route_hdr* route_hdr;
      route_hdr = pjsip_route_hdr_create((*tdata_notify)->pool);
      route_hdr->name_addr.uri = PJUtils::uri_from_string(*i,
                                                         (*tdata_notify)->pool);
      pj_list_push_back( &(*tdata_notify)->msg->hdr, route_hdr);
    }

    // Add the Event header
    pjsip_event_hdr* event_hdr = pjsip_event_hdr_create((*tdata_notify)->pool);
    event_hdr->event_type = STR_REG;
    pj_list_push_back( &(*tdata_notify)->msg->hdr, event_hdr);

    // Add the Subscription-State header
    pjsip_sub_state_hdr* sub_state_hdr = pjsip_sub_state_hdr_create((*tdata_notify)->pool);

    if (subscription_state == NotifyUtils::TERMINATED)
    {
      // The only reason we support is timeout (this also covers
      // actively unsubscribing)
      sub_state_hdr->sub_state = STR_TERMINATED;
      sub_state_hdr->reason_param = STR_TIMEOUT;
    }
    else
    {
      sub_state_hdr->sub_state = STR_ACTIVE;
      sub_state_hdr->expires_param = expiry;
    }

    pj_list_push_back( &(*tdata_notify)->msg->hdr, sub_state_hdr);

    // complete body
    pjsip_msg_body *body2;
    body2 = PJ_POOL_ZALLOC_T((*tdata_notify)->pool, pjsip_msg_body);
    status = notify_create_body(body2,
                               (*tdata_notify)->pool,
                                aor,
                                subscription,
                                bindings,
                                doc_state,
                                reg_state,
                                contact_state,
                                contact_event);
    (*tdata_notify)->msg->body = body2;
  }
  else
  {
   // LCOV_EXCL_START
    status = PJ_FALSE;
   // LCOV_EXCL_STOP
  }

  return status;
}
