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
#include <stdint.h>
}


#include <string>
#include <algorithm>
#include <cassert>
#include "regstore.h"
#include "constants.h"
#include "pjutils.h"
#include "stack.h"
#include "registrar.h"
#include "notify_utils.h"
#include "log.h"
#include <boost/lexical_cast.hpp>

#define MAX_SIP_MSG_SIZE 65535

/* MIME */
static const pj_str_t STR_MIME_TYPE    = { "application", 11 };
static const pj_str_t STR_MIME_SUBTYPE = { "reginfo+xml", 11 };

/* XML node name constants */
static const pj_str_t STR_REGISTRATION  = { "registration", 12 };
static const pj_str_t STR_CONTACT       = { "contact", 7 };
static const pj_str_t STR_URI           = { "uri", 3 };

/* XML node attribute constants */
static const pj_str_t STR_STATE         = { "state", 5 };
static const pj_str_t STR_AOR           = { "aor", 3 };
static const pj_str_t STR_ID            = { "id", 2 };
static const pj_str_t STR_EVENT         = { "event", 5 };
static const pj_str_t STR_DURATION      = { "duration-registered", 19 };
static const pj_str_t STR_EXPIRES       = { "expires", 7 };
static const pj_str_t STR_RETRY         = { "retry-after", 11 };
static const pj_str_t STR_Q             = { "q", 1 };
static const pj_str_t STR_CALLID        = { "callid", 6 };
static const pj_str_t STR_CSEQ          = { "cseq", 4 };

/* XML node registration STATE attribute enum constants. */
static const pj_str_t STR_INIT        = { "init", 4 };
static const pj_str_t STR_ACTIVE      = { "active", 6 };
static const pj_str_t STR_TERMINATED  = { "terminated", 10 };

/* XML node doc STATE attribute enum constants. */
static const pj_str_t STR_FULL           = { "full", 4 };
static const pj_str_t STR_PARTIAL        = { "partial", 7 };

/* XML node EVENT attribute enum constants. */
static const pj_str_t STR_REGISTERED     = { "registered", 10 };
static const pj_str_t STR_CREATED        = { "created", 7 };
static const pj_str_t STR_REFRESHED      = { "refreshed", 9 };
static const pj_str_t STR_SHORTENED      = { "shortened", 9 };
static const pj_str_t STR_EXPIRED        = { "expired", 7 };
static const pj_str_t STR_DEACTIVATED    = { "deactivated", 11 };
static const pj_str_t STR_PROBATION      = { "probation", 9 };
static const pj_str_t STR_UNREGISTERED   = { "unregistered", 12 };
static const pj_str_t STR_REJECTED       = { "rejected", 8 };

/* XML attributes constants */
static const pj_str_t STR_REGINFO        = { "reginfo", 7 };
static const pj_str_t STR_XMLNS_NAME     = { "xmlns", 5 };
static const pj_str_t STR_XMLNS_VAL      = { "urn:ietf:params:xml:ns:reginfo", 30 };
static const pj_str_t STR_VERSION        = { "version", 7 };
static const pj_str_t STR_VERSION_VAL    = { "0", 1 }; 
static const pj_str_t STR_XMLNS_XSI_NAME = { "xmlns:xsi", 9 };
static const pj_str_t STR_XMLNS_XSI_VAL  = { "http://www.w3.org/2001/XMLSchema-instance", 41 };

// XML schema location
static const pj_str_t STR_XSI_SLOC_NAME = { "xsi:schemaLocation", 18 };
static const pj_str_t STR_XSI_SLOC_VAL  = { "http://www.w3.org/2001/03/xml.xsd", 33 };

// return a xml registration node with the attributes populated
pj_xml_node* create_reg_node(pj_pool_t *pool,
                             pj_str_t *aor,
                             pj_str_t *id,
                             pj_str_t *state)
{
  pj_xml_node *reg_node;
  pj_xml_attr *attr;

  reg_node = pj_xml_node_new(pool, &STR_REGISTRATION);

  // aor - required
  attr = pj_xml_attr_new(pool, &STR_AOR, aor); 
  pj_xml_add_attr(reg_node, attr);
  // id - required
  attr = pj_xml_attr_new(pool, &STR_ID, id); 
  pj_xml_add_attr(reg_node, attr);
  // state - required
  attr = pj_xml_attr_new(pool, &STR_STATE, state); 
  pj_xml_add_attr(reg_node, attr);

  return reg_node;
}

// return a xml contact node with the attributes populated
pj_xml_node* create_contact_node(pj_pool_t *pool,
                                 pj_str_t *id,
                                 pj_str_t *state,
                                 pj_str_t *event,
                                 pj_str_t *duration,
                                 pj_str_t *expires,
                                 pj_str_t *retry,
                                 pj_str_t *q,
                                 pj_str_t *callid,
                                 pj_str_t *cseq)
{
  pj_xml_node *contact_node;
  pj_xml_attr *attr;

  contact_node = pj_xml_node_new(pool, &STR_CONTACT);

  // id - required
  attr = pj_xml_attr_new(pool, &STR_ID, id); 
  pj_xml_add_attr(contact_node, attr);
  // state - required
  attr = pj_xml_attr_new(pool, &STR_STATE, state); 
  pj_xml_add_attr(contact_node, attr);     
  // event - required
  attr = pj_xml_attr_new(pool, &STR_EVENT, event); 
  pj_xml_add_attr(contact_node, attr);

  // duration
  if (duration)
  {
    attr = pj_xml_attr_new(pool, &STR_DURATION, duration); 
    pj_xml_add_attr(contact_node, attr);
  }
  // expired 
  if (expires)
  {
    attr = pj_xml_attr_new(pool, &STR_EXPIRES, expires); 
    pj_xml_add_attr(contact_node, attr);
  }
  // retry-after 
  if (retry)
  { 
    attr = pj_xml_attr_new(pool, &STR_RETRY, retry); 
    pj_xml_add_attr(contact_node, attr);
  }
  // q 
  if (q)
  {
    attr = pj_xml_attr_new(pool, &STR_Q, q); 
    pj_xml_add_attr(contact_node, attr);
  }
  // callid
  if (callid)
  { 
    attr = pj_xml_attr_new(pool, &STR_CALLID, callid); 
    pj_xml_add_attr(contact_node, attr);
  }
  // cseq 
  if (cseq)
  {
    attr = pj_xml_attr_new(pool, &STR_CSEQ, cseq); 
    pj_xml_add_attr(contact_node, attr);
  }

  return contact_node;
}

// refer to RFC3680 for schema
// function to create complete xml body for a NOTIFY
pj_xml_node* notify_create_xml(pj_pool_t *pool,
                               std::string& aor,
                               RegStore::AoR::Subscription* subscription, 
                               const RegStore::AoR::Bindings& bindings,
                               NotifyUtils::DocState doc_state,
                               NotifyUtils::RegState reg_state)
{
  pj_xml_node *doc, *reg_node, *contact_node, *uri_node;
  pj_xml_attr *attr;

  if (!subscription)
  {
    return NULL;
  }

  /* Root document. refinfo */
  doc = pj_xml_node_new(pool, &STR_REGINFO);

  /* Add attributes to Root */
  // XMLNS
  attr = pj_xml_attr_new(pool, &STR_XMLNS_NAME, &STR_XMLNS_VAL);
  pj_xml_add_attr(doc, attr);
  // XMLNS XSI
  attr = pj_xml_attr_new(pool, &STR_XMLNS_XSI_NAME, &STR_XMLNS_XSI_VAL);
  pj_xml_add_attr(doc, attr);
  // version - required
  attr = pj_xml_attr_new(pool, &STR_VERSION, &STR_VERSION_VAL);
  pj_xml_add_attr(doc, attr);
  // state - required
  const pj_str_t* state_str = (doc_state == NotifyUtils::FULL) ? &STR_FULL : &STR_PARTIAL;
  attr = pj_xml_attr_new(pool, &STR_STATE, state_str);
  pj_xml_add_attr(doc, attr);

  // registration node
  pj_str_t reg_aor;
  pj_str_t reg_id;
  pj_str_t reg_state_str;

  reg_aor = pj_str(const_cast<char *>(aor.c_str()));
  reg_id = pj_str(const_cast<char *>(subscription->_to_tag.c_str()));

  switch (reg_state)
  {
    case NotifyUtils::INIT:
      reg_state_str = STR_INIT;
      break;  
    case NotifyUtils::ACTIVE:
      reg_state_str = STR_ACTIVE;
      break;  
    case NotifyUtils::TERMINATED:
      reg_state_str = STR_TERMINATED;
      break;  
  }

  reg_node = create_reg_node(pool, &reg_aor, &reg_id, &reg_state_str); 

  // contacts

  int now = time(NULL);

  // for each binding, add a contact node to the registration node
  for (RegStore::AoR::Bindings::const_iterator i = bindings.begin();
       i != bindings.end();
       ++i)
  {
    // for each attribute, correctly populate
    pj_str_t c_id;
    pj_str_t c_state;
    pj_str_t c_event;
    pj_cstr(&c_id, i->first.c_str());
//    *c_id =  pj_str(const_cast<char *>(i->first.c_str()));

    // TODO state and event need correct handling
    c_state = STR_ACTIVE; 
    c_event = STR_CREATED; 

    // optional attributes:
    pj_str_t c_duration; // don't have any way to know this
    pj_str_t c_expires;  //required for 'shortened' event
    pj_str_t c_retry; // required for 'probation' event
    pj_str_t c_q;
    pj_str_t c_callid;
    pj_str_t c_cseq;
    pj_str_t c_uri;

    int expires = std::max(0, i->second->_expires - now); // min value of 0
    pj_cstr(&c_expires, std::to_string(expires).c_str());
//    *c_expires = pj_str(const_cast<char *>(std::to_string(expires).c_str()));

    float q = (i->second->_priority / 1000);
    pj_cstr(&c_q, std::to_string(q).c_str());//*c_q = pj_str(const_cast<char *>(std::to_string(q).c_str()));

    if (i->second->_cid.size() > 0)
    {
pj_cstr(&c_callid, i->second->_cid.c_str());//      *c_callid = pj_str(const_cast<char *>(i->second->_cid.c_str()));
    }

pj_cstr(&c_cseq, std::to_string(i->second->_cseq).c_str());//    *c_cseq = pj_str(const_cast<char *>(std::to_string(i->second->_cseq).c_str()));

    if (i->second->_uri.size() > 0)
    {
pj_cstr(&c_uri, i->second->_uri.c_str());//      *c_uri = pj_str(const_cast<char *>(i->second->_uri.c_str()));
    }

    contact_node = create_contact_node(pool, 
                                       &c_id, 
                                       &c_state, 
                                       &c_event, 
                                       &c_duration,
                                       &c_expires, 
                                       &c_retry, 
                                       &c_q, 
                                       &c_callid, 
                                       &c_cseq);

    // create and add uri element
    uri_node = pj_xml_node_new(pool, &STR_URI);
    pj_strdup(pool, &uri_node->content, &c_uri);
    pj_xml_add_node(contact_node, uri_node);

    // we don't add a display-name, but do it here if we do 
   
    pj_xml_add_node(reg_node, contact_node);
  }

  pj_xml_add_node(doc, reg_node);
    
  /* Done! */

  return doc;
}


/*
* Function to print XML message body.
*/
static int xml_print_body( struct pjsip_msg_body *msg_body,
                         char *buf, pj_size_t size)
{
    return pj_xml_print((const pj_xml_node*)msg_body->data, buf, size,
                            PJ_TRUE);
}


/*
* Function to clone XML document.
*/
static void* xml_clone_data(pj_pool_t *pool, const void *data, unsigned len)
{
    PJ_UNUSED_ARG(len);
    return pj_xml_clone( pool, (const pj_xml_node*)data);
}




void NotifyUtils::notify_create_body(pjsip_msg_body* body,
                                     pj_pool_t *pool,
                                     std::string& aor,
                                     RegStore::AoR::Subscription* subscription,
                                     const RegStore::AoR::Bindings& bindings,
                                     NotifyUtils::DocState doc_state,
                                     NotifyUtils::RegState reg_state)
{
  pj_xml_node *doc;

  doc = notify_create_xml(pool, aor, subscription, bindings, doc_state, reg_state);

  body->content_type.type = STR_MIME_TYPE;
  body->content_type.subtype = STR_MIME_SUBTYPE;

  body->data = doc;
  body->len = 0;

  body->print_body = &xml_print_body;
  body->clone_data = &xml_clone_data;
}

pj_str_t NotifyUtils::create_contact(pj_str_t aor, std::string id, pj_str_t state, std::string uri, std::string display_name, std::string unknown_param)
{
  return {NULL, 0};
}

pj_status_t NotifyUtils::create_request_from_subscription(pjsip_tx_data** p_tdata, RegStore::AoR::Subscription* subscription, int cseq, pj_str_t* body)
{
  // TODO no route headers yet. 
  pj_str_t from;
  pj_str_t to;
  pj_str_t uri;
  pj_str_t cid;
  pj_cstr(&from, subscription->_from_uri.c_str());
  pj_cstr(&to, subscription->_to_uri.c_str());
  pj_cstr(&uri, subscription->_req_uri.c_str());
  pj_cstr(&cid, subscription->_cid.c_str());

  return pjsip_endpt_create_request(stack_data.endpt,
                                    pjsip_get_notify_method(),
                                    &uri,
                                    &from,
                                    &to,
                                    &uri,
                                    &cid,
                                    cseq,
                                    body,
                                    p_tdata);
}
