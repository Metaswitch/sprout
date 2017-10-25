/**
 * @file notify_utils.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
#include "wildcard_utils.h"
#include "sproutsasevent.h"

// Return a XML registration node with the attributes populated
pj_xml_node* create_reg_node(pj_pool_t *pool,
                             pj_str_t *aor,
                             pj_str_t *id,
                             pj_str_t *state)
{
  TRC_DEBUG("Create registration node");

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
  TRC_DEBUG("Create contact node");

  pj_xml_node *contact_node;
  pj_xml_attr *attr;

  contact_node = pj_xml_node_new(pool, &STR_CONTACT);

  // Contact node requires an id, state and event
  attr = pj_xml_attr_new(pool, &STR_ID, id);
  pj_xml_add_attr(contact_node, attr);
  attr = pj_xml_attr_new(pool, &STR_STATE, state);
  pj_xml_add_attr(contact_node, attr);
  attr = pj_xml_attr_new(pool, &STR_EVENT_LOWER, event);
  pj_xml_add_attr(contact_node, attr);

  return contact_node;
}

// Create complete XML body for a NOTIFY
pj_xml_node* notify_create_reg_state_xml(
                         pj_pool_t *pool,
                         std::string& aor,
                         AssociatedURIs* associated_uris,
                         AoR::Subscription* subscription,
                         std::vector<NotifyUtils::BindingNotifyInformation*> bnis,
                         NotifyUtils::RegistrationState reg_state,
                         SAS::TrailId trail)
{
  TRC_DEBUG("Create the XML body for a SIP NOTIFY");

  pj_xml_node *doc, *reg_node, *contact_node, *uri_node;
  pj_xml_attr *attr;

  // Create the root document
  doc = pj_xml_node_new(pool, &STR_REGINFO);

  // Add attributes to the doc
  attr = pj_xml_attr_new(pool, &STR_XMLNS_NAME, &STR_XMLNS_VAL);
  pj_xml_add_attr(doc, attr);
  attr = pj_xml_attr_new(pool, &STR_XMLNS_GRUU_NAME, &STR_XMLNS_GRUU_VAL);
  pj_xml_add_attr(doc, attr);
  attr = pj_xml_attr_new(pool, &STR_XMLNS_XSI_NAME, &STR_XMLNS_XSI_VAL);
  pj_xml_add_attr(doc, attr);
  attr = pj_xml_attr_new(pool, &STR_XMLNS_ERE_NAME, &STR_XMLNS_ERE_VAL);
  pj_xml_add_attr(doc, attr);
  attr = pj_xml_attr_new(pool, &STR_VERSION, &STR_VERSION_VAL);
  pj_xml_add_attr(doc, attr);

  // Add the state - this will be partial except on an initial subscription
  const pj_str_t* state_str = &STR_FULL;
  attr = pj_xml_attr_new(pool, &STR_STATE, state_str);
  pj_xml_add_attr(doc, attr);

  // Create the registration nodes.  We need one per IMPU in the Implicit
  // Registration Set, with the same binding/contact information in each.
  //
  // Note that TS24.229 is ambiguous on how bindings for different IMPUs in an
  // IRS should be reported (see 5.4.2.1.2 4) e) IV) ).  For now, Clearwater
  // assumes that the same binding/contact data needs to be reported for each
  // IMPU.
  pj_str_t reg_aor;
  pj_str_t reg_id;
  pj_str_t reg_state_str;

  // Log any URIs that have been left out of the P-Associated-URI because they
  // are barred.
  std::vector<std::string> barred_uris = associated_uris->get_barred_uris();
  if (!barred_uris.empty())
  {
    std::stringstream ss;
    std::copy(barred_uris.begin(), barred_uris.end(), std::ostream_iterator<std::string>(ss, ","));
    std::string list = ss.str();
    if (!list.empty())
    {
      // Strip the trailing comma.
      list = list.substr(0, list.length() - 1);
    }

    SAS::Event event(trail, SASEvent::OMIT_BARRED_ID_FROM_NOTIFY, 0);
    event.add_var_param(list);
    SAS::report_event(event);
  }

  // Iterate over the unbarred IMPUs in the IRS, inserting a registration
  // element for each one
  std::vector<std::string> irs_impus = associated_uris->get_unbarred_uris();
  for (std::vector<std::string>::const_iterator impu = irs_impus.begin();
       impu != irs_impus.end();
       ++impu)
  {
    bool is_wildcard_impu = WildcardUtils::is_wildcard_uri(*impu);
    TRC_DEBUG("Insert registration element for one IRS");
    // Escape the IMPU as an aor
    std::string unescaped_aor = *impu;

    // For each wildcarded identity, the TS specs (24.229) say that the aor
    // should be set to an arbitrary IMPU that matches the wildcard identity.
    // The S-CSCF may not know of any IMPUs that definitely match the wildcard
    // however, so we'd just have to just create one. This is hard (it’s also
    // potentially impossible as the wildcard regex could be written in such a
    // way as that there are no valid matches). Also, the created IMPU may not
    // actually match the wildcard anyway (as it could belong to a different
    // wildcard range, or be a distinct IMPU in its own right) – the S-CSCF
    // doesn’t have enough information to determine this, and any single HSS
    // doesn’t have enough information either. Probably because of this
    // uncertainty, the TS spec is clear that the receiver of the NOTIFY will
    // not use the value of the aor attribute. Rather than solve an impossible
    // problem to populate the aor attribute that then shouldn’t be used by
    // anything, the aor attribute is always set to sip:wildcardimpu@wildcard
    // for a wildcard IMPU.
    if (is_wildcard_impu)
    {
      unescaped_aor = "sip:wildcardimpu@wildcard";
    }

    pj_strdup2(pool, &reg_aor, Utils::xml_escape(unescaped_aor).c_str());
    std::string unescaped_reg_id = subscription->_to_tag;
    pj_strdup2(pool, &reg_id, Utils::xml_escape(unescaped_reg_id).c_str());
    reg_state_str = (reg_state == NotifyUtils::RegistrationState::ACTIVE)
                                                    ? STR_ACTIVE : STR_TERMINATED;
    reg_node = create_reg_node(pool, &reg_aor, &reg_id, &reg_state_str);

    // Create the contact nodes
    // For each binding, add a contact node to the registration node
    for (std::vector<NotifyUtils::BindingNotifyInformation*>::const_iterator bni =
           bnis.begin();
         bni != bnis.end();
         ++bni)
    {
      // for each attribute, correctly populate
      pj_str_t c_id;
      pj_str_t c_state;
      pj_str_t c_event;

      std::string unescaped_c_id = (*bni)->_id;
      pj_strdup2(pool, &c_id, Utils::xml_escape(unescaped_c_id).c_str());

      switch ((*bni)->_contact_event)
      {
        case NotifyUtils::ContactEvent::REGISTERED:
          c_event = STR_REGISTERED;
          c_state = STR_ACTIVE;
          break;
        case NotifyUtils::ContactEvent::CREATED:
          c_event = STR_CREATED;
          c_state = STR_ACTIVE;
          break;
        case NotifyUtils::ContactEvent::REFRESHED:
          c_event = STR_REFRESHED;
          c_state = STR_ACTIVE;
          break;
        case NotifyUtils::ContactEvent::SHORTENED:
          c_event = STR_SHORTENED;
          c_state = STR_ACTIVE;
          break;
        case NotifyUtils::ContactEvent::EXPIRED:
          c_event = STR_EXPIRED;
          c_state = STR_TERMINATED;
          break;
        case NotifyUtils::ContactEvent::UNREGISTERED:
          c_event = STR_UNREGISTERED;
          c_state = STR_TERMINATED;
          break;
        case NotifyUtils::ContactEvent::DEACTIVATED:
          c_event = STR_DEACTIVATED;
          c_state = STR_TERMINATED;
          break;
      }

      contact_node = create_contact_node(pool,
                                         &c_id,
                                         &c_state,
                                         &c_event);

      // Create and add URI element
      pj_str_t c_uri;

      if ((*bni)->_b->_uri.size() > 0)
      {
        std::string unescaped_c_uri = (*bni)->_b->_uri;
        pj_strdup2(pool, &c_uri, Utils::xml_escape(unescaped_c_uri).c_str());
      }

      uri_node = pj_xml_node_new(pool, &STR_URI);
      pj_strdup(pool, &uri_node->content, &c_uri);
      pj_xml_add_node(contact_node, uri_node);

      pj_str_t gruu;
      pj_strdup2(pool,
                 &gruu,
                 Utils::xml_escape((*bni)->_b->pub_gruu_str(pool)).c_str());

      // Add all 'unknown parameters' from the contact header into the contact
      // element as <unknown-param> elements. For example, a contact header that
      // looks like this:
      //
      //     Contact: <sip:alice@example.com;p1=v1>;expires=3600;p2;p3=v3
      //
      // Would result in the following unknown param elements being added.
      //
      //     <unknown-param name="p2" />
      //     <unknown-param name="p3">v3<unknown-param>
      //
      // Note that p1 is not included (as it's a URI parameter) and expires is
      // not included (as it is defined in RFC 3261 so is a 'known' parameter).
      for (const std::pair<std::string, std::string>& param: (*bni)->_b->_params)
      {
        // RFC 3680 defines unknown parameters as any parameter not defined in
        // RFC 3261. RFC 3261 defines 'q' and 'expires' so don't add these.
        if ((param.first != "q") && (param.first != "expires"))
        {
          // Add the parameter value as the element content, and the parameter
          // name as the 'name' attribute.
          pj_xml_node* unknown_param_node = pj_xml_node_new(pool, &STR_UNKNOWN_PARAM);
          std::string escaped_value = Utils::xml_check_escape(param.second);
          pj_strdup2(pool, &unknown_param_node->content, escaped_value.c_str());

          pj_str_t param_name;
          pj_strdup2(pool, &param_name, param.first.c_str());
          pj_xml_attr* name_attr = pj_xml_attr_new(pool, &STR_NAME, &param_name);
          pj_xml_add_attr(unknown_param_node, name_attr);

          pj_xml_add_node(contact_node, unknown_param_node);
        }
      }

      if (gruu.slen != 0)
      {
        TRC_DEBUG("Create pub-gruu node");

        pj_xml_node* gruu_node = pj_xml_node_new(pool, &STR_XML_PUB_GRUU);
        attr = pj_xml_attr_new(pool, &STR_URI, &gruu);
        pj_xml_add_attr(gruu_node, attr);
        pj_xml_add_node(contact_node, gruu_node);
      }

      if (is_wildcard_impu)
      {
        // Add the wildcard node to the registration node
        TRC_DEBUG("Add wildcard registration node");
        pj_str_t c_wildcard;
        pj_strdup2(pool, &c_wildcard, Utils::xml_escape(*impu).c_str());
        pj_xml_node* wildcard_node = pj_xml_node_new(pool, &STR_WILDCARD);
        pj_strdup(pool, &wildcard_node->content, &c_wildcard);
        pj_xml_add_node(reg_node, wildcard_node);
      }

      // Add the contact node to the registration node
      pj_xml_add_node(reg_node, contact_node);
    }

    pj_xml_add_node(doc, reg_node);

  }
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
                               AssociatedURIs* associated_uris,
                               AoR::Subscription* subscription,
                               std::vector<NotifyUtils::BindingNotifyInformation*> bnis,
                               NotifyUtils::RegistrationState reg_state,
                               SAS::TrailId trail)
{
  TRC_DEBUG("Create body of a SIP NOTIFY");

  pj_xml_node *doc;
  doc = notify_create_reg_state_xml(pool,
                                    aor,
                                    associated_uris,
                                    subscription,
                                    bnis,
                                    reg_state,
                                    trail);

  if (doc == NULL)
  {
    // LCOV_EXCL_START
    TRC_DEBUG("Failed to create body");
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
                                     AoR::Subscription* subscription,
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

  TRC_DEBUG("Create NOTIFY request");
  pj_status_t status = pjsip_endpt_create_request(stack_data.endpt,
                                                  pjsip_get_notify_method(),
                                                  &uri,
                                                  &from,
                                                  &to,
                                                  &stack_data.scscf_contact,
                                                  &cid,
                                                  cseq,
                                                  body,
                                                  p_tdata);

  return status;
}

// Pass the correct subscription parameters in to create_notify
pj_status_t NotifyUtils::create_subscription_notify(
                                    pjsip_tx_data** tdata_notify,
                                    AoR::Subscription* s,
                                    std::string aor,
                                    AssociatedURIs* associated_uris,
                                    AoR* aor_data,
                                    std::vector<NotifyUtils::BindingNotifyInformation*> bnis,
                                    NotifyUtils::RegistrationState reg_state,
                                    int now,
                                    SAS::TrailId trail)
{
  // Set the correct subscription state header
  NotifyUtils::SubscriptionState state = NotifyUtils::SubscriptionState::ACTIVE;

  int expiry = (s->_expires > now) ? (s->_expires - now) : 0;

  if (expiry == 0)
  {
    state = NotifyUtils::SubscriptionState::TERMINATED;
  }

  pj_status_t status = NotifyUtils::create_notify(tdata_notify,
                                                  s,
                                                  aor,
                                                  associated_uris,
                                                  aor_data->_notify_cseq,
                                                  bnis,
                                                  reg_state,
                                                  state,
                                                  expiry,
                                                  trail);
  return status;
}
// Create the request with to and from headers and a null body string, then add the body.
pj_status_t NotifyUtils::create_notify(
                                    pjsip_tx_data** tdata_notify,
                                    AoR::Subscription* subscription,
                                    std::string aor,
                                    AssociatedURIs* associated_uris,
                                    int cseq,
                                    std::vector<NotifyUtils::BindingNotifyInformation*> bnis,
                                    NotifyUtils::RegistrationState reg_state,
                                    NotifyUtils::SubscriptionState subscription_state,
                                    int expiry,
                                    SAS::TrailId trail)
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

    if (subscription_state == NotifyUtils::SubscriptionState::TERMINATED)
    {
      // If there are any bindings remaining (e.g. the registration state isn't
      // terminated) set the reason to timeout. Otherwise set it to deactivated
      sub_state_hdr->sub_state = STR_TERMINATED;

      if (reg_state == NotifyUtils::RegistrationState::TERMINATED)
      {
        sub_state_hdr->reason_param = STR_DEACTIVATED;
      }
      else
      {
        sub_state_hdr->reason_param = STR_TIMEOUT;
      }
    }
    else
    {
      // If the subscription is active add the expiry parameter
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
                                associated_uris,
                                subscription,
                                bnis,
                                reg_state,
                                trail);
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
