/**
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef AOR_TEST_UTILS_H__
#define AOR_TEST_UTILS_H__

#include "aor.h"

namespace AoRTestUtils
{
  const std::string CONTACT_URI = "sip:6505550231@192.91.191.29:59934;transport=tcp;ob";
  const std::string BINDING_ID = "<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1";
  const std::string SUBSCRIPTION_ID = "1234";
  const std::string TIMER_ID = "123";
  const std::string SUBSCRIPTION_URI = "<sip:5102175698@cw-ngv.com>";

  inline Binding*
    build_binding(std::string aor_id,
                  int now,
                  std::string uri = CONTACT_URI,
                  int expiry = 300)
  {
    Binding* b = new Binding(aor_id);

    b->_uri = uri;
    b->_cid = "gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq";
    b->_cseq = 17038;
    b->_expires = now + expiry;
    b->_priority = 0;
    b->_path_headers.push_back("<sip:abcdefgh@bono1.homedomain;transport=tcp;lr>");
    b->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
    b->_params["reg-id"] = "1";
    b->_params["+sip.ice"] = "";
    b->_emergency_registration = false;
    b->_private_id = "6505550231";

    return b;
  }

  inline Subscription*
    build_subscription(std::string to_tag,
                       int now,
                       int expiry = 300)
  {
    Subscription* s = new Subscription;

    s->_req_uri = std::string(CONTACT_URI);
    s->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
    s->_from_tag = std::string("4321");
    s->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
    s->_to_tag = to_tag;
    s->_cid = std::string("xyzabc@192.91.191.29");
    // SDM-REFACTOR-TODO want to change the route URI to a full header not just the URI part.
    s->_route_uris.push_back(std::string("sip:abcdefgh@bono1.homedomain;lr"));
    s->_expires = now + expiry;

    return s;
  }

  inline AoR* create_simple_aor(std::string aor_id,
                                bool include_subscription = true,
                                bool set_timer_id = true,
                                int expiry = 300)
  {
    AoR* aor = new AoR(aor_id);
    int now = time(NULL);

    Binding* b = build_binding(aor_id, now, CONTACT_URI, expiry);
    aor->_bindings.insert(std::make_pair(BINDING_ID, b));

    if (include_subscription)
    {
      Subscription* s = build_subscription(SUBSCRIPTION_ID, now);
      aor->_subscriptions.insert(std::make_pair(SUBSCRIPTION_ID, s));
    }

    aor->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
    aor->_associated_uris.add_uri(aor_id, false);
    aor->_notify_cseq = 10;

    if (set_timer_id)
    {
      aor->_timer_id = TIMER_ID;
    }

    return aor;
  }

  // This adds a single binding and subscription, and either increments the CSeq
  // or sets it to a minimum.
  inline PatchObject* create_simple_patch(std::string aor_id,
                                          int minimum = 0)
  {
    int now = time(NULL);

    PatchObject* po = new PatchObject();

    Binding* b = build_binding(aor_id, now, CONTACT_URI, 600);
    po->_update_bindings.insert(std::make_pair(BINDING_ID, b));

    Subscription* s = build_subscription(SUBSCRIPTION_ID, now, 600);
    po->_update_subscriptions.insert(std::make_pair(SUBSCRIPTION_ID, s));

    if (minimum == 0)
    {
      po->_increment_cseq = true;
    }
    else
    {
      po->_minimum_cseq = minimum;
    }

    return po;
  }

  // This builds a complex patch which adds two bindings and two subscriptions,
  // removes two bindings and two subscriptions, updates the associated URIs,
  // and either increments the CSeq or sets it to a minimum.
  inline PatchObject* create_complex_patch(std::string aor_id,
                                           int minimum = 0)
  {
    int now = time(NULL);

    PatchObject* po = new PatchObject();

    std::string b_id1 = BINDING_ID;
    Binding* b1 = build_binding(aor_id, now, CONTACT_URI, 600);
    po->_update_bindings.insert(std::make_pair(b_id1, b1));

    std::string b_id2 = BINDING_ID + "2";
    Binding* b2 = build_binding(aor_id, now, CONTACT_URI, 600);
    po->_update_bindings.insert(std::make_pair(b_id2, b2));

    std::string s_id1 = SUBSCRIPTION_ID;
    Subscription* s1 = build_subscription(s_id1, now, 600);
    po->_update_subscriptions.insert(std::make_pair(s_id1, s1));

    std::string s_id2 = SUBSCRIPTION_ID + "2";
    Subscription* s2 = build_subscription(s_id2, now, 600);
    po->_update_subscriptions.insert(std::make_pair(s_id2, s2));

    po->_remove_bindings.push_back(BINDING_ID + "3");
    po->_remove_bindings.push_back(BINDING_ID + "4");

    po->_remove_subscriptions.push_back(SUBSCRIPTION_ID + "3");
    po->_remove_subscriptions.push_back(SUBSCRIPTION_ID + "4");

    AssociatedURIs associated_uris;
    associated_uris.add_uri(aor_id, false);
    associated_uris.add_uri(aor_id + "-wildcard!.*!", false);
    associated_uris.add_uri(aor_id + "-barred", true);
    associated_uris.add_wildcard_mapping(aor_id + "-wildcard", aor_id + "-wildcard!.*!");
    po->_associated_uris = associated_uris;

    if (minimum == 0)
    {
      po->_increment_cseq = true;
    }
    else
    {
      po->_minimum_cseq = minimum;
    }

    return po;
  }
};

#endif
