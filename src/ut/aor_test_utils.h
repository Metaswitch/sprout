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
  static const std::string CONTACT_URI = "<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>";
  static const std::string BINDING_ID = "<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1";
  static const std::string SUBSCRIPTION_ID = "1234";

  inline Binding*
    build_binding(std::string aor_id,
                  int now,
                  std::string uri = CONTACT_URI)
  {
    Binding* b = new Binding(aor_id);

    b->_uri = uri;
    b->_cid = "gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq";
    b->_cseq = 17038;
    b->_expires = now + 300;
    b->_priority = 0;
    b->_path_headers.push_back("<sip:abcdefgh@bono1.homedomain;lr>");
    b->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
    b->_params["reg-id"] = "1";
    b->_params["+sip.ice"] = "";
    b->_emergency_registration = false;
    b->_private_id = "6505550231";

    return b;
  }

  inline Subscription*
    build_subscription(std::string to_tag,
                       int now)
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
    s->_expires = now + 300;

    return s;
  }

  inline AoR* build_aor(std::string aor_id,
                        bool include_subscription = true)
  {
    AoR* aor = new AoR(aor_id);
    int now = time(NULL);

    Binding* b = build_binding(aor_id, now);
    aor->_bindings.insert(std::make_pair(BINDING_ID, b));

    if (include_subscription)
    {
      Subscription* s = build_subscription(SUBSCRIPTION_ID, now);
      aor->_subscriptions.insert(std::make_pair(SUBSCRIPTION_ID, s));
    }
    aor->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";
    aor->_associated_uris.add_uri(aor_id, false);

    return aor;
  }

  inline PatchObject* build_po(std::string aor_id)
  {
    PatchObject* po = new PatchObject();
    return po;
  }
};

#endif
