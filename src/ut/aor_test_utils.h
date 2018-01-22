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
  inline Binding*
    build_binding(std::string aor_id,
                  int now)
  {
    Binding* b = new Binding(aor_id);

    b->_uri = "<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>";
    b->_cid = "gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq";
    b->_cseq = 17038;
    b->_expires = now + 5;
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

    s->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
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

    std::string binding_id = "<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1";
    Binding* b = build_binding(aor_id, now);
    aor->_bindings.insert(std::make_pair(binding_id, b));

    if (include_subscription)
    {
      std::string to_tag = "1234";
      Subscription* s = build_subscription(to_tag, now);
      aor->_subscriptions.insert(std::make_pair(to_tag, s));
    }
    aor->_scscf_uri = "sip:scscf.sprout.homedomain:5058;transport=TCP";

    return aor;
  }

  inline PatchObject* build_po(std::string aor_id)
  {
    PatchObject* po = new PatchObject();
    return po;
  }
};

#endif
