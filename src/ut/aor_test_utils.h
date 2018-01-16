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
    build_binding(AoR* aor,
                  int now,
                  const std::string& id = "<urn:uuid:00000000-0000-0000-0000-b4dd32817622>:1")
  {
    Binding* b = aor->get_binding(std::string(id));
    b->_uri = std::string("<sip:6505550231@192.91.191.29:59934;transport=tcp;ob>");
    b->_cid = std::string("gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq");
    b->_cseq = 17038;
    b->_expires = now + 5;
    b->_priority = 0;
    b->_path_headers.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
    b->_params["+sip.instance"] = "\"<urn:uuid:00000000-0000-0000-0000-b4dd32817622>\"";
    b->_params["reg-id"] = "1";
    b->_params["+sip.ice"] = "";
    b->_emergency_registration = false;
    b->_private_id = "6505550231";
    return b;
  }

  inline Subscription*
    build_subscription(AoR* aor,
                       int now,
                       const std::string& id = "1234")
  {
    Subscription* s = aor->get_subscription(id);
    s->_req_uri = std::string("sip:5102175698@192.91.191.29:59934;transport=tcp");
    s->_from_uri = std::string("<sip:5102175698@cw-ngv.com>");
    s->_from_tag = std::string("4321");
    s->_to_uri = std::string("<sip:5102175698@cw-ngv.com>");
    s->_to_tag = std::string("1234");
    s->_cid = std::string("xyzabc@192.91.191.29");
    s->_route_uris.push_back(std::string("<sip:abcdefgh@bono-1.cw-ngv.com;lr>"));
    s->_expires = now + 300;
    return s;
  }

  inline AoR* build_aor(std::string aor_id,
                 bool include_subscription = true)
  {
    AoR* aor = new AoR(aor_id);
    int now = time(NULL);
    build_binding(aor, now);
    if (include_subscription)
    {
      build_subscription(aor, now);
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
