/**
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#include "gtest/gtest.h"
#include "contact_filtering.h"
#include "pjsip.h"
#include "pjutils.h"

// Defined in sip_parser.c in pjSIP
void init_sip_parser(void);
void deinit_sip_parser(void);

class GRUUTest : public ::testing::Test
{
public:
  static pj_caching_pool caching_pool;
  static pj_pool_t* pool;
  static pjsip_endpoint* endpt;

  static void SetUpTestCase()
  {
    pj_init();
    register_custom_headers();
    pj_caching_pool_init(&caching_pool, &pj_pool_factory_default_policy, 0);
    pjsip_endpt_create(&caching_pool.factory, NULL, &endpt);
    pool = pj_pool_create(&caching_pool.factory, "contact-filtering-test", 4000, 4000, NULL);
  };
  static void TearDownTestCase()
  {
    pj_pool_release(pool); pool = NULL;
    pjsip_endpt_destroy(endpt); endpt = NULL;
    pj_caching_pool_destroy(&caching_pool);
    pj_shutdown();
  };

  void create_binding(SubscriberDataManager::AoR::Binding& binding, std::string instance_id)
  {
    binding._uri = "sip:2125551212@192.168.0.1:55491;transport=TCP;rinstance=fad34fbcdea6a931";
    binding._cid = "gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq";
    binding._path_headers.push_back("sip:token@domain.com;lr");
    binding._path_headers.push_back("sip:token2@domain2.com;lr");
    binding._cseq = 3;
    binding._expires = 300;
    binding._priority = 1234;
    if (!instance_id.empty())
    {
      binding._params["+sip.instance"] = instance_id;
    };
    binding._params["+sip.boolean"] = "";
    binding._params["methods"] = "invite,options";
    binding._timer_id = "";
    binding._private_id = "user@domain.com";
    binding._emergency_registration = false;
  }
};
pj_pool_t* GRUUTest::pool;
pj_caching_pool GRUUTest::caching_pool;
pjsip_endpoint* GRUUTest::endpt;

TEST_F(GRUUTest, Simple)
{
  std::string aor = "sip:user@domain.com";
  SubscriberDataManager::AoR::Binding binding(&aor);
  create_binding(binding, "hello");
  ASSERT_EQ("sip:user@domain.com;gr=hello",
            PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, (pjsip_uri*)binding.pub_gruu(pool)));
}

TEST_F(GRUUTest, Proper)
{
  std::string aor = "sip:user@domain.com";
  SubscriberDataManager::AoR::Binding binding(&aor);
  create_binding(binding, "\"<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>\"");
  ASSERT_EQ("sip:user@domain.com;gr=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, (pjsip_uri*)binding.pub_gruu(pool)));
}

TEST_F(GRUUTest, NeedsEscaping)
{
  std::string aor = "sip:user@domain.com";
  SubscriberDataManager::AoR::Binding binding(&aor);
  create_binding(binding, "hel;lo");
  ASSERT_EQ("sip:user@domain.com;gr=hel%3blo",
            PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, (pjsip_uri*)binding.pub_gruu(pool)));
}

TEST_F(GRUUTest, NoInstanceID)
{
  std::string aor = "sip:user@domain.com";
  SubscriberDataManager::AoR::Binding binding(&aor);
  create_binding(binding, "");
  ASSERT_EQ(NULL, binding.pub_gruu(pool));
}

TEST_F(GRUUTest, NeedsEscapingQuoted)
{
  std::string aor = "sip:user@domain.com";
  SubscriberDataManager::AoR::Binding binding(&aor);
  create_binding(binding, "hel;lo");
  ASSERT_EQ("\"sip:user@domain.com;gr=hel%3blo\"", binding.pub_gruu_quoted_string(pool));
}

TEST_F(GRUUTest, NoInstanceIDQuoted)
{
  std::string aor = "sip:user@domain.com";
  SubscriberDataManager::AoR::Binding binding(&aor);
  create_binding(binding, "");
  ASSERT_EQ("", binding.pub_gruu_quoted_string(pool));
}
