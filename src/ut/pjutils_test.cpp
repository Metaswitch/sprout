/**
 * @file pjutils_test.cpp UT for PJUtils.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2015 Metaswitch Networks Ltd
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

///
///----------------------------------------------------------------------------

#include <string>
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "basetest.hpp"
#include "pjsip.h"
#include "pjutils.h"

 class PJUtilsTest : public BaseTest
 {
 public:
   static pj_caching_pool caching_pool;
   static pj_pool_t* pool;
   static pjsip_endpoint* endpt;

  static void SetUpTestCase()
  {
    pj_init();
    pj_caching_pool_init(&caching_pool, &pj_pool_factory_default_policy, 0);
    pjsip_endpt_create(&caching_pool.factory, NULL, &endpt);
    pool = pj_pool_create(&caching_pool.factory, "contact-filtering-test", 4000, 4000, NULL);
  };

    PJUtilsTest()
    {
    }

    virtual ~PJUtilsTest()
    {
    }
 };



 TEST_F(PJUtilsTest, GetDNTest)
 {
    std::string uri_str = "sip:2012030005@domain.com";
    pjsip_uri* uri = PJUtils::uri_from_string(uri_str, pool);
    std::string routing_value;

    EXPECT_EQ(true, PJUtils::get_dn(uri, routing_value));
 }

 TEST_F(PJUtilsTest, TestEmptyURI)
 {
    std::string uri_str = "";
    pjsip_uri* uri = PJUtils::uri_from_string(uri_str, pool);
    std::string routing_value;

    EXPECT_EQ(false, PJUtils::get_dn(uri, routing_value));
 }