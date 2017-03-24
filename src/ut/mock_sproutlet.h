/**
 * @file mock_sproutlet.h Mock Sproutlet
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2015  Metaswitch Networks Ltd
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

#ifndef MOCKSPROUTLET_H__
#define MOCKSPROUTLET_H__

#include "gmock/gmock.h"
#include "sproutlet.h"

/// Mock class for Sproutlet.
class MockSproutlet : public Sproutlet
{
public:
  MockSproutlet(
      const std::string& service_name="mock-sproutlet",
      int port=0,
      const std::string& service_host="") :
    Sproutlet(service_name, port, service_host) {}

  MOCK_METHOD3(
      get_tsx,
      SproutletTsx*(SproutletTsxHelper*, const std::string&, pjsip_msg*));
};


/// Mock class for SproutletTsx.
class MockSproutletTsx : public SproutletTsx
{
public:
  MockSproutletTsx() :
    SproutletTsx(NULL)
  {
  }

  void set_helper(SproutletTsxHelper* helper)
  {
    _helper = helper;
  }

  MOCK_METHOD1(on_rx_initial_request, void(pjsip_msg*));
  MOCK_METHOD1(on_rx_in_dialog_request, void(pjsip_msg*));
  MOCK_METHOD2(obs_rx_request, void(pjsip_msg*, bool));
  MOCK_METHOD3(obs_tx_request, void(pjsip_msg*, int, bool));
  MOCK_METHOD2(on_rx_response, void(pjsip_msg*, int));
  MOCK_METHOD3(obs_rx_response, void(pjsip_msg*, int, bool));
  MOCK_METHOD2(obs_tx_response, void(pjsip_msg*, bool));
  MOCK_METHOD2(on_rx_cancel, void(int, pjsip_msg*));
  MOCK_METHOD1(on_timer_expiry, void(void*));
};

#endif
