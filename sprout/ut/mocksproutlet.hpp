/**
 * @file mocksproutlet.h  Mocks for testing Sproutlet integration points
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

#ifndef MOCLSPROUTLET_H__
#define MOCKSPROUTLET_H__

#include "gmock/gmock.h"
#include "sproutlet.h"

class MockSproutletTsxHelper : public SproutletTsxHelper
{
public:
  MockSproutletTsxHelper(std::string dialog_id = "",
                         SAS::TrailId trail = 0) :
                        _dialog_id(dialog_id),
                        _trail(trail) {}

  const std::string& dialog_id() const {return _dialog_id;}
  std::string _dialog_id;

  SAS::TrailId trail() const {return _trail;}
  SAS::TrailId _trail;

  MOCK_METHOD1(add_to_dialog, void(const std::string&));
  MOCK_METHOD1(clone_request, pjsip_msg*(pjsip_msg*));
  MOCK_METHOD1(forward_request, int(pjsip_msg*&));
  MOCK_METHOD1(forward_response, void(pjsip_msg*&));
  MOCK_METHOD2(reject, void(int, const std::string&));
  MOCK_METHOD1(free_msg, void(pjsip_msg*&));
  MOCK_METHOD1(get_pool, pj_pool_t*(const pjsip_msg*));
};


class MockSproutlet : public Sproutlet
{
public:
  MockSproutlet(const std::string& service_name = "mock") : Sproutlet(service_name) {}

  MOCK_METHOD2(get_app_tsx, SproutletTsx*(SproutletTsxHelper*, pjsip_msg*));
};


class MockSproutletTsx : public SproutletTsx
{
public:
  MockSproutletTsx(SproutletTsxHelper* helper) : SproutletTsx(helper) {}

  MOCK_METHOD1(on_initial_request, void(pjsip_msg*));
  MOCK_METHOD1(on_in_dialog_request, void(pjsip_msg*));
  MOCK_METHOD2(on_response, void(pjsip_msg*, int));
  MOCK_METHOD1(on_cancel, void(int));
};

#endif
