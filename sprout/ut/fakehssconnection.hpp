/**
 * @file fakehssconnection.hpp Header file for fake HSS connection (for testing).
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

///
///----------------------------------------------------------------------------

#pragma once

#include <string>
#include "log.h"
#include "sas.h"
#include "hssconnection.h"

/// HSSConnection that writes to/reads from a local map rather than the HSS.
class FakeHSSConnection : public HSSConnection
{
public:
  FakeHSSConnection();
  ~FakeHSSConnection();

  void flush_all();

  bool get_user_ifc(const std::string& public_user_identity,
                    std::string& xml_data,
                    SAS::TrailId trail);

  void set_user_ifc(const std::string& public_user_identity,
                    const std::string& xml_data);

  void set_json(const std::string& url, const std::string& json);

private:
  Json::Value* get_object(const std::string& url, SAS::TrailId trail);
  void set_object(const std::string& url, Json::Value& object, SAS::TrailId trail);

  std::map<std::string, Json::Value> _json_db;
  std::map<std::string, std::string> _ifc_db;
};
