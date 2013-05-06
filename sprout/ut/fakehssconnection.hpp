/**
 * @file fakehssconnection.hpp Header file for fake HSS connection (for testing).
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

///
///----------------------------------------------------------------------------

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

private:
  Json::Value* get_object(const std::string& url, SAS::TrailId trail);
  void set_object(const std::string& url, Json::Value& object, SAS::TrailId trail);

  std::map<std::string, Json::Value> _json_db;
  std::map<std::string, std::string> _ifc_db;
};
