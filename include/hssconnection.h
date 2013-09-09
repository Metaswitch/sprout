/**
 * @file hssconnection.h Definitions for HSSConnection class.
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
///

#ifndef HSSCONNECTION_H__
#define HSSCONNECTION_H__

#include <curl/curl.h>
#include <json/value.h>

#include "httpconnection.h"
#include "sas.h"
#include "accumulator.h"

/// @class HSSConnection
///
/// Provides a connection to the Homstead service for retrieving user
/// profiles and authentication information.
///
class HSSConnection
{
public:
  HSSConnection(const std::string& server);
  ~HSSConnection();

  Json::Value* get_digest_data(const std::string& private_user_id,
                               const std::string& public_user_id,
                               SAS::TrailId trail);
  Json::Value* get_associated_uris(const std::string& private_user_id,
                                   SAS::TrailId);
  virtual bool get_user_ifc(const std::string& public_user_id,
                            std::string& xml_data,
                            SAS::TrailId trail);

private:
  virtual Json::Value* get_object(const std::string& path, SAS::TrailId trail);

  HttpConnection* _http;
  StatisticAccumulator _latency_stat;
  StatisticAccumulator _digest_latency_stat;
  StatisticAccumulator _associated_uri_latency_stat;
  StatisticAccumulator _ifc_latency_stat;
};

#endif
