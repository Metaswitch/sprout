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

#pragma once

#include <set>
#include <string>
#include "log.h"
#include "sas.h"
#include "hssconnection.h"
#include "mock_hss_connection.h"
#include "associated_uris.h"

/// HSSConnection that writes to/reads from a local map rather than the HSS.
/// Optionally accepts a MockHSSConnection object -- if this is provided then
/// (currently only some) methods call through to the corresponding Mock
/// methods so method invocation parameters / counts can be policed by test
/// scripts.  This only enables method invocations to be checked -- it does not
/// allow control of the behaviour of those functions -- in all cases the
/// resulting behaviour is dictated by the FakeHSSConnection class.
class FakeHSSConnection : public HSSConnection
{
public:
  FakeHSSConnection(MockHSSConnection* = NULL);
  ~FakeHSSConnection();

  void flush_all();

  void set_result(const std::string& url, const std::string& result);
  void set_impu_result(const std::string&,
                       const std::string&,
                       const std::string&,
                       std::string,
                       std::string = "",
                       const std::string& = "");
  void delete_result(const std::string& url);
  void set_rc(const std::string& url, long rc);
  void delete_rc(const std::string& url);
  bool url_was_requested(const std::string& url, const std::string& body);

  HTTPCode update_registration_state(const std::string&,
                                     const std::string&,
                                     const std::string&,
                                     SAS::TrailId);

  HTTPCode update_registration_state(const std::string& public_user_identity,
                                     const std::string& private_user_identity,
                                     const std::string& type,
                                     std::string& regstate,
                                     std::map<std::string, Ifcs >& service_profiles,
                                     AssociatedURIs& associated_uris,
                                     std::deque<std::string>& ccfs,
                                     std::deque<std::string>& ecfs,
                                     SAS::TrailId trail);

private:
  long get_json_object(const std::string& path, rapidjson::Document*& object, SAS::TrailId trail);
  long get_xml_object(const std::string& path, rapidxml::xml_document<>*& root, SAS::TrailId trail);
  long get_xml_object(const std::string& path, std::string body, rapidxml::xml_document<>*& root, SAS::TrailId trail);
  long put_for_xml_object(const std::string& path, std::string body, bool cache_allowed, rapidxml::xml_document<>*& root, SAS::TrailId trail);

  // Map of URL/body pair to result
  typedef std::pair<std::string, std::string> UrlBody;
  std::map<UrlBody, std::string> _results;
  std::map<std::string, long> _rcs;
  std::set<UrlBody> _calls;

  // Optional MockHSSConnection object.  May be NULL if the creator of the
  // FakeHSSConnection  does not want to explicitly check method invocation.
  MockHSSConnection* _hss_connection_observer;
};
