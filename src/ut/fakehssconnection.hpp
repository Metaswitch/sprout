/**
 * @file fakehssconnection.hpp Header file for fake HSS connection (for testing).
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
                       const std::string& wildcard = "",
                       std::string chargingaddrsxml = "");
void set_impu_result_with_prev(const std::string&,
                               const std::string&,
                               const std::string&,
                               const std::string&,
                               std::string,
                               std::string = "",
                               const std::string& wildcard = "",
                               std::string chargingaddrsxml = "");
void delete_result(const std::string& url);
  void set_rc(const std::string& url, long rc);
  void delete_rc(const std::string& url);
  bool url_was_requested(const std::string& url, const std::string& body);

  HTTPCode update_registration_state(const HSSConnection::irs_query& irs_query,
                                     HSSConnection::irs_info& irs_info,
                                     SAS::TrailId trail);

private:
  void set_impu_result_internal(const std::string&,
                                const std::string&,
                                const std::string&,
                                const std::string&,
                                std::string,
                                std::string,
                                const std::string& wildcard,
                                std::string chargingaddrsxml);

  long get_json_object(const std::string& path, rapidjson::Document*& object, SAS::TrailId trail);
  long get_xml_object(const std::string& path, rapidxml::xml_document<>*& root, SAS::TrailId trail);
  long get_xml_object(const std::string& path, std::string body, rapidxml::xml_document<>*& root, SAS::TrailId trail);
  long put_for_xml_object(const std::string& path, std::string body, const bool& cache_allowed, rapidxml::xml_document<>*& root, SAS::TrailId trail);

  // Map of URL/body pair to result
  typedef std::pair<std::string, std::string> UrlBody;
  std::map<std::string, std::string> _results;
  std::map<std::string, long> _rcs;
  std::set<UrlBody> _calls;

  // Optional MockHSSConnection object.  May be NULL if the creator of the
  // FakeHSSConnection  does not want to explicitly check method invocation.
  MockHSSConnection* _hss_connection_observer;
};
