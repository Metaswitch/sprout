/**
 * @file handlers.cpp
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

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "handlers.h"
#include "log.h"
#include "regstore.h"
#include "ifchandler.h"
#include "registration_utils.h"
#include "stack.h"
#include "pjutils.h"
#include "sproutsasevent.h"
#include "uri_classifier.h"

static bool reg_store_access_common(RegStore::AoR** aor_data,
                                    std::string aor_id,
                                    RegStore* current_store,
                                    SAS::TrailId trail,
                                    bool should_send_notify)
{
  // Find the current bindings for the AoR.
  delete *aor_data;
  *aor_data = current_store->get_aor_data(aor_id, trail, should_send_notify);
  TRC_DEBUG("Retrieved AoR data %p", *aor_data);

  if (*aor_data == NULL)
  {
    // Failed to get data for the AoR because there is no connection
    // to the store.
    TRC_ERROR("Failed to get AoR binding for %s from store", aor_id.c_str());
    return false;
  }

  return true;
}

static void report_sip_all_register_marker(SAS::TrailId trail, std::string uri_str)
{
  // Parse the SIP URI and get the username from it.
  pj_pool_t* tmp_pool = pj_pool_create(&stack_data.cp.factory, "handlers", 1024, 512, NULL);
  pjsip_uri* uri = PJUtils::uri_from_string(uri_str, tmp_pool);

  if (uri != NULL)
  {
    pj_str_t user = PJUtils::user_from_uri(uri);

    // Create and report the marker.
    SAS::Marker sip_all_register(trail, MARKER_ID_SIP_ALL_REGISTER, 1u);
    sip_all_register.add_var_param(PJUtils::strip_uri_scheme(uri_str));
    // Add the DN parameter. If the user part is not numeric just log it in
    // its entirety.
    sip_all_register.add_var_param(URIClassifier::is_user_numeric(user) ?
                                   PJUtils::remove_visual_separators(user) :
                                   PJUtils::pj_str_to_string(&user));
    SAS::report_marker(sip_all_register);
  }
  else
  {
    TRC_WARNING("Could not raise SAS REGISTER marker for unparseable URI '%s'", uri_str.c_str());
  }

  // Remember to release the temporary pool.
  pj_pool_release(tmp_pool);
}

//LCOV_EXCL_START - don't want to actually run the handlers in the UT
void RegSubTimeoutTask::run()
{
  if (_req.method() != htp_method_POST)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  HTTPCode rc = parse_response(_req.get_rx_body());

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Unable to parse response from Chronos");
    send_http_reply(rc);
    delete this;
    return;
  }

  send_http_reply(HTTP_OK);

  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  handle_response();

  SAS::Marker end_marker(trail(), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  delete this;
}

void AuthTimeoutTask::run()
{
  if (_req.method() != htp_method_POST)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  HTTPCode rc = handle_response(_req.get_rx_body());

  SAS::Marker end_marker(trail(), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Unable to handle callback from Chronos");
    send_http_reply(rc);
    delete this;
    return;
  }

  send_http_reply(HTTP_OK);
  delete this;
}
//LCOV_EXCL_STOP

void DeregistrationTask::run()
{
  // HTTP method must be a DELETE
  if (_req.method() != htp_method_DELETE)
  {
    TRC_WARNING("HTTP method isn't delete");
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  // Mandatory query parameter 'send-notifications' that must be true or false
  _notify = _req.param("send-notifications");

  if (_notify != "true" && _notify != "false")
  {
    TRC_WARNING("Mandatory send-notifications param is missing or invalid, send 400");
    send_http_reply(HTTP_BAD_REQUEST);
    delete this;
    return;
  }

  // Parse the JSON body
  HTTPCode rc = parse_request(_req.get_rx_body());

  if (rc != HTTP_OK)
  {
    TRC_WARNING("Request body is invalid, send %d", rc);
    send_http_reply(rc);
    delete this;
    return;
  }

  rc = handle_request();

  send_http_reply(rc);
  delete this;
}

void RegSubTimeoutTask::handle_response()
{
  bool all_bindings_expired = false;
  RegStore::AoR* aor_data = set_aor_data(_cfg->_store, _aor_id, true,
                                         all_bindings_expired);

  if (aor_data != NULL)
  {
    if (all_bindings_expired)
    {
      TRC_DEBUG("All bindings have expired based on a Chronos callback - triggering deregistration at the HSS");
      _cfg->_hss->update_registration_state(_aor_id, "", HSSConnection::DEREG_TIMEOUT, 0);
    }
  }
  else
  {
    // We couldn't update the RegStore but there is nothing else we can do to
    // recover from this.
    TRC_INFO("Could not update RegStore on registration timeout for AoR: %s",
             _aor_id.c_str());
  }

  delete aor_data;
  report_sip_all_register_marker(trail(), _aor_id);
}

RegStore::AoR* RegSubTimeoutTask::set_aor_data(RegStore* current_store,
                                                     std::string aor_id,
                                                     bool is_primary,
                                                     bool& all_bindings_expired)
{
  RegStore::AoR* aor_data = NULL;
  Store::Status set_rc;

  do
  {
    if (!reg_store_access_common(&aor_data,
                                 aor_id,
                                 current_store,
                                 trail(),
                                 is_primary))
    {
      // LCOV_EXCL_START - local store (used in testing) never fails
      break;
      // LCOV_EXCL_STOP
    }

    // Do not send NOTIFYs in regstore as the RegSubTimoutTask is called
    // with both the local and remote stores as current_store, and NOTIFYs should
    // have already been sent correctly by the above call to reg_store_access_common.
    set_rc = current_store->set_aor_data(aor_id,
                                         aor_data,
                                         is_primary,
                                         trail(),
                                         false,
                                         all_bindings_expired);
    if (set_rc != Store::OK)
    {
      delete aor_data; aor_data = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  return aor_data;
}

// Retrieve the aor and binding ID from the opaque data
HTTPCode RegSubTimeoutTask::parse_response(std::string body)
{
  rapidjson::Document doc;
  std::string json_str = body;
  doc.Parse<0>(json_str.c_str());

  if (doc.HasParseError())
  {
    TRC_DEBUG("Failed to parse opaque data as JSON: %s\nError: %s",
              json_str.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_GET_STRING_MEMBER(doc, "aor_id", _aor_id);
  }
  catch (JsonFormatError err)
  {
    TRC_DEBUG("Badly formed opaque data (missing aor_id)");
    return HTTP_BAD_REQUEST;
  }

  std::string _binding_id = (((doc.HasMember("binding_id"))   &&
                            ((doc["binding_id"]).IsString())) ?
                            (doc["binding_id"].GetString()) : "");

  std::string _subscription_id = (((doc.HasMember("subscription_id")) &&
                                 ((doc["subscription_id"]).IsString())) ?
                                 (doc["subscription_id"].GetString()) : "");

  if (_binding_id == "" && _subscription_id == "")
  {
    TRC_DEBUG("No binding id or subscription id found");
  }
  else if (_binding_id != "" && _subscription_id != "")
  {
    TRC_DEBUG("Found both binding id: %s and subscription id: %s", _binding_id.c_str(),
                                                                   _subscription_id.c_str());
  }
  else if (_binding_id != "")
  {
    TRC_DEBUG("Handling timer pop for binding id: %s", _binding_id.c_str());
  }
  else if (_subscription_id != "")
  {
    TRC_DEBUG("Handling timer pop for subscription id: %s", _subscription_id.c_str());
  }

  return HTTP_OK;
}

// Retrieve the aors and any private IDs from the request body
HTTPCode DeregistrationTask::parse_request(std::string body)
{
  rapidjson::Document doc;
  doc.Parse<0>(body.c_str());

  if (doc.HasParseError())
  {
    TRC_INFO("Failed to parse data as JSON: %s\nError: %s",
             body.c_str(),
             rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_ASSERT_CONTAINS(doc, "registrations");
    JSON_ASSERT_ARRAY(doc["registrations"]);
    const rapidjson::Value& reg_arr = doc["registrations"];

    for (rapidjson::Value::ConstValueIterator reg_it = reg_arr.Begin();
         reg_it != reg_arr.End();
         ++reg_it)
    {
      try
      {
        std::string primary_impu;
        std::string impi = "";
        JSON_GET_STRING_MEMBER(*reg_it, "primary-impu", primary_impu);

        if (((*reg_it).HasMember("impi")) &&
            ((*reg_it)["impi"].IsString()))
        {
          impi = (*reg_it)["impi"].GetString();
        }

        _bindings.insert(std::make_pair(primary_impu, impi));
      }
      catch (JsonFormatError err)
      {
        TRC_WARNING("Invalid JSON - registration doesn't contain primary-impu");
        return HTTP_BAD_REQUEST;
      }
    }
  }
  catch (JsonFormatError err)
  {
    TRC_INFO("Registrations not available in JSON");
    return HTTP_BAD_REQUEST;
  }

  TRC_DEBUG("HTTP request successfully parsed");
  return HTTP_OK;
}

HTTPCode DeregistrationTask::handle_request()
{
  for (std::map<std::string, std::string>::iterator it=_bindings.begin(); it!=_bindings.end(); ++it)
  {
    RegStore::AoR* aor_data = set_aor_data(_cfg->_store,
                                           it->first,
                                           it->second,
                                           true);

    if (aor_data == NULL)
    {
      // Can't connect to memcached, return 500. If this isn't the first AoR being edited
      // then this will lead to an inconsistency between the HSS and Sprout, as
      // Sprout will have changed some of the AoRs, but HSS will believe they all failed.
      // Sprout accepts changes to AoRs that don't exist though.
      TRC_WARNING("Unable to connect to memcached for AoR %s", it->first.c_str());

      delete aor_data;
      return HTTP_SERVER_ERROR;
    }

    delete aor_data;
  }

  return HTTP_OK;
}

RegStore::AoR* DeregistrationTask::set_aor_data(RegStore* current_store,
                                                std::string aor_id,
                                                std::string private_id,
                                                bool is_primary)
{
  RegStore::AoR* aor_data = NULL;
  bool all_bindings_expired = false;
  Store::Status set_rc;

  do
  {
    if (!reg_store_access_common(&aor_data,
                                 aor_id,
                                 current_store,
                                 trail(),
                                 is_primary))
    {
      break;
    }

    std::vector<std::string> binding_ids;

    for (RegStore::AoR::Bindings::const_iterator i = aor_data->bindings().begin();
         i != aor_data->bindings().end();
         ++i)
    {
      // Get a list of the bindings to iterate over
      binding_ids.push_back(i->first);
    }

    for (std::vector<std::string>::const_iterator i = binding_ids.begin();
         i != binding_ids.end();
         ++i)
    {
      std::string b_id = *i;
      RegStore::AoR::Binding* b = aor_data->get_binding(b_id);

      if (private_id == "" || private_id == b->_private_id)
      {
        // Update the cseq
        aor_data->_notify_cseq++;

        // The binding matches the private id, or no private id was supplied.
        // Send a SIP NOTIFY for this binding if there are any subscriptions
        if (_notify == "true" && is_primary)
        {
          for (RegStore::AoR::Subscriptions::const_iterator j = aor_data->subscriptions().begin();
              j != aor_data->subscriptions().end();
               ++j)
          {
            current_store->send_notify(j->second, aor_data->_notify_cseq, b, b_id, trail());
          }
        }

        aor_data->remove_binding(b_id);
      }
    }

    set_rc = current_store->set_aor_data(aor_id,
                                         aor_data,
                                         is_primary,
                                         trail(),
                                         all_bindings_expired);
    if (set_rc != Store::OK)
    {
      delete aor_data; aor_data = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  if (private_id == "")
  {
    // Deregister with any application servers
    std::vector<std::string> uris;
    std::map<std::string, Ifcs> ifc_map;
    std::string state;
    TRC_INFO("ID %s", aor_id.c_str());

    if (_cfg->_hss->get_registration_data(aor_id, state, ifc_map, uris, trail()) == HTTP_OK)
    {
      RegistrationUtils::deregister_with_application_servers(ifc_map[aor_id],
                                                             current_store,
                                                             aor_id,
                                                             trail());
    }
  }

  return aor_data;
}

HTTPCode AuthTimeoutTask::handle_response(std::string body)
{
  rapidjson::Document doc;
  std::string json_str = body;
  doc.Parse<0>(json_str.c_str());

  if (doc.HasParseError())
  {
    TRC_INFO("Failed to parse opaque data as JSON: %s\nError: %s",
             json_str.c_str(),
             rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_GET_STRING_MEMBER(doc, "impu", _impu);
    JSON_GET_STRING_MEMBER(doc, "impi", _impi);
    JSON_GET_STRING_MEMBER(doc, "nonce", _nonce);
    report_sip_all_register_marker(trail(), _impu);
  }
  catch (JsonFormatError err)
  {
    TRC_INFO("Badly formed opaque data (missing impu, impi or nonce");
    return HTTP_BAD_REQUEST;
  }

  bool success = false;
  uint64_t cas;
  rapidjson::Document* av = _cfg->_avstore->get_av(_impi, _nonce, cas, trail());
  if (av != NULL)
  {
    // Use the original REGISTER's branch parameter for SAS
    // correlation

    correlate_branch_from_av(av, trail());

    // If authentication completed, we'll have written a marker to
    // indicate that. Look for it.
    if (!av->HasMember("tombstone"))
    {
      TRC_DEBUG("AV for %s:%s has timed out", _impi.c_str(), _nonce.c_str());

      // The AUTHENTICATION_TIMEOUT SAR is idempotent, so there's no
      // problem if Chronos' timer pops twice (e.g. if we have high
      // latency and these operations take more than 2 seconds).

      // If either of these operations fail, we return a 500 Internal
      // Server Error - this will trigger Chronos to try a different
      // Sprout, which may have better connectivity to Homestead or Memcached.
      HTTPCode hss_query = _cfg->_hss->update_registration_state(_impu, _impi, HSSConnection::AUTH_TIMEOUT, trail());

      if (hss_query == HTTP_OK)
      {
        success = true;
      }
    }
    else
    {
      SAS::Event event(trail(), SASEvent::AUTHENTICATION_TIMER_POP_IGNORED, 0);
      SAS::report_event(event);

      TRC_DEBUG("Tombstone record indicates Authentication Vector has been used successfully - ignoring timer pop");
      success = true;
    }
  }
  else
  {
    TRC_WARNING("Could not find AV for %s:%s when checking authentication timeout", _impi.c_str(), _nonce.c_str()); // LCOV_EXCL_LINE
  }
  delete av;

  return success ? HTTP_OK : HTTP_SERVER_ERROR;
}
