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

#include <json/reader.h>

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

static bool reg_store_access_common(RegStore::AoR** aor_data, bool& previous_aor_data_alloced,
                                    std::string aor_id, RegStore* current_store,
                                    RegStore* remote_store, RegStore::AoR** previous_aor_data,
                                    SAS::TrailId trail)
{
  // Find the current bindings for the AoR.
  delete *aor_data;
  *aor_data = current_store->get_aor_data(aor_id, trail);
  LOG_DEBUG("Retrieved AoR data %p", *aor_data);

  if (*aor_data == NULL)
  {
    // Failed to get data for the AoR because there is no connection
    // to the store.
    // LCOV_EXCL_START - local store (used in testing) never fails
    LOG_ERROR("Failed to get AoR binding for %s from store", aor_id.c_str());
    return false;
    // LCOV_EXCL_STOP
  }

  // If we don't have any bindings, try the backup AoR and/or store.
  if ((*aor_data)->bindings().empty())
  {
    if ((*previous_aor_data == NULL) &&
        (remote_store != NULL))
    {
      *previous_aor_data = remote_store->get_aor_data(aor_id, trail);
      previous_aor_data_alloced = true;
    }

    if ((*previous_aor_data != NULL) &&
        (!(*previous_aor_data)->bindings().empty()))
    {
      //LCOV_EXCL_START
      for (RegStore::AoR::Bindings::const_iterator i = (*previous_aor_data)->bindings().begin();
           i != (*previous_aor_data)->bindings().end();
           ++i)
      {
        RegStore::AoR::Binding* src = i->second;
        RegStore::AoR::Binding* dst = (*aor_data)->get_binding(i->first);
        *dst = *src;
      }

      for (RegStore::AoR::Subscriptions::const_iterator i = (*previous_aor_data)->subscriptions().begin();
           i != (*previous_aor_data)->subscriptions().end();
           ++i)
      {
        RegStore::AoR::Subscription* src = i->second;
        RegStore::AoR::Subscription* dst = (*aor_data)->get_subscription(i->first);
        *dst = *src;
      }
      //LCOV_EXCL_STOP
    }
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
    sip_all_register.add_var_param(uri_str);
    sip_all_register.add_var_param(user.slen, user.ptr);
    SAS::report_marker(sip_all_register);
  }
  else
  {
    LOG_WARNING("Could not raise SAS REGISTER marker for unparseable URI '%s'", uri_str.c_str());
  }

  // Remember to release the temporary pool.
  pj_pool_release(tmp_pool);
}

//LCOV_EXCL_START - don't want to actually run the handlers in the UT
void RegistrationTimeoutTask::run()
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
    LOG_DEBUG("Unable to parse response from Chronos");
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
    LOG_DEBUG("Unable to handle callback from Chronos");
    send_http_reply(rc);
    delete this;
    return;
  }

  send_http_reply(HTTP_OK);
  delete this;
}

void DeregistrationTask::run()
{
  // HTTP method must be a DELETE
  if (_req.method() != htp_method_DELETE)
  {
    LOG_WARNING("HTTP method isn't delete");
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  // Mandatory query parameter 'send-notifications' that must be true or false
  _notify = _req.param("send-notifications");

  if (_notify != "true" && _notify != "false")
  {
    LOG_WARNING("Mandatory send-notifications param is missing or invalid, send 400");
    send_http_reply(HTTP_BAD_RESULT);
    delete this;
    return;
  }

  // Parse the JSON body
  HTTPCode rc = parse_request(_req.get_rx_body());

  if (rc != HTTP_OK)
  {
    LOG_WARNING("Request body is invalid, send %d", rc);
    send_http_reply(rc);
    delete this;
    return;
  }

  rc = handle_request();

  send_http_reply(rc);
  delete this;
}
//LCOV_EXCL_STOP

void RegistrationTimeoutTask::handle_response()
{
  bool all_bindings_expired = false;
  RegStore::AoR* aor_data = set_aor_data(_cfg->_store, _aor_id, NULL, _cfg->_remote_store, true, all_bindings_expired);

  if (aor_data != NULL)
  {
    // If we have a remote store, try to store this there too.  We don't worry
    // about failures in this case.
    if (_cfg->_remote_store != NULL)
    {
      bool ignored;
      RegStore::AoR* remote_aor_data = set_aor_data(_cfg->_remote_store, _aor_id, aor_data, NULL, false, ignored);
      delete remote_aor_data;
    }

    if (all_bindings_expired)
    {
      LOG_DEBUG("All bindings have expired based on a Chronos callback - triggering deregistration at the HSS");
      _cfg->_hss->update_registration_state(_aor_id, "", HSSConnection::DEREG_TIMEOUT, 0);
    }
  }

  delete aor_data;
  report_sip_all_register_marker(trail(), _aor_id);
}

RegStore::AoR* RegistrationTimeoutTask::set_aor_data(RegStore* current_store,
                                                     std::string aor_id,
                                                     RegStore::AoR* previous_aor_data,
                                                     RegStore* remote_store,
                                                     bool is_primary,
                                                     bool& all_bindings_expired)
{
  RegStore::AoR* aor_data = NULL;
  bool previous_aor_data_alloced = false;

  do
  {
    if (!reg_store_access_common(&aor_data, previous_aor_data_alloced, aor_id,
                                 current_store, remote_store, &previous_aor_data, trail()))
    {
      // LCOV_EXCL_START - local store (used in testing) never fails
      break;
      // LCOV_EXCL_STOP
    }
  }
  while (!current_store->set_aor_data(aor_id, aor_data, is_primary, trail(), all_bindings_expired));

  // If we allocated the AoR, tidy up.
  if (previous_aor_data_alloced)
  {
    delete previous_aor_data;
  }

  return aor_data;
}

// Retrieve the aor and binding ID from the opaque data
HTTPCode RegistrationTimeoutTask::parse_response(std::string body)
{
  Json::Value json_body;
  std::string json_str = body;
  Json::Reader reader;
  bool parsingSuccessful = reader.parse(json_str.c_str(), json_body);

  if (!parsingSuccessful)
  {
    LOG_WARNING("Failed to read opaque data, %s",
                reader.getFormattedErrorMessages().c_str());
    return HTTP_BAD_RESULT;
  }

  if ((json_body.isMember("aor_id")) &&
      ((json_body)["aor_id"].isString()))
  {
    _aor_id = json_body.get("aor_id", "").asString();
  }
  else
  {
    LOG_WARNING("AoR ID not available in JSON");
    return HTTP_BAD_RESULT;
  }

  if ((json_body.isMember("binding_id")) &&
      ((json_body)["binding_id"].isString()))
  {
    _binding_id = json_body.get("binding_id", "").asString();
  }
  else
  {
    LOG_WARNING("Binding ID not available in JSON");
    return HTTP_BAD_RESULT;
  }

  return HTTP_OK;
}

// Retrieve the aors and any private IDs from the request body
HTTPCode DeregistrationTask::parse_request(std::string body)
{
  Json::Value json_body;
  Json::Reader reader;
  bool parsingSuccessful = reader.parse(body.c_str(), json_body);

  if (!parsingSuccessful)
  {
    LOG_WARNING("Failed to read data, %s",
                reader.getFormattedErrorMessages().c_str());
    return HTTP_BAD_RESULT;
  }

  if ((json_body.isMember("registrations")) &&
      ((json_body)["registrations"].isArray()))
  {
    Json::Value registration_vals = json_body["registrations"];

    for (size_t ii = 0; ii < registration_vals.size(); ++ii)
    {
      Json::Value registration = registration_vals[(int)ii];
      std::string primary_impu;
      std::string impi = "";

      if ((registration.isMember("primary-impu")) &&
          ((registration)["primary-impu"].isString()))
      {
        primary_impu = registration["primary-impu"].asString();

        if ((registration.isMember("impi")) &&
            (registration["impi"].isString()))

        {
          impi = registration["impi"].asString();
        }
      }
      else
      {
        LOG_WARNING("Invalid JSON - registration doesn't contain primary-impu");
        return HTTP_BAD_RESULT;
      }

      _bindings.insert(std::make_pair(primary_impu, impi));
    }
  }
  else
  {
    LOG_WARNING("Registrations not available in JSON");
    return HTTP_BAD_RESULT;
  }

  LOG_DEBUG("HTTP request successfully parsed");
  return HTTP_OK;
}

HTTPCode DeregistrationTask::handle_request()
{
  for (std::map<std::string, std::string>::iterator it=_bindings.begin(); it!=_bindings.end(); ++it)
  {
    RegStore::AoR* aor_data = set_aor_data(_cfg->_store, it->first, it->second, NULL, _cfg->_remote_store, true);

    if (aor_data != NULL)
    {
      // If we have a remote store, try to store this there too.  We don't worry
      // about failures in this case.
      if (_cfg->_remote_store != NULL)
      {
        RegStore::AoR* remote_aor_data = set_aor_data(_cfg->_remote_store, it->first, it->second, aor_data, NULL, false);
        delete remote_aor_data;
      }
    }
    else
    {
      // Can't connect to memcached, return 500. If this isn't the first AoR being edited
      // then this will lead to an inconsistency between the HSS and Sprout, as
      // Sprout will have changed some of the AoRs, but HSS will believe they all failed.
      // Sprout accepts changes to AoRs that don't exist though.
      // LCOV_EXCL_START - local store (used in testing) never fails
      LOG_WARNING("Unable to connect to memcached for AoR %s", it->first.c_str());
      delete aor_data;
      return HTTP_SERVER_ERROR;
      // LCOV_EXCL_STOP
    }

    delete aor_data;
  }

  return HTTP_OK;
}

RegStore::AoR* DeregistrationTask::set_aor_data(RegStore* current_store,
                                                std::string aor_id,
                                                std::string private_id,
                                                RegStore::AoR* previous_aor_data,
                                                RegStore* remote_store,
                                                bool is_primary)
{
  RegStore::AoR* aor_data = NULL;
  bool previous_aor_data_alloced = false;
  bool all_bindings_expired = false;

  do
  {
    if (!reg_store_access_common(&aor_data, previous_aor_data_alloced, aor_id,
                                 current_store, remote_store, &previous_aor_data, trail()))
    {
      // LCOV_EXCL_START - local store (used in testing) never fails
      break;
      // LCOV_EXCL_STOP
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
            // LCOV_EXCL_START
            current_store->send_notify(j->second, aor_data->_notify_cseq, b, b_id, trail());
            // LCOV_EXCL_STOP
          }
        }

        aor_data->remove_binding(b_id);
      }
    }
  }
  while (!current_store->set_aor_data(aor_id, aor_data, is_primary, trail(), all_bindings_expired));

  if (private_id == "")
  {
    // Deregister with any application servers
    std::vector<std::string> uris;
    std::map<std::string, Ifcs> ifc_map;
    std::string state;
    LOG_INFO("ID %s", aor_id.c_str());

    if (_cfg->_hss->get_registration_data(aor_id, state, ifc_map, uris, trail()) == HTTP_OK)
    {
      RegistrationUtils::deregister_with_application_servers(ifc_map[aor_id],
                                                             current_store,
                                                             aor_id,
                                                             trail());
    }
  }

  // If we allocated the AoR, tidy up.
  if (previous_aor_data_alloced)
  {
    delete previous_aor_data;
  }

  return aor_data;
}

HTTPCode AuthTimeoutTask::handle_response(std::string body)
{
  Json::Value json_body;
  std::string json_str = body;
  Json::Reader reader;
  bool parsingSuccessful = reader.parse(json_str.c_str(), json_body);

  if (!parsingSuccessful)
  {
    LOG_ERROR("Failed to read opaque data, %s",
              reader.getFormattedErrorMessages().c_str());
    return HTTP_BAD_RESULT;
  }

  if ((json_body.isMember("impu")) &&
      ((json_body)["impu"].isString()))
  {
    _impu = json_body.get("impu", "").asString();
    report_sip_all_register_marker(trail(), _impu);
  }
  else
  {
    LOG_ERROR("IMPU not available in JSON");
    return HTTP_BAD_RESULT;
  }

  if ((json_body.isMember("impi")) &&
      ((json_body)["impi"].isString()))
  {
    _impi = json_body.get("impi", "").asString();
  }
  else
  {
    LOG_ERROR("IMPI not available in JSON");
    return HTTP_BAD_RESULT;
  }

  if ((json_body.isMember("nonce")) &&
      ((json_body)["nonce"].isString()))
  {
    _nonce = json_body.get("nonce", "").asString();
  }
  else
  {
    LOG_ERROR("Nonce not available in JSON");
    return HTTP_BAD_RESULT;
  }

  bool success = false;
  uint64_t cas;
  Json::Value* av = _cfg->_avstore->get_av(_impi, _nonce, cas, trail());
  if (av != NULL)
  {
    // If authentication completed, we'll have written a marker to
    // indicate that. Look for it.
    if (!av->isMember("tombstone"))
    {
      LOG_DEBUG("AV for %s:%s has timed out", _impi.c_str(), _nonce.c_str());

      // Retrieve the original authentication vector, so we have the
      // original REGISTER's branch parameter for SAS correlation

      correlate_branch_from_av(av, trail());

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
      LOG_DEBUG("Tombstone record indicates Authentication Vector has been used successfully - ignoring timer pop");
      success = true;
    }
  }
  else
  {
    LOG_WARNING("Could not find AV for %s:%s when checking authentication timeout", _impi.c_str(), _nonce.c_str()); // LCOV_EXCL_LINE
  }
  delete av;

  return success ? HTTP_OK : HTTP_SERVER_ERROR;
}
