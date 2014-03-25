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

static bool reg_store_access_common(RegStore::AoR** aor_data, bool& previous_aor_data_alloced,
                                    bool& all_bindings_expired, std::string aor_id,
                                    RegStore* current_store, RegStore* remote_store,
                                    RegStore::AoR** previous_aor_data)
{
  // Find the current bindings for the AoR.
  delete *aor_data;
  *aor_data = current_store->get_aor_data(aor_id);
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
      *previous_aor_data = remote_store->get_aor_data(aor_id);
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

//LCOV_EXCL_START - don't want to actually run the handlers in the UT
void RegistrationTimeoutHandler::run()
{
  if (_req.method() != htp_method_POST)
  {
    _req.send_reply(405);
    delete this;
    return;
  }

  int rc = parse_response(_req.body());
  if (rc != 200)
  {
    LOG_DEBUG("Unable to parse response from Chronos");
    _req.send_reply(rc);
    delete this;
    return;
  }

  _req.send_reply(200);
  handle_response();
  delete this;
}

void AuthTimeoutHandler::run()
{
  if (_req.method() != htp_method_POST)
  {
    _req.send_reply(405);
    delete this;
    return;
  }

  int rc = handle_response(_req.body());
  if (rc != 200)
  {
    LOG_DEBUG("Unable to handle callback from Chronos");
    _req.send_reply(rc);
    delete this;
    return;
  }

  _req.send_reply(200);
  delete this;
}

void DeregistrationHandler::run()
{
  // HTTP method must be a DELETE
  if (_req.method() != htp_method_DELETE)
  {
    LOG_WARNING("HTTP method isn't delete");
    _req.send_reply(405);
    delete this;
    return;
  }

  // Mandatory query parameter 'send-notifications' that must be true or false
  _notify = _req.param("send-notifications");

  if (_notify != "true" && _notify != "false")
  {
    LOG_WARNING("Mandatory send-notifications param is missing or invalid, send 400");
    _req.send_reply(400);
    delete this;
    return;
  }

  // Parse the JSON body
  int rc = parse_request(_req.body());

  if (rc != 200)
  {
    LOG_WARNING("Request body is invalid, send %d", rc);
    _req.send_reply(rc);
    delete this;
    return;
  }

  rc = handle_request();
  _req.send_reply(rc);
  delete this;
}
//LCOV_EXCL_STOP

void RegistrationTimeoutHandler::handle_response()
{
  bool all_bindings_expired = false;
  RegStore::AoR* aor_data = set_aor_data(_cfg->_store, _aor_id, NULL, _cfg->_remote_store, true, all_bindings_expired);

  if (aor_data != NULL)
  {
    // If we have a remote store, try to store this there too.  We don't worry
    // about failures in this case.
    if (_cfg->_remote_store != NULL)
    {
      RegStore::AoR* remote_aor_data = set_aor_data(_cfg->_remote_store, _aor_id, aor_data, NULL, false, false);
      delete remote_aor_data;
    }

    if (all_bindings_expired)
    {
      //LCOV_EXCL_START
      LOG_DEBUG("All bindings have expired based on a Chronos callback - triggering deregistration at the HSS");
      _cfg->_hss->update_registration_state(_aor_id, "", HSSConnection::DEREG_TIMEOUT, 0);
      //LCOV_EXCL_STOP
    }
  }

  delete aor_data;
}

RegStore::AoR* RegistrationTimeoutHandler::set_aor_data(RegStore* current_store,
                                                        std::string aor_id,
                                                        RegStore::AoR* previous_aor_data,
                                                        RegStore* remote_store,
                                                        bool is_primary,
                                                        bool all_bindings_expired)
{
  RegStore::AoR* aor_data = NULL;
  bool previous_aor_data_alloced = false;

  do
  {
    if (!reg_store_access_common(&aor_data, previous_aor_data_alloced, all_bindings_expired,
                                 aor_id, current_store, remote_store, &previous_aor_data))
    {
      // LCOV_EXCL_START - local store (used in testing) never fails
      break;
      // LCOV_EXCL_STOP
    }
  }
  while (!current_store->set_aor_data(aor_id, aor_data, is_primary, all_bindings_expired));

  // If we allocated the AoR, tidy up.
  if (previous_aor_data_alloced)
  {
    delete previous_aor_data;
  }

  return aor_data;
}

// Retrieve the aor and binding ID from the opaque data
int RegistrationTimeoutHandler::parse_response(std::string body)
{
  Json::Value json_body;
  std::string json_str = body;
  Json::Reader reader;
  bool parsingSuccessful = reader.parse(json_str.c_str(), json_body);

  if (!parsingSuccessful)
  {
    LOG_WARNING("Failed to read opaque data, %s",
                reader.getFormattedErrorMessages().c_str());
    return 400;
  }

  if ((json_body.isMember("aor_id")) &&
      ((json_body)["aor_id"].isString()))
  {
    _aor_id = json_body.get("aor_id", "").asString();
  }
  else
  {
    LOG_WARNING("AoR ID not available in JSON");
    return 400;
  }

  if ((json_body.isMember("binding_id")) &&
      ((json_body)["binding_id"].isString()))
  {
    _binding_id = json_body.get("binding_id", "").asString();
  }
  else
  {
    LOG_WARNING("Binding ID not available in JSON");
    return 400;
  }

  return 200;
}

// Retrieve the aors and any private IDs from the request body
int DeregistrationHandler::parse_request(std::string body)
{
  Json::Value json_body;
  Json::Reader reader;
  bool parsingSuccessful = reader.parse(body.c_str(), json_body);

  if (!parsingSuccessful)
  {
    LOG_WARNING("Failed to read data, %s",
                reader.getFormattedErrorMessages().c_str());
    return 400;
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
        return 400;
      }

      _bindings.insert(std::make_pair(primary_impu, impi));
    }
  }
  else
  {
    LOG_WARNING("Registrations not available in JSON");
    return 400;
  }

  LOG_DEBUG("HTTP request successfully parsed");
  return 200;
}

int DeregistrationHandler::handle_request()
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
      return 500;
      // LCOV_EXCL_STOP
    }

    delete aor_data;
  }

  return 200;
}

RegStore::AoR* DeregistrationHandler::set_aor_data(RegStore* current_store,
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
    if (!reg_store_access_common(&aor_data, previous_aor_data_alloced, all_bindings_expired,
                                 aor_id, current_store, remote_store, &previous_aor_data))
    {
      // LCOV_EXCL_START - local store (used in testing) never fails
      break;
      // LCOV_EXCL_STOP
    }

    // LCOV_EXCL_START - local store (used in testing) never fails
    for (RegStore::AoR::Bindings::const_iterator i = aor_data->bindings().begin();
         i != aor_data->bindings().end();
         ++i)
    {
      RegStore::AoR::Binding* b = i->second;
      std::string b_id = i->first;

      if (private_id == "" || private_id == b->_private_id)
      {
        // Update the cseq
        aor_data->_notify_cseq++;

        // The binding has expired, so remove it. Send a SIP NOTIFY for this binding
        // if there are any subscriptions
        if (_notify == "true" && is_primary)
        {
          for (RegStore::AoR::Subscriptions::const_iterator j = aor_data->subscriptions().begin();
              j != aor_data->subscriptions().end();
               ++j)
          {
            current_store->send_notify(j->second, aor_data->_notify_cseq, b, b_id);
          }
        }

        aor_data->remove_binding(b_id);
      }
    }
    // LCOV_EXCL_STOP
  }
  while (!current_store->set_aor_data(aor_id, aor_data, is_primary, all_bindings_expired));

  if (private_id == "")
  {
    // Deregister with any application servers
    std::vector<std::string> uris;
    std::map<std::string, Ifcs> ifc_map;
    std::string state;
    LOG_INFO("ID %s", aor_id.c_str());
    _cfg->_hss->get_registration_data(aor_id, state, ifc_map, uris, 0);
    RegistrationUtils::deregister_with_application_servers(ifc_map[aor_id], current_store, _cfg->_sipresolver, aor_id, 0);
  }

  // If we allocated the AoR, tidy up.
  if (previous_aor_data_alloced)
  {
    delete previous_aor_data;
  }

  return aor_data;
}

int AuthTimeoutHandler::handle_response(std::string body)
{
  Json::Value json_body;
  std::string json_str = body;
  Json::Reader reader;
  bool parsingSuccessful = reader.parse(json_str.c_str(), json_body);

  if (!parsingSuccessful)
  {
    LOG_ERROR("Failed to read opaque data, %s",
              reader.getFormattedErrorMessages().c_str());
    return 400;
  }

  if ((json_body.isMember("impi")) &&
      ((json_body)["impi"].isString()))
  {
    _impi = json_body.get("impi", "").asString();
  }
  else
  {
    LOG_ERROR("IMPI not available in JSON");
    return 400;
  }

  if ((json_body.isMember("impu")) &&
      ((json_body)["impu"].isString()))
  {
    _impu = json_body.get("impu", "").asString();
  }
  else
  {
    LOG_ERROR("IMPU not available in JSON");
    return 400;
  }

  if ((json_body.isMember("nonce")) &&
      ((json_body)["nonce"].isString()))
  {
    _nonce = json_body.get("nonce", "").asString();
  }
  else
  {
    LOG_ERROR("Nonce not available in JSON");
    return 400;
  }

  Json::Value* json = _cfg->_avstore->get_av(_impi, _nonce);
  bool success = false;


  if (json == NULL)
  {
    // Mainline case - our AV has already been deleted because the
    // user has tried to authenticate. No need to notify the HSS in
    // this case (as they'll either have successfully authenticated
    // and triggered a REGISTRATION SAR, or failed and triggered an
    // AUTHENTICATION_FAILURE SAR).
    success = true;
  }
  else
  {
    LOG_DEBUG("AV for %s:%s has timed out", _impi.c_str(), _nonce.c_str());

    // Note that both AV deletion and the AUTHENTICATION_TIMEOUT SAR
    // are idempotent, so there's no problem if Chronos' timer pops
    // twice (e.g. if we have high latency and these operations take
    // more than 2 seconds).

    // If either of these operations fail, we return a 500 Internal
    // Server Error - this will trigger Chronos to try a different
    // Sprout, which may have better connectivity to Homestead or Memcached.
    success = _cfg->_hss->update_registration_state(_impu, _impi, HSSConnection::AUTH_TIMEOUT, 0);

    if (success)
    {
      success = _cfg->_avstore->delete_av(_impi, _nonce);
    }

    delete json;
  }
  return success ? 200 : 500;
}
