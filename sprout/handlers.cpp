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

#include "handlers.h"
#include "log.h"
#include "regstore.h"

void ChronosHandler::run()
{
  if (_req.method() != htp_method_POST)
  {
    _req.send_reply(405);
    return;
  }

  std::string aor = "";
  std::string binding = "";

  int rc = parse_response(_req.body(), &aor, &binding);
  if (rc != 200)
  {
    LOG_DEBUG("Unable to parse response from Chronos");
    _req.send_reply(rc);
    return;
  }

  _req.send_reply(200);
  handle_response(aor, binding);
  delete this;
}

void ChronosHandler::handle_response(const std::string aor, const std::string binding)
{
  RegStore::AoR* aor_data = NULL;
    
  do
  {
    // delete NULL is safe, so we can do this on every iteration.
    delete aor_data;

    // Find the current bindings for the AoR.
    aor_data = _cfg->store->get_aor_data(aor);
    LOG_DEBUG("Retrieved AoR data %p", aor_data);

    if (aor_data == NULL)
    {
      // Failed to get data for the AoR because there is no connection
      // to the store.
      // LCOV_EXCL_START - local store (used in testing) never fails
      LOG_ERROR("Failed to get AoR binding for %s from store", aor.c_str());
      break;
      // LCOV_EXCL_STOP
    }

    // Get the binding 
    RegStore::AoR::Binding* bind = aor_data->get_binding(binding);
    
    if (bind->_cid != "")
    { 
      // Existing binding 
      int now = time(NULL);
      int expiry = bind->_expires - now; 

      if (expiry <= 1)
      {
        // Update the cseq
        aor_data->_notify_cseq++;
       
        // Send a SIP NOTIFY for this binding if there are any subscriptions
        for (RegStore::AoR::Subscriptions::const_iterator i = aor_data->subscriptions().begin();
             i != aor_data->subscriptions().end();
             ++i)
        {
          _cfg->store->send_notify(i->second, aor_data->_notify_cseq, bind, binding);  
        }
 
        aor_data->remove_binding(binding);
      } 
      else
      {
        LOG_DEBUG("The timer wasn't due to expire, update the Chronos timer");

        std::string timer_id;
        HTTPCode status;
        std::string opaque = "{\"aor_id\": \"" + aor + "\", \"binding_id\": \"" + binding +"\"}";

        if (bind->_timer_id == "")
        {
          timer_id = "";
          status = _cfg->chronos->send_post(timer_id, expiry, "http://localhost:9888/timers", opaque, 0);
        }
        else
        {
          timer_id = bind->_timer_id;
          status = _cfg->chronos->send_put(timer_id, expiry, "http://localhost:9888/timers", opaque, 0);
        }

        // Update the timer id. If the put/post to Chronos failed, set the timer_id to ""
        if (status == HTTP_OK)
        {
          bind->_timer_id = timer_id;
        }
        else
        {
          bind->_timer_id = "";
        }
      }
    }
    else
    {
      LOG_DEBUG("This is a new binding, so the old binding has expired");
      break;
    }
  }
  while (!_cfg->store->set_aor_data(aor, aor_data));
  delete aor_data;
}

// Retrieve the aor and binding ID from the opaque data
int ChronosHandler::parse_response(std::string body, std::string *aor, std::string *binding)
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
    *aor = json_body.get("aor", "").asString();
  }
  else
  {
    LOG_WARNING("AoR ID not available in JSON");
    return 400;
  }

  if ((json_body.isMember("binding_id")) &&
      ((json_body)["binding_id"].isString()))
  {
    *binding = json_body.get("binding", "").asString();
  }
  else
  {
    LOG_WARNING("Binding ID not available in JSON");
    return 400;
  }

  return 200;
}
