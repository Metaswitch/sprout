/**
 * @file regstore.cpp Registration data store.
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

extern "C" {
#include <pjlib-util.h>
#include <pjlib.h>
#include "pjsip-simple/evsub.h"
}

// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <time.h>

#include "log.h"
#include "utils.h"
#include "regstore.h"
#include "notify_utils.h"
#include "stack.h"
#include "pjutils.h"
#include "chronosconnection.h"
#include "sproutsasevent.h"
#include "constants.h"
#include "json_parse_utils.h"

RegStore::RegStore(Store* data_store,
                   SerializerDeserializer*& serializer,
                   std::vector<SerializerDeserializer*>& deserializers,
                   ChronosConnection* chronos_connection) :
  _chronos(chronos_connection),
  _connector(NULL)
{
  _connector = new Connector(data_store, serializer, deserializers);
}


RegStore::RegStore(Store* data_store,
                   ChronosConnection* chronos_connection) :
  _chronos(chronos_connection),
  _connector(NULL)
{
  SerializerDeserializer* serializer = new BinarySerializerDeserializer();
  std::vector<SerializerDeserializer*> deserializers = {
    new BinarySerializerDeserializer(),
  };

  _connector = new Connector(data_store, serializer, deserializers);
}


RegStore::~RegStore()
{
  delete _connector;
}


/// Retrieve the registration data for a given SIP Address of Record, creating
/// an empty record if no data exists for the AoR.
///
/// @param aor_id       The SIP Address of Record for the registration
RegStore::AoR* RegStore::get_aor_data(const std::string& aor_id, SAS::TrailId trail)
{
  AoR* aor_data = _connector->get_aor_data(aor_id, trail);

  if (aor_data != NULL)
  {
    int now = time(NULL);
    expire_bindings(aor_data, now, trail);
    expire_subscriptions(aor_data, now);
  }

  return aor_data;
}

RegStore::AoR* RegStore::Connector::get_aor_data(const std::string& aor_id, SAS::TrailId trail)
{
  LOG_DEBUG("Get AoR data for %s", aor_id.c_str());
  AoR* aor_data = NULL;

  std::string data;
  uint64_t cas;
  Store::Status status = _data_store->get_data("reg", aor_id, data, cas, trail);

  if (status == Store::Status::OK)
  {
    // Retrieved the data, so deserialize it.
    LOG_DEBUG("Data store returned a record, CAS = %ld", cas);
    aor_data = deserialize_aor(aor_id, data);

    if (aor_data != NULL)
    {
      aor_data->_cas = cas;

      SAS::Event event(trail, SASEvent::REGSTORE_GET_FOUND, 0);
      event.add_var_param(aor_id);
      SAS::report_event(event);
    }
    else
    {
      // Could not deserialize the record. Treat it as not found.
      LOG_INFO("Failed to deserialize record");
      SAS::Event event(trail, SASEvent::REGSTORE_DESERIALIZATION_FAILED, 0);
      event.add_var_param(aor_id);
      event.add_var_param(data);
      SAS::report_event(event);
    }
  }
  else if (status == Store::Status::NOT_FOUND)
  {
    // Data store didn't find the record, so create a new blank record.
    aor_data = new AoR(aor_id);

    SAS::Event event(trail, SASEvent::REGSTORE_GET_NEW, 0);
    event.add_var_param(aor_id);
    SAS::report_event(event);

    LOG_DEBUG("Data store returned not found, so create new record, CAS = %ld", aor_data->_cas);
  }
  else
  {
    // LCOV_EXCL_START
    SAS::Event event(trail, SASEvent::REGSTORE_GET_FAILURE, 0);
    event.add_var_param(aor_id);
    SAS::report_event(event);
    // LCOV_EXCL_STOP
  }

  return aor_data;
}

bool RegStore::set_aor_data(const std::string& aor_id,
                            AoR* aor_data,
                            bool set_chronos,
                            SAS::TrailId trail)
{
  bool unused;
  return set_aor_data(aor_id, aor_data, set_chronos, trail, unused);
}


/// Update the data for a particular address of record.  Writes the data
/// atomically.  If the underlying data has changed since it was last
/// read, the update is rejected and this returns false; if the update
/// succeeds, this returns true.
///
/// @param aor_id     The SIP Address of Record for the registration
/// @param aor_data   The registration data record.
/// @param set_chronos   Determines whether a Chronos request should
///                      be sent to keep track of binding expiry time.
/// @param all_bindings_expired   Set to true to flag to the caller that
///                               no bindings remain for this AoR.

bool RegStore::set_aor_data(const std::string& aor_id,
                            AoR* aor_data,
                            bool set_chronos,
                            SAS::TrailId trail,
                            bool& all_bindings_expired)
{
  all_bindings_expired = false;
  // Expire any old bindings before writing to the server.  In theory, if
  // there are no bindings left we could delete the entry, but this may
  // cause concurrency problems because memcached does not support
  // cas on delete operations.  In this case we do a memcached_cas with
  // an effectively immediate expiry time.
  int now = time(NULL);

  // Set the max expires to be greater than the longest binding expiry time.
  // This prevents a window condition where Chronos can return a binding to
  // expire, but memcached has already deleted the aor data (meaning that
  // no NOTIFYs could be sent)
  int orig_max_expires = expire_bindings(aor_data, now, trail);
  int max_expires = orig_max_expires + 10;

  // expire_bindings returns "now" if there are no remaining bindings,
  // so test for that.
  if (orig_max_expires == now)
  {
    LOG_DEBUG("All bindings have expired, so this is a deregistration for AOR %s", aor_id.c_str());
    all_bindings_expired = true;
  }

  // Expire any old subscriptions as well.  This doesn't get factored in to
  // the expiry time on the store record because, according to 5.4.2.1.2 /
  // TS 24.229, all subscriptions automatically expire when the last binding
  // expires.
  expire_subscriptions(aor_data, now);

  LOG_DEBUG("Set AoR data for %s, CAS=%ld, expiry = %d",
            aor_id.c_str(), aor_data->_cas, max_expires);

  // Set the chronos timers
  if (set_chronos)
  {
    for (AoR::Bindings::iterator i = aor_data->_bindings.begin();
         i != aor_data->_bindings.end();
         ++i)
    {
      AoR::Binding* b = i->second;
      std::string b_id = i->first;

      HTTPCode status;
      std::string timer_id = "";
      std::string opaque = "{\"aor_id\": \"" + aor_id + "\", \"binding_id\": \"" + b_id +"\"}";
      std::string callback_uri = "/timers";

      int now = time(NULL);
      int expiry = b->_expires - now;

      // If a timer has been previously set for this binding, send a PUT. Otherwise sent a POST.
      if (b->_timer_id == "")
      {
        status = _chronos->send_post(timer_id, expiry, callback_uri, opaque, 0);
      }
      else
      {
        timer_id = b->_timer_id;
        status = _chronos->send_put(timer_id, expiry, callback_uri, opaque, 0);
      }

      // Update the timer id. If the update to Chronos failed, that's OK, don't reject the register
      // or update the stored timer id.
      if (status == HTTP_OK)
      {
        b->_timer_id = timer_id;
      }
    }
  }

  return _connector->set_aor_data(aor_id, aor_data, max_expires - now, trail);
}

bool RegStore::Connector::set_aor_data(const std::string& aor_id,
                                       AoR* aor_data,
                                       int expiry,
                                       SAS::TrailId trail)
{
  std::string data = serialize_aor(aor_data);

  SAS::Event event(trail, SASEvent::REGSTORE_SET_START, 0);
  event.add_var_param(aor_id);
  SAS::report_event(event);

  Store::Status status = _data_store->set_data("reg",
                                               aor_id,
                                               data,
                                               aor_data->_cas,
                                               expiry,
                                               trail);

  LOG_DEBUG("Data store set_data returned %d", status);

  if (status == Store::Status::OK)
  {
    SAS::Event event2(trail, SASEvent::REGSTORE_SET_SUCCESS, 0);
    event2.add_var_param(aor_id);
    SAS::report_event(event2);
  }
  else
  {
    // LCOV_EXCL_START
    SAS::Event event2(trail, SASEvent::REGSTORE_SET_FAILURE, 0);
    event2.add_var_param(aor_id);
    SAS::report_event(event2);
    // LCOV_EXCL_STOP
  }


  return (status == Store::Status::OK);
}


/// Expire any old bindings, and calculates the latest outstanding expiry time,
/// or now if none.
///
/// @returns             The latest expiry time from all unexpired bindings.
/// @param aor_data      The registration data record.
/// @param now           The current time in seconds since the epoch.
int RegStore::expire_bindings(AoR* aor_data,
                              int now,
                              SAS::TrailId trail)
{
  int max_expires = now;
  for (AoR::Bindings::iterator i = aor_data->_bindings.begin();
       i != aor_data->_bindings.end();
      )
  {
    AoR::Binding* b = i->second;
    std::string b_id = i->first;
    if (b->_expires <= now)
    {
      // Update the cseq
      aor_data->_notify_cseq++;

      // The binding has expired, so remove it. Send a SIP NOTIFY for this binding
      // if there are any subscriptions
      for (AoR::Subscriptions::iterator j = aor_data->_subscriptions.begin();
           j != aor_data->_subscriptions.end();
          ++j)
      {
        // Don't send a notification when an emergency registration expires
        if (!b->_emergency_registration)
        {
          send_notify(j->second, aor_data->_notify_cseq, b, b_id, trail);
        }
      }

      // If a timer id is present, then delete it. If the timer id is empty (because a
      // previous post/put failed) then don't.
      if (b->_timer_id != "")
      {
        _chronos->send_delete(b->_timer_id, trail);
      }

      delete i->second;
      aor_data->_bindings.erase(i++);
    }
    else
    {
      if (b->_expires > max_expires)
      {
        max_expires = b->_expires;
      }
      ++i;
    }
  }
  return max_expires;
}


/// Expire any old subscriptions.
///
/// @param aor_data      The registration data record.
/// @param now           The current time in seconds since the epoch.
void RegStore::expire_subscriptions(AoR* aor_data,
                                   int now)
{
  for (AoR::Subscriptions::iterator i = aor_data->_subscriptions.begin();
       i != aor_data->_subscriptions.end();
      )
  {
    AoR::Subscription* s = i->second;
    if (s->_expires <= now)
    {
      // The subscription has expired, so remove it.
      delete i->second;
      aor_data->_subscriptions.erase(i++);
    }
    else
    {
      ++i;
    }
  }
}


/// Serialize the contents of an AoR.
std::string RegStore::Connector::serialize_aor(AoR* aor_data)
{
  return _serializer->serialize_aor(aor_data);
}


/// Deserialize the contents of an AoR
RegStore::AoR* RegStore::Connector::deserialize_aor(const std::string& aor_id, const std::string& s)
{
  AoR* aor = NULL;

  for(std::vector<SerializerDeserializer*>::iterator it = _deserializers.begin();
      it != _deserializers.end();
      ++it)
  {
    SerializerDeserializer* deserializer = *it;
    aor = deserializer->deserialize_aor(aor_id, s);

    if (aor != NULL)
    {
      LOG_DEBUG("Deserialized record with '%s' deserializer",
                deserializer->name().c_str());
      return aor;
    }
    else
    {
      LOG_DEBUG("Failed to deserialized record with '%s' deserializer",
                deserializer->name().c_str());
    }
  }

  return aor;
}


/// Default constructor.
RegStore::AoR::AoR(std::string sip_uri) :
  _notify_cseq(1),
  _bindings(),
  _subscriptions(),
  _cas(0),
  _uri(sip_uri)
{
}


/// Destructor.
RegStore::AoR::~AoR()
{
  clear(true);
}


/// Copy constructor.
RegStore::AoR::AoR(const AoR& other)
{
  common_constructor(other);
}

// Make sure assignment is deep!
RegStore::AoR& RegStore::AoR::operator= (AoR const& other)
{
  if (this != &other)
  {
    clear(true);
    common_constructor(other);
  }

  return *this;
}

void RegStore::AoR::common_constructor(const AoR& other)
{
  for (Bindings::const_iterator i = other._bindings.begin();
       i != other._bindings.end();
       ++i)
  {
    Binding* bb = new Binding(*i->second);
    _bindings.insert(std::make_pair(i->first, bb));
  }

  for (Subscriptions::const_iterator i = other._subscriptions.begin();
       i != other._subscriptions.end();
       ++i)
  {
    Subscription* ss = new Subscription(*i->second);
    _subscriptions.insert(std::make_pair(i->first, ss));
  }

  _notify_cseq = other._notify_cseq;
  _cas = other._cas;
}


/// Clear all the bindings and subscriptions from this object.
void RegStore::AoR::clear(bool clear_emergency_bindings)
{
  for (Bindings::iterator i = _bindings.begin();
       i != _bindings.end();
       )
  {
    if ((clear_emergency_bindings) || (!i->second->_emergency_registration))
    {
      delete i->second;
      _bindings.erase(i++);
    }
    else
    {
      ++i;
    }
  }

  if (clear_emergency_bindings)
  {
    _bindings.clear();
  }

  for (Subscriptions::iterator i = _subscriptions.begin();
       i != _subscriptions.end();
       ++i)
  {
    delete i->second;
  }

  _subscriptions.clear();
}


/// Retrieve a binding by binding identifier, creating an empty one if
/// necessary.  The created binding is completely empty, even the Contact URI
/// field.
RegStore::AoR::Binding* RegStore::AoR::get_binding(const std::string& binding_id)
{
  AoR::Binding* b;
  AoR::Bindings::const_iterator i = _bindings.find(binding_id);
  if (i != _bindings.end())
  {
    b = i->second;
  }
  else
  {
    // No existing binding with this id, so create a new one.
    b = new Binding(&_uri);
    b->_expires = 0;
    _bindings.insert(std::make_pair(binding_id, b));
  }
  return b;
}


/// Removes any binding that had the given ID.  If there is no such binding,
/// does nothing.
void RegStore::AoR::remove_binding(const std::string& binding_id)
{
  AoR::Bindings::iterator i = _bindings.find(binding_id);
  if (i != _bindings.end())
  {
    delete i->second;
    _bindings.erase(i);
  }
}

/// Retrieve a subscription by To tag, creating an empty subscription if
/// necessary.
RegStore::AoR::Subscription* RegStore::AoR::get_subscription(const std::string& to_tag)
{
  AoR::Subscription* s;
  AoR::Subscriptions::const_iterator i = _subscriptions.find(to_tag);
  if (i != _subscriptions.end())
  {
    s = i->second;
  }
  else
  {
    // No existing subscription with this tag, so create a new one.
    s = new Subscription;
    _subscriptions.insert(std::make_pair(to_tag, s));
  }
  return s;
}


/// Removes the subscription with the specified tag.  If there is no such
/// subscription, does nothing.
void RegStore::AoR::remove_subscription(const std::string& to_tag)
{
  AoR::Subscriptions::iterator i = _subscriptions.find(to_tag);
  if (i != _subscriptions.end())
  {
    delete i->second;
    _subscriptions.erase(i);
  }
}

void RegStore::send_notify(AoR::Subscription* s, int cseq,
                           AoR::Binding* b, std::string b_id,
                           SAS::TrailId trail)
{
  pjsip_tx_data* tdata_notify = NULL;
  std::map<std::string, AoR::Binding> bindings;
  bindings.insert(std::pair<std::string, RegStore::AoR::Binding>(b_id, *b));
  pj_status_t status = NotifyUtils::create_notify(&tdata_notify, s, "aor", cseq, bindings,
                                  NotifyUtils::DocState::PARTIAL,
                                  NotifyUtils::RegistrationState::ACTIVE,
                                  NotifyUtils::ContactState::TERMINATED,
                                  NotifyUtils::ContactEvent::EXPIRED,
                                  NotifyUtils::SubscriptionState::ACTIVE,
                                  (s->_expires - time(NULL)));

  if (status == PJ_SUCCESS)
  {
    set_trail(tdata_notify, trail);
    status = PJUtils::send_request(tdata_notify, 0, NULL, NULL, true);
  }
}

RegStore::Connector::Connector(Store* data_store,
                               SerializerDeserializer*& serializer,
                               std::vector<SerializerDeserializer*>& deserializers) :
  _data_store(data_store),
  _serializer(serializer),
  _deserializers(deserializers)
{
  // We have taken ownership of the serializer and deserializers.
  serializer = NULL;
  deserializers.clear();
}

RegStore::Connector::~Connector()
{
  delete _serializer; _serializer = NULL;

  for(std::vector<SerializerDeserializer*>::iterator it = _deserializers.begin();
      it != _deserializers.end();
      ++it)
  {
    delete *it; *it = NULL;
  }
}

// Generates the public GRUU for this binding from the address of record and
// instance-id. Returns NULL if this binding has no valid GRUU.
pjsip_sip_uri* RegStore::AoR::Binding::pub_gruu(pj_pool_t* pool) const
{
  pjsip_sip_uri* uri = (pjsip_sip_uri*)PJUtils::uri_from_string(*_address_of_record, pool);

  if ((_params.find("+sip.instance") == _params.cend()) ||
      (uri == NULL) ||
      !PJSIP_URI_SCHEME_IS_SIP(uri))
  {
    // GRUUs are only valid for SIP URIs with an instance-id.
    return NULL;
  }

  // The instance parameter might be too short to be a valid GRUU. Specifically
  // if its less than 2 characters in length, the stripping function will give
  // us a buffer underrun, so exit now.
  std::string sip_instance = _params.at("+sip.instance");
  if (sip_instance.length() < 2)
  {
    // instance ID too short to be parsed
    return NULL;
  }

  pjsip_param* gr_param = (pjsip_param*) pj_pool_alloc(pool, sizeof(pjsip_param));
  gr_param->name = STR_GR;
  pj_strdup2(pool, &gr_param->value, sip_instance.c_str());

  // instance-ids are often of the form '"<urn:..."' - convert that to
  // just 'urn:...'
  if (*(gr_param->value.ptr) == '"')
  {
    gr_param->value.ptr++;
    gr_param->value.slen -= 2;
  }

  if (*(gr_param->value.ptr) == '<')
  {
    gr_param->value.ptr++;
    gr_param->value.slen -= 2;
  }

  pj_list_push_back((pj_list_type*)&(uri->other_param), (pj_list_type*)gr_param);
  return uri;
}

// Utility method to return the public GRUU as a string.
// Returns "" if this binding has no GRUU.
pj_str_t RegStore::AoR::Binding::pub_gruu_pj_str(pj_pool_t* pool) const
{
  pjsip_sip_uri* pub_gruu_uri = pub_gruu(pool);

  if (pub_gruu_uri == NULL)
  {
    return pj_str("");
  }

  return PJUtils::uri_to_pj_str(PJSIP_URI_IN_REQ_URI, (pjsip_uri*)pub_gruu_uri, pool);
}

// Utility method to return the public GRUU surrounded by quotes.
// Returns "" if this binding has no GRUU.
std::string RegStore::AoR::Binding::pub_gruu_quoted_string(pj_pool_t* pool) const
{
  pj_str_t unquoted_pub_gruu = pub_gruu_pj_str(pool);

  if (unquoted_pub_gruu.slen == 0)
  {
    return "";
  }

  std::string ret;
  ret.reserve(unquoted_pub_gruu.slen + 2);
  ret.append("\"");
  ret.append(unquoted_pub_gruu.ptr, unquoted_pub_gruu.slen);
  ret.append("\"");
  return ret;
}


//
// (De)serializer for the binary RegStore format.
//

RegStore::AoR* RegStore::BinarySerializerDeserializer::
  deserialize_aor(const std::string& aor_id, const std::string& s)
{
  std::istringstream iss(s, std::istringstream::in|std::istringstream::binary);

  // First off, try to read the number of bindings.
  int num_bindings;
  iss.read((char *)&num_bindings, sizeof(int));

  if (iss.eof())
  {
    // Hit an EOF which means the record is corrupt.
    LOG_INFO("Could not deserialize AOR - EOF reached");
    return NULL;
  }

  if (num_bindings > 0xffffff)
  {
    // That's a lot of bindings. It is more likely that the data is corrupt, or
    // that we have been passed a record in a different format.
    LOG_INFO("Could not deserialize AOR. Got %d bindings suggesting the data"
             " is corrupt or not in the binary format",
             num_bindings);
    return NULL;
  }

  AoR* aor_data = new AoR(aor_id);

  LOG_DEBUG("Deserialize %d bindings", num_bindings);

  for (int ii = 0; ii < num_bindings; ++ii)
  {
    // Extract the binding identifier into a string.
    std::string binding_id;
    getline(iss, binding_id, '\0');
    LOG_DEBUG("  Binding %s", binding_id.c_str());

    AoR::Binding* b = aor_data->get_binding(binding_id);

    // Now extract the various fixed binding parameters.
    getline(iss, b->_uri, '\0');
    getline(iss, b->_cid, '\0');
    iss.read((char *)&b->_cseq, sizeof(int));
    iss.read((char *)&b->_expires, sizeof(int));

    iss.read((char *)&b->_priority, sizeof(int));

    int num_params;
    iss.read((char *)&num_params, sizeof(int));
    for (int ii = 0;
         ii < num_params;
         ++ii)
    {
      std::string pname;
      std::string pvalue;
      getline(iss, pname, '\0');
      getline(iss, pvalue, '\0');
      b->_params[pname] = pvalue;
    }

    int num_paths = 0;
    iss.read((char *)&num_paths, sizeof(int));
    b->_path_headers.resize(num_paths);
    LOG_DEBUG("Deserialize %d path headers", num_paths);
    for (std::list<std::string>::iterator i = b->_path_headers.begin();
         i != b->_path_headers.end();
         ++i)
    {
      getline(iss, *i, '\0');
      LOG_DEBUG("  Deserialized path header %s", i->c_str());
    }
    getline(iss, b->_timer_id, '\0');
    getline(iss, b->_private_id, '\0');
    iss.read((char *)&b->_emergency_registration, sizeof(int));
  }

  int num_subscriptions;
  iss.read((char *)&num_subscriptions, sizeof(int));
  LOG_DEBUG("Deserialize %d subscriptions", num_subscriptions);

  for (int ii = 0; ii < num_subscriptions; ++ii)
  {
    // Extract the to tag index into a string.
    std::string to_tag;
    getline(iss, to_tag, '\0');
    LOG_DEBUG("  Subscription %s", to_tag.c_str());

    AoR::Subscription* s = aor_data->get_subscription(to_tag);

    // Now extract the various fixed subscription parameters.
    getline(iss, s->_req_uri, '\0');
    getline(iss, s->_from_uri, '\0');
    getline(iss, s->_from_tag, '\0');
    getline(iss, s->_to_uri, '\0');
    getline(iss, s->_to_tag, '\0');
    getline(iss, s->_cid, '\0');

    int num_routes = 0;
    iss.read((char *)&num_routes, sizeof(int));
    LOG_DEBUG("    number of routes = %d", num_routes);
    s->_route_uris.resize(num_routes);
    for (std::list<std::string>::iterator i = s->_route_uris.begin();
         i != s->_route_uris.end();
         ++i)
    {
      getline(iss, *i, '\0');
    }

    iss.read((char *)&s->_expires, sizeof(int));
  }

  iss.read((char*)&aor_data->_notify_cseq, sizeof(int));

  return aor_data;
}


std::string RegStore::BinarySerializerDeserializer::serialize_aor(AoR* aor_data)
{
  std::ostringstream oss(std::ostringstream::out|std::ostringstream::binary);

  int num_bindings = aor_data->bindings().size();
  LOG_DEBUG("Serialize %d bindings", num_bindings);
  oss.write((const char *)&num_bindings, sizeof(int));

  for (AoR::Bindings::const_iterator i = aor_data->bindings().begin();
       i != aor_data->bindings().end();
       ++i)
  {
    LOG_DEBUG("  Binding %s", i->first.c_str());
    oss << i->first << '\0';

    AoR::Binding* b = i->second;
    oss << b->_uri << '\0';
    oss << b->_cid << '\0';
    oss.write((const char *)&b->_cseq, sizeof(int));
    oss.write((const char *)&b->_expires, sizeof(int));
    oss.write((const char *)&b->_priority, sizeof(int));
    int num_params = b->_params.size();
    oss.write((const char *)&num_params, sizeof(int));
    for (std::map<std::string, std::string>::const_iterator i = b->_params.begin();
         i != b->_params.end();
         ++i)
    {
      oss << i->first << '\0' << i->second << '\0';
    }
    int num_path_hdrs = b->_path_headers.size();
    oss.write((const char *)&num_path_hdrs, sizeof(int));
    for (std::list<std::string>::const_iterator i = b->_path_headers.begin();
         i != b->_path_headers.end();
         ++i)
    {
      oss << *i << '\0';
    }
    oss << b->_timer_id << '\0';
    oss << b->_private_id << '\0';
    oss.write((const char *)&b->_emergency_registration, sizeof(int));
  }

  int num_subscriptions = aor_data->subscriptions().size();
  LOG_DEBUG("Serialize %d subscriptions", num_subscriptions);
  oss.write((const char *)&num_subscriptions, sizeof(int));

  for (AoR::Subscriptions::const_iterator i = aor_data->subscriptions().begin();
       i != aor_data->subscriptions().end();
       ++i)
  {
    LOG_DEBUG("  Subscription %s", i->first.c_str());
    oss << i->first << '\0';

    AoR::Subscription* s = i->second;
    oss << s->_req_uri << '\0';
    oss << s->_from_uri << '\0';
    oss << s->_from_tag << '\0';
    oss << s->_to_uri << '\0';
    oss << s->_to_tag << '\0';
    oss << s->_cid << '\0';
    int num_routes = s->_route_uris.size();
    LOG_DEBUG("    number of routes = %d", num_routes);
    oss.write((const char *)&num_routes, sizeof(int));
    for (std::list<std::string>::const_iterator i = s->_route_uris.begin();
         i != s->_route_uris.end();
         ++i)
    {
      oss << *i << '\0';
    }
    oss.write((const char *)&s->_expires, sizeof(int));
  }

  oss.write((const char *)&aor_data->_notify_cseq, sizeof(int));

  return oss.str();
}

std::string RegStore::BinarySerializerDeserializer::name()
{
  return "binary";
}


//
// (De)serializer for the JSON RegStore format.
//

static const char* const JSON_BINDINGS = "bindings";
static const char* const JSON_URI = "uri";
static const char* const JSON_CID = "cid";
static const char* const JSON_CSEQ = "cseq";
static const char* const JSON_EXPIRES = "expires";
static const char* const JSON_PRIORITY = "priority";
static const char* const JSON_PARAMS = "params";
static const char* const JSON_PATHS = "paths";
static const char* const JSON_TIMER_ID = "timer_id";
static const char* const JSON_PRIVATE_ID = "private_id";
static const char* const JSON_EMERGENCY_REG = "emergency_reg";
static const char* const JSON_SUBSCRIPTIONS = "subscriptions";
static const char* const JSON_REQ_URI = "req_uri";
static const char* const JSON_FROM_URI = "from_uri";
static const char* const JSON_FROM_TAG = "from_tag";
static const char* const JSON_TO_URI = "to_uri";
static const char* const JSON_TO_TAG = "to_tag";
static const char* const JSON_ROUTES = "routes";
static const char* const JSON_NOTIFY_CSEQ = "notify_cseq";


RegStore::AoR* RegStore::JsonSerializerDeserializer::
  deserialize_aor(const std::string& aor_id, const std::string& s)
{
  rapidjson::Document doc;
  doc.Parse<0>(s.c_str());

  if (doc.HasParseError())
  {
    LOG_DEBUG("Failed to parse JSON document: %s", s.c_str());
    return NULL;
  }

  AoR* aor = new AoR(aor_id);

  try
  {
    JSON_ASSERT_CONTAINS(doc, JSON_BINDINGS);
    JSON_ASSERT_OBJECT(doc[JSON_BINDINGS]);

    for (rapidjson::Value::ConstMemberIterator bindings_it = doc[JSON_BINDINGS].MemberBegin();
         bindings_it != doc[JSON_BINDINGS].MemberEnd();
         ++bindings_it)
    {
      AoR::Binding* b = aor->get_binding(bindings_it->name.GetString());

      JSON_GET_STRING_MEMBER(bindings_it->value, JSON_URI, b->_uri);
      JSON_GET_STRING_MEMBER(bindings_it->value, JSON_CID, b->_cid);
      JSON_GET_INT_MEMBER(bindings_it->value, JSON_CSEQ, b->_cseq);
      JSON_GET_INT_MEMBER(bindings_it->value, JSON_EXPIRES, b->_expires);
      JSON_GET_INT_MEMBER(bindings_it->value, JSON_PRIORITY, b->_priority);

      JSON_ASSERT_CONTAINS(bindings_it->value, JSON_PARAMS);
      JSON_ASSERT_OBJECT(bindings_it->value[JSON_PARAMS]);

      for (rapidjson::Value::ConstMemberIterator params_it =
             bindings_it->value[JSON_PARAMS].MemberBegin();
           params_it != bindings_it->value[JSON_PARAMS].MemberEnd();
           ++params_it)
      {
        JSON_ASSERT_STRING(params_it->value);
        b->_params[params_it->name.GetString()] = params_it->value.GetString();
      }

      JSON_ASSERT_CONTAINS(bindings_it->value, JSON_PATHS);
      JSON_ASSERT_OBJECT(bindings_it->value[JSON_PATHS]);

      for (rapidjson::Value::ConstValueIterator paths_it =
             bindings_it->value[JSON_PATHS].Begin();
           paths_it != bindings_it->value[JSON_PATHS].End();
           ++paths_it)
      {
        JSON_ASSERT_INT(*paths_it);
        b->_path_headers.push_back(paths_it->GetString());
      }

      JSON_GET_STRING_MEMBER(bindings_it->value, JSON_TIMER_ID, b->_timer_id);
      JSON_GET_STRING_MEMBER(bindings_it->value, JSON_PRIVATE_ID, b->_private_id);
      JSON_GET_BOOL_MEMBER(bindings_it->value, JSON_EMERGENCY_REG, b->_emergency_registration);
    }

    JSON_ASSERT_CONTAINS(doc, JSON_SUBSCRIPTIONS);
    JSON_ASSERT_OBJECT(doc[JSON_SUBSCRIPTIONS]);

    for (rapidjson::Value::ConstMemberIterator subscriptions_it = doc[JSON_SUBSCRIPTIONS].MemberBegin();
         subscriptions_it != doc[JSON_BINDINGS].MemberEnd();
         ++subscriptions_it)
    {
      AoR::Subscription* s = aor->get_subscription(subscriptions_it->name.GetString());

      JSON_GET_STRING_MEMBER(subscriptions_it->value, JSON_REQ_URI, s->_req_uri);
      JSON_GET_STRING_MEMBER(subscriptions_it->value, JSON_FROM_URI, s->_from_uri);
      JSON_GET_STRING_MEMBER(subscriptions_it->value, JSON_FROM_TAG, s->_from_tag);
      JSON_GET_STRING_MEMBER(subscriptions_it->value, JSON_TO_URI, s->_to_uri);
      JSON_GET_STRING_MEMBER(subscriptions_it->value, JSON_TO_TAG, s->_to_tag);
      JSON_GET_STRING_MEMBER(subscriptions_it->value, JSON_CID, s->_cid);

      JSON_ASSERT_CONTAINS(subscriptions_it->value, JSON_ROUTES);
      JSON_ASSERT_OBJECT(subscriptions_it->value[JSON_ROUTES]);

      for (rapidjson::Value::ConstValueIterator routes_it =
             subscriptions_it->value[JSON_PATHS].Begin();
           routes_it != subscriptions_it->value[JSON_PATHS].End();
           ++routes_it)
      {
        JSON_ASSERT_STRING(*routes_it);
        s->_route_uris.push_back(routes_it->GetString());
      }

      JSON_GET_INT_MEMBER(subscriptions_it->value, JSON_EXPIRES, s->_expires);
    }

    JSON_GET_INT_MEMBER(doc, JSON_NOTIFY_CSEQ, aor->_notify_cseq);
  }
  catch(JsonFormatError err)
  {
    LOG_INFO("Failed to deserialize JSON document (hit error at %s:%s)",
             err._file, err._line);
    delete aor; aor = NULL;
  }

  return aor;
}


std::string RegStore::JsonSerializerDeserializer::serialize_aor(AoR* aor_data)
{
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

  writer.StartObject();
  {
    //
    // Bindings
    //
    writer.String(JSON_BINDINGS);
    writer.StartObject();
    {
      for (AoR::Bindings::const_iterator it = aor_data->bindings().begin();
           it != aor_data->bindings().end();
           ++it)
      {
        LOG_DEBUG("  Binding %s", it->first.c_str());
        writer.String(it->first.c_str());

        writer.StartObject();
        {
          AoR::Binding* b = it->second;
          writer.String(JSON_URI); writer.String(b->_uri.c_str());
          writer.String(JSON_CID); writer.String(b->_cid.c_str());
          writer.String(JSON_CSEQ); writer.Int(b->_cseq);
          writer.String(JSON_EXPIRES); writer.Int(b->_expires);
          writer.String(JSON_PRIORITY); writer.Int(b->_priority);

          writer.String(JSON_PARAMS);
          writer.StartObject();
          {
            for (std::map<std::string, std::string>::const_iterator p = b->_params.begin();
                 p != b->_params.end();
                 ++p)
            {
              writer.String(p->first.c_str()); writer.String(p->second.c_str());
            }
          }
          writer.EndObject();

          writer.String(JSON_PATHS);
          writer.StartArray();
          {
            for (std::list<std::string>::const_iterator p = b->_path_headers.begin();
                 p != b->_path_headers.end();
                 ++p)
            {
              writer.String(p->c_str());
            }
          }
          writer.EndArray();

          writer.String(JSON_TIMER_ID); writer.String(b->_timer_id.c_str());
          writer.String(JSON_PRIVATE_ID); writer.String(b->_private_id.c_str());
          writer.String(JSON_EMERGENCY_REG); writer.Bool(b->_emergency_registration);
        }
        writer.EndObject();
      }
    }
    writer.EndObject();

    //
    // Subscriptions.
    //
    writer.String(JSON_SUBSCRIPTIONS);
    writer.StartObject();
    {
      for (AoR::Subscriptions::const_iterator it = aor_data->subscriptions().begin();
           it != aor_data->subscriptions().end();
           ++it)
      {
        LOG_DEBUG("  Subscription %s", it->first.c_str());
        writer.String(it->first.c_str());
        writer.StartObject();
        {
          AoR::Subscription* s = it->second;
          writer.String(JSON_REQ_URI); writer.String(s->_req_uri.c_str());
          writer.String(JSON_FROM_URI); writer.String(s->_from_uri.c_str());
          writer.String(JSON_FROM_TAG); writer.String(s->_from_tag.c_str());
          writer.String(JSON_TO_URI); writer.String(s->_to_uri.c_str());
          writer.String(JSON_TO_TAG); writer.String(s->_to_tag.c_str());
          writer.String(JSON_CID); writer.String(s->_cid.c_str());

          writer.String(JSON_ROUTES);
          writer.StartArray();
          {
            for (std::list<std::string>::const_iterator r = s->_route_uris.begin();
                 r != s->_route_uris.end();
                 ++r)
            {
              writer.String(r->c_str());
            }
          }
          writer.EndArray();

          writer.String(JSON_EXPIRES); writer.Int(s->_expires);
        }
        writer.EndObject();
      }
    }
    writer.EndObject();

    // Notify Cseq flag
    writer.String(JSON_NOTIFY_CSEQ); writer.Int(aor_data->_notify_cseq);
  }
  writer.EndObject();

  return sb.GetString();
}

std::string RegStore::JsonSerializerDeserializer::name()
{
  return "JSON";
}
