/**
 * @file subscriber_data_manager.cpp
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
#include "subscriber_data_manager.h"
#include "notify_utils.h"
#include "stack.h"
#include "pjutils.h"
#include "chronosconnection.h"
#include "sproutsasevent.h"
#include "constants.h"
#include "json_parse_utils.h"
#include "rapidjson/error/en.h"

const std::vector<std::string> SubscriberDataManager::TAGS_NONE = {};
const std::vector<std::string> SubscriberDataManager::TAGS_REG = {"REG"};
const std::vector<std::string> SubscriberDataManager::TAGS_SUB = {"SUB"};

/// SubscriberDataManager Methods

SubscriberDataManager::SubscriberDataManager(Store* data_store,
                                             SerializerDeserializer*& serializer,
                                             std::vector<SerializerDeserializer*>& deserializers,
                                             ChronosConnection* chronos_connection,
                                             bool is_primary) :
  _primary_sdm(is_primary)
{
  _connector = new Connector(data_store, serializer, deserializers);
  _chronos_timer_request_sender = new ChronosTimerRequestSender(chronos_connection);
  _notify_sender = new NotifySender();
}


SubscriberDataManager::SubscriberDataManager(Store* data_store,
                                             ChronosConnection* chronos_connection,
                                             bool is_primary) :
  _primary_sdm(is_primary)
{
  SerializerDeserializer* serializer = new JsonSerializerDeserializer();
  std::vector<SerializerDeserializer*> deserializers = {
    new JsonSerializerDeserializer(),
  };

  _connector = new Connector(data_store, serializer, deserializers);
  _chronos_timer_request_sender = new ChronosTimerRequestSender(chronos_connection);
  _notify_sender = new NotifySender();
}


SubscriberDataManager::~SubscriberDataManager()
{
  delete _notify_sender;
  delete _chronos_timer_request_sender;
  delete _connector;
}

/// Retrieve the registration data for a given SIP Address of Record.
///
/// @param aor_id       The SIP Address of Record for the registration
SubscriberDataManager::AoRPair* SubscriberDataManager::get_aor_data(
                                          const std::string& aor_id,
                                          SAS::TrailId trail)
{
  AoR* aor_data = _connector->get_aor_data(aor_id, trail);

  if (aor_data != NULL)
  {
    // We got some data from the store. Copy the AoR, expire the copy,
    // and return both AoRs as an AoR pair.
    AoR* aor_copy = new AoR(*aor_data);
    int now = time(NULL);
    AoRPair* aor_pair = new AoRPair(aor_data, aor_copy);
    expire_aor_members(aor_pair, now);
    return aor_pair;
  }
  else
  {
    // We hit some kind of error in the store.
    return NULL;
  }
}

/// Update the data for a particular address of record.  Writes the data
/// atomically.  Returns the code returned by the underlying store, one of:
/// -  OK:              the AoR was writen successfully.
/// -  DATA_CONTENTION: the AoR was not written to the store because the CAS is
///                     out of date. The caller can refetch the AoR and try again.
/// -  ERROR:           the AoR was not written successfully and the caller
///                     should not retry.
///
/// @param aor_id     The SIP Address of Record for the registration
/// @param aor_pair   The registration data record.
/// @param trail      The SAS trail
bool SubscriberDataManager::unused_bool = false;

Store::Status SubscriberDataManager::set_aor_data(
                                     const std::string& aor_id,
                                     AoRPair* aor_pair,
                                     SAS::TrailId trail,
                                     bool& all_bindings_expired,
                                     pjsip_rx_data* extra_message_rdata,
                                     pjsip_tx_data* extra_message_tdata)
{
  // The ordering of this function is quite important.
  //
  // 1. Expire any old bindings/subscriptions.
  // 2. Send any Chronos timer requests
  // 3. Write the data to memcached. If this fails, bail out here
  // 4. Send any messages we were asked to by the caller
  // 5. Send any NOTIFYs
  //
  // This ordering is important to ensure that we don't send
  // duplicate NOTIFYs (so we send these after writing to memcached) and
  // so that only one piece of code has responsibility for this
  all_bindings_expired = false;

  // Expire old subscriptions and bindings before writing to the server. If
  // there were no bindings left we could delete the entry, but this may
  // cause concurrency problems because memcached does not support
  // cas on delete operations.  In this case we do a memcached_cas with
  // an effectively immediate expiry time.
  int now = time(NULL);

  // Set the max expires to be greater than the longest binding expiry time.
  // This prevents a window condition where Chronos can return a binding to
  // expire, but memcached has already deleted the aor data (meaning that
  // no NOTIFYs could be sent)
  int orig_max_expires = expire_aor_members(aor_pair, now);
  int max_expires = orig_max_expires + 10;

  // expire_aor_members returns "now" if there are no remaining bindings,
  // so test for that.
  if (orig_max_expires == now)
  {
    TRC_DEBUG("All bindings have expired, so this is a deregistration for AOR %s",
              aor_id.c_str());
    all_bindings_expired = true;
  }

  TRC_DEBUG("Set AoR data for %s, CAS=%ld, expiry = %d",
            aor_id.c_str(), aor_pair->get_current()->_cas, max_expires);

  // Set the chronos timers
  if (_primary_sdm)
  {
    _chronos_timer_request_sender->send_timers(aor_id, aor_pair, now, trail);
  }

  // Update the Notify CSeq, and write to store. We always update the cseq
  // as it's safe to increment it unnecessarily, and if we wait to find out
  // how many NOTIFYs we're going to send then we'll have to write back to
  // memcached again
  aor_pair->get_current()->_notify_cseq++;
  Store::Status rc = _connector->set_aor_data(aor_id,
                                              aor_pair->get_current(),
                                              max_expires - now,
                                              trail);

  if (rc != Store::Status::OK)
  {
    // We were unable to write to the store - return to the caller and
    // send no further messages
    return rc;
  }

  if (_primary_sdm)
  {
    // We may have been given some messages to send by the caller.
    if ((extra_message_rdata != NULL) &&
        (extra_message_tdata != NULL))
    {
      pjsip_endpt_send_response2(stack_data.endpt,
                                 extra_message_rdata,
                                 extra_message_tdata,
                                 NULL,
                                 NULL);
    }

    // Send any NOTIFYs needed
    _notify_sender->send_notifys(aor_id, aor_pair, now, trail);
  }

  return Store::Status::OK;
}

int SubscriberDataManager::expire_aor_members(AoRPair* aor_pair,
                                              int now)
{
  int max_expires = expire_bindings(aor_pair->get_current(), now);

  // N.B. Subscriptions are not factored into the returned expiry time on the
  // store record because, according to 5.4.2.1.2/TS 24.229, all subscriptions
  // automatically expire when the last binding expires.
  expire_subscriptions(aor_pair, now, (max_expires == now));

  return max_expires;
}

/// Expire any old subscriptions. Expire all subscriptions if requested
/// (e.g. when all the bindings have expired)
///
/// @param aor_data      The registration data record.
/// @param now           The current time in seconds since the epoch.
/// @param force_expire  Whether we should always remove the subscriptions
void SubscriberDataManager::expire_subscriptions(AoRPair* aor_pair,
                                                 int now,
                                                 bool force_expire)
{
  for (AoR::Subscriptions::iterator i =
         aor_pair->get_current()->_subscriptions.begin();
       i != aor_pair->get_current()->_subscriptions.end();
      )
  {
    AoR::Subscription* s = i->second;

    if ((force_expire) || (s->_expires <= now))
    {
      // The subscription has expired, so remove it. This could be
      // a single one shot subscription though - if so pretend it was
      // part of the original AoR
      SubscriberDataManager::AoR::Subscriptions::const_iterator aor_orig_s =
        aor_pair->get_orig()->subscriptions().find(i->first);

      if (aor_orig_s == aor_pair->get_orig()->subscriptions().end())
      {
        SubscriberDataManager::AoR::Subscription* s_copy =
          aor_pair->get_orig()->get_subscription(i->first);
        *s_copy = *i->second;
      }

      delete i->second;
      aor_pair->get_current()->_subscriptions.erase(i++);
    }
    else
    {
      ++i;
    }
  }
}

/// Expire any old bindings, and calculates the latest outstanding expiry time,
/// or now if none.
///
/// @returns             The latest expiry time from all unexpired bindings.
/// @param aor_data      The registration data record.
/// @param now           The current time in seconds since the epoch.
int SubscriberDataManager::expire_bindings(AoR* aor_data,
                                           int now)
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

/// SubscriberDataManager::Connector Methods

SubscriberDataManager::Connector::Connector(Store* data_store,
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

SubscriberDataManager::Connector::~Connector()
{
  delete _serializer; _serializer = NULL;

  for(std::vector<SerializerDeserializer*>::iterator it = _deserializers.begin();
      it != _deserializers.end();
      ++it)
  {
    delete *it; *it = NULL;
  }
}

/// Retrieve the registration data for a given SIP Address of Record, creating
/// an empty record if no data exists for the AoR.
///
/// @param aor_id       The SIP Address of Record for the registration
SubscriberDataManager::AoR* SubscriberDataManager::Connector::get_aor_data(
                                                 const std::string& aor_id,
                                                 SAS::TrailId trail)
{
  TRC_DEBUG("Get AoR data for %s", aor_id.c_str());
  AoR* aor_data = NULL;

  std::string data;
  uint64_t cas;
  Store::Status status = _data_store->get_data("reg", aor_id, data, cas, trail);

  if (status == Store::Status::OK)
  {
    // Retrieved the data, so deserialize it.
    TRC_DEBUG("Data store returned a record, CAS = %ld", cas);
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
      TRC_INFO("Failed to deserialize record");
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

    TRC_DEBUG("Data store returned not found, so create new record, CAS = %ld",
              aor_data->_cas);
  }
  else
  {
    SAS::Event event(trail, SASEvent::REGSTORE_GET_FAILURE, 0);
    event.add_var_param(aor_id);
    SAS::report_event(event);
  }

  return aor_data;
}

Store::Status SubscriberDataManager::Connector::set_aor_data(
                                                const std::string& aor_id,
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

  TRC_DEBUG("Data store set_data returned %d", status);

  if (status == Store::Status::OK)
  {
    SAS::Event event2(trail, SASEvent::REGSTORE_SET_SUCCESS, 0);
    event2.add_var_param(aor_id);
    SAS::report_event(event2);
  }
  else
  {
    SAS::Event event2(trail, SASEvent::REGSTORE_SET_FAILURE, 0);
    event2.add_var_param(aor_id);
    SAS::report_event(event2);
  }

  return status;
}

/// Serialize the contents of an AoR.
std::string SubscriberDataManager::Connector::serialize_aor(AoR* aor_data)
{
  return _serializer->serialize_aor(aor_data);
}

/// Deserialize the contents of an AoR
SubscriberDataManager::AoR* SubscriberDataManager::Connector::deserialize_aor(
                                                   const std::string& aor_id,
                                                   const std::string& s)
{
  AoR* aor = NULL;

  for(std::vector<SerializerDeserializer*>::iterator it = _deserializers.begin();
      it != _deserializers.end();
      ++it)
  {
    SerializerDeserializer* deserializer = *it;

    TRC_DEBUG("Try to deserialize record for %s with '%s' deserializer",
              aor_id.c_str(),
              deserializer->name().c_str());
    aor = deserializer->deserialize_aor(aor_id, s);

    if (aor != NULL)
    {
      TRC_DEBUG("Deserialization suceeded");
      return aor;
    }
    else
    {
      TRC_DEBUG("Deserialization failed");
    }
  }

  return aor;
}


/// AoR Methods

/// Default constructor.
SubscriberDataManager::AoR::AoR(std::string sip_uri) :
  _notify_cseq(1),
  _bindings(),
  _subscriptions(),
  _cas(0),
  _uri(sip_uri)
{
}


/// Destructor.
SubscriberDataManager::AoR::~AoR()
{
  clear(true);
}


/// Copy constructor.
SubscriberDataManager::AoR::AoR(const AoR& other)
{
  common_constructor(other);
}

// Make sure assignment is deep!
SubscriberDataManager::AoR& SubscriberDataManager::AoR::operator= (AoR const& other)
{
  if (this != &other)
  {
    clear(true);
    common_constructor(other);
  }

  return *this;
}

void SubscriberDataManager::AoR::common_constructor(const AoR& other)
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
  _uri = other._uri;
}


/// Clear all the bindings and subscriptions from this object.
void SubscriberDataManager::AoR::clear(bool clear_emergency_bindings)
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
SubscriberDataManager::AoR::Binding*
         SubscriberDataManager::AoR::get_binding(const std::string& binding_id)
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
void SubscriberDataManager::AoR::remove_binding(const std::string& binding_id)
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
SubscriberDataManager::AoR::Subscription*
       SubscriberDataManager::AoR::get_subscription(const std::string& to_tag)
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
void SubscriberDataManager::AoR::remove_subscription(const std::string& to_tag)
{
  AoR::Subscriptions::iterator i = _subscriptions.find(to_tag);
  if (i != _subscriptions.end())
  {
    delete i->second;
    _subscriptions.erase(i);
  }
}

// Generates the public GRUU for this binding from the address of record and
// instance-id. Returns NULL if this binding has no valid GRUU.
pjsip_sip_uri* SubscriberDataManager::AoR::Binding::pub_gruu(pj_pool_t* pool) const
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
std::string SubscriberDataManager::AoR::Binding::pub_gruu_str(pj_pool_t* pool) const
{
  pjsip_sip_uri* pub_gruu_uri = pub_gruu(pool);

  if (pub_gruu_uri == NULL)
  {
    return "";
  }

  return PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, (pjsip_uri*)pub_gruu_uri);
}

// Utility method to return the public GRUU surrounded by quotes.
// Returns "" if this binding has no GRUU.
std::string SubscriberDataManager::AoR::Binding::pub_gruu_quoted_string(pj_pool_t* pool) const
{
  std::string unquoted_pub_gruu = pub_gruu_str(pool);

  if (unquoted_pub_gruu.length() == 0)
  {
    return "";
  }

  std::string ret = "\"" + unquoted_pub_gruu + "\"";
  return ret;
}


//
// (De)serializer for the binary SubscriberDataManager format.
//

SubscriberDataManager::AoR* SubscriberDataManager::BinarySerializerDeserializer::
  deserialize_aor(const std::string& aor_id, const std::string& s)
{
  std::istringstream iss(s, std::istringstream::in|std::istringstream::binary);

  // First off, try to read the number of bindings.
  int num_bindings;
  iss.read((char*)&num_bindings, sizeof(int));

  if (iss.eof())
  {
    // Hit an EOF which means the record is corrupt.
    TRC_INFO("Could not deserialize AOR - EOF reached");
    return NULL;
  }

  if (num_bindings > 0xffffff)
  {
    // That's a lot of bindings. It is more likely that the data is corrupt, or
    // that we have been passed a record in a different format.
    TRC_INFO("Could not deserialize AOR. Got %d bindings suggesting the data"
             " is corrupt or not in the binary format",
             num_bindings);
    return NULL;
  }

  AoR* aor_data = new AoR(aor_id);

  TRC_DEBUG("Deserialize %d bindings", num_bindings);

  for (int ii = 0; ii < num_bindings; ++ii)
  {
    // Extract the binding identifier into a string.
    std::string binding_id;
    getline(iss, binding_id, '\0');
    TRC_DEBUG("  Binding %s", binding_id.c_str());

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
    TRC_DEBUG("Deserialize %d path headers", num_paths);
    for (std::list<std::string>::iterator i = b->_path_headers.begin();
         i != b->_path_headers.end();
         ++i)
    {
      getline(iss, *i, '\0');
      TRC_DEBUG("  Deserialized path header %s", i->c_str());
    }
    getline(iss, b->_timer_id, '\0');
    getline(iss, b->_private_id, '\0');
    iss.read((char *)&b->_emergency_registration, sizeof(int));
  }

  int num_subscriptions;
  iss.read((char *)&num_subscriptions, sizeof(int));
  TRC_DEBUG("Deserialize %d subscriptions", num_subscriptions);

  for (int ii = 0; ii < num_subscriptions; ++ii)
  {
    // Extract the to tag index into a string.
    std::string to_tag;
    getline(iss, to_tag, '\0');
    TRC_DEBUG("  Subscription %s", to_tag.c_str());

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
    TRC_DEBUG("    number of routes = %d", num_routes);
    s->_route_uris.resize(num_routes);
    for (std::list<std::string>::iterator i = s->_route_uris.begin();
         i != s->_route_uris.end();
         ++i)
    {
      getline(iss, *i, '\0');
    }

    iss.read((char *)&s->_expires, sizeof(int));
    getline(iss, s->_timer_id, '\0');
  }

  iss.read((char*)&aor_data->_notify_cseq, sizeof(int));

  return aor_data;
}


std::string SubscriberDataManager::BinarySerializerDeserializer::serialize_aor(AoR* aor_data)
{
  std::ostringstream oss(std::ostringstream::out|std::ostringstream::binary);

  int num_bindings = aor_data->bindings().size();
  TRC_DEBUG("Serialize %d bindings", num_bindings);
  oss.write((const char *)&num_bindings, sizeof(int));

  for (AoR::Bindings::const_iterator i = aor_data->bindings().begin();
       i != aor_data->bindings().end();
       ++i)
  {
    TRC_DEBUG("  Binding %s", i->first.c_str());
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
  TRC_DEBUG("Serialize %d subscriptions", num_subscriptions);
  oss.write((const char *)&num_subscriptions, sizeof(int));

  for (AoR::Subscriptions::const_iterator i = aor_data->subscriptions().begin();
       i != aor_data->subscriptions().end();
       ++i)
  {
    TRC_DEBUG("  Subscription %s", i->first.c_str());
    oss << i->first << '\0';

    AoR::Subscription* s = i->second;
    oss << s->_req_uri << '\0';
    oss << s->_from_uri << '\0';
    oss << s->_from_tag << '\0';
    oss << s->_to_uri << '\0';
    oss << s->_to_tag << '\0';
    oss << s->_cid << '\0';
    int num_routes = s->_route_uris.size();
    TRC_DEBUG("    number of routes = %d", num_routes);
    oss.write((const char *)&num_routes, sizeof(int));
    for (std::list<std::string>::const_iterator i = s->_route_uris.begin();
         i != s->_route_uris.end();
         ++i)
    {
      oss << *i << '\0';
    }
    oss.write((const char *)&s->_expires, sizeof(int));
    oss << s->_timer_id << '\0';
  }

  oss.write((const char *)&aor_data->_notify_cseq, sizeof(int));

  return oss.str();
}

std::string SubscriberDataManager::BinarySerializerDeserializer::name()
{
  return "binary";
}


//
// (De)serializer for the JSON SubscriberDataManager format.
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


SubscriberDataManager::AoR* SubscriberDataManager::JsonSerializerDeserializer::
  deserialize_aor(const std::string& aor_id, const std::string& s)
{
  TRC_DEBUG("Deserialize JSON document: %s", s.c_str());

  rapidjson::Document doc;
  doc.Parse<0>(s.c_str());

  if (doc.HasParseError())
  {
    TRC_DEBUG("Failed to parse document: %s\nError: %s",
              s.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    return NULL;
  }

  AoR* aor = new AoR(aor_id);

  try
  {
    JSON_ASSERT_CONTAINS(doc, JSON_BINDINGS);
    JSON_ASSERT_OBJECT(doc[JSON_BINDINGS]);
    const rapidjson::Value& bindings_obj = doc[JSON_BINDINGS];

    for (rapidjson::Value::ConstMemberIterator bindings_it = bindings_obj.MemberBegin();
         bindings_it != bindings_obj.MemberEnd();
         ++bindings_it)
    {
      TRC_DEBUG("  Binding: %s", bindings_it->name.GetString());
      AoR::Binding* b = aor->get_binding(bindings_it->name.GetString());

      JSON_ASSERT_OBJECT(bindings_it->value);
      const rapidjson::Value& b_obj = bindings_it->value;

      JSON_GET_STRING_MEMBER(b_obj, JSON_URI, b->_uri);
      JSON_GET_STRING_MEMBER(b_obj, JSON_CID, b->_cid);
      JSON_GET_INT_MEMBER(b_obj, JSON_CSEQ, b->_cseq);
      JSON_GET_INT_MEMBER(b_obj, JSON_EXPIRES, b->_expires);
      JSON_GET_INT_MEMBER(b_obj, JSON_PRIORITY, b->_priority);

      JSON_ASSERT_CONTAINS(b_obj, JSON_PARAMS);
      JSON_ASSERT_OBJECT(b_obj[JSON_PARAMS]);
      const rapidjson::Value& params_obj = b_obj[JSON_PARAMS];

      for (rapidjson::Value::ConstMemberIterator params_it = params_obj.MemberBegin();
           params_it != params_obj.MemberEnd();
           ++params_it)
      {
        JSON_ASSERT_STRING(params_it->value);
        b->_params[params_it->name.GetString()] = params_it->value.GetString();
      }

      JSON_ASSERT_CONTAINS(b_obj, JSON_PATHS);
      JSON_ASSERT_ARRAY(b_obj[JSON_PATHS]);
      const rapidjson::Value& paths_arr = b_obj[JSON_PATHS];

      for (rapidjson::Value::ConstValueIterator paths_it = paths_arr.Begin();
           paths_it != paths_arr.End();
           ++paths_it)
      {
        JSON_ASSERT_STRING(*paths_it);
        b->_path_headers.push_back(paths_it->GetString());
      }

      JSON_GET_STRING_MEMBER(b_obj, JSON_TIMER_ID, b->_timer_id);
      JSON_GET_STRING_MEMBER(b_obj, JSON_PRIVATE_ID, b->_private_id);
      JSON_GET_BOOL_MEMBER(b_obj, JSON_EMERGENCY_REG, b->_emergency_registration);
    }

    JSON_ASSERT_CONTAINS(doc, JSON_SUBSCRIPTIONS);
    JSON_ASSERT_OBJECT(doc[JSON_SUBSCRIPTIONS]);
    const rapidjson::Value& subscriptions_obj = doc[JSON_SUBSCRIPTIONS];

    for (rapidjson::Value::ConstMemberIterator subscriptions_it = subscriptions_obj.MemberBegin();
         subscriptions_it != subscriptions_obj.MemberEnd();
         ++subscriptions_it)
    {
      TRC_DEBUG("  Subscription: %s", subscriptions_it->name.GetString());
      AoR::Subscription* s = aor->get_subscription(subscriptions_it->name.GetString());

      JSON_ASSERT_OBJECT(subscriptions_it->value);
      const rapidjson::Value& s_obj = subscriptions_it->value;

      JSON_GET_STRING_MEMBER(s_obj, JSON_REQ_URI, s->_req_uri);
      JSON_GET_STRING_MEMBER(s_obj, JSON_FROM_URI, s->_from_uri);
      JSON_GET_STRING_MEMBER(s_obj, JSON_FROM_TAG, s->_from_tag);
      JSON_GET_STRING_MEMBER(s_obj, JSON_TO_URI, s->_to_uri);
      JSON_GET_STRING_MEMBER(s_obj, JSON_TO_TAG, s->_to_tag);
      JSON_GET_STRING_MEMBER(s_obj, JSON_CID, s->_cid);

      JSON_ASSERT_CONTAINS(s_obj, JSON_ROUTES);
      JSON_ASSERT_ARRAY(s_obj[JSON_ROUTES]);
      const rapidjson::Value& routes_arr = s_obj[JSON_ROUTES];

      for (rapidjson::Value::ConstValueIterator routes_it = routes_arr.Begin();
           routes_it != routes_arr.End();
           ++routes_it)
      {
        JSON_ASSERT_STRING(*routes_it);
        s->_route_uris.push_back(routes_it->GetString());
      }

      JSON_GET_INT_MEMBER(s_obj, JSON_EXPIRES, s->_expires);
      s->_timer_id =
         ((s_obj.HasMember(JSON_TIMER_ID)) && ((s_obj[JSON_TIMER_ID]).IsString()) ?
                                               (s_obj[JSON_TIMER_ID].GetString()) :
                                                "");
    }

    JSON_GET_INT_MEMBER(doc, JSON_NOTIFY_CSEQ, aor->_notify_cseq);
  }
  catch(JsonFormatError err)
  {
    TRC_INFO("Failed to deserialize JSON document (hit error at %s:%d)",
             err._file, err._line);
    delete aor; aor = NULL;
  }

  return aor;
}


std::string SubscriberDataManager::JsonSerializerDeserializer::serialize_aor(AoR* aor_data)
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
          writer.String(JSON_TIMER_ID); writer.String(s->_timer_id.c_str());

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

std::string SubscriberDataManager::JsonSerializerDeserializer::name()
{
  return "JSON";
}

/// ChronosTimerRequestSender Methods

SubscriberDataManager::ChronosTimerRequestSender::
     ChronosTimerRequestSender(ChronosConnection* chronos_conn) :
  _chronos_conn(chronos_conn)
{
}

SubscriberDataManager::ChronosTimerRequestSender::~ChronosTimerRequestSender()
{
}

void SubscriberDataManager::ChronosTimerRequestSender::send_timers(
                             const std::string& aor_id,
                             AoRPair* aor_pair,
                             int now,
                             SAS::TrailId trail)
{
  send_binding_timers(aor_id, aor_pair, now, trail);
  send_subscription_timers(aor_id, aor_pair, now, trail);
}

void SubscriberDataManager::ChronosTimerRequestSender::set_timer(
                                    const std::string& aor_id,
                                    std::string object_id,
                                    std::string& timer_id,
                                    int expiry,
                                    std::string id_type,
                                    std::vector<std::string> tags,
                                    SAS::TrailId trail)
{
  std::string temp_timer_id = "";
  HTTPCode status;
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\", \"" +
                              id_type + "\": \""+ object_id +"\"}";
  std::string callback_uri = "/timers";

  // If a timer has been previously set for this binding, send a PUT.
  // Otherwise sent a POST.
  if (timer_id == "")
  {
    status = _chronos_conn->send_post(temp_timer_id,
                                      expiry,
                                      callback_uri,
                                      opaque,
                                      trail,
                                      tags);
  }
  else
  {
    temp_timer_id = timer_id;
    status = _chronos_conn->send_put(temp_timer_id,
                                     expiry,
                                     callback_uri,
                                     opaque,
                                     trail,
                                     tags);
  }

  // Update the timer id. If the update to Chronos failed, that's OK,
  // don't reject the request or update the stored timer id.
  if (status == HTTP_OK)
  {
    timer_id = temp_timer_id;
  }
}

void SubscriberDataManager::ChronosTimerRequestSender::send_binding_timers(
                                const std::string& aor_id,
                                SubscriberDataManager::AoRPair* aor_pair,
                                int now,
                                SAS::TrailId trail)
{
  // Iterate over the bindings in the original AoR, and process any
  // that aren't in the current AoR
  for (SubscriberDataManager::AoR::Bindings::const_iterator aor_orig =
         aor_pair->get_orig()->bindings().begin();
       aor_orig != aor_pair->get_orig()->bindings().end();
       ++aor_orig)
  {
    SubscriberDataManager::AoR::Binding* b = aor_orig->second;
    std::string b_id = aor_orig->first;

    // Is this binding present in the new AoR?
    SubscriberDataManager::AoR::Bindings::const_iterator aor_current =
      aor_pair->get_current()->bindings().find(b_id);

    if (aor_current == aor_pair->get_current()->bindings().end())
    {
      // The binding has been deleted. If a timer id is present,
      // then delete it (it can be empty because a previous post/put failed).
      if (b->_timer_id != "")
      {
        _chronos_conn->send_delete(b->_timer_id, trail);
      }
    }
  }

  for (SubscriberDataManager::AoR::Bindings::const_iterator aor_current =
         aor_pair->get_current()->bindings().begin();
       aor_current != aor_pair->get_current()->bindings().end();
       ++aor_current)
  {
    SubscriberDataManager::AoR::Binding* b = aor_current->second;
    std::string b_id = aor_current->first;

    // Was the binding present in the original AoR?
    SubscriberDataManager::AoR::Bindings::const_iterator aor_orig =
      aor_pair->get_orig()->bindings().find(b_id);

    // Set a timer if the binding is new, if a previous attempt to
    // set a timer failed, or if the expiry time has changed
    if ((aor_orig == aor_pair->get_orig()->bindings().end()) ||
        (b->_timer_id == "") ||
        (b->_expires != aor_orig->second->_expires))
    {
      // It must be a new binding - set a timer
      set_timer(aor_id,
                b_id,
                b->_timer_id,
                b->_expires - now,
                "binding_id",
                SubscriberDataManager::TAGS_REG,
                trail);
    }
  }
}

void SubscriberDataManager::ChronosTimerRequestSender::send_subscription_timers(
                               const std::string& aor_id,
                               SubscriberDataManager::AoRPair* aor_pair,
                               int now,
                               SAS::TrailId trail)
{
  // Iterate over the subscription in the original AoR, and process any
  // that aren't in the current AoR
  for (SubscriberDataManager::AoR::Subscriptions::const_iterator aor_orig =
         aor_pair->get_orig()->subscriptions().begin();
       aor_orig != aor_pair->get_orig()->subscriptions().end();
       ++aor_orig)
  {
    SubscriberDataManager::AoR::Subscription* s = aor_orig->second;
    std::string s_id = aor_orig->first;

    // Is this subscription present in the new AoR?
    SubscriberDataManager::AoR::Subscriptions::const_iterator aor_current =
      aor_pair->get_current()->subscriptions().find(s_id);

    if (aor_current == aor_pair->get_current()->subscriptions().end())
    {
      // The subscription has been deleted. If a timer id is present,
      // then delete it (it can be empty because a previous post/put failed).
      if (s->_timer_id != "")
      {
        _chronos_conn->send_delete(s->_timer_id, trail);
      }
    }
  }

  for (SubscriberDataManager::AoR::Subscriptions::const_iterator aor_current =
         aor_pair->get_current()->subscriptions().begin();
       aor_current != aor_pair->get_current()->subscriptions().end();
       ++aor_current)
  {
    SubscriberDataManager::AoR::Subscription* s = aor_current->second;
    std::string s_id = aor_current->first;

    // Was the subscription present in the original AoR?
    SubscriberDataManager::AoR::Subscriptions::const_iterator aor_orig =
      aor_pair->get_orig()->subscriptions().find(s_id);

    // Set a timer if the subscription is new, if a previous attempt to
    // set a timer failed, or if the expiry time has changed
    if ((aor_orig == aor_pair->get_orig()->subscriptions().end()) ||
        (s->_timer_id == "") ||
        (s->_expires != aor_orig->second->_expires))
    {
      // It must be a new subscription - set a timer
      set_timer(aor_id,
                s_id,
                s->_timer_id,
                s->_expires - now,
                "subscription_id",
                SubscriberDataManager::TAGS_SUB,
                trail);
    }
  }
}

/// NotifySender Methods

SubscriberDataManager::NotifySender::NotifySender()
{
}

SubscriberDataManager::NotifySender::~NotifySender()
{
}

void SubscriberDataManager::NotifySender::send_notifys(
                               const std::string& aor_id,
                               SubscriberDataManager::AoRPair* aor_pair,
                               int now,
                               SAS::TrailId trail)
{
  // Iterate over the subscriptions in the original AoR, and send NOTIFYs for
  // any subscriptions that aren't in the current AoR
  send_notifys_for_expired_subscriptions(aor_id, aor_pair, now, trail);

  // Iterate over the subscriptions in the current AoR and send NOTIFYs
  send_notifys_for_current_subscriptions(aor_id, aor_pair, now, trail);
}

void SubscriberDataManager::NotifySender::send_notifys_for_expired_subscriptions(
                               const std::string& aor_id,
                               SubscriberDataManager::AoRPair* aor_pair,
                               int now,
                               SAS::TrailId trail)
{
  // Work out which bindings have expired - we no longer have a valid connection to these endpoints,
  // so shouldn't send a NOTIFY to them (even to say that their subscription is terminated).
  //
  // Note that we can't just check whether a binding exists before sending a NOTIFY - a SUBSCRIBE
  // may have come from a P-CSCF or AS, which wouldn't match a binding.
  std::vector<std::string> expired_bindings;

  for (SubscriberDataManager::AoR::Bindings::const_iterator aor_orig =
         aor_pair->get_orig()->bindings().begin();
       aor_orig != aor_pair->get_orig()->bindings().end();
       ++aor_orig)
  {
    SubscriberDataManager::AoR::Binding* b = aor_orig->second;
    std::string b_id = aor_orig->first;

    // Compare the original and current lists to see whether this binding has expired.
    if (aor_pair->get_current()->bindings().find(b_id) == aor_pair->get_current()->bindings().end())
    {
      expired_bindings.push_back(b->_uri);
    }
  }

  // Iterate over the subscriptions in the original AoR, and send NOTIFYs for
  // any subscriptions that aren't in the current AoR
  for (SubscriberDataManager::AoR::Subscriptions::const_iterator aor_orig_s =
         aor_pair->get_orig()->subscriptions().begin();
       aor_orig_s != aor_pair->get_orig()->subscriptions().end();
       ++aor_orig_s)
  {
    SubscriberDataManager::AoR::Subscription* s = aor_orig_s->second;
    std::string s_id = aor_orig_s->first;

    if (std::find(expired_bindings.begin(), expired_bindings.end(), s->_req_uri) != expired_bindings.end())
    {
      // This NOTIFY would go to a binding which no longer exists - skip it.
      continue;
    }

    // Is this subscription present in the new AoR?
    SubscriberDataManager::AoR::Subscriptions::const_iterator aor_current =
      aor_pair->get_current()->subscriptions().find(s_id);

    // The subscription has been deleted. We should send a final NOTIFY
    // about the state of the bindings in the original AoR
    if (aor_current == aor_pair->get_current()->subscriptions().end())
    {
      TRC_DEBUG("The subscription (%s) has been terminated", s_id.c_str());

      NotifyUtils::ContactEvent contact_event;
      NotifyUtils::RegistrationState reg_state;

      // There are no non-emergency bindings left; the subscription has been
      // terminated.
      bool bindings_remaining = false;
      for (SubscriberDataManager::AoR::Bindings::const_iterator aor_current_b =
             aor_pair->get_current()->bindings().begin();
           aor_current_b != aor_pair->get_current()->bindings().end();
           ++aor_current_b)
      {
        if (!aor_current_b->second->_emergency_registration)
        {
          bindings_remaining = true;
          break;
        }
      }

      if (bindings_remaining)
      {
        contact_event = NotifyUtils::ContactEvent::REGISTERED;
        reg_state = NotifyUtils::RegistrationState::ACTIVE;
      }
      else
      {
        contact_event = NotifyUtils::ContactEvent::EXPIRED;
        reg_state = NotifyUtils::RegistrationState::TERMINATED;
      }

      std::vector<NotifyUtils::BindingNotifyInformation*> binding_notify;

      for (SubscriberDataManager::AoR::Bindings::const_iterator aor_orig_b =
             aor_pair->get_orig()->bindings().begin();
           aor_orig_b != aor_pair->get_orig()->bindings().end();
           ++aor_orig_b)
      {
        // Don't include emergency registrations
        if (!aor_orig_b->second->_emergency_registration)
        {
          NotifyUtils::BindingNotifyInformation* bni =
               new NotifyUtils::BindingNotifyInformation(aor_orig_b->first,
                                                         aor_orig_b->second,
                                                         contact_event);
          binding_notify.push_back(bni);
        }
      }

      pjsip_tx_data* tdata_notify = NULL;

      // This is a terminated subscription - set the expiry time to now
      s->_expires = now;
      pj_status_t status = NotifyUtils::create_subscription_notify(
                                          &tdata_notify,
                                          s,
                                          aor_id,
                                          aor_pair->get_orig(),
                                          binding_notify,
                                          reg_state,
                                          now);

      if (status == PJ_SUCCESS)
      {
        set_trail(tdata_notify, trail);
        status = PJUtils::send_request(tdata_notify, 0, NULL, NULL, true);

        if (status != PJ_SUCCESS)
        {
          // LCOV_EXCL_START
          SAS::Event event(trail, SASEvent::NOTIFICATION_FAILED, 0);
          std::string error_msg = "Failed to send NOTIFY - error: " +
                                       PJUtils::pj_status_to_string(status);
          event.add_var_param(error_msg);
          SAS::report_event(event);
         // LCOV_EXCL_STOP
        }
      }

      for (std::vector<NotifyUtils::BindingNotifyInformation*>::iterator it =
             binding_notify.begin();
           it != binding_notify.end();
           ++it)
      {
        delete *it;
      }
    }
  }
}

void SubscriberDataManager::NotifySender::send_notifys_for_current_subscriptions(
                               const std::string& aor_id,
                               SubscriberDataManager::AoRPair* aor_pair,
                               int now,
                               SAS::TrailId trail)
{
  // Iterate over the subscriptions in the current AoR.
  for (SubscriberDataManager::AoR::Subscriptions::const_iterator aor_current =
         aor_pair->get_current()->subscriptions().begin();
       aor_current != aor_pair->get_current()->subscriptions().end();
       ++aor_current)
  {
    TRC_DEBUG("The subscription (%s) is still active", aor_current->first.c_str());
    std::vector<NotifyUtils::BindingNotifyInformation*> binding_notify;

    // Iterate over the bindings in the original AoR. If they're not present
    // the current AoR, mark them as expired
    for (SubscriberDataManager::AoR::Bindings::const_iterator aor_orig_b =
           aor_pair->get_orig()->bindings().begin();
         aor_orig_b != aor_pair->get_orig()->bindings().end();
         ++aor_orig_b)
    {
      if (!aor_orig_b->second->_emergency_registration)
      {
        SubscriberDataManager::AoR::Bindings::const_iterator aor_current =
          aor_pair->get_current()->bindings().find(aor_orig_b->first);

        if (aor_current == aor_pair->get_current()->bindings().end())
        {
          TRC_DEBUG("Binding %s has been removed", aor_orig_b->first.c_str());
          NotifyUtils::BindingNotifyInformation* bni =
             new NotifyUtils::BindingNotifyInformation(
                                              aor_orig_b->first,
                                              aor_orig_b->second,
                                              NotifyUtils::ContactEvent::EXPIRED);
          binding_notify.push_back(bni);
        }
      }
    }

    // Iterate over the bindings in the current AoR.
    for (SubscriberDataManager::AoR::Bindings::const_iterator aor_current_b =
           aor_pair->get_current()->bindings().begin();
         aor_current_b != aor_pair->get_current()->bindings().end();
         ++aor_current_b)
    {
      if (!aor_current_b->second->_emergency_registration)
      {
        // If the binding is only in the current AoR, mark it as created
        SubscriberDataManager::AoR::Bindings::const_iterator aor_orig_b =
          aor_pair->get_orig()->bindings().find(aor_current_b->first);

        if (aor_orig_b == aor_pair->get_orig()->bindings().end())
        {
          TRC_DEBUG("Binding %s has been created", aor_current_b->first.c_str());
          NotifyUtils::BindingNotifyInformation* bni =
              new NotifyUtils::BindingNotifyInformation(aor_current_b->first,
                                                   aor_current_b->second,
                                                   NotifyUtils::ContactEvent::CREATED);
          binding_notify.push_back(bni);
        }
        else
        {
          // The binding is in both AoRs. Check if the expiry time has changed at all
          NotifyUtils::ContactEvent event;

          if (aor_orig_b->second->_expires < aor_current_b->second->_expires)
          {
            TRC_DEBUG("Binding %s has been refreshed", aor_current_b->first.c_str());
            event = NotifyUtils::ContactEvent::REFRESHED;
          }
          else if (aor_orig_b->second->_expires > aor_current_b->second->_expires)
          {
            TRC_DEBUG("Binding %s has been shortened", aor_current_b->first.c_str());
            event = NotifyUtils::ContactEvent::SHORTENED;
          }
          else
          {
            TRC_DEBUG("Binding %s is unchanged", aor_current_b->first.c_str());
            event = NotifyUtils::ContactEvent::REGISTERED;
          }


          NotifyUtils::BindingNotifyInformation* bni =
             new NotifyUtils::BindingNotifyInformation(aor_current_b->first,
                                                       aor_current_b->second,
                                                       event);
          binding_notify.push_back(bni);
        }
      }
    }

    pjsip_tx_data* tdata_notify = NULL;
    pj_status_t status = NotifyUtils::create_subscription_notify(
                                          &tdata_notify,
                                          aor_current->second,
                                          aor_id,
                                          aor_pair->get_orig(),
                                          binding_notify,
                                          NotifyUtils::RegistrationState::ACTIVE,
                                          now);

    if (status == PJ_SUCCESS)
    {
      set_trail(tdata_notify, trail);
      status = PJUtils::send_request(tdata_notify, 0, NULL, NULL, true);

      if (status != PJ_SUCCESS)
      {
        // LCOV_EXCL_START
        SAS::Event event(trail, SASEvent::NOTIFICATION_FAILED, 0);
        std::string error_msg = "Failed to send NOTIFY - error: " +
                                       PJUtils::pj_status_to_string(status);
        event.add_var_param(error_msg);
        SAS::report_event(event);
       // LCOV_EXCL_STOP
      }
    }

    for (std::vector<NotifyUtils::BindingNotifyInformation*>::iterator it =
           binding_notify.begin();
         it != binding_notify.end();
         ++it)
    {
      delete *it;
    }
  }
}
