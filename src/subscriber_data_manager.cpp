/**
 * @file subscriber_data_manager.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

/// JSON serialization constants.
static const char* const JSON_BINDINGS = "bindings";
static const char* const JSON_URI = "uri";
static const char* const JSON_CID = "cid";
static const char* const JSON_CSEQ = "cseq";
static const char* const JSON_EXPIRES = "expires";
static const char* const JSON_PRIORITY = "priority";
static const char* const JSON_PARAMS = "params";
static const char* const JSON_PATHS = "paths"; // Depracated as of PC release 119.
static const char* const JSON_PATH_HEADERS = "path_headers";
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
static const char* const JSON_SCSCF_URI = "scscf-uri";

/// Helper to delete vectors of bindings safely
void delete_bindings(ClassifiedBindings& cbs)
{
  for (ClassifiedBinding* cb : cbs)
  {
    delete cb;
  }

  cbs.clear();
}

/// SubscriberDataManager Methods
SubscriberDataManager::SubscriberDataManager(Store* data_store,
                                             ChronosConnection* chronos_connection,
                                             AnalyticsLogger* analytics_logger,
                                             bool is_primary) :
  _primary_sdm(is_primary)
{
  JsonSerializerDeserializer* serializer = new JsonSerializerDeserializer();
  std::vector<JsonSerializerDeserializer*> deserializers = { new JsonSerializerDeserializer() };

  _connector = new Connector(data_store, serializer, deserializers);
  _chronos_timer_request_sender = new ChronosTimerRequestSender(chronos_connection);
  _notify_sender = new NotifySender();
  _analytics = analytics_logger;
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
    expire_aor_members(aor_pair, now, trail);
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
/// @param associated_uris
///                   The associated IMPUs in the Implicit Registration Set for the AoR
/// @param aor_pair   The registration data record.
/// @param trail      The SAS trail
bool SubscriberDataManager::unused_bool = false;

Store::Status SubscriberDataManager::set_aor_data(
                                     const std::string& aor_id,
                                     AssociatedURIs* associated_uris,
                                     AoRPair* aor_pair,
                                     SAS::TrailId trail,
                                     bool& all_bindings_expired)
{
  // The ordering of this function is quite important.
  //
  // 1. Expire any old bindings/subscriptions.
  // 2. Log removed or shortened bindings
  // 3. Send any Chronos timer requests
  // 4. Write the data to memcached. If this fails, bail out here
  // 5. Log new or extended bindings
  // 6. Send any messages we were asked to by the caller
  // 7. Send any NOTIFYs
  //
  // This ordering is important to ensure that we don't send
  // duplicate NOTIFYs (so we send these after writing to memcached) and
  // so that only one piece of code has responsibility for this. Furthermore,
  // we want registration logs used for licensing counts to undercount in edge
  // cases where a Chronos or memcached call fails and we're in an uncertain
  // state. Therefore, we log removed or shortened bindings before any such calls,
  // and we log new or extended bindings afterwards.

  // 1. Expire any old bindings/subscriptions.
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
  int orig_max_expires = expire_aor_members(aor_pair, now, trail);
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

  ClassifiedBindings classified_bindings;

  if (_primary_sdm)
  {
    // 2. Log removed or shortened bindings
    classify_bindings(aor_id, aor_pair, classified_bindings);

    if (_analytics != NULL)
    {
      log_removed_or_shortened_bindings(classified_bindings, now);
    }

    // 3. Send any Chronos timer requests
    _chronos_timer_request_sender->send_timers(aor_id, aor_pair, now, trail);
  }

  // 4. Write the data to memcached. If this fails, bail out here

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
    delete_bindings(classified_bindings);
    return rc;
  }

  if (_primary_sdm)
  {
    // 5. Log new / extended bindings
    if (_analytics != NULL)
    {
      log_new_or_extended_bindings(classified_bindings, now);
    }

    // 6. Send any NOTIFYs
    _notify_sender->send_notifys(aor_id, associated_uris, aor_pair, now, trail);
  }

  delete_bindings(classified_bindings);

  return Store::Status::OK;
}

void SubscriberDataManager::classify_bindings(const std::string& aor_id,
                                              SubscriberDataManager::AoRPair* aor_pair,
                                              ClassifiedBindings& classified_bindings)
{
  // We should have been given an empty classified_bindings vector, but clear
  // it just in case
  delete_bindings(classified_bindings);

  // 1/2: Iterate over original bindings and record those not in current AoR
  for (std::pair<std::string, SubscriberDataManager::AoR::Binding*> aor_orig_b :
         aor_pair->get_orig()->bindings())
  {
    if (aor_pair->get_current()->bindings().find(aor_orig_b.first) ==
        aor_pair->get_current()->bindings().end())
    {
      // Binding is gone (which may mean deregistration or expiry)
      ClassifiedBinding* binding_record =
        new ClassifiedBinding(aor_orig_b.first,
                              aor_orig_b.second,
                              NotifyUtils::ContactEvent::EXPIRED);
      classified_bindings.push_back(binding_record);
    }
  }

  // 2/2: Iterate over the bindings in the current AoR.
  for (std::pair<std::string, SubscriberDataManager::AoR::Binding*> aor_current_b :
         aor_pair->get_current()->bindings())
  {
    SubscriberDataManager::AoR::Bindings::const_iterator aor_orig_b_match =
      aor_pair->get_orig()->bindings().find(aor_current_b.first);

    NotifyUtils::ContactEvent event;

    if (aor_orig_b_match == aor_pair->get_orig()->bindings().end())
    {
      // Binding is new
      event = NotifyUtils::ContactEvent::CREATED;
    }
    else
    {
      // The binding is in both AoRs. Check if the expiry time has changed at all
      if (aor_orig_b_match->second->_expires < aor_current_b.second->_expires)
      {
        // Binding has been refreshed
        event = NotifyUtils::ContactEvent::REFRESHED;
      }
      else if (aor_orig_b_match->second->_expires > aor_current_b.second->_expires)
      {
        // Binding has been shortened
        event = NotifyUtils::ContactEvent::SHORTENED;
      }
      else
      {
        // Binding unchanged
        event = NotifyUtils::ContactEvent::REGISTERED;
      }
    }

    ClassifiedBinding* binding_record =
      new ClassifiedBinding(aor_current_b.first,
                            aor_current_b.second,
                            event);
    classified_bindings.push_back(binding_record);
  }
}

void SubscriberDataManager::log_removed_or_shortened_bindings(ClassifiedBindings& classified_bindings,
                                                              int now)
{
  for (ClassifiedBinding* classified_binding : classified_bindings)
  {
    if (classified_binding->_contact_event == NotifyUtils::ContactEvent::EXPIRED)
    {
      _analytics->registration(classified_binding->_b->_address_of_record,
                               classified_binding->_id,
                               classified_binding->_b->_uri,
                               0);
    }
    else if (classified_binding->_contact_event == NotifyUtils::ContactEvent::SHORTENED)
    {
      _analytics->registration(classified_binding->_b->_address_of_record,
                               classified_binding->_id,
                               classified_binding->_b->_uri,
                               classified_binding->_b->_expires - now);
    }
  }
}

void SubscriberDataManager::log_new_or_extended_bindings(ClassifiedBindings& classified_bindings,
                                                         int now)
{
  for (ClassifiedBinding* classified_binding : classified_bindings)
  {
    if (classified_binding->_contact_event == NotifyUtils::ContactEvent::CREATED ||
        classified_binding->_contact_event == NotifyUtils::ContactEvent::REFRESHED)
    {
      _analytics->registration(classified_binding->_b->_address_of_record,
                               classified_binding->_id,
                               classified_binding->_b->_uri,
                               classified_binding->_b->_expires - now);
    }
  }
}

int SubscriberDataManager::expire_aor_members(AoRPair* aor_pair,
                                              int now,
                                              SAS::TrailId trail)
{
  int max_expires = expire_bindings(aor_pair->get_current(), now, trail);

  // N.B. Subscriptions are not factored into the returned expiry time on the
  // store record because, according to 5.4.2.1.2/TS 24.229, all subscriptions
  // automatically expire when the last binding expires.
  expire_subscriptions(aor_pair, now, (max_expires == now), trail);

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
                                                 bool force_expire,
                                                 SAS::TrailId trail)
{
  for (AoR::Subscriptions::iterator i =
         aor_pair->get_current()->_subscriptions.begin();
       i != aor_pair->get_current()->_subscriptions.end();
      )
  {
    AoR::Subscription* s = i->second;

    if ((force_expire) || (s->_expires <= now))
    {
      if (trail != 0)
      {
        SAS::Event event(trail, SASEvent::REGSTORE_SUBSCRIPTION_EXPIRED, 0);
        event.add_var_param(s->_from_uri);
        event.add_static_param(force_expire);
        event.add_static_param(s->_expires);
        event.add_static_param(now);
        SAS::report_event(event);
      }
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
/// @param trail         SAS trail
int SubscriberDataManager::expire_bindings(AoR* aor_data,
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
      if (trail != 0)
      {
        SAS::Event event(trail, SASEvent::REGSTORE_BINDING_EXPIRED, 0);
        event.add_var_param(b->_address_of_record);
        event.add_var_param(b->_uri);
        event.add_var_param(b->_cid);
        event.add_static_param(b->_expires);
        event.add_static_param(now);
        SAS::report_event(event);
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

/// SubscriberDataManager::Connector Methods

SubscriberDataManager::Connector::Connector(Store* data_store,
                               JsonSerializerDeserializer*& serializer,
                               std::vector<JsonSerializerDeserializer*>& deserializers) :
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

  for (JsonSerializerDeserializer* ds : _deserializers)
  {
    delete ds; ds = NULL;
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

  for (JsonSerializerDeserializer* deserializer : _deserializers)
  {
    TRC_DEBUG("Try to deserialize record for %s with JSON deserializer",
              aor_id.c_str());
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
  _timer_id(""),
  _scscf_uri(""),
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
  _timer_id = other._timer_id;
  _cas = other._cas;
  _uri = other._uri;
  _scscf_uri = other._scscf_uri;
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
    b = new Binding(_uri);
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

/// Remove all the bindings from an AOR object
void SubscriberDataManager::AoR::clear_bindings()
{
  for (Bindings::const_iterator i = _bindings.begin();
       i != _bindings.end();
       ++i)
  {
    delete i->second;
  }

  // Clear the bindings map.
  _bindings.clear();
}

// Generates the public GRUU for this binding from the address of record and
// instance-id. Returns NULL if this binding has no valid GRUU.
pjsip_sip_uri* SubscriberDataManager::AoR::Binding::pub_gruu(pj_pool_t* pool) const
{
  pjsip_sip_uri* uri = (pjsip_sip_uri*)PJUtils::uri_from_string(_address_of_record, pool);

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

void SubscriberDataManager::AoR::Binding::
  to_json(rapidjson::Writer<rapidjson::StringBuffer>& writer) const
{
  writer.StartObject();
  {
    writer.String(JSON_URI); writer.String(_uri.c_str());
    writer.String(JSON_CID); writer.String(_cid.c_str());
    writer.String(JSON_CSEQ); writer.Int(_cseq);
    writer.String(JSON_EXPIRES); writer.Int(_expires);
    writer.String(JSON_PRIORITY); writer.Int(_priority);

    writer.String(JSON_PARAMS);
    writer.StartObject();
    {
      for (std::map<std::string, std::string>::const_iterator p = _params.begin();
           p != _params.end();
           ++p)
      {
        writer.String(p->first.c_str()); writer.String(p->second.c_str());
      }
    }
    writer.EndObject();

    writer.String(JSON_PATH_HEADERS);
    writer.StartArray();
    {
      for (std::list<std::string>::const_iterator p = _path_headers.begin();
           p != _path_headers.end();
           ++p)
      {
        writer.String(p->c_str());
      }
    }
    writer.EndArray();

    writer.String(JSON_PATHS);
    writer.StartArray();
    {
      for (std::list<std::string>::const_iterator p = _path_uris.begin();
           p != _path_uris.end();
           ++p)
      {
        writer.String(p->c_str());
      }
    }
    writer.EndArray();

    writer.String(JSON_TIMER_ID); writer.String("Deprecated");
    writer.String(JSON_PRIVATE_ID); writer.String(_private_id.c_str());
    writer.String(JSON_EMERGENCY_REG); writer.Bool(_emergency_registration);
  }
  writer.EndObject();
}

void SubscriberDataManager::AoR::Binding::from_json(const rapidjson::Value& b_obj)
{

  JSON_GET_STRING_MEMBER(b_obj, JSON_URI, _uri);
  JSON_GET_STRING_MEMBER(b_obj, JSON_CID, _cid);
  JSON_GET_INT_MEMBER(b_obj, JSON_CSEQ, _cseq);
  JSON_GET_INT_MEMBER(b_obj, JSON_EXPIRES, _expires);
  JSON_GET_INT_MEMBER(b_obj, JSON_PRIORITY, _priority);

  JSON_ASSERT_CONTAINS(b_obj, JSON_PARAMS);
  JSON_ASSERT_OBJECT(b_obj[JSON_PARAMS]);
  const rapidjson::Value& params_obj = b_obj[JSON_PARAMS];

  for (rapidjson::Value::ConstMemberIterator params_it = params_obj.MemberBegin();
       params_it != params_obj.MemberEnd();
       ++params_it)
  {
    JSON_ASSERT_STRING(params_it->value);
    _params[params_it->name.GetString()] = params_it->value.GetString();
  }

  if (b_obj.HasMember(JSON_PATH_HEADERS))
  {
    JSON_ASSERT_ARRAY(b_obj[JSON_PATH_HEADERS]);
    const rapidjson::Value& path_headers_arr = b_obj[JSON_PATH_HEADERS];

    for (rapidjson::Value::ConstValueIterator path_headers_it = path_headers_arr.Begin();
         path_headers_it != path_headers_arr.End();
         ++path_headers_it)
    {
      JSON_ASSERT_STRING(*path_headers_it);
      _path_headers.push_back(path_headers_it->GetString());
    }
  }

  if (b_obj.HasMember(JSON_PATHS))
  {
    JSON_ASSERT_ARRAY(b_obj[JSON_PATHS]);
    const rapidjson::Value& path_uris_arr = b_obj[JSON_PATHS];

    for (rapidjson::Value::ConstValueIterator path_uris_it = path_uris_arr.Begin();
         path_uris_it != path_uris_arr.End();
         ++path_uris_it)
    {
      JSON_ASSERT_STRING(*path_uris_it);
      _path_uris.push_back(path_uris_it->GetString());
    }
  }

  _timer_id =
    ((b_obj.HasMember(JSON_TIMER_ID)) && ((b_obj[JSON_TIMER_ID]).IsString()) ?
     (b_obj[JSON_TIMER_ID].GetString()) :
     "");
  //      JSON_GET_STRING_MEMBER(b_obj, JSON_TIMER_ID, _timer_id);
  JSON_GET_STRING_MEMBER(b_obj, JSON_PRIVATE_ID, _private_id);
  JSON_GET_BOOL_MEMBER(b_obj, JSON_EMERGENCY_REG, _emergency_registration);
}

void SubscriberDataManager::AoR::Subscription::
  to_json(rapidjson::Writer<rapidjson::StringBuffer>& writer) const
{
  writer.StartObject();
  {
    writer.String(JSON_REQ_URI); writer.String(_req_uri.c_str());
    writer.String(JSON_FROM_URI); writer.String(_from_uri.c_str());
    writer.String(JSON_FROM_TAG); writer.String(_from_tag.c_str());
    writer.String(JSON_TO_URI); writer.String(_to_uri.c_str());
    writer.String(JSON_TO_TAG); writer.String(_to_tag.c_str());
    writer.String(JSON_CID); writer.String(_cid.c_str());

    writer.String(JSON_ROUTES);
    writer.StartArray();
    {
      for (std::list<std::string>::const_iterator r = _route_uris.begin();
           r != _route_uris.end();
           ++r)
      {
        writer.String(r->c_str());
      }
    }
    writer.EndArray();

    writer.String(JSON_EXPIRES); writer.Int(_expires);
    writer.String(JSON_TIMER_ID); writer.String("Deprecated");

  }
  writer.EndObject();
}

void SubscriberDataManager::AoR::Subscription::from_json(const rapidjson::Value& s_obj)
{
  JSON_GET_STRING_MEMBER(s_obj, JSON_REQ_URI, _req_uri);
  JSON_GET_STRING_MEMBER(s_obj, JSON_FROM_URI, _from_uri);
  JSON_GET_STRING_MEMBER(s_obj, JSON_FROM_TAG, _from_tag);
  JSON_GET_STRING_MEMBER(s_obj, JSON_TO_URI, _to_uri);
  JSON_GET_STRING_MEMBER(s_obj, JSON_TO_TAG, _to_tag);
  JSON_GET_STRING_MEMBER(s_obj, JSON_CID, _cid);

  JSON_ASSERT_CONTAINS(s_obj, JSON_ROUTES);
  JSON_ASSERT_ARRAY(s_obj[JSON_ROUTES]);
  const rapidjson::Value& routes_arr = s_obj[JSON_ROUTES];

  for (rapidjson::Value::ConstValueIterator routes_it = routes_arr.Begin();
       routes_it != routes_arr.End();
       ++routes_it)
  {
    JSON_ASSERT_STRING(*routes_it);
    _route_uris.push_back(routes_it->GetString());
  }

  JSON_GET_INT_MEMBER(s_obj, JSON_EXPIRES, _expires);
  _timer_id =
    ((s_obj.HasMember(JSON_TIMER_ID)) && ((s_obj[JSON_TIMER_ID]).IsString()) ?
     (s_obj[JSON_TIMER_ID].GetString()) :
     "");
}

// Utility function to return the expiry time of the binding or subscription due
// to expire next. If the function finds no expiry times in the bindings or
// subscriptions it returns 0. This function should never be called on an empty AoR,
// so a 0 is indicative of something wrong with the _expires values of AoR members.
int SubscriberDataManager::AoR::get_next_expires()
{
  // Set a temp int to INT_MAX to compare expiry times to.
  int _next_expires = INT_MAX;

  for (SubscriberDataManager::AoR::Bindings::const_iterator b = _bindings.begin();
       b != _bindings.end();
       ++b)
  {
    if (b->second->_expires < _next_expires)
    {
      _next_expires = b->second->_expires;
    }
  }
  for (SubscriberDataManager::AoR::Subscriptions::const_iterator s = _subscriptions.begin();
       s != _subscriptions.end();
       ++s)
  {
    if (s->second->_expires < _next_expires)
    {
      _next_expires = s->second->_expires;
    }
  }

  // If nothing has altered the _next_expires, the AoR is empty and invalid.
  // Return 0 to indicate there is nothing to expire.
  if (_next_expires == INT_MAX)
  {
    return 0;
  }
  // Otherwise we return the value found.
  return _next_expires;
}

// Copy all bindings and subscriptions to this AoR
void SubscriberDataManager::AoR::copy_subscriptions_and_bindings(SubscriberDataManager::AoR* source_aor)
{
  for (Bindings::const_iterator i = source_aor->bindings().begin();
       i != source_aor->bindings().end();
       ++i)
  {
    Binding* src = i->second;
    Binding* dst = get_binding(i->first);
    *dst = *src;
  }

  for (Subscriptions::const_iterator i = source_aor->subscriptions().begin();
       i != source_aor->subscriptions().end();
       ++i)
  {
    Subscription* src = i->second;
    Subscription* dst = get_subscription(i->first);
    *dst = *src;
  }
}

//
// (De)serializer for the JSON SubscriberDataManager format.
//

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

      b->from_json(b_obj);
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

      s->from_json(s_obj);
    }

    JSON_GET_INT_MEMBER(doc, JSON_NOTIFY_CSEQ, aor->_notify_cseq);
    aor->_timer_id =
         ((doc.HasMember(JSON_TIMER_ID)) && ((doc[JSON_TIMER_ID]).IsString()) ?
                                             (doc[JSON_TIMER_ID].GetString()) :
                                              "");
    aor->_scscf_uri =
         ((doc.HasMember(JSON_SCSCF_URI)) && ((doc[JSON_SCSCF_URI]).IsString()) ?
                                                (doc[JSON_SCSCF_URI].GetString()) :
                                                 "");
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
        it->second->to_json(writer);
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
        it->second->to_json(writer);
      }
    }
    writer.EndObject();

    // Notify Cseq flag
    writer.String(JSON_NOTIFY_CSEQ); writer.Int(aor_data->_notify_cseq);
    writer.String(JSON_TIMER_ID); writer.String(aor_data->_timer_id.c_str());
    writer.String(JSON_SCSCF_URI); writer.String(aor_data->_scscf_uri.c_str());
  }
  writer.EndObject();

  return sb.GetString();
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

void SubscriberDataManager::ChronosTimerRequestSender::build_tag_info (
                                                AoR* aor,
                                                std::map<std::string, uint32_t>& tag_map)
{
  // Each timer is built to represent a single registration i.e. an AoR.
  tag_map["REG"] = 1;
  tag_map["BIND"] = aor->get_bindings_count();
  tag_map["SUB"] = aor->get_subscriptions_count();
}


void SubscriberDataManager::ChronosTimerRequestSender::send_timers(
                             const std::string& aor_id,
                             AoRPair* aor_pair,
                             int now,
                             SAS::TrailId trail)
{
  std::map<std::string, uint32_t> old_tags;
  std::map<std::string, uint32_t> new_tags;
  AoR* orig_aor = aor_pair->get_orig();
  AoR* current_aor = aor_pair->get_current();
  std::string& timer_id = current_aor->_timer_id;

  // An AoR with no bindings is invalid, and the timer should be deleted.
  // We do this before getting next_expires to save on processing.
  if (current_aor->get_bindings_count() == 0)
  {
    if (timer_id != "")
    {
      _chronos_conn->send_delete(timer_id, trail);
    }
  return;
  }

  build_tag_info(orig_aor, old_tags);
  build_tag_info(current_aor, new_tags);
  int old_next_expires = orig_aor->get_next_expires();
  int new_next_expires = current_aor->get_next_expires();

  if ((old_next_expires == 0) || (new_next_expires == 0))
  {
    // This should never happen, as an empty AoR should never reach get_next_expires
    TRC_DEBUG("get_next_expires returned 0. The expiry of AoR members is corrupt, or an empty (invalid) AoR was passed in.");
  }

  if ((new_tags != old_tags)                 ||
      (new_next_expires != old_next_expires) ||
      (timer_id == ""))
  {
    // Set the expiry time to be relative to now.
    int expiry = (new_next_expires > now) ? (new_next_expires - now) : (now);

    set_timer(aor_id,
              timer_id,
              expiry,
              new_tags,
              trail);
  }
}

void SubscriberDataManager::ChronosTimerRequestSender::set_timer(
                                    const std::string& aor_id,
                                    std::string& timer_id,
                                    int expiry,
                                    std::map<std::string, uint32_t> tags,
                                    SAS::TrailId trail)
{
  std::string temp_timer_id = "";
  HTTPCode status;
  std::string opaque = "{\"aor_id\": \"" + aor_id + "\"}";
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

/// NotifySender Methods

SubscriberDataManager::NotifySender::NotifySender()
{
}

SubscriberDataManager::NotifySender::~NotifySender()
{
}

void SubscriberDataManager::NotifySender::send_notifys(
                               const std::string& aor_id,
                               AssociatedURIs* associated_uris,
                               SubscriberDataManager::AoRPair* aor_pair,
                               int now,
                               SAS::TrailId trail)
{
  std::vector<std::string> expired_binding_uris;
  ClassifiedBindings binding_info_to_notify;
  bool bindings_changed = false;

  // Iterate over the bindings in the original AoR. Find any that aren't in the current
  // AoR and mark those as expired.
  for (std::pair<std::string, SubscriberDataManager::AoR::Binding*> aor_orig_b :
         aor_pair->get_orig()->bindings())
  {
    SubscriberDataManager::AoR::Binding* binding = aor_orig_b.second;
    std::string b_id = aor_orig_b.first;

    // Compare the original and current lists to see whether this binding has expired.
    // Emergency bindings are excluded from notifications.
    if ((!binding->_emergency_registration) &&
        (aor_pair->get_current()->bindings().find(b_id) == aor_pair->get_current()->bindings().end()))
    {
      TRC_DEBUG("Binding %s has expired", b_id.c_str());
      expired_binding_uris.push_back(binding->_uri);
      NotifyUtils::BindingNotifyInformation* bni =
               new NotifyUtils::BindingNotifyInformation(b_id,
                                                         binding,
                                                         NotifyUtils::ContactEvent::EXPIRED);
      binding_info_to_notify.push_back(bni);
      bindings_changed = true;
    }
  }

  // Iterate over the bindings in the current AoR. Figure out if the bindings
  // have been CREATED, REFRESHED, REGISTERED or SHORTENED.
  for (std::pair<std::string, SubscriberDataManager::AoR::Binding*> aor_current_b :
         aor_pair->get_current()->bindings())
  {
    SubscriberDataManager::AoR::Binding* binding = aor_current_b.second;
    std::string b_id = aor_current_b.first;

    if (!binding->_emergency_registration)
    {
      // If the binding is only in the current AoR, mark it as created
      SubscriberDataManager::AoR::Bindings::const_iterator aor_orig_b_match =
        aor_pair->get_orig()->bindings().find(b_id);

      if (aor_orig_b_match == aor_pair->get_orig()->bindings().end())
      {
        TRC_DEBUG("Binding %s has been created", aor_current_b.first.c_str());
        NotifyUtils::BindingNotifyInformation* bni =
              new NotifyUtils::BindingNotifyInformation(b_id,
                                                        binding,
                                                        NotifyUtils::ContactEvent::CREATED);
        binding_info_to_notify.push_back(bni);
        bindings_changed = true;
      }
      else
      {
        // The binding is in both AoRs. Check if the expiry time has changed at all
        NotifyUtils::ContactEvent event;

        if (aor_orig_b_match->second->_expires < binding->_expires)
        {
          TRC_DEBUG("Binding %s has been refreshed", b_id.c_str());
          event = NotifyUtils::ContactEvent::REFRESHED;
          bindings_changed = true;
        }
        else if (aor_orig_b_match->second->_expires > binding->_expires)
        {
          TRC_DEBUG("Binding %s has been shortened", b_id.c_str());
          event = NotifyUtils::ContactEvent::SHORTENED;
          bindings_changed = true;
        }
        else
        {
          TRC_DEBUG("Binding %s is unchanged", b_id.c_str());
          event = NotifyUtils::ContactEvent::REGISTERED;
        }

        NotifyUtils::BindingNotifyInformation* bni =
              new NotifyUtils::BindingNotifyInformation(b_id,
                                                        binding,
                                                        event);
        binding_info_to_notify.push_back(bni);
      }
    }
  }

  // Iterate over the subscriptions in the original AoR, and send NOTIFYs for
  // any subscriptions that aren't in the current AoR.
  send_notifys_for_expired_subscriptions(aor_id,
                                         associated_uris,
                                         aor_pair,
                                         binding_info_to_notify,
                                         expired_binding_uris,
                                         now,
                                         trail);

  // Iterate over the subscriptions in the current AoR and send NOTIFYs.
  // If the bindings have changed, then send NOTIFYs to all subscribers; otherwise,
  // only send them when the subscription has been created or updated.
  for (SubscriberDataManager::AoR::Subscriptions::const_iterator current_sub =
        aor_pair->get_current()->subscriptions().begin();
      current_sub != aor_pair->get_current()->subscriptions().end();
      ++current_sub)
  {
    SubscriberDataManager::AoR::Subscription* subscription = current_sub->second;
    std::string s_id = current_sub->first;

    // Find the subscription in the original AoR to determine if the current subscription
    // has been created.
    SubscriberDataManager::AoR::Subscriptions::const_iterator orig_sub =
      aor_pair->get_orig()->subscriptions().find(s_id);
    bool sub_created = (orig_sub == aor_pair->get_orig()->subscriptions().end());

    // If the subscription has just been created then orig_sub won't be valid,
    // so don't try to check whether it's been refreshed.
    bool sub_refreshed = (!sub_created) && subscription->_refreshed;

    if (bindings_changed || sub_created || sub_refreshed)
    {
      std::string reasons;

      if (bindings_changed)
      {
        reasons += "bindings_changed ";
      }

      if (sub_created)
      {
        reasons += "subscription_created ";
      }

      if (sub_refreshed)
      {
        reasons += "subscription_refreshed ";
      }

      TRC_DEBUG("Sending NOTIFY for subscription %s: reason(s) %s",
                s_id.c_str(),
                reasons.c_str());

      pjsip_tx_data* tdata_notify = NULL;
      pj_status_t status = NotifyUtils::create_subscription_notify(
                                            &tdata_notify,
                                            subscription,
                                            aor_id,
                                            associated_uris,
                                            aor_pair->get_orig(),
                                            binding_info_to_notify,
                                            NotifyUtils::RegistrationState::ACTIVE,
                                            now,
                                            trail);

      if (status == PJ_SUCCESS)
      {
        set_trail(tdata_notify, trail);
        status = PJUtils::send_request(tdata_notify, 0, NULL, NULL, true);

        if (status == PJ_SUCCESS)
        {
          subscription->_refreshed = false;
        }
        else
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
    }
  }

  delete_bindings(binding_info_to_notify);
}

void SubscriberDataManager::NotifySender::send_notifys_for_expired_subscriptions(
                               const std::string& aor_id,
                               AssociatedURIs* associated_uris,
                               SubscriberDataManager::AoRPair* aor_pair,
                               ClassifiedBindings binding_info_to_notify,
                               std::vector<std::string> expired_binding_uris,
                               int now,
                               SAS::TrailId trail)
{
  // The registration state to send is ACTIVE if we have at least one active binding,
  // otherwise TERMINATED.
  NotifyUtils::RegistrationState reg_state = (!aor_pair->get_current()->bindings().empty()) ?
    NotifyUtils::RegistrationState::ACTIVE :
    NotifyUtils::RegistrationState::TERMINATED;

  // expired_binding_uris lists bindings which have expired - we no longer have a valid connection to
  // these endpoints, so shouldn't send a NOTIFY to them (even to say that their subscription is
  // terminated).
  //
  // Note that we can't just check whether a binding exists before sending a NOTIFY - a SUBSCRIBE
  // may have come from a P-CSCF or AS, which wouldn't match a binding.

  // Iterate over the subscriptions in the original AoR, and send NOTIFYs for
  // any subscriptions that aren't in the current AoR.
  for (SubscriberDataManager::AoR::Subscriptions::const_iterator aor_orig_s =
         aor_pair->get_orig()->subscriptions().begin();
       aor_orig_s != aor_pair->get_orig()->subscriptions().end();
       ++aor_orig_s)
  {
    SubscriberDataManager::AoR::Subscription* s = aor_orig_s->second;
    std::string s_id = aor_orig_s->first;

    if (std::find(expired_binding_uris.begin(), expired_binding_uris.end(), s->_req_uri) !=
      expired_binding_uris.end())
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

      pjsip_tx_data* tdata_notify = NULL;

      // This is a terminated subscription - set the expiry time to now
      s->_expires = now;
      pj_status_t status = NotifyUtils::create_subscription_notify(
                                          &tdata_notify,
                                          s,
                                          aor_id,
                                          associated_uris,
                                          aor_pair->get_orig(),
                                          binding_info_to_notify,
                                          reg_state,
                                          now,
                                          trail);

      if (status == PJ_SUCCESS)
      {
        set_trail(tdata_notify, trail);
        status = PJUtils::send_request(tdata_notify, 0, NULL, NULL, true);

        if (status == PJ_SUCCESS)
        {
          s->_refreshed = false;
        }
        else
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
    }
  }
}
