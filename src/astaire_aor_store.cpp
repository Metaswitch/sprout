/**
 * @file astaire_aor_store.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


// Common STL includes.
#include "astaire_aor_store.h"
#include "json_parse_utils.h"
#include "rapidjson/error/en.h"
#include "sproutsasevent.h"


AstaireAoRStore::AstaireAoRStore(Store* store) : AoRStore()
{
  JsonSerializerDeserializer* serializer_deserializer = new JsonSerializerDeserializer();
  _connector = new Connector(store, serializer_deserializer); // Takes ownership of serializer_deserializer
}

AstaireAoRStore::~AstaireAoRStore()
{
  // Ownership of serializer_deserializer passed to _connector
  delete _connector; _connector = NULL;
}

/// AstaireAoRStore methods

/// Calls through into the connector get and set commands
AoR* AstaireAoRStore::get_aor_data(const std::string& aor_id,
                                   SAS::TrailId trail)
{
  return _connector->get_aor_data(aor_id, trail);
}


Store::Status AstaireAoRStore::set_aor_data(const std::string& aor_id,
                                            AoRPair* aor_data,
                                            int expiry,
                                            SAS::TrailId trail)
{
  return _connector->set_aor_data(aor_id,
                                  aor_data->get_current(),
                                  expiry,
                                  trail);
}

/// AstaireAoRStore::Connector Methods

AstaireAoRStore::Connector::Connector(Store* data_store,
                            JsonSerializerDeserializer*& serializer_deserializer) :
  _data_store(data_store),
  _serializer_deserializer(serializer_deserializer)
{
  // We have taken ownership of the serializer_deserializer.
  serializer_deserializer = NULL;
}

AstaireAoRStore::Connector::~Connector()
{
  delete _serializer_deserializer; _serializer_deserializer = NULL;
}

/// Retrieve the registration data for a given SIP Address of Record, creating
/// an empty record if no data exists for the AoR.
///
/// @param aor_id       The SIP Address of Record for the registration
AoR* AstaireAoRStore::Connector::get_aor_data(
                                             const std::string& aor_id,
                                             SAS::TrailId trail)
{
  TRC_DEBUG("Get AoR data for %s", aor_id.c_str());
  AoR* aor_data = NULL;

  std::string data;
  uint64_t cas;
  Store::Status status = _data_store->get_data("reg", 
                                               aor_id,
                                               data,
                                               cas,
                                               trail,
                                               Store::Format::JSON);

  if (status == Store::Status::OK)
  {
    // Retrieved the data, so deserialize it.
    TRC_DEBUG("Data store returned a record, CAS = %ld", cas);
    aor_data = _serializer_deserializer->deserialize_aor(aor_id, data);

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

Store::Status AstaireAoRStore::Connector::set_aor_data(
                                            const std::string& aor_id,
                                            AoR* aor_data,
                                            int expiry,
                                            SAS::TrailId trail)
{
  std::string data = _serializer_deserializer->serialize_aor(aor_data);

  SAS::Event event(trail, SASEvent::REGSTORE_SET_START, 0);
  event.add_var_param(aor_id);
  SAS::report_event(event);

  Store::Status status = _data_store->set_data("reg",
                                               aor_id,
                                               data,
                                               aor_data->_cas,
                                               expiry,
                                               trail,
                                               Store::Format::JSON);

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


//
// (De)serializer for the JSON SubscriberDataManager format.
//

AoR* AstaireAoRStore::JsonSerializerDeserializer::
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
    JSON_ASSERT_OBJECT(doc);
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

    if (doc.HasMember(JSON_ASSOCIATED_URIS))
    {
      JSON_ASSERT_OBJECT(doc[JSON_ASSOCIATED_URIS]);
      const rapidjson::Value& au_obj = doc[JSON_ASSOCIATED_URIS];
      aor->_associated_uris.from_json(au_obj);
    }

    JSON_GET_INT_MEMBER(doc, JSON_NOTIFY_CSEQ, aor->_notify_cseq);

    JSON_SAFE_GET_STRING_MEMBER(doc, JSON_TIMER_ID, aor->_timer_id);
    JSON_SAFE_GET_STRING_MEMBER(doc, JSON_SCSCF_URI, aor->_scscf_uri);
  }
  catch(JsonFormatError err)
  {
    TRC_INFO("Failed to deserialize JSON document (hit error at %s:%d)",
             err._file, err._line);
    delete aor; aor = NULL;
  }

  return aor;
}


std::string AstaireAoRStore::JsonSerializerDeserializer::serialize_aor(AoR* aor_data)
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

    // Associated URIs
    writer.String(JSON_ASSOCIATED_URIS);
    aor_data->_associated_uris.to_json(writer);

    // Notify Cseq flag
    writer.String(JSON_NOTIFY_CSEQ); writer.Int(aor_data->_notify_cseq);
    writer.String(JSON_TIMER_ID); writer.String(aor_data->_timer_id.c_str());
    writer.String(JSON_SCSCF_URI); writer.String(aor_data->_scscf_uri.c_str());
  }
  writer.EndObject();

  return sb.GetString();
}
