/**
 * @file aor.cpp
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

#include "aor.h"
#include "json_parse_utils.h"
#include "rapidjson/error/en.h"

/// Default constructor.
AoR::AoR(std::string sip_uri) :
  _notify_cseq(1),
  _timer_id(""),
  _scscf_uri(""),
  _bindings(),
  _subscriptions(),
  _associated_uris(),
  _cas(0),
  _uri(sip_uri)
{
}


/// Destructor.
AoR::~AoR()
{
  clear(true);
}


/// Copy constructor.
AoR::AoR(const AoR& other)
{
  common_constructor(other);
}

// Make sure assignment is deep!
AoR& AoR::operator= (AoR const& other)
{
  if (this != &other)
  {
    clear(true);
    common_constructor(other);
  }

  return *this;
}

void AoR::common_constructor(const AoR& other)
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

  _associated_uris = AssociatedURIs(other._associated_uris);
  _notify_cseq = other._notify_cseq;
  _timer_id = other._timer_id;
  _cas = other._cas;
  _uri = other._uri;
  _scscf_uri = other._scscf_uri;
}

/// Clear all the bindings and subscriptions from this object.
void AoR::clear(bool clear_emergency_bindings)
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
  _associated_uris.clear_uris();
}


/// Retrieve a binding by binding identifier, creating an empty one if
/// necessary.  The created binding is completely empty, even the Contact URI
/// field.
AoR::Binding* AoR::get_binding(const std::string& binding_id)
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
void AoR::remove_binding(const std::string& binding_id)
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
AoR::Subscription* AoR::get_subscription(const std::string& to_tag)
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
void AoR::remove_subscription(const std::string& to_tag)
{
  AoR::Subscriptions::iterator i = _subscriptions.find(to_tag);
  if (i != _subscriptions.end())
  {
    delete i->second;
    _subscriptions.erase(i);
  }
}

/// Remove all the bindings from an AOR object
void AoR::clear_bindings()
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
pjsip_sip_uri* AoR::Binding::pub_gruu(pj_pool_t* pool) const
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
std::string AoR::Binding::pub_gruu_str(pj_pool_t* pool) const
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
std::string AoR::Binding::pub_gruu_quoted_string(pj_pool_t* pool) const
{
  std::string unquoted_pub_gruu = pub_gruu_str(pool);

  if (unquoted_pub_gruu.length() == 0)
  {
    return "";
  }

  std::string ret = "\"" + unquoted_pub_gruu + "\"";
  return ret;
}

void AoR::Binding::
  to_json(rapidjson::Writer<rapidjson::StringBuffer>& writer) const
{
  writer.StartObject();
  {
    writer.String(JSON_URI); writer.String(_uri.c_str());
    writer.String(JSON_CID); writer.String(_cid.c_str());
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

    writer.String(JSON_PRIVATE_ID); writer.String(_private_id.c_str());
    writer.String(JSON_EMERGENCY_REG); writer.Bool(_emergency_registration);
  }
  writer.EndObject();
}

void AoR::Binding::from_json(const rapidjson::Value& b_obj)
{

  JSON_GET_STRING_MEMBER(b_obj, JSON_URI, _uri);
  JSON_GET_STRING_MEMBER(b_obj, JSON_CID, _cid);
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

  JSON_GET_STRING_MEMBER(b_obj, JSON_PRIVATE_ID, _private_id);
  JSON_GET_BOOL_MEMBER(b_obj, JSON_EMERGENCY_REG, _emergency_registration);
}

void AoR::Subscription::
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
    writer.String(JSON_NOTIFY_CSEQ); writer.Int(_notify_cseq);
  }
  writer.EndObject();
}

void AoR::Subscription::from_json(const rapidjson::Value& s_obj)
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
  JSON_GET_INT_MEMBER(s_obj, JSON_NOTIFY_CSEQ, _notify_cseq);
}

// Utility function to return the expiry time of the binding or subscription due
// to expire next. If the function finds no expiry times in the bindings or
// subscriptions it returns 0. This function should never be called on an empty AoR,
// so a 0 is indicative of something wrong with the _expires values of AoR members.
int AoR::get_next_expires()
{
  // Set a temp int to INT_MAX to compare expiry times to.
  int _next_expires = INT_MAX;

  for (AoR::Bindings::const_iterator b = _bindings.begin();
       b != _bindings.end();
       ++b)
  {
    if (b->second->_expires < _next_expires)
    {
      _next_expires = b->second->_expires;
    }
  }
  for (AoR::Subscriptions::const_iterator s = _subscriptions.begin();
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

void AoR::copy_aor(AoR* source_aor)
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

  _associated_uris = AssociatedURIs(source_aor->_associated_uris);
  _notify_cseq = source_aor->_notify_cseq;
  _timer_id = source_aor->_timer_id;
  _uri = source_aor->_uri;
  _scscf_uri = source_aor->_scscf_uri;
}

AoR::Bindings AoRPair::get_updated_bindings()
{
  AoR::Bindings updated_bindings;

  // Iterate over the bindings in the current AoR. Figure out if the bindings
  // have been created or updated.
  for (std::pair<std::string, AoR::Binding*> current_aor_binding :
         _current_aor->bindings())
  {
    std::string b_id = current_aor_binding.first;
    AoR::Binding* binding = current_aor_binding.second;

    // Find any binding match in the original AoR
    AoR::Bindings::const_iterator orig_aor_binding_match =
      _orig_aor->bindings().find(b_id);

    // If the binding is only in the current AoR, it has been created
    if (orig_aor_binding_match == _orig_aor->bindings().end())
    {
      TRC_DEBUG("Binding %s has been created", current_aor_binding.first.c_str());
      updated_bindings.insert(std::make_pair(b_id, binding));
    }
    else
    {
      // The binding is in both AoRs. Check if the expiry time has changed at all
      if (orig_aor_binding_match->second->_expires != binding->_expires)
      {
        TRC_DEBUG("Binding %s expiry has been changed", b_id.c_str());
        updated_bindings.insert(std::make_pair(b_id, binding));
      }
      else
      {
        TRC_DEBUG("Binding %s is unchanged", b_id.c_str());
      }
    }
  }
  return updated_bindings;
}

AoR::Subscriptions AoRPair::get_updated_subscriptions()
{
  AoR::Subscriptions updated_subscriptions;

  // Iterate over the subscriptions in the current AoR. Figure out if the
  // subscriptions have been created or updated.
  for (std::pair<std::string, AoR::Subscription*> current_aor_subscription :
         _current_aor->subscriptions())
  {
    std::string s_id = current_aor_subscription.first;
    AoR::Subscription* subscription = current_aor_subscription.second;

    // Find any subscriptions match in the original AoR
    AoR::Subscriptions::const_iterator orig_aor_subscription_match =
      _orig_aor->subscriptions().find(s_id);

    // If the subscription is only in the current AoR, it has been created
    if (orig_aor_subscription_match == _orig_aor->subscriptions().end())
    {
      TRC_DEBUG("Subscription %s has been created", current_aor_subscription.first.c_str());
      updated_subscriptions.insert(std::make_pair(s_id, subscription));
    }
    else
    {
      // The subscription is in both AoRs. Check if the expiry time has changed at all
      if (orig_aor_subscription_match->second->_expires != subscription->_expires)
      {
        TRC_DEBUG("Subscription %s expiry has been changed", s_id.c_str());
        updated_subscriptions.insert(std::make_pair(s_id, subscription));
      }
      else
      {
        TRC_DEBUG("Subscription %s is unchanged", s_id.c_str());
      }
    }
  }

  return updated_subscriptions;
}

AoR::Bindings AoRPair::get_removed_bindings()
{
  AoR::Bindings removed_bindings;

  // Iterate over original bindings and record those not in current AoR
  for (std::pair<std::string, AoR::Binding*> orig_aor_binding :
         _orig_aor->bindings())
  {
    if (_current_aor->bindings().find(orig_aor_binding.first) ==
        _current_aor->bindings().end())
    {
      // Binding is gone (which may mean deregistration or expiry)
      TRC_DEBUG("Binding %s has been removed", orig_aor_binding.first.c_str());
      removed_bindings.insert(std::make_pair(orig_aor_binding.first,
                                             orig_aor_binding.second));
    }
  }

  return removed_bindings;
}

AoR::Subscriptions AoRPair::get_removed_subscriptions()
{
  AoR::Subscriptions removed_subscriptions;

  // Iterate over original subscriptions and record those not in current AoR
  for (std::pair<std::string, AoR::Subscription*> orig_aor_subscription :
         _orig_aor->subscriptions())
  {
    // Is this subscription present in the new AoR?
    if (_current_aor->subscriptions().find(orig_aor_subscription.first) ==
        _current_aor->subscriptions().end())
    {
      // Subscription is gone
      TRC_DEBUG("Subscription %s is no longer present",
                    orig_aor_subscription.first.c_str());
      removed_subscriptions.insert(std::make_pair(orig_aor_subscription.first,
                                                  orig_aor_subscription.second));
    }
  }
  return removed_subscriptions;
}
