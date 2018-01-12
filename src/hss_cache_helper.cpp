/**
 * @file hss_cache_helper.cpp Helper functions to cache/distribute info from the
 * HSS.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "hss_cache_helper.h"

HssCacheHelper::HssCacheHelper() :
  _hss_data_cached(false),
  _registered(false),
  _barred(false),
  _default_uri(""),
  _ifcs(),
  _impi(),
  _auto_reg(false),
  _wildcard(""),
  _scscf_uri()
{
}


HssCacheHelper::~HssCacheHelper()
{
}


bool HssCacheHelper::get_associated_uris(std::string public_id,
                                         std::vector<std::string>& uris,
                                         SubscriberManager* sm,
                                         SAS::TrailId trail)
{
  long http_code = get_data_from_hss(public_id, sm, trail);
  if (http_code == HTTP_OK)
  {
    uris = _irs_info._associated_uris.get_all_uris();
  }
  return (http_code == HTTP_OK);
}


bool HssCacheHelper::get_aliases(std::string public_id,
                                 std::vector<std::string>& aliases,
                                 SubscriberManager* sm,
                                 SAS::TrailId trail)
{
  long http_code = get_data_from_hss(public_id, sm, trail);
  if (http_code == HTTP_OK)
  {
    aliases = _irs_info._aliases;
  }
  return (http_code == HTTP_OK);
}


HTTPCode HssCacheHelper::lookup_ifcs(std::string public_id,
                                     Ifcs& ifcs,
                                     SubscriberManager* sm,
                                     SAS::TrailId trail)
{
  HTTPCode http_code = get_data_from_hss(public_id, sm, trail);
  if (http_code == HTTP_OK)
  {
    ifcs = _ifcs;
  }
  return http_code;
}


HTTPCode HssCacheHelper::get_data_from_hss(std::string public_id,
                                           SubscriberManager* sm,
                                           SAS::TrailId trail)
{
  HTTPCode http_code = HTTP_OK;

  // Read IRS information from HSS if not previously cached.
  if (!_hss_data_cached)
  {
    HSSConnection::irs_query irs_query;
    irs_query._public_id = public_id;
    irs_query._private_id =_impi;
    irs_query._req_type = _auto_reg ? HSSConnection::REG : HSSConnection::CALL;
    irs_query._server_name = _scscf_uri;
    irs_query._wildcard = _wildcard;
    irs_query._cache_allowed = !_auto_reg;

    http_code = read_hss_data(public_id, irs_query, sm, trail);

    if (http_code == HTTP_OK)
    {
      _hss_data_cached = true;
    }
  }

  return http_code;
}


HTTPCode HssCacheHelper::read_hss_data(std::string public_id,
                                       const HSSConnection::irs_query& irs_query,
                                       SubscriberManager* sm,
                                       SAS::TrailId trail)
{
  SubscriberManager::SubscriberInfo subscriber_info;
  HTTPCode http_code = sm->get_subscriber_state(public_id,
                                                subscriber_info,
                                                irs_query,
                                                trail);
  // Have I picked the right function here? (Previous was
  // HSSConnection::update_registration_state.)

  // Take all of this out once can just pass in _irs_info, not subscriber_info,
  // above.
  _irs_info._regstate = subscriber_info._regstate;
  _irs_info._prev_regstate = subscriber_info._prev_regstate;
  _irs_info._service_profiles = subscriber_info._service_profiles;
  _irs_info._associated_uris = subscriber_info._associated_uris;
  _irs_info._aliases = subscriber_info._aliases;
  _irs_info._ccfs = subscriber_info._ccfs;
  _irs_info._ecfs = subscriber_info._ecfs;

  if (http_code == HTTP_OK)
  {
    _ifcs = _irs_info._service_profiles[irs_query._public_id];

    // Get the default URI. This should always succeed.
    _irs_info._associated_uris.get_default_impu(_default_uri, true);

    // We may want to route to bindings that are barred (in case of an
    // emergency), so get all the URIs.
    _registered = (_irs_info._regstate == RegDataXMLUtils::STATE_REGISTERED);
    _barred = _irs_info._associated_uris.is_impu_barred(irs_query._public_id);
  }

  return http_code;
}

