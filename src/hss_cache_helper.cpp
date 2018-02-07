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

bool HssCacheHelper::get_associated_uris(std::string public_id,
                                         std::vector<std::string>& uris,
                                         HSSConnection::irs_info& irs_info,
                                         SubscriberManager* sm,
                                         std::string impi,
                                         bool auto_reg,
                                         std::string scscf_uri,
                                         std::string wildcard,
                                         bool hss_data_cached,
                                         bool registered,
                                         bool barred,
                                         Ifcs& ifcs,
                                         std::string default_uri,
                                         SAS::TrailId trail)
{
  HTTPCode http_code = get_data_from_hss(public_id,
                                         sm,
                                         impi,
                                         auto_reg,
                                         scscf_uri,
                                         wildcard,
                                         hss_data_cached,
                                         registered,
                                         barred,
                                         ifcs,
                                         irs_info,
                                         default_uri,
                                         trail);
  if (http_code == HTTP_OK)
  {
    uris = irs_info._associated_uris.get_all_uris();
  }
  return (http_code == HTTP_OK);
}

bool HssCacheHelper::get_aliases(std::string public_id,
                                 std::vector<std::string>& aliases,
                                 HSSConnection::irs_info& irs_info,
                                 SubscriberManager* sm,
                                 std::string impi,
                                 bool auto_reg,
                                 std::string scscf_uri,
                                 std::string wildcard,
                                 bool hss_data_cached,
                                 bool registered,
                                 bool barred,
                                 Ifcs& ifcs,
                                 std::string default_uri,
                                 SAS::TrailId trail)
{
  HTTPCode http_code = get_data_from_hss(public_id,
                                         sm,
                                         impi,
                                         auto_reg,
                                         scscf_uri,
                                         wildcard,
                                         hss_data_cached,
                                         registered,
                                         barred,
                                         ifcs,
                                         irs_info,
                                         default_uri,
                                         trail);
  if (http_code == HTTP_OK)
  {
    aliases = irs_info._aliases;
  }
  return (http_code == HTTP_OK);
}

HTTPCode HssCacheHelper::lookup_ifcs(std::string public_id,
                                     Ifcs& ifcs,
                                     Ifcs& class_ifcs,
                                     SubscriberManager* sm,
                                     std::string impi,
                                     bool auto_reg,
                                     std::string scscf_uri,
                                     std::string wildcard,
                                     bool hss_data_cached,
                                     bool registered,
                                     bool barred,
                                     HSSConnection::irs_info& irs_info,
                                     std::string default_uri,
                                     SAS::TrailId trail)
{
  HTTPCode http_code = get_data_from_hss(public_id,
                                         sm,
                                         impi,
                                         auto_reg,
                                         scscf_uri,
                                         wildcard,
                                         hss_data_cached,
                                         registered,
                                         barred,
                                         class_ifcs,
                                         irs_info,
                                         default_uri,
                                         trail);
  if (http_code == HTTP_OK)
  {
    ifcs = class_ifcs;
    // SDM-REFACTOR-TODO - god this is awful. Look into fixing (for this and
    // other functions as well).
  }
  return http_code;
}

HTTPCode HssCacheHelper::get_data_from_hss(std::string public_id,
                                           SubscriberManager* sm,
                                           std::string impi,
                                           bool auto_reg,
                                           std::string scscf_uri,
                                           std::string wildcard,
                                           bool hss_data_cached,
                                           bool registered,
                                           bool barred,
                                           Ifcs& ifcs,
                                           HSSConnection::irs_info& irs_info,
                                           std::string default_uri,
                                           SAS::TrailId trail)
{
  HTTPCode http_code = HTTP_OK;

  // Read IRS information from HSS if not previously cached.
  if (!hss_data_cached)
  {
    HSSConnection::irs_query irs_query;
    irs_query._public_id = public_id;
    irs_query._private_id = impi;
    irs_query._req_type = auto_reg ? HSSConnection::REG : HSSConnection::CALL;
    irs_query._server_name = scscf_uri;
    irs_query._wildcard = wildcard;
    irs_query._cache_allowed = !auto_reg;

    http_code = read_hss_data(public_id,
                              irs_query,
                              sm,
                              registered,
                              barred,
                              ifcs,
                              irs_info,
                              default_uri,
                              trail);

    if (http_code == HTTP_OK)
    {
      hss_data_cached = true;
    }
  }

  return http_code;
}

HTTPCode HssCacheHelper::read_hss_data(std::string public_id,
                                       const HSSConnection::irs_query& irs_query,
                                       SubscriberManager* sm,
                                       bool registered,
                                       bool barred,
                                       Ifcs& ifcs,
                                       HSSConnection::irs_info& irs_info,
                                       std::string default_uri,
                                       SAS::TrailId trail)
{
  HTTPCode http_code = sm->get_subscriber_state(irs_query,
                                                irs_info,
                                                trail);
  // Have I picked the right function here? (Previous was
  // HSSConnection::update_registration_state.)

  if (http_code == HTTP_OK)
  {
    ifcs = irs_info._service_profiles[irs_query._public_id];

    // Get the default URI. This should always succeed.
    irs_info._associated_uris.get_default_impu(default_uri, true);

    // We may want to route to bindings that are barred (in case of an
    // emergency), so get all the URIs.
    registered = (irs_info._regstate == RegDataXMLUtils::STATE_REGISTERED);
    barred = irs_info._associated_uris.is_impu_barred(irs_query._public_id);
  }

  return http_code;
}


