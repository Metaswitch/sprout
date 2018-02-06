/**
 * @file hss_cache_helper.h Helper functions to cache/distribute info from the
 * HSS.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef HSS_CACHE_HELPER_H__
#define HSS_CACHE_HELPER_H__

#include "sas.h"
#include "aschain.h"
#include "subscriber_manager.h"
#include "sproutlet.h"
#include "httpclient.h"

namespace HssCacheHelper {

/// Look up the associated URIs for the given public ID, using the cache if
/// possible (and caching them and the iFC otherwise).
/// The uris parameter is only filled in correctly if this function
/// returns true.
bool get_associated_uris(std::string public_id,
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
                         SAS::TrailId trail);

/// Look up the aliases for the given public ID, using the cache if
/// possible (and caching them and the iFC otherwise).
/// The aliases parameter is only filled in correctly if this function
/// returns true.
bool get_aliases(std::string public_id,
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
                 SAS::TrailId trail);

/// Look up the Ifcs for the given public ID, using the cache if possible
/// (and caching them and the associated URIs otherwise).
/// Returns the HTTP result code obtained from homestead.
/// The ifcs parameter is only filled in correctly if this function
/// returns HTTP_OK.
HTTPCode lookup_ifcs(std::string public_id,
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
                     SAS::TrailId trail);

/// Gets the subscriber's associated URIs and iFCs for each URI from
/// the HSS and stores cached values.
/// Returns the HTTP result code obtained from the SM.
HTTPCode get_data_from_hss(std::string public_id,
                           SubscriberManager* sm,
                           std::string impi,
                           bool auto_reg,
                           std::string scscf_uri,
                           std::string wildcard,
                           bool hss_data_cached,
                           bool registered,
                           bool barred,
                           Ifcs& class_ifcs,
                           HSSConnection::irs_info& irs_info,
                           std::string default_uri,
                           SAS::TrailId trail);

/// Reads data for a public user identity from the HSS, and stores it in
/// member fields for the sproutlet.
/// Returns the HTTP result code obtained from the SM.
HTTPCode read_hss_data(std::string public_id,
                       const HSSConnection::irs_query& irs_query,
                       SubscriberManager* sm,
                       bool registered,
                       bool barred,
                       Ifcs& class_ifcs,
                       HSSConnection::irs_info& irs_info,
                       std::string default_uri,
                       SAS::TrailId trail);

}

#endif
