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

class HssCacheHelper
{

public:

  HssCacheHelper();
  ~HssCacheHelper();

  // Data received from HSS for this service hop.
  bool _hss_data_cached;
  bool _registered;
  bool _barred;
  std::string _default_uri;
  Ifcs _ifcs;
  HSSConnection::irs_info _irs_info;

  /// The private identity associated with the request. Empty unless the
  /// request had a Proxy-Authorization header.
  std::string _impi;

  /// Whether this request should cause the user to be automatically
  /// registered in the HSS. This is set if there is an `auto-reg` parameter
  /// in the S-CSCF's route header.
  ///
  /// This has the following impacts:
  /// - It causes registration state updates to have a type of REG rather than
  ///   CALL.
  /// - If there is a real HSS it forces registration state updates to flow all
  ///   the way to the HSS (i.e. Homestead may not answer the response solely
  ///   from its cache).
  bool _auto_reg;

  /// The wildcarded public identity associated with the requestee. This is
  /// pulled from the P-Profile-Key header (RFC 5002).
  std::string _wildcard;

  /// The S-CSCF URI for this transaction. This is used in the SAR sent to the
  /// HSS. This field should not be changed once it has been set by the
  /// on_rx_intial_request() call.
  std::string _scscf_uri;

  /// Look up the associated URIs for the given public ID, using the cache if
  /// possible (and caching them and the iFC otherwise).
  /// The uris parameter is only filled in correctly if this function
  /// returns true.
  bool get_associated_uris(std::string public_id,
                           std::vector<std::string>& uris,
                           SAS::TrailId trail,
                           SubscriberManager* sm);

  /// Look up the aliases for the given public ID, using the cache if
  /// possible (and caching them and the iFC otherwise).
  /// The aliases parameter is only filled in correctly if this function
  /// returns true.
  bool get_aliases(std::string public_id,
                   std::vector<std::string>& aliases,
                   SAS::TrailId trail,
                   SubscriberManager* sm);

  /// Look up the Ifcs for the given public ID, using the cache if possible
  /// (and caching them and the associated URIs otherwise).
  /// Returns the HTTP result code obtained from homestead.
  /// The ifcs parameter is only filled in correctly if this function
  /// returns HTTP_OK.
  HTTPCode lookup_ifcs(std::string public_id,
                       Ifcs& ifcs,
                       SAS::TrailId trail,
                       SubscriberManager* sm);

private:

  /// Reads data for a public user identity from the HSS, and stores it in
  /// member fields for the sproutlet.
  /// Returns the HTTP result code obtained from the SM.
  HTTPCode read_hss_data(const HSSConnection::irs_query& irs_query,
                         HSSConnection::irs_info& irs_info,
                         SAS::TrailId trail,
                         SubscriberManager* sm,
                         std::string public_id);

  /// Gets the subscriber's associated URIs and iFCs for each URI from
  /// the HSS and stores cached values.
  /// Returns the HTTP result code obtained from the SM.
  HTTPCode get_data_from_hss(std::string public_id,
                             SAS::TrailId trail,
                             SubscriberManager* sm);

};

#endif
