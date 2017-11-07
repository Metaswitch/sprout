/**
 * @file icscfsproutlet.cpp Definition of the I-CSCF Sproutlet classes,
 *                          implementing I-CSCF specific SIP proxy functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef ICSCFSPROUTLET_H__
#define ICSCFSPROUTLET_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <vector>
#include <map>

#include "pjutils.h"
#include "hssconnection.h"
#include "scscfselector.h"
#include "enumservice.h"
#include "icscfrouter.h"
#include "acr.h"
#include "sproutlet.h"
#include "snmp_success_fail_count_by_request_type_table.h"
#include "snmp_success_fail_count_table.h"
#include "compositesproutlet.h"

class ICSCFSproutletTsx;
class ICSCFSproutletRegTsx;

class ICSCFSproutlet : public Sproutlet
{
public:
  ICSCFSproutlet(const std::string& icscf_name,
                 const std::string& bgcf_uri,
                 int port,
                 const std::string& uri,
                 const std::string& network_function,
                 const std::string& next_hop_service,
                 HSSConnection* hss,
                 ACRFactory* acr_factory,
                 SCSCFSelector* scscf_selector,
                 EnumService* enum_service,
                 SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl,
                 SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl,
                 bool override_npdi,
                 int network_function_port,
                 std::set<std::string> blacklisted_scscfs = std::set<std::string>());

  virtual ~ICSCFSproutlet();

  bool init();

  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail);

private:

  /// Returns the configured BGCF URI for this system.
  inline const pjsip_uri* bgcf_uri() const
  {
    return _bgcf_uri;
  }

  inline HSSConnection* get_hss_connection() const
  {
    return _hss;
  }

  inline SCSCFSelector* get_scscf_selector() const
  {
    return _scscf_selector;
  }

  inline bool should_override_npdi() const
  {
    return _override_npdi;
  }

  inline int network_function_port() const
  {
    return _network_function_port;
  }

  /// Attempts to use ENUM to translate the specified Tel URI into a SIP URI.
  void translate_request_uri(pjsip_msg* req, pj_pool_t* pool, SAS::TrailId trail);

  /// Get an ACR instance from the factory.
  /// @param trail                SAS trail identifier to use for the ACR.
  ACR* get_acr(SAS::TrailId trail);

  friend class ICSCFSproutletTsx;
  friend class ICSCFSproutletRegTsx;

  /// A URI which routes to the BGCF.
  pjsip_uri* _bgcf_uri;

  const std::string _next_hop_service;

  HSSConnection* _hss;

  SCSCFSelector* _scscf_selector;

  ACRFactory* _acr_factory;

  EnumService* _enum_service;

  bool _override_npdi;

  /// String versions of cluster URIs
  std::string _bgcf_uri_str;

  /// Stats tables
  SNMP::SuccessFailCountTable* _session_establishment_tbl = NULL;
  SNMP::SuccessFailCountTable* _session_establishment_network_tbl = NULL;

  /// Port owned by this network function, for purposes other than Sproutlet
  /// routing.
  int _network_function_port;

  /// The list of blacklisted S-CSCFs
  std::set<std::string> _blacklisted_scscfs;
};


class ICSCFSproutletTsx : public CompositeSproutletTsx
{
public:
  ICSCFSproutletTsx(ICSCFSproutlet* icscf,
                    const std::string& next_hop_service,
                    pjsip_method_e req_type);
  ~ICSCFSproutletTsx();

  virtual void on_rx_initial_request(pjsip_msg* req) override;
  virtual void on_rx_in_dialog_request(pjsip_msg* req) override;
  virtual void on_tx_request(pjsip_msg* req, int fork_id) override;
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id) override;
  virtual void on_tx_response(pjsip_msg* rsp) override;
  virtual void on_rx_cancel(int status_code, pjsip_msg* req) override;

private:
  /// Determine whether a status code indicates that the S-CSCF wasn't
  /// found.
  ///
  /// @returns                    True/false.
  /// @param status_code          The status code returned from the S-CSCF
  ///                             lookup.
  inline bool scscf_not_found(const pjsip_status_code scscf_lookup)
  {
    return ((scscf_lookup == PJSIP_SC_NOT_FOUND) ||
            (scscf_lookup == PJSIP_SC_DOES_NOT_EXIST_ANYWHERE));
  }

  /// Routes a request to a BGCF.
  ///
  /// @param req                  The request to route.
  void route_to_bgcf(pjsip_msg* req);

  /// Adds a P-Profile-Key header to a request (built from a wildcard returned
  /// on an LIA).
  ///
  /// @param wildcard - The wildcard to add (can be empty, in which case no
  ///                   header is added)
  /// @param req      - The request to add a header to
  void add_p_profile_header(const std::string& wildcard,
                            pjsip_msg* req);

  ICSCFSproutlet* _icscf;
  ACR* _acr;
  ICSCFRouter* _router;
  bool _originating;
  bool _routed_to_bgcf;

  /// Tracks request type and whether a session has been set up for the purposes
  /// of reporting session_establishment stats.  Note that the defintion we
  /// need of "set up" is slightly unusual here: we consider the session to be
  /// set up as soon as we see either a 180 RINGING or a 2xx response.  This is
  /// as defined in TS 32.409.
  pjsip_method_e _req_type;
  bool _session_set_up;
};

class ICSCFSproutletRegTsx : public CompositeSproutletTsx
{
public:
  ICSCFSproutletRegTsx(ICSCFSproutlet* icscf, const std::string& next_hop_service);
  ~ICSCFSproutletRegTsx();

  virtual void on_rx_initial_request(pjsip_msg* req) override;
  virtual void on_rx_in_dialog_request(pjsip_msg* req) override;
  virtual void on_tx_request(pjsip_msg* req, int fork_id) override;
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id) override;
  virtual void on_tx_response(pjsip_msg* rsp) override;

private:
  ICSCFSproutlet* _icscf;
  ACR* _acr;
  ICSCFRouter* _router;
};

#endif
