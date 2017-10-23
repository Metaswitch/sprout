/**
 * @file icscfrouter.h  I-CSCF routing functions
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef ICSCFROUTER_H__
#define ICSCFROUTER_H__

#include "hssconnection.h"
#include "scscfselector.h"
#include "servercaps.h"
#include "acr.h"

#include "rapidjson/document.h"

/// Class implementing common routing functions of an I-CSCF.
class ICSCFRouter
{
public:
  ICSCFRouter(HSSConnection* hss,
              SCSCFSelector* scscf_selector,
              SAS::TrailId trail,
              ACR* acr,
              int port,
              std::set<std::string> blacklisted_scscfs = std::set<std::string>());
  virtual ~ICSCFRouter();

  int get_scscf(pj_pool_t* pool,
                pjsip_sip_uri*& scscf_uri,
                std::string& wildcard,
                bool do_billing=false);

protected:
  /// Do the HSS query.  This must be implemented by the request-type specific
  /// routers.
  virtual int hss_query() = 0;

  /// Parses the HSS response.
  int parse_hss_response(rapidjson::Document*& rsp, bool queried_caps);

  /// Parses a set of capabilities in the HSS response.
  bool parse_capabilities(rapidjson::Value& caps, std::vector<int>& parsed_caps);

  /// Homestead connection class for performing HSS queries.
  HSSConnection* _hss;

  /// S-CSCF selector used to select S-CSCFs from configuration.
  SCSCFSelector* _scscf_selector;

  /// The SAS trail identifier used for logging.
  SAS::TrailId _trail;

  /// The ACR for the request if ACR reported is enabled, NULL otherwise.
  ACR* _acr;

  // Port that I-CSCF is listening on
  int _port;

  /// Flag which indicates whether or not we have asked the HSS for
  /// capabilities and got a successful response (even if there were no
  /// capabilities specified for this subscriber).
  bool _queried_caps;

  /// Structure storing the most recent response from the HSS for this
  /// transaction.
  ServerCapabilities _hss_rsp;

  /// The list of S-CSCFs already attempted for this request.
  std::vector<std::string> _attempted_scscfs;

  /// The list of blacklisted S_CSCFs.
  std::set<std::string> _blacklisted_scscfs;
};


/// Class implementing I-CSCF UAR routing functions.
class ICSCFUARouter : public ICSCFRouter
{
public:
  ICSCFUARouter(HSSConnection* hss,
                SCSCFSelector* scscf_selector,
                SAS::TrailId trail,
                ACR* acr,
                int port,
                const std::string& impi,
                const std::string& impu,
                const std::string& visited_network,
                const std::string& auth_type,
                const bool& emergency,
                std::set<std::string> blacklisted_scscfs = std::set<std::string>());
  ~ICSCFUARouter();

private:

  /// Perform the HSS UAR query.
  virtual int hss_query();

  /// The private user identity to use on HSS queries.
  std::string _impi;

  /// The public user identity to use on HSS queries.
  std::string _impu;

  /// The visited network identifier to use on HSS queries;
  std::string _visited_network;

  /// The authorization type to be used on HSS queries.
  std::string _auth_type;

  /// Whether to signal emergency on HSS queries.
  bool _emergency;
};


/// Class implementing I-CSCF LIR routing functions.
class ICSCFLIRouter : public ICSCFRouter
{
public:
  ICSCFLIRouter(HSSConnection* hss,
                 SCSCFSelector* scscf_selector,
                 SAS::TrailId trail,
                 ACR* acr,
                 int port,
                 const std::string& impu,
                 bool originating,
                 std::set<std::string> blacklisted_scscfs = std::set<std::string>());
  ~ICSCFLIRouter();

  /// Function to change the _impu we're looking up. This is used after
  /// doing an ENUM translation.
  inline void change_impu(std::string& new_impu) { _impu = new_impu; }

private:

  /// Perform the HSS LIR query.
  virtual int hss_query();

  /// The public user identity to use on HSS queries.
  std::string _impu;

  /// Indicates whether this is an originating request or a terminating request.
  bool _originating;
};

#endif
