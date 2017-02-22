/**
 * @file icscfrouter.h  I-CSCF routing functions
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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
              int port);
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
                const std::string& auth_type);
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
                 bool originating);
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
