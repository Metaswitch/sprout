/**
 * @file icscfproxy.h  I-CSCF proxy class definition
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

#ifndef ICSCFPROXY_H__
#define ICSCFPROXY_H__

#include "hssconnection.h"
#include "analyticslogger.h"
#include "scscfselector.h"
#include "basicproxy.h"

class ICSCFProxy : public BasicProxy
{
public:
  /// Constructor.
  ICSCFProxy(pjsip_endpoint* endpt,
             int port,
             int priority,
             HSSConnection* hss,
             SCSCFSelector* scscf_selector,
             AnalyticsLogger* analytics_logger);

  /// Destructor.
  ~ICSCFProxy();

protected:
  /// Process received requests not absorbed by transaction layer.
  virtual pj_bool_t on_rx_request(pjsip_rx_data* rdata);

  /// Perform I-CSCF specific verification of incoming requests.
  virtual pj_status_t verify_request(pjsip_rx_data *rdata);

  /// Create I-CSCF UAS transaction objects.
  BasicProxy::UASTsx* create_uas_tsx();

private:

  class UASTsx : public BasicProxy::UASTsx
  {
  public:
    /// Constructor.
    UASTsx(HSSConnection* hss,
           SCSCFSelector* scscf_selector,
           BasicProxy* proxy);

    /// Destructor.
    ~UASTsx();

  protected:
    /// Calculate targets for incoming requests by querying HSS.
    virtual int calculate_targets(pjsip_tx_data* tdata);

    /// Called when the final response has been determined.
    virtual void on_final_response();

  private:
    /// Gets a suitable target S-CSCF for the request.
    int get_scscf(Json::Value* rsp);

    /// Parses the HSS response.
    int parse_hss_response(Json::Value& rsp);

    /// Parses a set of capabilities in the HSS response.
    bool parse_capabilities(Json::Value& caps, std::vector<int>& parsed_caps);

    /// Homestead connection class for performing HSS queries.
    HSSConnection* _hss;

    /// S-CSCF selector used to select S-CSCFs from configuration.
    SCSCFSelector* _scscf_selector;

    /// The S-CSCF returned by the HSS or selected from configuration.
    std::string _scscf;

    /// Flag which indicates whether or not the HSS has already returned
    /// capabilities for this.
    bool _have_caps;

    /// The list of mandatory capabilities returned by the HSS.
    std::vector<int> _mandatory_caps;

    /// The list of optional capabilities returned by the HSS.
    std::vector<int> _optional_caps;

    /// The list of S-CSCFs already attempted for this request.
    std::vector<std::string> _attempted_scscfs;
  };

  /// Port for I-CSCF function.  This proxy will only process requests
  /// sent to this port, and leave other requests to other PJSIP modules.
  int _port;

  /// Homestead connection class for performing HSS queries.
  HSSConnection* _hss;

  /// S-CSCF selector used to select S-CSCFs from configuration.
  SCSCFSelector* _scscf_selector;

};


#endif
