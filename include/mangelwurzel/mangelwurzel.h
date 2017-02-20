/**
 * @file mangelwurzel.h Mangelwurzel class definitions.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#ifndef MANGELWURZEL_H__
#define MANGELWURZEL_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include "pjutils.h"
#include "stack.h"
#include "sproutlet.h"

class MangelwurzelTsx;

/// Definition of MangelwurzelTsx class.
class Mangelwurzel : public Sproutlet
{
public:
  /// Constructor.
  Mangelwurzel(std::string name,
               int port,
               const std::string& uri) :
    Sproutlet(name, port, uri) {}

  /// Destructor.
  ~Mangelwurzel() {}

  /// Create a MangelwurzelTsx.
  SproutletTsx* get_tsx(SproutletTsxHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req);
};

/// Definition of the MangelwurzelTsx class.
class MangelwurzelTsx : public SproutletTsx
{
public:
  /// Enum defining the valid mangalgorithms mangelwurzel implements.
  enum Mangalgorithm
  {
    ROT_13 = 0,
    REVERSE = 1
  };

  /// Config object for a MangelwurzelTsx. Sets sensible defaults for all the
  /// fields.
  class Config
  {
  public:
    Config() :
      dialog(false),
      req_uri(false),
      to(false),
      change_domain(false),
      routes(false),
      mangalgorithm(ROT_13),
      orig(false),
      ootb(false)
    {}

    ~Config() {}

    /// Whether or not to mangle the dialog identifiers on messages.
    bool dialog;

    /// Whether or not to mangle the Request URI and Contact URI on requests
    /// (and the Contact URI on responses).
    bool req_uri;

    /// Whether or not to mangle the To URI on requests.
    bool to;

    /// Whether or not to mangle the domain of the Request URI, Contact URI and
    /// To URI.
    bool change_domain;

    /// Whether or not to mangle the route-sets.
    bool routes;

    /// Which Mangalgorithm to use for mangling strings.
    Mangalgorithm mangalgorithm;

    /// Whether or not requests should be sent back to the S-CSCF as originating
    /// requests.
    bool orig;

    /// Whether requests should be sent back to the S-CSCF as out of the blue
    /// requests.
    bool ootb;
  };

  /// Constructor.
  MangelwurzelTsx(SproutletTsxHelper* helper, Config& config) :
    SproutletTsx(helper),
    _config(config),
    _unmodified_request(original_request())
  {}

  /// Destructor.
  ~MangelwurzelTsx()
  {
    free_msg(_unmodified_request);
  }

  /// Implementation of SproutletTsx methods in mangelwurzel.
  virtual void on_rx_initial_request(pjsip_msg* req);
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id);
  virtual void on_rx_in_dialog_request(pjsip_msg* req);

private:
  /// The config object for this transaction.
  Config _config;
  pjsip_msg* _unmodified_request;

  /// Helper functions for manipulating SIP messages.
  void mangle_dialog_identifiers(pjsip_msg* req, pj_pool_t* pool);
  void mangle_req_uri(pjsip_msg* req, pj_pool_t* pool);
  void mangle_contact(pjsip_msg* req, pj_pool_t* pool);
  void mangle_to(pjsip_msg* req, pj_pool_t* pool);
  void mangle_uri(pjsip_uri* req, pj_pool_t* pool, bool force_mangle_domain);

  void mangle_record_routes(pjsip_msg* msg, pj_pool_t* pool);
  void mangle_routes(pjsip_msg* msg, pj_pool_t* pool);

  void mangle_string(std::string& str);
  void rot13(std::string& str);
  void reverse(std::string& str);

  void strip_via_hdrs(pjsip_msg* req);
  void add_via_hdrs(pjsip_msg* rsp, pj_pool_t* pool);

  void edit_scscf_route_hdr(pjsip_msg* req, pj_pool_t* pool);

  void record_route(pjsip_msg* req, pj_pool_t* pool, pjsip_uri* uri);
};

#endif
