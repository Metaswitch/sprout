/**
 * @file mangelwurzel.h Mangelwurzel class definitions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail);
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
  MangelwurzelTsx(Mangelwurzel* mangelwurzel, Config& config) :
    SproutletTsx(mangelwurzel),
    _config(config),
    _unmodified_request(NULL)
  {}

  /// Destructor.
  ~MangelwurzelTsx()
  {
    if (_unmodified_request != NULL)
    {
      free_msg(_unmodified_request);
    }
  }

  /// Implementation of SproutletTsx methods in mangelwurzel.
  virtual void on_rx_initial_request(pjsip_msg* req);
  virtual void on_rx_response(pjsip_msg* rsp, int fork_id);
  virtual void on_rx_in_dialog_request(pjsip_msg* req);

private:
  /// The config object for this transaction.
  Config _config;

  /// The original request that started this transaction.
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
