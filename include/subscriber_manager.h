/**
 * @file subscriber_manager.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef SUBSCRIBER_MANAGER_H__
#define SUBSCRIBER_MANAGER_H__

extern "C" {
#include <pjsip.h>
}

#include <string>
#include <list>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "sas.h"
#include "analyticslogger.h"
#include "associated_uris.h"
#include "hssconnection.h"
#include "ifchandler.h"

class SubscriberManager
{
public:
  enum EventTrigger
  {
    USER,
    ADMIN
  };

  class Binding
  {
  public:
    Binding(std::string binding_id): _uri(binding_id) {};

    /// This is binding ID.
    /// The registered contact URI, e.g.,
    /// "sip:2125551212@192.168.0.1:55491;transport=TCP;rinstance=fad34fbcdea6a931"
    std::string _uri;

    /// The Call-ID: of the registration.  Per RFC3261, this is the same for
    /// all registrations from a given UAC to this registrar (for this AoR).
    /// E.g., "gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"
    std::string _cid;

    /// Contains any path headers (in order) that were present on the
    /// register.  Empty if there were none. This is the full path header,
    /// including the disply name, URI and any header parameters.
    std::list<std::string> _path_headers;

    /// The CSeq value of the REGISTER request.
    int _cseq;

    /// The time (in seconds since the epoch) at which this binding should
    /// expire. Based on the expires parameter of the Contact: header.
    int _expires;

    /// The Contact: header q parameter (qvalue), times 1000.  This is used
    /// to prioritise the registrations (highest value first), per RFC3261
    /// s10.2.1.2.
    int _priority;

    /// Any other parameters found in the Contact: header, stored as key ->
    /// value.  E.g., "+sip.ice" -> "".
    std::map<std::string, std::string> _params;

    /// The private ID this binding was registered with.
    std::string _private_id;

    /// Whether this is an emergency registration.
    bool _emergency_registration;

    /// Returns the ID of this binding.
    std::string get_id() const { return _uri; }

    pjsip_sip_uri* pub_gruu(pj_pool_t* pool) const { return NULL; }
    std::string pub_gruu_str(pj_pool_t* pool) const { return std::string(); }
    std::string pub_gruu_quoted_string(pj_pool_t* pool) const { return std::string(); }
  };

  class Subscription
  {
  public:
    Subscription(std::string subscription_id): _to_tag(subscription_id), _refreshed(false) {};

    /// The Contact URI for the subscription dialog (used as the Request URI
    /// of the NOTIFY)
    std::string _req_uri;

    /// The From URI for the subscription dialog (used in the to header of
    /// the NOTIFY)
    std::string _from_uri;

    /// The From tag for the subscription dialog.
    std::string _from_tag;

    /// The To URI for the subscription dialog.
    std::string _to_uri;

    /// This is the subscription ID.
    /// The To tag for the subscription dialog.
    std::string _to_tag;

    /// The call ID for the subscription dialog.
    std::string _cid;

    /// Whether the subscription has been refreshed since the last NOTIFY.
    bool _refreshed;

    /// The list of Record Route URIs from the subscription dialog.
    std::list<std::string> _route_uris;

    /// The time (in seconds since the epoch) at which this subscription
    /// should expire.
    int _expires;

    /// The current NOTIFY CSeq value.
    int _cseq;

    /// Returns the ID of this subscription.
    std::string get_id() const { return _to_tag; }
  };

  struct SubscriberInfo
  {
    std::string _regstate;
    std::string _prev_regstate;
    std::map<std::string, Ifcs> _service_profiles;
    AssociatedURIs _associated_uris;
    std::vector<std::string> _aliases;
    std::deque<std::string> _ccfs;
    std::deque<std::string> _ecfs;

    SubscriberInfo() :
      _regstate(""),
      _prev_regstate(""),
      _service_profiles(),
      _associated_uris({}),
      _aliases(),
      _ccfs(),
      _ecfs()
    {
    }
  };

  /// SubscriberManager constructor.
  ///
  /// @param s4                 - Pointer to the underlying data store interface
  ///                             SDM-REFACTOR-TODO: We don't know what this looks like yet. Add it in when we do.
  /// @param hss_connection     -
  /// @param analytics_logger   - AnalyticsLogger for reporting registration events
  SubscriberManager(HSSConnection* hss_connection,
                    AnalyticsLogger* analytics_logger);

  /// Destructor.
  virtual ~SubscriberManager();

  bool update_binding(const Binding& binding,
                      std::vector<Binding>& bindings,
                      SAS::TrailId trail) { return true; }

  bool remove_bindings(std::vector<std::string> binding_ids,
                       EventTrigger event_trigger,
                       std::vector<Binding>& bindings,
                       SAS::TrailId trail) { return true; }

  bool update_subscription(const Subscription& subscription,
                           SAS::TrailId trail) { return true; }

  bool remove_subscription(std::string subscription_id,
                           SAS::TrailId trail) { return true; }

  bool deregister_subscriber(std::string public_id,
                             EventTrigger event_trigger,
                             SAS::TrailId trail) { return true; }

  bool get_bindings(std::string public_id,
                    std::vector<Binding>& bindings,
                    SAS::TrailId trail) { return true; }

  bool get_subscriber_state(std::string public_id,
                            SubscriberInfo& subscriber_info,
                            SAS::TrailId trail) { return true; }

private:
  AnalyticsLogger* _analytics;
  HSSConnection* _hss_connection;
};

#endif
