/**
 * @file sipresolver.h  Declaration of SIP DNS resolver class.
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef SIPRESOLVER_H__
#define SIPRESOLVER_H__

#include "baseresolver.h"
#include "sas.h"

class SIPResolver : public BaseResolver
{
public:
  SIPResolver(DnsCachedResolver* dns_client,
              int blacklist_duration = DEFAULT_BLACKLIST_DURATION,
              int graylist_duration = DEFAULT_GRAYLIST_DURATION);
  ~SIPResolver();

  void resolve(const std::string& name,
               int af,
               int port,
               int transport,
               int retries,
               std::vector<AddrInfo>& targets,
               int allowed_host_state,
               SAS::TrailId trail = 0);

  BaseAddrIterator* resolve_iter(const std::string& name,
                                 int af,
                                 int port,
                                 int transport,
                                 int allowed_host_state,
                                 SAS::TrailId trail = 0);

  /// Default duration to blacklist hosts after we fail to connect to them.
  static const int DEFAULT_BLACKLIST_DURATION = 30;

  /// Default duration to graylist hosts after they have timed out of the
  /// blacklist.
  static const int DEFAULT_GRAYLIST_DURATION = 30;

  std::string get_transport_str(int transport);
};

#endif
