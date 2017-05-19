/**
 * @file dnsresolver.h class definition for a DNS resolver
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///

#ifndef DNSRESOLVER_H__
#define DNSRESOLVER_H__

#include <string>
#include <netinet/in.h>
#include <ares.h>
#include "sas.h"
#include "baseresolver.h"

/// @class DNSResolver
///
/// DNS resolver using the ares library.  Since the ares library is
/// asynchronous but we want to use it synchronously, this also implements the
/// function to wait for events and store off the results.  It is not
/// thread-safe - each thread must have its own DNSResolver.
class DNSResolver
{
public:
  DNSResolver(const std::vector<struct IP46Address>& servers);
  virtual ~DNSResolver();
  // Helper function wrapping the destructor for use as thread-local callbacks.
  static void destroy(DNSResolver* resolver);
  // Perform a NAPTR query for the specified domain, returning the results in
  // the naptr_reply structure, and logging to the trail.  The caller must
  // call free_naptr_reply when it has finished with naptr_reply.
  virtual int perform_naptr_query(const std::string& domain, struct ares_naptr_reply*& naptr_reply, SAS::TrailId trail);
  // Free a naptr_reply structure.
  virtual void free_naptr_reply(struct ares_naptr_reply* naptr_reply) const;

private:
  // Send a query for the specified domain.
  void send_naptr_query(const std::string& domain, SAS::TrailId trail);
  // Wait for a response to the query.
  void wait_for_response();
  // ares callback function - static, wrapping the member function below.
  static void ares_callback(void* arg,
                            int status,
                            int timeouts,
                            unsigned char* abuf,
                            int alen);
  // Handle receiving a NAPTR reply or timeout, and store the results.
  void ares_callback(int status,
                     int timeouts,
                     unsigned char* abuf,
                     int alen);

  // The ares data structure that controls actually making the query.
  ares_channel _channel;
  // Whether a request is pending.
  bool _req_pending;
  // While a request is outstanding, the trail to log to.  When no request is
  // outstanding, 0.
  SAS::TrailId _trail;
  // While a request is outstanding, the domain that was queried (used for
  // logging).  When no request is outstanding, the empty string.
  std::string _domain;
  // The status of the last query.  Only valid between ares_callback and
  // perform_naptr_query returning.
  int _status;
  // The reply data structure.  Only valid between ares_callback and
  // perform_naptr_query returning, and only if _status is ARES_SUCCESS.
  struct ares_naptr_reply* _naptr_reply;
  // Pointer to a linked list of servers
  struct ares_addr_node _ares_addrs[3];

};

/// @class DNSResolverFactory
///
/// Factory class for DNSResolvers.  Only really used to allow dependency
/// injection (and hence UT) of the DNSEnumService class.
class DNSResolverFactory
{
public:
  inline DNSResolverFactory() {};
  virtual ~DNSResolverFactory() {}
  // Create a new resolver.
  virtual DNSResolver* new_resolver(const std::vector<struct IP46Address>& servers) const;

};

#endif
