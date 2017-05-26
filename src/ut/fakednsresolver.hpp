/**
 * @file fakednsresolver.hpp Header file for fake DNS resolver (for testing).
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///----------------------------------------------------------------------------

#include <string>
#include <map>
#include "dnsresolver.h"

/// Fake DNSResolver which returns responses directly from its database.
class FakeDNSResolver : public DNSResolver
{
public:
  inline FakeDNSResolver(const std::vector<struct IP46Address>& servers) : DNSResolver(servers) {};
  virtual int perform_naptr_query(const std::string& domain, struct ares_naptr_reply*& naptr_reply, SAS::TrailId trail);
  virtual void free_naptr_reply(struct ares_naptr_reply* naptr_reply) const;
  // Reset the static data.
  static inline void reset() { _num_calls = 0; _database.clear(); };

  // Number of calls that have been made so far.
  static int _num_calls;
  // Database mapping domain names to NAPTR responses.
  static std::map<std::string,struct ares_naptr_reply*> _database;

};

/// Fake DNSResolverFactory that checks parameters and then creates a
/// FakeDNSResolver.
class FakeDNSResolverFactory : public DNSResolverFactory
{
public:
  virtual DNSResolver* new_resolver(const std::vector<struct IP46Address>& server) const;

  // The server for which we expect to create resolvers.
  static struct IP46Address _expected_server;

};

/// Fake DNSResolver which returns error responses.
class BrokenDNSResolver : public DNSResolver
{
public:
  inline BrokenDNSResolver(const std::vector<struct IP46Address>& servers) : DNSResolver(servers) {};
  virtual int perform_naptr_query(const std::string& domain, struct ares_naptr_reply*& naptr_reply, SAS::TrailId trail);
  virtual void free_naptr_reply(struct ares_naptr_reply* naptr_reply) const;
};

/// Fake DNSResolverFactory that checks parameters and then creates a
/// BrokenDNSResolver.
class BrokenDNSResolverFactory : public DNSResolverFactory
{
public:
  virtual DNSResolver* new_resolver(const std::vector<struct IP46Address>& server) const;

  // The server for which we expect to create resolvers.
  static struct IP46Address _expected_server;

};
