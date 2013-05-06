/**
 * @file fakednsresolver.hpp Header file for fake DNS resolver (for testing).
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
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
  inline FakeDNSResolver(const struct in_addr* server) : DNSResolver(server) {};
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
  virtual DNSResolver* new_resolver(const struct in_addr* server) const;

  // The server for which we expect to create resolvers.
  static struct in_addr _expected_server;

};
