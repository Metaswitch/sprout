/**
 * @file fakednsresolver.cpp Fake DNS resolver (for testing).
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

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include "gtest/gtest.h"

#include "fakednsresolver.hpp"


int FakeDNSResolver::_num_calls = 0;
std::map<std::string,struct ares_naptr_reply*> FakeDNSResolver::_database = std::map<std::string,struct ares_naptr_reply*>();
// By default, expect requests for 127.0.0.1.
struct in_addr FakeDNSResolverFactory::_expected_server = {htonl(0x7f000001)};


int FakeDNSResolver::perform_naptr_query(const std::string& domain, struct ares_naptr_reply*& naptr_reply, SAS::TrailId trail)
{
  ++_num_calls;
  // Look up the query domain and return the reply if found.
  std::map<std::string,struct ares_naptr_reply*>::iterator i = _database.find(domain);
  if (i != _database.end())
  {
    naptr_reply = i->second;
    return ARES_SUCCESS;
  }
  else
  {
    naptr_reply = NULL;
    return ARES_ENOTFOUND;
  }
}


void FakeDNSResolver::free_naptr_reply(struct ares_naptr_reply* naptr_reply) const
{
}


DNSResolver* FakeDNSResolverFactory::new_resolver(const struct in_addr* server) const
{
  // Check the server is as expected and then construct a FakeDNSResolver.
  EXPECT_TRUE(memcmp(server, &_expected_server, sizeof(struct in_addr)) == 0);
  return new FakeDNSResolver(server);
}
