/**
 * @file fakednsresolver.cpp Fake DNS resolver (for testing).
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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
struct IP46Address FakeDNSResolverFactory::_expected_server = {AF_INET, {{htonl(0x7f000001)}}};


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


DNSResolver* FakeDNSResolverFactory::new_resolver(const std::vector<struct IP46Address>& servers) const
{
  // Check the server is as expected and then construct a FakeDNSResolver.
  EXPECT_TRUE(servers[0].compare(_expected_server) == 0);
  return new FakeDNSResolver(servers);
}

int BrokenDNSResolver::perform_naptr_query(const std::string& domain, struct ares_naptr_reply*& naptr_reply, SAS::TrailId trail)
{
  return ARES_ESERVFAIL;
}


void BrokenDNSResolver::free_naptr_reply(struct ares_naptr_reply* naptr_reply) const
{
}


DNSResolver* BrokenDNSResolverFactory::new_resolver(const std::vector<struct IP46Address>& servers) const
{
  return new BrokenDNSResolver(servers);
}
