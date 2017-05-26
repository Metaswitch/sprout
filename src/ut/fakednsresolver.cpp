/**
 * @file fakednsresolver.cpp Fake DNS resolver (for testing).
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
