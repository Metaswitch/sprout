/**
 * @file sipresolver_test.cpp UT for SIPResolver class.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "dnscachedresolver.h"
#include "httpresolver.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

/// Fixture for SIPResolverTest.
class HTTPResolverTest : public ::testing::Test
{
  DnsCachedResolver _dnsresolver;
  HttpResolver _httpresolver;

  // DNS Resolver is created with server address 0.0.0.0 to disable server
  // queries.
  HTTPResolverTest() :
    _dnsresolver("0.0.0.0"),
    _httpresolver(&_dnsresolver, AF_INET)
  {
  }

  virtual ~HTTPResolverTest()
  {
  }

  DnsRRecord* a(const std::string& name,
                int ttl,
                const std::string& address)
  {
    struct in_addr addr;
    inet_pton(AF_INET, address.c_str(), &addr);
    return (DnsRRecord*)new DnsARecord(name, ttl, addr);
  }

  DnsRRecord* aaaa(const std::string& name,
                   int ttl,
                   const std::string& address)
  {
    struct in6_addr addr;
    inet_pton(AF_INET6, address.c_str(), &addr);
    return (DnsRRecord*)new DnsAAAARecord(name, ttl, addr);
  }

  DnsRRecord* srv(const std::string& name,
                  int ttl,
                  int priority,
                  int weight,
                  int port,
                  const std::string& target)
  {
    return (DnsRRecord*)new DnsSrvRecord(name, ttl, priority, weight, port, target);
  }

  DnsRRecord* naptr(const std::string& name,
                    int ttl,
                    int order,
                    int preference,
                    const std::string& flags,
                    const std::string& service,
                    const std::string& regex,
                    const std::string& replacement)
  {
    return (DnsRRecord*)new DnsNaptrRecord(name, ttl, order, preference, flags,
                                           service, regex, replacement);
  }
};

/// A single resolver operation.
class HttpRT
{
public:
  HttpRT(HttpResolver& resolver, const std::string& name) :
    _resolver(resolver),
    _name(name),
    _port(0),
    _transport(-1),
    _af(AF_INET)
  {
  }

  HttpRT& set_port(int port)
  {
    _port = port;
    return *this;
  }

  HttpRT& set_transport(int transport)
  {
    _transport = transport;
    return *this;
  }

  HttpRT& set_af(int af)
  {
    _af = af;
    return *this;
  }

  std::string resolve(int port)
  {
    SCOPED_TRACE(_name);
    std::vector<AddrInfo> targets;
    std::string output;

    _resolver.resolve(_name, port, 1, targets, 0);
    if (!targets.empty())
    {
      // Successful, so render AddrInfo as a string.
      output = addrinfo_to_string(targets[0]);
    }
    return output;
  }

private:
  std::string addrinfo_to_string(const AddrInfo& ai) const
  {
    ostringstream oss;
    char buf[100];
    if (ai.address.af == AF_INET6)
    {
      oss << "[";
    }
    oss << inet_ntop(ai.address.af, &ai.address.addr, buf, sizeof(buf));
    if (ai.address.af == AF_INET6)
    {
      oss << "]";
    }
    oss << ":" << ai.port;
    assert(ai.transport == IPPROTO_TCP);
    return oss.str();
  }

  /// Reference to the SIPResolver.
  HttpResolver& _resolver;

  /// Input parameters to request.
  std::string _name;
  int _port;
  int _transport;
  int _af;
};

TEST_F(HTTPResolverTest, IPv4AddressResolution)
{
  // Test defaulting of port and transport when target is IP address
  EXPECT_EQ("3.0.0.1:80",
            HttpRT(_httpresolver, "3.0.0.1").resolve(0));
}

TEST_F(HTTPResolverTest, DNSResolution)
{
  // Test selection of TCP transport and port using NAPTR and SRV records.
  std::vector<DnsRRecord*> records;
  records.push_back(a("sprout.cw-ngv.com", 3600, "1.2.3.4"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, records);

  EXPECT_EQ("1.2.3.4:7888",
            HttpRT(_httpresolver, "sprout.cw-ngv.com").resolve(7888));


}
