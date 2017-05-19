/**
 * @file sipresolver_test.cpp UT for SIPResolver class.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "dnscachedresolver.h"
#include "sipresolver.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

/// Fixture for SIPResolverTest.
class SIPResolverTest : public ::testing::Test
{
  DnsCachedResolver _dnsresolver;
  SIPResolver _sipresolver;

  // DNS Resolver is created with server address 0.0.0.0 to disable server
  // queries.
  SIPResolverTest() :
    _dnsresolver("0.0.0.0"),
    _sipresolver(&_dnsresolver)
  {
  }

  virtual ~SIPResolverTest()
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
class RT
{
public:
  RT(SIPResolver& resolver, const std::string& name) :
    _resolver(resolver),
    _name(name),
    _port(0),
    _transport(-1),
    _af(AF_INET)
  {
  }

  RT& set_port(int port)
  {
    _port = port;
    return *this;
  }

  RT& set_transport(int transport)
  {
    _transport = transport;
    return *this;
  }

  RT& set_af(int af)
  {
    _af = af;
    return *this;
  }

  std::string resolve()
  {
    SCOPED_TRACE(_name);
    std::vector<AddrInfo> targets;
    std::string output;

    _resolver.resolve(_name, _af, _port, _transport, 1, targets, 0);
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
    oss << ";transport=";
    if (ai.transport == IPPROTO_UDP)
    {
      oss << "UDP";
    }
    else if (ai.transport == IPPROTO_TCP)
    {
      oss << "TCP";
    }
    else
    {
      oss << "Unknown (" << ai.transport << ")";
    }
    return oss.str();
  }

  /// Reference to the SIPResolver.
  SIPResolver& _resolver;

  /// Input parameters to request.
  std::string _name;
  int _port;
  int _transport;
  int _af;
};

TEST_F(SIPResolverTest, IPv4AddressResolution)
{
  // Test defaulting of port and transport when target is IP address
  EXPECT_EQ("3.0.0.1:5060;transport=UDP",
            RT(_sipresolver, "3.0.0.1").resolve());

  // Test defaulting of port when target is IP address
  EXPECT_EQ("3.0.0.2:5060;transport=TCP",
            RT(_sipresolver, "3.0.0.2").set_transport(IPPROTO_TCP).resolve());

  // Test defaulting of transport when target is IP address
  EXPECT_EQ("3.0.0.3:5054;transport=UDP",
            RT(_sipresolver, "3.0.0.3").set_port(5054).resolve());

  // Test specifying both port and transport when target is IP address
  EXPECT_EQ("3.0.0.4:5052;transport=TCP",
            RT(_sipresolver, "3.0.0.4").set_port(5052).set_transport(IPPROTO_TCP).resolve());
}

TEST_F(SIPResolverTest, IPv6AddressResolution)
{
  // Test defaulting of port and transport when target is IP address
  EXPECT_EQ("[3::1]:5060;transport=UDP",
            RT(_sipresolver, "3::1").set_af(AF_INET6).resolve());

  // Test defaulting of port when target is IP address
  EXPECT_EQ("[3::2]:5060;transport=TCP",
            RT(_sipresolver, "3::2").set_transport(IPPROTO_TCP).set_af(AF_INET6).resolve());

  // Test defaulting of transport when target is IP address
  EXPECT_EQ("[3::3]:5054;transport=UDP",
            RT(_sipresolver, "3::3").set_port(5054).set_af(AF_INET6).resolve());

  // Test specifying both port and transport when target is IP address
  EXPECT_EQ("[3::4]:5052;transport=TCP",
            RT(_sipresolver, "3::4").set_port(5052).set_transport(IPPROTO_TCP).set_af(AF_INET6).resolve());
}

TEST_F(SIPResolverTest, SimpleNAPTRSRVTCPResolution)
{
  // Test selection of TCP transport and port using NAPTR and SRV records.
  std::vector<DnsRRecord*> records;
  records.push_back(naptr("sprout.cw-ngv.com", 3600, 0, 0, "S", "SIP+D2T", "", "_sip._tcp.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_naptr, records);

  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 0, 5054, "sprout-1.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._tcp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  EXPECT_EQ("3.0.0.1:5054;transport=TCP",
            RT(_sipresolver, "sprout.cw-ngv.com").resolve());
}

TEST_F(SIPResolverTest, SimpleNAPTRSRVUDPResolution)
{
  // Test selection of UDP transport and port using NAPTR and SRV records (with lowercase s).
  std::vector<DnsRRecord*> records;
  records.push_back(naptr("sprout.cw-ngv.com", 3600, 0, 0, "s", "SIP+D2U", "", "_sip._udp.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_naptr, records);

  records.push_back(srv("_sip._udp.sprout.cw-ngv.com", 3600, 0, 0, 5054, "sprout-1.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._udp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  EXPECT_EQ("3.0.0.1:5054;transport=UDP",
            RT(_sipresolver, "sprout.cw-ngv.com").resolve());
}

TEST_F(SIPResolverTest, SimpleSRVTCPResolution)
{
  // Test selection of TCP transport and port using SRV records only
  std::vector<DnsRRecord*> records;
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 0, 5054, "sprout-1.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._tcp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  EXPECT_EQ("3.0.0.1:5054;transport=TCP",
            RT(_sipresolver, "sprout.cw-ngv.com").resolve());
}

TEST_F(SIPResolverTest, SimpleSRVUDPResolution)
{
  // Test selection of UDP transport and port using SRV records only
  std::vector<DnsRRecord*> records;
  records.push_back(srv("_sip._udp.sprout.cw-ngv.com", 3600, 0, 0, 5054, "sprout-1.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._udp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  EXPECT_EQ("3.0.0.1:5054;transport=UDP",
            RT(_sipresolver, "sprout.cw-ngv.com").resolve());
}

TEST_F(SIPResolverTest, SimpleSRVUDPPreference)
{
  // Test preference for UDP transport over TCP transport if both configure in SRV.
  std::vector<DnsRRecord*> records;
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 0, 5054, "sprout-1.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._tcp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(srv("_sip._udp.sprout.cw-ngv.com", 3600, 0, 0, 5054, "sprout-1.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._udp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  EXPECT_EQ("3.0.0.1:5054;transport=UDP",
            RT(_sipresolver, "sprout.cw-ngv.com").resolve());
}

TEST_F(SIPResolverTest, SimpleAResolution)
{
  // Test resolution using A records only.
  std::vector<DnsRRecord*> records;
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  // Test default port/transport.
  EXPECT_EQ("3.0.0.1:5060;transport=UDP",
            RT(_sipresolver, "sprout.cw-ngv.com").resolve());

  // Test overriding port.
  EXPECT_EQ("3.0.0.1:5054;transport=UDP",
            RT(_sipresolver, "sprout.cw-ngv.com").set_port(5054).resolve());

  // Test overriding transport.
  EXPECT_EQ("3.0.0.1:5060;transport=TCP",
            RT(_sipresolver, "sprout.cw-ngv.com").set_transport(IPPROTO_TCP).resolve());

  // Test overriding port and transport.
  EXPECT_EQ("3.0.0.1:5054;transport=TCP",
            RT(_sipresolver, "sprout.cw-ngv.com").set_port(5054).set_transport(IPPROTO_TCP).resolve());
}

// This unit test doesn't assert anything - it tests for a bug where
// DNS expiry triggered invalid memory accesses, which will show up in
// the Valgrind output
TEST_F(SIPResolverTest, Expiry)
{
  cwtest_completely_control_time();
  std::vector<DnsRRecord*> udp_records;
  std::vector<DnsRRecord*> tcp_records;
  udp_records.push_back(a("sprout.cw-ngv.com", 5, "3.0.0.1"));
  tcp_records.push_back(a("sprout.cw-ngv.com", 2, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, udp_records);
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, tcp_records);
  ASSERT_NE("", _dnsresolver.display_cache());

  cwtest_advance_time_ms(1000);
  _dnsresolver.expire_cache();
  ASSERT_NE("", _dnsresolver.display_cache());

  // Cached records should be available for 5 minutes past their TTL
  // to protect against DNS server failure
  cwtest_advance_time_ms(2000);
  _dnsresolver.expire_cache();
  ASSERT_NE("", _dnsresolver.display_cache());

  cwtest_advance_time_ms(300000);
  _dnsresolver.expire_cache();
  ASSERT_EQ("", _dnsresolver.display_cache());

  cwtest_reset_time();
}


// This unit test doesn't assert anything - it tests for a bug where
// DNS expiry triggered invalid memory accesses, which will show up in
// the Valgrind output
TEST_F(SIPResolverTest, ExpiryNoInvalidRead)
{
  cwtest_completely_control_time();
  // Test resolution using A records only.
  std::vector<DnsRRecord*> udp_records;
  std::vector<DnsRRecord*> tcp_records;
  udp_records.push_back(a("sprout.cw-ngv.com", 2, "3.0.0.1"));
  tcp_records.push_back(a("sprout.cw-ngv.com", 2, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, udp_records);
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, tcp_records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());
  cwtest_advance_time_ms(3000);
  _dnsresolver.expire_cache();
  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());
  cwtest_reset_time();
}

TEST_F(SIPResolverTest, SimpleAAAAResolution)
{
  // Test resolution using AAAA records only.
  std::vector<DnsRRecord*> records;
  records.push_back(aaaa("sprout.cw-ngv.com", 3600, "3::1"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_aaaa, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  // Test default port/transport.
  EXPECT_EQ("[3::1]:5060;transport=UDP",
            RT(_sipresolver, "sprout.cw-ngv.com").set_af(AF_INET6).resolve());

  // Test overriding port.
  EXPECT_EQ("[3::1]:5054;transport=UDP",
            RT(_sipresolver, "sprout.cw-ngv.com").set_af(AF_INET6).set_port(5054).resolve());

  // Test overriding transport.
  EXPECT_EQ("[3::1]:5060;transport=TCP",
            RT(_sipresolver, "sprout.cw-ngv.com").set_af(AF_INET6).set_transport(IPPROTO_TCP).resolve());

  // Test overriding port and transport.
  EXPECT_EQ("[3::1]:5054;transport=TCP",
            RT(_sipresolver, "sprout.cw-ngv.com").set_af(AF_INET6).set_port(5054).set_transport(IPPROTO_TCP).resolve());
}

TEST_F(SIPResolverTest, NAPTROrderPreference)
{
  // Test NAPTR selection according to order - select TCP as first in order.
  std::vector<DnsRRecord*> records;
  records.push_back(naptr("sprout-1.cw-ngv.com", 3600, 1, 0, "S", "SIP+D2T", "", "_sip._tcp.sprout.cw-ngv.com"));
  records.push_back(naptr("sprout-1.cw-ngv.com", 3600, 2, 0, "S", "SIP+D2U", "", "_sip._udp.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_naptr, records);

  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 0, 5054, "sprout-1.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._tcp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(srv("_sip._udp.sprout.cw-ngv.com", 3600, 0, 0, 5054, "sprout-1.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._udp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  EXPECT_EQ("3.0.0.1:5054;transport=TCP",
            RT(_sipresolver, "sprout-1.cw-ngv.com").resolve());

  // Test NAPTR selection according to preference - select UDP as first in preference.
  records.push_back(naptr("sprout-2.cw-ngv.com", 3600, 0, 2, "S", "SIP+D2T", "", "_sip._tcp.sprout.cw-ngv.com"));
  records.push_back(naptr("sprout-2.cw-ngv.com", 3600, 0, 1, "S", "SIP+D2U", "", "_sip._udp.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("sprout-2.cw-ngv.com", ns_t_naptr, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  EXPECT_EQ("3.0.0.1:5054;transport=UDP",
            RT(_sipresolver, "sprout-2.cw-ngv.com").resolve());
}

TEST_F(SIPResolverTest, SRVPriority)
{
  // Test SRV selection according to priority.
  std::vector<DnsRRecord*> records;
  records.push_back(naptr("sprout.cw-ngv.com", 3600, 0, 0, "S", "SIP+D2T", "", "_sip._tcp.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_naptr, records);

  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 1, 0, 5054, "sprout-1.cw-ngv.com"));
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 2, 0, 5054, "sprout-2.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._tcp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);
  records.push_back(a("sprout-2.cw-ngv.com", 3600, "3.0.0.2"));
  _dnsresolver.add_to_cache("sprout-2.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  // Do 100 resolutions and check that sprout-1 is picked every time.
  std::map<std::string, int> counts;

  for (int ii = 0; ii < 100; ++ii)
  {
    counts[RT(_sipresolver, "sprout.cw-ngv.com").resolve()]++;
  }

  EXPECT_EQ(100, counts["3.0.0.1:5054;transport=TCP"]);
  EXPECT_EQ(0, counts["3.0.0.2:5054;transport=TCP"]);
}

TEST_F(SIPResolverTest, SRVWeight)
{
  // Test SRV selection according to weight.
  std::vector<DnsRRecord*> records;
  records.push_back(naptr("sprout.cw-ngv.com", 3600, 0, 0, "S", "SIP+D2T", "", "_sip._tcp.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_naptr, records);

  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 100, 5054, "sprout-1.cw-ngv.com"));
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 300, 5054, "sprout-2.cw-ngv.com"));
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 200, 5054, "sprout-3.cw-ngv.com"));
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 400, 5054, "sprout-4.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._tcp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);
  records.push_back(a("sprout-2.cw-ngv.com", 3600, "3.0.0.2"));
  _dnsresolver.add_to_cache("sprout-2.cw-ngv.com", ns_t_a, records);
  records.push_back(a("sprout-3.cw-ngv.com", 3600, "3.0.0.3"));
  _dnsresolver.add_to_cache("sprout-3.cw-ngv.com", ns_t_a, records);
  records.push_back(a("sprout-4.cw-ngv.com", 3600, "3.0.0.4"));
  _dnsresolver.add_to_cache("sprout-4.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  // Do 1000 resolutions and check that the proportions are roughly as
  // expected.  The error bound is chosen to be 5 standard deviations.
  std::map<std::string, int> counts;

  for (int ii = 0; ii < 1000; ++ii)
  {
    counts[RT(_sipresolver, "sprout.cw-ngv.com").resolve()]++;
  }

  EXPECT_LT(100-5*9, counts["3.0.0.1:5054;transport=TCP"]);
  EXPECT_GT(100+5*9, counts["3.0.0.1:5054;transport=TCP"]);
  EXPECT_LT(300-5*14, counts["3.0.0.2:5054;transport=TCP"]);
  EXPECT_GT(300+5*14, counts["3.0.0.2:5054;transport=TCP"]);
  EXPECT_LT(200-5*13, counts["3.0.0.3:5054;transport=TCP"]);
  EXPECT_GT(200+5*13, counts["3.0.0.3:5054;transport=TCP"]);
  EXPECT_LT(400-5*15, counts["3.0.0.4:5054;transport=TCP"]);
  EXPECT_GT(400+5*15, counts["3.0.0.4:5054;transport=TCP"]);
}

TEST_F(SIPResolverTest, ARecordLoadBalancing)
{
  // Test load balancing across multiple A records.
  std::vector<DnsRRecord*> records;
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.1"));
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.2"));
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.3"));
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.4"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  // Do 10000 resolutions and check that the proportions are roughly even
  // The error bound is chosen to be 5 standard deviations.
  std::map<std::string, int> counts;

  for (int ii = 0; ii < 1000; ++ii)
  {
    counts[RT(_sipresolver, "sprout.cw-ngv.com").resolve()]++;
  }

  EXPECT_LT(250-5*14, counts["3.0.0.1:5060;transport=UDP"]);
  EXPECT_GT(250+5*14, counts["3.0.0.1:5060;transport=UDP"]);
  EXPECT_LT(250-5*14, counts["3.0.0.2:5060;transport=UDP"]);
  EXPECT_GT(250+5*14, counts["3.0.0.2:5060;transport=UDP"]);
  EXPECT_LT(250-5*14, counts["3.0.0.3:5060;transport=UDP"]);
  EXPECT_GT(250+5*14, counts["3.0.0.3:5060;transport=UDP"]);
  EXPECT_LT(250-5*14, counts["3.0.0.4:5060;transport=UDP"]);
  EXPECT_GT(250+5*14, counts["3.0.0.4:5060;transport=UDP"]);
}

TEST_F(SIPResolverTest, BlacklistSRVRecords)
{
  // Test blacklist of SRV selections.
  std::vector<DnsRRecord*> records;
  records.push_back(naptr("sprout.cw-ngv.com", 3600, 0, 0, "S", "SIP+D2T", "", "_sip._tcp.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_naptr, records);

  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 100, 5054, "sprout-1.cw-ngv.com"));
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 300, 5054, "sprout-2.cw-ngv.com"));
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 200, 5054, "sprout-3.cw-ngv.com"));
  records.push_back(srv("_sip._tcp.sprout.cw-ngv.com", 3600, 0, 400, 5054, "sprout-4.cw-ngv.com"));
  _dnsresolver.add_to_cache("_sip._tcp.sprout.cw-ngv.com", ns_t_srv, records);

  records.push_back(a("sprout-1.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("sprout-1.cw-ngv.com", ns_t_a, records);
  records.push_back(a("sprout-2.cw-ngv.com", 3600, "3.0.0.2"));
  _dnsresolver.add_to_cache("sprout-2.cw-ngv.com", ns_t_a, records);
  records.push_back(a("sprout-3.cw-ngv.com", 3600, "3.0.0.3"));
  _dnsresolver.add_to_cache("sprout-3.cw-ngv.com", ns_t_a, records);
  records.push_back(a("sprout-4.cw-ngv.com", 3600, "3.0.0.4"));
  _dnsresolver.add_to_cache("sprout-4.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  // Blacklist 3.0.0.4.
  AddrInfo ai;
  ai.address.af = AF_INET;
  inet_pton(AF_INET, "3.0.0.4", &ai.address.addr.ipv4);
  ai.port = 5054;
  ai.transport = IPPROTO_TCP;
  _sipresolver.blacklist(ai, 300);

  // Do 1000 resolutions and check that 3.0.0.4 is never selected and the
  // proportions of the other addresses are as expected.  The error bounds are
  // chosen to be 5 standard deviations.
  std::map<std::string, int> counts;

  for (int ii = 0; ii < 1000; ++ii)
  {
    counts[RT(_sipresolver, "sprout.cw-ngv.com").resolve()]++;
  }

  EXPECT_EQ(0, counts["3.0.0.4:5054;transport=TCP"]);
  EXPECT_LT(167-5*12, counts["3.0.0.1:5054;transport=TCP"]);
  EXPECT_GT(167+5*12, counts["3.0.0.1:5054;transport=TCP"]);
  EXPECT_LT(500-5*16, counts["3.0.0.2:5054;transport=TCP"]);
  EXPECT_GT(500+5*16, counts["3.0.0.2:5054;transport=TCP"]);
  EXPECT_LT(333-5*15, counts["3.0.0.3:5054;transport=TCP"]);
  EXPECT_GT(333+5*15, counts["3.0.0.3:5054;transport=TCP"]);
}

TEST_F(SIPResolverTest, BlacklistARecord)
{
  // Test blacklisting of an A record.
  std::vector<DnsRRecord*> records;
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.1"));
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.2"));
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.3"));
  records.push_back(a("sprout.cw-ngv.com", 3600, "3.0.0.4"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  // Blacklist 3.0.0.3.
  AddrInfo ai;
  ai.address.af = AF_INET;
  inet_pton(AF_INET, "3.0.0.3", &ai.address.addr.ipv4);
  ai.port = 5060;
  ai.transport = IPPROTO_UDP;
  _sipresolver.blacklist(ai, 300);

  // Do 1000 resolutions and check that 3.0.0.3 is not selected, and that
  // the other addresses are selected roughly equally.
  std::map<std::string, int> counts;

  for (int ii = 0; ii < 1000; ++ii)
  {
    counts[RT(_sipresolver, "sprout.cw-ngv.com").resolve()]++;
  }

  EXPECT_EQ(0, counts["3.0.0.3:5060;transport=UDP"]);
  EXPECT_LT(333-5*15, counts["3.0.0.1:5060;transport=UDP"]);
  EXPECT_GT(333+5*15, counts["3.0.0.1:5060;transport=UDP"]);
  EXPECT_LT(333-5*15, counts["3.0.0.2:5060;transport=UDP"]);
  EXPECT_GT(333+5*15, counts["3.0.0.2:5060;transport=UDP"]);
  EXPECT_LT(333-5*15, counts["3.0.0.4:5060;transport=UDP"]);
  EXPECT_GT(333+5*15, counts["3.0.0.4:5060;transport=UDP"]);
}

// Test receiving a NAPTR response that doesn't contain a SIP service
// Repros https://github.com/Metaswitch/homestead/issues/94
TEST_F(SIPResolverTest, NoMatchingNAPTR)
{
  // Add a NAPTR record for an invalid service.  This should be ignored.
  std::vector<DnsRRecord*> records;
  records.push_back(naptr("sprout.cw-ngv.com", 3600, 0, 0, "S", "BAD", "", "bad.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_naptr, records);

  // Add SRV and A record so that if the NAPTR wasn't ignored, we'd resolve to 3.0.0.1.
  records.push_back(srv("bad.sprout.cw-ngv.com", 3600, 0, 0, 5054, "bad.sprout.cw-ngv.com"));
  _dnsresolver.add_to_cache("bad.sprout.cw-ngv.com", ns_t_srv, records);
  records.push_back(a("bad.sprout.cw-ngv.com", 3600, "3.0.0.1"));
  _dnsresolver.add_to_cache("bad.sprout.cw-ngv.com", ns_t_a, records);

  // Add a default A record that we should resolve to instead (4.0.0.1).
  records.push_back(a("sprout.cw-ngv.com", 3600, "4.0.0.1"));
  _dnsresolver.add_to_cache("sprout.cw-ngv.com", ns_t_a, records);

  TRC_DEBUG("Cache status\n%s", _dnsresolver.display_cache().c_str());

  EXPECT_EQ("4.0.0.1:5060;transport=UDP",
            RT(_sipresolver, "sprout.cw-ngv.com").resolve());
}
