/**
 * @file enumservice_test.cpp UT for Sprout ENUM service.
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

#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "enumservice.h"
#include "fakednsresolver.hpp"
#include "fakelogger.h"
#include "test_utils.hpp"
#include "mockcommunicationmonitor.h"

using namespace std;
using ::testing::_;

/// Fixture for EnumServiceTest.
class EnumServiceTest : public ::testing::Test
{
  EnumServiceTest()
  {
    FakeDNSResolver::reset();
    FakeDNSResolverFactory::_expected_server.af = AF_INET;
    FakeDNSResolverFactory::_expected_server.addr.ipv4.s_addr = htonl(0x7f000001);
  }

  virtual ~EnumServiceTest()
  {
  }
};

class JSONEnumServiceTest : public EnumServiceTest {};
class DNSEnumServiceTest : public EnumServiceTest
{
  DNSEnumServiceTest() : EnumServiceTest()
  {
    _servers.push_back("127.0.0.1");
    _different_servers.push_back("1.2.3.4");
    _ipv6_servers.push_back("0102:0304:0506:0708:090a:0b0c:0d0e:0f10");
    _bad_servers.push_back("foobar");
  }
private:
  std::vector<std::string> _servers;
  std::vector<std::string> _different_servers;
  std::vector<std::string> _ipv6_servers;
  std::vector<std::string> _bad_servers;
};

/// A single test case.
class ET
{
public:
  ET(string in, string out) :
    _in(in),
    _out(out)
  {
  }

  void test(EnumService& enum_)
  {
    SCOPED_TRACE(_in);
    string ret = enum_.lookup_uri_from_user(_in, 0);
    EXPECT_EQ(_out, ret);
  }

private:
  string _in; //^ input
  string _out; //^ expected output
};


TEST_F(JSONEnumServiceTest, SimpleTests)
{
  JSONEnumService enum_(string(UT_DIR).append("/test_enum.json"));

  ET("+15108580271", "sip:+15108580271@ut.cw-ngv.com"   ).test(enum_);
  ET("+15108580277", "sip:+15108580277@utext.cw-ngv.com").test(enum_);
  ET("",             ""                                 ).test(enum_);
  ET("214+4324",     "sip:2144324@198.147.226.2"        ).test(enum_);
  ET("6505551234",   "sip:6505551234@ut-int.cw-ngv.com" ).test(enum_);
  ET("+16108580277", "sip:+16108580277@198.147.226.2"   ).test(enum_);
}

TEST_F(JSONEnumServiceTest, NoMatch)
{
  JSONEnumService enum_(string(UT_DIR).append("/test_enum_no_match.json"));
  ET("1234567890", "").test(enum_);
}

TEST_F(JSONEnumServiceTest, ParseError)
{
  CapturingTestLogger log;
  JSONEnumService enum_(string(UT_DIR).append("/test_enum_parse_error.json"));
  EXPECT_TRUE(log.contains("Failed to read ENUM configuration data"));
  ET("+15108580271", "").test(enum_);
}

TEST_F(JSONEnumServiceTest, MissingParts)
{
  CapturingTestLogger log;
  JSONEnumService enum_(string(UT_DIR).append("/test_enum_missing_parts.json"));
  EXPECT_TRUE(log.contains("Badly formed ENUM number block"));
  ET("+15108580271", "").test(enum_);
  ET("+15108580272", "").test(enum_);
  ET("+15108580273", "").test(enum_);
  ET("+15108580274", "sip:+15108580274@ut.cw-ngv.com").test(enum_);
}

TEST_F(JSONEnumServiceTest, MissingBlock)
{
  CapturingTestLogger log;
  JSONEnumService enum_(string(UT_DIR).append("/test_enum_missing_block.json"));
  EXPECT_TRUE(log.contains("Badly formed ENUM configuration data - missing number_blocks object"));
  ET("+15108580271", "").test(enum_);
}

TEST_F(JSONEnumServiceTest, MissingFile)
{
  CapturingTestLogger log;
  JSONEnumService enum_(string(UT_DIR).append("/NONEXISTENT_FILE.json"));
  EXPECT_TRUE(log.contains("No ENUM configuration"));
  ET("+15108580271", "").test(enum_);
}

TEST_F(JSONEnumServiceTest, Regex)
{
  JSONEnumService enum_(string(UT_DIR).append("/test_enum_regex.json"));
  ET("5108580271", "sip:5108580271@ut.cw-ngv.com").test(enum_);
  ET("+15108580271", "sip:5108580271@ut.cw-ngv.com").test(enum_);
  ET("01115108580271", "sip:5108580271@ut.cw-ngv.com").test(enum_);
  ET("5108580272", "sip:5108580272@ut.cw-ngv.com").test(enum_);
}

TEST_F(JSONEnumServiceTest, BadRegex)
{
  CapturingTestLogger log;
  JSONEnumService enum_(string(UT_DIR).append("/test_enum_bad_regex.json"));
  // Unfortunately the logs here are hard to parse, so we just look for at least one instance of the
  // "badly formed regular expression" log, followed by the bad regexes
  EXPECT_TRUE(log.contains("Badly formed regular expression in ENUM number block"));
  EXPECT_TRUE(log.contains("!(^.*$)!sip:\\1@ut.cw-ngv.com"));
  EXPECT_TRUE(log.contains("!(^.*$)sip:\\1@ut.cw-ngv.com!"));
  EXPECT_TRUE(log.contains("!(^.*$)!sip:\\1@!ut.cw-ngv.com!"));
  EXPECT_TRUE(log.contains("!(^[a-z*$)!sip:\\1@ut.cw-ngv.com!"));
  // First entry is valid to confirm basic regular expression is valid.
  ET("+15108580271", "sip:+15108580271@ut.cw-ngv.com").test(enum_);
  // Second entry is technically invalid but it works in the obvious way and it's easier to permit than to add code to reject.
  ET("+15108580272", "sip:+15108580272@ut.cw-ngv.com").test(enum_);
  // Remaining are not - they should fail.
  ET("+15108580273", "").test(enum_);
  ET("+15108580274", "").test(enum_);
  ET("+15108580275", "").test(enum_);
}

struct ares_naptr_reply basic_naptr_reply[] = {
  {NULL, (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!(^.*$)!sip:\\1@ut.cw-ngv.com!", ".", 1, 1}
};

TEST_F(DNSEnumServiceTest, BasicTest)
{
  CommunicationMonitor cm_(new Alarm("sprout", AlarmDef::SPROUT_ENUM_COMM_ERROR, AlarmDef::MAJOR));
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)basic_naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory(), &cm_);
  ET("1234", "sip:1234@ut.cw-ngv.com").test(enum_);
}

TEST_F(DNSEnumServiceTest, BlankTest)
{
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("", "").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 0);
}

TEST_F(DNSEnumServiceTest, PlusPrefixTest)
{
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)basic_naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("+1234", "sip:+1234@ut.cw-ngv.com").test(enum_);
}

TEST_F(DNSEnumServiceTest, ArbitraryPunctuationTest)
{
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)basic_naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1-2.3(4)", "sip:1234@ut.cw-ngv.com").test(enum_);
}

TEST_F(DNSEnumServiceTest, NonTerminalRuleTest)
{
  struct ares_naptr_reply naptr_reply[] = {{NULL, (unsigned char*)"", (unsigned char*)"e2u+sip", (unsigned char*)"!1234!5678!", ".", 1, 1}};
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  FakeDNSResolver::_database.insert(std::make_pair(std::string("8.7.6.5.e164.arpa"), (struct ares_naptr_reply*)basic_naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "sip:1234@ut.cw-ngv.com").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 2);
}

TEST_F(DNSEnumServiceTest, MultipleRuleTest)
{
  struct ares_naptr_reply naptr_reply[] = {
    {&naptr_reply[1], (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!(1234)!sip:\\1@ut.cw-ngv.com!", ".", 1, 1},
    {NULL, (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!(5678)!sip:\\1@ut2.cw-ngv.com!", ".", 1, 1}
  };
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  FakeDNSResolver::_database.insert(std::make_pair(std::string("8.7.6.5.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "sip:1234@ut.cw-ngv.com").test(enum_);
  ET("5678", "sip:5678@ut2.cw-ngv.com").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 2);
}

TEST_F(DNSEnumServiceTest, OrderPriorityTest)
{
  struct ares_naptr_reply naptr_reply[] = {
    {&naptr_reply[1], (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!(^.*$)!sip:\\1@ut3.cw-ngv.com!", ".", 2, 1},
    {&naptr_reply[2], (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!(^.*$)!sip:\\1@ut2.cw-ngv.com!", ".", 1, 2},
    {NULL, (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!(^.*$)!sip:\\1@ut.cw-ngv.com!", ".", 1, 1},
  };
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "sip:1234@ut.cw-ngv.com").test(enum_);
}

TEST_F(DNSEnumServiceTest, NoResponseTest)
{
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 1);
}

TEST_F(DNSEnumServiceTest, IncompleteRegexpTest)
{
  struct ares_naptr_reply naptr_reply[] = {{NULL, (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!1234", ".", 1, 1}};
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 1);
}

TEST_F(DNSEnumServiceTest, InvalidRegexpTest)
{
  struct ares_naptr_reply naptr_reply[] = {{NULL, (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!(!!", ".", 1, 1}};
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 1);
}

TEST_F(DNSEnumServiceTest, InvalidFlagsTest)
{
  struct ares_naptr_reply naptr_reply[] = {{NULL, (unsigned char*)"foo", (unsigned char*)"e2u+sip", (unsigned char*)"!(^.*$)!sip:\\1@ut.cw-ngv.com!", ".", 1, 1}};
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 1);
}

TEST_F(DNSEnumServiceTest, PstnSipTypeTest)
{
  struct ares_naptr_reply naptr_reply[] = {{NULL, (unsigned char*)"u", (unsigned char*)"e2u+pstn:sip", (unsigned char*)"!(^.*$)!sip:\\1@ut.cw-ngv.com!", ".", 1, 1}};
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "sip:1234@ut.cw-ngv.com").test(enum_);
}

TEST_F(DNSEnumServiceTest, InvalidTypeTest)
{
  struct ares_naptr_reply naptr_reply[] = {{NULL, (unsigned char*)"u", (unsigned char*)"e2u+tel", (unsigned char*)"!(^.*$)!tel:\\1@ut.cw-ngv.com!", ".", 1, 1}};
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "").test(enum_);
}

TEST_F(DNSEnumServiceTest, NoMatchTest)
{
  struct ares_naptr_reply naptr_reply[] = {{NULL, (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!5678!!", ".", 1, 1}};
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 1);
}

TEST_F(DNSEnumServiceTest, LoopingRuleTest)
{
  struct ares_naptr_reply naptr_reply[] = {{NULL, (unsigned char*)"", (unsigned char*)"e2u+sip", (unsigned char*)"!(^.*$)!\\1!", ".", 1, 1}};
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "").test(enum_);
  EXPECT_EQ(FakeDNSResolver::_num_calls, 5);
}

TEST_F(DNSEnumServiceTest, DifferentServerTest)
{
  FakeDNSResolverFactory::_expected_server.addr.ipv4.s_addr = htonl(0x01020304);
  DNSEnumService enum_(_different_servers, ".e164.arpa", new FakeDNSResolverFactory());
}

TEST_F(DNSEnumServiceTest, IPv6ServerTest)
{
  FakeDNSResolverFactory::_expected_server.af = AF_INET6;
  for (int i = 0; i < 16; i++)
  {
    FakeDNSResolverFactory::_expected_server.addr.ipv6.s6_addr[0] = i + 1;
  }
  DNSEnumService enum_(_ipv6_servers, ".e164.arpa", new FakeDNSResolverFactory());
}

TEST_F(DNSEnumServiceTest, InvalidServerTest)
{
  DNSEnumService enum_(_bad_servers, ".e164.arpa", new FakeDNSResolverFactory());
}

TEST_F(DNSEnumServiceTest, DifferentSuffixTest)
{
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa.cw-ngv.com"), (struct ares_naptr_reply*)basic_naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa.cw-ngv.com", new FakeDNSResolverFactory());
  ET("1234", "sip:1234@ut.cw-ngv.com").test(enum_);
}

TEST_F(DNSEnumServiceTest, ResolverErrorTest)
{
  CommunicationMonitor cm_(new Alarm("sprout", AlarmDef::SPROUT_ENUM_COMM_ERROR, AlarmDef::MAJOR));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory(), &cm_);
  ET("1234", "").test(enum_);
}

TEST_F(DNSEnumServiceTest, ResolverOkCommMonMockTest)
{
  MockCommunicationMonitor cm_;
  EXPECT_CALL(cm_, inform_success(_));
  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)basic_naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory(), &cm_);
  ET("1234", "sip:1234@ut.cw-ngv.com").test(enum_);
}

TEST_F(DNSEnumServiceTest, ResolverNotFoundCommMonMockTest)
{
  // If we request a nonexistent number, and the ENUM server tells us it doesn't exist,
  // we shouldn't treat that as a communications error.
  MockCommunicationMonitor cm_;
  EXPECT_CALL(cm_, inform_success(_));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory(), &cm_);
  ET("1234", "").test(enum_);
}

TEST_F(DNSEnumServiceTest, ResolverErrorCommMonMockTest)
{
  // If we request a number, and the ENUM server fails to respond,
  // we should treat that as a communications error.
  MockCommunicationMonitor cm_;
  EXPECT_CALL(cm_, inform_failure(_));
  DNSEnumService enum_(_servers, ".e164.arpa", new BrokenDNSResolverFactory(), &cm_);
  ET("1234", "").test(enum_);
}

TEST_F(DNSEnumServiceTest, PosixRegexTest)
{
  /* [:digit:]+? is interpreted differently in Perl-compatible and POSIX Extended regular expressions:
     - Perl treats +? as a nongreedy match, so will only read one digit.
     - POSIX doesn't have nongreedy match syntax, so "?+" is unparseable and the match fails

     This testcase outpus "sip:1@ut.cw-ngv.com if Perl-compatible regular expressions are used.
  */

  struct ares_naptr_reply invalid_posix_regex_naptr_reply[] = {
    {NULL, (unsigned char*)"u", (unsigned char*)"e2u+sip", (unsigned char*)"!(^[[:digit:]]+?)!sip:\\1@ut.cw-ngv.com!", ".", 1, 1}
  };

  FakeDNSResolver::_database.insert(std::make_pair(std::string("4.3.2.1.e164.arpa"), (struct ares_naptr_reply*)invalid_posix_regex_naptr_reply));
  DNSEnumService enum_(_servers, ".e164.arpa", new FakeDNSResolverFactory());
  ET("1234", "").test(enum_);
}

