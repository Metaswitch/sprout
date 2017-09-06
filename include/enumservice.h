/**
 * @file enumservice.h class definition for an ENUM service provider
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///

#ifndef ENUMSERVICE_H__
#define ENUMSERVICE_H__

#include <list>
#include <string>
#include <boost/regex.hpp>
#include <boost/thread.hpp>
#include <netinet/in.h>
#include <ares.h>
#include "sas.h"
#include "baseresolver.h"
#include "dnsresolver.h"
#include "communicationmonitor.h"
#include "updater.h"

/// @class EnumService
///
/// Abstract base class for ENUM service implementations.  These perform an
/// ENUM lookup to translate a PSTN number to a SIP URI.
class EnumService
{
public:
  /// Must define a destructor, even though it does nothing, to ensure there
  /// is an entry for it in the vtable.
  virtual ~EnumService() {}

  /// Translate a PSTN number to a SIP URI.
  virtual std::string lookup_uri_from_user(const std::string& user, SAS::TrailId trail) const = 0;

  // Parse a string of the form !<regex>!<replace>! into a regular expression
  // and a replacement string.
  static bool parse_regex_replace(const std::string& regex_replace, boost::regex& regex, std::string& replace);

  // Converts an input user to an Application Unique String by stripping out
  // invalid characters, specifically anything other than 0-9 and + for the
  // first character, or just 0-9 for subsequent characters.  Since the ENUM
  // "First Well Known Rule" is the identity, the Application Unique String is
  // also the first key to use.
  static const boost::regex CHARS_TO_STRIP_FROM_UAS;
  static std::string user_to_aus(const std::string& user) { return boost::regex_replace(user, CHARS_TO_STRIP_FROM_UAS, std::string("")); };

};


/// @class DummyEnumService
///
/// Provides an "ENUM service" which just translates tel:whatever to sip:whatever.
class DummyEnumService : public EnumService
{
public:
  DummyEnumService(std::string home_domain):
    EnumService(),
    _default_home_domain(home_domain)
  {}
  std::string lookup_uri_from_user(const std::string& user, SAS::TrailId trail) const;

private:
  std::string _default_home_domain;
};


/// @class JSONEnumService
///
/// Provides an "ENUM service" based on configuration read from a JSON file.
class JSONEnumService : public EnumService
{
public:
  JSONEnumService(std::string configuration = "./enum.json");
  ~JSONEnumService();

  // Updates the enum configuration
  void update_enum();

  std::string lookup_uri_from_user(const std::string& user, SAS::TrailId trail) const;

private:
  struct NumberPrefix
  {
    std::string prefix;
    boost::regex match;
    std::string replace;
  };

  std::vector<NumberPrefix> _number_prefixes;
  std::map<std::string, NumberPrefix> _prefix_regex_map;
  std::string _configuration;
  Updater<void, JSONEnumService>* _updater;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the class, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _number_prefixes_rw_lock;

  const NumberPrefix* prefix_match(const std::string& number) const;
};

/// @class DNSEnumService
///
/// Provides an ENUM service based on DNS queries from an ENUM server.
class DNSEnumService : public EnumService
{
public:
  DNSEnumService(const std::vector<std::string>& dns_server,
                 const std::string& dns_suffix = ".e164.arpa",
                 const DNSResolverFactory* resolver_factory =
                                                       new DNSResolverFactory(),
                 CommunicationMonitor* comm_monitor = NULL);
  ~DNSEnumService();

  std::string lookup_uri_from_user(const std::string& user, SAS::TrailId trail) const;

  // Characters to strip from a key before turning it into a domain.  This is
  // all non-digit characters.
  static const boost::regex CHARS_TO_STRIP_FROM_DOMAIN;

private:
  /// @class Rule
  ///
  /// Represents an ENUM translation rule, as extracted from a NAPTR record.
  class Rule
  {
  public:
    Rule(const boost::regex& regex,
         const std::string& replace,
         bool terminal,
         int order,
         int preference);

    // Whether this rule matches.
    inline bool matches(const std::string& string) const { return boost::regex_search(string, _regex); };
    // Whether this rule is terminal.
    inline bool is_terminal() const { return _terminal; }
    // Apply the regular expression match/replace processing for this rule.
    std::string replace(const std::string& string, SAS::TrailId trail) const;
    // Compares two rules according to order and preference.
    static bool compare_order_preference(Rule first, Rule second);

  private:
    // The regular expression and replacement for this rule.
    boost::regex _regex;
    std::string _replace;
    // Whether this rule is terminal.
    bool _terminal;
    // The order and preference for this rule (used for sorting into order).
    int _order;
    int _preference;

  };

  // Maximum number of DNS queries per request.
  static const int MAX_DNS_QUERIES = 5;

  // Converts a key to an ENUM domain name.
  std::string key_to_domain(const std::string& key) const;
  // Gets a resolver (from thread-local data).
  DNSResolver* get_resolver() const;
  // Parses a naptr_reply into a list of Rule objects.
  static void parse_naptr_reply(const struct ares_naptr_reply* naptr_reply,
                                std::vector<DNSEnumService::Rule>& rules);

  // The IP address of the DNS server to query.
  std::vector<struct IP46Address> _servers;
  // The suffix to apply to domain names used for ENUM lookups.
  const std::string _dns_suffix;
  // The thread-local store - used for storing DNSResolvers.
  pthread_key_t _thread_local;
  // DNSResolverFactory, used for constructing DNSResolvers when required.
  const DNSResolverFactory* _resolver_factory;

  // Helper used to track enum communication state, and issue/clear alarms
  // based upon recent activity.
  CommunicationMonitor* _comm_monitor;
};

#endif

