/**
 * @file dnsresolver.cpp class implementation for a DNS resolver
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <sys/stat.h>
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"
#include <fstream>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>

#include "pjutils.h"
#include "enumservice.h"
#include "dnsresolver.h"
#include "utils.h"
#include "log.h"
#include "sproutsasevent.h"
#include "sprout_pd_definitions.h"


const boost::regex EnumService::CHARS_TO_STRIP_FROM_UAS = boost::regex("([^0-9+]|(?<=.)[^0-9])");
const boost::regex DNSEnumService::CHARS_TO_STRIP_FROM_DOMAIN = boost::regex("[^0-9]");

std::string DummyEnumService::lookup_uri_from_user(const std::string &user, SAS::TrailId trail) const
{
  // If we have no ENUM server configured, we act as if all ENUM lookups
  // return a successful response and perform the following mappings:
  //  - tel:<number> to sip:<number>@<homedomain>
  //  - sip:<number>@<homedomain> to itself
  //
  // We do this in order to avoid needing to setup an ENUM server on test
  // systems just to allow local calls to work.
  TRC_DEBUG("No ENUM server or ENUM file configured, perform default translation");
  SAS::Event event(trail, SASEvent::ENUM_NOT_ENABLED, 0);
  SAS::report_event(event);

  std::string new_uri;

  new_uri = "sip:";
  new_uri += user;
  new_uri += "@";
  new_uri += _default_home_domain;
  TRC_DEBUG("Translate telephone number %s to SIP URI %s",
            user.c_str(),
            new_uri.c_str());

  return new_uri;
}

bool EnumService::parse_regex_replace(const std::string& regex_replace, boost::regex& regex, std::string& replace)
{
  bool success = false;

  // Split the regular expression into the match and replace sections.  RFC3402
  // says any character other than 1-9 or i can be the delimiter, but
  // recommends / or !.  We just use the first character and reject if it
  // doesn't neatly split the regex into two.
  std::vector<std::string> match_replace;
  Utils::split_string(regex_replace, regex_replace[0], match_replace);

  if (match_replace.size() == 2)
  {
    TRC_DEBUG("Split regex into match=%s, replace=%s", match_replace[0].c_str(), match_replace[1].c_str());
    try
    {
      regex.assign(match_replace[0], boost::regex::extended);
      replace = match_replace[1];
      success = true;
    }
    catch (...)
    {
      success = false;
    }
  }
  else
  {
    success = false;
  }

  return success;
}


JSONEnumService::JSONEnumService(std::string configuration):
  _configuration(configuration),
  _updater(NULL)
{
  // create and updater which, by default, runs the function when initialized
  _updater = new Updater<void, JSONEnumService>(this,
                                  std::mem_fun(&JSONEnumService::update_enum));
}

void JSONEnumService::update_enum()
{
  // Check whether the file exists.
  struct stat s;
  if ((stat(_configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    TRC_STATUS("No ENUM configuration (file %s does not exist)",
               _configuration.c_str());
    CL_SPROUT_ENUM_FILE_MISSING.log(_configuration.c_str());
    return;
  }

  TRC_STATUS("Loading ENUM configuration from %s", _configuration.c_str());

  // Read from the file
  std::ifstream fs(_configuration.c_str());
  std::string enum_str((std::istreambuf_iterator<char>(fs)),
                        std::istreambuf_iterator<char>());

  if (enum_str == "")
  {
    // LCOV_EXCL_START
    TRC_ERROR("Failed to read ENUM configuration data from %s",
              _configuration.c_str());
    CL_SPROUT_ENUM_FILE_EMPTY.log(_configuration.c_str());
    return;
    // LCOV_EXCL_STOP
  }

  // Now parse the document
  rapidjson::Document doc;
  doc.Parse<0>(enum_str.c_str());

  if (doc.HasParseError())
  {
    TRC_ERROR("Failed to read ENUM configuration data: %s\nError: %s",
              enum_str.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    CL_SPROUT_ENUM_FILE_INVALID.log(_configuration.c_str());
    return;
  }

  try
  {
    std::vector<NumberPrefix> new_number_prefixes;
    std::map<std::string, NumberPrefix> new_prefix_regex_map;

    JSON_ASSERT_CONTAINS(doc, "number_blocks");
    JSON_ASSERT_ARRAY(doc["number_blocks"]);
    const rapidjson::Value& nb_arr = doc["number_blocks"];

    for (rapidjson::Value::ConstValueIterator nb_it = nb_arr.Begin();
         nb_it != nb_arr.End();
         ++nb_it)
    {
      try
      {
        std::string prefix;
        JSON_GET_STRING_MEMBER(*nb_it, "prefix", prefix);
        std::string regex;
        JSON_GET_STRING_MEMBER(*nb_it, "regex", regex);

        // Entry is well-formed, so strip off visual separators and add it.
        TRC_DEBUG("Found valid number prefix block %s", prefix.c_str());
        NumberPrefix pfix;
        prefix = Utils::remove_visual_separators(prefix);
        pfix.prefix = prefix;

        if (parse_regex_replace(regex, pfix.match, pfix.replace))
        {
          // Create an array in order of entries in json file, and a map
          // (automatically sorted in order of key length) so we can later
          // match numbers to the most specific prefixes
          new_number_prefixes.push_back(pfix);
          new_prefix_regex_map.insert(std::make_pair(prefix, pfix));
          TRC_STATUS("  Adding number prefix %s, regex=%s",
                     pfix.prefix.c_str(), regex.c_str());
        }
        else
        {
          TRC_WARNING("Badly formed regular expression in ENUM number block %s",
                      regex.c_str());
        }
      }
      catch (JsonFormatError err)
      {
        // Badly formed number block.
        TRC_WARNING("Badly formed ENUM number block (hit error at %s:%d)",
                    err._file, err._line);
        CL_SPROUT_ENUM_FILE_INVALID.log(_configuration.c_str());
      }
    }

    // Take a write lock on the mutex in RAII style
    boost::lock_guard<boost::shared_mutex> write_lock(_number_prefixes_rw_lock);
    _number_prefixes = new_number_prefixes;
    _prefix_regex_map = new_prefix_regex_map;
  }
  catch (JsonFormatError err)
  {
    TRC_ERROR("Badly formed ENUM configuration data - missing number_blocks object");
    CL_SPROUT_ENUM_FILE_INVALID.log(_configuration.c_str());
  }
}


JSONEnumService::~JSONEnumService()
{
  delete _updater;
  _updater = NULL;
}


std::string JSONEnumService::lookup_uri_from_user(const std::string &user, SAS::TrailId trail) const
{
  std::string uri;

  TRC_DEBUG("Translating URI via JSON ENUM lookup");

  if (user.empty())
  {
    TRC_INFO("No dial string supplied, so don't do ENUM lookup");
    return std::string();
  }

  std::string aus = user_to_aus(user);

  // Take a read lock on the mutex in RAII style
  boost::shared_lock<boost::shared_mutex> read_lock(_number_prefixes_rw_lock);

  const struct NumberPrefix* pfix = prefix_match(aus);

  if (pfix == NULL)
  {
    TRC_INFO("No matching number range %s from ENUM lookup", user.c_str());
    SAS::Event event(trail, SASEvent::ENUM_INCOMPLETE, 0);
    event.add_var_param(user);
    SAS::report_event(event);
    return uri;
  }

  // Apply the regular expression to the user string to generate a new
  // URI.
  try
  {
    uri = boost::regex_replace(aus, pfix->match, pfix->replace);
  }
  catch(...) // LCOV_EXCL_START Only throws if expression too complex or similar hard-to-hit conditions
  {
    TRC_ERROR("Failed to translate number with regex");
    SAS::Event event(trail, SASEvent::ENUM_INCOMPLETE, 1);
    event.add_var_param(user);
    SAS::report_event(event);
    return uri;
    // LCOV_EXCL_STOP
  }

  TRC_INFO("Number %s found, translated URI = %s", user.c_str(), uri.c_str());
  SAS::Event event(trail, SASEvent::ENUM_COMPLETE, 0);
  event.add_var_param(user);
  event.add_var_param(uri);
  SAS::report_event(event);

  return uri;
}


// This function returns a pointer to a struct that may be destroyed by the
// updater. Callers must therefore ensure that they have the read lock before
// calling this function and only release the lock once they no longer need
// the object.
const JSONEnumService::NumberPrefix* JSONEnumService::prefix_match(const std::string& number) const
{
  // Iterate through map in reverse order (already sorted by key length during
  // construction) to find the most specific matching prefix
  for (std::map<std::string, NumberPrefix>::const_reverse_iterator it =
                                                     _prefix_regex_map.rbegin();
       it != _prefix_regex_map.rend();
       it++)
  {
    int len = std::min(number.size(), (*it).first.size());

    TRC_DEBUG("Comparing first %d numbers of %s against prefix %s",
              len, number.c_str(), (*it).first.c_str());

    if (Utils::remove_visual_separators(number).
                                      compare(0, len, (*it).first, 0, len) == 0)
    {
      // Found a match, so return it.
      TRC_DEBUG("Match found");
      return &((*it).second);
    }
  }

  return NULL;
}

DNSEnumService::DNSEnumService(const std::vector<std::string>& dns_servers,
                               const std::string& dns_suffix,
                               const DNSResolverFactory* resolver_factory,
                               CommunicationMonitor* comm_monitor) :
                               _dns_suffix(dns_suffix),
                               _resolver_factory(resolver_factory),
                               _comm_monitor(comm_monitor)
{
  // Initialize the ares library.  This might have already been done by curl
  // but it's safe to do it twice.
  ares_library_init(ARES_LIB_INIT_ALL);
  struct addrinfo* res;

  for (std::vector<std::string>::const_iterator server = dns_servers.begin();
       server != dns_servers.end();
       server++)
  {
    struct IP46Address dns_server_addr;
    // Parse the DNS server's IP address.
    if (inet_pton(AF_INET, server->c_str(), &dns_server_addr.addr.ipv4))
    {
      dns_server_addr.af = AF_INET;
    }
    else if (inet_pton(AF_INET6, server->c_str(), &dns_server_addr.addr.ipv6))
    {
      dns_server_addr.af = AF_INET6;
    }
    else if ((getaddrinfo(server->c_str(), NULL, NULL, &res)) == 0)
    {
      dns_server_addr.af = res->ai_family;
      if (dns_server_addr.af == AF_INET)
      {
        dns_server_addr.addr.ipv4 = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
      }
      else if (dns_server_addr.af == AF_INET6)
      {
        dns_server_addr.addr.ipv6 = ((struct sockaddr_in6*)res->ai_addr)->sin6_addr;
      }
      freeaddrinfo(res);
    }
    else
    {
      TRC_ERROR("Failed to parse '%s' as IP address or resolve host name - defaulting to 127.0.0.1", server->c_str());
      dns_server_addr.af = AF_INET;
      (void)inet_aton("127.0.0.1", &dns_server_addr.addr.ipv4);
    }
    _servers.push_back(dns_server_addr);
  }

  // We store a DNSResolver in thread-local data, so create the thread-local
  // store.
  pthread_key_create(&_thread_local, (void(*)(void*))DNSResolver::destroy);
}


DNSEnumService::~DNSEnumService()
{
  // Clean up this thread's connection now, rather than waiting for
  // pthread_exit.  This is to support use by single-threaded code
  // (e.g., UTs), where pthread_exit is never called.
  DNSResolver* resolver = (DNSResolver*)pthread_getspecific(_thread_local);
  if (resolver != NULL)
  {
    pthread_setspecific(_thread_local, NULL);
    DNSResolver::destroy(resolver);
  }

  delete _resolver_factory;
  _resolver_factory = NULL;
}


std::string DNSEnumService::lookup_uri_from_user(const std::string& user, SAS::TrailId trail) const
{
  if (user.empty())
  {
    TRC_INFO("No dial string supplied, so don't do ENUM lookup");
    return std::string();
  }

  // Log starting ENUM processing.
  SAS::Event event(trail, SASEvent::ENUM_START, 0);
  event.add_var_param(user);
  SAS::report_event(event);

  // Determine the Application Unique String (AUS) from the user.  This is
  // used to form the first key, and also as the input into the regular
  // expressions.
  std::string aus = user_to_aus(user);
  std::string string = aus;
  // Get the resolver to use.  This comes from thread-local data.
  DNSResolver* resolver = get_resolver();
  // Spin round until we've finished (successfully or otherwise) or we've done
  // the maximum number of queries.
  bool complete = false;
  bool failed = false;
  bool server_failed = false;
  int dns_queries = 0;
  while ((!complete) &&
         (!failed) &&
         (dns_queries < MAX_DNS_QUERIES))
  {
    // Translate the key into a domain and issue a query for it.
    std::string domain = key_to_domain(string);
    struct ares_naptr_reply* naptr_reply = NULL;
    int status = resolver->perform_naptr_query(domain, naptr_reply, trail);
    if (status == ARES_SUCCESS)
    {
      // Parse the reply into a sorted list of rules.
      std::vector<Rule> rules;
      parse_naptr_reply(naptr_reply, rules);
      // Now spin through the rules, looking for the first match.
      std::vector<DNSEnumService::Rule>::const_iterator rule;
      for (rule = rules.begin();
           rule != rules.end();
           ++rule)
      {
        if (rule->matches(string))
        {
          // We found a match, so apply the regular expression to the AUS (not
          // the previous string - this is what ENUM mandates).  If this was a
          // terminal rule, we now have a SIP URI and we're finished.
          // Otherwise, the output of the regular expression is used as the
          // next key.
          try
          {
            string = rule->replace(aus, trail);
            complete = rule->is_terminal();
          }
          catch(...) // LCOV_EXCL_START Only throws if expression too complex or similar hard-to-hit conditions
          {
            TRC_ERROR("Failed to translate number with regex");
            failed = true;
            // LCOV_EXCL_STOP
          }
          break;
        }
      }
      // If we didn't find a match (and so hit the end of the list), consider
      // this a failure.
      failed = failed || (rule == rules.end());
    }
    else if (status == ARES_ENOTFOUND)
    {
      // Our DNS query failed, so give up, but this is not an ENUM server issue -
      // we just tried to look up an unknown name.
      failed = true;
    }
    else
    {
      // Our DNS query failed. Give up, and track an ENUM server failure.
      failed = true;
      server_failed = true;
    }


    // Free off the NAPTR reply if we have one.
    if (naptr_reply != NULL)
    {
      resolver->free_naptr_reply(naptr_reply);
      naptr_reply = NULL;
    }

    dns_queries++;
  }

  // Log that we've finished processing (and whether it was successful or not).
  if (complete)
  {
    TRC_DEBUG("Enum lookup completes: %s", string.c_str());
    SAS::Event event(trail, SASEvent::ENUM_COMPLETE, 0);
    event.add_var_param(user);
    event.add_var_param(string);
    SAS::report_event(event);
  }
  else
  {
    TRC_WARNING("Enum lookup did not complete for user %s", user.c_str());
    SAS::Event event(trail, SASEvent::ENUM_INCOMPLETE, 0);
    event.add_var_param(user);
    SAS::report_event(event);
    // On failure, we must return an empty (rather than incomplete) string.
    string = std::string("");
  }

  // Report state of last communication attempt (which may potentially set/clear
  // an associated alarm).
  if (_comm_monitor)
  {
    if (server_failed)
    {
      _comm_monitor->inform_failure();
    }
    else
    {
      _comm_monitor->inform_success();
    }
  }

  return string;
}


std::string DNSEnumService::key_to_domain(const std::string& key) const
{
  // First strip all non-numeric characters from the key.
  std::string number = boost::regex_replace(key, CHARS_TO_STRIP_FROM_DOMAIN, std::string(""));
  // Then spin backwards through the number, adding each digit separated by
  // dots.
  std::string domain;
  for (int ch_idx = number.length() - 1; ch_idx >= 0; ch_idx--)
  {
    domain.push_back(number[ch_idx]);
    if (ch_idx != 0)
    {
      domain.push_back('.');
    }
  }
  // Finally, append the suffix.
  domain += _dns_suffix;
  return domain;
}


DNSResolver* DNSEnumService::get_resolver() const
{
  // Get the resolver from the thread-local data, or create a new one if none
  // found.
  DNSResolver* resolver = (DNSResolver*)pthread_getspecific(_thread_local);
  if (resolver == NULL)
  {
    resolver = _resolver_factory->new_resolver(_servers);
    pthread_setspecific(_thread_local, resolver);
  }
  return resolver;
}


void DNSEnumService::parse_naptr_reply(const struct ares_naptr_reply* naptr_reply,
                                       std::vector<DNSEnumService::Rule>& rules)
{
  for (const struct ares_naptr_reply* record = naptr_reply; record != NULL; record = record->next)
  {
    TRC_DEBUG("Got NAPTR record: %u %u \"%s\" \"%s\" \"%s\" %s", record->order, record->preference, record->service, record->flags, record->regexp, record->replacement);
    if ((strcasecmp((char*)record->service, "e2u+sip") == 0) ||
        (strcasecmp((char*)record->service, "e2u+pstn:sip") == 0) ||
        (strcasecmp((char*)record->service, "e2u+pstn:tel") == 0))
    {
      boost::regex regex;
      std::string replace;
      bool terminal = false;

      if (!EnumService::parse_regex_replace(std::string((char*)record->regexp), regex, replace))
      {
        TRC_WARNING("DNS ENUM record contains unparseable regular expression: %s", record->regexp);
        // As above, we don't give up totally here.
        continue;
      }

      // The only valid flag is u.  If we see any other flags, we must ignore
      // the whole record (according to RFC 3761, 2.4.1).
      if (strcasecmp((char*)record->flags, "u") == 0)
      {
        terminal = true;
      }
      else if (strcmp((char*)record->flags, "") != 0)
      {
        TRC_WARNING("DNS ENUM record contains unknown flags: %s", record->flags);
        // Note that we don't give up totally here.  If we end up with an empty
        // list, we'll break out then.  Otherwise, we'll just try and push on.
        continue;
      }

      rules.push_back(Rule(regex,
                           replace,
                           terminal,
                           record->order,
                           record->preference));
    }
  }
  std::sort(rules.begin(), rules.end(), DNSEnumService::Rule::compare_order_preference);
}


DNSEnumService::Rule::Rule(const boost::regex& regex,
                           const std::string& replace,
                           bool terminal,
                           int order,
                           int preference) :
                           _regex(regex),
                           _replace(replace),
                           _terminal(terminal),
                           _order(order),
                           _preference(preference)
{
}


std::string DNSEnumService::Rule::replace(const std::string& string, SAS::TrailId trail) const
{
  // Perform the match and replace.
  std::string result = boost::regex_replace(string, _regex, _replace);
  // Log the results.
  SAS::Event event(trail, SASEvent::ENUM_MATCH, 0);
  event.add_static_param(_terminal);
  event.add_var_param(string);
  event.add_var_param(_regex.str());
  event.add_var_param(_replace);
  event.add_var_param(result);
  SAS::report_event(event);

  return result;
}


bool DNSEnumService::Rule::compare_order_preference(DNSEnumService::Rule first, DNSEnumService::Rule second)
{
  return ((first._order < second._order) ||
          ((first._order == second._order) &&
           (first._preference < second._preference)));
}
