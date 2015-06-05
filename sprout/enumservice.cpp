/**
 * @file dnsresolver.cpp class implementation for a DNS resolver
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

#include <sys/stat.h>
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"
#include <fstream>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "enumservice.h"
#include "dnsresolver.h"
#include "utils.h"
#include "log.h"
#include "sproutsasevent.h"
#include "sprout_pd_definitions.h"


const boost::regex EnumService::CHARS_TO_STRIP_FROM_UAS = boost::regex("([^0-9+]|(?<=.)[^0-9])");
const boost::regex DNSEnumService::CHARS_TO_STRIP_FROM_DOMAIN = boost::regex("[^0-9]");


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
    LOG_DEBUG("Split regex into match=%s, replace=%s", match_replace[0].c_str(), match_replace[1].c_str());
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


JSONEnumService::JSONEnumService(std::string configuration)
{
  // Check whether the file exists.
  struct stat s;
  if ((stat(configuration.c_str(), &s) != 0) &&
      (errno == ENOENT))
  {
    LOG_STATUS("No ENUM configuration (file %s does not exist)",
               configuration.c_str());
    CL_SPROUT_ENUM_FILE_MISSING.log(configuration.c_str());
    return;
  }

  LOG_STATUS("Loading ENUM configuration from %s", configuration.c_str());

  // Read from the file
  std::ifstream fs(configuration.c_str());
  std::string enum_str((std::istreambuf_iterator<char>(fs)),
                        std::istreambuf_iterator<char>());

  if (enum_str == "")
  {
    // LCOV_EXCL_START
    LOG_ERROR("Failed to read ENUM configuration data from %s",
              configuration.c_str());
    CL_SPROUT_ENUM_FILE_EMPTY.log(configuration.c_str());
    return;
    // LCOV_EXCL_STOP
  }

  // Now parse the document
  rapidjson::Document doc;
  doc.Parse<0>(enum_str.c_str());

  if (doc.HasParseError())
  {
    LOG_ERROR("Failed to read ENUM configuration data: %s\nError: %s",
              enum_str.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    CL_SPROUT_ENUM_FILE_INVALID.log(configuration.c_str());
    return;
  }

  try
  {
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

        // Entry is well-formed, so add it.
        LOG_DEBUG("Found valid number prefix block %s", prefix.c_str());
        NumberPrefix *pfix = new NumberPrefix;
        pfix->prefix = prefix;

        if (parse_regex_replace(regex, pfix->match, pfix->replace))
        {
          _number_prefixes.push_back(pfix);
          LOG_STATUS("  Adding number prefix %s, regex=%s",
                     pfix->prefix.c_str(), regex.c_str());
        }
        else
        {
          LOG_WARNING("Badly formed regular expression in ENUM number block %s",
                      regex.c_str());
          delete pfix;
        }
      }
      catch (JsonFormatError err)
      {
        // Badly formed number block.
        LOG_WARNING("Badly formed ENUM number block (hit error at %s:%d)",
                    err._file, err._line);
        CL_SPROUT_ENUM_FILE_INVALID.log(configuration.c_str());
      }
    }
  }
  catch (JsonFormatError err)
  {
    LOG_ERROR("Badly formed ENUM configuration data - missing number_blocks object");
    CL_SPROUT_ENUM_FILE_INVALID.log(configuration.c_str());
  }
}


JSONEnumService::~JSONEnumService()
{
  for (std::list<struct NumberPrefix*>::iterator it = _number_prefixes.begin();
       it != _number_prefixes.end();
       it++)
  {
    delete *it;
  }
}


std::string JSONEnumService::lookup_uri_from_user(const std::string &user, SAS::TrailId trail) const
{
  std::string uri;

  LOG_DEBUG("Translating URI via JSON ENUM lookup");

  if (user.empty())
  {
    LOG_INFO("No dial string supplied, so don't do ENUM lookup");
    return std::string();
  }

  std::string aus = user_to_aus(user);
  struct NumberPrefix* pfix = prefix_match(aus);

  if (pfix == NULL)
  {
    LOG_INFO("No matching number range %s from ENUM lookup", user.c_str());
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
    LOG_ERROR("Failed to translate number with regex");
    return uri;
    // LCOV_EXCL_STOP
  }

  LOG_INFO("Number %s found, translated URI = %s", user.c_str(), uri.c_str());

  return uri;
}


JSONEnumService::NumberPrefix* JSONEnumService::prefix_match(const std::string& number) const
{
  // For simplicity this uses a linear scan since we don't expect too many
  // entries.  Should shift to a radix tree at some point.
  for (std::list<struct NumberPrefix*>::const_iterator it = _number_prefixes.begin();
       it != _number_prefixes.end();
       it++)
  {
    int len = std::min(number.size(), (*it)->prefix.size());

    LOG_DEBUG("Comparing first %d numbers of %s against prefix %s",
              len, number.c_str(), (*it)->prefix.c_str());

    if (number.compare(0, len, (*it)->prefix, 0, len) == 0)
    {
      // Found a match, so return it (at the moment we assume the entries are
      // ordered with most specific matches first so we can stop as soon as we
      // have one match).
      LOG_DEBUG("Match found");
      return *it;
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
    else
    {
      LOG_ERROR("Failed to parse '%s' as IP address - defaulting to 127.0.0.1", server->c_str());
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
    LOG_INFO("No dial string supplied, so don't do ENUM lookup");
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
            LOG_ERROR("Failed to translate number with regex");
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
    LOG_DEBUG("Enum lookup completes: %s", string.c_str());
    SAS::Event event(trail, SASEvent::ENUM_COMPLETE, 0);
    event.add_var_param(user);
    event.add_var_param(string);
    SAS::report_event(event);
  }
  else
  {
    LOG_WARNING("Enum lookup did not complete for user %s", user.c_str());
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
    LOG_DEBUG("Got NAPTR record: %u %u \"%s\" \"%s\" \"%s\" %s", record->order, record->preference, record->service, record->flags, record->regexp, record->replacement);
    if ((strcasecmp((char*)record->service, "e2u+sip") == 0) ||
        (strcasecmp((char*)record->service, "e2u+pstn:sip") == 0) || 
        (strcasecmp((char*)record->service, "e2u+pstn:tel") == 0))
    {
      boost::regex regex;
      std::string replace;
      bool terminal = false;

      if (!EnumService::parse_regex_replace(std::string((char*)record->regexp), regex, replace))
      {
        LOG_WARNING("DNS ENUM record contains unparseable regular expression: %s", record->regexp);
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
        LOG_WARNING("DNS ENUM record contains unknown flags: %s", record->flags);
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
