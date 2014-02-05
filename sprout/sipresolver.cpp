/**
 * @file sipresolver.cpp  Implementation of SIP DNS resolver class.
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

#include "log.h"
#include "sipresolver.h"

SIPResolver::SIPResolver(DnsCachedResolver* dns_client) :
  BaseResolver(dns_client)
{
  LOG_DEBUG("Creating SIP resolver");

  // Create the NAPTR cache.
  std::map<std::string, int> naptr_services;
  naptr_services["SIP+D2U"] = IPPROTO_UDP;
  naptr_services["SIP+D2T"] = IPPROTO_TCP;
  create_naptr_cache(naptr_services);

  // Create the SRV cache.
  create_srv_cache();

  // Create the blacklist.
  create_blacklist();

  LOG_STATUS("Created SIP resolver");
}

SIPResolver::~SIPResolver()
{
  destroy_blacklist();
  destroy_srv_cache();
  destroy_naptr_cache();
}

bool SIPResolver::resolve(const std::string& target,
                          int port,
                          int transport,
                          int af,
                          AddrInfo& ai)
{
  // First determine the transport following the process in RFC3263 section
  // 4.1.
  bool rc = false;

  LOG_DEBUG("SIPResolver::resolve for target %s, port %d, transport %d", target.c_str(), port, transport);

  if (parse_ip_target(target, ai.address))
  {
    // The target is already an IP address, so no DNS resolution is possible.
    // Use specified transport and port or defaults if not specified.
    LOG_DEBUG("Target is an IP address - default port/transport if required");
    ai.transport = (transport != -1) ? transport : IPPROTO_UDP;
    ai.port = (port != 0) ? port : 5060;
    rc = true;
  }
  else
  {
    std::string srv_target;
    std::string a_target = target;

    if (port != 0)
    {
      // Port is specified, so don't do NAPTR or SRV look-ups.  Default transport
      // if required and move straight to A record look-up.
      LOG_DEBUG("Port is specified");
      ai.transport = (transport != -1) ? transport : IPPROTO_UDP;
    }
    else if (transport == -1)
    {
      // Transport protocol isn't specified, so do a NAPTR lookup for the target.
      LOG_DEBUG("Do NAPTR look-up for %s", target.c_str());
      NAPTRReplacement* naptr = _naptr_cache->get(target);

      if (naptr != NULL)
      {
        // NAPTR resolved to a supported service
        LOG_DEBUG("NAPTR resolved to transport %d", naptr->transport);
        ai.transport = naptr->transport;
        if (naptr->flags == "S")
        {
          // Do an SRV lookup with the replacement domain from the NAPTR lookup.
          srv_target = naptr->replacement;
        }
        else
        {
          // Move straight to A/AAAA lookup of the domain returned by NAPTR.
          a_target = naptr->replacement;
        }
      }
      else
      {
        // NAPTR resolution failed, so do SRV lookups for both UDP and TCP to
        // see which transports are supported.
        LOG_DEBUG("NAPTR lookup failed, so do SRV lookups for UDP and TCP");
        std::vector<std::string> domains;
        domains.push_back("_sip._udp." + target);
        domains.push_back("_sip._tcp." + target);
        std::vector<DnsResult> results;
        _dns_client->dns_query(domains, ns_t_srv, results);
        DnsResult& udp_result = results[0];
        LOG_DEBUG("UDP SRV record %s returned %d records",
                  udp_result.domain().c_str(), udp_result.records().size());
        DnsResult& tcp_result = results[1];
        LOG_DEBUG("TCP SRV record %s returned %d records",
                  tcp_result.domain().c_str(), tcp_result.records().size());

        if (!udp_result.records().empty())
        {
          // UDP SRV lookup returned some records, so use UDP transport.
          LOG_DEBUG("UDP SRV lookup successful, select UDP transport");
          ai.transport = IPPROTO_UDP;
          srv_target = udp_result.domain();
        }
        else if (!tcp_result.records().empty())
        {
          // TCP SRV lookup returned some records, so use TCP transport.
          LOG_DEBUG("TCP SRV lookup successful, select TCP transport");
          ai.transport = IPPROTO_TCP;
          srv_target = tcp_result.domain();
        }
        else
        {
          // Neither UDP nor TCP SRV lookup returned any results, so default to
          // UDP transport and move straight to A/AAAA record lookups.
          LOG_DEBUG("UDP and TCP SRV queries unsuccessful, default to UDP");
          ai.transport = IPPROTO_UDP;
        }
      }

      _naptr_cache->dec_ref(target);
    }
    else if (transport == IPPROTO_UDP)
    {
      // Use specified transport and try an SRV lookup.
      ai.transport = IPPROTO_UDP;
      srv_target = "_sip._udp." + target;
    }
    else if (transport == IPPROTO_TCP)
    {
      // Use specified transport and try an SRV lookup.
      ai.transport = IPPROTO_TCP;
      srv_target = "_sip._tcp." + target;
    }

    if (srv_target != "")
    {
      LOG_DEBUG("Do SRV lookup for %s", srv_target.c_str());
      SRVSelector* srv = _srv_cache->get(srv_target);

      if (srv != NULL)
      {
        // SRV lookup returned a valid selector, so loop selecting servers until
        // we find one which isn't blacklisted.
        LOG_DEBUG("SRV lookup successful");
        while (true)
        {
          LOG_DEBUG("Select an entry from SRV list");
          std::pair<std::string, int> selection = srv->select();
          LOG_DEBUG("Selected %s:%d", selection.first.c_str(), selection.second);

          if (selection.first == "")
          {
            // The selector has no valid, unblacklisted targets, so give up.
            break;
          }

          // SRV selector returned a valid result, so do A/AAAA lookup(s) on
          // this name.
          LOG_DEBUG("Do A/AAAA record lookup for %s", selection.first.c_str());
          std::list<IP46Address> addrs;
          int ttl = a_query(selection.first, af, addrs);
          LOG_DEBUG("Returned %d A/AAAA records", addrs.size());

          if (!addrs.empty())
          {
            // Now filter the list against the global blacklist with the selected
            // transport and port.
            ttl = blacklist_filter(addrs, selection.second, ai.transport);
            LOG_DEBUG("%d candidates not blacklisted", addrs.size());

            if (!addrs.empty())
            {
              // We have at least one valid result, so pick one at random.
              ai.address = select_address(addrs);
              ai.port = selection.second;
              rc = true;
              break;
            }
          }

          // Either the SRV target host name failed to resolve, or all the
          // results are blacklisted.  We will blacklist this target in the SRV
          // selector and try again.
          LOG_DEBUG("Adding SRV selection %s:%d to blacklist for %d seconds",
                    selection.first.c_str(), selection.second, ttl);
          srv->blacklist(selection, ttl);
        }
      }

      _srv_cache->dec_ref(srv_target);
    }

    if (!rc)
    {
      // We either didn't try an SRV lookup or we got no results, so just do
      // an A/AAAA query.
      LOG_DEBUG("Perform A/AAAA record lookup only, target = %s", a_target.c_str());
      ai.port = (port != 0) ? port : 5060;
      std::list<IP46Address> addrs;
      a_query(a_target, af, addrs);

      // Now filter the list against the global blacklist with the selected
      // transport and port.
      blacklist_filter(addrs, ai.port, ai.transport);

      if (!addrs.empty())
      {
        // We have at least one valid result, so pick one at random.
        ai.address = select_address(addrs);
        rc = true;
      }
    }
  }
  return rc;
}

