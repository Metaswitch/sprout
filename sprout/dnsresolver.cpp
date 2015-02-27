/**
 * @file enumservice.cpp class implementation for an ENUM service provider
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

#include <fstream>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <boost/algorithm/string/predicate.hpp>
#include <poll.h>

#include "dnsresolver.h"
#include "log.h"
#include "sproutsasevent.h"

DNSResolver::DNSResolver(const std::vector<struct IP46Address>& servers) :
                         _req_pending(false),
                         _trail(0),
                         _domain(""),
                         _status(ARES_SUCCESS),
                         _naptr_reply(NULL)
{
  // Set options to ensure we always get a response as quickly as possible -
  // we are on the call path!
  struct ares_options options;
  options.flags = ARES_FLAG_STAYOPEN;
  options.timeout = 1000;
  options.tries = servers.size();
  options.ndots = 0;
  options.servers = NULL;
  options.nservers = 0;
  ares_init_options(&_channel,
                    &options,
                    ARES_OPT_FLAGS |
                    ARES_OPT_TIMEOUTMS |
                    ARES_OPT_TRIES |
                    ARES_OPT_NDOTS |
                    ARES_OPT_SERVERS);

  // Point the DNS resolver at the desired server.  We must use
  // ares_set_servers rather than setting it in the options for IPv6 support,
  struct ares_addr_node *first_addr = NULL;
  struct ares_addr_node *addr = first_addr;

  // Convert our vector of IP46Addresses into the linked list of
  // ares_addr_nodes which ares_set_server takes.
  for (std::vector<struct IP46Address>::const_iterator server = servers.begin();
       server != servers.end();
       server++)
  {
    struct ares_addr_node* new_addr = (struct ares_addr_node*)malloc(sizeof(struct ares_addr_node));
    memset(new_addr, 0, sizeof(struct ares_addr_node));
    if (addr)
    {
      addr->next = new_addr;
    }
    else
    {
      first_addr = new_addr;
    }
    addr = new_addr;
    addr->family = server->af;
    if (server->af == AF_INET)
    {
      memcpy(&addr->addr.addr4, &server->addr.ipv4, sizeof(addr->addr.addr4));
    }
    else
    {
      memcpy(&addr->addr.addr6, &server->addr.ipv6, sizeof(addr->addr.addr6));
    }
  }
  ares_set_servers(_channel, first_addr);
}


DNSResolver::~DNSResolver()
{
  struct ares_addr_node *addr = NULL;
  ares_get_servers(_channel, &addr);

  while (addr != NULL)
  {
    struct ares_addr_node *tmp = addr->next;
    free(addr);
    addr = tmp;
  }

  ares_destroy(_channel);

  // If we have a left-over NAPTR reply, destroy it.
  if (_naptr_reply != NULL)
  {
    free_naptr_reply(_naptr_reply);
    _naptr_reply = NULL;
  }
}


void DNSResolver::destroy(DNSResolver* resolver)
{
  delete resolver;
}


int DNSResolver::perform_naptr_query(const std::string& domain, struct ares_naptr_reply*& naptr_reply, SAS::TrailId trail)
{
  send_naptr_query(domain, trail);
  wait_for_response();

  // Save off the results...
  naptr_reply = _naptr_reply;
  int status = _status;
  // ...and then clear out our state.
  _trail = 0;
  _domain = "";
  _naptr_reply = NULL;
  _status = ARES_SUCCESS;

  return status;
}


void DNSResolver::free_naptr_reply(struct ares_naptr_reply* naptr_reply) const
{
  // Just call through to ares to free off the data.
  ares_free_data(naptr_reply);
}


void DNSResolver::send_naptr_query(const std::string& domain, SAS::TrailId trail)
{
  // Log the query.
  SAS::Event event(trail, SASEvent::TX_ENUM_REQ, 0);
  event.add_var_param(domain);
  SAS::report_event(event);
  _trail = trail;
  _domain = domain;

  // Send the query.
  LOG_DEBUG("Sending DNS NAPTR query for %s", domain.c_str());
  _req_pending = true;
  ares_query(_channel,
             domain.c_str(),
             ns_c_in,
             ns_t_naptr,
             DNSResolver::ares_callback,
             this);
}


void DNSResolver::wait_for_response()
{
  // Wait until the request is complete.
  while (_req_pending)
  {
    // Call into ares to get details of the sockets it's using.
    ares_socket_t scks[ARES_GETSOCK_MAXNUM];
    int rw_bits = ares_getsock(_channel, scks, ARES_GETSOCK_MAXNUM);

    // Translate these sockets into pollfd structures.
    int num_fds = 0;
    struct pollfd fds[ARES_GETSOCK_MAXNUM];
    for (int fd_idx = 0; fd_idx < ARES_GETSOCK_MAXNUM; fd_idx++)
    {
      struct pollfd* fd = &fds[fd_idx];
      fd->fd = scks[fd_idx];
      fd->events = 0;
      fd->revents = 0;
      if (ARES_GETSOCK_READABLE(rw_bits, fd_idx))
      {
        fd->events |= POLLRDNORM | POLLIN;
      }
      if (ARES_GETSOCK_WRITABLE(rw_bits, fd_idx))
      {
        fd->events |= POLLWRNORM | POLLOUT;
      }
      if (fd->events != 0)
      {
        num_fds++;
      }
    }

    // Calculate the timeout.
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    (void)ares_timeout(_channel, NULL, &tv);

    // Wait for events on these file descriptors.
    if (poll(fds, num_fds, tv.tv_sec * 1000 + tv.tv_usec / 1000) != 0)
    {
      // We got at least one event, so find which file descriptor(s) this was on.
      for (int fd_idx = 0; fd_idx < num_fds; fd_idx++)
      {
        struct pollfd* fd = &fds[fd_idx];
        if (fd->revents != 0)
        {
          // Call into ares to notify it of the event.  The interface requires
          // that we pass separate file descriptors for read and write events
          // or ARES_SOCKET_BAD if no event has occurred.
          ares_process_fd(_channel,
                          fd->revents & (POLLRDNORM | POLLIN) ? fd->fd : ARES_SOCKET_BAD,
                          fd->revents & (POLLWRNORM | POLLOUT) ? fd->fd : ARES_SOCKET_BAD);
        }
      }
    }
    else
    {
      // No events, so just call into ares with no file descriptor to let it handle timeouts.
      ares_process_fd(_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }
  }
}


void DNSResolver::ares_callback(void* arg,
                                int status,
                                int timeouts,
                                unsigned char* abuf,
                                int alen)
{
  ((DNSResolver*)arg)->ares_callback(status, timeouts, abuf, alen);
}


void DNSResolver::ares_callback(int status,
                                int timeouts,
                                unsigned char* abuf,
                                int alen)
{
  _status = status;
  if (status == ARES_SUCCESS)
  {
    // Log that we've succeeded.
    SAS::Event event(_trail, SASEvent::RX_ENUM_RSP, 0);
    event.add_var_param(_domain);
    event.add_var_param(alen, abuf);
    SAS::report_event(event);

    // Parse the reply.
    _status = ares_parse_naptr_reply(abuf, alen, &_naptr_reply);
    if (_status != ARES_SUCCESS)
    {
      LOG_WARNING("Unparseable DNS ENUM response from host %s: %s", _domain.c_str(), ares_strerror(status));
    }
  }
  else
  {
    // Log that we've failed.
    LOG_WARNING("DNS ENUM query failed for host %s: %s", _domain.c_str(), ares_strerror(status));
    SAS::Event event(_trail, SASEvent::RX_ENUM_ERR, 0);
    event.add_static_param(status);
    event.add_var_param(_domain);
    SAS::report_event(event);
  }
  _req_pending = false;
}


DNSResolver* DNSResolverFactory::new_resolver(const std::vector<struct IP46Address>& servers) const
{
  return new DNSResolver(servers);
}
