/**
 * @file enumservice.cpp class implementation for an ENUM service provider
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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

  // ARES_FLAG_STAYOPEN implements TCP keepalive - it doesn't do
  // anything obviously helpful for UDP connections to the DNS server,
  // but it's what we've always tested with so not worth the risk of removing.
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

  // Convert our vector of IP46Addresses into the linked list of
  // ares_addr_nodes which ares_set_server takes.
  size_t server_count = std::min((size_t)3u, servers.size());
  for (size_t ii = 0;
       ii < server_count;
       ii++)
  {
    IP46Address server = servers[ii];
    struct ares_addr_node* ares_addr = &_ares_addrs[ii];
    memset(ares_addr, 0, sizeof(struct ares_addr_node));
    if (ii > 0)
    {
      int prev_idx = ii - 1;
      _ares_addrs[prev_idx].next = ares_addr;
    }

    ares_addr->family = server.af;
    if (server.af == AF_INET)
    {
      memcpy(&ares_addr->addr.addr4, &server.addr.ipv4, sizeof(ares_addr->addr.addr4));
    }
    else
    {
      memcpy(&ares_addr->addr.addr6, &server.addr.ipv6, sizeof(ares_addr->addr.addr6));
    }
  }
  ares_set_servers(_channel, &(_ares_addrs[0]));
}


DNSResolver::~DNSResolver()
{
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
  TRC_DEBUG("Sending DNS NAPTR query for %s", domain.c_str());
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
      TRC_WARNING("Unparseable DNS ENUM response from host %s: %s", _domain.c_str(), ares_strerror(status));
    }
  }
  else
  {
    // Log that we've failed.
    TRC_WARNING("DNS ENUM query failed for host %s: %s", _domain.c_str(), ares_strerror(status));
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
