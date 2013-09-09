/**
 * @file cw_stat.cpp
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

// C++ re-implementation of Ruby cw_stat tool.
// Runs significantly faster - useful on heavily-loaded cacti systems.
// Usage: cw_stat <hostname> <statname>
// Compile: g++ -o cw_stat cw_stat.cpp -lzmq

#include <string>
#include <vector>
#include <string.h>
#include <stdint.h>
#include <zmq.h>

// Gets a block of messages from the specified host, for the specified
// statistic.
// Return true on success, false on failure.
bool get_msgs(char* host, char* stat, std::vector<std::string>& msgs)
{
  // Create the context.
  void* ctx = zmq_ctx_new();
  if (ctx == NULL)
  {
    perror("zmq_ctx_new");
    return false;
  }

  // Create the socket and connect it to the host.
  void* sck = zmq_socket(ctx, ZMQ_SUB);
  if (sck == NULL)
  {
    perror("zmq_socket");
    return false;
  }
  std::string ep = std::string("tcp://") + host + ":6666";
  if (zmq_connect(sck, ep.c_str()) != 0)
  {
    perror("zmq_connect");
    return false;
  }

  // Subscribe to the specified statistic.
  if (zmq_setsockopt(sck, ZMQ_SUBSCRIBE, stat, strlen(stat)) != 0)
  {
    perror("zmq_setsockopt");
    return false;
  }

  // Spin round until we've got all the messages in this block.
  int64_t more = 0;
  size_t more_sz = sizeof(more);
  do
  {
    zmq_msg_t msg;
    if (zmq_msg_init(&msg) != 0)
    {
      perror("zmq_msg_init");
      return false;
    }
    if (zmq_msg_recv(&msg, sck, 0) == -1)
    {
      perror("zmq_msg_recv");
      return false;
    }
    msgs.push_back(std::string((char*)zmq_msg_data(&msg), zmq_msg_size(&msg)));
    if (zmq_getsockopt(sck, ZMQ_RCVMORE, &more, &more_sz) != 0)
    {
      perror("zmq_getsockopt");
      return false;
    }
    zmq_msg_close(&msg);
  }
  while (more);

  // Close the socket.
  if (zmq_close(sck) != 0)
  {
    perror("zmq_close");
    return false;
  }
  sck = NULL;

  // Destroy the context.
  if (zmq_ctx_destroy(ctx) != 0)
  {
    perror("zmq_ctx_destroy");
    return false;
  }
  ctx = NULL;

  return true;
}

// Render a simple statistic - just output its value.
void render_simple_stat(std::vector<std::string>& msgs)
{
  if (msgs.size() >= 3)
  {
    printf("%s\n", msgs[2].c_str());
  }
  else
  {
    printf("No value returned\n");
  }
}

// Render a list of IP addresses and counts.
void render_connected_ips(std::vector<std::string>& msgs)
{
  for (int msg_idx = 2; msg_idx < (int)msgs.size(); msg_idx += 2)
  {
    printf("%s: %s\n", msgs[msg_idx].c_str(), msgs[msg_idx + 1].c_str());
  }
}

// Render a set of call statistics.  The names here match those in Ruby
// cw_stat.
void render_call_stats(std::vector<std::string>& msgs)
{
  if (msgs.size() >= 10 )
  {
    printf("initial_registers:%s\n", msgs[2].c_str());
    printf("initial_registers_delta:%s\n", msgs[6].c_str());
    printf("ongoing_registers:%s\n", msgs[3].c_str());
    printf("ongoing_registers_delta:%s\n", msgs[7].c_str());
    printf("call_attempts:%s\n", msgs[4].c_str());
    printf("call_attempts_delta:%s\n", msgs[8].c_str());
    printf("successful_calls:%s\n", msgs[5].c_str());
    printf("successful_calls_delta:%s\n", msgs[9].c_str());
  }
  else
  {
    fprintf(stderr, "Too short call statistics - %d < 10", (int)msgs.size());
  }
}

// Render a set of latency statistics.  The names here match those in Ruby
// cw_stat.
void render_latency_us(std::vector<std::string>& msgs)
{
  if (msgs.size() >= 6 )
  {
    printf("mean:%s\n", msgs[2].c_str());
    printf("variance:%s\n", msgs[3].c_str());
    printf("lwm:%s\n", msgs[4].c_str());
    printf("hwm:%s\n", msgs[5].c_str());
  }
  else
  {
    fprintf(stderr, "Too short call statistics - %d < 6", (int)msgs.size());
  }
}

int main(int argc, char** argv)
{
  // Check arguments.
  if (argc != 3)
  {
    fprintf(stderr, "Usage: %s <hostname> <statname>\n", argv[0]);
    return 1;
  }

  // Get messages from the server.
  std::vector<std::string> msgs;
  if (!get_msgs(argv[1], argv[2], msgs))
  {
    return 2;
  }

  // The messages start with the statistic name and "OK" (hopefully).
  if ((msgs.size() >= 2) &&
      (msgs[1] == "OK"))
  {
    // Determine which statistic we have and output it.
    if (msgs[0] == "client_count")
    {
      render_simple_stat(msgs);
    }
    else if ((msgs[0] == "connected_homesteads") ||
             (msgs[0] == "connected_homers") ||
             (msgs[0] == "connected_sprouts"))
    {
      render_connected_ips(msgs);
    }
    else if (msgs[0] == "call_stats")
    {
      render_call_stats(msgs);
    }
    else if ((msgs[0] == "latency_us") ||
             (msgs[0] == "hss_latency_us") ||
             (msgs[0] == "hss_digest_latency_us") ||
             (msgs[0] == "hss_assoc_uri_latency_us") ||
             (msgs[0] == "hss_ifc_latency_us") ||
             (msgs[0] == "xdm_latency_us"))
    {
      render_latency_us(msgs);
    }
    else
    {
      fprintf(stderr, "Unknown statistic \"%s\"\n", msgs[0].c_str());
    }
  }
  else if (msgs.size() == 1)
  {
    fprintf(stderr, "Incomplete response \"%s\"\n", msgs[0].c_str());
  }
  else
  {
    fprintf(stderr, "Error response \"%s\" for statistic \"%s\"\n", msgs[1].c_str(), msgs[0].c_str());
  }

  return 0;
}
