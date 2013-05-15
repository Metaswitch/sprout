/**
 * @file sas.cpp Dummy implementation of SAS class used for reporting events
 * and markers to Service Assurance Server - does not actually do so
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

#include <time.h>
#include <string.h>
#include <arpa/inet.h>

#include "log.h"
#include "sas.h"


// SAS message types.
const int SAS_MSG_INIT   = 1;
const int SAS_MSG_EVENT  = 3;
const int SAS_MSG_MARKER = 4;

// SAS message header sizes
const int COMMON_HDR_SIZE = 12;
const int INIT_HDR_SIZE   = COMMON_HDR_SIZE;
const int EVENT_HDR_SIZE  = COMMON_HDR_SIZE + 18;
const int MARKER_HDR_SIZE = COMMON_HDR_SIZE + 20;

const int SAS_PORT = 6761;


std::atomic<SAS::TrailId> SAS::_next_trail_id(1);
eventq<std::string> SAS::_msg_q;
pthread_t SAS::_writer;
int SAS::_so;
std::string SAS::_system_name;
std::string SAS::_sas_address;
std::atomic<bool> SAS::_connected(false);


void SAS::init(int system_name_length, const char* system_name, const std::string& sas_address)
{
  _connected = false;

  _system_name = std::string(system_name, system_name_length);
  _sas_address = sas_address;
  _writer = 0;

  if (_sas_address != "0.0.0.0")
  {
    // Spawn a thread to open and write to the SAS connection.
    int rc = pthread_create(&_writer, NULL, &writer_thread, NULL);

    if (rc < 0)
    {
      // LCOV_EXCL_START
      LOG_ERROR("Error creating SAS thread");
      // LCOV_EXCL_STOP
    }
  }
}


void SAS::term()
{
  // Close off the queue.
  _connected = false;

  if (_writer != 0)
  {
    // Signal the writer thread to disconnect the socket and end.
    _msg_q.terminate();

    // Wait for the writer thread to exit.
    pthread_join(_writer, NULL);

    _writer = 0;
  }
}


void* SAS::writer_thread(void* p)
{
  int rc;

  while (true)
  {
    int reconnect_timeout = 10;  // If connect fail, retry every 10 seconds.

    if (connect_init())
    {
      // Open the queue for input
      _connected = true;

      // Now can start dequeuing and sending data.
      std::string msg;
      while (_msg_q.pop(msg))
      {
        LOG_DEBUG("Dequeued SAS message (%d bytes)", msg.length());
        rc = ::send(_so, msg.data(), msg.length(), 0);
        if (rc < 0)
        {
          LOG_ERROR("SAS connection to %s:%d failed: %d %s", _sas_address.c_str(), SAS_PORT, errno, ::strerror(errno));
          ::close(_so);
          break;
        }
        LOG_DEBUG("Sent SAS message (%d bytes)", msg.length());
      }

      // Close the input queue and flush it.
      _connected = false;
      _msg_q.flush();

      // Terminate the socket.
      ::close(_so);

      if (_msg_q.is_terminated())
      {
        // Received a termination signal on the queue, so exit.
        break;
      }

      // Try reconnecting after 1 second after a failure.
      reconnect_timeout = 1;
    }

    // Wait on the input queue for the specified timeout before trying to
    // reconnect.  We wait on the queue so we get a kick if the term function
    // is called.
    std::string msg;
    if (!_msg_q.pop(msg, reconnect_timeout))
    {
      // Received a termination signal on the queue, so exit.
      break;
    }
  }

  return NULL;
}


bool SAS::connect_init()
{
  int rc;
  struct sockaddr_in addr;

  LOG_STATUS("Attempting to connect to SAS %s", _sas_address.c_str());

  if ((_so = ::socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    LOG_ERROR("Failed to open SAS socket: %d (%s)\n", errno, ::strerror(errno));
    return false;
  }

  LOG_DEBUG("Created SAS socket %d", _so);

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(SAS_PORT);
  addr.sin_addr.s_addr = inet_addr(_sas_address.c_str());

  rc = ::connect(_so, (struct sockaddr*)&addr, sizeof(addr));

  if (rc != 0)
  {
    LOG_ERROR("Failed to connect to SAS %s:%d : %d %s\n", _sas_address.c_str(), SAS_PORT, errno, ::strerror(errno));
    ::close(_so);
    return false;
  }

  LOG_DEBUG("Connected SAS socket to %s:%d", _sas_address.c_str(), SAS_PORT);

  // Send an init message to SAS.
  std::string init;
  std::string version("v0.1");
  int init_len = INIT_HDR_SIZE + 1 + _system_name.length() + 4 + 1 + version.length();
  init.reserve(init_len);
  write_hdr(init, init_len, SAS_MSG_INIT);
  write_int8(init, (uint8_t)_system_name.length());
  write_data(init, _system_name.length(), _system_name.data());
  int endianness = 1;
  init.append((char*)&endianness, sizeof(int));     // Endianness must be written in machine order.
  write_int8(init, version.length());
  write_data(init, version.length(), version.data());

  LOG_DEBUG("Sending SAS INIT message");

  rc = ::send(_so, init.data(), init.length(), 0);
  if (rc < 0)
  {
    LOG_ERROR("SAS connection to %s:%d failed: %d %s", _sas_address.c_str(), SAS_PORT, errno, ::strerror(errno));
    return false;
  }

  LOG_STATUS("Connected to SAS %s:%d", _sas_address.c_str(), SAS_PORT);

  return true;
}


SAS::TrailId SAS::new_trail(uint32_t instance)
{
  TrailId trail = _next_trail_id++;
  return trail;
}


void SAS::report_event(const Event& event)
{
  if (_connected)
  {
    _msg_q.push_noblock(event.to_string());
  }
}


void SAS::report_marker(const Marker& marker)
{
  if (_connected)
  {
    _msg_q.push_noblock(marker.to_string(Marker::Scope::None));
  }
}


void SAS::report_marker(const Marker& marker, Marker::Scope scope)
{
  if (_connected)
  {
    _msg_q.push_noblock(marker.to_string(scope));
  }
}


void SAS::write_hdr(std::string& s, uint16_t msg_length, uint8_t msg_type)
{
  SAS::write_int16(s, msg_length);
  SAS::write_int8(s, 1);             // Version = 1
  SAS::write_int8(s, msg_type);
  SAS::write_timestamp(s);
}


void SAS::write_int8(std::string& s, uint8_t c)
{
  s.append(1, c);
}


void SAS::write_int16(std::string& s, uint16_t v)
{
  uint16_t v_nw = htons(v);
  s.append((char*)&v_nw, sizeof(uint16_t));
}


void SAS::write_int32(std::string& s, uint32_t v)
{
  uint32_t v_nw = htonl(v);
  s.append((char*)&v_nw, sizeof(uint32_t));
}


void SAS::write_int64(std::string& s, uint64_t v)
{
  uint32_t vh_nw = htonl(v >> 32);
  uint32_t vl_nw = htonl(v & 0xffffffff);
  s.append((char*)&vh_nw, sizeof(uint32_t));
  s.append((char*)&vl_nw, sizeof(uint32_t));
}


void SAS::write_data(std::string& s, size_t len, const char* data)
{
  s.append(data, len);
}


void SAS::write_timestamp(std::string& s)
{
  unsigned long long timestamp;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  timestamp = ts.tv_sec;
  timestamp = timestamp * 1000 + (ts.tv_nsec / 1000000);
  write_int64(s, timestamp);
}


void SAS::write_trail(std::string& s, TrailId trail)
{
  write_int64(s, trail);
}


std::string SAS::Event::to_string() const
{
  std::string s;
  int msg_length = EVENT_HDR_SIZE + _msg.hdr.static_data_len;
  for (uint32_t ii = 0; ii < _msg.hdr.num_var_data; ++ii)
  {
    msg_length += sizeof(uint16_t) + _msg.var_data[ii].len;
  }
  s.reserve(msg_length);

  SAS::write_hdr(s, msg_length, SAS_MSG_EVENT);
  write_trail(s, _trail);
  write_int32(s, _msg.hdr.id);
  write_int32(s, _msg.hdr.instance);
  write_int16(s, _msg.hdr.static_data_len);
  for (uint32_t ii = 0; ii < _msg.hdr.static_data_len / 4; ++ii)
  {
    write_int32(s, _msg.static_data[ii]);
  }
  for (uint32_t ii = 0; ii < _msg.hdr.num_var_data; ++ii)
  {
    write_int16(s, _msg.var_data[ii].len);
    write_data(s, _msg.var_data[ii].len, (char *)_msg.var_data[ii].ptr);
  }

  LOG_DEBUG("Built SAS event message (%d bytes)", s.length());

  return s;
}


std::string SAS::Marker::to_string(Marker::Scope scope) const
{
  std::string s;

  int msg_length = MARKER_HDR_SIZE + _msg.hdr.static_data_len;
  for (uint32_t ii = 0; ii < _msg.hdr.num_var_data; ++ii)
  {
    msg_length += sizeof(uint16_t) + _msg.var_data[ii].len;
  }
  s.reserve(msg_length);

  write_hdr(s, msg_length, SAS_MSG_MARKER);
  write_trail(s, _trail);
  write_int32(s, _msg.hdr.id);
  write_int32(s, _msg.hdr.instance);
  write_int8(s, (uint8_t)(scope != Scope::None));
  write_int8(s, (uint8_t)scope);
  write_int16(s, _msg.hdr.static_data_len);
  for (uint32_t ii = 0; ii < _msg.hdr.static_data_len / 4; ++ii)
  {
    write_int32(s, _msg.static_data[ii]);
  }
  for (uint32_t ii = 0; ii < _msg.hdr.num_var_data; ++ii)
  {
    write_int16(s, _msg.var_data[ii].len);
    write_data(s, _msg.var_data[ii].len, (char *)_msg.var_data[ii].ptr);
  }

  LOG_DEBUG("Built SAS marker message (%d bytes)", s.length());

  return s;
}



