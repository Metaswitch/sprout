/**
 * @file sas.cpp Implementation of SAS class used for reporting events
 * and markers to Service Assurance Server.
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
#include <unistd.h>

#include "log.h"
#include "sas.h"


// SAS message types.
const int SAS_MSG_INIT   = 1;
const int SAS_MSG_EVENT  = 3;
const int SAS_MSG_MARKER = 4;

// SAS message header sizes
const int COMMON_HDR_SIZE = sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
const int INIT_HDR_SIZE   = COMMON_HDR_SIZE;
const int EVENT_HDR_SIZE  = COMMON_HDR_SIZE + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t);
const int MARKER_HDR_SIZE = COMMON_HDR_SIZE + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);

const int SAS_PORT = 6761;


std::atomic<SAS::TrailId> SAS::_next_trail_id(1);
SAS::Connection* SAS::_connection = NULL;


void SAS::init(int system_name_length, const char* system_name, const std::string& sas_address)
{
  if (sas_address != "0.0.0.0")
  {
    _connection = new Connection(std::string(system_name, system_name_length),
                                 sas_address);
  }
}


void SAS::term()
{
  delete _connection;
  _connection = NULL;
}


SAS::Connection::Connection(const std::string& system_name, const std::string& sas_address) :
  _system_name(system_name),
  _sas_address(sas_address),
  _msg_q(MAX_MSG_QUEUE, false),
  _writer(0),
  _sock(-1)
{
  // Spawn a thread to open and write to the SAS connection.
  int rc = pthread_create(&_writer, NULL, &writer_thread, this);

  if (rc < 0)
  {
    // LCOV_EXCL_START
    LOG_ERROR("Error creating SAS thread");
    // LCOV_EXCL_STOP
  }
}


SAS::Connection::~Connection()
{
  // Close off the queue.
  _msg_q.close();

  if (_writer != 0)
  {
    // Signal the writer thread to disconnect the socket and end.
    _msg_q.terminate();

    // Wait for the writer thread to exit.
    pthread_join(_writer, NULL);

    _writer = 0;
  }
}


void* SAS::Connection::writer_thread(void* p)
{
  ((SAS::Connection*)p)->writer();
  return NULL;
}


void SAS::Connection::writer()
{
  while (true)
  {
    int reconnect_timeout = 10000;  // If connect fails, retry every 10 seconds.

    if (connect_init())
    {
      // Open the queue for input
      _msg_q.open();

      // Now can start dequeuing and sending data.
      std::string msg;
      while ((_sock != -1) && (_msg_q.pop(msg)))
      {
        int len = msg.length();
        char* buf = (char*)msg.data();
        while (len > 0)
        {
          int flags = 0;
#ifdef MSG_NOSIGNAL
          flags |= MSG_NOSIGNAL;
#endif
          int nsent = ::send(_sock, buf, len, flags);
          if (nsent > 0)
          {
            len -= nsent;
            buf += nsent;
          }
          else if ((nsent < 0) && (errno != EINTR))
          {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN))
            {
              // The send timeout has expired, so close the socket so we
              // try to connect again (and avoid buffering data while waiting
              // for long TCP timeouts).
              LOG_ERROR("SAS connection to %s:%d locked up: %d %s", _sas_address.c_str(), SAS_PORT, errno, ::strerror(errno));
            }
            else
            {
              // The socket has failed.
              LOG_ERROR("SAS connection to %s:%d failed: %d %s", _sas_address.c_str(), SAS_PORT, errno, ::strerror(errno));
            }
            ::close(_sock);
            _sock = -1;
            break;
          }
        }
      }

      // Close the input queue and purge it.
      _msg_q.close();
      _msg_q.purge();

      // Terminate the socket.
      ::close(_sock);

      if (_msg_q.is_terminated())
      {
        // Received a termination signal on the queue, so exit.
        break;
      }

      // Try reconnecting after 1 second after a failure.
      reconnect_timeout = 1000;
    }

    // Wait on the input queue for the specified timeout before trying to
    // reconnect.  We wait on the queue so we get a kick if the term function
    // is called.
    std::string msg;
    LOG_DEBUG("Waiting to reconnect to SAS - timeout = %d", reconnect_timeout);
    if (!_msg_q.pop(msg, reconnect_timeout))
    {
      // Received a termination signal on the queue, so exit.
      break;
    }
  }
}


bool SAS::Connection::connect_init()
{
  int rc;
  struct sockaddr_in addr;

  LOG_STATUS("Attempting to connect to SAS %s", _sas_address.c_str());

  if ((_sock = ::socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    LOG_ERROR("Failed to open SAS socket: %d (%s)\n", errno, ::strerror(errno));
    return false;
  }

  // Set a maximum send timeout on the socket so we don't wait forever if the
  // connection fails.
  struct timeval timeout;      
  timeout.tv_sec = SEND_TIMEOUT;
  timeout.tv_usec = 0;

  rc = ::setsockopt(_sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
  if (rc < 0) 
  {
    LOG_ERROR("Failed to set send timeout on SAS connection : %d %d %s", rc, errno, ::strerror(errno));
    ::close(_sock);
    _sock = -1;
    return false;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(SAS_PORT);
  addr.sin_addr.s_addr = inet_addr(_sas_address.c_str());

  rc = ::connect(_sock, (struct sockaddr*)&addr, sizeof(addr));

  if (rc != 0)
  {
    LOG_ERROR("Failed to connect to SAS %s:%d : %d %s", _sas_address.c_str(), SAS_PORT, errno, ::strerror(errno));
    ::close(_sock);
    _sock = -1;
    return false;
  }

  LOG_DEBUG("Connected SAS socket to %s:%d", _sas_address.c_str(), SAS_PORT);

  // Send an init message to SAS.
  std::string init;
  std::string version("v0.1");
  int init_len = INIT_HDR_SIZE + sizeof(uint8_t) + _system_name.length() + sizeof(uint32_t) + sizeof(uint8_t) + version.length();
  init.reserve(init_len);
  write_hdr(init, init_len, SAS_MSG_INIT);
  write_int8(init, (uint8_t)_system_name.length());
  write_data(init, _system_name.length(), _system_name.data());
  int endianness = 1;
  init.append((char*)&endianness, sizeof(int));     // Endianness must be written in machine order.
  write_int8(init, version.length());
  write_data(init, version.length(), version.data());

  LOG_DEBUG("Sending SAS INIT message");

  rc = ::send(_sock, init.data(), init.length(), 0);
  if (rc < 0)
  {
    LOG_ERROR("SAS connection to %s:%d failed: %d %s", _sas_address.c_str(), SAS_PORT, errno, ::strerror(errno));
    ::close(_sock);
    _sock = -1;
    return false;
  }

  LOG_STATUS("Connected to SAS %s:%d", _sas_address.c_str(), SAS_PORT);

  return true;
}


void SAS::Connection::send_msg(std::string msg)
{
  _msg_q.push_noblock(msg);
}


SAS::TrailId SAS::new_trail(uint32_t instance)
{
  TrailId trail = _next_trail_id++;
  return trail;
}


void SAS::report_event(const Event& event)
{
  if (_connection)
  {
    _connection->send_msg(event.to_string());
  }
}


void SAS::report_marker(const Marker& marker, Marker::Scope scope)
{
  if (_connection)
  {
    _connection->send_msg(marker.to_string(scope));
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
  s.append((char*)&c, sizeof(uint8_t));
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
    // Static parameters are written in native byte order, not network order.
    write_data(s, sizeof(uint32_t), (char *)&_msg.static_data[ii]);
  }
  for (uint32_t ii = 0; ii < _msg.hdr.num_var_data; ++ii)
  {
    write_int16(s, _msg.var_data[ii].len);
    write_data(s, _msg.var_data[ii].len, (char *)_msg.var_data[ii].ptr);
  }

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
    // Static parameters are written in native byte order, not network order.
    write_data(s, sizeof(uint32_t), (char *)&_msg.static_data[ii]);
  }
  for (uint32_t ii = 0; ii < _msg.hdr.num_var_data; ++ii)
  {
    write_int16(s, _msg.var_data[ii].len);
    write_data(s, _msg.var_data[ii].len, (char *)_msg.var_data[ii].ptr);
  }

  return s;
}



