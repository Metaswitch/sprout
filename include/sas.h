/**
 * @file sas.h Definition of SAS class used for reporting events and markers
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

/// to Service Assurance Server
///
///

#ifndef SAS_H__
#define SAS_H__

#include <string.h>

class SAS
{
public:
  typedef unsigned long long TrailId;

  class Message
  {
  public:
    static const int MAX_NUM_STATIC_PARAMS = 20;
    static const int MAX_NUM_VAR_PARAMS = 20;

    inline Message(TrailId trail, unsigned long id, unsigned long instance)
    {
      _trail = trail;
      _msg.hdr.id = id;
      _msg.hdr.instance = instance;
      _msg.hdr.static_data_len = 0;
      _msg.hdr.num_var_data = 0;
      _msg.hdr.var_data_array = _msg.var_data;
    }

    inline Message& add_static_param(unsigned long param)
    {
      _msg.static_data[_msg.hdr.static_data_len / sizeof(unsigned long)] = param;
      _msg.hdr.static_data_len += sizeof(unsigned long);
      return *this;
    }

    inline Message& add_var_param(int len, unsigned char* data)
    {
      _msg.var_data[_msg.hdr.num_var_data].len = (unsigned long)len;
      _msg.var_data[_msg.hdr.num_var_data].ptr = data;
      ++_msg.hdr.num_var_data;
      return *this;
    }

    inline Message& add_var_param(int len, char* s)
    {
      return add_var_param(len, (unsigned char*)s);
    }

    inline Message& add_var_param(char* s)
    {
      return add_var_param(strlen(s), (unsigned char*)s);
    }

    inline Message& add_var_param(const std::string& s)
    {
      return add_var_param(s.length(), (unsigned char*)s.data());
    }

    friend class SAS;

  private:
    TrailId _trail;
    struct
    {
      struct
      {
        unsigned long id;
        unsigned long instance;
        unsigned long static_data_len;
        unsigned long num_var_data;
        void* var_data_array;
      } hdr;
      unsigned long static_data[MAX_NUM_STATIC_PARAMS];
      struct {
        unsigned long len;
        unsigned char* ptr;
      } var_data[MAX_NUM_VAR_PARAMS];
    } _msg;
  };

  class Event : public Message
  {
  public:
    inline Event(TrailId trail, unsigned long event, unsigned long instance) :
      Message(trail, event, instance)
    {
    }
  };

  class Marker : public Message
  {
  public:
    inline Marker(TrailId trail, unsigned long marker, unsigned long instance) :
      Message(trail, marker, instance)
    {
    }

    enum Scope
    {
      Branch = 1,
      TrailGroup = 2
    };
  };

  static void init(int system_name_length, const char* system_name, const std::string& sas_address);
  static void term();
  static TrailId new_trail(unsigned long instance);
  static void report_event(const Event& event);
  static void report_marker(const Marker& marker);
  static void report_marker(const Marker& marker, Marker::Scope scope);
};

#endif
