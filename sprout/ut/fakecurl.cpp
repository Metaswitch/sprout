/**
 * @file fakecurl.cpp Fake cURL library for testing.
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

#include "fakecurl.hpp"

#include <cstdarg>
#include <stdexcept>

using namespace std;

typedef size_t (*datafn_ty)(char* ptr, size_t size, size_t nmemb, void* userdata);

/// Object representing a single fake cURL handle.
class FakeCurl
{
public:
  string _method;
  string _url;

  list<string> _headers;

  bool _failonerror;
  long _httpauth;  //^ OR of CURLAUTH_* constants
  string _username;
  string _password;
  bool _fresh;

  datafn_ty _readfn;
  void* _readdata; //^ user data; not owned by this object

  datafn_ty _writefn;
  void* _writedata; //^ user data; not owned by this object

  datafn_ty _hdrfn;
  void* _hdrdata; //^ user data; not owned by this object

  void* _private;

  FakeCurl() :
    _method("GET"),
    _failonerror(false),
    _httpauth(0L),
    _fresh(false),
    _readfn(NULL),
    _readdata(NULL),
    _writefn(NULL),
    _writedata(NULL),
    _hdrfn(NULL),
    _hdrdata(NULL),
    _private(NULL)
  {
  }

  virtual ~FakeCurl()
  {
  }

  CURLcode easy_perform();
};

/// Responses to give, by URL.
map<string,Response> fakecurl_responses;

/// Requests received, by URL.
map<string,Request> fakecurl_requests;

CURLcode FakeCurl::easy_perform()
{
  // Save off the request.
  Request req;
  req._method = _method;
  req._headers = _headers;
  req._httpauth = _httpauth;
  req._username = _username;
  req._password = _password;
  req._fresh = _fresh;
  req._body = "";

  if (_readfn != NULL)
  {
    char rbuf[1024];
    int rlen;

    while (0 != (rlen = _readfn(rbuf, sizeof(rbuf), 1, _readdata)))
    {
      req._body.append(rbuf, rlen);
    }
  }

  fakecurl_requests[_url] = req;

  // Check if there's a response ready.
  map<string,Response>::iterator iter = fakecurl_responses.find(_url);
  if (iter == fakecurl_responses.end())
  {
    string msg("cURL URL ");
    msg.append(_url).append(" unknown to FakeCurl");
    throw runtime_error(msg);
  }

  // Send the response.
  Response& resp = iter->second;
  CURLcode rc;

  if (resp._code_once != CURLE_OK)
  {
    // Return this code just once.
    rc = resp._code_once;
    resp._code_once = CURLE_OK;
  }
  else
  {
    rc = resp._code;

    if (_writefn != NULL)
    {
      int len = resp._body.length();
      char* ptr = const_cast<char*>(resp._body.c_str());
      int handled = _writefn(ptr, 1, len, _writedata);

      if (handled != len)
      {
        throw runtime_error("Write function didn't handle everything");
      }
    }

    if (_hdrfn != NULL)
    {
      for (std::list<string>::const_iterator it = resp._headers.begin();
           it != resp._headers.end(); ++it)
      {
        int len = it->length();
        char* ptr = const_cast<char*>(it->c_str());
        int handled = _hdrfn(ptr, 1, len, _hdrdata);

        if (handled != len)
        {
          throw runtime_error("Header function didn't handle everything");
        }
      }
    }
  }

  return rc;
}

CURLcode curl_global_init(long flags)
{
  // Don't care too much about this.
  return CURLE_OK;
}

CURL* curl_easy_init()
{
  FakeCurl* curl = new FakeCurl();
  return (CURL*)curl;
}

void curl_easy_cleanup(CURL* handle)
{
  FakeCurl* curl = (FakeCurl*)handle;
  delete curl;
}

CURLcode curl_easy_setopt(CURL* handle, CURLoption option, ...)
{
  va_list args;
  va_start(args, option);
  FakeCurl* curl = (FakeCurl*)handle;

  switch (option)
  {
  case CURLOPT_PRIVATE:
  {
    curl->_private = va_arg(args, void*);
  }
  break;
  case CURLOPT_HTTPHEADER:
  {
    struct curl_slist* headers = va_arg(args, struct curl_slist*);
    list<string>* truelist = (list<string>*)headers;
    if (truelist != NULL)
    {
      curl->_headers = *truelist;
    }
    else
    {
      curl->_headers.clear();
    }
  }
  break;
  case CURLOPT_URL:
  {
    curl->_url = va_arg(args, char*);
  }
  break;
  case CURLOPT_WRITEFUNCTION:
  {
    curl->_writefn = va_arg(args, datafn_ty);
  }
  break;
  case CURLOPT_WRITEDATA:
  {
    curl->_writedata = va_arg(args, void*);
  }
  break;
  case CURLOPT_FAILONERROR:
  {
    curl->_failonerror = va_arg(args, long);
  }
  break;
  case CURLOPT_HTTPAUTH:
  {
    curl->_httpauth = va_arg(args, long);
  }
  break;
  case CURLOPT_USERNAME:
  {
    curl->_username = va_arg(args, char*);
  }
  break;
  case CURLOPT_PASSWORD:
  {
    curl->_password = va_arg(args, char*);
  }
  break;
  case CURLOPT_PUT:
  {
    if (va_arg(args, long))
    {
      curl->_method = "PUT";
    }
  }
  break;
  case CURLOPT_HTTPGET:
  {
    if (va_arg(args, long))
    {
      curl->_method = "GET";
    }
  }
  break;
  case CURLOPT_POST:
  {
    if (va_arg(args, long))
    {
      curl->_method = "POST";
    }
  }
  break;
  case CURLOPT_READDATA:
  {
    curl->_readdata = va_arg(args, void*);
  }
  break;
  case CURLOPT_READFUNCTION:
  {
    curl->_readfn = va_arg(args, datafn_ty);
  }
  break;
  case CURLOPT_CUSTOMREQUEST:
  {
    char* method = va_arg(args, char*);
    if (method != NULL)
    {
      curl->_method = method;
    }
    else
    {
      curl->_method = "GET";
    }
  }
  break;
  case CURLOPT_FRESH_CONNECT:
  {
    curl->_fresh = !!va_arg(args, long);
  }
  break;
  case CURLOPT_HEADERFUNCTION:
  {
    curl->_hdrfn = va_arg(args, datafn_ty);
  }
  break;
  case CURLOPT_WRITEHEADER:
  {
    curl->_hdrdata = va_arg(args, void*);
  }
  break;
  case CURLOPT_MAXCONNECTS:
  case CURLOPT_TIMEOUT_MS:
  case CURLOPT_CONNECTTIMEOUT_MS:
  case CURLOPT_DNS_CACHE_TIMEOUT:
  case CURLOPT_TCP_NODELAY:
  case CURLOPT_NOSIGNAL:
  case CURLOPT_POSTFIELDS:
  {
    // ignore
  }
  break;
  default:
  {
    throw runtime_error("cURL option unknown to FakeCurl");
  }
  }

  va_end(args);  // http://www.gnu.org/software/gnu-c-manual/gnu-c-manual.html#Variable-Length-Parameter-Lists clarifies that in GCC this does nothing, so is fine even in the presence of exceptions
  return CURLE_OK;
}

CURLcode curl_easy_perform(CURL* handle)
{
  FakeCurl* curl = (FakeCurl*)handle;
  return curl->easy_perform();
}

CURLcode curl_easy_getinfo(CURL* handle, CURLINFO info, ...)
{
  va_list args;
  va_start(args, info);
  FakeCurl* curl = (FakeCurl*)handle;

  switch (info)
  {
    case CURLINFO_PRIVATE:
    {
      char** dataptr = va_arg(args, char**);
      *(void**)dataptr = curl->_private;
    }
    break;

    case CURLINFO_PRIMARY_IP:
    {
      static char ip[] = "10.42.42.42";
      char** dataptr = va_arg(args, char**);
      *dataptr = ip;
    }
    break;

    case CURLINFO_RESPONSE_CODE:
    {
      long* dataptr = va_arg(args, long*);
      *dataptr = 503;
    }
    break;

    default:
    {
      throw runtime_error("cURL info unknown to FakeCurl");
    }
  }

  va_end(args);  // http://www.gnu.org/software/gnu-c-manual/gnu-c-manual.html#Variable-Length-Parameter-Lists clarifies that in GCC this does nothing, so is fine even in the presence of exceptions
  return CURLE_OK;
}

struct curl_slist* curl_slist_append(struct curl_slist* lst, const char* str)
{
  list<string>* truelist;

  if (lst == NULL)
  {
    truelist = new list<string>();
  }
  else
  {
    truelist = (list<string>*)lst;
  }

  truelist->push_back(str);

  return (struct curl_slist*)truelist;
}

void curl_slist_free_all(struct curl_slist* lst)
{
  list<string>* truelist = (list<string>*)lst;
  delete truelist;
}

const char* curl_easy_strerror(CURLcode errnum)
{
  return "Insert error string here";
}
