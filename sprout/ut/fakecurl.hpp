/**
 * @file fakecurl.hpp Fake cURL library header for testing.
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

#include <string>
#include <list>
#include <map>

#include <curl/curl.h>

/// The content of a request.
class Request
{
public:
  std::string _method;
  std::list<std::string> _headers;
  std::string _body;
  long _httpauth; //^ OR of CURLAUTH_ constants
  std::string _username;
  std::string _password;
  bool _fresh;
};

/// The content of a response.
class Response
{
public:
  CURLcode _code_once;  //< If not CURLE_OK, issue this code first then the other.
  CURLcode _code;  //< cURL easy doesn't accept HTTP status codes
  std::string _body;
  std::list<std::string> _headers;

  Response() :
    _code_once(CURLE_OK),
    _code(CURLE_OK),
    _body("")
  {
  }

  Response(const std::string& body) :
    _code_once(CURLE_OK),
    _code(CURLE_OK),
    _body(body)
  {
  }

  Response(CURLcode code_once, const std::string& body) :
    _code_once(code_once),
    _code(CURLE_OK),
    _body(body)
  {
  }

  Response(std::list<std::string> headers) :
    _code_once(CURLE_OK),
    _code(CURLE_OK),
    _body(""),
    _headers(headers)
  {
  }

  Response(const char* body) :
    _code_once(CURLE_OK),
    _code(CURLE_OK),
    _body(body)
  {
  }

  Response(CURLcode code) :
    _code_once(CURLE_OK),
    _code(code),
    _body("")
  {
  }
};

/// Responses to give, by URL.
extern std::map<std::string,Response> fakecurl_responses;

/// Requests received, by URL.
extern std::map<std::string,Request> fakecurl_requests;
