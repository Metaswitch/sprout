/**
 * @file fakecurl.hpp Fake cURL library header for testing.
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

///

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
