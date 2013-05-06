/**
 * @file utils.h Utility functions.
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

#ifndef UTILS_H_
#define UTILS_H_

#include <algorithm>
#include <functional>
#include <string>
#include <list>
#include <vector>
#include <cctype>

namespace Utils
{
  std::string url_escape(const std::string& s);

// trim from start
  inline std::string& ltrim(std::string &s)
  {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                    std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
  }

// trim from end
  inline std::string& rtrim(std::string &s)
  {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
  }

// trim from both ends
  inline std::string& trim(std::string &s)
  {
    return ltrim(rtrim(s));
  }

  /// Split the string s using delimiter and store the resulting tokens in order
  /// at the end of tokens. Only non-empty tokens will be stored; empty tokens are ignored (and not counted).
  template <class T>  //< container that has T::push_back(std::string)
  void split_string(const std::string& str_in,  //< string to scan (will not be changed)
                    char delimiter,  //< delimiter to use
                    T& tokens,  //< tokens will be added to this list
                    const int max_tokens = 0,  //< max number of tokens to push; last token will be tail of string (delimiters will not be parsed in this section)
                    bool trim = false)  //< trim the string at both ends before splitting?
  {
    std::string token;

    std::string s = str_in;
    if (trim)
    {
      Utils::trim(s);
    }

    size_t token_start_pos = 0;
    size_t token_end_pos = s.find(delimiter);
    int num_tokens = 0;

    while ((token_end_pos != std::string::npos) &&
           ((max_tokens == 0) ||
            (num_tokens < (max_tokens-1))))
    {
      token = s.substr(token_start_pos, token_end_pos - token_start_pos);
      if (token.length() > 0)
      {
        tokens.push_back(token);
        num_tokens++;
      }
      token_start_pos = token_end_pos + 1;
      token_end_pos = s.find(delimiter, token_start_pos);
    }

    token = s.substr(token_start_pos);
    if (token.length() > 0)
    {
      tokens.push_back(token);
    }
  }
} // namespace Utils

#endif /* UTILS_H_ */
