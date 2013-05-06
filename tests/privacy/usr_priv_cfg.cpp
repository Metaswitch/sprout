/**
 * @file usr_priv_cfg.cpp
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

#include <string>
#include <cstring>
#include <iostream>
#include <getopt.h>
#include "xdmconnection.h"

using namespace std;

std::string username;
std::string password;
std::string action;

void parse_args(int argc, char **argv)
{
  static struct option long_options[] = {
    { "user", 1, 0, 'u' },
    { "pass", 1, 0, 'p' },
    { 0, 0, 0, 0 }
  };
  int option_index = 0;
  int c;
  while ((c = getopt_long(argc, argv, "u:p:", long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case 'u':
        username = optarg;
        break;

      case 'p':
        password = optarg;
        break;

      default:
        break;
    }
  }
}

void usage()
{
  cout << "usage: usr_priv_cfg --user <user> [--pass <password>] (enable|disable|info)" << endl;
}

int main(int argc, char ** argv)
{
  XDMConnection *_xdmc;

  parse_args(argc, argv);

  // Check only one unread option remains (the action to take).
  if (argc - optind != 1)
  {
    usage();
    return 2;
  }

  if ((username == "") || (password== ""))
  {
    usage();
    return 2;
  }

  cout << "Password " << password << " supplied, using HTTP_DIGEST authentication" << endl;
  _xdmc = new XDMConnection("librarian.cw-ngv.com:8080");

  if (!strcmp(argv[optind], "enable"))
  {
    // Turn on privacy
    if (_xdmc->put_simservs(username, "enable_privacy.xml", password, 0L))
    {
      cout << "Enabled privacy by default for user: " << username << endl;
    }
    else
    {
      cout << "Failed to enable privacy for user: " << username << endl;
    }
  }
  else if (!strcmp(argv[optind], "disable"))
  {
    // Turn off privacy
    if (_xdmc->put_simservs(username, "disable_privacy.xml", password, 0L))
    {
      cout << "Disabled privacy by default for user: " << username << endl;
    }
    else
    {
      cout << "Failed to disable privacy for user: " << username << endl;
    }
  }
  else if (strcmp(argv[optind], "info"))
  {
    usage();
    return 2;
  }

  string curr_xml;
  if (_xdmc->get_simservs(username, curr_xml, password, 0L))
  {
    cout << "Current simservs document :" << endl << curr_xml << endl;
  }
  else
  {
    cout << "Failed to fetch simservs document for user: " << username << endl;
  }

  return 0;
}
