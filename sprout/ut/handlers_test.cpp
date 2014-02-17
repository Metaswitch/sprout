/**
 * @file handlers_test.cpp UT for Handlers module.
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

#include "test_utils.hpp"
#include <curl/curl.h>

#include "mockhttpstack.hpp"
#include "handlers.h"
#include "gtest/gtest.h"
#include "basetest.hpp"
#include "regstore.h"
#include "chronosconnection.h"
#include "localstore.h"

using namespace std;

class HandlersTest : public BaseTest
{
  ChronosConnection* chronos_connection;
  LocalStore* local_data_store;
  RegStore* store;

  HandlersTest() 
  {
    chronos_connection = new ChronosConnection("localhost");
    local_data_store = new LocalStore();
    store = new RegStore((Store*)local_data_store, chronos_connection);
  }

  virtual ~HandlersTest()
  {
    delete store; store = NULL;
    delete local_data_store; local_data_store = NULL;
    delete chronos_connection; chronos_connection = NULL;
  }
};

TEST_F(HandlersTest, MainlineTest)
{
  MockHttpStack stack;
  MockHttpStack::Request req(&stack, "/", "timers");
  ChronosHandler::Config chronos_config(HandlersTest::store,
                                        HandlersTest::store);
  ChronosHandler* handler = new ChronosHandler(req, &chronos_config);

  std::string body = "{\"aor_id\": \"aor_id\", \"binding_id\": \"binding_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 200);

  handler->handle_response();
  delete handler;
}

TEST_F(HandlersTest, InvalidJSONTest)
{
  MockHttpStack stack;
  MockHttpStack::Request req(&stack, "/", "timers");
  ChronosHandler::Config chronos_config(HandlersTest::store,
                                        HandlersTest::store);
  ChronosHandler* handler = new ChronosHandler(req, &chronos_config);

  std::string body = "{\"aor_id\" \"aor_id\", \"binding_id\": \"binding_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
  delete handler;
}

TEST_F(HandlersTest, MissingAorJSONTest)
{
  MockHttpStack stack;
  MockHttpStack::Request req(&stack, "/", "timers");
  ChronosHandler::Config chronos_config(HandlersTest::store,
                                        HandlersTest::store);
  ChronosHandler* handler = new ChronosHandler(req, &chronos_config);

  std::string body = "{\"binding_id\": \"binding_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
  delete handler;
}

TEST_F(HandlersTest, MissingBindingJSONTest)
{
  MockHttpStack stack;
  MockHttpStack::Request req(&stack, "/", "timers");
  ChronosHandler::Config chronos_config(HandlersTest::store,
                                        HandlersTest::store);
  ChronosHandler* handler = new ChronosHandler(req, &chronos_config);

  std::string body = "{\"aor_id\": \"aor_id\"}";
  int status = handler->parse_response(body);

  ASSERT_EQ(status, 400);
  delete handler;
}
