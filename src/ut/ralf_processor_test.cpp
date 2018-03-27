/**
 * @file ralf_processor_test.cpp
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include "gtest/gtest.h"

#include "basetest.hpp"
#include "ralf_processor.h"
#include "mock_httpclient.h"
#include "httpconnection.h"

using ::testing::_;
using ::testing::Return;
using ::testing::AllOf;

class RalfProcessorTest : public BaseTest
{
  MockHttpClient* _mock_client;
  HttpConnection* _ralf_connection;
  RalfProcessor* _ralf_processor;

  RalfProcessorTest()
  {
    _mock_client = new MockHttpClient();
    _ralf_connection = new HttpConnection("ralf", _mock_client, "http");
    _ralf_processor = new RalfProcessor(_ralf_connection, NULL, 1);

    // If we don't override the default behaviour, return a nonsensical HTTP Code
    ON_CALL(*_mock_client, send_request(_))
            .WillByDefault(Return(HttpResponse(-1, "", {})));
  }

  virtual ~RalfProcessorTest()
  {
    delete _ralf_processor;
    delete _ralf_connection;
    delete _mock_client;
  }
};

TEST_F(RalfProcessorTest, RequestComplete)
{
  // Create a response that will be returned
  HttpResponse resp(HTTP_OK, "", {});

  // Create a Ralf request and populate it
  RalfProcessor::RalfRequest* rr = new RalfProcessor::RalfRequest();
  rr->path = "path";
  rr->message = "message";
  rr->trail = 0;

  EXPECT_CALL(*_mock_client, send_request(AllOf(IsPost(),
                                                HasScheme("http"),
                                                HasServer("ralf"),
                                                HasPath("path"),
                                                HasBody("message"),
                                                HasTrail(0))));

  _ralf_processor->send_request_to_ralf(rr);
  sleep(1);
}
