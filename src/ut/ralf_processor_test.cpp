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
#include "mock_httpconnection.h"
#include "mock_http_request.h"

using ::testing::_;
using ::testing::Return;

class RalfProcessorTest : public BaseTest
{
  MockHttpConnection* _ralf_connection;
  RalfProcessor* _ralf_processor;
  MockHttpRequest* _mock_http_req;

  RalfProcessorTest()
  {
    _ralf_connection = new MockHttpConnection();
    _ralf_processor = new RalfProcessor(_ralf_connection, NULL, 1);
    _mock_http_req = new MockHttpRequest();
  }

 virtual ~RalfProcessorTest()
 {
   delete _ralf_processor;
   delete _ralf_connection;
   // We don't delete the MockHttpRequest, as that will be deleted when the
   // unique pointer returned from HttpConnection::create_request() goes out of
   // scope
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

  EXPECT_CALL(*_ralf_connection, create_request_proxy(HttpClient::RequestType::POST, rr->path))
    .WillOnce(Return(_mock_http_req));

  EXPECT_CALL(*_mock_http_req, set_body(rr->message)).Times(1);
  EXPECT_CALL(*_mock_http_req, set_sas_trail(rr->trail)).Times(1);

  EXPECT_CALL(*_mock_http_req, send()).WillOnce(Return(resp));
  _ralf_processor->send_request_to_ralf(rr);
  sleep(1);
}
