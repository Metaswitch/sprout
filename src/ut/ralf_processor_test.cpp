/**
 * @file ralf_processor_test.cpp
 *
 * Copyright (C) Metaswitch Networks
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
#include "mockhttpconnection.h"

using ::testing::_;
using ::testing::Return;

class RalfProcessorTest : public BaseTest
{
  MockHttpConnection* _ralf_connection;
  RalfProcessor* _ralf_processor;

  RalfProcessorTest()
  {
    _ralf_connection = new MockHttpConnection();
    _ralf_processor = new RalfProcessor(_ralf_connection, NULL, 1);
  }

 virtual ~RalfProcessorTest()
 {
   delete _ralf_processor;
   delete _ralf_connection;
 }
};

TEST_F(RalfProcessorTest, RequestComplete)
{
  // Create a Ralf request and populate it
  RalfProcessor::RalfRequest* rr = new RalfProcessor::RalfRequest();
  rr->path = "path";
  rr->message = "message";
  rr->trail = 0;

  EXPECT_CALL(*_ralf_connection, send_post(_,_,_,_,_)).WillOnce(Return(200));
  _ralf_processor->send_request_to_ralf(rr);
  sleep(1);
}
