/**
 * @file mock_ralf_processor.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_RALF_PROCESSOR_H_
#define MOCK_RALF_PROCESSOR_H_

#include "gmock/gmock.h"
#include "ralf_processor.h"
#include "mockhttpconnection.h"

class MockRalfProcessor : public RalfProcessor 
{
public:
    MockRalfProcessor(HttpConnection* ralf_connection) : 
      RalfProcessor(ralf_connection, NULL, 2){};

    virtual ~MockRalfProcessor(){};

    MOCK_METHOD1(send_request_to_ralf, void(RalfProcessor::RalfRequest* rr));
};

#endif
