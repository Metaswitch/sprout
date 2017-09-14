#ifndef MOCK_RALF_PROCESSOR_H_
#define MOCK_RALF_PROCESSOR_H_

#include "gmock/gmock.h"
#include "ralf_processor.h"
#include "mockhttpconnection.h"

class MockRalfProcessor : public RalfProcessor 
{
public:
    MockRalfProcessor() : RalfProcessor(new MockHttpConnection(),
                                        NULL,
                                        2){};

    virtual ~MockRalfProcessor(){};

    MOCK_METHOD1(send_request_to_ralf, void(RalfProcessor::RalfRequest* rr));
    //MOCK_METHOD2(exception_callback, void(RalfProcessor::RalfRequest* work));
};

#endif
