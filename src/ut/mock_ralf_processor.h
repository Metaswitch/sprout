#ifndef MOCK_RALF_PROCESSOR_H_
#define MOCK_RALF_PROCESSOR_H_

#include "gmock/gmock.h"
#include "ralf_processor.h"

class MockRalfProcessor : public RalfProcessor 
{
public:
    MockRalfProcessor() : RalfProcessor(HttpConnection* ralf_connection,
                                        ExceptionHandler* exception_handler,
                                        const int ralf_threads){};

    virtual ~MockRalfProcessor(){};

    MOCK_METHOD1(send_request_to_ralf, void(RalfRequest* rr));
    MOCK_METHOD2(exception_callback, void(RalfProcessor::RalfRequest* work));
};

#endif
