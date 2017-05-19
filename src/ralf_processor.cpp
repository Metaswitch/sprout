/**
 * @file ralf_processor.cpp
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */
#include "ralf_processor.h"
#include "exception_handler.h"

/// Constructor.
RalfProcessor::RalfProcessor(HttpConnection* ralf_connection,
                             ExceptionHandler* exception_handler,
                             const int ralf_threads) :
  _thread_pool(new Pool(ralf_connection,
                        exception_handler,
                        &exception_callback,
                        ralf_threads))
{
  _thread_pool->start();
}

/// Destructor.
RalfProcessor::~RalfProcessor()
{
  if (_thread_pool != NULL)
  {
    _thread_pool->stop();
    _thread_pool->join();
    delete _thread_pool; _thread_pool = NULL;
  }
}

/// Adds a ralf request to the queue
void RalfProcessor::send_request_to_ralf(RalfRequest* rr)
{
  _thread_pool->add_work(rr);
}

// Send the ACR to Ralf
void RalfProcessor::Pool::process_work(RalfProcessor::RalfRequest*& rr)
{
  // Send the request using HTTPConnection, which adds penalties via
  // the load monitor if the request fails
  std::map<std::string, std::string> headers;
  _ralf_connection->send_post(rr->path,
                              headers,
                              rr->message,
                              rr->trail);
  delete rr; rr = NULL;
}

RalfProcessor::Pool::Pool(HttpConnection* ralf_connection,
                          ExceptionHandler* exception_handler, 
                          void (*callback)(RalfProcessor::RalfRequest*),
                          unsigned int num_threads) :
  ThreadPool<RalfProcessor::RalfRequest*>(num_threads, 
                                          exception_handler, 
                                          callback, 
                                          100),
  _ralf_connection(ralf_connection)
{}

RalfProcessor::Pool::~Pool()
{}
