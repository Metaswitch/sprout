/**
 * @file ralf_processor.h
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef RALF_PROCESSOR_H_
#define RALF_PROCESSOR_H_

#include "threadpool.h"
#include "sas.h"
#include "httpconnection.h"
#include "exception_handler.h"

class RalfProcessor
{
public:
  /// Constructor
  RalfProcessor(HttpConnection* ralf_connection,
                ExceptionHandler* exception_handler,
                const int ralf_threads);

  /// Destructor
  virtual ~RalfProcessor();

  struct RalfRequest
  {
    std::string path;
    std::string message;
    SAS::TrailId trail;
  };

  /// This function adds a ralf request to the pool. Actually sending
  /// the Ralf request must be done in a separate thread to avoid
  /// introducing unnecessary latencies in the call path.
  /// @param rr         The RalfRequest to add to the queue
  virtual void send_request_to_ralf(RalfRequest* rr);

  static void exception_callback(RalfProcessor::RalfRequest* work)
  {
    // No recovery behaviour as this is asynchronous, so we can't sensibly
    // respond
  }

private:
  /// @class Pool
  /// The thread pool used by the ralf processor
  class Pool : public ThreadPool<RalfProcessor::RalfRequest*>
  {
  public:
    /// Constructor.
    /// @param ralf_connection    A pointer to the underlying ralf connection.
    /// @param num_threads        Number of ralf threads to start
    /// @param exception_handler  Exception handler
    Pool(HttpConnection* ralf_connection,
         ExceptionHandler* exception_handler,
         void (*callback)(RalfProcessor::RalfRequest*),
         unsigned int num_threads);

    /// Destructor
    virtual ~Pool();

  private:
    /// Called by worker threads when they pull work off the queue.
    virtual void process_work(RalfProcessor::RalfRequest*&);

    /// Underlying Ralf connection
    HttpConnection* _ralf_connection;
  };

  friend class Pool;

  ///  Thread pool
  Pool* _thread_pool;
};

#endif
