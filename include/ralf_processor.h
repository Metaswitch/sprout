/**
 * @file ralf_processor.h
 *
 * Project Clearwater - IMS in the cloud.
 * Copyright (C) 2015  Metaswitch Networks Ltd
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
