/**
 * @file ralf_processor.cpp
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
#include "ralf_processor.h"
#include "exception_handler.h"

/// Constructor.
RalfProcessor::RalfProcessor(HttpConnection* ralf_connection,
                             ExceptionHandler* exception_handler,
                             const int ralf_threads) :
  _thread_pool(new Pool(this,
                        ralf_connection,
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

// TODO may need splitting up
/// Creates a call list entry and adds it to the queue.
void RalfProcessor::send_request_to_ralf(RalfRequest* rr)
//                                      std::string path,
  //                                    std::map<std::string,std::string> headers,
    //                                  std::string message,
      //                                SAS::TrailId trail)
{
  // Create stop watch to time how long between the CallListStoreProcessor
  // receives the request, and a worker thread finishes processing it.

  // Create a call list entry and populate it
//  RalfRequest* rr = new RalfProcessor::RalfRequest();

 // rr->id = id;
  //rr->type = type;
  ///rr->contents = xml;
  //rr->trail = trail;

  _thread_pool->add_work(rr);
}

// Write the call list entry to the call list store
void RalfProcessor::Pool::process_work(RalfProcessor::RalfRequest*& rr)
{
  TRC_STATUS("Sending Ralf message");

  std::map<std::string, std::string> headers;
  TRC_STATUS("Path %s", rr->path.c_str());
  TRC_STATUS("Message %s", rr->message.c_str());

  long rc = _ralf_connection->send_post(rr->path,
                                        headers,
                                        rr->message,
                                        rr->trail);

  
  if (rc != HTTP_OK)
  {
   TRC_STATUS("Sending Ralf message failed with rc = %ld", rc);

//    TRC_WARNING("Failed to send Ralf ACR message (%p), rc = %ld", this, rc);
  }

  delete rr; rr = NULL;
}

RalfProcessor::Pool::Pool(RalfProcessor* ralf_processor,
                          HttpConnection* ralf_connection,
                          ExceptionHandler* exception_handler, 
                          void (*callback)(RalfProcessor::RalfRequest*),
                          unsigned int num_threads) :
  ThreadPool<RalfProcessor::RalfRequest*>(num_threads, 
                                          exception_handler, 
                                          callback, 
                                          0), // No maximum queue size for Ralf
  _ralf_connection(ralf_connection),
  _ralf_proc(ralf_processor) // Needed?
{}

RalfProcessor::Pool::~Pool()
{}
