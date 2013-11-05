/**
 * @file signalhandler.h  Handler for UNIX signals.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#ifndef SIGNALHANDLER_H__
#define SIGNALHANDLER_H__

#include <signal.h>
#include <pthread.h>
#include <semaphore.h>

#include "log.h"

/// Singleton class template for handling UNIX signals.  Only a single
/// instance of this class should be created for each UNIX signal type.
/// This has to be templated because there has to be a unique static signal
/// handler function and semphore for each signal being hooked, so creating
/// multiple instances of a non-templated class doesn't work
template <int SIGNUM>
class SignalHandler
{
public:
  SignalHandler()
  {
    // Create the mutex and condition.
    pthread_mutex_init(&_mutex, NULL);
    pthread_cond_init(&_cond, NULL);

    // Create the semaphore
    sem_init(&_sema, 0, 0);

    // Create the dispatcher thread.
    pthread_create(&_dispatcher_thread, 0, &SignalHandler::dispatcher, (void*)this);

    // Hook the signal.
    sighandler_t old_handler = signal(SIGNUM, &SignalHandler::handler);

    if (old_handler != SIG_DFL)
    {
// LCOV_EXCL_START
      // Old handler is not the default handler, so someone else has previously
      // hooked the signal.
      LOG_WARNING("SIGHUP already hooked");
// LCOV_EXCL_STOP
    }
  }

  ~SignalHandler()
  {
    // Unhook the signal.
    signal(SIGNUM, SIG_DFL);

    // Cancel the dispatcher thread and wait for it to end.
    pthread_cancel(_dispatcher_thread);
    pthread_join(_dispatcher_thread, NULL);

    // Destroy the semaphore.
    sem_destroy(&_sema);

    // Destroy the mutex and condition.
    pthread_mutex_destroy(&_mutex);
    pthread_cond_destroy(&_cond);
  }

  /// Waits for the signal to be raised.
  void wait_for_signal()
  {
    // Grab the mutex.  On its own this isn't enough to guarantee we won't
    // miss a signal, but to do that we would have to hold the mutex while
    // calling back to user code, which is not desireable.  If we really
    // cannot miss signals then we will probably need to add sequence numbers
    // to this API.
    pthread_mutex_lock(&_mutex);

    // Wait for the signal condition to trigger.
    pthread_cond_wait(&_cond, &_mutex);

    // Unlock the mutex
    pthread_mutex_unlock(&_mutex);
  }

private:
  /// Thread responsible for dispatching signals to the appropriate caller.
  static void* dispatcher(void* p)
  {
    while (true)
    {
      // Wait for the signal handler to indicate the signal has been raised.
      sem_wait(&_sema);
      LOG_DEBUG("Signal %d raised", SIGNUM);

      // Broadcast to all the waiting threads.
      pthread_cond_broadcast(&_cond);
    }
    return NULL;
  }

  /// The signal handler.
  static void handler(int sig)
  {
    // Post the semaphore to wake up the dispatcher.
    sem_post(&_sema);
  }

  /// Identifier of dispatcher thread.
  pthread_t _dispatcher_thread;

  /// Mutex used for signalling to waiting threads.
  static pthread_mutex_t _mutex;

  /// Condition used for signalling to waiting threads.
  static pthread_cond_t _cond;

  /// Semaphore used for signaling from signal handler to dispatcher thread.
  static sem_t _sema;
};

template<int SIGNUM> pthread_mutex_t SignalHandler<SIGNUM>::_mutex;
template<int SIGNUM> pthread_cond_t SignalHandler<SIGNUM>::_cond;
template<int SIGNUM> sem_t SignalHandler<SIGNUM>::_sema;

#endif


