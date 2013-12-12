/**
 * @file updater.h Declarations for Updater class.
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

#ifndef UPDATER_H__
#define UPDATER_H__

#include "signalhandler.h"
#include <pthread.h>
#include <functional>

template<class ReturnType, class ClassType> class Updater
{
public:
  Updater(ClassType* pointer, std::mem_fun_t<ReturnType, ClassType> myFunctor) :
    _terminate(false),
    _func(myFunctor),
    _pointer(pointer)
  {
    LOG_DEBUG("Created updater");

    // Do initial configuration.
    myFunctor(pointer);

    // Create the thread to handle further changes of view.
    int rc = pthread_create(&_updater, NULL, &updater_thread, this);

    if (rc < 0)
    {
      // LCOV_EXCL_START
      LOG_ERROR("Error creating updater thread");
      // LCOV_EXCL_STOP
    }
  }
 
  ~Updater()
  {
    // Destroy the updater thread.
    _terminate = true;
    pthread_join(_updater, NULL);
  }

private:
  static void* updater_thread(void* p)
  {
    ((Updater*)p)->updater();
    return NULL;
  }
 
  void updater()
  {
    LOG_DEBUG("Started updater thread");

    while (!_terminate)
    {
      // Wait for the SIGHUP signal.
      bool rc = _sighup_handler.wait_for_signal();

      // If the signal handler didn't timeout, then call the
      // update function
      if (rc)
      {
        // LCOV_EXCL_START
        _func(_pointer);
        // LCOV_EXCL_STOP
      }
    }
  }

  volatile bool _terminate;
  std::mem_fun_t<ReturnType, ClassType> _func;
  pthread_t _updater;
  ClassType* _pointer;
};

#endif
