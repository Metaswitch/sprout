/**
 * @file eventq.h Template definition for event queue
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

#ifndef EVENTQ__
#define EVENTQ__

#include <pthread.h>
#include <errno.h>

#include <queue>

template<class T>
class eventq
{
public:
  /// Create an event queue.
  ///
  /// @param max_queue maximum size of event queue, zero is unlimited.
  eventq(unsigned int max_queue=0, bool open=true) :
    _open(open),
    _max_queue(max_queue),
    _q(),
    _writers(0),
    _readers(0),
    _terminated(false)
  {
    pthread_mutex_init(&_m, NULL);
    pthread_cond_init(&_w_cond, NULL);
    pthread_cond_init(&_r_cond, NULL);
  };

  ~eventq()
  {
  };

  /// Open the queue for new inputs.
  void open()
  {
    _open = true;
  }

  /// Close the queue to new inputs.
  void close()
  {
    _open = false;
  }

  /// Send a termination signal via the queue.
  void terminate()
  {
    pthread_mutex_lock(&_m);


    _terminated = true;

    // Are there any readers waiting?
    if (_readers > 0)
    {
      // Signal all waiting readers.  Can do this before releasing the mutex
      // as we're relying on wait-morphing being supported by the OS (so
      // there will be no spurious context switches).
      pthread_cond_broadcast(&_r_cond);
    }

    pthread_mutex_unlock(&_m);
  }

  /// Indicates whether the queue has been terminated.
  bool is_terminated()
  {
    pthread_mutex_lock(&_m);
    bool terminated = _terminated;
    pthread_mutex_unlock(&_m);
    return terminated;
  }

  /// Purges all the events currently in the queue.
  void purge()
  {
    pthread_mutex_lock(&_m);
    while (!_q.empty())
    {
      _q.pop();
    }
    pthread_mutex_unlock(&_m);
  }

  /// Push an item on to the event queue.
  ///
  /// This may block if the queue is full, and will fail if the queue is closed.
  bool push(T item)
  {
    bool rc = false;

    pthread_mutex_lock(&_m);

    if (_open)
    {
      if (_max_queue != 0)
      {
        while (_q.size() >= _max_queue)
        {
          // Queue is full, so writer must block.
          ++_writers;
          pthread_cond_wait(&_w_cond, &_m);
          --_writers;
        }
      }

      // Must be space on the queue now.
      _q.push(item);

      // Are there any readers waiting?
      if (_readers > 0)
      {
        pthread_cond_signal(&_r_cond);
      }

      rc = true;
    }

    pthread_mutex_unlock(&_m);

    return rc;
  };

  /// Push an item on to the event queue.
  ///
  /// This will not block, but may discard the event if the queue is full.
  bool push_noblock(T item)
  {
    bool rc = false;

    pthread_mutex_lock(&_m);

    if ((_open) && ((_max_queue == 0) || (_q.size() < _max_queue)))
    {
      // There is space on the queue.
      _q.push(item);

      // Are there any readers waiting?
      if (_readers > 0)
      {
        pthread_cond_signal(&_r_cond);
      }

      rc = true;
    }

    pthread_mutex_unlock(&_m);

    return rc;
  };

  /// Pop an item from the event queue, waiting indefinitely if it is empty.
  bool pop(T& item)
  {
    pthread_mutex_lock(&_m);

    while ((_q.empty()) && (!_terminated))
    {
      // The queue is empty, so wait for something to arrive.
      ++_readers;
      pthread_cond_wait(&_r_cond, &_m);
      --_readers;
    }

    if (!_q.empty())
    {
      // Something on the queue to receive.
      item = _q.front();
      _q.pop();

      // Are there blocked writers?
      if ((_max_queue != 0) &&
          (_q.size() < _max_queue) &&
          (_writers > 0))
      {
        pthread_cond_signal(&_w_cond);
      }
    }

    pthread_mutex_unlock(&_m);

    return !_terminated;
  };

  /// Pop an item from the event queue, waiting for the specified timeout if
  /// the queue is empty.
  ///
  /// @param timeout Maximum time to wait in milliseconds.
  bool pop(T& item, int timeout)
  {
    pthread_mutex_lock(&_m);

    if ((_q.empty()) && (timeout != 0))
    {
      // The queue is empty and the timeout is non-zero, so wait for
      // something to arrive.
      struct timespec attime;
      if (timeout != -1)
      {
        clock_gettime(CLOCK_MONOTONIC, &attime);
        attime.tv_sec += timeout / 1000;
        attime.tv_nsec += ((timeout % 1000) * 1000000);
        if (attime.tv_nsec >= 1000000000)
        {
          attime.tv_nsec -= 1000000000;
          attime.tv_sec += 1;
        }
      }

      ++_readers;

      while ((_q.empty()) && (!_terminated))
      {
        // The queue is empty, so wait for something to arrive.
        if (timeout != -1)
        {
          int rc = pthread_cond_timedwait(&_r_cond, &_m, &attime);
          if (rc == ETIMEDOUT)
          {
            break;
          }
        }
        else
        {
          pthread_cond_wait(&_r_cond, &_m);
        }
      }

      --_readers;
    }

    if (!_q.empty())
    {
      item = _q.front();
      _q.pop();

      if ((_max_queue != 0) &&
          (_q.size() < _max_queue) &&
          (_writers > 0))
      {
        pthread_cond_signal(&_w_cond);
      }
    }

    pthread_mutex_unlock(&_m);

    return !_terminated;
  };

  /// Peek at the item at the front of the event queue.
  T peek() const
  {
    return _q.front();
  };

  int size() const
  {
    return _q.size();
  };

private:

  bool _open;
  unsigned int _max_queue;
  std::queue<T> _q;
  int _writers;
  int _readers;
  bool _terminated;

  pthread_mutex_t _m;
  pthread_cond_t _w_cond;
  pthread_cond_t _r_cond;

};

#endif
