/**
 * @file flowtable.cpp Edge Proxy flow table maintenance
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

///

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

// Common STL includes.
#include <cassert>
#include <map>
#include <string>

#include "log.h"
#include "utils.h"
#include "pjutils.h"
#include "stack.h"
#include "flowtable.h"

FlowTable::FlowTable() :
  _tp2flow_map(),
  _tk2flow_map(),
  _statistic("client_count")
{
  pthread_mutex_init(&_flow_map_lock, NULL);
  report_flow_count();
}


FlowTable::~FlowTable()
{
  // Delete all the existing flows.
  for (std::map<FlowKey, Flow*>::iterator i = _tp2flow_map.begin();
       i != _tp2flow_map.end();
       ++i)
  {
    delete i->second;
  }

  pthread_mutex_destroy(&_flow_map_lock);
}


/// Find or create a flow corresponding to the specified transport and remote
/// IP address and port. This is a single method to ensure it is atomic.
Flow* FlowTable::find_create_flow(pjsip_transport* transport, const pj_sockaddr* raddr)
{
  Flow* flow = NULL;
  FlowKey key(transport->key.type, raddr);

  char buf[100];
  LOG_DEBUG("Find or create flow for transport %s (%d), remote address %s",
            transport->obj_name, transport->key.type,
            pj_sockaddr_print(raddr, buf, sizeof(buf), 3));

  pthread_mutex_lock(&_flow_map_lock);

  std::map<FlowKey, Flow*>::iterator i = _tp2flow_map.find(key);

  if (i == _tp2flow_map.end())
  {
    // No matching flow, so create a new one.
    flow = new Flow(this, transport, raddr);

    // Add the new flow to the maps.
    _tp2flow_map.insert(std::make_pair(key, flow));
    _tk2flow_map.insert(std::make_pair(flow->token(), flow));

    LOG_DEBUG("Added flow record %p", flow);

    report_flow_count();
  }
  else
  {
    // Found a matching flow, so return this one.
    flow = i->second;

    LOG_DEBUG("Found flow record %p", flow);
  }

  // Add a reference to the flow.
  flow->inc_ref();

  pthread_mutex_unlock(&_flow_map_lock);

  return flow;
}


/// Find the flow corresponding to the specified transport and remote IP
/// address and port.
Flow* FlowTable::find_flow(pjsip_transport* transport, const pj_sockaddr* raddr)
{
  Flow* flow = NULL;
  FlowKey key(transport->key.type, raddr);

  char buf[100];
  LOG_DEBUG("Find flow for transport %s (%d), remote address %s",
            transport->obj_name, transport->key.type,
            pj_sockaddr_print(raddr, buf, sizeof(buf), 3));

  pthread_mutex_lock(&_flow_map_lock);

  std::map<FlowKey, Flow*>::iterator i = _tp2flow_map.find(key);

  if (i != _tp2flow_map.end())
  {
    // Found a matching flow, so return this one.
    flow = i->second;

    // Increment the reference count on the flow.
    flow->inc_ref();

    LOG_DEBUG("Found flow record %p", flow);
  }

  pthread_mutex_unlock(&_flow_map_lock);

  return flow;
}


/// Find the flow corresponding to the specified flow token.
Flow* FlowTable::find_flow(const std::string& token)
{
  Flow* flow = NULL;

  LOG_DEBUG("Find flow for flow token %s", token.c_str());

  pthread_mutex_lock(&_flow_map_lock);

  std::map<std::string, Flow*>::iterator i = _tk2flow_map.find(token);
  if (i != _tk2flow_map.end())
  {
    // Found a flow matching the token.
    flow = i->second;

    // Add a reference to the flow.
    flow->inc_ref();

    LOG_DEBUG("Found flow record %p", flow);
  }

  pthread_mutex_unlock(&_flow_map_lock);

  return flow;
}


void FlowTable::remove_flow(Flow* flow)
{
  pthread_mutex_lock(&_flow_map_lock);

  LOG_DEBUG("Remove flow %p", flow);

  FlowKey key(flow->transport()->key.type, flow->remote_addr());

  std::map<FlowKey, Flow*>::iterator i = _tp2flow_map.find(key);
  if (i != _tp2flow_map.end())
  {
    _tp2flow_map.erase(i);
  }

  std::map<std::string, Flow*>::iterator j = _tk2flow_map.find(flow->token());
  if (j != _tk2flow_map.end())
  {
    _tk2flow_map.erase(j);
  }

  report_flow_count();

  delete flow;

  pthread_mutex_unlock(&_flow_map_lock);
}

void FlowTable::report_flow_count()
{
  LOG_DEBUG("Reporting current flow count: %d", _tp2flow_map.size());
  std::vector<std::string> message;
  message.push_back(std::to_string(_tp2flow_map.size()));
  _statistic.report_change(message);
}

Flow::Flow(FlowTable* flow_table, pjsip_transport* transport, const pj_sockaddr* remote_addr) :
  _flow_table(flow_table),
  _transport(transport),
  _remote_addr(*remote_addr),
  _token(),
  _authenticated(false),
  _refs(1)
{
  // Create a random base64 encoded token for the flow.
  PJUtils::create_random_token(Flow::TOKEN_LENGTH, _token);

  if (PJSIP_TRANSPORT_IS_RELIABLE(_transport))
  {
    // We're adding a new reliable transport, so make sure it stays around
    // until we remove it from the map.
    pjsip_transport_add_ref(transport);

    // Add a state listener so we find out when the flow is destroyed.
    pjsip_tp_state_listener_key* listener_key;
    pjsip_transport_add_state_listener(transport,
                                       &on_transport_state_changed,
                                       this,
                                       &listener_key);
    LOG_DEBUG("Added transport listener for flow %p", this);
  }
  else
  {
    // We run our own keepalive timer on non-reliable transports, so start the
    // timer.
    pj_timer_entry_init(&_ka_timer, PJ_FALSE, (void*)this, &on_ka_timer_expiry);
    pj_time_val delay = {EXPIRY_TIMEOUT, 0};
    pjsip_endpt_schedule_timer(stack_data.endpt, &_ka_timer, &delay);
    _ka_timer.id = PJ_TRUE;
    LOG_DEBUG("Started keepalive timer for flow %p", this);
  }
}


Flow::~Flow()
{
  if (PJSIP_TRANSPORT_IS_RELIABLE(_transport))
  {
    // We incremented the ref count when we put it in the map.
    pjsip_transport_dec_ref(_transport);
  }
  else
  {
    // Stop the keepalive timer.
    pjsip_endpt_cancel_timer(stack_data.endpt, &_ka_timer);
    _ka_timer.id = PJ_FALSE;
  }
}


void Flow::keepalive()
{
  // We only run keepalive times on non-reliable transport flows.
  if (!PJSIP_TRANSPORT_IS_RELIABLE(_transport))
  {
    if (_ka_timer.id)
    {
      // Stop the existing keepalive timer.
      pjsip_endpt_cancel_timer(stack_data.endpt, &_ka_timer);
      _ka_timer.id = PJ_FALSE;
    }

    // Start the keepalive timer.
    pj_time_val delay = {EXPIRY_TIMEOUT, 0};
    pjsip_endpt_schedule_timer(stack_data.endpt, &_ka_timer, &delay);
    _ka_timer.id = PJ_TRUE;
    LOG_DEBUG("(Re)started keepalive timer for flow %p", this);
  }
}


void Flow::inc_ref()
{
  // Increment the reference count on the flow.  This is always called when
  // the flowtable lock is held, so no need to lock.
  ++_refs;
}


void Flow::dec_ref()
{
  // Decrement the reference count on the flow, and suicides if it gets
  // to zero.
  pthread_mutex_lock(&_flow_table->_flow_map_lock);

  if ((--_refs) == 0)
  {
    pthread_mutex_unlock(&_flow_table->_flow_map_lock);
    _flow_table->remove_flow(this);
  }
  else
  {
    pthread_mutex_unlock(&_flow_table->_flow_map_lock);
  }
}


void Flow::on_transport_state_changed(pjsip_transport *tp,
                                      pjsip_transport_state state,
                                      const pjsip_transport_state_info *info)
{
  LOG_DEBUG("Transport state changed for flow %p, state = %d",
            info->user_data, state);
  if (state == PJSIP_TP_STATE_DISCONNECTED)
  {
    // Transport connection has disconnected, so decrement the reference count
    // so it will eventually get removed from the map.
    ((Flow*)(info->user_data))->dec_ref();
  }
}


void Flow::on_ka_timer_expiry(pj_timer_heap_t *th, pj_timer_entry *e)
{
  LOG_DEBUG("Keepalive timer expired for flow %p", e->user_data);
  if (e->id)
  {
    // The keepalive timer has not been cancelled, so decrement the reference
    // count so the flow will eventually get deleted.
    ((Flow*)e->user_data)->dec_ref();
  }
}

