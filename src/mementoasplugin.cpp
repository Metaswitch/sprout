/**
 * @file mementoasplugin.cpp  Plug-in wrapper for the Memento Sproutlet.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

#include "cfgoptions.h"
#include "sproutletplugin.h"
#include "mementoappserver.h"
#include "call_list_store.h"
#include "sproutletappserver.h"
#include "memento_as_alarmdefinition.h"

class MementoPlugin : public SproutletPlugin
{
public:
  MementoPlugin();
  ~MementoPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>& sproutlets);
  void unload();

private:
  Alarm* _cass_comm_alarm;
  CommunicationMonitor* _cass_comm_monitor;
  CallListStore::Store* _call_list_store;
  MementoAppServer* _memento;
  SproutletAppServerShim* _memento_sproutlet;
};

/// Export the plug-in using the magic symbol "sproutlet_plugin"
extern "C" {
MementoPlugin sproutlet_plugin;
}


MementoPlugin::MementoPlugin() :
  _cass_comm_alarm(NULL),
  _cass_comm_monitor(NULL),
  _call_list_store(NULL),
  _memento(NULL),
  _memento_sproutlet(NULL)
{
}

MementoPlugin::~MementoPlugin()
{
}

/// Loads the Memento plug-in, returning the supported Sproutlets.
bool MementoPlugin::load(struct options& opt, std::list<Sproutlet*>& sproutlets)
{
  bool plugin_loaded = true;

  SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("memento_as_incoming_sip_transactions",
                                                                                                                             "1.2.826.0.1.1578918.9.8.1.4");
  SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl = SNMP::SuccessFailCountByRequestTypeTable::create("memento_as_outgoing_sip_transactions",
                                                                                                                             "1.2.826.0.1.1578918.9.8.1.5");
  if (((opt.max_call_list_length == 0) &&
       (opt.call_list_ttl == 0)))
  {
    TRC_ERROR("Can't have an unlimited maximum call length and a unlimited TTL for the call list store - disabling Memento");
  }
  else
  {
    _cass_comm_alarm = new Alarm("memento",
                                 AlarmDef::MEMENTO_AS_CASSANDRA_COMM_ERROR,
                                 AlarmDef::CRITICAL);
    _cass_comm_monitor = new CommunicationMonitor(_cass_comm_alarm, "Memento", "Memcached");

    _call_list_store = new CallListStore::Store();
    _call_list_store->configure_connection("localhost", 9160, _cass_comm_monitor);

    _memento = new MementoAppServer("memento",
                                    _call_list_store,
                                    opt.home_domain,
                                    opt.max_call_list_length,
                                    opt.memento_threads,
                                    opt.call_list_ttl,
                                    stack_data.stats_aggregator,
                                    opt.cass_target_latency_us,
                                    opt.max_tokens,
                                    opt.init_token_rate,
                                    opt.min_token_rate,
                                    exception_handler,
                                    http_resolver,
                                    opt.memento_notify_url);

    _memento_sproutlet = new SproutletAppServerShim(_memento, incoming_sip_transactions_tbl, outgoing_sip_transactions_tbl);
    sproutlets.push_back(_memento_sproutlet);
  }

  return plugin_loaded;
}

/// Unloads the Memento plug-in.
void MementoPlugin::unload()
{
  delete _memento_sproutlet;
  delete _memento;
  delete _call_list_store;
  delete _cass_comm_monitor;
  delete _cass_comm_alarm;
}
