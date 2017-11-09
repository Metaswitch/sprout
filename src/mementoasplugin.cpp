/**
 * @file mementoasplugin.cpp  Plug-in wrapper for the Memento Sproutlet.
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "cfgoptions.h"
#include "sproutletplugin.h"
#include "mementoappserver.h"
#include "call_list_store.h"
#include "sproutletappserver.h"
#include "memento_as_alarmdefinition.h"
#include "log.h"

class MementoPlugin : public SproutletPlugin
{
public:
  MementoPlugin();
  ~MementoPlugin();

  bool load(struct options& opt, std::list<Sproutlet*>& sproutlets);
  void unload();

private:
  CassandraResolver* _cass_resolver;
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
  std::string cassandra = "localhost";

  if (opt.enabled_memento)
  {
    TRC_STATUS("Memento plugin enabled");

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
      _cass_comm_monitor = new CommunicationMonitor(new Alarm(alarm_manager,
                                                              "memento",
                                                              AlarmDef::MEMENTO_AS_CASSANDRA_COMM_ERROR,
                                                              AlarmDef::CRITICAL),
                                                    "Memento",
                                                    "Memcached");

      // We need the address family for the CassandraResolver
      int af = AF_INET;
      struct in6_addr dummy_addr;
      if (inet_pton(AF_INET6, opt.local_host.c_str(), &dummy_addr) == 1)
      {
        TRC_DEBUG("Local host is an IPv6 address");
        af = AF_INET6;
      }

      // Default to a 30s blacklist/graylist duration and port 9160
      _cass_resolver = new CassandraResolver(dns_resolver,
                                             af,
                                             30,
                                             30,
                                             9160);

      // If the memento cassandra hostname option is set, use that instead of "localhost".
      if (opt.plugin_options["memento"].count("cassandra"))
      {
        cassandra = opt.plugin_options.find("memento")->second.find("cassandra")->second;
      }

      _call_list_store = new CallListStore::Store();
      _call_list_store->configure_connection(cassandra, 9160, _cass_comm_monitor, _cass_resolver);

      _memento = new MementoAppServer(opt.prefix_memento,
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
                                      opt.max_token_rate,
                                      exception_handler,
                                      http_resolver,
                                      opt.memento_notify_url);

      _memento_sproutlet = new SproutletAppServerShim(_memento,
                                                      opt.port_memento,
                                                      opt.uri_memento,
                                                      incoming_sip_transactions_tbl,
                                                      outgoing_sip_transactions_tbl);
      sproutlets.push_back(_memento_sproutlet);
    }
  }

  return plugin_loaded;
}

/// Unloads the Memento plug-in.
void MementoPlugin::unload()
{
  delete _memento_sproutlet;
  delete _memento;
  delete _cass_resolver;
  delete _call_list_store;
  delete _cass_comm_monitor;
}
