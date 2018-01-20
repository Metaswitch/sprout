/**
 * @file handlers.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef HANDLERS_H__
#define HANDLERS_H__

#include "httpstack.h"
#include "httpstack_utils.h"
#include "chronosconnection.h"
#include "hssconnection.h"
#include "subscriber_data_manager.h"
#include "subscriber_manager.h"
#include "sipresolver.h"
#include "impistore.h"
#include "fifcservice.h"
#include "aor.h"

/// Common factory for all handlers that deal with timer pops. This is
/// a subclass of SpawningHandler that requests HTTP flows to be
/// logged at detail level.
template<class H, class C>
class TimerHandler : public HttpStackUtils::SpawningHandler<H, C>
{
public:
  TimerHandler(C* cfg) : HttpStackUtils::SpawningHandler<H, C>(cfg)
  {}

  virtual ~TimerHandler() {}

  HttpStack::SasLogger* sas_logger(HttpStack::Request& req)
  {
    // Note that we use a Chronos SAS Logger here even though this TimerHandler
    // isn't specific to Chronos.  In reality there isn't anything Chronos
    // specific about the logger, but we should fix up the naming in future
    // when we actually support multiple timer services.
    return &HttpStackUtils::CHRONOS_SAS_LOGGER;
  }
};

/// Base AoRTimeoutTask class for tasks that implement AoR timeout callbacks
/// from specific timer services.
class AoRTimeoutTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberDataManager* sdm,
           std::vector<SubscriberDataManager*> remote_sdms,
           HSSConnection* hss,
           FIFCService* fifc_service,
           IFCConfiguration ifc_configuration) :
      _sdm(sdm),
      _remote_sdms(remote_sdms),
      _hss(hss),
      _fifc_service(fifc_service),
      _ifc_configuration(ifc_configuration)
    {}
    SubscriberDataManager* _sdm;
    std::vector<SubscriberDataManager*> _remote_sdms;
    HSSConnection* _hss;
    FIFCService* _fifc_service;
    IFCConfiguration _ifc_configuration;
  };

  AoRTimeoutTask(HttpStack::Request& req,
                       const Config* cfg,
                       SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  virtual void run() = 0;

protected:
  void process_aor_timeout(std::string aor_id);

protected:
  const Config* _cfg;
};

/// Base AuthTimeoutTask class for tasks that implement authentication timeout
/// callbacks from specific timer services.
class AuthTimeoutTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(ImpiStore* local_impi_store, HSSConnection* hss) :
      _local_impi_store(local_impi_store),
      _hss(hss)
    {}
    ImpiStore* _local_impi_store;
    HSSConnection* _hss;
  };
  AuthTimeoutTask(HttpStack::Request& req,
                  const Config* cfg,
                  SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  virtual void run() = 0;

protected:
  HTTPCode timeout_auth_challenge(std::string impu,
                                  std::string impi,
                                  std::string nonce);
  const Config* _cfg;
};

class DeregistrationTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberManager* sm,
           SIPResolver* sipresolver,
           ImpiStore* local_impi_store,
           std::vector<ImpiStore*> remote_impi_stores) :
      _sm(sm),
      _sipresolver(sipresolver),
      _local_impi_store(local_impi_store),
      _remote_impi_stores(remote_impi_stores)
    {}
    SubscriberManager* _sm;
    SIPResolver* _sipresolver;
    ImpiStore* _local_impi_store;
    std::vector<ImpiStore*> _remote_impi_stores;
  };


  DeregistrationTask(HttpStack::Request& req,
                     const Config* cfg,
                     SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  void run();
  HTTPCode handle_request();
  HTTPCode parse_request(std::string body);
  HTTPCode deregister_bindings(std::string aor_id,
                               std::string private_id,
                               std::set<std::string>& impis_to_delete);

protected:
  void delete_impi_from_store(ImpiStore* store, const std::string& impi);

  const Config* _cfg;
  std::map<std::string, std::string> _bindings;
  std::string _notify;
};

/// For retrieving bindings from store.
class GetBindingsTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberManager* sm) :
      _sm(sm)
    {}

    SubscriberManager* _sm;
  };

  GetBindingsTask(HttpStack::Request& req, const Config* cfg, SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  void run();

protected:
  std::string serialize_data(const Bindings& bindings);
  const Config* _cfg;
};

/// For retrieving subscriptions from store.
class GetSubscriptionsTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberManager* sm) :
      _sm(sm)
    {}

    SubscriberManager* _sm;
  };

  GetSubscriptionsTask(HttpStack::Request& req, const Config* cfg, SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  void run();

protected:
  std::string serialize_data(const Subscriptions& subscriptions);
  const Config* _cfg;
};

/// Task for performing an administrative deregistration at the S-CSCF. This
///
/// -  Deletes subscriber data from the store (including all bindings and
///    subscriptions).
/// -  Sends a deregistration request to homestead.
/// -  Sends NOTIFYs for any subscriptions to the reg state package for the AoR.
/// -  Sends 3rd party deregister requests to Application Servers if required.
class DeleteImpuTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberManager* sm) :
      _sm(sm)
    {}

    SubscriberManager* _sm;
  };

  DeleteImpuTask(HttpStack::Request& req, const Config* cfg, SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};
  virtual ~DeleteImpuTask() {}

  void run();

private:
  const Config* _cfg;
};

/// Task for receiving user data sent by Homestead when it receives a PPR.
/// It will send NOTIFYs if the associated URIs have changed (by calling
/// into the SDM).
class PushProfileTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberManager* sm) :
      _sm(sm)
    {}

    SubscriberManager* _sm;
  };

  PushProfileTask(HttpStack::Request& req,
                  const Config* cfg,
		  SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  void run();
  HTTPCode get_associated_uris(std::string body, SAS::TrailId trail);
  HTTPCode update_associated_uris(SAS::TrailId trail);

protected:
  const Config* _cfg;
  std::string _default_public_id;
  AssociatedURIs _associated_uris;
};
#endif
