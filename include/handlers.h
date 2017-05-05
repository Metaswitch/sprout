/**
 * @file handlers.cpp
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

#ifndef HANDLERS_H__
#define HANDLERS_H__

#include "httpstack.h"
#include "httpstack_utils.h"
#include "chronosconnection.h"
#include "hssconnection.h"
#include "subscriber_data_manager.h"
#include "sipresolver.h"
#include "impistore.h"

/// Common factory for all handlers that deal with chronos timer pops. This is
/// a subclass of SpawningHandler that requests HTTP flows to be
/// logged at detail level.
template<class H, class C>
class ChronosHandler : public HttpStackUtils::SpawningHandler<H, C>
{
public:
  ChronosHandler(C* cfg) : HttpStackUtils::SpawningHandler<H, C>(cfg)
  {}

  virtual ~ChronosHandler() {}

  HttpStack::SasLogger* sas_logger(HttpStack::Request& req)
  {
    return &HttpStackUtils::CHRONOS_SAS_LOGGER;
  }
};

class AoRTimeoutTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberDataManager* sdm,
           std::vector<SubscriberDataManager*> remote_sdms,
           HSSConnection* hss) :
      _sdm(sdm),
      _remote_sdms(remote_sdms),
      _hss(hss)
    {}
    SubscriberDataManager* _sdm;
    std::vector<SubscriberDataManager*> _remote_sdms;
    HSSConnection* _hss;
  };

  AoRTimeoutTask(HttpStack::Request& req,
                       const Config* cfg,
                       SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  void run();

protected:
  void handle_response();
  HTTPCode parse_response(std::string body);
  SubscriberDataManager::AoRPair* set_aor_data(
                        SubscriberDataManager* current_sdm,
                        std::string aor_id,
                        std::vector<std::string> unbarred_irs_impus,
                        SubscriberDataManager::AoRPair* previous_aor_data,
                        std::vector<SubscriberDataManager*> remote_sdms,
                        bool& all_bindings_expired);

protected:
  const Config* _cfg;
  std::string _aor_id;
};

class DeregistrationTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberDataManager* sdm,
           std::vector<SubscriberDataManager*> remote_sdms,
           HSSConnection* hss,
           SIPResolver* sipresolver,
           ImpiStore* impi_store) :
      _sdm(sdm),
      _remote_sdms(remote_sdms),
      _hss(hss),
      _sipresolver(sipresolver),
      _impi_store(impi_store)
    {}
    SubscriberDataManager* _sdm;
    std::vector<SubscriberDataManager*> _remote_sdms;
    HSSConnection* _hss;
    SIPResolver* _sipresolver;
    ImpiStore* _impi_store;
  };


  DeregistrationTask(HttpStack::Request& req,
                     const Config* cfg,
                     SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  void run();
  HTTPCode handle_request();
  HTTPCode parse_request(std::string body);
  SubscriberDataManager::AoRPair* deregister_bindings(
                    SubscriberDataManager* current_sdm,
                    HSSConnection* hss,
                    std::string aor_id,
                    std::string private_id,
                    SubscriberDataManager::AoRPair* previous_aor_data,
                    std::vector<SubscriberDataManager*> remote_sdms,
                    std::set<std::string>& impis_to_delete);

protected:
  const Config* _cfg;
  std::map<std::string, std::string> _bindings;
  std::string _notify;
};

class AuthTimeoutTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
  Config(ImpiStore* store, HSSConnection* hss) :
    _impi_store(store), _hss(hss) {}
    ImpiStore* _impi_store;
    HSSConnection* _hss;
  };
  AuthTimeoutTask(HttpStack::Request& req,
                  const Config* cfg,
                  SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  void run();
protected:
  HTTPCode handle_response(std::string body);
  const Config* _cfg;
  std::string _impi;
  std::string _impu;
  std::string _nonce;

};


/// Abstract class that contains most of the logic for retrieving stored
/// bindings and subscriptions.
///
/// This class handles checking the request, extracting the requested IMPU and
/// retrieving data from the store. It calls into the subclass to build a
/// response, which it then sends.
class GetCachedDataTask : public HttpStackUtils::Task
{
public:
  struct Config
  {
    Config(SubscriberDataManager* sdm,
           std::vector<SubscriberDataManager*> remote_sdms) :
      _sdm(sdm),
      _remote_sdms(remote_sdms)
    {}

    SubscriberDataManager* _sdm;
    std::vector<SubscriberDataManager*> _remote_sdms;
  };

  GetCachedDataTask(HttpStack::Request& req, const Config* cfg, SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};

  void run();

protected:
  virtual std::string serialize_data(SubscriberDataManager::AoR* aor) = 0;
  const Config* _cfg;
};

/// Concrete subclass for retrieving bindings.
class GetBindingsTask : public GetCachedDataTask
{
public:
  using GetCachedDataTask::GetCachedDataTask;
protected:
  std::string serialize_data(SubscriberDataManager::AoR* aor);
};

/// Concrete subclass for retrieving subscriptions.
class GetSubscriptionsTask : public GetCachedDataTask
{
public:
  using GetCachedDataTask::GetCachedDataTask;
protected:
  std::string serialize_data(SubscriberDataManager::AoR* aor);
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
    Config(SubscriberDataManager* sdm,
           std::vector<SubscriberDataManager*> remote_sdms,
           HSSConnection* hss) :
      _sdm(sdm), _remote_sdms(remote_sdms), _hss(hss)
    {}

    SubscriberDataManager* _sdm;
    std::vector<SubscriberDataManager*> _remote_sdms;
    HSSConnection* _hss;
  };

  DeleteImpuTask(HttpStack::Request& req, const Config* cfg, SAS::TrailId trail) :
    HttpStackUtils::Task(req, trail), _cfg(cfg)
  {};
  virtual ~DeleteImpuTask() {}

  void run();

private:
  const Config* _cfg;
};

#endif
