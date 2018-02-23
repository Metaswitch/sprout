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
#include "hssconnection.h"
#include "subscriber_manager.h"
#include "sipresolver.h"
#include "impistore.h"

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


/// Task to deregister bindings in AoR in response to RTR request
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

  /// Handles a RTR request based on parsed infomation
  ///
  /// @return HTTPCode   success code of deregister_bindings below
  HTTPCode handle_request();

  /// Retrieve the aors and any private IDs from the request body
  ///
  /// @param body[in]     HTTP request body
  ///
  /// @return HTTPCode
  ///  HTTP_OK          - request body successfully parsed
  ///  HTTP_BAD_REQUEST - json in request body is missing or wrong format
  HTTPCode parse_request(std::string body);

  /// Deregister binding in response to RTR request
  ///
  /// @param aor_id[in]              address of record for the bindings
  /// @param private_id[in]          IMPI of the bindings to be deregistered
  /// @param impis_to_delete[out]    IMPI of the bindings to be deregistered
  ///
  /// @return
  ///   HTTP_OK          - binding successfully deregistered
  ///
  ///   HTTP_SERVER_ERROR
  ///   HTTP_NOT_FOUND
  ///   HTTP_PRECONDITION_FAILED
  ///                    - error occurred during s4 handle_get, handle_patch, or
  ///                    deregister with hss
  HTTPCode deregister_bindings(std::string aor_id,
                               std::string private_id,
                               std::set<std::string>& impis_to_delete);

protected:
  /// @brief Delete IMPI from ImpiStore based on RTR request
  ///
  /// @param store[in]        ImpiStore where IMPIs are to be deleted
  /// @param impi[in]         IMPI to be deleted
  void delete_impi_from_store(ImpiStore* store, const std::string& impi);

  const Config* _cfg;
  std::map<std::string, std::string> _bindings;
};


///Task to retrieve bindings from store.
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
  /// Write information about all bindings in an AoR to a JSON string
  ///
  /// @param bindings[in]   map of binding_id to Binding object in an AoR
  ///
  /// @return JSON string containing all bindings information
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
  /// Write information about all subscriptions in an AoR to a JSON string
  ///
  /// @param subscription[in]   map of to_tag and Subscription object in an AoR
  ///
  /// @return JSON string containing all subscription information
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

 
  /// Parse push profile request to populate _associated_uris for this task
  ///
  /// @param body[in]   request body of Push Profile
  /// @param trail[in]  SAS logging
  ///
  /// @return
  ///  HTTP_OK          - Associated URIS successfully populated
  ///  HTTP_BAD_REQUEST - failed to parse request body as JSON/XML
  HTTPCode get_associated_uris(std::string body, SAS::TrailId trail);

  /// Get subscriber manager to update associated uris based on _associated_uris
  /// that is populated in get_associated_uris
  ///
  /// @param trail[in]   SAS logging
  ///
  /// @return
  ///  HTTP_OK         - Subscriber Manager successfully updated associated URIs
  ///
  ///  HTTP_SERVER_ERROR
  ///  HTTP_NOT_FOUND
  ///  HTTP_PRECONDITION_FAILED
  ///                  - error occurred during s4 handle_get or handle_patch
  HTTPCode update_associated_uris(SAS::TrailId trail);

protected:
  const Config* _cfg;
  std::string _default_public_id;
  AssociatedURIs _associated_uris;
};
#endif
