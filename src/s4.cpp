/**
 * @file s4.cpp
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


// Common STL includes.
#include <cassert>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <queue>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <time.h>

#include "log.h"
#include "utils.h"
#include "s4.h"
#include "astaire_aor_store.h"
#include "sproutsasevent.h"
#include "constants.h"

// SDM-REFACTOR-TODO:
// Commonise logic in the handles? Or at least make more similar.
// TRC statements
// SAS logging (poss already covered by memcached logs)
// Lifetimes of AoRs?
// Implement PATCH
// Implement PATCH/PUT conversion, and protect against loops
// Implement max_expiry
// Full UT

S4::S4(std::string id,
       AoRStore* aor_store,
       std::vector<S4*> remote_s4s) :
  _id(id),
  _aor_store(aor_store),
  _remote_s4s(remote_s4s)
{
}

S4::~S4()
{
}

HTTPCode S4::handle_get(std::string aor_id,
                        AoR** aor,
                        SAS::TrailId trail)
{
  HTTPCode rc;
  bool retry_get = true;

  while (retry_get)
  {
    *aor = _aor_store->get_aor_data(aor_id, trail);

    if (aor == NULL || *aor == NULL)
    {
      // Failed to get data for the AoR because there is no connection
      // to the store. This will already have been SAS logged by the AoR store.
      TRC_DEBUG("Store error for %s. Failed to get AoR for %s from store",
                _id.c_str(),
                aor_id.c_str());
      rc = HTTP_SERVER_ERROR;
      retry_get = false;
    }
    else if ((*aor)->bindings().empty())
    {
      // If we don't have any bindings, try the remote stores.
      TRC_DEBUG("AoR is empty for %s in %s",
                aor_id.c_str(),
                _id.c_str());
      rc = HTTP_NOT_FOUND;
      retry_get = false;

      for (S4* remote_s4 : _remote_s4s)
      {
        AoR* remote_aor = NULL;
        HTTPCode remote_rc = remote_s4->handle_get(aor_id, &remote_aor, trail);

        if (remote_rc == HTTP_OK)
        {
          // The remote store has an entry for this AoR and it has bindings -
          // copy the information across.
          (*aor)->copy_aor(remote_aor);
          Store::Status store_rc = _aor_store->set_aor_data(aor_id, *aor, (*aor)->get_expiry(), trail);

          if (store_rc == Store::Status::ERROR)
          {
            // We haven't been able to write the data back to memcached.
            rc = HTTP_SERVER_ERROR;
          }
          else if (store_rc == Store::Status::OK)
          {
            rc = HTTP_OK;
          }
          else if (store_rc == Store::Status::DATA_CONTENTION)
          {
            retry_get = true;
          }

          break;
        }
        else if (remote_rc == HTTP_NOT_FOUND)
        {
          // We created an AoR but it's empty. Free it off.
          delete remote_aor; remote_aor = NULL;
        }
      }
    }
    else
    {
      retry_get = false;
      rc = HTTP_OK;
    }
  }

  return rc;
}

HTTPCode S4::handle_delete(std::string aor_id, SAS::TrailId trail)
{
  Store::Status store_rc = Store::Status::DATA_CONTENTION;

  while (store_rc == Store::Status::DATA_CONTENTION)
  {
    // Get the AoR from the data store - this only looks in the local store.
    AoR* aor = _aor_store->get_aor_data(aor_id, trail);

    if (aor == NULL)
    {
      store_rc = Store::Status::ERROR;
    }
    else if (aor->bindings().empty())
    {
      store_rc = Store::Status::OK;
    }
    else
    {
      // Clear the AoR.
      aor->clear(true);

      // Write the empty AoR back to the store.
      store_rc = _aor_store->set_aor_data(aor_id, aor, aor->get_expiry(), trail);
    }
  }

  HTTPCode rc;

  if (store_rc == Store::Status::OK)
  {
    // Subscriber has been deleted from the local site, so send the DELETE
    // out to the remote sites. The response to the SM is always going to be
    // OK independently of whether any remote DELETEs are successful.
    replicate_delete_cross_site(aor_id, trail);
    rc = HTTP_OK;
  }
  else
  {
    // Failed to delete data - we don't try and delete the subscriber from
    // any remote sites.
    TRC_DEBUG("Failed to delete subscriber %s from %s",
              aor_id.c_str(),
              _id.c_str());
    rc = HTTP_SERVER_ERROR;
  }

  return rc;
}

HTTPCode S4::handle_put(std::string aor_id,
                        AoR* new_aor,
                        SAS::TrailId trail)
{
  HTTPCode rc = HTTP_OK;

  while (true)
  {
    // Get the AoR from the data store - this only looks in the local store.
    AoR* current_aor = _aor_store->get_aor_data(aor_id, trail);

    if (current_aor == NULL)
    {
      rc = HTTP_SERVER_ERROR;
      break;
    }
    else if (!current_aor->bindings().empty())
    {
      // We already have data for this AoR, so we shouldn't have had a PUT for it.
      rc = HTTP_UNPROCESSABLE_ENTITY;
      delete current_aor; current_aor = NULL;
      break;
    }
    else
    {
      // Update the AoR with the requested changes.
      current_aor->copy_aor(new_aor);
      Store::Status store_rc = _aor_store->set_aor_data(aor_id,
                                                        current_aor,
                                                        current_aor->get_expiry(),
                                                        trail);

      if (store_rc == Store::Status::OK)
      {
        replicate_put_cross_site(aor_id, new_aor, trail);
        rc = HTTP_OK;
        break;
      }
      else if (store_rc == Store::Status::ERROR)
      {
        // Failed to add data - we don't try and add the subscriber to
        // any remote sites.
        TRC_DEBUG("Failed to add subscriber %s to %s",
                  aor_id.c_str(),
                  _id.c_str());
        rc = HTTP_SERVER_ERROR;
        break;
      }
    }
  }

  return rc;
}

HTTPCode S4::handle_patch(std::string aor_id,
                          PatchObject* po,
                          SAS::TrailId trail)
{
  HTTPCode rc = HTTP_OK;

  while (true)
  {
    // Get the AoR from the data store - this only looks in the local store.
    AoR* aor = _aor_store->get_aor_data(aor_id, trail);

    if (aor == NULL)
    {
      rc = HTTP_SERVER_ERROR;
      break;
    }
    else if (aor->bindings().empty())
    {
      // We don't have data for this AoR, so we shouldn't have had a PATCH for it.
      rc = HTTP_NOT_FOUND;
      delete aor; aor = NULL;
      break;
    }
    else
    {
      // Update the AoR with the requested changes.
      aor->patch_aor(po);
      Store::Status store_rc = _aor_store->set_aor_data(aor_id,
                                                        aor,
                                                        aor->get_expiry(),
                                                        trail);

      if (store_rc == Store::Status::OK)
      {
        replicate_patch_cross_site(aor_id, po, trail);
        rc = HTTP_OK;
        break;
      }
      else if (store_rc == Store::Status::ERROR)
      {
        // Failed to updateadd data - we don't try and update the subscriber in
        // any remote sites.
        TRC_DEBUG("Failed to update subscriber %s to %s",
                  aor_id.c_str(),
                  _id.c_str());
        rc = HTTP_SERVER_ERROR;
        break;
      }
    }
  }

  return rc;
}

void S4::replicate_delete_cross_site(std::string aor_id,
                                     SAS::TrailId trail)
{
  for (S4* remote_s4 : _remote_s4s)
  {
    remote_s4->handle_delete(aor_id, trail);
  }
}

void S4::replicate_put_cross_site(std::string aor_id,
                                  AoR* aor,
                                  SAS::TrailId trail)
{
  for (S4* remote_s4 : _remote_s4s)
  {
    HTTPCode rc = remote_s4->handle_put(aor_id, aor, trail);

    if (rc == HTTP_UNPROCESSABLE_ENTITY)
    {
      // We've tried to do a PUT to a remote site that already has data. We need
      // to send a PATCH instead.
      TRC_DEBUG("Need to convert PUT to PATCH for %s", _id.c_str());
      PatchObject* po = new PatchObject();
      aor->convert_aor_to_patch(po);
      remote_s4->handle_patch(aor_id, po, trail);
    }
  }
}

void S4::replicate_patch_cross_site(std::string aor_id,
                                    PatchObject* po,
                                    SAS::TrailId trail)
{
  for (S4* remote_s4 : _remote_s4s)
  {
    HTTPCode rc = remote_s4->handle_patch(aor_id, po, trail);

    if (rc == HTTP_UNPROCESSABLE_ENTITY)
    {
      // We've tried to do a PATCH to a remote site that doesn't have any data.
      // We need to send a PUT.
      TRC_DEBUG("Need to convert PATCH to PUT for %s", _id.c_str());
      AoR* aor = new AoR(aor_id);
      aor->convert_patch_to_aor(po);
      remote_s4->handle_put(aor_id, aor, trail);
    }
  }
}
