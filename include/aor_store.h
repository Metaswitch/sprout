/**
 * @file aor_store.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef AOR_STORE_H__
#define AOR_STORE_H__


#include <string>
#include <stdio.h>
#include <stdlib.h>


#include "store.h"
#include "aor.h"

// Pure virtual parent class for implementations of the AoRStore, for use
// in the SubscriberDataManager. Defines the public interface that must
// be implemented in any derived classes.
class AoRStore
{
public:
  /// AoRSore constructor.
  AoRStore(){}

  /// Destructor.
  virtual ~AoRStore(){}

  // Called through to from handlers code.
  virtual bool has_servers() = 0;

  /// Get the data for a particular address of record (registered SIP URI,
  /// in format "sip:2125551212@example.com"), creating it if necessary.
  /// May return NULL in case of error.  Result is owned
  /// by caller and must be freed with delete.
  ///
  /// @param aor_id    The AoR to retrieve
  /// @param trail     SAS trail
  virtual AoR* get_aor_data(const std::string& aor_id, SAS::TrailId trail) = 0;

  /// Update the data for a particular address of record.
  /// if the update succeeds, this returns true.
  ///
  /// @param aor_id               The AoR ID to set
  /// @param aor_pair             The AoR pair to set data from
  /// @param expiry               The expiry time associated with the AoR
  /// @param trail                SAS trail
  virtual Store::Status set_aor_data(const std::string& aor_id,
                                     AoRPair* aor_pair,
                                     int expiry,
                                     SAS::TrailId trail) = 0;
};

#endif
