/**
 * @file astaire_aor_store.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef ASTAIRE_AOR_STORE_H__
#define ASTAIRE_AOR_STORE_H__


#include <string>
#include <stdio.h>
#include <stdlib.h>


#include "aor_store.h"

// Implementation of the AoRStore specific to our use of Memcached under Astaire
class AstaireAoRStore: public AoRStore
{
public:
  /// Constructor.
  AstaireAoRStore(Store* store);

  /// Destructor.
  virtual ~AstaireAoRStore();

  // Called through to from handlers code.
  virtual bool has_servers() override { return _connector->underlying_store_has_servers(); }

  /// Get the data for a particular address of record (registered SIP URI,
  /// in format "sip:2125551212@example.com"), creating it if necessary.
  /// May return NULL in case of error.  Result is owned
  /// by caller and must be freed with delete.
  ///
  /// @param aor_id    The AoR to retrieve
  /// @param trail     SAS trail
  virtual AoR* get_aor_data(const std::string& aor_id, SAS::TrailId trail) override;

  /// Update the data for a particular address of record.
  /// if the update succeeds, this returns true.
  ///
  /// @param aor_id               The AoR ID to set
  /// @param aor_pair             The AoR pair to set data from
  /// @param expiry               The expiry time associated with the AoR
  /// @param trail                SAS trail
  virtual Store::Status set_aor_data(const std::string& aor_id,
                                     AoR* aor,
                                     int expiry,
                                     SAS::TrailId trail) override;


  /// Class used by the AstaireAoRStore to serialize AoRs from C++
  /// objects to the JSON format used in the store, and deserialize them.
  class JsonSerializerDeserializer
  {
  public:
    /// Destructor.
    ~JsonSerializerDeserializer() {}

    /// Serialize an AoR object to the format used in the store.
    ///
    /// @param aor_data - The AoR object to serialize.
    /// @return         - The serialized form.
    std::string serialize_aor(AoR* aor_data);

    /// Deserialize some data from the store into an AoR object.
    ///
    /// @param aor_id - The primary public ID for the AoR. This is also the key
    ///                 used used for the record in the store.
    /// @param s      - The data to deserialize.
    ///
    /// @return       - An AoR object, or NULL if the data could not be
    ///                 deserialized (e.g. because it is corrupt).
    AoR* deserialize_aor(const std::string& aor_id,
                         const std::string& s);
  };

  /// Provides the interface to the data store. This is responsible for
  /// updating and getting information from the underlying data store. The
  /// classes that call this class are responsible for retrying the get/set
  /// functions in case of failure.
  class Connector
  {
    Connector(Store* data_store,
              JsonSerializerDeserializer*& serializer_deserializer);

    ~Connector();

    AoR* get_aor_data(const std::string& aor_id, SAS::TrailId trail);

    Store::Status set_aor_data(const std::string& aor_id,
                               AoR* aor_data,
                               int expiry,
                               SAS::TrailId trail);

    bool underlying_store_has_servers() { return (_data_store != NULL) && _data_store->has_servers(); }

    Store* _data_store;

    /// AstaireAoRStore is the only class that can use Connector
    friend class AstaireAoRStore;

  private:
    JsonSerializerDeserializer* _serializer_deserializer;
  };

public:
  Connector* _connector;
};

#endif
