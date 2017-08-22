/**
 * @file astaire_impistore.h  Definition of class for storing IMPIs in a
 *                            Memcached-like store
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef ASTAIRE_IMPISTORE_H_
#define ASTAIRE_IMPISTORE_H_

#include "store.h"
#include "impistore.h"
#include <rapidjson/document.h>
#include <rapidjson/writer.h>

/// Class implementing store of IMPIs, including authentication challenges.
/// This is a wrapper around an underlying Store class which implements a
/// simple KV store API with atomic write and record expiry semantics.  The
/// underlying store can be any implementation that implements the Store API.
///
/// We read and write a JSON object representing the full IMPI, including its
/// authentication challenges, keyed solely off its private ID.
class AstaireImpiStore : public ImpiStore
{
public:
  /// @class AstaireImpiStore::Impi
  ///
  /// Represents an IMPI, below which AVs may exist
  class Impi : public ImpiStore::Impi
  {
  public:
    /// Constructor.
    /// @param _impi         The private ID.
    Impi(const std::string& _impi) : ImpiStore::Impi(_impi), _cas(0) {};

    /// Destructor.
    virtual ~Impi() {};

  private:
    /// Write to JSON writer.
    virtual void write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer) override;

    /// Memcached CAS value.
    uint64_t _cas;

    // The IMPI store is a friend so it can read our CAS value.
    friend class AstaireImpiStore;
  };

  /// Constructor.
  /// @param data_store    A pointer to the underlying data store.
  AstaireImpiStore(Store* data_store);

  /// Destructor.
  virtual ~AstaireImpiStore();

  /// Store the specified IMPI in the store.
  /// @returns Store::Status::OK on success, or an error code on failure.
  /// @param impi      An Impi object representing the IMPI.  The caller
  ///                  continues to own this object.
  virtual Store::Status set_impi(ImpiStore::Impi* impi,
                                 SAS::TrailId trail) override;

  /// Retrieves the IMPI for the specified private user identity.
  ///
  /// @returns         A pointer to an Impi object describing the IMPI. The
  ///                  caller owns the returned object. This method only returns
  ///                  NULL if the underlying store failed - if no IMPI was
  ///                  found it returns an empty object.
  /// @param impi      The private user identity.
  virtual ImpiStore::Impi* get_impi(const std::string& impi,
                                    SAS::TrailId trail) override;

  /// Delete all record of the IMPI.
  ///
  /// @param impi      An Impi object representing the IMPI.  The caller
  ///                  continues to own this object.
  /// @returns Store::Status::OK on success, or an error code on failure.
  virtual Store::Status delete_impi(ImpiStore::Impi* impi,
                                    SAS::TrailId trail) override;

  /// Deserialization from JSON.
  static AstaireImpiStore::Impi* from_json(const std::string& impi, const std::string& json);

  /// Deserialization from JSON.
  static AstaireImpiStore::Impi* from_json(const std::string& impi, rapidjson::Value* json);

private:
  /// Identifier for IMPI table.
  static const std::string TABLE_IMPI;

  /// The underlying data store.
  Store* _data_store;
};

#endif
