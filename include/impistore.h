/**
 * @file impistore.h  Definition of class for storing IMPIs
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef IMPISTORE_H_
#define IMPISTORE_H_

#include "store.h"
#include <rapidjson/document.h>
#include <rapidjson/writer.h>

/// Class implementing store of IMPIs, including authentication challenges.
/// This is a wrapper around an underlying Store class which implements a
/// simple KV store API with atomic write and record expiry semantics.  The
/// underlying store can be any implementation that implements the Store API.
///
/// We read and write a JSON object representing the full IMPI, including its
/// authentication challenges, keyed solely off its private ID.
class ImpiStore
{
public:
  /// @class ImpiStore::AuthChallenge
  ///
  /// Represents an authentication challenge
  class AuthChallenge
  {
  public:
    /// @class ImpiStore::AuthChallenge::Type
    ///
    /// Describes the type of the challenge
    enum Type
    {
      DIGEST,
      AKA
    };

    /// Initial nonce count, when creating new challenges.
    static const int INITIAL_NONCE_COUNT = 1;

    /// Default expiry time, if no value can be read from the store.  This
    /// should always be long enough for the UE to respond to the
    /// authentication challenge, and means that on authentication timeout our
    /// 30-second Chronos timer should pop before it expires.
    static const int DEFAULT_EXPIRES = 40;

    /// Constructor.
    /// @param _type         Type of authentication challenge.
    /// @param _nonce        Nonce used for this challenge.
    /// @param _expires      Absolute expiry time in seconds since the epoch.
    AuthChallenge(const Type _type, const std::string& _nonce, int _expires) :
      type(_type),
      nonce(_nonce),
      nonce_count(INITIAL_NONCE_COUNT),
      expires(_expires),
      correlator(),
      scscf_uri(),
      _cas(0) {};

    /// Destructor must be virtual as we're going to extend this class.
    virtual ~AuthChallenge() {};

    /// Type of the AV
    enum Type type;

    /// Nonce used for this challenge.
    std::string nonce;

    /// Minimum nonce count we will accept - any nonce count lower than this
    /// might be a replay and must be rejected.
    uint32_t nonce_count;

    /// Expiry time - absolute in seconds since the Epoch
    int expires;

    /// Correlator between original challenge and responses.
    std::string correlator;

    /// URI of the S-CSCF that issued the challenge. This is the server name
    /// used on the SAR if the authentication times out. This field should not
    /// be changed once the challenge has been created.
    std::string scscf_uri;

  private:
    /// Constructor.
    /// @param _type         Type of authentication challenge.
    AuthChallenge(const Type _type) :
      type(_type),
      nonce(),
      nonce_count(0),
      expires(0),
      correlator(),
      scscf_uri(),
      _cas(0) {};

    /// Write to JSON writer (IMPI format).
    virtual void write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer);

    /// Deserialization from JSON (IMPI format).
    static ImpiStore::AuthChallenge* from_json(rapidjson::Value* json);

    /// Memcached CAS value.
    uint64_t _cas;

    // The IMPI store is a friend so it can call our JSON serialization
    // functions and read our CAS value.
    friend class ImpiStore;
  };

  /// @class ImpiStore::DigestAuthChallenge
  ///
  /// Represents a digest authentication challenge
  class DigestAuthChallenge : public AuthChallenge
  {
  public:
    /// Constructor.
    /// @param _nonce        Nonce used for this challenge.
    /// @param _realm        Authentication realm.
    /// @param _qop          Quality of Protection.
    /// @param _ha1          HA1 digest.
    /// @param _expires      Absolute expiry time in seconds since the epoch.
    DigestAuthChallenge(const std::string& _nonce,
                        const std::string& _realm,
                        const std::string& _qop,
                        const std::string& _ha1,
                        int _expires) :
      AuthChallenge(AuthChallenge::Type::DIGEST, _nonce, _expires),
      realm(_realm),
      qop(_qop),
      ha1(_ha1) {};

    /// Destructor.
    virtual ~DigestAuthChallenge() {};

    /// Digest realm
    std::string realm;

    /// Digest Quality of Protection
    std::string qop;

    /// Digest HA1
    std::string ha1;

  private:
    /// Constructor.
    DigestAuthChallenge() :
      AuthChallenge(AuthChallenge::Type::DIGEST),
      realm(),
      qop(),
      ha1() {};

    /// Write to JSON writer (IMPI format).
    virtual void write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer);

    /// Deserialization from JSON (IMPI format).
    static ImpiStore::DigestAuthChallenge* from_json(rapidjson::Value* json);

    // The IMPI store is a friend so it can call our JSON serialization
    // functions.
    friend class ImpiStore;
  };

  /// @class ImpiStore::AKAAuthChallenge
  ///
  /// Represents an AKA authentication challenge
  class AKAAuthChallenge : public AuthChallenge
  {
  public:
    /// Constructor.
    /// @param _nonce        Nonce used for this challenge.
    /// @param _response     AKA response.
    /// @param _expires      Absolute expiry time in seconds since the epoch.
    AKAAuthChallenge(const std::string& _nonce,
                     const std::string& _response,
                     int _expires) :
      AuthChallenge(AuthChallenge::Type::AKA, _nonce, _expires),
      response(_response) {};

    /// Destructor.
    virtual ~AKAAuthChallenge() {};

    /// AKA expected response
    std::string response;

  private:
    /// Constructor.
    AKAAuthChallenge() :
      AuthChallenge(AuthChallenge::Type::AKA),
      response() {};

    /// Write to JSON writer (IMPI format).
    virtual void write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer);

    /// Deserialization from JSON (IMPI format).
    static ImpiStore::AKAAuthChallenge* from_json(rapidjson::Value* json);

    // The IMPI store is a friend so it can call our JSON serialization
    // functions.
    friend class ImpiStore;
  };

  /// @class ImpiStore::Impi
  ///
  /// Represents an IMPI, below which AVs may exist
  class Impi
  {
  public:
    /// Constructor.
    /// @param _impi         The private ID.
    Impi(const std::string& _impi) : impi(_impi), auth_challenges(), _cas(0) {};

    /// Destructor.
    ~Impi();

    /// Helper - get authentication challenge for a given nonce.
    /// @returns the authentication challenge, or NULL if not found
    /// @param nonce         The nonce to look up.
    ImpiStore::AuthChallenge* get_auth_challenge(const std::string& nonce);

    /// Private ID
    std::string impi;

    /// List of authentication challenges that can be used with this IMPI.
    /// Challenges in the list are owned by the Impi (although can be modified
    /// by the user).  New challenges can be added to the list.  If challenges
    /// are removed, they must be destroyed by the user.
    std::vector<ImpiStore::AuthChallenge*> auth_challenges;

  private:
    /// Serialization to JSON.
    std::string to_json();

    /// Write to JSON writer.
    void write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer);

    /// Deserialization from JSON.
    static ImpiStore::Impi* from_json(const std::string& impi, const std::string& json);

    /// Deserialization from JSON.
    static ImpiStore::Impi* from_json(const std::string& impi, rapidjson::Value* json);

    /// Get the expiry time for the whole IMPI object.
    /// @returns the expiry time.
    int get_expires();

    /// Memcached CAS value.
    uint64_t _cas;

    // The IMPI store is a friend so it can read our CAS value.
    friend class ImpiStore;
  };

  /// Constructor.
  /// @param data_store    A pointer to the underlying data store.
  ImpiStore(Store* data_store);

  /// Destructor.
  virtual ~ImpiStore();

  /// Store the specified IMPI in the store.
  /// @returns Store::Status::OK on success, or an error code on failure.
  /// @param impi      An Impi object representing the IMPI.  The caller
  ///                  continues to own this object.
  virtual Store::Status set_impi(Impi* impi,
                                 SAS::TrailId trail);

  /// Retrieves the IMPI for the specified private user identity.
  ///
  /// @returns         A pointer to an Impi object describing the IMPI. The
  ///                  caller owns the returned object. This method only returns
  ///                  NULL if the underlying store failed - if no IMPI was
  ///                  found it returns an empty object.
  /// @param impi      The private user identity.
  virtual Impi* get_impi(const std::string& impi,
                         SAS::TrailId trail);

  /// Delete all record of the IMPI.
  ///
  /// @param impi      An Impi object representing the IMPI.  The caller
  ///                  continues to own this object.
  /// @returns Store::Status::OK on success, or an error code on failure.
  virtual Store::Status delete_impi(Impi* impi,
                                    SAS::TrailId trail);

private:
  /// Identifier for IMPI table.
  static const std::string TABLE_IMPI;

  /// The underlying data store.
  Store* _data_store;
};

// Utility function - retrieves the "corrlator" field from the give challenge
// and raises a correlating transaction marker in the given trail.
void correlate_trail_to_challenge(ImpiStore::AuthChallenge* auth_challenge,
                                  SAS::TrailId trail);

#endif
