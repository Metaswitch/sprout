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
    /// @param type         Type of authentication challenge.
    /// @param nonce        Nonce used for this challenge.
    /// @param expires      Absolute expiry time in seconds since the epoch.
    ///
    /// Marks the AuthChallenge as Updated, so that it appears new to the Store.
    AuthChallenge(const Type type, const std::string& nonce, int expires) :
      _type(type),
      _nonce(nonce),
      _nonce_count(INITIAL_NONCE_COUNT),
      _expires(expires),
      _correlator(),
      _scscf_uri(),
      _timer_id(""),
      _updated(true),
      _impu() {};

    /// Destructor must be virtual as we're going to extend this class.
    virtual ~AuthChallenge() {};

    /// Write to JSON writer (IMPI format).
    virtual void write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer,
                            bool expiry_in_ms = false);

    /// Deserialization from JSON (IMPI format).
    static ImpiStore::AuthChallenge* from_json(rapidjson::Value* json,
                                               bool expiry_in_ms = false,
                                               bool include_expired = false);

    /// Getters and setters
    Type get_type()
    {
      return _type;
    }

    std::string get_nonce()
    {
      return _nonce;
    }

    void set_nonce(const std::string& nonce)
    {
      _updated = true;
      _nonce = nonce;
    }

    uint32_t get_nonce_count()
    {
      return _nonce_count;
    }

    void set_nonce_count(int nonce_count)
    {
      _updated = true;
      _nonce_count = nonce_count;
    }

    int get_expires()
    {
      return _expires;
    }

    void set_expires(int expires)
    {
      _updated = true;
      _expires = expires;
    }

    std::string get_correlator()
    {
      return _correlator;
    }

    void set_correlator(const std::string& correlator)
    {
      _updated = true;
      _correlator = correlator;
    }

    std::string get_scscf_uri()
    {
      return _scscf_uri;
    }

    void set_scscf_uri(const std::string& uri)
    {
      _updated = true;
      _scscf_uri = uri;
    }

    std::string get_impu()
    {
      return _impu;
    }

    void set_impu(const std::string& impu)
    {
      // Setting the Impu doesn't mark the challenge as updated, as we never
      // change the impu after initial creation
      _impu = impu;
    }

    std::string get_timer_id()
    {
      return _timer_id;
    }

    void set_timer_id(std::string timer_id)
    {
      _updated = true;
      _timer_id = timer_id;
    }

    /// Returns whether this AuthChallenge has been updated since reading it
    /// from the store.
    bool is_updated()
    {
      return _updated;
    }

  private:
    /// Constructor.
    /// @param _type         Type of authentication challenge.
    ///
    /// Marks the AuthChallenge as not Updated, as this is called when
    /// retrieving one from the store
    AuthChallenge(const Type type) :
      _type(type),
      _nonce(),
      _nonce_count(0),
      _expires(0),
      _correlator(),
      _scscf_uri(),
      _timer_id(""),
      _updated(false),
      _impu() {};

    /// Type of the AV
    enum Type _type;

    /// Nonce used for this challenge.
    std::string _nonce;

    /// Minimum nonce count we will accept - any nonce count lower than this
    /// might be a replay and must be rejected.
    uint32_t _nonce_count;

    /// Expiry time - absolute in seconds since the Epoch
    int _expires;

    /// Correlator between original challenge and responses.
    std::string _correlator;

    /// URI of the S-CSCF that issued the challenge. This is the server name
    /// used on the SAR if the authentication times out. This field should not
    /// be changed once the challenge has been created.
    std::string _scscf_uri;

    /// Timer ID of the Chronos timer used to track when the challenge expires
    std::string _timer_id;

    /// Tracks whether this AV has been updated
    bool _updated;

    /// The IMPU for which this challenge was generated
    std::string _impu;

  friend class ImpiStore;
  };

  /// @class ImpiStore::DigestAuthChallenge
  ///
  /// Represents a digest authentication challenge
  class DigestAuthChallenge : public AuthChallenge
  {
  public:
    /// Constructor.
    /// @param nonce        Nonce used for this challenge.
    /// @param realm        Authentication realm.
    /// @param qop          Quality of Protection.
    /// @param ha1          HA1 digest.
    /// @param expires      Absolute expiry time in seconds since the epoch.
    DigestAuthChallenge(const std::string& nonce,
                        const std::string& realm,
                        const std::string& qop,
                        const std::string& ha1,
                        int expires) :
      AuthChallenge(AuthChallenge::Type::DIGEST, nonce, expires),
      _realm(realm),
      _qop(qop),
      _ha1(ha1) {};

    /// Destructor.
    virtual ~DigestAuthChallenge() {};

    /// Write to JSON writer (IMPI format).
    virtual void write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer,
                            bool expiry_in_ms = false) override;

    /// Deserialization from JSON (IMPI format).
    static ImpiStore::DigestAuthChallenge* from_json(rapidjson::Value* json);

    /// Getters and Setters
    std::string get_realm()
    {
      return _realm;
    }

    void set_realm(const std::string& realm)
    {
      _updated = true;
      _realm = realm;
    }

    std::string get_qop()
    {
      return _qop;
    }

    void set_qop(const std::string& qop)
    {
      _updated = true;
      _qop = qop;
    }

    std::string get_ha1()
    {
      return _ha1;
    }

    void set_ha1(const std::string& ha1)
    {
      _updated = true;
      _ha1 = ha1;
    }

  private:
    /// Constructor.
    DigestAuthChallenge() :
      AuthChallenge(AuthChallenge::Type::DIGEST),
      _realm(),
      _qop(),
      _ha1() {};

    /// Digest realm
    std::string _realm;

    /// Digest Quality of Protection
    std::string _qop;

    /// Digest HA1
    std::string _ha1;

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
    /// @param nonce        Nonce used for this challenge.
    /// @param response     AKA response.
    /// @param expires      Absolute expiry time in seconds since the epoch.
    AKAAuthChallenge(const std::string& nonce,
                     const std::string& response,
                     int expires) :
      AuthChallenge(AuthChallenge::Type::AKA, nonce, expires),
      _response(response) {};

    /// Destructor.
    virtual ~AKAAuthChallenge() {};

    /// Write to JSON writer (IMPI format).
    virtual void write_json(rapidjson::Writer<rapidjson::StringBuffer>* writer,
                            bool expiry_in_ms = false) override;

    /// Deserialization from JSON (IMPI format).
    static ImpiStore::AKAAuthChallenge* from_json(rapidjson::Value* json);

    /// Getters and Setters
    std::string get_response()
    {
      return _response;
    }

    void set_response(const std::string& response)
    {
      _updated = true;
      _response = response;
    }

  private:
    /// Constructor.
    AKAAuthChallenge() :
      AuthChallenge(AuthChallenge::Type::AKA),
      _response() {};

    /// AKA expected response
    std::string _response;

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
    Impi(const std::string& _impi) : impi(_impi), auth_challenges() {};

    /// Destructor.
    virtual ~Impi();

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

    /// Get the expiry time for the whole IMPI object.
    /// @returns the expiry time.
    int get_expires();

    // The IMPI store is a friend so it can read our CAS value.
    friend class ImpiStore;
  };

  /// Destructor.
  virtual ~ImpiStore();

  /// Store the specified IMPI in the store.
  /// @returns Store::Status::OK on success, or an error code on failure.
  /// @param impi      An Impi object representing the IMPI.  The caller
  ///                  continues to own this object.
  virtual Store::Status set_impi(Impi* impi,
                                 SAS::TrailId trail) = 0;

  /// Retrieves the IMPI for the specified private user identity.
  ///
  /// @returns         A pointer to an Impi object describing the IMPI. The
  ///                  caller owns the returned object. This method only returns
  ///                  NULL if the underlying store failed - if no IMPI was
  ///                  found it returns an empty object.
  /// @param impi                 The private user identity.
  /// @param include_expired      Whether to include expired challenges.
  virtual Impi* get_impi(const std::string& impi,
                         SAS::TrailId trail,
                         bool include_expired = false) = 0;

  /// Delete all record of the IMPI.
  ///
  /// @param impi      An Impi object representing the IMPI.  The caller
  ///                  continues to own this object.
  /// @returns Store::Status::OK on success, or an error code on failure.
  virtual Store::Status delete_impi(Impi* impi,
                                    SAS::TrailId trail) = 0;

protected:
  static rapidjson::Document* json_from_string(const std::string& string);
};

// Utility function - retrieves the "corrlator" field from the given challenge
// and raises a correlating transaction marker in the given trail.
void correlate_trail_to_challenge(ImpiStore::AuthChallenge* auth_challenge,
                                  SAS::TrailId trail);

#endif
