/**
 * @file subscriber_data_manager.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef SUBSCRIBER_DATA_MANAGER_H__
#define SUBSCRIBER_DATA_MANAGER_H__

extern "C" {
#include <pj/pool.h>
#include <pjsip.h>
}

#include <string>
#include <list>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "store.h"
#include "chronosconnection.h"
#include "sas.h"
#include "analyticslogger.h"
#include "associated_uris.h"
#include "rapidjson/writer.h"
#include "rapidjson/document.h"

// We need to declare the parts of NotifyUtils needed below to avoid a
// circular dependency between this and notify_utils.h
namespace NotifyUtils { struct BindingNotifyInformation; };

typedef NotifyUtils::BindingNotifyInformation ClassifiedBinding;
typedef std::vector<ClassifiedBinding*> ClassifiedBindings;

class SubscriberDataManager
{
public:
  /// @class SubscriberDataManager::AoR
  ///
  /// Addresses that are registered for this address of record.
  class AoR
  {
  public:
    /// @class SubscriberDataManager::AoR::Binding
    ///
    /// A single registered address.
    class Binding
    {
    public:
      Binding(std::string address_of_record): _address_of_record(address_of_record) {};

      /// The address of record, e.g. "sip:name@example.com".
      std::string _address_of_record;

      /// The registered contact URI, e.g.,
      /// "sip:2125551212@192.168.0.1:55491;transport=TCP;rinstance=fad34fbcdea6a931"
      std::string _uri;

      /// The Call-ID: of the registration.  Per RFC3261, this is the same for
      /// all registrations from a given UAC to this registrar (for this AoR).
      /// E.g., "gfYHoZGaFaRNxhlV0WIwoS-f91NoJ2gq"
      std::string _cid;

      /// Contains any path headers (in order) that were present on the
      /// register.  Empty if there were none. This is the full path header,
      /// including the disply name, URI and any header parameters.
      std::list<std::string> _path_headers;

      /// Contains the URI part of any path headers (in order) that were
      /// present on the register. Empty if there were none.
      std::list<std::string> _path_uris;

      /// The CSeq value of the REGISTER request.
      int _cseq;

      /// The time (in seconds since the epoch) at which this binding should
      /// expire.  Based on the expires parameter of the Contact: header.
      int _expires;

      /// The Contact: header q parameter (qvalue), times 1000.  This is used
      /// to prioritise the registrations (highest value first), per RFC3261
      /// s10.2.1.2.
      int _priority;

      /// Any other parameters found in the Contact: header, stored as key ->
      /// value.  E.g., "+sip.ice" -> "".
      std::map<std::string, std::string> _params;

      /// The timer ID provided by Chronos.
      std::string _timer_id;

      /// The private ID this binding was registered with.
      std::string _private_id;

      /// Whether this is an emergency registration.
      bool _emergency_registration;

      pjsip_sip_uri* pub_gruu(pj_pool_t* pool) const;
      std::string pub_gruu_str(pj_pool_t* pool) const;
      std::string pub_gruu_quoted_string(pj_pool_t* pool) const;

      /// Serialize the binding as a JSON object.
      ///
      /// @param writer - a rapidjson writer to write to.
      void to_json(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;

      // Deserialize a binding from a JSON object.
      //
      // @param b_obj - The binding as a JSON object.
      //
      // @return      - Nothing. If this function fails (because the JSON is not
      //                semantically valid) this method throws JsonFormError.
      void from_json(const rapidjson::Value& b_obj);
    };

    /// @class SubscriberDataManager::AoR::Subscription
    ///
    /// Represents a subscription to registration events for the AoR.
    class Subscription
    {
    public:
      Subscription(): _refreshed(false) {};

      /// The Contact URI for the subscription dialog (used as the Request URI
      /// of the NOTIFY)
      std::string _req_uri;

      /// The From URI for the subscription dialog (used in the to header of
      /// the NOTIFY)
      std::string _from_uri;

      /// The From tag for the subscription dialog.
      std::string _from_tag;

      /// The To URI for the subscription dialog.
      std::string _to_uri;

      /// The To tag for the subscription dialog.
      std::string _to_tag;

      /// The call ID for the subscription dialog.
      std::string _cid;

      /// Whether the subscription has been refreshed since the last NOTIFY.
      bool _refreshed;

      /// The list of Record Route URIs from the subscription dialog.
      std::list<std::string> _route_uris;

      /// The time (in seconds since the epoch) at which this subscription
      /// should expire.
      int _expires;

      /// The timer ID provided by Chronos.
      std::string _timer_id;

      /// Serialize the subscription as a JSON object.
      ///
      /// @param writer - a rapidjson writer to write to.
      void to_json(rapidjson::Writer<rapidjson::StringBuffer>& writer) const;

      // Deserialize a subscription from a JSON object.
      //
      // @param s_obj - The subscription as a JSON object.
      //
      // @return      - Nothing. If this function fails (because the JSON is not
      //                semantically valid) this method throws JsonFormError.
      void from_json(const rapidjson::Value& s_obj);
   };

    /// Default Constructor.
    AoR(std::string sip_uri);

    /// Destructor.
    ~AoR();

    /// Make sure copy is deep!
    AoR(const AoR& other);

    // Make sure assignment is deep!
    AoR& operator= (AoR const& other);

    // Common code between copy and assignment
    void common_constructor(const AoR& other);

    /// Clear all the bindings and subscriptions from this object.
    void clear(bool clear_emergency_bindings);

    /// Retrieve a binding by Binding ID, creating an empty one if necessary.
    /// The created binding is completely empty, even the Contact URI field.
    Binding* get_binding(const std::string& binding_id);

    /// Removes any binding that had the given ID.  If there is no such binding,
    /// does nothing.
    void remove_binding(const std::string& binding_id);

    /// Retrieve a subscription by To tag, creating an empty one if necessary.
    Subscription* get_subscription(const std::string& to_tag);

    /// Remove a subscription for the specified To tag.  If there is no
    /// corresponding subscription does nothing.
    void remove_subscription(const std::string& to_tag);

    // Remove the bindings from an AOR object
    void clear_bindings();

    /// Binding ID -> Binding.  First is sometimes the contact URI, but not always.
    /// Second is a pointer to an object owned by this object.
    typedef std::map<std::string, Binding*> Bindings;

    /// To tag -> Subscription.
    typedef std::map<std::string, Subscription*> Subscriptions;

    /// Retrieve all the bindings.
    inline const Bindings& bindings() const { return _bindings; }

    /// Retrieve all the subscriptions.
    inline const Subscriptions& subscriptions() const { return _subscriptions; }

    // Return the number of bindings in the AoR.
    inline uint32_t get_bindings_count() const { return _bindings.size(); }

    // Return the number of subscriptions in the AoR.
    inline uint32_t get_subscriptions_count() const { return _subscriptions.size(); }

    // Return the expiry time of the binding or subscription due to expire next.
    int get_next_expires();

    /// Copy all bindings and subscriptions to this AoR
    ///
    /// @param source_aor           Source AoR for the copy
    void copy_subscriptions_and_bindings(SubscriberDataManager::AoR* source_aor);

    /// CSeq value for event notifications for this AoR.  This is initialised
    /// to one when the AoR record is first set up and incremented every time
    /// the record is updated while there are active subscriptions.  (It is
    /// sufficient to use the same CSeq for each NOTIFY sent on each active
    /// because there is no requirement that the first NOTIFY in a dialog has
    /// CSeq=1, and once a subscription dialog is established it should
    /// receive every NOTIFY for the AoR.)
    int _notify_cseq;

    // Chronos Timer ID
    std::string _timer_id;

  private:
    /// Map holding the bindings for a particular AoR indexed by binding ID.
    Bindings _bindings;

    /// Map holding the subscriptions for this AoR, indexed by the To tag
    /// generated when the subscription dialog was established.
    Subscriptions _subscriptions;

    /// CAS value for this AoR record.  Used when updating an existing record.
    /// Zero for a new record that has not yet been written to a store.
    uint64_t _cas;

    // SIP URI for this AoR
    std::string _uri;

    /// Store code is allowed to manipulate bindings and subscriptions directly.
    friend class SubscriberDataManager;
  };

  /// @class SubscriberDataManager::AoRPair
  ///
  /// Class to hold a pair of AoRs. The original AoR holds the AoR retrieved
  /// from the store, the current AoR holds any changes made to the AoR before
  /// it's put back in the store
  class AoRPair
  {
  public:
    AoRPair(AoR* orig_aor, AoR* current_aor):
      _orig_aor(orig_aor),
      _current_aor(current_aor)
    {}

    ~AoRPair()
    {
      delete _orig_aor; _orig_aor = NULL;
      delete _current_aor; _current_aor = NULL;
    }

    /// Get the current AoR
    AoR* get_current() { return _current_aor; }

    /// Does the current AoR contain any bindings?
    bool current_contains_bindings()
    {
      return ((_current_aor != NULL) &&
              (!_current_aor->_bindings.empty()));
    }

    /// Does the current AoR contain any subscriptions?
    bool current_contains_subscriptions()
    {
      return ((_current_aor != NULL) &&
              (!_current_aor->subscriptions().empty()));
    }

  private:
    AoR* _orig_aor;
    AoR* _current_aor;

    /// Get the original AoR
    AoR* get_orig() { return _orig_aor; }

    /// The subscriber data manager is allowed to access the original AoR
    friend class SubscriberDataManager;
  };

  /// Interface used by the SubscriberDataManager to serialize AoRs from C++ objects to the
  /// format used in the store, and deserialize them.
  ///
  /// This interface allows multiple (de)serializers to be defined and for the
  /// SubscriberDataManager to use them in a pluggable fashion.
  class SerializerDeserializer
  {
  public:
    /// Virtual destructor.
    virtual ~SerializerDeserializer() {};

    /// Serialize an AoR object to the format used in the store.
    ///
    /// @param aor_data - The AoR object to serialize.
    /// @return         - The serialized form.
    virtual std::string serialize_aor(AoR* aor_data) = 0;

    /// Deserialize some data from the store into an AoR object.
    ///
    /// @param aor_id - The primary public ID for the AoR. This is also the key
    ///                 used used for the record in the store.
    /// @param s      - The data to deserialize.
    ///
    /// @return       - An AoR object, or NULL if the data could not be
    ///                 deserialized (e.g. because it is corrupt).
    virtual AoR* deserialize_aor(const std::string& aor_id,
                                 const std::string& s) = 0;

    /// @return the name of this (de)serializer.
    virtual std::string name() = 0;
  };

  /// A (de)serializer for the (deprecated) custom binary format.
  class BinarySerializerDeserializer : public SerializerDeserializer
  {
  public:
    ~BinarySerializerDeserializer() {}

    std::string serialize_aor(AoR* aor_data);
    AoR* deserialize_aor(const std::string& aor_id,
                         const std::string& s);
    std::string name();
  };

  /// A (de)serializer for the JSON format.
  class JsonSerializerDeserializer : public SerializerDeserializer
  {
  public:
    ~JsonSerializerDeserializer() {}

    std::string serialize_aor(AoR* aor_data);
    AoR* deserialize_aor(const std::string& aor_id,
                         const std::string& s);
    std::string name();
  };

  /// Provides the interface to the data store. This is responsible for
  /// updating and getting information from the underlying data store. The
  /// classes that call this class are responsible for retrying the get/set
  /// functions in case of failure.
  class Connector
  {
    Connector(Store* data_store,
              SerializerDeserializer*& serializer,
              std::vector<SerializerDeserializer*>& deserializers);

    ~Connector();

    AoR* get_aor_data(const std::string& aor_id, SAS::TrailId trail);

    Store::Status set_aor_data(const std::string& aor_id,
                               AoR* aor_data,
                               int expiry,
                               SAS::TrailId trail);

    std::string serialize_aor(AoR* aor_data);
    AoR* deserialize_aor(const std::string& aor_id, const std::string& s);

    bool underlying_store_has_servers() { return (_data_store != NULL) && _data_store->has_servers(); }

    Store* _data_store;

    /// SubscriberDataManager is the only class that can use Connector
    friend class SubscriberDataManager;

  private:
    SerializerDeserializer* _serializer;
    std::vector<SerializerDeserializer*> _deserializers;
  };

  /// @class SubscriberDataManager::ChronosTimerRequestSender
  ///
  /// Class responsible for sending any requests to Chronos about
  /// registration/subscription expiry
  ///
  /// @param chronos_conn    The underlying chronos connection
  class ChronosTimerRequestSender
  {
  public:
    ChronosTimerRequestSender(ChronosConnection* chronos_conn);

    virtual ~ChronosTimerRequestSender();

    /// Create and send any appropriate Chronos requests
    ///
    /// @param aor_id       The AoR ID
    /// @param aor_pair     The AoR pair to send Chronos requests for
    /// @param now          The current time
    /// @param trail        SAS trail
    virtual void send_timers(const std::string& aor_id,
                             AoRPair* aor_pair,
                             int now,
                             SAS::TrailId trail);

    /// SubscriberDataManager is the only class that can use
    /// ChronosTimerRequestSender
    friend class SubscriberDataManager;

  private:
    ChronosConnection* _chronos_conn;

    /// Build the tag info map from an AoR
    virtual void build_tag_info(AoR* aor,
                                std::map<std::string, uint32_t>& tag_map);

    /// Create the Chronos Timer request
    ///
    /// @param aor_id       The AoR ID
    /// @param timer_id     The Timer ID
    /// @param expiry       Timer length
    /// @param tags         Any tags to add to the Chronos timer
    /// @param trail        SAS trail
    virtual void set_timer(const std::string& aor_id,
                           std::string& timer_id,
                           int expiry,
                           std::map<std::string, uint32_t> tags,
                           SAS::TrailId trail);
  };

  /// @class SubscriberDataManager::NotifySender
  ///
  /// Class responsible for sending any NOTIFYs about registration state
  /// change
  class NotifySender
  {
  public:
    NotifySender();

    virtual ~NotifySender();

    /// Create and send any appropriate NOTIFYs
    ///
    /// @param aor_id       The AoR ID
    /// @param associated_uris
    ///                     The IMPUs associated with this IRS
    /// @param aor_pair     The AoR pair to send NOTIFYs for
    /// @param now          The current time
    /// @param trail        SAS trail
    void send_notifys(const std::string& aor_id,
                      AssociatedURIs* associated_uris,
                      AoRPair* aor_pair,
                      int now,
                      SAS::TrailId trail);

    /// SubscriberDataManager is the only class that can use NotifySender
    friend class SubscriberDataManager;

  private:
    // Create and send any appropriate NOTIFYs for any expired subscriptions
    //
    // @param aor_id       The AoR ID
    // @param associated_uris
    //                     The IMPUs associated with this IRS
    // @param aor_pair     The AoR pair to send NOTIFYs for
    // @param binding_info_to_notify
    //                     The list of bindings to include on the NOTIFY
    // @param expired_binding_uris
    //                     A list of URIs of expired bindings    
    // @param now          The current time
    // @param trail        SAS trail
    void send_notifys_for_expired_subscriptions(
                                   const std::string& aor_id,
                                   AssociatedURIs* associated_uris,
                                   SubscriberDataManager::AoRPair* aor_pair,
                                   ClassifiedBindings binding_info_to_notify,
                                   std::vector<std::string> expired_binding_uris,                                  
                                   int now,
                                   SAS::TrailId trail);
  };

  /// Tags to use when setting timers for nothing, for registration and for subscription.
  static const std::vector<std::string> TAGS_NONE;
  static const std::vector<std::string> TAGS_REG;
  static const std::vector<std::string> TAGS_SUB;

  /// SubscriberDataManager constructor that allows the user to specify which serializer and
  /// deserializers to use.
  ///
  /// @param data_store         - Pointer to the underlying data store.
  /// @param serializer         - The serializer to use when writing records.
  ///                             The SubscriberDataManager takes ownership of it.
  /// @param deserializer       - A vector of deserializers to when reading
  ///                             records. The order of this vector is
  ///                             important - each deserializer is
  ///                             tried in turn until one successfully parses
  ///                             the record. The SubscriberDataManager takes ownership of
  ///                             the entries in the vector.
  /// @param chronos_connection - Chronos connection used to set timers for
  ///                             expiring registrations and subscriptions.
  /// @param analytics_logger   - AnalyticsLogger for reporting registration events.
  /// @param is_primary         - Whether the underlying data store is the local
  ///                             store or remote.
  SubscriberDataManager(Store* data_store,
                        SerializerDeserializer*& serializer,
                        std::vector<SerializerDeserializer*>& deserializers,
                        ChronosConnection* chronos_connection,
                        AnalyticsLogger* analytics_logger,
                        bool is_primary);

  /// Alternative SubscriberDataManager constructor that creates a SubscriberDataManager using just the
  /// default (de)serializer.
  ///
  /// @param data_store         - Pointer to the underlying data store.
  /// @param chronos_connection - Chronos connection used to set timers for
  ///                             expiring registrations and subscriptions.
  /// @param is_primary         - Whether the underlying data store is the local
  ///                             store or remote
  SubscriberDataManager(Store* data_store,
                        ChronosConnection* chronos_connection,
                        bool is_primary);

  /// Destructor.
  virtual ~SubscriberDataManager();

  virtual bool has_servers() { return _connector->underlying_store_has_servers(); }

  /// Get the data for a particular address of record (registered SIP URI,
  /// in format "sip:2125551212@example.com"), creating creating it if
  /// necessary.  May return NULL in case of error.  Result is owned
  /// by caller and must be freed with delete.
  ///
  /// @param aor_id    The AoR to retrieve
  /// @param trail     SAS trail
  virtual AoRPair* get_aor_data(const std::string& aor_id,
                                SAS::TrailId trail);

  /// Update the data for a particular address of record.  Writes the data
  /// atomically. If the underlying data has changed since it was last
  /// read, the update is rejected and this returns false; if the update
  /// succeeds, this returns true.
  ///
  /// @param aor_id               The AoR to retrieve
  /// @param associated_uris      The IMPUs associated with this IRS
  /// @param aor_pair             The AoR pair to set
  /// @param trail                SAS trail
  /// @param all_bindings_expired Whether all bindings have expired
  ///                             as a result of the set
  virtual Store::Status set_aor_data(const std::string& aor_id,
                                     AssociatedURIs* associated_uris,
                                     AoRPair* aor_pair,
                                     SAS::TrailId trail,
                                     bool& all_bindings_expired = unused_bool);

private:
  // Expire any out of date bindings in the current AoR
  //
  // @param aor_pair  The AoRPair to expire
  // @param now       The current time
  // @param trail     SAS trail
  int expire_aor_members(AoRPair* aor_pair,
                         int now,
                         SAS::TrailId trail);

  // Expire any old bindings, and return the maximum expiry
  //
  // @param aor_pair  The AoRPair to expire
  // @param now       The current time
  // @param trail     SAS trail
  int expire_bindings(AoR* aor_data,
                      int now,
                      SAS::TrailId trail);

  // Expire any old subscriptions.
  //
  // @param aor_pair      The AoRPair to expire
  // @param now           The current time
  // @param force_expires Whether all subscriptions should be expired
  //                      no matter the current time
  // @param trail         SAS trail
  void expire_subscriptions(AoRPair* aor_pair,
                            int now,
                            bool force_expire,
                            SAS::TrailId trail);

  // Iterate over all original and current bindings in an AoR pair and
  // classify them as removed ("EXPIRED"), created ("CREATED"), refreshed ("REFRESHED"),
  // shortened ("SHORTENED") or unchanged ("REGISTERED").
  //
  // @param aor_id                The AoR ID
  // @param aor_pair              The AoR pair to compare and classify bindings for
  // @param classified_bindings   Output vector of classified bindings
  void classify_bindings(const std::string& aor_id,
                         SubscriberDataManager::AoRPair* aor_pair,
                         ClassifiedBindings& classified_bindings);

  // Iterate over a list of classified bindings, and emit registration logs for those
  // that are EXPIRED or SHORTENED.
  void log_removed_or_shortened_bindings(ClassifiedBindings& classified_bindings,
                                         int now);

  // Iterate over a list of classified bindings, and emit registration logs for those
  // that are CREATED or REFRESHED.
  void log_new_or_extended_bindings(ClassifiedBindings& classified_bindings,
                                    int now);

  static bool unused_bool;
  AnalyticsLogger* _analytics;
  Connector* _connector;
  ChronosTimerRequestSender* _chronos_timer_request_sender;
  NotifySender* _notify_sender;
  bool _primary_sdm;
};


#endif
