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

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "aor.h"
#include "handlers.h"
#include "log.h"
#include "subscriber_data_manager.h"
#include "ifchandler.h"
#include "registration_utils.h"
#include "stack.h"
#include "pjutils.h"
#include "sproutsasevent.h"
#include "uri_classifier.h"
#include "sprout_xml_utils.h"

static AoRPair* get_and_set_local_aor_data(
                          SubscriberDataManager* current_sdm,
                          std::string aor_id,
                          const SubscriberDataManager::EventTrigger& event_trigger,
                          AssociatedURIs* associated_uris,
                          AoRPair* previous_aor_pair,
                          std::vector<SubscriberDataManager*> remote_sdms,
                          bool& all_bindings_expired,
                          SAS::TrailId trail)
{
  AoRPair* aor_pair = NULL;
  Store::Status set_rc;

  do
  {
    if (!RegistrationUtils::get_aor_data(&aor_pair,
                                         aor_id,
                                         current_sdm,
                                         remote_sdms,
                                         previous_aor_pair,
                                         trail))
    {
      break;
    }

    aor_pair->get_current()->_associated_uris = *associated_uris;

    set_rc = current_sdm->set_aor_data(aor_id,
                                       event_trigger,
                                       aor_pair,
                                       trail,
                                       all_bindings_expired);
    if (set_rc != Store::OK)
    {
      delete aor_pair; aor_pair = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  return aor_pair;
}

static void set_remote_aor_data(std::string aor_id,
                                const SubscriberDataManager::EventTrigger& event_trigger,
                                AssociatedURIs* associated_uris,
                                AoRPair* previous_aor_pair,
                                std::vector<SubscriberDataManager*> remote_sdms,
                                HSSConnection* hss,
                                SAS::TrailId trail)
{
  bool ignored = false;

  // If we have any remote stores, try to store this in them too.  We don't worry
  // about failures in this case.
  for (SubscriberDataManager* sdm : remote_sdms)
  {
    if (sdm->has_servers())
    {
      AoRPair* remote_aor_pair = get_and_set_local_aor_data(sdm,
                                                            aor_id,
                                                            event_trigger,
                                                            associated_uris,
                                                            previous_aor_pair,
                                                            {},
                                                            ignored,
                                                            trail);
      delete remote_aor_pair;
    }
  }
}

static void update_hss_on_aor_expiry(const std::string& aor_id,
                                     AoRPair& aor_pair,
                                     HSSConnection* hss,
                                     SAS::TrailId trail)
{
  // No bindings left - inform the HSS
  TRC_DEBUG("All bindings have expired - triggering deregistration at the HSS");

  SAS::Event event(trail, SASEvent::REGISTRATION_EXPIRED, 0);
  event.add_var_param(aor_id);
  SAS::report_event(event);

  // Get the S-CSCF URI off the AoR to put on the SAR.
  AoR* aor = aor_pair.get_current();

  HSSConnection::irs_query irs_query;
  irs_query._public_id = aor_id;
  irs_query._req_type = HSSConnection::DEREG_TIMEOUT;
  irs_query._server_name = aor->_scscf_uri;

  HSSConnection::irs_info unused_irs_info;

  hss->update_registration_state(irs_query,
                                 unused_irs_info,
                                 trail);
}

static bool get_reg_data(HSSConnection* hss,
                         const std::string& aor_id,
                         HSSConnection::irs_info& irs_info,
                         SAS::TrailId trail)
{
  HTTPCode http_code = hss->get_registration_data(aor_id,
                                                  irs_info,
                                                  trail);

  if ((http_code != HTTP_OK) || irs_info._associated_uris.get_unbarred_uris().empty())
  {
    // We were unable to determine the set of IMPUs for this AoR. Push the AoR
    // we have into the Associated URIs list so that we have at least one IMPU
    // we can issue NOTIFYs for. We should only do this if that IMPU is not barred.
    TRC_WARNING("Unable to get Implicit Registration Set for %s: %d", aor_id.c_str(), http_code);
    if (!irs_info._associated_uris.is_impu_barred(aor_id))
    {
      irs_info._associated_uris.clear_uris();
      irs_info._associated_uris.add_uri(aor_id, false);
    }
  }

  return (http_code == HTTP_OK);
}

static void report_sip_all_register_marker(SAS::TrailId trail, std::string uri_str)
{
  // Parse the SIP URI and get the username from it.
  pj_pool_t* tmp_pool = pj_pool_create(&stack_data.cp.factory, "handlers", 1024, 512, NULL);
  pjsip_uri* uri = PJUtils::uri_from_string(uri_str, tmp_pool);

  if (uri != NULL)
  {
    pj_str_t user = PJUtils::user_from_uri(uri);

    // Create and report the marker.
    SAS::Marker sip_all_register(trail, MARKER_ID_SIP_ALL_REGISTER, 1u);
    sip_all_register.add_var_param(Utils::strip_uri_scheme(uri_str));
    // Add the DN parameter. If the user part is not numeric just log it in
    // its entirety.
    sip_all_register.add_var_param(URIClassifier::is_user_numeric(user) ?
                                   PJUtils::remove_visual_separators(user) :
                                   PJUtils::pj_str_to_string(&user));
    SAS::report_marker(sip_all_register);
  }
  else
  {
    TRC_WARNING("Could not raise SAS REGISTER marker for unparseable URI '%s'", uri_str.c_str());
  }

  // Remember to release the temporary pool.
  pj_pool_release(tmp_pool);
}

void DeregistrationTask::run()
{
  // HTTP method must be a DELETE
  if (_req.method() != htp_method_DELETE)
  {
    TRC_WARNING("HTTP method isn't delete");
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  // Parse the JSON body
  HTTPCode rc = parse_request(_req.get_rx_body());

  if (rc != HTTP_OK)
  {
    TRC_WARNING("Request body is invalid, send %d", rc);
    send_http_reply(rc);
    delete this;
    return;
  }

  SAS::Marker start_marker(trail(), MARKER_ID_START, 2u);
  SAS::report_marker(start_marker);

  rc = handle_request();

  SAS::Marker end_marker(trail(), MARKER_ID_END, 2u);
  SAS::report_marker(end_marker);

  send_http_reply(rc);
  delete this;
}

void AoRTimeoutTask::process_aor_timeout(std::string aor_id)
{
  TRC_DEBUG("Handling timer pop for AoR id: %s", aor_id.c_str());

  // Determine the set of IMPUs in the Implicit Registration Set
  HSSConnection::irs_info irs_info;
  bool got_ifcs = get_reg_data(_cfg->_hss, aor_id, irs_info, trail());

  bool all_bindings_expired = false;
  AoRPair* aor_pair = get_and_set_local_aor_data(_cfg->_sdm,
                                                 aor_id,
                                                 SubscriberDataManager::EventTrigger::TIMEOUT,
                                                 &(irs_info._associated_uris),
                                                 NULL,
                                                 _cfg->_remote_sdms,
                                                 all_bindings_expired,
                                                 trail());

  if (aor_pair != NULL)
  {
    set_remote_aor_data(aor_id,
                        SubscriberDataManager::EventTrigger::TIMEOUT,
                        &(irs_info._associated_uris),
                        aor_pair,
                        _cfg->_remote_sdms,
                        _cfg->_hss,
                        trail());

    if (all_bindings_expired)
    {
      update_hss_on_aor_expiry(aor_id,
                               *aor_pair,
                               _cfg->_hss,
                               trail());

      if (got_ifcs)
      {
        RegistrationUtils::deregister_with_application_servers(irs_info._service_profiles[aor_id],
                                                               _cfg->_fifc_service,
                                                               _cfg->_ifc_configuration,
                                                               _cfg->_sdm,
                                                               _cfg->_remote_sdms,
                                                               _cfg->_hss,
                                                               aor_id,
                                                               trail());
      }
    }
  }
  else
  {
    // We couldn't update the SubscriberDataManager but there is nothing else we can do to
    // recover from this.
    TRC_INFO("Could not update SubscriberDataManager on registration timeout for AoR: %s",
             aor_id.c_str());
  }

  delete aor_pair;
  report_sip_all_register_marker(trail(), aor_id);
}

HTTPCode DeregistrationTask::parse_request(std::string body)
{
  rapidjson::Document doc;
  doc.Parse<0>(body.c_str());

  if (doc.HasParseError())
  {
    TRC_INFO("Failed to parse data as JSON: %s\nError: %s",
             body.c_str(),
             rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_ASSERT_CONTAINS(doc, "registrations");
    JSON_ASSERT_ARRAY(doc["registrations"]);
    const rapidjson::Value& reg_arr = doc["registrations"];

    for (rapidjson::Value::ConstValueIterator reg_it = reg_arr.Begin();
         reg_it != reg_arr.End();
         ++reg_it)
    {
      try
      {
        std::string primary_impu;
        std::string impi = "";
        JSON_GET_STRING_MEMBER(*reg_it, "primary-impu", primary_impu);

        if (((*reg_it).HasMember("impi")) &&
            ((*reg_it)["impi"].IsString()))
        {
          impi = (*reg_it)["impi"].GetString();
        }

        _bindings.insert(std::make_pair(primary_impu, impi));
      }
      catch (JsonFormatError err)
      {
        TRC_WARNING("Invalid JSON - registration doesn't contain primary-impu");
        return HTTP_BAD_REQUEST;
      }
    }
  }
  catch (JsonFormatError err)
  {
    TRC_INFO("Registrations not available in JSON");
    return HTTP_BAD_REQUEST;
  }

  TRC_DEBUG("HTTP request successfully parsed");
  return HTTP_OK;
}

HTTPCode DeregistrationTask::handle_request()
{
  HTTPCode rc = HTTP_OK;
  std::set<std::string> impis_to_delete;

  for (std::pair<std::string, std::string> binding : _bindings)
  {
    rc = deregister_bindings(binding.first,
                             binding.second,
                             impis_to_delete);

  }

  // Delete IMPIs from the store.
  for(std::set<std::string>::iterator impi = impis_to_delete.begin();
      impi != impis_to_delete.end();
      ++impi)
  {
    TRC_DEBUG("Delete %s from the IMPI store(s)", impi->c_str());

    delete_impi_from_store(_cfg->_local_impi_store, *impi);
    for (ImpiStore* store: _cfg->_remote_impi_stores)
    {
      delete_impi_from_store(store, *impi);
    }
  }

  return rc;
}

void DeregistrationTask::delete_impi_from_store(ImpiStore* store,
                                                const std::string& impi)
{
  Store::Status store_rc = Store::OK;
  ImpiStore::Impi* impi_obj = NULL;

  do
  {
    // Free any IMPI we had from the last loop iteration.
    delete impi_obj; impi_obj = NULL;

    impi_obj = store->get_impi(impi, _trail);

    if (impi_obj != NULL)
    {
      store_rc = store->delete_impi(impi_obj, _trail);
    }
  }
  while ((impi_obj != NULL) && (store_rc == Store::DATA_CONTENTION));

  delete impi_obj; impi_obj = NULL;
}


HTTPCode DeregistrationTask::deregister_bindings(
                                         std::string aor_id,
                                         std::string private_id,
                                         std::set<std::string>& impis_to_delete)
{
  Bindings bindings;

  HTTPCode rc = _cfg->_sm->get_bindings(aor_id,
                                        bindings,
                                        trail());
  if (rc != HTTP_OK)
  {
    return rc;
  }

  std::vector<std::string> binding_ids;

  for (BindingPair binding : bindings)
  {
    if (private_id.empty() || private_id == binding.second->_private_id)
    {
      if (!binding.second->_private_id.empty())
      {
        // Record the IMPIs that we need to delete as a result of deleting
        // this binding.
        impis_to_delete.insert(binding.second->_private_id);
      }

      binding_ids.push_back(binding.second->get_id());
    }
  }

  Bindings unused_bindings;
  return _cfg->_sm->remove_bindings(aor_id,
                                    binding_ids,
                                    SubscriberManager::EventTrigger::ADMIN,
                                    unused_bindings,
                                    trail());
}

HTTPCode AuthTimeoutTask::timeout_auth_challenge(std::string impu,
                                                 std::string impi,
                                                 std::string nonce)
{
  // Locate the challenge that this timer refers to, to check if the user
  // authenticated against it. If it didn't, we will need to send an
  // AUTHENTICATION_TIMEOUT SAR.
  //
  // Note that we don't bother checking any of the remote IMPI stores if we
  // don't find a record in the local store. This suggests that the IMPI record
  // didn't get replicated to this site but the timer did, which is
  // quite a weird situation to be in. If we do hit it, we'll return a 500
  // response to the timer service which will eventually cause it to retry in a different
  // site, which will hopefully have the data.

  report_sip_all_register_marker(trail(), impu);

  bool success = false;

  // We ask the ImpiStore to return expired challenges here, so that we'll still
  // get the challenge if the timer has popped after the challenge has expired
  ImpiStore::Impi* impi_obj = _cfg->_local_impi_store->get_impi(impi, trail(), true);
  ImpiStore::AuthChallenge* auth_challenge = NULL;

  if (impi_obj != NULL)
  {
    auth_challenge = impi_obj->get_auth_challenge(nonce);
  }

  if (auth_challenge != NULL)
  {
    // Use the original REGISTER's branch parameter for SAS
    // correlation
    correlate_trail_to_challenge(auth_challenge, trail());

    // If authentication completed, we'll have incremented the nonce count.
    // If not, authentication has timed out.
    if (auth_challenge->get_nonce_count() == ImpiStore::AuthChallenge::INITIAL_NONCE_COUNT)
    {
      TRC_DEBUG("AV for %s:%s has timed out", impi.c_str(), nonce.c_str());

      // The AUTHENTICATION_TIMEOUT SAR is idempotent, so there's no
      // problem if the timer pops twice (e.g. if we have high
      // latency and these operations take more than 2 seconds).

      // If either of these operations fail, we return a 500 Internal
      // Server Error - this will trigger the timer service to try a different
      // Sprout, which may have better connectivity to Homestead or Memcached.
      HSSConnection::irs_query irs_query;
      irs_query._public_id = impu;
      irs_query._private_id = impi;
      irs_query._req_type = HSSConnection::AUTH_TIMEOUT;
      irs_query._server_name = auth_challenge->get_scscf_uri();
      HSSConnection::irs_info unused_irs_info;

      HTTPCode hss_query = _cfg->_hss->update_registration_state(irs_query,
                                                                 unused_irs_info,
                                                                 trail());

      if (hss_query == HTTP_OK)
      {
        success = true;
      }
    }
    else
    {
      SAS::Event event(trail(), SASEvent::AUTHENTICATION_TIMER_POP_IGNORED, 0);
      SAS::report_event(event);
      TRC_DEBUG("Tombstone record indicates Authentication Vector has been used successfully - ignoring timer pop");
      success = true;
    }
  }
  else
  {
    SAS::Event event(trail(), SASEvent::AUTHENTICATION_TIMER_POP_AV_NOT_FOUND, 0);
    SAS::report_event(event);
    TRC_WARNING("Could not find AV for %s:%s when checking authentication timeout", impi.c_str(), nonce.c_str());
  }
  delete impi_obj;

  return success ? HTTP_OK : HTTP_SERVER_ERROR;
}

// Get cached bindings.
void GetBindingsTask::run()
{
  // This interface is read only so reject any non-GETs.
  if (_req.method() != htp_method_GET)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  SAS::Marker start_marker(trail(), MARKER_ID_START, 3u);
  SAS::report_marker(start_marker);

  // Extract the IMPU that has been requested. The URL is of the form
  //   /impu/<public ID>/<element>
  // When <element> is either "bindings" or "subscriptions"
  const std::string prefix = "/impu/";
  std::string full_path = _req.full_path();
  size_t end_of_impu = full_path.find('/', prefix.length());
  std::string impu = full_path.substr(prefix.length(), end_of_impu - prefix.length());
  TRC_DEBUG("Extracted impu %s", impu.c_str());

  Bindings bindings;
  HTTPCode rc = _cfg->_sm->get_bindings(impu, bindings, trail());
  std::string content = serialize_data(bindings);
  _req.add_content(content);

  send_http_reply(rc);

  for (BindingPair b : bindings)
  {
    delete b.second; b.second = NULL;
  }

  SAS::Marker end_marker(trail(), MARKER_ID_END, 3u);
  SAS::report_marker(end_marker);

  delete this;
  return;
}

// Get cached subscriptions.
void GetSubscriptionsTask::run()
{
  // This interface is read only so reject any non-GETs.
  if (_req.method() != htp_method_GET)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  SAS::Marker start_marker(trail(), MARKER_ID_START, 3u);
  SAS::report_marker(start_marker);

  // Extract the IMPU that has been requested. The URL is of the form
  //   /impu/<public ID>/<element>
  // When <element> is either "bindings" or "subscriptions"
  const std::string prefix = "/impu/";
  std::string full_path = _req.full_path();
  size_t end_of_impu = full_path.find('/', prefix.length());
  std::string impu = full_path.substr(prefix.length(), end_of_impu - prefix.length());
  TRC_DEBUG("Extracted impu %s", impu.c_str());

  Subscriptions subscriptions;
  HTTPCode rc = _cfg->_sm->get_subscriptions(impu, subscriptions, trail());
  std::string content = serialize_data(subscriptions);
  _req.add_content(content);

  send_http_reply(rc);

  for (SubscriptionPair s : subscriptions)
  {
    delete s.second; s.second = NULL;
  }

  SAS::Marker end_marker(trail(), MARKER_ID_END, 3u);
  SAS::report_marker(end_marker);

  delete this;
  return;
}

std::string GetBindingsTask::serialize_data(
                                const Bindings& bindings)
{
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

  writer.StartObject();
  {
    writer.String(JSON_BINDINGS);
    writer.StartObject();
    {
      for (BindingPair b : bindings)
      {
        writer.String(b.first.c_str());
        b.second->to_json(writer);
      }
    }
    writer.EndObject();
  }
  writer.EndObject();

  return sb.GetString();
}

std::string GetSubscriptionsTask::serialize_data(
                      const Subscriptions& subscriptions)
{
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

  writer.StartObject();
  {
    writer.String(JSON_SUBSCRIPTIONS);
    writer.StartObject();
    {
      for (SubscriptionPair s : subscriptions)
      {
        writer.String(s.first.c_str());
        s.second->to_json(writer);
      }
    }
    writer.EndObject();
  }
  writer.EndObject();

  return sb.GetString();
}

void DeleteImpuTask::run()
{
  TRC_DEBUG("Request to delete an IMPU");

  // This interface only supports DELETEs
  if (_req.method() != htp_method_DELETE)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  SAS::Marker start_marker(trail(), MARKER_ID_START, 4u);
  SAS::report_marker(start_marker);

  // Extract the IMPU that has been requested. The URL is of the form
  //
  //   /impu/<public ID>
  const std::string prefix = "/impu/";
  std::string impu = _req.full_path().substr(prefix.length());
  TRC_DEBUG("Extracted impu %s", impu.c_str());

  HTTPCode sc = _cfg->_sm->deregister_subscriber(impu,
                                                 SubscriberManager::EventTrigger::ADMIN,
                                                 trail());

  send_http_reply(sc);

  SAS::Marker end_marker(trail(), MARKER_ID_END, 4u);
  SAS::report_marker(end_marker);

  delete this;
  return;
}

// Deals with requests sent from Homestead in Push Profile Requests.
void PushProfileTask::run()
{
  // HTTP method must be a PUT
  if (_req.method() != htp_method_PUT)
  {
    TRC_DEBUG("Rejecting request, since HTTP Method isn't PUT");
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  TRC_DEBUG("Received body %s", (_req.get_rx_body()).c_str());
  HTTPCode rc = get_associated_uris(_req.get_rx_body(), trail());

  if (rc != HTTP_OK)
  {
    TRC_WARNING("Request body is invalid, send %d", rc);
    send_http_reply(rc);
    delete this;
    return;
  }

  rc = update_associated_uris(trail());
  send_http_reply(rc);
  delete this;
}

HTTPCode PushProfileTask::get_associated_uris(std::string body,
                                              SAS::TrailId trail)
{
  std::string user_data_xml;
  rapidjson::Document doc;
  doc.Parse<0>(body.c_str());

  if (doc.HasParseError())
  {
    TRC_INFO("Failed to parse data as JSON: %s\nError: %s",
             body.c_str(),
             rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_GET_STRING_MEMBER(doc, "user-data-xml", user_data_xml);
  }
  catch (JsonFormatError err)
  {
    TRC_WARNING("User data not available in the JSON");
    return HTTP_BAD_REQUEST;
  }

  const std::string prefix = "/registrations/";
  std::string full_path = _req.full_path();
  size_t end_of_impu = full_path.length();
  _default_public_id = full_path.substr(prefix.length(), end_of_impu - prefix.length());
  TRC_DEBUG("Extracted impu %s", _default_public_id.c_str());

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;

  try
  {
    root->parse<0>(root->allocate_string(user_data_xml.c_str()));
  }
  catch (rapidxml::parse_error& err)
  {
    // report to the user the failure and their locations in the document.
    TRC_WARNING("Failed to parse XML:\n %s\n %s", body.c_str(), err.what());
    delete root; root = NULL;
    return HTTP_BAD_REQUEST;
  }

  // Decode service profile from the XML. Create and populate an instance of the
  // Associated URIs class
  rapidxml::xml_node<>* imss = root->first_node(RegDataXMLUtils::IMS_SUBSCRIPTION);
  bool rc = SproutXmlUtils::get_uris_from_ims_subscription(imss,
                                                           _associated_uris,
                                                           trail);
  delete root; root = NULL;
  return rc ? HTTP_OK : HTTP_BAD_REQUEST;
}

HTTPCode PushProfileTask::update_associated_uris(SAS::TrailId trail)
{
  return _cfg->_sm->update_associated_uris(_default_public_id,
                                           _associated_uris,
                                           trail);
}
