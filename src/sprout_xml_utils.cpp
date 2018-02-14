/**
 * @file sprout_xml_utils.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "sprout_xml_utils.h"

#include <string>
#include <vector>

namespace SproutXmlUtils
{

bool validate_service_profile(rapidxml::xml_node<>* node)
{
  if (!node->first_node(RegDataXMLUtils::SERVICE_PROFILE))
  {
    TRC_WARNING("Malformed HSS XML - no ServiceProfiles");
    return false;
  }

  return true;
}

bool validate_public_identity(rapidxml::xml_node<>* node)
{
  if (!node->first_node(RegDataXMLUtils::PUBLIC_IDENTITY))
  {
    TRC_WARNING("Malformed ServiceProfile XML - no Public Identity");
    return false;
  }

  return true;
}

void get_identities_and_barring_status(rapidxml::xml_node<>* public_id,
                                       rapidxml::xml_node<>* identity,
                                       bool& barred,
                                       std::string& associated_uri,
                                       std::string& identity_uri)
{
  // There are two potential identities in the Identity node:
  //  - identity_uri: Identity used for matching against identities to
  //                  select the correct service profile.
  //  - associated_uri: The actual associated URI.
  //
  // These identities are normally the same, except in the case of a
  // non-distinct IMPU (an IMPU that is part of a wildcard range, but is
  // explicitly included in the XML), where the identity_uri is the
  // distinct IMPU, and the associated_uri is the wildcard IMPU.
  identity_uri = std::string(identity->value());
  associated_uri = identity_uri;
  rapidxml::xml_node<>* extension =
                        public_id->first_node(RegDataXMLUtils::EXTENSION);

  if (extension)
  {
    RegDataXMLUtils::parse_extension_identity(associated_uri, extension);
  }

  rapidxml::xml_node<>* barring_indication =
               public_id->first_node(RegDataXMLUtils::BARRING_INDICATION);

  TRC_DEBUG("Processing Identity node from HSS XML - %s", identity_uri.c_str());

  if (barring_indication)
  {
    std::string value = barring_indication->value();
    if (value == RegDataXMLUtils::STATE_BARRED)
    {
      barred = true;
    }
  }
}

void add_uri_to_associated_uris(AssociatedURIs& associated_uris,
                                bool barred,
                                std::string associated_uri,
                                std::string identity_uri)
{
  if (associated_uri != identity_uri)
  {
    // We're in the case where we're processing a non-distinct IMPU. We
    // don't want to handle updating the associated URI, as this should
    // be covered when we handle the corresponding wildcard IMPU entry.
    // Instead, store off any barring information for the IMPU as this
    // needs to override the barring status of the wildcard IMPU.
    associated_uris.add_barring_status(identity_uri, barred);
  }
  else if (!associated_uris.contains_uri(associated_uri))
  {
    associated_uris.add_uri(associated_uri, barred);
  }
}

bool get_uris_from_ims_subscription(rapidxml::xml_node<>* node,
                                    AssociatedURIs& associated_uris,
                                    SAS::TrailId trail)
{
  associated_uris.clear_uris();

  if (!validate_service_profile(node))
  {
    return false;
  }

  rapidxml::xml_node<>* sp = NULL;
  for (sp = node->first_node(RegDataXMLUtils::SERVICE_PROFILE);
       sp != NULL;
       sp = sp->next_sibling(RegDataXMLUtils::SERVICE_PROFILE))
  {
    if (!validate_public_identity(sp))
    {
      return false;
    }

    rapidxml::xml_node<>* public_id = NULL;
    for (public_id = sp->first_node(RegDataXMLUtils::PUBLIC_IDENTITY);
         public_id != NULL;
         public_id = public_id->next_sibling(RegDataXMLUtils::PUBLIC_IDENTITY))
    {
      rapidxml::xml_node<>* identity = public_id->first_node(RegDataXMLUtils::IDENTITY);

      if (identity)
      {
        bool barred = false;
        std::string associated_uri;
        std::string identity_uri;
        get_identities_and_barring_status(public_id,
                                          identity,
                                          barred,
                                          associated_uri,
                                          identity_uri);
        add_uri_to_associated_uris(associated_uris,
                                   barred,
                                   associated_uri,
                                   identity_uri);

      }
    }
  }

  return true;
}

bool parse_ims_subscription(const std::string public_user_identity,
                            std::shared_ptr<rapidxml::xml_document<> > root,
                            rapidxml::xml_node<>* node,
                            std::map<std::string, Ifcs >& ifcs_map,
                            AssociatedURIs& associated_uris,
                            std::vector<std::string>& aliases,
                            SIFCService* sifc_service,
                            SAS::TrailId trail)
{
  // The set of aliases consists of the set of public identities in the same
  // Service Profile, which also share the same service-specific data (ie. any
  // AS that they are sent to will treat them in the same way).  It is a subset
  // of the associated URIs.
  // TODO - There is no way we can be certain that two identities in the same
  // service profile are actually aliases, so we should rename our "aliases"
  // variable to avoid confusion.

  // In order to find the set of aliases we want, we need to find the Service
  // Profile containing our public identity and then save off all of the public
  // identities in this Service Profile.

  // There are five types of public identity, and different ways to check if
  // they match our identity.
  //   Distinct IMPU, non distinct/specific IMPU, Distinct PSI - If we get a
  //        match against one of these, then this is definitely the correct
  //        identity, and we stop looking for a match.
  //   Wildcarded IMPU - Regex matching the IMPU. If we get a match we might be
  //        in the correct service profile, but there could be a matching
  //        distinct/non-distinct IMPU later. It's a misconfiguration to have
  //        multiple wildcards that match an IMPU without having a distinct/non-
  //        distinct IMPU as well.
  //   Wildcarded PSI - Regex matching the IMPU. There's no way to indicate
  //        what regex is the correct regex to match against the IMPU if there
  //        are overlapping ranges in the user data (but this makes no sense
  //        for a HSS to return, unlike for overlapping ranges for wildcard
  //        IMPUs). We allow distinct PSIs to trump wildcard matches, otherwise
  //        the first match is the one we take.
  //
  // - sp_identities is used to save the public identities in the current Service
  // Profile.
  // - current_sp_contains_public_id is a flag used to indicate that the
  // Service Profile we're currently cycling through definitely contains our
  // public identity (e.g. it wasn't found by matching a wildcard).
  // - current_sp_maybe_contains_public_id is a flag used to indicate that the
  // Service Profile we're currently cycling through might contain our public
  // identity (e.g. it matched on a regex, but there could still be a non
  // wildcard match to come).
  // - found_aliases is a flag used to indicate that we've already found our list
  // of aliases, maybe_found_aliases indicates that we might have found it, but
  // it could be overridden later.
  // - wildcard_uri saves of the value of a wildcard identity that potentially
  // matches the public identity, so that we can update the barring state of
  // the public identity if the wildcard identity is the best match after we've
  // looked at all the service profiles.
  std::vector<std::string> sp_identities;
  std::vector<std::string> temp_aliases;
  bool current_sp_contains_public_id = false;
  bool current_sp_maybe_contains_public_id = false;
  bool found_aliases = false;
  bool maybe_found_aliases = false;
  bool found_multiple_matches = false;
  std::string wildcard_uri;
  associated_uris.clear_uris();
  rapidxml::xml_node<>* sp = NULL;
  Ifcs ifc;

  if (!validate_service_profile(node))
  {
    return false;
  }

  for (sp = node->first_node(RegDataXMLUtils::SERVICE_PROFILE);
       sp != NULL;
       sp = sp->next_sibling(RegDataXMLUtils::SERVICE_PROFILE))
  {
    Ifcs ifc(root, sp, sifc_service, trail);
    rapidxml::xml_node<>* public_id = NULL;

    if (!validate_public_identity(sp))
    {
      return false;
    }

    for (public_id = sp->first_node(RegDataXMLUtils::PUBLIC_IDENTITY);
         public_id != NULL;
         public_id = public_id->next_sibling(RegDataXMLUtils::PUBLIC_IDENTITY))
    {
      rapidxml::xml_node<>* identity = public_id->first_node(RegDataXMLUtils::IDENTITY);

      if (identity)
      {
        bool barred = false;
        std::string associated_uri;
        std::string identity_uri;
        get_identities_and_barring_status(public_id,
                                          identity,
                                          barred,
                                          associated_uri,
                                          identity_uri);
        add_uri_to_associated_uris(associated_uris,
                                   barred,
                                   associated_uri,
                                   identity_uri);

        if (associated_uri == identity_uri)
        {
          // Only add the URI to the IFC map if the two types of identity
          // match
          ifcs_map[associated_uri] = ifc;
        }

        if (!found_aliases)
        {
          sp_identities.push_back(associated_uri);

          if (identity_uri == public_user_identity)
          {
            current_sp_contains_public_id = true;
          }
          else if (WildcardUtils::check_users_equivalent(identity_uri,
                                                         public_user_identity))
          {
            found_multiple_matches = maybe_found_aliases;
            current_sp_maybe_contains_public_id = true;

            if (!maybe_found_aliases)
            {
              ifcs_map[public_user_identity] = ifc;
              wildcard_uri = identity_uri;
            }
          }
        }
      }
      else
      {
        TRC_WARNING("Malformed PublicIdentity XML - no Identity");
        return false;
      }
    }

    if ((!found_aliases) &&
        (current_sp_contains_public_id))
    {
      aliases = sp_identities;
      found_aliases = true;
    }
    else if ((!found_multiple_matches) &&
             (current_sp_maybe_contains_public_id))
    {
      temp_aliases = sp_identities;
      maybe_found_aliases = true;
    }

    sp_identities.clear();
  }

  if (aliases.empty())
  {
    if (!temp_aliases.empty())
    {
      // The best match was a wildcard.
      aliases = temp_aliases;
      associated_uris.add_wildcard_mapping(wildcard_uri,
                                           public_user_identity);

      if (found_multiple_matches)
      {
        SAS::Event event(trail, SASEvent::AMBIGUOUS_WILDCARD_MATCH, 0);
        event.add_var_param(public_user_identity);
        SAS::report_event(event);
      }
    }
    else
    {
      SAS::Event event(trail, SASEvent::NO_MATCHING_SERVICE_PROFILE, 0);
      event.add_var_param(public_user_identity);
      SAS::report_event(event);
    }
  }
  return true;
}

} // End of SproutXmlUtils namespace
