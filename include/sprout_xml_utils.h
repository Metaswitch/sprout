/**
 * @file sprout_xml_utils.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "log.h"
#include "utils.h"
#include "wildcard_utils.h"
#include "sas.h"
#include "sproutsasevent.h"
#include "httpconnection.h"
#include "hssconnection.h"
#include "rapidjson/error/en.h"
#include "snmp_continuous_accumulator_table.h"
#include "xml_utils.h"

namespace SproutXmlUtils
{

// Validates that the XML contains at least one ServiceProfile
bool validate_service_profile(rapidxml::xml_node<>* node);

// Validates that the XML contains at least one PublicIdentity
bool validate_public_identity(rapidxml::xml_node<>* node);

// Parses a PublicIdentity node and pulls out the identities and their
// barring status
void get_identities_and_barring_status(rapidxml::xml_node<>* public_id,
                                       rapidxml::xml_node<>* identity,
                                       bool& barred,
                                       std::string& associated_uri,
                                       std::string& identity_uri);

// Adds a URI and its barring status to the set of associated URIs
void add_uri_to_associated_uris(AssociatedURIs& associated_uris,
                                bool barred,
                                std::string associated_uri,
                                std::string identity_uri);

// Parses an IMS subscription to pull out the associated URIs
bool get_uris_from_ims_subscription(rapidxml::xml_node<>* node,
                                    AssociatedURIs& associated_uris,
                                    SAS::TrailId trail);

// Parse an IMS subscription to pull out the associated URIs, the IFCs and the
// aliases
bool parse_ims_subscription(const std::string public_user_identity,
                            std::shared_ptr<rapidxml::xml_document<> > root,
                            rapidxml::xml_node<>* node,
                            std::map<std::string, Ifcs >& ifcs_map,
                            AssociatedURIs& associated_uris,
                            std::vector<std::string>& aliases,
                            SIFCService* sifc_service,
                            SAS::TrailId trail);
}
