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
bool get_uris_from_service_profile(rapidxml::xml_node<>* node,
                                    AssociatedURIs& associated_uris,
                                    SAS::TrailId trail);

bool decode_service_profile(const std::string public_user_identity,
		             std::shared_ptr<rapidxml::xml_document<> > root,
                             rapidxml::xml_node<>* node,
                             std::map<std::string, Ifcs >& ifcs_map,
                             AssociatedURIs& associated_uris,
                             std::vector<std::string>& aliases,
	        	     SIFCService* sifc_service,
                             SAS::TrailId trail);
}

