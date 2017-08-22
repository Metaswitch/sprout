#include <string>
#include <vector>
#include <memory>

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
bool decode_service_profile(const std::string public_user_identity,
		            std::shared_ptr<rapidxml::xml_document<> > root,
                            rapidxml::xml_node<>* node,
                            std::map<std::string, Ifcs >& ifcs_map,
                            AssociatedURIs& associated_uris,
                            std::vector<std::string>& aliases,
	        	    SIFCService* sifc_service,
	  		    bool contain_ifcs,
                            SAS::TrailId trail);
}

