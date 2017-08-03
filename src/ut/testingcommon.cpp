/**
 * @file testingcommon.cpp  Contains common test functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <testingcommon.h>

// Returns the text marking the start of a node.
std::string Common::start_node(std::string node)
{
  return("<" + node + ">");
}

// Returns the text marking the end of the node.
std::string Common::end_node(std::string node)
{
  return("</" + node + ">");
}

// Returns the text for a complete node.
std::string Common::add_node(std::string node_name,
                             std::string node_value)
{
  return("<" + node_name + ">" + node_value + "</" + node_name + ">");
}


ServiceProfileBuilder::ServiceProfileBuilder()
{
}

ServiceProfileBuilder::~ServiceProfileBuilder()
{
}

// Returns a string, which is the service profile in XML.
std::string ServiceProfileBuilder::return_profile()
{
  std::string service_profile;
  service_profile = Common::start_node(Common::SERVICE_PROFILE);
  for (std::vector<IdentityStruct>::iterator it = _identities.begin();
       it != _identities.end();
       ++it)
  {
    service_profile += Common::start_node(Common::PUBLIC_ID);
    service_profile += Common::add_node(Common::ID, it->identity);
    // If a barring indication is present, add this node.
    if(it->barring_indication != Common::NO_BARRING_FIELD)
    {
      service_profile += Common::add_node(Common::BARRING_INDICATION, it->barring_indication);
    }
    // If a wildcarded identity is present, both the identity type and
    // wildcarded IMPU should have been set. Check if this is the case, and if
    // so, add the wildcard info to the XML string.
    if((it->identity_type != Common::NO_ID_TYPE) && (it->wildcard_impu != Common::NO_WILDCARD_IMPU))
    {
      // The number of extensions here is correct.
      service_profile += Common::start_node(Common::EXTENSION);
      service_profile += Common::add_node(Common::ID_TYPE, it->identity_type);
      service_profile += Common::start_node(Common::EXTENSION);
      service_profile += Common::start_node(Common::EXTENSION);
      service_profile += Common::add_node(Common::WILDCARD_IMPU, it->wildcard_impu);
      service_profile += Common::end_node(Common::EXTENSION);
      service_profile += Common::end_node(Common::EXTENSION);
      service_profile += Common::end_node(Common::EXTENSION);
    }
    service_profile += Common::end_node(Common::PUBLIC_ID);
  }
  for(std::vector<IfcStruct>::iterator ifc = _ifcs.begin();
      ifc != _ifcs.end();
      ++ifc)
  {
    service_profile += create_ifc(*ifc);
  }
  service_profile += Common::end_node(Common::SERVICE_PROFILE);
  return service_profile;
}

// Add an identity to the list of identities. This identity is always added with
// "none" set for the BarringIndication, IdentityType and WildcardedIMPU.
// If the BarringIndication node is required, the addBarringIndication function
// should be used.
// If wildcard info is required, the addWildcard function should be used.
ServiceProfileBuilder& ServiceProfileBuilder::addIdentity(std::string identity)
{
  IdentityStruct new_identity;
  new_identity.identity = identity;
  new_identity.barring_indication = Common::NO_BARRING_FIELD;
  new_identity.identity_type = Common::NO_ID_TYPE;
  new_identity.wildcard_impu = Common::NO_WILDCARD_IMPU;
  _identities.push_back(new_identity);

  return *this;
}

// Add wildcard information (identity type of 3, and the wildcarded impu) to a
// public identity.
ServiceProfileBuilder& ServiceProfileBuilder::addWildcard(std::string identity,
                                                          int identity_type,
                                                          std::string wildcard_impu)
{
  // Locate the specified identity in the list of identities, and apply the
  // given wildcard information to it.
  for (std::vector<IdentityStruct>::iterator it = _identities.begin();
       it != _identities.end();
       ++it)
  {
    if (it->identity == identity)
    {
      it->identity_type = std::to_string(identity_type);
      it->wildcard_impu = wildcard_impu;
    }
  }

  return *this;
}

// Add a BarringIndication to an identity. This can be either "1" or "0", where
// 1 means the identity is barred, and 0 means the identity is unbarred.
ServiceProfileBuilder& ServiceProfileBuilder::addBarringIndication(std::string identity,
                                               std::string barring_indication)
{
  // Locate the specified identity in the list of identities, and apply the
  // given barring_indication to it.
  for (std::vector<IdentityStruct>::iterator it = _identities.begin();
       it != _identities.end();
       ++it)
  {
    if (it->identity == identity)
    {
      it->barring_indication = barring_indication;
    }
  }

  return *this;
}

// Add a new iFC, which includes no DefaultHandling field, to the list of iFCs.
// Note: This is an incorrect form!! We are using the for error handling
// testing only.
ServiceProfileBuilder& ServiceProfileBuilder::addIfcNoDefHandling(int priority,
                                                                  std::vector<std::string> triggers,
                                                                  std::string app_serv_name,
                                                                  int cond_neg)
{
  IfcStruct new_ifc;
  new_ifc.priority = priority;
  new_ifc.triggers = triggers;
  new_ifc.app_server_name = app_serv_name;
  new_ifc.condition_negated = std::to_string(cond_neg);
  new_ifc.default_handling = Common::NO_DEF_HANDLING_FIELD;

  _ifcs.push_back(new_ifc);
  return *this;
}

// Add a new iFC, where the value in the DefaultHandling field is malformed, to
// the list of iFCs.
ServiceProfileBuilder& ServiceProfileBuilder::addIfcBadDefField(int priority,
                                                                std::vector<std::string> triggers,
                                                                std::string app_serv_name,
                                                                int cond_neg,
                                                                std::string default_handling)
{
  IfcStruct new_ifc;
  new_ifc.priority = priority;
  new_ifc.triggers = triggers;
  new_ifc.app_server_name = app_serv_name;
  new_ifc.condition_negated = std::to_string(cond_neg);
  new_ifc.default_handling = default_handling;

  _ifcs.push_back(new_ifc);
  return *this;
}

// Add a new iFC to the list of iFCs.
ServiceProfileBuilder& ServiceProfileBuilder::addIfc(int priority,
                                                     std::vector<std::string> triggers,
                                                     std::string app_serv_name,
                                                     int cond_neg,
                                                     int default_handling)
{
  IfcStruct new_ifc;
  new_ifc.priority = priority;
  new_ifc.triggers = triggers;
  new_ifc.app_server_name = app_serv_name;
  new_ifc.condition_negated = std::to_string(cond_neg);
  new_ifc.default_handling = std::to_string(default_handling);

  _ifcs.push_back(new_ifc);
  return *this;
}

// Returns the text for an iFC.
std::string ServiceProfileBuilder::create_ifc(IfcStruct ifc_info)
{
  std::string ifc;
  ifc = Common::start_node(Common::IFC);
  ifc += Common::add_node(Common::PRIORITY, std::to_string(ifc_info.priority));
  ifc += Common::start_node(Common::TRIGGER_POINT);
  ifc += Common::add_node(Common::CONDITION_CNF, "0");
  std::vector<std::string> trigger_list = ifc_info.triggers;
  for (std::vector<std::string>::iterator trigger = trigger_list.begin();
       trigger != trigger_list.end();
       ++trigger)
  {
    ifc += Common::start_node(Common::SPT);
    ifc += Common::add_node(Common::CONDITION_NEGATED, ifc_info.condition_negated);
    ifc += Common::add_node(Common::GROUP, "0");
    ifc += *trigger;
    ifc += Common::add_node(Common::EXTENSION, "");
    ifc += Common::end_node(Common::SPT);
  }
  ifc += Common::end_node(Common::TRIGGER_POINT);
  ifc += Common::start_node(Common::APP_SERVER);
  ifc += Common::add_node(Common::SERVER_NAME, ifc_info.app_server_name);
  if (ifc_info.default_handling != Common::NO_DEF_HANDLING_FIELD)
  {
    ifc += Common::add_node(Common::DEFAULT_HANDLING, ifc_info.default_handling);
  }
  ifc += Common::end_node(Common::APP_SERVER);
  ifc += Common::end_node(Common::IFC);
  return ifc;
}


SubscriptionBuilder::SubscriptionBuilder()
{
}

SubscriptionBuilder::~SubscriptionBuilder()
{
}

// Returns a string, which is the IMS subscription in XML.
std::string SubscriptionBuilder::return_sub()
{
  std::string sub;
  sub = Common::start_node(Common::IMS_SUBSCRIPTION);
  for (std::vector<ServiceProfileBuilder>::iterator service_profile = _service_profiles.begin();
       service_profile != _service_profiles.end();
       ++service_profile)
  {
    std::string service_prof = service_profile->return_profile();
    sub += service_prof;
  }
  sub += Common::end_node(Common::IMS_SUBSCRIPTION);
  printf("sub is:\n%s\n", sub.c_str());
  return sub;
}

// Adds a service profile to the list of service profiles in this subscription.
SubscriptionBuilder& SubscriptionBuilder::addServiceProfile(ServiceProfileBuilder service_profile)
{
  _service_profiles.push_back(service_profile);
  return *this;
}


