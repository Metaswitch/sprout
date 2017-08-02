/**
 * @file testingcommon.h  Contains common test functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef TESTINGCOMMON_H__
#define TESTINGCOMMON_H__

// Node names.
std::string IMS_SUBSCRIPTION = "IMSSubscription";
std::string SERVICE_PROFILE = "ServiceProfile";
std::string PUBLIC_ID = "PublicIdentity";
std::string ID = "Identity";
std::string IFC = "InitialFilterCriteria";
std::string PRIORITY = "Priority";
std::string TRIGGER_POINT = "TriggerPoint";
std::string CONDITION_CNF = "ConditionTypeCNF";
std::string SPT = "SPT";
std::string CONDITION_NEGATED = "ConditionNegated";
std::string GROUP = "Group";
std::string METHOD = "Method";
std::string EXTENSION = "Extension";
std::string APP_SERVER = "ApplicationServer";
std::string SERVER_NAME = "ServerName";
std::string DEFAULT_HANDLING = "DefaultHandling";
std::string BARRING_INDICATION = "BarringIndication";

// Not node names. Just used in the functions.
std::string NO_BARRING_FIELD = "none";


// Tools to help build XML strings.

// Returns the text marking the start of a node.
std::string start_node(std::string node)
{
  return("<" + node + ">");
}

// Returns the text marking the end of the node.
std::string end_node(std::string node)
{
  return("</" + node + ">");
}

// Returns the text for a complete node.
std::string add_node(std::string node_name,
                     std::string node_value)
{
  return("<" + node_name + ">" + node_value + "</" + node_name + ">");
}


// Class which can build up and return a Service Profile.
// A service profile has this format:
//   <ServiceProfile>
//     <PublicIdentity>                        There can be multiple of this node.
//       <Identity>
//         sip:1234567890@example              This value can vary.
//       </Identity>
//       <BarringIndication>                   This node is optional.
//         0                                   This can be 0 or 1.
//       </BarringIndication>
//     </PublicIdentity>
//     <InitialFilterCriteria>                 There can be multiple of this node.
//       <Priority>1</Priority>                This can be set to 1 or 2.
//       <TriggerPoint>
//         <ConditionTypeCNF>
//           0
//         </ConditionTypeCNF>
//         <SPT>                               There can be multiple of this node.
//           <ConditionNegated>
//             0                               This can be 0 or 1.
//           </ConditionNegated>
//           <Group>0</Group>
//           <Method>INVITE<Method>            This trigger point can vary.
//           <Extension></Extension>
//         </SPT>
//       </TriggerPoint>
//       <ApplicationServer>
//         <ServerName>
//           sip:1.2.3.4:567890;transport=UDP  This value can vary.
//         </ServerName>
//         <DefaultHandling>
//           0
//         </DefaultHandling>
//       </ApplicationServer>
//     </InitialFilterCriteria>
//   </ServiceProfile>
class ServiceProfileBuilder
{
public:
  std::vector<std::pair<std::string, std::string>> _identities;
  std::vector<std::string> _ifcs;

  std::string return_profile();
  void addIdentity(std::string);
  void addBarringIndication(std::string, std::string);
  void addIfc(int, std::vector<std::string>, std::string, int);
};

// Returns a string, which is the service profile in XML.
std::string ServiceProfileBuilder::return_profile()
{
  std::string service_profile;
  service_profile = start_node(SERVICE_PROFILE);
  for (std::vector<std::pair<std::string, std::string>>::iterator it = _identities.begin();
       it != _identities.end();
       ++it)
  {
    service_profile += start_node(PUBLIC_ID);
    service_profile += add_node(ID, it->first);
    // If a barring indication is present, add this node.
    if(it->second != NO_BARRING_FIELD)
    {
      service_profile += add_node(BARRING_INDICATION, it->second);
    }
    service_profile += end_node(PUBLIC_ID);
  }
  for(std::vector<std::string>::iterator ifc = _ifcs.begin();
      ifc != _ifcs.end();
      ++ifc)
  {
    service_profile += *ifc;
  }
  service_profile += end_node(SERVICE_PROFILE);
  return service_profile;
}

// Add an identity to the list of identities. This identity is always added with
// "none" set for the BarringIndication. If the BarringIndication node is
// required, the addBarringIndication function should be used.
void ServiceProfileBuilder::addIdentity(std::string identity)
{
  std::string barring_indication = NO_BARRING_FIELD;
  _identities.push_back(std::make_pair(identity, barring_indication));
}

// Add a BarringIndication to an identity. This can be either "1" or "0", where
// 1 means the identity is barred, and 0 means the identity is unbarred.
void ServiceProfileBuilder::addBarringIndication(std::string identity,
                                               std::string barring_indication)
{
  // Locate the specified identity in the list of identities, and apply the
  // given barring_indication to it.
  for (std::vector<std::pair<std::string, std::string>>::iterator it = _identities.begin();
       it != _identities.end();
       ++it)
  {
    if (it->first == identity)
    {
      it->second = barring_indication;
    }
  }
}

// Add the text for an iFC to the list of iFCs.
void ServiceProfileBuilder::addIfc(int priority,
                                   std::vector<std::string> triggers,
                                   std::string app_serv_name,
                                   int cond_neg=0)
{
  std::string ifc;
  ifc = start_node(IFC);
  ifc += add_node(PRIORITY, std::to_string(priority));
  ifc += start_node(TRIGGER_POINT);
  ifc += add_node(CONDITION_CNF, "0");
  for(std::vector<std::string>::iterator trigger = triggers.begin();
      trigger != triggers.end();
      ++trigger)
  {
    ifc += start_node(SPT);
    ifc += add_node(CONDITION_NEGATED, std::to_string(cond_neg));
    ifc += add_node(GROUP, "0");
    ifc += *trigger;
    ifc += add_node(EXTENSION, "");
    ifc += end_node(SPT);
  }
  ifc += end_node(TRIGGER_POINT);
  ifc += start_node(APP_SERVER);
  ifc += add_node(SERVER_NAME, app_serv_name);
  ifc += add_node(DEFAULT_HANDLING, "0");
  ifc += end_node(APP_SERVER);
  ifc += end_node(IFC);
  _ifcs.push_back(ifc);
}

// Class which can build up and return an IMS Subscription.
// An IMS subscription has this format:
//   <IMSSubscription>
//     <ServiceProfile>    There can be multiple of this node.
//       ...               The contents of the service profile are detailed
//       ...                 above the ServiceProfileBuilder class.
//     <ServiceProfile>
//   <IMSSubscription>
class SubscriptionBuilder
{
public:
  std::vector<ServiceProfileBuilder> _service_profiles;

  std::string return_sub();
  void addServiceProfile(ServiceProfileBuilder);
};

// Returns a string, which is the IMS subscription in XML.
std::string SubscriptionBuilder::return_sub()
{
  std::string sub;
  sub = start_node(IMS_SUBSCRIPTION);
  for (std::vector<ServiceProfileBuilder>::iterator service_profile = _service_profiles.begin();
       service_profile != _service_profiles.end();
       ++service_profile)
  {
    std::string service_prof = service_profile->return_profile();
    sub += service_prof;
  }
  sub += end_node(IMS_SUBSCRIPTION);
  return sub;
}

// Adds a service profile to the list of service profiles in this subscription.
void SubscriptionBuilder::addServiceProfile(ServiceProfileBuilder service_profile)
{
  _service_profiles.push_back(service_profile);
}

#endif
