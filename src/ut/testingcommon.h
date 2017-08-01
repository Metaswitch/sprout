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

// ADD EXAMPLES TO THIS DOC SO THAT POOR INTERNS KNOW WHAT THESE THINGS LOOK
// LIKE!!

#ifndef TESTINGCOMMON_H__
#define TESTINGCOMMON_H__

std::string IMS_SUB = "IMSSubscription";
std::string SERV_PROF = "ServiceProfile";
std::string PUB_ID = "PublicIdentity";
std::string ID = "Identity";
std::string IFC = "InitialFilterCriteria";
std::string PRIORITY = "Priority";
std::string TRIG_POINT = "TriggerPoint";
std::string COND_TYPE = "ConditionTypeCNF";
std::string SPT = "SPT";
std::string COND_NEG = "ConditionNegated";
std::string GROUP = "Group";
std::string METHOD = "Method";
std::string EXT = "Extension";
std::string APP_SERV = "ApplicationServer";
std::string SERV_NAME = "ServerName";
std::string DEF = "DefaultHandling";
std::string BAR_IND = "BarringIndication";

class SubscriptionBuilder
{
public:
  std::vector<std::pair<std::string, bool>> _identities;
  std::vector<std::string> _ifcs;

  std::string return_sub();
  void addIdentity(std::string, bool);
  void addIfc(int, std::vector<std::string>, std::string, int);
  std::string start_node(std::string);
  std::string end_node(std::string);
  std::string add_node(std::string, std::string);
};

// Return the full subscription text.
std::string SubscriptionBuilder::return_sub()
{
  std::string sub;
  sub = start_node(IMS_SUB) + start_node(SERV_PROF);
  for (std::vector<std::pair<std::string, bool>>::iterator it = _identities.begin();
       it != _identities.end();
       ++it)
  {
    sub += start_node(PUB_ID);
    sub += add_node(ID, it->first);
    // If the identity is barred, show the barring indication.
    if(it->second == true)
    {
      sub += add_node(BAR_IND, "1");
    }
    sub += end_node(PUB_ID);
  }
  for(std::vector<std::string>::iterator ifc = _ifcs.begin();
      ifc != _ifcs.end();
      ++ifc)
  {
    sub += *ifc;
  }
  sub += end_node(SERV_PROF) + end_node(IMS_SUB);
  printf("sub is:\n%s\n", sub.c_str());
  return sub;
}

// Add an identity to the list of identities.
void SubscriptionBuilder::addIdentity(std::string identity, bool barred=false)
{
  _identities.push_back(std::make_pair(identity, barred));
}

// Add the text for an iFC to the list of iFCs.
void SubscriptionBuilder::addIfc(int priority,
                                 std::vector<std::string> triggers,
                                 std::string app_serv_name,
                                 int cond_neg=0)
{
  std::string ifc;
  ifc = start_node(IFC);
  ifc += add_node(PRIORITY, std::to_string(priority));
  ifc += start_node(TRIG_POINT);
  ifc += add_node(COND_TYPE, "0");
  for(std::vector<std::string>::iterator trigger = triggers.begin();
      trigger != triggers.end();
      ++trigger)
  {
    ifc += start_node(SPT);
    ifc += add_node(COND_NEG, std::to_string(cond_neg));
    ifc += add_node(GROUP, "0");
    ifc += *trigger;
    ifc += add_node(EXT, "");
    ifc += end_node(SPT);
  }
  ifc += end_node(TRIG_POINT);
  ifc += start_node(APP_SERV);
  ifc += add_node(SERV_NAME, app_serv_name);
  ifc += add_node(DEF, "0");
  ifc += end_node(APP_SERV);
  ifc += end_node(IFC);
  _ifcs.push_back(ifc);
}


// Create the text marking the start of a node.
std::string SubscriptionBuilder::start_node(std::string node)
{
  return("<" + node + ">");
}


// Create the text marking the end of the node.
std::string SubscriptionBuilder::end_node(std::string node)
{
  return("</" + node + ">");
}

// Create the text for a complete node.
std::string SubscriptionBuilder::add_node(std::string node_name,
                                          std::string node_value)
{
  return("<" + node_name + ">" + node_value + "</" + node_name + ">");
}

#endif
