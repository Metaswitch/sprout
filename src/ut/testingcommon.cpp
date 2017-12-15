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

#include "testingcommon.h"

// Returns the text marking the start of a node.
std::string TestingCommon::start_node(std::string node)
{
  return("<" + node + ">");
}

// Returns the text marking the end of the node.
std::string TestingCommon::end_node(std::string node)
{
  return("</" + node + ">");
}

// Returns the text for a complete node.
std::string TestingCommon::add_node(std::string node_name,
                                    std::string node_value)
{
  return("<" + node_name + ">" + node_value + "</" + node_name + ">");
}

using namespace TestingCommon;


// Returns a string, which is the service profile in XML.
std::string ServiceProfileBuilder::return_profile()
{
  std::string service_profile;
  service_profile = start_node(SERVICE_PROFILE);

  for (std::vector<IdentityStruct>::iterator it = _identities.begin();
       it != _identities.end();
       ++it)
  {
    service_profile += start_node(PUBLIC_ID);
    service_profile += add_node(ID, it->identity);

    // If a barring indication is present, add this node.
    if(it->barring_indication != NO_BARRING_FIELD)
    {
      service_profile += add_node(BARRING_INDICATION, it->barring_indication);
    }

    // If a wildcarded identity is present, both the identity type and
    // wildcarded IMPU should have been set. Check if this is the case, and if
    // so, add the wildcard info to the XML string.
    if((it->identity_type != NO_ID_TYPE) && (it->wildcard_impu != NO_WILDCARD_IMPU))
    {
      // The number of extensions here is correct.
      service_profile += start_node(EXTENSION);
      service_profile += add_node(ID_TYPE, it->identity_type);
      service_profile += start_node(EXTENSION);
      service_profile += start_node(EXTENSION);
      service_profile += add_node(WILDCARD_IMPU, it->wildcard_impu);
      service_profile += end_node(EXTENSION);
      service_profile += end_node(EXTENSION);
      service_profile += end_node(EXTENSION);
    }
    service_profile += end_node(PUBLIC_ID);
  }

  if (_ifcs.empty())
  {
    service_profile += add_node(IFC, "");
  }
  else
  {
    for(std::vector<IfcStruct>::iterator ifc = _ifcs.begin();
        ifc != _ifcs.end();
        ++ifc)
    {
      service_profile += create_ifc(*ifc);
    }
  }

  service_profile += end_node(SERVICE_PROFILE);
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
  new_identity.barring_indication = NO_BARRING_FIELD;
  new_identity.identity_type = NO_ID_TYPE;
  new_identity.wildcard_impu = NO_WILDCARD_IMPU;
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
// Note: This is an incorrect form!! We are using this for error handling
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
  new_ifc.default_handling = NO_DEF_HANDLING_FIELD;

  _ifcs.push_back(new_ifc);
  return *this;
}

// Add a new iFC, where the value in the DefaultHandling field is malformed, to
// the list of iFCs.
// Note: This is an incorrect iFC!! We are using this for error handling testing
// only.
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
  ifc = start_node(IFC);
  ifc += add_node(PRIORITY, std::to_string(ifc_info.priority));
  ifc += start_node(TRIGGER_POINT);
  ifc += add_node(CONDITION_CNF, "0");
  std::vector<std::string> trigger_list = ifc_info.triggers;
  for (std::vector<std::string>::iterator trigger = trigger_list.begin();
       trigger != trigger_list.end();
       ++trigger)
  {
    ifc += start_node(SPT);
    ifc += add_node(CONDITION_NEGATED, ifc_info.condition_negated);
    ifc += add_node(GROUP, "0");
    ifc += *trigger;
    ifc += add_node(EXTENSION, "");
    ifc += end_node(SPT);
  }
  ifc += end_node(TRIGGER_POINT);
  ifc += start_node(APP_SERVER);
  ifc += add_node(SERVER_NAME, ifc_info.app_server_name);
  if (ifc_info.default_handling != NO_DEF_HANDLING_FIELD)
  {
    ifc += add_node(DEFAULT_HANDLING, ifc_info.default_handling);
  }
  ifc += end_node(APP_SERVER);
  ifc += end_node(IFC);
  return ifc;
}


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
SubscriptionBuilder& SubscriptionBuilder::addServiceProfile(ServiceProfileBuilder service_profile)
{
  _service_profiles.push_back(service_profile);
  return *this;
}


// Set the route field on a message.
void Message::convert_routeset(pjsip_msg* msg)
{
  std::string route = get_headers(msg, "Record-Route");
  if (route != "")
  {
    // Convert to a Route set by replacing all instances of Record-Route: with Route:
    for (size_t n = 0; (n = route.find("Record-Route:", n)) != std::string::npos;)
    {
      route.replace(n, 13, "Route:");
    }
  }
  _route = route;
}

std::string Message::get_call_id()
{
  char buf[80];

  int n = snprintf(buf,
                   sizeof(buf),
                   "0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%1$04dohntC@10.114.61.213",
                   _unique);
  std::string ret(buf, n);
  return ret;
}

// Build a request message, which is returned as a string.
std::string Message::get_request()
{
  char buf[16384];

  // The remote target.
  std::string target = std::string(_toscheme).append(":").append(_to);
  if (!_todomain.empty())
  {
    if (!_to.empty())
    {
      target.append("@");
    }
    target.append(_todomain);
  }

  // Set the request uri and the route variables.
  std::string requri = target;
  std::string route = _route.empty() ? "" : _route + "\r\n";

  // Set the value of the To header.
  std::string to_header = _full_to_header;
  if (to_header.empty())
  {
    to_header.append("To: <").append(target).append(">");
    if (_in_dialog)
    {
      to_header.append(";tag=10.114.61.213+1+8c8b232a+5fb751cf");
    }
  }

  // Default branch parameter if it's not supplied.
  std::string branch = _branch.empty() ? "Pjmo1aimuq33BAI4rjhgQgBr4sY" + std::to_string(_unique) : _branch;

  // Set the content length variable.
  char content_length[128];
  snprintf(content_length, sizeof(content_length), "Content-Length: %d\r\n", (int)_body.length());

  int n = snprintf(buf, sizeof(buf),
                   "%1$s %9$s SIP/2.0\r\n"
                   "Via: SIP/2.0/TCP %13$s;rport;branch=z9hG4bK%16$s\r\n"
                   "%12$s"
                   "From: <sip:%2$s%17$s%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "%10$s\r\n"
                   "Max-Forwards: %8$d\r\n"
                   "Call-ID: %11$s\r\n"
                   "CSeq: %15$d %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "%4$s"
                   "%7$s"
                   "%14$s"
                   "%5$s"
                   "\r\n"
                   "%6$s",
                   /*  1 */ _method.c_str(),
                   /*  2 */ _from.c_str(),
                   /*  3 */ _fromdomain.c_str(),
                   /*  4 */ _content_type.empty() ? "" : std::string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                   /*  5 */ _contentlength ? content_length : "",
                   /*  6 */ _body.c_str(),
                   /*  7 */ _extra.empty() ? "" : std::string(_extra).append("\r\n").c_str(),
                   /*  8 */ _forwards,
                   /*  9 */ _requri.empty() ? requri.c_str() : _requri.c_str(),
                   /* 10 */ to_header.c_str(),
                   /* 11 */ get_call_id().c_str(),
                   /* 12 */ _first_hop ? "" : "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n",
                   /* 13 */ _via.c_str(),
                   /* 14 */ route.c_str(),
                   /* 15 */ _cseq,
                   /* 16 */ branch.c_str(),
                   /* 17 */ _from.empty() ? "" : "@"
                     );

  EXPECT_LT(n, (int)sizeof(buf));

  std::string ret(buf, n);
  return ret;
}

// Build a response message, which is returned as a string.
std::string Message::get_response()
{
  char buf[16384];

  // Default branch parameter if it's not supplied.
  std::string branch = _branch.empty() ? "Pjmo1aimuq33BAI4rjhgQgBr4sY" + std::to_string(_unique) : _branch;

  int n = snprintf(buf, sizeof(buf),
                   "SIP/2.0 %9$s\r\n"
                   "Via: SIP/2.0/TCP %14$s;rport;branch=z9hG4bK%15$s\r\n"
                   "%12$s"
                   "From: <sip:%2$s@%3$s>;tag=10.114.61.213+1+8c8b232a+5fb751cf\r\n"
                   "To: <sip:%7$s%8$s>\r\n"
                   "Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs%11$04dohntC@10.114.61.213\r\n"
                   "CSeq: %13$d %1$s\r\n"
                   "User-Agent: Accession 2.0.0.0\r\n"
                   "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
                   "%4$s"
                   "%10$s"
                   "Content-Length: %5$d\r\n"
                   "\r\n"
                   "%6$s",
                   /*  1 */ _method.c_str(),
                   /*  2 */ _from.c_str(),
                   /*  3 */ _fromdomain.c_str(),
                   /*  4 */ _content_type.empty() ? "" : std::string("Content-Type: ").append(_content_type).append("\r\n").c_str(),
                   /*  5 */ (int)_body.length(),
                   /*  6 */ _body.c_str(),
                   /*  7 */ _to.c_str(),
                   /*  8 */ _todomain.empty() ? "" : std::string("@").append(_todomain).c_str(),
                   /*  9 */ _status.c_str(),
                   /* 10 */ _extra.empty() ? "" : std::string(_extra).append("\r\n").c_str(),
                   /* 11 */ _unique,
                   /* 12 */ _first_hop ? "" : "Via: SIP/2.0/TCP 10.114.61.213:5061;received=23.20.193.43;branch=z9hG4bK+7f6b263a983ef39b0bbda2135ee454871+sip+1+a64de9f6\r\n",
                   /* 13 */ _cseq,
                   /* 14 */ _via.c_str(),
                   /* 15 */ branch.c_str()
                     );

  EXPECT_LT(n, (int)sizeof(buf));

  std::string ret(buf, n);
  return ret;
}
