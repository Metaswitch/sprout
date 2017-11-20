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

#include <string>
#include <vector>
#include "gtest/gtest.h"

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "siptest.hpp"


namespace TestingCommon
{

  // XML node names.
  const std::string IMS_SUBSCRIPTION = "IMSSubscription";
  const std::string SERVICE_PROFILE = "ServiceProfile";
  const std::string PUBLIC_ID = "PublicIdentity";
  const std::string ID = "Identity";
  const std::string IFC = "InitialFilterCriteria";
  const std::string PRIORITY = "Priority";
  const std::string TRIGGER_POINT = "TriggerPoint";
  const std::string CONDITION_CNF = "ConditionTypeCNF";
  const std::string SPT = "SPT";
  const std::string CONDITION_NEGATED = "ConditionNegated";
  const std::string GROUP = "Group";
  const std::string METHOD = "Method";
  const std::string EXTENSION = "Extension";
  const std::string APP_SERVER = "ApplicationServer";
  const std::string SERVER_NAME = "ServerName";
  const std::string DEFAULT_HANDLING = "DefaultHandling";
  const std::string BARRING_INDICATION = "BarringIndication";
  const std::string ID_TYPE = "IdentityType";
  const std::string WILDCARD_IMPU = "WildcardedIMPU";

  // Not node names. Just used in the functions.
  const std::string NO_BARRING_FIELD = "none";
  const std::string NO_DEF_HANDLING_FIELD = "none";
  const std::string NO_ID_TYPE = "none";
  const std::string NO_WILDCARD_IMPU = "none";

  // Tools to help build XML strings.
  std::string start_node(std::string);
  std::string end_node(std::string);
  std::string add_node(std::string, std::string);


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
  //       <Extension>                           Entire Extension node is optional.
  //         <IdentityType>
  //           3                                 Can vary, but is always 3 for wildcarded IMPUS.
  //         </IdentityType>
  //         <Extension>
  //           <Extension>
  //             <WildcardedIMPU>
  //               sip:!*.!@example              The wildcarded IMPU can vary.
  //             </WildcardedIMPU>
  //           </Extension>
  //         </Extension>
  //       </Extension>
  //     </PublicIdentity>
  //     <InitialFilterCriteria>                 There can be multiple of this node. If a service profile has no iFCs, this node is present but empty.
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
  //           0                                 This can be 0, 1, or invalid.
  //         </DefaultHandling>
  //       </ApplicationServer>
  //     </InitialFilterCriteria>
  //   </ServiceProfile>
  class ServiceProfileBuilder
  {
  public:
    ServiceProfileBuilder() {};
    ~ServiceProfileBuilder() {};

    std::string return_profile();
    ServiceProfileBuilder& addIdentity(std::string);
    ServiceProfileBuilder& addWildcard(std::string, int, std::string);
    ServiceProfileBuilder& addBarringIndication(std::string, std::string);
    ServiceProfileBuilder& addIfc(int, std::vector<std::string>, std::string, int=0, int=0);
    ServiceProfileBuilder& addIfcNoDefHandling(int, std::vector<std::string>, std::string, int=0);
    ServiceProfileBuilder& addIfcBadDefField(int, std::vector<std::string>, std::string, int, std::string);

  private:
    // Structure containing the info needed to build a single PublicIdentity node.
    struct IdentityStruct
    {
      std::string identity;
      std::string barring_indication;
      std::string identity_type;
      std::string wildcard_impu;
    };

    //Structure containing the info needed to build a single iFC.
    struct IfcStruct
    {
      int priority;
      std::vector<std::string> triggers;
      std::string app_server_name;
      std::string condition_negated;
      std::string default_handling;
    };

    std::vector<IdentityStruct> _identities;
    std::vector<IfcStruct> _ifcs;

    std::string create_ifc(IfcStruct);
  };


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
    SubscriptionBuilder() {};
    ~SubscriptionBuilder() {};

    std::string return_sub();
    SubscriptionBuilder& addServiceProfile(ServiceProfileBuilder);

  private:
    std::vector<ServiceProfileBuilder> _service_profiles;
  };


  // TODO - Edit this class so that it is more consistent with the
  // SubscriptionBuilder class. (Instead of tests setting _method, etc.
  // directly, have functions setMethod(), etc. This means the interface will be
  // more consistent.) When this work is done, the subclass SCSCFMessage (in
  // scscf_test.cpp) should also be reworked.
  //
  // Class which can build request/response messages.
  //
  // The format of the request message is:
  //    <Method> <RequestURI> SIP/2.0
  //    Via: SIP/2.0/TCP <Via>;rport;branch=z9hG4bK<Branch>
  //    <OptionalOtherViaHeaders>
  //    From: <sip:<From>@<FromDomain>>;tag=10.114.61.213+1+8c8b232a+5fb751cf
  //    To: <<Target>><OptionalTag>
  //    Max-Forwards: <MaxForwards>
  //    Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs<Num>ohntC@10.114.61.213
  //    CSeq: <CSeq> <Method>
  //    User-Agent: Accession 2.0.0.0
  //    Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS
  //    <OptionalContentType>
  //    <OptionalExtras>
  //    <OptionalContentLength>
  //    <OptionalRoute>
  //
  // An example of a request message:
  //    INVITE sip:123@example SIP/2.0
  //    Via: SIP/2.0/TCP 1.2.3.4:10000;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY1042
  //    From: <sip:567@example>;tag=10.114.61.213+1+8c8b232a+5fb751cf
  //    To: <sip:890@example>
  //    Max-Forwards: 68
  //    Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213
  //    CSeq: 16567 INVITE
  //    User-Agent: Accession 2.0.0.0
  //    Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS
  //
  // The format of the response message is:
  //   SIP/2.0 <Status>
  //   Via: SIP/2.0/TCP <Via>;rport;branch=z9hG4bK<Branch>
  //   <OptionalOtherViaHeaders>
  //   From: <sip:<From>@<FromDomain>>;tag=10.114.61.213+1+8c8b232a+5fb751cf
  //   To: <sip:<To><ToDomain>>\r\n
  //   Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs<Num>ohntC@10.114.61.213
  //   CSeq: <CSeq> <Method>
  //   User-Agent: Accession 2.0.0.0
  //   Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS
  //   <OptionalContentType>
  //   <OptionalExtras>
  //   Content-Length: <ContentLength>
  //   <OptionalRoute>
  //
  // An example of a response message:
  //   SIP/2.0 200 OK
  //   Via: SIP/2.0/TCP 1.2.3.4:10000;rport;branch=z9hG4bKPjmo1aimuq33BAI4rjhgQgBr4sY1042
  //   From: <sip:123@example>;tag=10.114.61.213+1+8c8b232a+5fb751cf
  //   To: <sip:456@example>
  //   Call-ID: 0gQAAC8WAAACBAAALxYAAAL8P3UbW8l4mT8YBkKGRKc5SOHaJ1gMRqs1042ohntC@10.114.61.213
  //   CSeq: 16567 INVITE
  //   User-Agent: Accession 2.0.0.0
  //   Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS
  //   Content-Type: application/sdp
  //   Content-Length: 0
  //
  class Message
  {
  public:
    std::string _method;
    std::string _requri; //< overrides toscheme:to@todomain
    std::string _toscheme;
    std::string _status;
    std::string _from;
    std::string _fromdomain;
    std::string _to;
    std::string _todomain;
    std::string _full_to_header;
    std::string _content_type;
    std::string _body;
    std::string _extra;
    int _forwards;
    int _unique; //< unique to this dialog; inserted into Call-ID
    bool _first_hop;
    std::string _via;
    std::string _branch;
    std::string _route;
    int _cseq;
    bool _in_dialog;
    bool _contentlength;

    Message() :
      _method("INVITE"),
      _toscheme("sip"),
      _status("200 OK"),
      _from("6505551000"),
      _fromdomain("homedomain"),
      _to("6505551234"),
      _todomain("homedomain"),
      _content_type("application/sdp"),
      _forwards(68),
      _first_hop(false),
      _via("10.83.18.38:36530"),
      _cseq(16567),
      _in_dialog(false),
      _contentlength(true)
    {
      static int unique = 1042;
      _unique = unique;
      unique += 10; // leave room for manual increments
    };
    ~Message() {};

    void convert_routeset(pjsip_msg*);
    std::string get_request();
    std::string get_response();
    std::string get_call_id();
  };

}

#endif
