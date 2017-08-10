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

  // Node names.
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

    ServiceProfileBuilder();
    ~ServiceProfileBuilder();

    std::string return_profile();
    ServiceProfileBuilder& addIdentity(std::string);
    ServiceProfileBuilder& addWildcard(std::string, int, std::string);
    ServiceProfileBuilder& addBarringIndication(std::string, std::string);
    ServiceProfileBuilder& addIfc(int, std::vector<std::string>, std::string, int=0, int=0);
    ServiceProfileBuilder& addIfcNoDefHandling(int, std::vector<std::string>, std::string, int=0);
    ServiceProfileBuilder& addIfcBadDefField(int, std::vector<std::string>, std::string, int, std::string);
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
    std::vector<ServiceProfileBuilder> _service_profiles;

    SubscriptionBuilder();
    ~SubscriptionBuilder();

    std::string return_sub();
    SubscriptionBuilder& addServiceProfile(ServiceProfileBuilder);
  };


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

    Message();
    ~Message();

    void set_route(pjsip_msg* msg);
    std::string get_request();
    std::string get_response();
  };
}

#endif

