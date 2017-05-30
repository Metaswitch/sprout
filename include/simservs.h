/**
 * @file simservs.h Interface declaration for the simservs XML parser
 *
 * Copyright (C) Metaswitch Networks 2014
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///

#ifndef SIMSERVS_H__
#define SIMSERVS_H__

#include <string>
#include <vector>

#include "rapidxml/rapidxml.hpp"

class simservs
{
public:
  simservs(std::string xml);
  simservs(const std::string forward_target,
           unsigned int conditions,
           unsigned int no_reply_timer);
  ~simservs();

  class Rule
  {
  public:
    Rule(rapidxml::xml_node<>* rule);
    Rule(unsigned int conditions) : _conditions(conditions) {};
    ~Rule();

    static const unsigned int CONDITION_BUSY =               0x0001;
    static const unsigned int CONDITION_NOT_REGISTERED =     0x0002;
    static const unsigned int CONDITION_NO_ANSWER =          0x0004;
    static const unsigned int CONDITION_NOT_REACHABLE =      0x0008;
    static const unsigned int CONDITION_MEDIA_AUDIO =        0x0010;
    static const unsigned int CONDITION_MEDIA_VIDEO =        0x0020;
    static const unsigned int CONDITION_ROAMING =            0x0040;
    static const unsigned int CONDITION_INTERNATIONAL =      0x0080;
    static const unsigned int CONDITION_INTERNATIONAL_EXHC = 0x0100;
    unsigned int conditions() const;

  private:
    unsigned int _conditions;
  };

  class CDIVRule : public Rule
  {
  public:
    CDIVRule(rapidxml::xml_node<>* rule);
    CDIVRule(const std::string forward_target, unsigned int conditions) :
      Rule(conditions), _forward_target(forward_target) {};
    ~CDIVRule();
    std::string forward_target() const;

  private:
    std::string _forward_target;
  };

  class CBRule : public Rule
  {
  public:
    CBRule(rapidxml::xml_node<>* rule);
    ~CBRule();
    bool allow_call() const;

  private:
    bool _allow_call;
  };

  bool oip_enabled();
  bool oir_enabled();
  bool oir_presentation_restricted();
  bool cdiv_enabled() const;
  unsigned int cdiv_no_reply_timer() const;
  const std::vector<CDIVRule>* cdiv_rules() const;
  bool inbound_cb_enabled() const;
  bool outbound_cb_enabled() const;
  const std::vector<CBRule>* inbound_cb_rules() const;
  const std::vector<CBRule>* outbound_cb_rules() const;

private:
  bool check_active(rapidxml::xml_node<> *service);

  bool _oip_enabled;

  bool _oir_enabled;
  bool _oir_presentation_restricted;

  bool _cdiv_enabled;
  unsigned int _cdiv_no_reply_timer;
  std::vector<CDIVRule> _cdiv_rules;

  bool _inbound_cb_enabled;
  bool _outbound_cb_enabled;
  std::vector<CBRule> _inbound_cb_rules;
  std::vector<CBRule> _outbound_cb_rules;
};

#endif
